package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOrasDigestResolver_Resolve_LocalPathNeverContactsARegistry exercises
// the one branch of OrasDigestResolver.Resolve that doesn't need the real
// `oras` binary or a registry -- looksLikeLocalPath short-circuits before
// exec.CommandContext is ever constructed, so this can run in any Go
// environment, unlike a real registry-fetch case.
func TestOrasDigestResolver_Resolve_LocalPathNeverContactsARegistry(t *testing.T) {
	r := NewOrasDigestResolver("", "")
	digest, err := r.Resolve(context.Background(), "/tmp/report.sarif", false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if digest != "" {
		t.Fatalf("digest = %q, want empty -- a local path should never be treated as a registry ref", digest)
	}
}

// TestQualifyDockerHubRef covers the actual bug this was written to fix,
// confirmed live against a real cluster: unlike Docker itself, oras never
// defaults an unqualified ref to docker.io, so `oras manifest fetch
// nginx:alpine` parses "nginx" as the registry host and fails a DNS
// lookup for it -- every single bare Docker Hub ref, deterministically.
func TestQualifyDockerHubRef(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		want string
	}{
		{
			name: "single-segment official image gets docker.io/library/",
			ref:  "nginx:alpine",
			want: "docker.io/library/nginx:alpine",
		},
		{
			name: "single-segment, no tag",
			ref:  "busybox",
			want: "docker.io/library/busybox",
		},
		{
			name: "user/org image gets docker.io/ only -- already names an owner",
			ref:  "bitnami/redis:7.2.5",
			want: "docker.io/bitnami/redis:7.2.5",
		},
		{
			name: "already-qualified real registry is left untouched",
			ref:  "ghcr.io/cert-manager/cert-manager-controller:v1.14.5",
			want: "ghcr.io/cert-manager/cert-manager-controller:v1.14.5",
		},
		{
			name: "multi-segment path on a real registry is left untouched",
			ref:  "mcr.microsoft.com/vscode/devcontainers/base:ubuntu",
			want: "mcr.microsoft.com/vscode/devcontainers/base:ubuntu",
		},
		{
			name: "host:port form (has a colon in the first segment) is left untouched",
			ref:  "localhost:5000/scans/app-sarif:1",
			want: "localhost:5000/scans/app-sarif:1",
		},
		{
			name: "bare \"localhost\" host, no port, is left untouched",
			ref:  "localhost/scans/app-sarif:1",
			want: "localhost/scans/app-sarif:1",
		},
		{
			name: "in-cluster FQDN (scm-registry) is left untouched",
			ref:  "scm-registry.supply-chain-monitor.svc.cluster.local:5000/scans/app-sarif:1",
			want: "scm-registry.supply-chain-monitor.svc.cluster.local:5000/scans/app-sarif:1",
		},
		{
			name: "already docker.io-qualified is left untouched (idempotent)",
			ref:  "docker.io/library/nginx:alpine",
			want: "docker.io/library/nginx:alpine",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifyDockerHubRef(tc.ref); got != tc.want {
				t.Fatalf("qualifyDockerHubRef(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// scm-registry requires a bearer token for every /v2/ request, so an
// anonymous manifest fetch is refused at the token endpoint with a 401.
// That failure is SILENT -- resolveDigest swallows it and continues
// without a digest -- so the only symptom is dedup quietly not working
// for in-cluster images.
func TestOrasDigestResolver_PassesCredentials(t *testing.T) {
	withCreds := NewOrasDigestResolver("scm-reader", "hunter2")
	anonymous := NewOrasDigestResolver("", "")

	// The resolver shells out, so assert on the argv it would build
	// rather than on a live registry.
	got := withCreds.args("example.com/app:1", false)
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--username scm-reader") || !strings.Contains(joined, "--password hunter2") {
		t.Errorf("credentials missing from argv: %q", joined)
	}

	// Anonymous must stay anonymous -- public registries reject an
	// empty --username outright rather than ignoring it.
	anon := strings.Join(anonymous.args("example.com/app:1", false), " ")
	if strings.Contains(anon, "--username") {
		t.Errorf("empty credentials still produced a --username flag: %q", anon)
	}
}

// TestOrasDigestResolver_UsesRegistryConfig covers the multi-registry
// path: one merged docker config replaces the single credential pair,
// so each registry's credentials are scoped to its own host instead of
// being offered to whatever host the ref happens to name.
//
// Argv again rather than a live registry, for the same reason the test
// above does it -- the live leg is
// TestOrasDigestResolver_ResolvesAgainstAuthenticatedRegistry below.
func TestOrasDigestResolver_UsesRegistryConfig(t *testing.T) {
	joined := strings.Join(NewOrasDigestResolverWithConfig("/etc/scm/config.json").args("example.com/app:1", false), " ")
	if !strings.Contains(joined, "--registry-config /etc/scm/config.json") {
		t.Errorf("registry config missing from argv: %q", joined)
	}
	// The password must not reach argv, which is readable from the
	// pod's process list -- that is half the reason for the config file.
	if strings.Contains(joined, "--password") {
		t.Errorf("config-based resolver still put credentials in argv: %q", joined)
	}
}

// TestOrasDigestResolver_ResolvesAgainstAuthenticatedRegistry drives the
// real oras binary against a registry that REFUSES anonymous requests,
// with credentials supplied only through the merged docker config.
//
// The negative leg is the point. A resolver that fails to authenticate
// does not error loudly here -- resolveDigest swallows the failure and
// registers the artifact without a digest -- so a test that only
// asserted "we got a digest" would still pass if the config were
// ignored and the registry were open. Anonymous must be seen to fail
// first, against this same server, or the positive result proves
// nothing about the credentials.
//
// Skipped where oras is not installed: the CI container that runs `go
// test` is a bare golang image. It runs in the built monitor-api image,
// which is where the binary this code actually shells out to lives.
func TestOrasDigestResolver_ResolvesAgainstAuthenticatedRegistry(t *testing.T) {
	if _, err := exec.LookPath("oras"); err != nil {
		t.Skip("oras not on PATH -- this leg runs in the monitor-api image, not the bare go test container")
	}

	const (
		user = "scm-reader"
		pass = "hunter2"
		// Any well-formed digest: nothing here verifies the bytes, the
		// registry just has to answer consistently.
		digest = "sha256:6b1a4b56a52bb1c1a6bc4e1eb56c2a45e1a1e5f5d0d5f1a8b0f39fcb2cf5b2a1"
	)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digest + `","size":2},"layers":[]}`)

	var anonymousAttempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
			anonymousAttempts++
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", digest)
		// Content-Length explicitly, because oras resolves via HEAD and
		// a HEAD with no length is rejected as "unknown response
		// Content-Length" -- net/http will not infer one for a body it
		// is not going to write.
		w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			w.Write(manifest) //nolint:errcheck // test server
		}
	}))
	defer srv.Close()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/app:1"

	// httptest listens on loopback, which ValidateRef refuses outright
	// (SSRF: a ref must not be able to point this pod at its own
	// network). The allowlist is the mechanism an operator uses to say
	// "I know what this host is", so the test uses it rather than
	// weakening the check -- and in doing so covers the allowlist path
	// for a host that would otherwise be refused.
	t.Setenv(RefHostAllowlistEnv, strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0])

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := NewOrasDigestResolver("", "").Resolve(ctx, ref, true); err == nil {
		t.Fatal("anonymous resolution succeeded against a registry that requires auth -- the rest of this test would prove nothing")
	}
	if anonymousAttempts == 0 {
		t.Fatal("registry never saw an unauthenticated request; the negative leg did not exercise what it claims")
	}

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	auths := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`,
		strings.TrimPrefix(srv.URL, "http://"),
		base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	if err := os.WriteFile(cfg, []byte(auths), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := NewOrasDigestResolverWithConfig(cfg).Resolve(ctx, ref, true)
	if err != nil {
		t.Fatalf("resolve with merged docker config: %v", err)
	}
	if got != digest {
		t.Errorf("digest = %q, want %q", got, digest)
	}
}
