package scanner

import (
	"context"
	"testing"
)

// TestOrasDigestResolver_Resolve_LocalPathNeverContactsARegistry exercises
// the one branch of OrasDigestResolver.Resolve that doesn't need the real
// `oras` binary or a registry -- looksLikeLocalPath short-circuits before
// exec.CommandContext is ever constructed, so this can run in any Go
// environment, unlike a real registry-fetch case.
func TestOrasDigestResolver_Resolve_LocalPathNeverContactsARegistry(t *testing.T) {
	r := NewOrasDigestResolver()
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
