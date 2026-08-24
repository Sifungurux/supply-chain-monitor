package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const testRegistry = "scm-registry.supply-chain-monitor.svc.cluster.local:5000"

func testMirror(resolver DigestResolver) *OrasMirror {
	return NewOrasMirror(testRegistry, "", false, "/tmp/config.json", resolver)
}

// fakeResolver stands in for a real registry -- the destination digest
// is whatever the test says it is.
type fakeResolver struct {
	digest string
	err    error
}

func (f fakeResolver) Resolve(context.Context, string, bool) (string, error) {
	return f.digest, f.err
}

func TestMirrorRef(t *testing.T) {
	m := testMirror(fakeResolver{})
	cases := []struct{ ref, want string }{
		// Unqualified Docker Hub refs get qualified first -- otherwise
		// the destination would be named after a registry called
		// "nginx", exactly as digest.go documents.
		{"nginx:alpine", testRegistry + "/mirror/docker.io/library/nginx:alpine"},
		{"bitnami/redis:7.2.5", testRegistry + "/mirror/docker.io/bitnami/redis:7.2.5"},
		{"ghcr.io/org/app:v1", testRegistry + "/mirror/ghcr.io/org/app:v1"},
		// No tag means "latest", the same default every registry client
		// applies.
		{"ghcr.io/org/app", testRegistry + "/mirror/ghcr.io/org/app:latest"},
		// Uppercase is illegal in a repository path.
		{"ghcr.io/Org/App:V1", testRegistry + "/mirror/ghcr.io/org/app:V1"},
		// The ":" in a host:port is a port, not a tag, and is illegal in
		// the destination path.
		{"localhost:5000/app:v1", testRegistry + "/mirror/localhost-5000/app:v1"},
		// A digest-pinned ref has no tag of its own: the destination is
		// tagged after the digest so the copy is not left untagged and
		// garbage-collectable.
		{"ghcr.io/org/app@sha256:abc123", testRegistry + "/mirror/ghcr.io/org/app:sha256-abc123"},
		// Nothing to do: already in the local registry, or not a
		// registry ref at all.
		{testRegistry + "/mirror/ghcr.io/org/app:v1", ""},
		{"/var/lib/artifacts/report.json", ""},
		{"./report.json", ""},
	}
	for _, c := range cases {
		if got := m.MirrorRef(c.ref); got != c.want {
			t.Errorf("MirrorRef(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

// A digest must never be run through the path sanitizer: "sha256:ab..."
// would come back as "sha256-ab..." embedded in the repository path,
// producing a valid-looking ref that resolves to nothing.
func TestMirrorRefKeepsDigestOutOfThePath(t *testing.T) {
	got := testMirror(fakeResolver{}).MirrorRef("ghcr.io/org/app@sha256:deadbeef")
	if strings.Contains(strings.TrimSuffix(got, ":sha256-deadbeef"), "sha256") {
		t.Fatalf("digest leaked into the repository path: %q", got)
	}
}

func TestCopyArgs(t *testing.T) {
	m := testMirror(fakeResolver{})
	args := strings.Join(m.copyArgs("docker.io/library/nginx:alpine", m.MirrorRef("nginx:alpine")), " ")
	// copy takes --from-*/--to-* variants, not the plain flag names the
	// single-target commands use -- verified against oras 1.3.2.
	for _, want := range []string{
		"copy --recursive",
		"--from-registry-config /tmp/config.json",
		"--to-registry-config /tmp/config.json",
		"-- docker.io/library/nginx:alpine",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("copyArgs missing %q, got: %s", want, args)
		}
	}
	// The password must never reach argv.
	if strings.Contains(args, "--from-password") || strings.Contains(args, "--to-password") {
		t.Errorf("credentials leaked into argv: %s", args)
	}
	// PlainHTTP is off here, so the destination must keep TLS.
	if strings.Contains(args, "--to-plain-http") {
		t.Errorf("--to-plain-http applied with PlainHTTP=false: %s", args)
	}
	// And the SOURCE must never be downgraded, whatever the switch says.
	m.PlainHTTP = true
	t.Setenv(RegistryAddrEnv, testRegistry)
	args = strings.Join(m.copyArgs("docker.io/library/nginx:alpine", m.MirrorRef("nginx:alpine")), " ")
	if strings.Contains(args, "--from-plain-http") {
		t.Errorf("source transport downgraded: %s", args)
	}
	if !strings.Contains(args, "--to-plain-http") {
		t.Errorf("--to-plain-http not applied to this deployment's own registry: %s", args)
	}
}

// The check that proves the copy is real. A zero exit from `oras copy`
// is not evidence: a partial push, a wrong destination name, or an
// index/child mix-up all produce a ref that looks fine and scans as
// nothing. These exercise the verification directly rather than through
// exec, which is the half that has no business needing a live registry.
func TestMirrorVerification(t *testing.T) {
	t.Run("digest mismatch is refused", func(t *testing.T) {
		m := testMirror(fakeResolver{digest: "sha256:other"})
		if _, err := m.verify(context.Background(), "nginx:alpine", "dst:alpine", "sha256:wanted"); err == nil {
			t.Fatal("a destination resolving to different content was accepted")
		}
	})
	t.Run("unresolvable destination is refused", func(t *testing.T) {
		m := testMirror(fakeResolver{err: errors.New("not found")})
		if _, err := m.verify(context.Background(), "nginx:alpine", "dst:alpine", "sha256:wanted"); err == nil {
			t.Fatal("a destination that could not be resolved at all was accepted")
		}
	})
	t.Run("matching digest is accepted", func(t *testing.T) {
		m := testMirror(fakeResolver{digest: "sha256:wanted"})
		got, err := m.verify(context.Background(), "nginx:alpine", "dst:alpine", "sha256:wanted")
		if err != nil || got != "dst:alpine" {
			t.Fatalf("verify() = %q, %v; want the destination ref and no error", got, err)
		}
	})
}

// NewOrasMirror returning nil is what the handler reads as "mirroring is
// off" -- there has to be no way to build one that cannot do its job.
func TestNewOrasMirrorRefusesAnIncompleteConfig(t *testing.T) {
	if m := NewOrasMirror("", "mirror", false, "", fakeResolver{}); m != nil {
		t.Error("built a mirror with no destination registry")
	}
	if m := NewOrasMirror(testRegistry, "mirror", false, "", nil); m != nil {
		t.Error("built a mirror with no resolver -- its copies could never be verified")
	}
}
