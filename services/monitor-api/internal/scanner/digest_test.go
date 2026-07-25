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
