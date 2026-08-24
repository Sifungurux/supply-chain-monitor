package api

// In-package (not api_test) because the race this covers is decided
// inside mirrorArtifact's store mutate func, and reproducing it through
// the HTTP surface would mean racing two real scans and hoping. The
// handler is built directly here for the same reason.

import (
	"context"
	"fmt"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// countingMirror hands out a different destination per call, so a second
// rewrite of the same artifact is visible rather than idempotent.
type countingMirror struct{ n int }

func (c *countingMirror) Mirror(_ context.Context, ref, _ string) (string, error) {
	c.n++
	return fmt.Sprintf("scm-registry:5000/mirror/copy-%d/%s", c.n, ref), nil
}

// Two scans of one artifact can mirror it concurrently -- nothing
// serializes them, scan slots are per scanner kind. The second must not
// overwrite source_ref with the FIRST one's mirrored ref: that destroys
// the public ref permanently, and it is the one thing this feature must
// never do.
//
// The loser is modelled by the stale snapshot it holds, which is exactly
// what a scan that started before the winner finished would be carrying.
func TestMirrorArtifact_SecondRewriteCannotDestroySourceRef(t *testing.T) {
	store := artifact.NewMemStore()
	h := &handler{store: store, mirror: &countingMirror{}}

	a, err := store.Create("nginx:alpine", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	first := h.mirrorArtifact(context.Background(), a)
	if first.SourceRef != "nginx:alpine" {
		t.Fatalf("source_ref = %q after the first mirror, want the public ref", first.SourceRef)
	}
	if first.Ref == "nginx:alpine" {
		t.Fatalf("ref was never rewritten: %q", first.Ref)
	}

	stale := &artifact.Artifact{ID: a.ID, Ref: "nginx:alpine", Type: artifact.TypeImage}
	got := h.mirrorArtifact(context.Background(), stale)

	if got.SourceRef != "nginx:alpine" {
		t.Errorf("source_ref = %q, want the public ref -- a racing rewrite destroyed it", got.SourceRef)
	}
	if got.Ref != first.Ref {
		t.Errorf("ref = %q, want the first mirror %q -- the loser overwrote the winner", got.Ref, first.Ref)
	}

	stored, err := store.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.SourceRef != "nginx:alpine" || stored.Ref != first.Ref {
		t.Errorf("stored ref/source_ref = %q/%q, want %q/%q", stored.Ref, stored.SourceRef, first.Ref, "nginx:alpine")
	}
}
