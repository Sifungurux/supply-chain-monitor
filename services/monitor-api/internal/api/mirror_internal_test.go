package api

// In-package (not api_test) because the race this covers is decided
// inside mirrorArtifact's store mutate func, and reproducing it through
// the HTTP surface would mean racing two real scans and hoping. The
// handler is built directly here for the same reason.

import (
	"context"
	"errors"
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

// stubProvenance answers per ref, and records the order it was asked in.
type stubProvenance struct {
	byRef  map[string]string // ref -> provenance verdict
	errFor map[string]error
	asked  []string
}

func (s *stubProvenance) Kind() string { return "cosign" }

// Scan satisfies the embedded Scanner. Provenance verification never
// routes through it -- scanArtifact type-asserts ProvenanceScanner
// first -- so reaching it means the dispatch changed.
func (s *stubProvenance) Scan(_ context.Context, _ string) ([]artifact.Finding, error) {
	return nil, errors.New("Scan called: provenance should dispatch through ScanProvenance")
}
func (s *stubProvenance) ScanProvenance(_ context.Context, ref string) ([]artifact.Finding, string, string, error) {
	s.asked = append(s.asked, ref)
	p, ok := s.byRef[ref]
	if !ok {
		p = artifact.ProvenanceUnsigned
	}
	return nil, p, "public Sigstore", s.errFor[ref]
}

func TestProvenanceRefs_OrderPutsTheOriginalLast(t *testing.T) {
	mirrored := &artifact.Artifact{
		Ref:       "scm-registry:5000/mirror/ghcr.io/acme/app:1",
		SourceRef: "ghcr.io/acme/app:1",
	}
	got := provenanceRefs(mirrored)
	// The ORDER is the safety property: the last ref tried must be the
	// one this code used before the mirror was ever consulted.
	if len(got) != 2 || got[0] != mirrored.Ref || got[1] != mirrored.SourceRef {
		t.Fatalf("provenanceRefs = %q, want [mirror, source]", got)
	}

	// Not mirrored, mirrored-to-itself, and the local-path case all
	// collapse to one ref -- a second identical verification would be
	// pure cost.
	for name, a := range map[string]*artifact.Artifact{
		"never mirrored":     {Ref: "ghcr.io/acme/app:1"},
		"mirrored to itself": {Ref: "ghcr.io/acme/app:1", SourceRef: "ghcr.io/acme/app:1"},
	} {
		if got := provenanceRefs(a); len(got) != 1 {
			t.Errorf("%s: provenanceRefs = %q, want one ref", name, got)
		}
	}
}

func TestScanProvenanceRefs(t *testing.T) {
	const mirror = "scm-registry:5000/mirror/ghcr.io/acme/app:1"
	const source = "ghcr.io/acme/app:1"
	refs := []string{mirror, source}

	t.Run("mirror verifies: upstream is never contacted", func(t *testing.T) {
		s := &stubProvenance{byRef: map[string]string{mirror: artifact.ProvenanceVerified}}
		_, p, _, err := scanProvenanceRefs(context.Background(), s, refs)
		if p != artifact.ProvenanceVerified || err != nil {
			t.Fatalf("provenance = %q err = %v", p, err)
		}
		// The entire point: one local verification, no upstream call.
		if len(s.asked) != 1 || s.asked[0] != mirror {
			t.Errorf("asked = %q, want only the mirror", s.asked)
		}
	})

	// The classic .sig case: the signature did not travel with the copy.
	t.Run("mirror unsigned, source verified: falls back and keeps verified", func(t *testing.T) {
		s := &stubProvenance{byRef: map[string]string{
			mirror: artifact.ProvenanceUnsigned,
			source: artifact.ProvenanceVerified,
		}}
		_, p, _, _ := scanProvenanceRefs(context.Background(), s, refs)
		if p != artifact.ProvenanceVerified {
			t.Fatalf("provenance = %q, want verified -- a signature that did not travel must not read as unsigned", p)
		}
		if len(s.asked) != 2 {
			t.Errorf("asked = %q, want both refs tried", s.asked)
		}
	})

	// THE regression this design exists to prevent: a broken local
	// registry must never manufacture an unsigned verdict.
	t.Run("mirror errors, source verified: keeps verified", func(t *testing.T) {
		s := &stubProvenance{
			byRef:  map[string]string{mirror: artifact.ProvenanceUnverified, source: artifact.ProvenanceVerified},
			errFor: map[string]error{mirror: errors.New("local registry refused the connection")},
		}
		_, p, _, err := scanProvenanceRefs(context.Background(), s, refs)
		if p != artifact.ProvenanceVerified {
			t.Fatalf("provenance = %q, want verified", p)
		}
		if err != nil {
			t.Errorf("err = %v, want the failed mirror attempt's error discarded once a later ref verified", err)
		}
	})

	t.Run("both unsigned: the LAST answer wins, which is today's behaviour", func(t *testing.T) {
		s := &stubProvenance{byRef: map[string]string{
			mirror: artifact.ProvenanceUnverified,
			source: artifact.ProvenanceUnsigned,
		}}
		_, p, _, _ := scanProvenanceRefs(context.Background(), s, refs)
		if p != artifact.ProvenanceUnsigned {
			t.Fatalf("provenance = %q, want the source's verdict (%q)", p, artifact.ProvenanceUnsigned)
		}
	})

	t.Run("single ref behaves exactly as before", func(t *testing.T) {
		s := &stubProvenance{byRef: map[string]string{source: artifact.ProvenanceUnsigned}}
		_, p, _, _ := scanProvenanceRefs(context.Background(), s, []string{source})
		if p != artifact.ProvenanceUnsigned || len(s.asked) != 1 {
			t.Fatalf("provenance = %q asked = %q", p, s.asked)
		}
	})
}
