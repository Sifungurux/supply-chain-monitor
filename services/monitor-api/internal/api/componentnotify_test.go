package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// TestNotifyNewComponents covers the whole signal in one flow, because
// the three cases are the same sequence: an inventory with nothing to
// compare against, one that compared equal, and one that gained a
// package. Splitting them would re-upload the same fixtures three times
// to reach the interesting state.
//
// The notifier fires on the SBOM being INDEXED, not on a scan, so this
// drives the document-upload endpoint directly -- that is the real
// production path for an image, whose components are indexed when the
// scan-worker uploads the SBOM afterwards.
func TestNotifyNewComponents(t *testing.T) {
	n := newFakeNotifier()
	h, store := newNotifyingRouter(t, scanner.Registry{}, n, "high")
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	original := readSBOMFixture(t)

	// First inventory: one snapshot, nothing to compare against. Every
	// package in it is "new" only because nobody had looked before.
	uploadSBOM(t, h, created.ID, original)
	assertNoNotification(t, n, "the first SBOM indexed for an artifact")

	// Same SBOM again: two snapshots, nothing added. This is what a
	// re-scan of an unchanged digest looks like, and it is why the
	// event needs no severity threshold to stay quiet.
	uploadSBOM(t, h, created.ID, original)
	assertNoNotification(t, n, "an unchanged inventory")

	// A package appears that was not there before.
	uploadSBOM(t, h, created.ID, mutateSBOM(t, original))
	if !n.waitForNotify(t) {
		t.Fatal("no notification when the SBOM gained a package")
	}

	events := n.delivered()
	if len(events) != 1 {
		t.Fatalf("delivered %d events, want 1", len(events))
	}
	e := events[0]
	if e.ArtifactID != created.ID || e.ArtifactRef != "alpine:3.19" {
		t.Fatalf("event identifies the wrong artifact: %+v", e)
	}
	if len(e.NewFindings) != 0 {
		t.Fatalf("a component event carries no findings, got %+v", e.NewFindings)
	}

	// ADDED only. mutateSBOM also upgrades alpine-keys and drops
	// apk-tools; neither is a supply-chain signal, and reporting the
	// upgrade would page on every base-image bump.
	if len(e.NewComponents) != 1 || e.NewComponents[0].Name != "curl" {
		got := make([]string, 0, len(e.NewComponents))
		for _, c := range e.NewComponents {
			got = append(got, c.Name)
		}
		t.Fatalf("new components = %v, want only curl", got)
	}
}

// TestNotifyNewComponents_QuietWithoutNotifiers is the cheap guard on
// the store reads: with nothing configured to notify, the diff must not
// be computed at all.
func TestNotifyNewComponents_QuietWithoutNotifiers(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	original := readSBOMFixture(t)
	uploadSBOM(t, h, created.ID, original)
	uploadSBOM(t, h, created.ID, mutateSBOM(t, original))

	// Nothing to assert but that the upload path is unaffected -- the
	// point is that it neither panics nor errors with h.notifiers nil.
	rec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+created.ID+"/components/diff", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("diff status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func assertNoNotification(t *testing.T, n *fakeNotifier, what string) {
	t.Helper()
	select {
	case <-n.got:
		t.Fatalf("notified on %s -- that is noise, not a change signal", what)
	case <-time.After(300 * time.Millisecond):
	}
}
