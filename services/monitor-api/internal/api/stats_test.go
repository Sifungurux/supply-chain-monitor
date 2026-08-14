package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// These exercise the handler, the router wiring, and MemStore's own
// arithmetic in one pass -- GET /api/v1/stats has no request shape to
// speak of, so testing the store in isolation would cover strictly less
// for the same number of lines.
//
// The two cases that actually discriminate are
// TestStats_SuppressedFindingsDoNotCount (a missing IsActive filter
// passes everything else) and TestStats_CountsArtifactsNotFindings
// (count(*) where the query means count(DISTINCT artifact_id) passes
// everything else). PostgresStore is held to both in
// internal/artifact/postgres_store_integration_test.go, so the two
// backends can't quietly disagree about the numbers on the dashboard.

func getStats(t *testing.T, h http.Handler) artifact.Stats {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/v1/stats", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("stats status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var out artifact.Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode stats: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// mustSetFindings puts findings straight into a bucket, bypassing the
// scan/merge path -- these tests are about counting what's on record,
// not about how it got there.
func mustSetFindings(t *testing.T, store *artifact.MemStore, id string, mutate func(*artifact.Artifact)) {
	t.Helper()
	if _, err := store.Update(id, mutate); err != nil {
		t.Fatalf("store.Update(%s): %v", id, err)
	}
}

func TestStats_EmptyStore(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	stats := getStats(t, h)
	if stats.Total != 0 {
		t.Fatalf("total = %d, want 0", stats.Total)
	}
	// All four maps must be present and non-nil even with nothing to
	// report: a JSON `null` here would make every client's `stats.by_status[x]`
	// a different kind of failure than the 0 it should be.
	if stats.ByStatus == nil || stats.ByType == nil || stats.WithFindings == nil || stats.ByStage == nil {
		t.Fatalf("stats = %+v, want every map non-nil (JSON {} not null) on an empty store", stats)
	}
	// The five buckets are the one closed set that's always reported in
	// full -- see artifact.Stats. Everything else stays absent-means-zero.
	for _, bucket := range []string{"cve", "malware", "misconfiguration", "secret", "other"} {
		if n, ok := stats.WithFindings[bucket]; !ok || n != 0 {
			t.Errorf("with_findings[%q] = %d (present=%v), want an explicit 0", bucket, n, ok)
		}
	}
	if len(stats.ByStatus) != 0 || len(stats.ByType) != 0 || len(stats.ByStage) != 0 {
		t.Errorf("by_status/by_type/by_stage = %v/%v/%v, want empty (only observed keys appear)",
			stats.ByStatus, stats.ByType, stats.ByStage)
	}
}

func TestStats_CountsByStatusTypeAndStage(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	scanned := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustSetFindings(t, store, scanned.ID, func(a *artifact.Artifact) {
		a.Status = artifact.StatusScanned
		a.CurrentStage = "scan"
	})
	building := mustCreate(t, store, "ghcr.io/example/app:latest", artifact.TypeImage)
	mustSetFindings(t, store, building.ID, func(a *artifact.Artifact) {
		a.Status = artifact.StatusScanning
		a.CurrentStage = "build"
	})
	// Left exactly as registered: no status change, no stage.
	mustCreate(t, store, "/tmp/report.sarif", artifact.TypeSARIF)

	stats := getStats(t, h)

	if stats.Total != 3 {
		t.Fatalf("total = %d, want 3", stats.Total)
	}
	wantStatus := map[string]int{"scanned": 1, "scanning": 1, "registered": 1}
	for status, want := range wantStatus {
		if stats.ByStatus[status] != want {
			t.Errorf("by_status[%q] = %d, want %d (got %v)", status, stats.ByStatus[status], want, stats.ByStatus)
		}
	}
	if stats.ByType["image"] != 2 || stats.ByType["sarif"] != 1 {
		t.Errorf("by_type = %v, want image:2 sarif:1", stats.ByType)
	}
	if stats.ByType["file"] != 0 {
		t.Errorf("by_type = %v, want no entry for a type nothing is (absent reads as 0)", stats.ByType)
	}

	if stats.ByStage["scan"] != 1 || stats.ByStage["build"] != 1 {
		t.Errorf("by_stage = %v, want scan:1 build:1", stats.ByStage)
	}
	// The unstaged artifact goes under "" -- not "unassigned", which
	// could collide with a real configured stage. See Stats.ByStage.
	if stats.ByStage[""] != 1 {
		t.Errorf("by_stage[\"\"] = %d, want 1 -- an unstaged artifact belongs under the empty key (got %v)",
			stats.ByStage[""], stats.ByStage)
	}
}

func TestStats_CountsEveryFindingBucket(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustSetFindings(t, store, a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = []artifact.Finding{{ID: "CVE-2024-1", Status: artifact.FindingStatusOpen}}
		art.MalwareFindings = []artifact.Finding{{ID: "Eicar-Test-Signature", Status: artifact.FindingStatusOpen}}
		art.MisconfigFindings = []artifact.Finding{{ID: "KSV001", Status: artifact.FindingStatusOpen}}
		art.SecretFindings = []artifact.Finding{{ID: "aws-access-key", Status: artifact.FindingStatusOpen}}
		art.OtherFindings = []artifact.Finding{{ID: "go/sql-injection", Status: artifact.FindingStatusOpen}}
	})
	// A second artifact carrying only a CVE, so cve and the rest can't
	// all be right by accident of every bucket having the same number.
	b := mustCreate(t, store, "debian:12", artifact.TypeImage)
	mustSetFindings(t, store, b.ID, func(art *artifact.Artifact) {
		art.CVEFindings = []artifact.Finding{{ID: "CVE-2024-2", Status: artifact.FindingStatusOpen}}
	})

	stats := getStats(t, h)

	want := map[string]int{"cve": 2, "malware": 1, "misconfiguration": 1, "secret": 1, "other": 1}
	for bucket, n := range want {
		if stats.WithFindings[bucket] != n {
			t.Errorf("with_findings[%q] = %d, want %d (got %v)", bucket, stats.WithFindings[bucket], n, stats.WithFindings)
		}
	}
}

// A finding that's been fixed, or formally assessed as not applying via
// VEX, stays on the artifact forever as a record (see MergeFindings) --
// it must not keep the artifact in the "with CVEs" count. This is the
// bug a missing IsActive filter produces: every number stays plausible,
// and resolved problems are reported as live ones indefinitely.
func TestStats_SuppressedFindingsDoNotCount(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	fixed := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustSetFindings(t, store, fixed.ID, func(a *artifact.Artifact) {
		a.CVEFindings = []artifact.Finding{{ID: "CVE-2024-1", Status: artifact.FindingStatusFixed}}
	})
	suppressed := mustCreate(t, store, "debian:12", artifact.TypeImage)
	mustSetFindings(t, store, suppressed.ID, func(a *artifact.Artifact) {
		a.CVEFindings = []artifact.Finding{{ID: "CVE-2024-2", Status: artifact.FindingStatusNotAffected}}
	})
	// Empty status: a finding persisted before the lifecycle columns
	// existed, or submitted by a caller that never set one. IsActive
	// fails toward "still a problem", so this one DOES count.
	legacy := mustCreate(t, store, "ubuntu:24.04", artifact.TypeImage)
	mustSetFindings(t, store, legacy.ID, func(a *artifact.Artifact) {
		a.CVEFindings = []artifact.Finding{{ID: "CVE-2024-3"}}
	})

	stats := getStats(t, h)

	if stats.Total != 3 {
		t.Fatalf("total = %d, want 3 -- suppressed findings hide an artifact from the bucket counts, not from the store", stats.Total)
	}
	if stats.ByStatus["registered"] != 3 {
		t.Errorf("by_status = %v, want all 3 still counted", stats.ByStatus)
	}
	if stats.WithFindings["cve"] != 1 {
		t.Errorf("with_findings[cve] = %d, want 1 -- only the empty-status finding is active; fixed and not_affected are on record but resolved",
			stats.WithFindings["cve"])
	}
}

// Every number here counts ARTIFACTS. An artifact with three open CVEs
// is one artifact with CVEs, not three -- the bug a count(*) instead of
// count(DISTINCT artifact_id) produces, which inflates the headline
// number without ever exceeding a plausible-looking value.
func TestStats_CountsArtifactsNotFindings(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustSetFindings(t, store, a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = []artifact.Finding{
			{ID: "CVE-2024-1", Status: artifact.FindingStatusOpen},
			{ID: "CVE-2024-2", Status: artifact.FindingStatusOpen},
			{ID: "CVE-2024-3", Status: artifact.FindingStatusOpen},
		}
	})

	stats := getStats(t, h)

	if stats.WithFindings["cve"] != 1 {
		t.Fatalf("with_findings[cve] = %d, want 1 -- one artifact with three open CVEs is one affected artifact", stats.WithFindings["cve"])
	}
}

func TestStats_RequiresAPIKey(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	// No Authorization header: unlike /healthz and the swagger pages,
	// this reports data about the fleet, so it's behind the key.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without an API key", rec.Code)
	}
}
