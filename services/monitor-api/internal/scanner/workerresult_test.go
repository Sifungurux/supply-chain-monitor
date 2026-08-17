package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// TestExtractWorkerResult_BareJSON confirms the pre-existing shape --
// pod logs that are nothing but the WorkerResult JSON, exactly what
// every scan-worker Job produced before VerboseScanLogs existed, and
// what every Job still produces today whenever it's left off -- keeps
// parsing the same way it always has, via the fallback whole-body
// parse (no ResultMarker line present at all).
func TestExtractWorkerResult_BareJSON(t *testing.T) {
	logs := `{"findings":[{"id":"CVE-2024-1","severity":"HIGH","title":"x","source":"trivy"}]}`
	result, err := ExtractWorkerResult(logs)
	if err != nil {
		t.Fatalf("ExtractWorkerResult: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "CVE-2024-1" {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

// TestExtractWorkerResult_MarkerLineAmongNoise is the real-world verbose
// case: trivy's/unpacker's own progress output (and, previously, a
// stray cleanScanCache log.Printf -- see trivy.go's Scan comment) is
// mixed into the same combined stdout+stderr stream ahead of the
// result. ExtractWorkerResult must find the ResultMarker-prefixed line
// and ignore everything else around it.
func TestExtractWorkerResult_MarkerLineAmongNoise(t *testing.T) {
	logs := strings.Join([]string{
		"2026/07/23 20:36:30 pulling gcr.io/example/app:1.0 with oras",
		`INFO	Vulnerability scanning is enabled`,
		`INFO	Detected OS: alpine`,
		ResultMarker + `{"findings":[{"id":"CVE-2024-2","severity":"CRITICAL","title":"y","source":"trivy"}]}`,
	}, "\n")

	result, err := ExtractWorkerResult(logs)
	if err != nil {
		t.Fatalf("ExtractWorkerResult: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "CVE-2024-2" {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

// TestExtractWorkerResult_LastMarkerLineWins guards against the
// (unlikely, but not impossible) case of the marker text appearing more
// than once in the log stream -- e.g. verbose tool output happening to
// echo it back somehow. The real result is always the last thing
// runScanWorker ever prints, right before it exits, so "last line wins"
// is the correct tiebreak.
func TestExtractWorkerResult_LastMarkerLineWins(t *testing.T) {
	logs := strings.Join([]string{
		ResultMarker + `{"findings":[],"error":"stale, should not be used"}`,
		"some other output in between",
		ResultMarker + `{"findings":[],"error":""}`,
	}, "\n")

	result, err := ExtractWorkerResult(logs)
	if err != nil {
		t.Fatalf("ExtractWorkerResult: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("error = %q, want empty (expected the last marker line to win)", result.Error)
	}
}

// TestExtractWorkerResult_ErrorField confirms a WorkerResult carrying a
// scan error (not a Go error -- this is the worker successfully
// reporting that the scan itself failed) round-trips through the marker
// line correctly.
func TestExtractWorkerResult_ErrorField(t *testing.T) {
	logs := ResultMarker + `{"findings":null,"error":"trivy scan failed for \"alpine:3.19\": db not found"}`
	result, err := ExtractWorkerResult(logs)
	if err != nil {
		t.Fatalf("ExtractWorkerResult: %v", err)
	}
	if !strings.Contains(result.Error, "db not found") {
		t.Fatalf("error = %q", result.Error)
	}
}

// TestExtractWorkerResult_Unparseable confirms logs that are neither a
// bare JSON document nor contain a valid marker line produce a real
// error -- e.g. a worker that crashed before printing anything
// meaningful.
func TestExtractWorkerResult_Unparseable(t *testing.T) {
	if _, err := ExtractWorkerResult("not json at all"); err == nil {
		t.Fatal("expected an error for logs with no valid result")
	}
}

// TestWorkerResult_CategorySurvivesTheWire is a regression test for a
// bug that reached production and reported nothing.
//
// artifact.Finding.Category is `json:"-"`, so a Finding classified
// inside the scan-worker Job arrived at the parent with an empty
// Category. classifyBucket then fell through to Source -- "trivy"
// hits its default case -- and six real secrets detected in a live
// image were filed as CVEs. No error, no log line; the only symptom
// was findings with "secret:" IDs sitting in the CVE bucket.
//
// The isolated path is the DEFAULT path, so this affected production
// while the in-process path (DISABLE_SCAN_ISOLATION, used by tests and
// local dev) stayed correct -- which is exactly why unit tests on the
// parser did not catch it.
func TestWorkerResult_CategorySurvivesTheWire(t *testing.T) {
	in := WorkerResult{Findings: []artifact.Finding{
		{ID: "secret:/app/.env:aws-access-key-id:3", Severity: "CRITICAL", Title: "AWS Access Key ID", Source: "trivy", Category: "secret"},
		{ID: "malcontent:exec", Severity: "HIGH", Title: "exec", Source: "malcontent", Category: "malware"},
		{ID: "CVE-2024-1", Severity: "HIGH", Title: "a cve", Source: "trivy"},
	}}

	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Through the REAL extraction path the Job's pod logs go through,
	// not just json.Unmarshal -- that is the code that actually runs.
	got, err := ExtractWorkerResult(ResultMarker + string(encoded))
	if err != nil {
		t.Fatalf("ExtractWorkerResult: %v", err)
	}
	if len(got.Findings) != len(in.Findings) {
		t.Fatalf("got %d findings, want %d", len(got.Findings), len(in.Findings))
	}
	for i, want := range in.Findings {
		if got.Findings[i].Category != want.Category {
			t.Errorf("finding %d (%s): Category = %q, want %q -- an empty Category makes classifyBucket file this by Source, which sends it to the CVE bucket",
				i, want.ID, got.Findings[i].Category, want.Category)
		}
		if got.Findings[i].ID != want.ID || got.Findings[i].Severity != want.Severity {
			t.Errorf("finding %d round-tripped wrong: %+v, want %+v", i, got.Findings[i], want)
		}
	}
}

// A result written by an older worker has no "category" key at all.
// It must still decode, with empty Categories -- the behavior before
// this existed.
func TestWorkerResult_DecodesDocumentWithoutCategory(t *testing.T) {
	got, err := ExtractWorkerResult(ResultMarker + `{"findings":[{"id":"CVE-1","severity":"HIGH","title":"t","source":"trivy"}]}`)
	if err != nil {
		t.Fatalf("ExtractWorkerResult: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].ID != "CVE-1" || got.Findings[0].Category != "" {
		t.Fatalf("findings = %+v, want one CVE-1 with an empty Category", got.Findings)
	}
}
