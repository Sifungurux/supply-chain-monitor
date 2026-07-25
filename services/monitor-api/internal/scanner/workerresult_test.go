package scanner

import (
	"strings"
	"testing"
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
