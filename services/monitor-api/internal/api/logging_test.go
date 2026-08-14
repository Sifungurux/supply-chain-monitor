package api_test

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// captureLogs swaps the process-wide default logger for one writing
// JSON into a buffer, and puts the old one back afterwards.
//
// Global state, so these tests can't run in parallel with anything that
// logs -- acceptable because the thing under test IS the global logger
// (main.go calls slog.SetDefault; nothing here injects a logger), and
// the alternative is plumbing a *slog.Logger through every handler to
// make one test easier to write.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// logLines decodes every JSON object the buffer holds. A line that
// doesn't decode fails the test rather than being skipped: the whole
// point of the change is that this stream is machine-readable, so a
// stray unstructured line is the regression, not noise to tolerate.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("log line is not JSON: %s (%v)", line, err)
		}
		out = append(out, m)
	}
	return out
}

// The check that fails if someone folds a field back into a format
// string. `artifact_id=abc` has to find every line about abc across
// api, scanner and notify -- a message reading "scan error for artifact
// abc" is fine to read and not queryable, which is the entire
// difference this change is buying.
//
// Asserts across TWO call sites in one flow (the per-scanner failure
// and the run summary), because the failure mode is not one missing
// field, it is two places spelling the same fact differently.
func TestLogging_ScanFlowCarriesArtifactIDAsAField(t *testing.T) {
	buf := captureLogs(t)

	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:    store,
		Tracker:  pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:   testAPIKey,
		Scanners: scanner.Registry{artifact.TypeImage: {&panickingScanner{}}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil)
	if got := waitForScan(t, store, a.ID); got.Status != artifact.StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusFailed)
	}

	byMsg := map[string]map[string]any{}
	for _, line := range logLines(t, buf) {
		if msg, ok := line["msg"].(string); ok {
			byMsg[msg] = line
		}
	}

	// A scanner that panics is recovered in its own goroutine and
	// reported as a scan error -- runScan's own recover() is for a panic
	// in runScan itself, which is a different (and much rarer) thing.
	failure, ok := byMsg["scan error"]
	if !ok {
		t.Fatalf("no \"scan error\" line in:\n%s", buf.String())
	}
	if failure["artifact_id"] != a.ID {
		t.Errorf("scan error line: artifact_id = %v, want %s", failure["artifact_id"], a.ID)
	}
	if failure["err"] == nil {
		t.Errorf("scan error line has no err field: %v", failure)
	}
	if failure["level"] != "WARN" {
		t.Errorf("scan error line: level = %v, want WARN", failure["level"])
	}

	summary, ok := byMsg["scan finished"]
	if !ok {
		t.Fatalf("no \"scan finished\" line in:\n%s", buf.String())
	}
	// Same key, different call site -- this is the assertion that
	// catches one package drifting to "artifactID" or "id".
	if summary["artifact_id"] != a.ID {
		t.Errorf("scan finished line: artifact_id = %v, want %s", summary["artifact_id"], a.ID)
	}
	if summary["status"] != string(artifact.StatusFailed) {
		t.Errorf("scan finished line: status = %v, want %q", summary["status"], artifact.StatusFailed)
	}
}

// The stdlib log package is bridged through slog by main.go's
// setupLogging, so a log.Printf this migration didn't convert still
// comes out as JSON rather than as a plain line in the middle of a
// structured stream. Asserted here because that bridge is what makes a
// partial migration safe, and nothing else would notice if it broke.
func TestLogging_StdlibLogIsBridgedToJSON(t *testing.T) {
	buf := captureLogs(t)

	log.Printf("a legacy %s line", "unstructured")

	lines := logLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %s", len(lines), buf.String())
	}
	if lines[0]["msg"] != "a legacy unstructured line" {
		t.Errorf("msg = %v, want the log.Printf text carried into the msg field", lines[0]["msg"])
	}
}
