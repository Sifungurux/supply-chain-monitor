package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// WorkerResult is the JSON shape printed to stdout by `monitor-api
// scan-worker` (see main.go's runScanWorker) and read back by
// IsolatedUnpackerScanner (isolated_unpacker.go) from the completed
// Kubernetes Job's pod logs. Defined here, not in package main, since
// both main.go and isolated_unpacker.go need it and main isn't
// importable.
//
// Error is a string, not the error interface, so it survives a JSON
// round-trip -- the worker process and the process reading its output
// are never the same Go process, so there's no way to hand back a real
// error value.
type WorkerResult struct {
	Findings []artifact.Finding `json:"findings"`
	Error    string             `json:"error,omitempty"`
}

// ResultMarker prefixes the WorkerResult JSON line runScanWorker always
// prints as the very last thing it does before exiting. Kubernetes pod
// logs are a single combined stdout+stderr stream (see
// IsolatedTrivyScanner/IsolatedUnpackerScanner's PodLogs calls), so as
// soon as VerboseScanLogs also has trivy's or unpacker's own progress
// output mixed into that same stream, a naive "the whole log body is
// one JSON document" parse breaks the moment anything else is in
// there. Anchoring on a fixed, greppable prefix lets ExtractWorkerResult
// below find the real result regardless of how much other output
// surrounds it, and regardless of which of the two streams anything
// landed on.
const ResultMarker = "SCM_SCAN_RESULT_JSON "

// ExtractWorkerResult finds and decodes the WorkerResult out of a
// completed scan-worker Job's full pod logs.
//
// Prefers the last line starting with ResultMarker -- "last" in case
// verbose output from trivy/unpacker happened to include that literal
// text somewhere in its own noise; the real result is always the last
// thing runScanWorker ever prints, right before it exits. Falls back to
// parsing the entire trimmed log body as one JSON document if no such
// line is found, so logs that are already just the bare WorkerResult
// JSON with nothing else ever written to either stream -- every case
// before VerboseScanLogs existed, and every case today whenever it's
// left off -- keep parsing exactly as they always have.
func ExtractWorkerResult(logs string) (WorkerResult, error) {
	var markerLine string
	for _, line := range strings.Split(logs, "\n") {
		if rest, ok := strings.CutPrefix(line, ResultMarker); ok {
			markerLine = rest
		}
	}

	body := markerLine
	if body == "" {
		body = strings.TrimSpace(logs)
	}

	var result WorkerResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return WorkerResult{}, fmt.Errorf("did not contain a valid result: %w (output: %.200s)", err, logs)
	}
	return result, nil
}
