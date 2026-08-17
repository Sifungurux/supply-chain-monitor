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

// wireFinding carries a Finding across the worker->parent hop WITHOUT
// losing Category.
//
// artifact.Finding.Category is `json:"-"`, deliberately: it is a
// transient bucket-routing hint, and in the API and in storage the
// bucket is expressed by WHICH list a finding is in, so serializing it
// there would be redundant state that could contradict its own
// container. That tag is right everywhere it applies and wrong in
// exactly one place -- here. This is an internal wire format between
// two processes of the same binary, and it is the only hop where the
// hint has to survive serialization, because the parent has nothing
// else to route by: it never sees the tool output the worker parsed.
//
// Found in production, not in review. `trivy image --scanners
// vuln,secret` detected six secrets in a real image, the worker
// classified every one of them correctly, and all six arrived at the
// parent with an empty Category -- so classifyBucket fell through to
// Source "trivy", its default case, and filed them as CVEs. Nothing
// errored. The only symptom was six findings with "secret:" IDs
// sitting in the CVE bucket.
//
// This is NOT specific to secrets. MalcontentScanner sets
// Category "malware" with Source "malcontent", which classifyBucket
// has no case for -- so isolated malcontent findings would have been
// filed as CVEs the same way. They had produced no findings on this
// cluster yet, so it had never shown up.
type wireFinding struct {
	artifact.Finding
	// Shadows the embedded Finding's json:"-" Category -- the outer,
	// shallower field is the one encoding/json uses.
	Category string `json:"category,omitempty"`
}

// wireResult is WorkerResult's actual JSON shape. A separate type, so
// the Marshal/Unmarshal methods below cannot recurse into themselves.
type wireResult struct {
	Findings []wireFinding `json:"findings"`
	Error    string        `json:"error,omitempty"`
}

// MarshalJSON keeps the on-the-wire document identical to what it has
// always been, plus a per-finding "category" where one is set.
func (r WorkerResult) MarshalJSON() ([]byte, error) {
	out := wireResult{Error: r.Error}
	if r.Findings != nil {
		out.Findings = make([]wireFinding, 0, len(r.Findings))
		for _, f := range r.Findings {
			out.Findings = append(out.Findings, wireFinding{Finding: f, Category: f.Category})
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON restores Category onto each Finding. A document
// written by an older worker simply has no "category" key, and those
// findings decode with an empty one -- exactly the behavior before
// this existed, so a parent on a new binary can still read a Job that
// somehow started on an old one.
func (r *WorkerResult) UnmarshalJSON(b []byte) error {
	var in wireResult
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	r.Error = in.Error
	r.Findings = nil
	if in.Findings != nil {
		r.Findings = make([]artifact.Finding, 0, len(in.Findings))
		for _, wf := range in.Findings {
			f := wf.Finding
			f.Category = wf.Category
			r.Findings = append(r.Findings, f)
		}
	}
	return nil
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
