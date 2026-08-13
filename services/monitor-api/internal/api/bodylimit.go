package api

import (
	"errors"
	"net/http"
)

// Request body ceilings for the JSON write endpoints. Every one of
// these decodes attacker-controllable input straight into memory, and
// monitor-api runs with a 256Mi memory limit (see the chart's
// monitorApi.resources), so an unbounded POST is a plausible OOM rather
// than a theoretical one.
//
// The existing per-entry caps do NOT cover this: maxBulkArtifacts (500)
// and the findings-array validation are both checked AFTER
// json.Decode has already read the whole body into memory. They bound
// the logical size of a request, not the bytes spent getting there.
// ReadTimeout (main.go) bounds how LONG a body may take to arrive, not
// how large it may be -- a fast client on a cluster network can deliver
// a great deal inside 15s.
//
// Sizes are deliberately generous: these exist to stop something
// pathological, not to police ordinary payloads. Anything rejected here
// is far outside what a real caller sends.
const (
	// maxSmallJSONBytes covers the endpoints that take a handful of
	// short string fields (register one artifact, set a stage, set
	// maintainer info). 64KiB is roughly a thousand times the largest
	// realistic such request.
	maxSmallJSONBytes = 64 << 10

	// maxBulkArtifactsBytes covers POST /artifacts/bulk. At
	// maxBulkArtifacts (500) entries of ref+type+digest+maintainer, a
	// real request is tens of KB; testdata/bulk-test-images.json's 95
	// entries are ~6KB. 4MiB leaves room for unusually long refs and
	// full maintainer metadata on every entry.
	maxBulkArtifactsBytes = 4 << 20

	// maxFindingsBytes covers POST /artifacts/{id}/findings, which
	// accepts an unbounded findings array from an external system --
	// the largest JSON body this API takes. A scan of a large image can
	// legitimately produce thousands of findings (debian:11 alone
	// yielded 101; a full SARIF import is larger), so this is the one
	// that most needs room. 16MiB is well above any real submission and
	// well below what would threaten the pod.
	maxFindingsBytes = 16 << 20

	// maxVEXBytes covers POST /artifacts/{id}/vex. A VEX document is a
	// list of human-written assessments, not scanner output -- one
	// statement per vulnerability somebody actually triaged -- so real
	// documents are KB, not MB. 4MiB is thousands of statements, far
	// past any document a person maintains, and deliberately much
	// smaller than the 64MiB SBOM/SARIF ceiling: those carry a whole
	// image's component inventory, this carries opinions about it.
	maxVEXBytes = 4 << 20
)

// limitBody caps how much of a request body will be read, and reports
// whether the request may proceed. On a body over the limit it writes
// 413 rather than the 400 a decode failure would otherwise produce:
// "your JSON is malformed" and "your JSON is too big" are different
// problems, and a caller retrying the first forever because it was told
// the wrong one is a bad afternoon.
//
// Must be called before the body is read.
func limitBody(w http.ResponseWriter, r *http.Request, limit int64) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

// bodyTooLarge reports whether an error from reading/decoding a body is
// MaxBytesReader's limit being hit, as opposed to malformed input.
// http.MaxBytesError landed in Go 1.19; before it, this could only be
// done by matching an error string.
func bodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

// writeBodyError answers a body read/decode failure with the right
// status: 413 when the body exceeded its ceiling, 400 when it was
// simply not valid.
func writeBodyError(w http.ResponseWriter, err error, badRequestMsg string) {
	if bodyTooLarge(err) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, badRequestMsg)
}
