package scanner

import "strings"

// ClassifyScanError maps a scan-error string -- already cleaned by
// wrapTrivyScanError where that applies, or raw text from a scan-worker
// Job orchestration failure, a panic, or a pre-scan fetch failure -- to
// a stable reason code and a short, non-raw message safe to show a
// user. scan.go:scanArtifact is the single point every one of
// those origins converges on (see its own comment for why), so this is
// the only place that needs to know all of them.
//
// Ordered predicate list, first match wins, most specific first -- the
// same shape wrapTrivyScanError itself already uses one layer down, so
// adding a new failure mode later is a one-line addition here, not a
// new framework.
func ClassifyScanError(raw string) (reason, message string) {
	for _, c := range classifiers {
		if c.match(raw) {
			return c.reason, c.message
		}
	}
	return "unknown", "Scan failed (see server logs for details)"
}

// ReasonRank orders reason codes by specificity, lowest (most specific)
// first, matching classifiers' own ordering -- for a caller (currently
// only scan.go:scanArtifact) picking a single representative reason
// when an artifact's several scanners fail for different reasons in the
// same round. "unknown" always ranks last, whether or not it's the
// literal string ClassifyScanError's fallback returns.
func ReasonRank(reason string) int {
	for i, c := range classifiers {
		if c.reason == reason {
			return i
		}
	}
	return len(classifiers)
}

var classifiers = []struct {
	match           func(string) bool
	reason, message string
}{
	{
		match:   func(s string) bool { return strings.Contains(s, "not found in the registry") },
		reason:  "not_found",
		message: "Artifact not found in the registry",
	},
	{
		match: func(s string) bool {
			return strings.Contains(s, "registry authentication failed") || isRegistryAuthFailure(s)
		},
		reason:  "registry_auth_failed",
		message: "Scanner could not authenticate to the registry",
	},
	{
		match:   func(s string) bool { return strings.Contains(s, "unsupported artifact type") },
		reason:  "unsupported_artifact",
		message: "This artifact type isn't supported by the scanner",
	},
	{
		match:   func(s string) bool { return strings.Contains(s, "timed out waiting for") },
		reason:  "scan_timeout",
		message: "Scan timed out",
	},
	{
		match:   func(s string) bool { return strings.Contains(s, "crashed or was killed before producing a result") },
		reason:  "scan_crashed",
		message: "Scan crashed or was killed before completing (likely out of memory)",
	},
	{
		match: func(s string) bool {
			return strings.Contains(s, "create trivy scan job for") ||
				strings.Contains(s, "create scan job for") ||
				strings.Contains(s, "find pod for finished") ||
				strings.Contains(s, "read logs for") ||
				strings.Contains(s, "did not contain a valid result")
		},
		reason:  "scan_infra_error",
		message: "Could not run the scan (cluster infrastructure error)",
	},
	{
		match:   func(s string) bool { return strings.Contains(s, "fetch sbom artifact") },
		reason:  "fetch_failed",
		message: "Could not fetch the artifact to scan",
	},
	{
		match:   func(s string) bool { return strings.Contains(s, "scanner panicked:") },
		reason:  "scanner_error",
		message: "Scanner encountered an internal error",
	},
}
