package scanner

import (
	"context"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Scanner turns an artifact reference into a list of findings (CVEs,
// malware signatures, etc.).
type Scanner interface {
	Scan(ctx context.Context, ref string) ([]artifact.Finding, error)
}

// BucketAffinity is an optional interface a Scanner can implement to
// declare that it only ever produces findings for one specific bucket
// ("cve", "malware", "misconfiguration", "secret", or "other" -- the
// same vocabulary the API layer's classifyBucket sorts findings into).
// scanArtifact (internal/api/handlers.go) uses this to gate
// fix-detection per bucket instead of globally across the whole scan:
// today, one scanner erroring blocks fix-detection for every bucket,
// even ones that scanner could never have touched (a ClamAV failure
// blocking CVE fix-detection, say). A scanner that declares its bucket
// here only blocks that one bucket if it errors.
//
// Deliberately opt-in, not part of Scanner itself: a scanner that can
// legitimately return findings across more than one bucket in a single
// call (SARIFScanner, or a PluggableScanner whose wire contract lets
// each finding set its own category independently of any configured
// default) has no single honest answer to give here -- claiming one
// anyway risks a real false "fixed" if it's wrong, which is worse than
// today's coarse-but-safe behavior. Scanners like that simply don't
// implement this interface, and scanArtifact falls back to blocking
// every bucket on their failure, exactly as it did before this existed.
type BucketAffinity interface {
	Bucket() string
}

// ArtifactAwareScanner is an optional interface a Scanner can implement
// to also receive the ID of the artifact being scanned, not just its
// ref. Scan(ctx, ref) alone is enough for every scanner that only ever
// needs to know *what* to scan -- but IsolatedTrivyScanner's
// scan-worker Job also generates SBOM/SARIF documents (see
// documents.go) that need to be uploaded back to monitor-api associated
// with a specific artifact, and the Job has no other way to learn that
// artifact's ID (it only ever receives ref -- see main.go's
// runScanWorker). scanArtifact (internal/api/handlers.go) type-asserts
// for this the same optional-capability way it already does for
// BucketAffinity above, and calls ScanForArtifact instead of Scan when
// available -- every other Scanner implementation is unaffected and
// doesn't need to implement this.
type ArtifactAwareScanner interface {
	Scanner
	ScanForArtifact(ctx context.Context, ref, artifactID string) ([]artifact.Finding, error)
}

// Registry maps an artifact type to the scanners that apply to it. An
// artifact type can have more than one scanner registered against it --
// e.g. a container image gets both a CVE scan (Trivy) and a malware
// scan (unpack + ClamAV) -- the API handler tells their results apart
// downstream via Finding.Source rather than by type.
type Registry map[artifact.Type][]Scanner

func (r Registry) For(t artifact.Type) ([]Scanner, bool) {
	s, ok := r[t]
	return s, ok
}

// VerboseScanLogs, when true, makes every CLI-wrapping scanner in this
// package (TrivyScanner, SBOMScanner, UnpackerScanner) additionally
// stream the underlying tool's own stdout/stderr to this process's real
// stderr as it runs, on top of whatever this package already captures
// for parsing/error messages. Off by default: normally the only thing
// worth seeing is the final result (findings or an error), and
// trivy/unpacker's own step-by-step progress output is just noise once
// a scan is working correctly.
//
// This exists for one real, recurring need: diagnosing a scan that's
// slow, silently stuck, or failing in a way the final error alone
// doesn't explain -- being able to `kubectl logs` a scan-worker Job
// pod and see trivy's own scan steps, or unpacker's oras/crane pull
// attempts, as they happen, instead of only the pass/fail result after
// the fact.
//
// A package-level variable, not a per-scanner constructor argument,
// deliberately: every CLI-wrapping Scanner in this package needs to
// check it, and threading a bool through every constructor (several of
// which are called from multiple places in main.go, and are also
// exercised directly in tests with no interest in this setting) would
// be a lot of plumbing for what's really one global "how noisy should
// scan-worker Jobs be" knob. See main.go's runScanWorker (sets this
// from the SCM_SCAN_VERBOSE env var each Job's own process reads at
// startup) and runAPIServer (reads SCAN_WORKER_VERBOSE_LOGS once, sets
// this directly for the in-process fallback path under
// DISABLE_SCAN_ISOLATION, and forwards it into each isolated scanner's
// config to become that Job's own SCM_SCAN_VERBOSE).
//
// Tests that care about args()'s exact output reset this to false
// explicitly rather than relying on it already being false, since it's
// shared, mutable package state -- see TestTrivyScanner_Args.
var VerboseScanLogs bool
