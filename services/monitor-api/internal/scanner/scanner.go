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
// call (SARIFScanner, or an ExternalScanner whose wire contract lets
// each finding set its own category independently of any configured
// default) has no single honest answer to give here -- claiming one
// anyway risks a real false "fixed" if it's wrong, which is worse than
// today's coarse-but-safe behavior. Scanners like that simply don't
// implement this interface, and scanArtifact falls back to blocking
// every bucket on their failure, exactly as it did before this existed.
type BucketAffinity interface {
	Bucket() string
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
