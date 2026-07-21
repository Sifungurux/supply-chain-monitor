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
