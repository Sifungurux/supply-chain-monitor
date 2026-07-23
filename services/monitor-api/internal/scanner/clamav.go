package scanner

import (
	"context"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// ClamAVScanner scans a single local file (the `file` artifact type)
// against a clamd instance over the INSTREAM protocol.
//
// v1 stub: `ref` is expected to already be a filesystem path reachable
// from the monitor-api pod (e.g. a shared volume, or a path the
// artifact was downloaded to beforehand). See UnpackerScanner for the
// `image` artifact equivalent, which fetches and unpacks the artifact
// itself before scanning it this same way, file by file.
type ClamAVScanner struct {
	addr string
}

func NewClamAVScanner(addr string) *ClamAVScanner {
	return &ClamAVScanner{addr: addr}
}

// Bucket implements BucketAffinity: every finding this scanner produces
// is hardcoded to Source: "clamav" a few lines below, which
// classifyBucket always maps to "malware" -- so a failure here can only
// ever have blocked malware fix-detection, never any other bucket.
func (c *ClamAVScanner) Bucket() string { return "malware" }

func (c *ClamAVScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	result, err := scanFileWithClamd(ctx, c.addr, ref)
	if err != nil {
		return nil, err
	}
	if !result.Found {
		return nil, nil
	}
	return []artifact.Finding{{
		ID:       "clamav-signature-match",
		Severity: "critical",
		Title:    result.Signature,
		Source:   "clamav",
	}}, nil
}
