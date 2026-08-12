package scanner

import (
	"context"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// ClamAVScanner scans a single local file (the `file` artifact type)
// against a clamd instance over the INSTREAM protocol.
//
// `ref` here is a path, not a registry reference: FetchingScanner has
// already turned one into the other. It must be a path this scanner is
// permitted to open -- a fetched artifact, or one inside the operator's
// declared LOCAL_ARTIFACT_ROOT (see localpath.go) -- which Scan checks
// itself rather than assuming, because this runs in-process, in
// monitor-api's own pod. See UnpackerScanner for the `image` artifact
// equivalent, which fetches and unpacks the artifact itself before
// scanning it this same way, file by file.
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
	// Checked here rather than in scanFileWithClamd, which
	// UnpackerScanner also calls -- with paths from its own extraction
	// directory, which is not an artifact ref and has no business being
	// held to this rule. This is the ref-facing entry point, so this is
	// where a ref-shaped path gets refused. See ensureScannablePath.
	if err := ensureScannablePath(ref); err != nil {
		return nil, err
	}
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
