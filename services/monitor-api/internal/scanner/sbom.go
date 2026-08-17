package scanner

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// SBOMScanner shells out to `trivy sbom` to scan a CycloneDX or SPDX
// SBOM document for known CVEs in the components it lists. It shares
// TrivyDBConfig with TrivyScanner (trivy.go) since `trivy sbom` pulls
// the same vulnerability DB as `trivy image` and accepts the same
// --db-repository/--skip-db-update air-gapped-mirror flags -- see
// cluster/seed-trivy-db.sh and README's "Air-gapped operation".
//
// v1 stub: ref is assumed to already be a filesystem path reachable
// inside the monitor-api pod -- the same simplification `file`-type
// artifacts already make (see ClamAVScanner and docs/architecture.md's
// Roadmap). There's no fetch step for either yet.
type SBOMScanner struct {
	db TrivyDBConfig
}

func NewSBOMScanner(db TrivyDBConfig) *SBOMScanner {
	return &SBOMScanner{db: db}
}

// Bucket implements BucketAffinity: parseTrivyReport (shared with
// TrivyScanner) always sets Source: "trivy" -- classifyBucket's default
// case, "cve".
//
// Stays SINGLE-bucket even though the shared parser now also walks
// Results[].Secrets[]. `trivy sbom` has no secret scanner -- an SBOM
// lists packages, it contains no files to search -- so that loop
// decodes zero entries here. Declaring "secret" as well would mean an
// SBOM-scan failure blocks secret fix-detection for a bucket this
// scanner can never contribute to.
func (s *SBOMScanner) Bucket() string { return "cve" }

// args builds the trivy CLI invocation. Split out from Scan for the
// same reason TrivyScanner.args is: unit-testable without running
// trivy (see sbom_test.go).
func (s *SBOMScanner) args(ref string) []string {
	args := []string{"sbom"}
	args = append(args, verbosityArgs()...)
	args = append(args, "--format", "json")
	args = append(args, dbArgs(s.db)...)
	args = append(args, ref)
	return args
}

func (s *SBOMScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	// See TrivyScanner.Scan's identical (and identically-guarded) call
	// in trivy.go for the full reasoning: trivy's local scan-cache
	// grows unbounded per distinct input scanned otherwise, and this
	// shares that same cache with `trivy image` -- but only when
	// CacheDir is unset (the in-process path). When it's set
	// (IsolatedTrivyScanner's scan-worker Job), --cache-backend memory
	// already means there's nothing on disk to clean, and the cleanup
	// attempt itself fails against the Job's read-only root filesystem,
	// corrupting the WorkerResult JSON runScanWorker prints to stdout
	// with a stray log line on the same combined log stream.
	if s.db.CacheDir == "" {
		defer cleanScanCache()
	}

	cmd := exec.CommandContext(ctx, "trivy", s.args(ref)...)

	var stdout, stderr bytes.Buffer
	if VerboseScanLogs {
		// See TrivyScanner.Scan's identical teeing -- same reasoning
		// (os.Stderr only, os.Stdout stays reserved for the final
		// ResultMarker line).
		cmd.Stdout = io.MultiWriter(&stdout, os.Stderr)
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	if err := cmd.Run(); err != nil {
		return nil, wrapTrivyScanError("trivy sbom scan", ref, err, stderr.String())
	}

	return parseTrivyReport(stdout.Bytes())
}
