package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// GrypeSBOMScanner shells out to grype to scan a CycloneDX or SPDX SBOM
// document for known CVEs in the components it lists -- grype's SBOM
// counterpart to GrypeScanner (grype.go), the same way SBOMScanner
// (sbom.go) is trivy's. Shares GrypeDBConfig since the DB cache is
// identical regardless of source type.
//
// v1 stub: ref is assumed to already be a filesystem path reachable
// inside the monitor-api pod -- same simplification SBOMScanner makes.
type GrypeSBOMScanner struct {
	db GrypeDBConfig
}

func NewGrypeSBOMScanner(db GrypeDBConfig) *GrypeSBOMScanner {
	return &GrypeSBOMScanner{db: db}
}

// Bucket implements BucketAffinity: parseGrypeVulnerabilities (shared
// with GrypeScanner) always sets Source: "grype" -- classifyBucket's
// default case, "cve".
func (s *GrypeSBOMScanner) Bucket() string { return "cve" }

// args builds the grype CLI invocation. "sbom:" is grype's documented
// source prefix for reading a Syft-format JSON document from disk (see
// `grype --help`).
func (s *GrypeSBOMScanner) args(ref string) []string {
	args := []string{"sbom:" + ref, "-o", "json"}
	if GrypeByCVE {
		// See scanner.GrypeByCVE for why this matters here.
		args = append(args, "--by-cve")
	}
	if VerboseScanLogs {
		args = append(args, "-vv")
	} else {
		args = append(args, "-q")
	}
	return args
}

func (s *GrypeSBOMScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	cmd := exec.CommandContext(ctx, "grype", s.args(ref)...)
	cmd.Env = append(os.Environ(), s.db.env()...)

	var stdout, stderr bytes.Buffer
	if VerboseScanLogs {
		cmd.Stdout = io.MultiWriter(&stdout, os.Stderr)
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("grype sbom scan failed for %q: %w (%s)", ref, err, stderr.String())
	}

	return parseGrypeVulnerabilities(stdout.Bytes())
}
