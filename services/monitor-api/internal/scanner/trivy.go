package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// TrivyDBConfig configures where trivy pulls its vulnerability
// databases from. trivy's DB (and the separate Java DB) are themselves
// distributed as OCI artifacts (ghcr.io/aquasecurity/trivy-db:2,
// ghcr.io/aquasecurity/trivy-java-db:1 by default) -- for an
// air-gapped deployment, mirror those into a registry the cluster can
// actually reach (e.g. scm-registry, via cluster/seed-trivy-db.sh
// while still online) and point this config at that mirror instead.
// See docs/architecture.md and the README's air-gapped section.
type TrivyDBConfig struct {
	DBRepository     string // "" = trivy's own default (public ghcr.io/mirror.gcr.io)
	JavaDBRepository string // "" = trivy's own default
	SkipDBUpdate     bool   // once a DB is cached/mirrored locally, stop trying to reach the public default
	SkipJavaDBUpdate bool
}

// TrivyScanner shells out to the trivy CLI (installed into the
// monitor-api image, see Dockerfile) to scan an OCI image reference for
// known CVEs.
//
// v1 stub: runs trivy in standalone mode directly against the image
// ref. A future iteration should point this at a shared trivy-server
// deployment to avoid re-downloading the vulnerability DB per pod, and
// should also cover SBOM inputs (`trivy sbom`) so sbom-type artifacts
// get real CVE findings instead of metadata-only handling.
type TrivyScanner struct {
	registryAddr string
	db           TrivyDBConfig
}

func NewTrivyScanner(registryAddr string, db TrivyDBConfig) *TrivyScanner {
	return &TrivyScanner{registryAddr: registryAddr, db: db}
}

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// dbArgs builds the shared DB-mirror flags both `trivy image` (this
// file) and `trivy sbom` (sbom.go) accept identically -- extracted so
// SBOMScanner doesn't duplicate this logic, and so it's independently
// unit-testable.
func dbArgs(db TrivyDBConfig) []string {
	var args []string
	if db.DBRepository != "" {
		args = append(args, "--db-repository", db.DBRepository)
	}
	if db.JavaDBRepository != "" {
		args = append(args, "--java-db-repository", db.JavaDBRepository)
	}
	if db.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	if db.SkipJavaDBUpdate {
		args = append(args, "--skip-java-db-update")
	}
	return args
}

// args builds the trivy CLI invocation. Split out from Scan so the
// DB-mirror flag wiring can be unit-tested (internal/scanner/trivy_test.go)
// without actually running trivy.
func (t *TrivyScanner) args(ref string) []string {
	args := []string{"image", "--quiet", "--format", "json"}
	args = append(args, dbArgs(t.db)...)
	args = append(args, ref)
	return args
}

// parseTrivyVulnerabilities decodes trivy's `--format json` output
// (shared by `trivy image` and `trivy sbom` -- both use the same
// Results[].Vulnerabilities[] shape) into normalized Findings. Split
// out from Scan so it's unit-testable against canned JSON without
// needing the real trivy binary (see trivy_test.go).
func parseTrivyVulnerabilities(output []byte) ([]artifact.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var findings []artifact.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, artifact.Finding{
				ID:       v.VulnerabilityID,
				Severity: v.Severity,
				Title:    v.Title,
				Source:   "trivy",
			})
		}
	}
	return findings, nil
}

func (t *TrivyScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	cmd := exec.CommandContext(ctx, "trivy", t.args(ref)...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy scan failed for %q: %w (%s)", ref, err, stderr.String())
	}

	return parseTrivyVulnerabilities(stdout.Bytes())
}
