package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

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

	// CacheDir points trivy at a specific --cache-dir instead of its
	// default (~/.cache/trivy). Empty for every in-process caller
	// (TrivyScanner/SBOMScanner run directly inside monitor-api's own
	// pod) -- those keep using trivy's own default cache location plus
	// cleanScanCache to bound its growth. Set only by
	// IsolatedTrivyScanner (isolated_trivy.go), which mounts a shared,
	// centrally-refreshed PersistentVolumeClaim holding the
	// vulnerability DB, read-only, into each scan-worker Job.
	//
	// Whenever this is set, dbArgs also adds --cache-backend memory.
	// trivy's vulnerability DB is opened read-only, so many concurrent
	// scan-worker Jobs can safely share it -- but trivy's separate scan
	// cache (the per-image/SBOM analysis-results cache, a different
	// thing from the DB -- see cleanScanCache's comment) is a BoltDB
	// file that only one process can hold open at a time. Forcing the
	// scan cache into process-memory instead of a file under the same
	// --cache-dir sidesteps that lock entirely, and needs no cleanup
	// afterwards since nothing is ever written to disk for it -- this
	// is trivy's own documented "Solution 1 (Recommended)" for running
	// concurrent scans (https://trivy.dev/docs/latest/guide/references/troubleshooting/,
	// "Cache lock errors").
	CacheDir string
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
	if db.CacheDir != "" {
		args = append(args, "--cache-dir", db.CacheDir, "--cache-backend", "memory")
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
	// Confirmed on a real cluster: without this, trivy's local
	// per-image analysis cache grows by roughly one entry per distinct
	// image scanned, forever (trivy has no automatic eviction for it),
	// eventually exceeding monitor-api's own pod's ephemeral-storage
	// limit and getting the whole pod kubelet-evicted -- not a
	// scan-worker Job, since TrivyScanner (unlike the unpacker+ClamAV
	// path) still runs in-process. See cleanScanCache's own comment.
	defer cleanScanCache()

	cmd := exec.CommandContext(ctx, "trivy", t.args(ref)...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy scan failed for %q: %w (%s)", ref, err, stderr.String())
	}

	return parseTrivyVulnerabilities(stdout.Bytes())
}

// cleanScanCache purges trivy's local image/SBOM analysis cache (the
// "scan cache" -- NOT the vulnerability DB, which deliberately stays
// warm across scans via TrivyDBConfig/dbArgs above) after every scan,
// success or failure. `trivy clean --scan-cache` is trivy's supported
// way to do this as of v0.53 (it replaced the older `--clear-cache`/
// `--reset` flags, which were removed as breaking changes -- see
// https://trivy.dev/docs/latest/references/configuration/cli/trivy_clean/).
//
// Deliberately runs on its own fresh context.Background(), not the
// Scan call's ctx -- the same reasoning IsolatedUnpackerScanner's Job
// cleanup already relies on (see isolated_unpacker.go): ctx may already
// be canceled or past its deadline by the time a scan finishes, and
// cleanup needs to run regardless of what happened to the caller.
// Any failure here is logged, never returned -- a cache-cleanup problem
// is not the scan's problem, and must never mask or override a real
// scan result/error.
func cleanScanCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "trivy", "clean", "--scan-cache").CombinedOutput(); err != nil {
		log.Printf("trivy clean --scan-cache failed (non-fatal, scan result unaffected -- but the scan cache will keep growing until this succeeds): %v (%s)", err, string(out))
	}
}
