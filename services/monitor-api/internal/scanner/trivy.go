package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
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

// Bucket implements BucketAffinity: every finding comes from
// parseTrivyVulnerabilities, which always sets Source: "trivy" --
// classifyBucket's default case, "cve".
func (t *TrivyScanner) Bucket() string { return "cve" }

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

// verbosityArgs returns trivy's own progress/log-output flag: "--quiet"
// normally, or "--debug" when VerboseScanLogs is set. Shared between
// TrivyScanner.args (here) and SBOMScanner.args (sbom.go) so `trivy
// image` and `trivy sbom` can never drift out of sync on this.
func verbosityArgs() []string {
	if VerboseScanLogs {
		return []string{"--debug"}
	}
	return []string{"--quiet"}
}

// args builds the trivy CLI invocation. Split out from Scan so the
// DB-mirror flag wiring can be unit-tested (internal/scanner/trivy_test.go)
// without actually running trivy.
func (t *TrivyScanner) args(ref string) []string {
	args := []string{"image"}
	args = append(args, verbosityArgs()...)
	args = append(args, "--format", "json")
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
	output, err := t.ScanRaw(ctx, ref)
	if err != nil {
		return nil, err
	}
	return parseTrivyVulnerabilities(output)
}

// ScanWithRaw is Scan plus the raw report ScanRaw returns, from a
// single trivy invocation -- runScanWorker's image-mode branch
// (main.go) needs both: the parsed findings every other caller gets
// from Scan, and the raw report to derive SBOM/SARIF documents from via
// GenerateImageDocuments. Every other caller keeps using Scan/ScanRaw
// individually; this exists only so that one caller doesn't have to
// scan twice to get both outputs.
func (t *TrivyScanner) ScanWithRaw(ctx context.Context, ref string) ([]artifact.Finding, []byte, error) {
	raw, err := t.ScanRaw(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	findings, err := parseTrivyVulnerabilities(raw)
	if err != nil {
		return nil, raw, err
	}
	return findings, raw, nil
}

// ScanRaw runs the same `trivy image --format json` invocation as Scan,
// returning trivy's raw JSON report bytes before any parsing -- split
// out so runScanWorker's image-mode branch (main.go) can also derive an
// SBOM/SARIF document from the same report via `trivy convert` (see
// GenerateImageDocuments in documents.go), without a second scan. Scan
// above is unchanged in behavior: it still runs this exact invocation
// and just discards the raw bytes after parsing, the same as before
// this was split out.
func (t *TrivyScanner) ScanRaw(ctx context.Context, ref string) ([]byte, error) {
	// Confirmed on a real cluster: without this, trivy's local
	// per-image analysis cache grows by roughly one entry per distinct
	// image scanned, forever (trivy has no automatic eviction for it),
	// eventually exceeding monitor-api's own pod's ephemeral-storage
	// limit and getting the whole pod kubelet-evicted -- not a
	// scan-worker Job, since TrivyScanner (unlike the unpacker+ClamAV
	// path) still runs in-process. See cleanScanCache's own comment.
	//
	// Only when CacheDir is unset, though -- CacheDir being set means
	// this is IsolatedTrivyScanner's scan-worker Job, which already
	// passes --cache-backend memory (see TrivyDBConfig.CacheDir's
	// comment), so there's no on-disk scan cache to clean in the first
	// place. Confirmed on a real cluster that skipping this check was a
	// real bug, not just an unnecessary call: `trivy clean --scan-cache`
	// tried to touch trivy's *default* cache location (not the mounted
	// --cache-dir), which sits on the scan-worker Job's deliberately
	// read-only root filesystem, so the cleanup itself failed every
	// time -- and cleanScanCache's log.Printf about that failure landed
	// on the same combined stdout+stderr stream runScanWorker's
	// WorkerResult JSON is printed to, which IsolatedTrivyScanner reads
	// back via the pod's logs expecting *only* that one JSON document.
	// The stray log line broke the parse outright ("unparseable
	// output"), not just added noise.
	if t.db.CacheDir == "" {
		defer cleanScanCache()
	}

	cmd := exec.CommandContext(ctx, "trivy", t.args(ref)...)

	var stdout, stderr bytes.Buffer
	if VerboseScanLogs {
		// Tee everything trivy writes to this process's real stderr
		// too, so `kubectl logs` on the scan-worker Job pod shows
		// trivy's own progress as it happens -- see VerboseScanLogs's
		// comment. Deliberately os.Stderr for both streams, never
		// os.Stdout: os.Stdout is reserved for the one
		// ResultMarker-prefixed line runScanWorker prints right before
		// it exits (see workerresult.go), so this process's own stdout
		// stays clean of anything else regardless of how noisy trivy
		// itself gets.
		cmd.Stdout = io.MultiWriter(&stdout, os.Stderr)
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	if err := cmd.Run(); err != nil {
		return nil, wrapTrivyScanError("trivy scan", ref, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// wrapTrivyScanError turns a failed trivy invocation into the error
// Scan returns. Most failures get trivy's raw stderr included verbatim
// -- an unfamiliar failure is exactly when the extra detail is worth
// keeping, even at the cost of some noise -- but "manifest unknown"
// (trivy's registry client couldn't find the requested tag/digest at
// all) is common enough, and unhelpful enough in its raw form, to
// special-case.
//
// The raw form is genuinely bad: trivy tries docker, containerd, podman,
// and the remote registry in turn before giving up, so a single missing
// tag prints three irrelevant "socket not found" lines (expected noise
// in an isolated scan-worker Job, which deliberately has none of those
// runtimes -- see IsolatedTrivyScanner's own comment) ahead of the one
// line that actually matters. None of that plumbing detail helps
// whoever's reading the error decide what to do next; "this ref doesn't
// exist in the registry, go check it" does. This is a real, recurring
// case in practice, not a hypothetical -- registries retag and remove
// images over time (see docs/architecture.md, "Bulk-registering
// artifacts" for a concrete example this project hit).
//
// label distinguishes TrivyScanner's "trivy scan" from SBOMScanner's
// "trivy sbom scan" (sbom.go shares this same function) so the message
// still says which of the two actually failed, without either caller
// needing to double-wrap the other's message.
func wrapTrivyScanError(label, ref string, err error, stderr string) error {
	if strings.Contains(stderr, "MANIFEST_UNKNOWN") && strings.Contains(stderr, "Failed to fetch") {
		return fmt.Errorf("%s failed for %q: image tag or digest not found in the registry -- check that the ref is correct and the tag still exists (it may have been removed, retagged, or replaced upstream)", label, ref)
	}
	return fmt.Errorf("%s failed for %q: %w (%s)", label, ref, err, stderr)
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
