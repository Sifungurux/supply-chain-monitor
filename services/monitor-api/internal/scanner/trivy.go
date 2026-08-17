package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

// Buckets implements MultiBucketAffinity: `trivy image` runs with
// --scanners vuln,secret (see args), so one invocation legitimately
// produces findings in two buckets -- CVEs and exposed secrets.
//
// Declaring only "cve" here would not merely be imprecise, it would be
// unsafe: on a trivy failure the secret bucket would stay unblocked and
// MergeFindings would mark every previously-open secret "fixed" purely
// because the scan that finds them didn't run.
//
// Note this is the IMAGE scanner. SBOMScanner (sbom.go) shares the
// parser below but runs `trivy sbom`, which has no secret scanner at
// all, and correctly still declares plain "cve".
func (t *TrivyScanner) Buckets() []string { return []string{"cve", "secret"} }

type trivyReport struct {
	Results []struct {
		// Target names what this result block is about -- for an image
		// scan, the package source ("app/Gemfile.lock") or, for secret
		// results, the file the secret was found in. Part of the secret
		// finding ID below, since a RuleID on its own is not unique.
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
		} `json:"Vulnerabilities"`
		// Secrets is populated only by `trivy image --scanners secret`.
		// Absent from `trivy sbom` output entirely, which is why
		// SBOMScanner can share this type and this parser unchanged --
		// it simply decodes zero of them.
		Secrets []struct {
			RuleID   string `json:"RuleID"`
			Severity string `json:"Severity"`
			Title    string `json:"Title"`
			// Category is TRIVY's own grouping ("AWS", "GitHub", ...),
			// NOT artifact.Finding.Category, which is this project's
			// bucket vocabulary and must be exactly "secret" here. The
			// two names collide and mean completely different things;
			// trivy's goes into the title for context instead.
			Category  string `json:"Category"`
			StartLine int    `json:"StartLine"`
		} `json:"Secrets"`
	} `json:"Results"`
}

// secretFindingID builds the stable, unique ID a secret finding is
// tracked by.
//
// MergeFindings (internal/artifact/merge.go) matches findings BY ID to
// decide what is new, still open, or newly fixed -- so a non-unique ID
// is not a cosmetic problem. RuleID alone is not unique: one rule
// ("aws-access-key-id") routinely fires on several files in one image,
// and every one of those would collapse into a single finding whose
// severity and title flip-flopped between scans depending on decode
// order.
//
// Target and line are both needed: the same rule can fire twice in one
// file. The cost is that a secret which MOVES within a file reads as
// one finding fixed and a new one opened -- accepted deliberately,
// because the alternative (dropping the line) silently merges two real,
// separate secrets into one, and because a moved line means a rebuilt
// image anyway.
func secretFindingID(target, ruleID string, startLine int) string {
	return fmt.Sprintf("secret:%s:%s:%d", target, ruleID, startLine)
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
	// Secret scanning alongside the vulnerability scan, in ONE trivy
	// invocation -- an image is pulled and unpacked once either way, so
	// a second pass for secrets would double the expensive part to
	// re-read files trivy already has open.
	//
	// Naming "vuln" explicitly is required, not decorative: --scanners
	// REPLACES the default set rather than adding to it, so
	// "--scanners secret" alone would silently stop reporting CVEs --
	// a scan that keeps succeeding while every vulnerability quietly
	// disappears, and MergeFindings marking them all "fixed".
	//
	// Deliberately NOT in dbArgs/verbosityArgs, which sbom.go shares:
	// `trivy sbom` has no secret scanner (there are no files in an
	// SBOM to scan) and rejects it. See TestSBOMScanner_ArgsHaveNoSecretScanner.
	args = append(args, "--scanners", "vuln,secret")
	args = append(args, dbArgs(t.db)...)
	// "--" ends flag parsing, so even a ref that somehow reached here
	// without passing ValidateRef is treated as a positional argument
	// rather than a flag. Belt and braces: the actual fix is the
	// leading-"-" rejection in refvalidate.go. Verified this tool
	// accepts the separator before adding it.
	args = append(args, "--", ref)
	return args
}

// parseTrivyReport decodes trivy's `--format json` output (shared by
// `trivy image` and `trivy sbom` -- both use the same Results[] shape)
// into normalized Findings. Split out from Scan so it's unit-testable
// against canned JSON without needing the real trivy binary (see
// trivy_test.go).
//
// Walks both Results[].Vulnerabilities[] and Results[].Secrets[]. The
// latter is only ever populated by `trivy image --scanners secret`, so
// `trivy sbom` decodes zero of them and SBOMScanner's behavior is
// unchanged by sharing this -- which is why this stayed one parser
// rather than becoming two.
func parseTrivyReport(output []byte) ([]artifact.Finding, error) {
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
		for _, s := range result.Secrets {
			// Category is set EXPLICITLY here, unlike the
			// vulnerabilities above. classifyBucket
			// (internal/api/scan.go) falls back to Source when Category
			// is empty, and Source "trivy" lands in its default case --
			// "cve". Without this one field every exposed secret would
			// be filed as a CVE.
			findings = append(findings, artifact.Finding{
				ID:       secretFindingID(result.Target, s.RuleID, s.StartLine),
				Severity: s.Severity,
				Title:    secretTitle(s.Title, s.Category, result.Target),
				Source:   "trivy",
				Category: "secret",
			})
		}
	}
	return findings, nil
}

// secretTitle composes the human-readable title for a secret finding.
//
// The ID is machine-shaped (see secretFindingID) and the dashboard
// shows the title, so the file has to appear here -- otherwise a row
// reads "AWS Access Key ID" with no indication of WHERE the key is,
// which is the first thing anyone acting on it needs.
//
// trivy's own Category ("AWS", "GitHub") is appended when it is not
// already implied by the title, since it groups rules usefully and is
// otherwise dropped entirely (artifact.Finding.Category is taken, and
// means something else).
func secretTitle(title, category, target string) string {
	if title == "" {
		title = "exposed secret"
	}
	if category != "" && !strings.Contains(strings.ToLower(title), strings.ToLower(category)) {
		title = fmt.Sprintf("%s (%s)", title, category)
	}
	if target != "" {
		title = fmt.Sprintf("%s in %s", title, target)
	}
	return title
}

func (t *TrivyScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	output, err := t.ScanRaw(ctx, ref)
	if err != nil {
		return nil, err
	}
	return parseTrivyReport(output)
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
	findings, err := parseTrivyReport(raw)
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
	// Validated HERE rather than in Scan, because Scan is not the only
	// way in: ScanWithRaw calls this too, and that is the path the
	// scan-worker Job uses (main.go's runScanWorker) -- a process the
	// API handler's own check never runs in. This is the one function
	// that turns the ref into a trivy argument, so it is the one that
	// has to be sure of it. Same reasoning as Fetch/Resolve.
	if err := ValidateRef(ctx, ref); err != nil {
		return nil, err
	}
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
	// time -- and cleanScanCache's log line about that failure landed
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
// keeping, even at the cost of some noise -- but two shapes are common
// enough, and unhelpful enough in raw form, to special-case: the ref
// simply doesn't exist, or the registry rejected the pull outright.
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
// The not-found check matches trivy's own "unable to find the
// specified image ... in [docker containerd podman remote]" summary
// line directly, rather than requiring the stricter (and narrower)
// "MANIFEST_UNKNOWN"+"Failed to fetch" pair the remote leg happens to
// use for one specific underlying registry error code. That pair is
// kept as a second, OR'd condition rather than removed: it's the one
// combination that can appear on its own outside this summary line (see
// TestWrapTrivyScanError_ManifestUnknown), so dropping it would be a
// silent regression for that shape even though every case it covers
// today already implies the summary line too. A bare, unqualified ref
// (e.g. "cosign:latest" instead of "docker.io/library/cosign:latest")
// hits the broader summary-line match without ever producing a
// MANIFEST_UNKNOWN error at all -- the remote leg fails to resolve the
// ref to a registry in the first place, a different underlying error
// this narrower pair was never going to catch.
//
// The auth check runs first, and deliberately does not get folded into
// the not-found match even though both can appear alongside the same
// summary line once Part C's registry auth lands: a pull rejected for
// bad/missing credentials is a completely different fix (check the
// configured registry credentials) from a pull that failed because the
// ref genuinely doesn't exist (check the ref itself) and must not be
// conflated into "not found" just because trivy's own wording happens
// to overlap.
//
// label distinguishes TrivyScanner's "trivy scan" from SBOMScanner's
// "trivy sbom scan" (sbom.go shares this same function) so the message
// still says which of the two actually failed, without either caller
// needing to double-wrap the other's message.
func wrapTrivyScanError(label, ref string, err error, stderr string) error {
	switch {
	case isRegistryAuthFailure(stderr):
		return fmt.Errorf("%s failed for %q: registry authentication failed -- check the configured registry credentials", label, ref)
	case strings.Contains(stderr, "unable to find the specified image") ||
		(strings.Contains(stderr, "MANIFEST_UNKNOWN") && strings.Contains(stderr, "Failed to fetch")):
		return fmt.Errorf("%s failed for %q: image tag or digest not found in the registry -- check that the ref is correct and the tag still exists (it may have been removed, retagged, or replaced upstream)", label, ref)
	default:
		return fmt.Errorf("%s failed for %q: %w (%s)", label, ref, err, stderr)
	}
}

// isRegistryAuthFailure recognizes the standard Docker Distribution
// token-auth rejection wording ("UNAUTHORIZED: authentication
// required", a bare "401 Unauthorized", etc.) inside a scan failure's
// stderr. Case-insensitive since trivy, the registry, and any
// intermediate proxy don't agree on capitalization.
func isRegistryAuthFailure(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "unauthorized") || strings.Contains(lower, "401 ")
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
		slog.Warn("trivy clean --scan-cache failed (non-fatal, scan result unaffected -- but the scan cache will keep growing until this succeeds)",
			"scanner", "trivy", "output", string(out), "err", err)
	}
}

// Kind implements ScanKind: this scanner is capped independently of
// the global scan cap via SCAN_CONCURRENCY_TRIVY.
func (s *TrivyScanner) Kind() string { return "trivy" }
