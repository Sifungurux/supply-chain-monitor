package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getenvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

// buildPostgresDSN assembles a "postgres://..." connection string from
// individual POSTGRES_* env vars. POSTGRES_DSN, if set, wins outright --
// an escape hatch for anyone who wants to hand a full connection string
// with query params this helper doesn't know about. Split out from
// main() so it's unit-testable without a real database (see
// main_test.go).
func buildPostgresDSN() string {
	if dsn := os.Getenv("POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	host := getenv("POSTGRES_HOST", "scm-postgres.supply-chain-monitor.svc.cluster.local")
	port := getenv("POSTGRES_PORT", "5432")
	user := getenv("POSTGRES_USER", "monitor_api")
	pass := os.Getenv("POSTGRES_PASSWORD")
	db := getenv("POSTGRES_DB", "monitor_api")
	sslmode := getenv("POSTGRES_SSLMODE", "disable")

	query := "sslmode=" + sslmode

	// pgxpool honors pool_max_conns/pool_min_conns as DSN query params
	// (see NewPostgresStore, which just hands this string straight to
	// pgxpool.New) -- left unset by default (0) so anyone running this
	// binary directly (README, "Running monitor-api outside a
	// Kubernetes pod") gets pgxpool's own untouched default (currently
	// max(4, runtime.NumCPU()*4) max conns, 0 min conns), same as
	// before this existed. The chart (values.yaml's
	// monitorApi.postgres.pool) sets real, deliberate values for the
	// in-cluster deployment instead of leaving them at that CPU-derived
	// default, which has no relationship at all to Postgres's own
	// max_connections limit or to how many other things (other
	// monitor-api replicas, if this ever scales beyond one) share it.
	if maxConns := getenvInt("POSTGRES_POOL_MAX_CONNS", 0); maxConns > 0 {
		query += fmt.Sprintf("&pool_max_conns=%d", maxConns)
	}
	if minConns := getenvInt("POSTGRES_POOL_MIN_CONNS", 0); minConns > 0 {
		query += fmt.Sprintf("&pool_min_conns=%d", minConns)
	}

	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, pass),
		Host:     fmt.Sprintf("%s:%s", host, port),
		Path:     "/" + db,
		RawQuery: query,
	}
	return u.String()
}

// connectStoreWithRetry retries NewPostgresStore with a fixed backoff.
// Postgres and monitor-api start up concurrently in Kubernetes -- the
// Percona pod can easily still be initializing its data directory (or
// just not Ready yet) the first few times this pod tries to connect.
// Failing fast and letting Kubernetes restart the whole pod would work
// too, but retrying in-process avoids a crash-loop-backoff delay on
// every fresh cluster bring-up.
func connectStoreWithRetry(ctx context.Context, dsn string, attempts int, delay time.Duration) (*artifact.PostgresStore, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		store, err := artifact.NewPostgresStore(ctx, dsn)
		if err == nil {
			return store, nil
		}
		lastErr = err
		log.Printf("postgres not ready yet (attempt %d/%d): %v", i+1, attempts, err)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", attempts, lastErr)
}

func main() {
	// `monitor-api scan-worker` is the same binary running in a
	// different mode: a single, one-shot unpack+malware-scan of one
	// image artifact, then exit -- no HTTP server, no Postgres
	// connection. This is what IsolatedUnpackerScanner
	// (internal/scanner/isolated_unpacker.go) runs as a Kubernetes Job
	// per scan, instead of calling UnpackerScanner directly inside the
	// long-running API server process. See docs/architecture.md
	// ("Isolating the unpack+scan step").
	if len(os.Args) > 1 && os.Args[1] == "scan-worker" {
		runScanWorker()
		return
	}
	runAPIServer()
}

// runScanWorker scans exactly one artifact (SCM_SCAN_REF) and prints
// the result as JSON (scanner.WorkerResult) to stdout, then exits.
// Intended to run inside a short-lived, minimally-privileged
// Kubernetes Job pod (see
// charts/supply-chain-monitor/templates/monitor-api/rbac.yaml,
// IsolatedUnpackerScanner, and IsolatedTrivyScanner), not as a
// long-running process.
//
// SCM_TRIVY_MODE selects which scan this invocation actually runs:
// unset (the default) means the original unpack+ClamAV malware scan;
// "image" or "sbom" means a trivy CVE scan instead (IsolatedTrivyScanner
// sets this). Both trivy modes reuse TrivyScanner/SBOMScanner as-is --
// the only thing that changes for the isolated path is TrivyDBConfig
// pointing at the read-only shared cache mount instead of trivy's own
// default location, and always skipping DB updates (see below).
//
// A scan error (couldn't pull the image, clamd unreachable, etc.) is
// reported *inside* the printed JSON (WorkerResult.Error), and the
// process still exits 0 -- the Job "succeeding" means "the worker ran
// and reported something," which keeps both isolated scanners' Job-
// completion handling to a single, simple path. Only a genuine setup
// failure (missing SCM_SCAN_REF, can't reach clamd's config, can't
// write the result) exits non-zero, since there's nothing meaningful
// to report in that case.
func runScanWorker() {
	ref := os.Getenv("SCM_SCAN_REF")
	if ref == "" {
		fmt.Fprintln(os.Stderr, "scan-worker: SCM_SCAN_REF is required")
		os.Exit(2)
	}

	// See scanner.VerboseScanLogs's own comment for what this actually
	// changes. Set once, at the very top, before any scanner runs --
	// every CLI-wrapping Scanner in the scanner package checks this
	// package-level variable directly rather than taking it as a
	// constructor argument.
	scanner.VerboseScanLogs = getenvBool("SCM_SCAN_VERBOSE", false)

	// Matches the scan timeout the API server itself used to apply
	// in-process (see internal/api/handlers.go) -- the Job's own
	// activeDeadlineSeconds (the Job template built in internal/k8sjob,
	// scoped by charts/supply-chain-monitor/templates/monitor-api/rbac.yaml's Role) is set a
	// little longer than this as a
	// backstop, so this context timeout is what actually fires first
	// in the normal case.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var findings []artifact.Finding
	var scanErr error

	switch trivyMode := os.Getenv("SCM_TRIVY_MODE"); trivyMode {
	case "image", "sbom":
		// The shared trivy-db-cache PVC (see
		// charts/supply-chain-monitor/templates/monitor-api/trivy-db-cache-pvc.yaml)
		// is mounted read-only here -- freshness is entirely the primer
		// Job/refresh CronJob's job, not this worker's, so DB updates
		// are always skipped regardless of TRIVY_SKIP_DB_UPDATE (that
		// env var only governs the separate in-process fallback path,
		// see runAPIServer's trivyDB). SkipDBUpdate/SkipJavaDBUpdate
		// forced true rather than read from env also means a scan never
		// wastes time on a network round-trip that would fail anyway
		// against a read-only mount.
		trivyDB := scanner.TrivyDBConfig{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
			CacheDir:         getenv("TRIVY_CACHE_DIR", "/trivy-cache"),
		}
		if trivyMode == "image" {
			findings, scanErr = scanner.NewTrivyScanner("", trivyDB).Scan(ctx, ref)
		} else {
			// sbom mode: ref may be an OCI registry reference (scm-registry
			// by default), not a path already inside this pod -- unlike
			// "image" mode, where trivy resolves ref itself, this Job has
			// no access to whatever monitor-api's own pod might have
			// already fetched (different pod, different filesystem), so
			// it fetches its own copy first via the same RegistryFetcher
			// the in-process path uses (internal/scanner/fetch.go). See
			// docs/architecture.md ("Isolating SBOM trivy scanning").
			fetcher := scanner.NewRegistryFetcher(getenvBool("FETCH_PLAIN_HTTP", true))
			path, cleanup, fetchErr := fetcher.Fetch(ctx, ref)
			defer cleanup()
			if fetchErr != nil {
				scanErr = fmt.Errorf("fetch sbom artifact %q: %w", ref, fetchErr)
			} else {
				findings, scanErr = scanner.NewSBOMScanner(trivyDB).Scan(ctx, path)
			}
		}
	default:
		clamAddr := getenv("CLAMAV_ADDR", "")
		unpackerBin := getenv("UNPACKER_BIN", "unpacker")
		unpackerInsecure := getenvBool("UNPACKER_INSECURE", true)
		unpackerPublic := getenvBool("UNPACKER_PUBLIC", true)
		unpackerMaxFileMB := getenvInt("UNPACKER_MAX_FILE_MB", 100)

		s := scanner.NewUnpackerScanner(clamAddr, unpackerBin, unpackerInsecure, unpackerPublic, int64(unpackerMaxFileMB)*1024*1024)
		findings, scanErr = s.Scan(ctx, ref)
	}

	result := scanner.WorkerResult{Findings: findings}
	if scanErr != nil {
		result.Error = scanErr.Error()
	}

	// Printed with scanner.ResultMarker as a prefix, not a bare
	// json.Encoder.Encode, so IsolatedTrivyScanner/IsolatedUnpackerScanner
	// (via scanner.ExtractWorkerResult) can find this exact line even
	// when SCM_SCAN_VERBOSE also has trivy's or unpacker's own progress
	// output mixed into the same pod log stream -- Kubernetes pod logs
	// are a single combined stdout+stderr stream, so without this anchor
	// any extra output written by a verbose scan (or even just
	// cleanScanCache's own log.Printf on a cleanup failure, which
	// already bit this project once before VerboseScanLogs existed --
	// see trivy.go's Scan) could land ahead of or after the real result
	// and break a naive whole-body JSON parse.
	resultJSON, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan-worker: failed to marshal result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s%s\n", scanner.ResultMarker, resultJSON)
}

// buildImageScanners picks both halves of the `image` artifact type's
// scanner list -- the CVE scanner (trivy) and the malware scanner
// (unpack + ClamAV) -- consistently: the isolated, Kubernetes-Job-per-
// scan path for both by default, or the in-process fallback for both
// when DISABLE_SCAN_ISOLATION is set. A single flag governing both
// scanners keeps "isolation is on" vs. "isolation is off" one coherent
// mental model instead of two independently-toggleable ones (see
// DISABLE_SCAN_ISOLATION's own comment in runAPIServer). Split out from
// runAPIServer specifically so this decision is unit-testable
// (main_test.go) without needing a real Kubernetes API client or a
// real trivy binary -- none of the four scanner arguments is ever
// actually invoked by this function, just selected.
func buildImageScanners(disableScanIsolation bool, trivyInProcess, trivyIsolated, inProcessUnpacker, isolatedUnpacker scanner.Scanner) []scanner.Scanner {
	if disableScanIsolation {
		return []scanner.Scanner{trivyInProcess, inProcessUnpacker}
	}
	return []scanner.Scanner{trivyIsolated, isolatedUnpacker}
}

// buildSBOMScanners picks the sbom artifact type's single scanner the
// same way buildImageScanners picks image's two: the isolated,
// Kubernetes-Job-per-scan path by default, or the in-process
// FetchingScanner+SBOMScanner fallback under DISABLE_SCAN_ISOLATION.
// Split out for the same reason buildImageScanners is: unit-testable
// (main_test.go) without needing a real Kubernetes API client.
func buildSBOMScanners(disableScanIsolation bool, inProcess, isolated scanner.Scanner) []scanner.Scanner {
	if disableScanIsolation {
		return []scanner.Scanner{inProcess}
	}
	return []scanner.Scanner{isolated}
}

// registerExternalScanners adds each operator-configured external
// scanner (EXTERNAL_SCANNERS -- see internal/scanner/external.go and
// docs/architecture.md, "Pluggable external scanners") into reg, once
// per artifact type it names. Additive, not replacing: this appends
// alongside whatever built-in scanners already exist for that type
// (e.g. registering a Grype-backed scanner against "image" doesn't
// remove trivy), the same way Registry already supports more than one
// scanner per type -- see buildImageScanners just above for the
// existing image/malware precedent.
//
// file/sbom/sarif registrations get wrapped in FetchingScanner,
// exactly like the built-in ClamAV/SBOM/SARIF scanners just above in
// runAPIServer, since ref for those types may be an OCI registry
// reference rather than a path already inside this pod. image
// registrations are left unwrapped: an external CVE scanner plugged in
// for images is expected to resolve an OCI ref itself, the same way
// trivy/unpacker already do -- wrapping it in FetchingScanner would
// hand it a single fetched blob path instead of the image reference it
// actually needs.
//
// Split out from runAPIServer specifically so the validation and
// per-type wrapping decision is unit-testable (main_test.go) without
// invoking any external command -- registerExternalScanners itself
// never calls Scan().
func registerExternalScanners(reg scanner.Registry, specs []scanner.ExternalScannerConfig, fetcher scanner.Fetcher) error {
	for _, spec := range specs {
		if spec.Name == "" {
			return fmt.Errorf("external scanner config missing required \"name\"")
		}
		if spec.Command == "" {
			return fmt.Errorf("external scanner %q missing required \"command\"", spec.Name)
		}
		if len(spec.ArtifactTypes) == 0 {
			return fmt.Errorf("external scanner %q must list at least one artifactType", spec.Name)
		}

		var s scanner.Scanner = scanner.NewExternalScanner(spec)
		for _, at := range spec.ArtifactTypes {
			t := artifact.Type(at)
			if !t.Valid() {
				return fmt.Errorf("external scanner %q: %q is not a valid artifactType (must be one of image, file, sbom, sarif)", spec.Name, at)
			}
			registered := s
			if t != artifact.TypeImage {
				registered = scanner.NewFetchingScanner(fetcher, s)
			}
			reg[t] = append(reg[t], registered)
		}
	}
	return nil
}

func runAPIServer() {
	listenAddr := getenv("LISTEN_ADDR", ":8080")
	clamAddr := getenv("CLAMAV_ADDR", "")
	registryAddr := getenv("REGISTRY_ADDR", "")
	stagesEnv := getenv("PIPELINE_STAGES", "source,build,test,scan,sign,publish,deploy")

	// unpacker (github.com/Sifungurux/unpacker) config, passed through
	// to each scan-worker Job's env -- see IsolatedUnpackerScanner.
	// Defaults assume a local, unauthenticated, plain-HTTP dev registry
	// (scm-registry); tighten these before pointing at anything else.
	unpackerBin := getenv("UNPACKER_BIN", "unpacker")
	unpackerInsecure := getenvBool("UNPACKER_INSECURE", true)
	unpackerPublic := getenvBool("UNPACKER_PUBLIC", true)
	unpackerMaxFileMB := getenvInt("UNPACKER_MAX_FILE_MB", 100)

	// trivy vulnerability DB config. Empty repository strings mean
	// "trivy's own default" (public ghcr.io/mirror.gcr.io) -- fine with
	// normal internet access. For an air-gapped cluster, seed a mirror
	// with cluster/seed-trivy-db.sh and point these at it (see README).
	trivyDB := scanner.TrivyDBConfig{
		DBRepository:     getenv("TRIVY_DB_REPOSITORY", ""),
		JavaDBRepository: getenv("TRIVY_JAVA_DB_REPOSITORY", ""),
		SkipDBUpdate:     getenvBool("TRIVY_SKIP_DB_UPDATE", false),
		SkipJavaDBUpdate: getenvBool("TRIVY_SKIP_JAVA_DB_UPDATE", false),
	}

	stages := strings.Split(stagesEnv, ",")
	for i := range stages {
		stages[i] = strings.TrimSpace(stages[i])
	}

	// Fail closed: no default, no "insecure mode" fallback. Every
	// request (except /healthz) must carry this as
	// `Authorization: Bearer <API_KEY>` -- see internal/api/router.go's
	// withAuth. Sourced from a Secret
	// (charts/supply-chain-monitor/templates/monitor-api/auth-secret.yaml), the same pattern
	// already used for POSTGRES_PASSWORD.
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatalf("API_KEY is required and was not set")
	}

	// Artifacts are persisted in Postgres (Percona Distribution for
	// PostgreSQL, deployed via charts/supply-chain-monitor/templates/postgres/) rather than in-memory --
	// see docs/architecture.md for why. artifact.MemStore still exists
	// and backs this package's own unit tests plus internal/api's
	// handler tests, but production always talks to a real database.
	ctx := context.Background()
	dsn := buildPostgresDSN()
	store, err := connectStoreWithRetry(ctx, dsn, 12, 5*time.Second)
	if err != nil {
		log.Fatalf("could not connect to postgres: %v", err)
	}

	stageTracker := pipeline.NewTracker(stages)

	// file/sbom/sarif artifacts can now be OCI registry references
	// (scm-registry by default), not just paths already sitting inside
	// this pod -- FetchingScanner below pulls them via `oras pull`
	// first. image artifacts don't need this: unpacker and trivy both
	// already fetch the image themselves. See internal/scanner/fetch.go.
	fetchPlainHTTP := getenvBool("FETCH_PLAIN_HTTP", true)
	fetcher := scanner.NewRegistryFetcher(fetchPlainHTTP)

	// Governs how much of trivy's/unpacker's own progress output ends up
	// visible in scan-worker Job pod logs -- see scanner.VerboseScanLogs's
	// own comment. Off by default: most of the time the only thing worth
	// seeing is the final findings/error. Set directly here for the
	// in-process fallback path (disableScanIsolation below runs in this
	// same process), and forwarded into each isolated scanner's config
	// below to become that Job's own SCM_SCAN_VERBOSE -- a Job is a
	// separate process with a fresh environment, so it has to be told
	// again at its own startup (see runScanWorker).
	verboseScanLogs := getenvBool("SCAN_WORKER_VERBOSE_LOGS", false)
	scanner.VerboseScanLogs = verboseScanLogs

	// Image malware scanning (unpack + ClamAV) and image CVE scanning
	// (trivy) both normally run in their own short-lived Kubernetes Job
	// per scan, not in this process -- see IsolatedUnpackerScanner,
	// IsolatedTrivyScanner, and docs/architecture.md ("Isolating the
	// unpack+scan step" and "Isolating Trivy scanning"). That requires a
	// real Kubernetes API client, which requires this pod to actually
	// have a ServiceAccount token
	// (charts/supply-chain-monitor/templates/monitor-api/serviceaccount.yaml -- deliberately
	// flipped to automountServiceAccountToken: true for exactly this,
	// scoped down tightly via charts/supply-chain-monitor/templates/monitor-api/rbac.yaml's
	// Role) -- which a bare
	// `docker run` outside any cluster does not have.
	//
	// DISABLE_SCAN_ISOLATION restores the ability to run this binary
	// that way, for quick local iteration: it skips
	// k8sjob.NewInClusterClient entirely (so its own log.Fatalf on a
	// missing ServiceAccount token never fires) and falls back to
	// running UnpackerScanner and TrivyScanner directly in-process,
	// exactly like before the isolation work landed. Left at its
	// default (isolation stays on) for every real deployment in k8s/ --
	// this is a deliberate, documented downgrade of the hardening in
	// "Isolating the unpack+scan step"/"Isolating Trivy scanning" for
	// local dev convenience, not something to flip on anywhere the pod
	// might see untrusted image content beyond a throwaway local
	// registry. See docs/architecture.md and README's "Running
	// monitor-api outside a Kubernetes pod".
	disableScanIsolation := getenvBool("DISABLE_SCAN_ISOLATION", false)
	inProcessUnpacker := scanner.NewUnpackerScanner(clamAddr, unpackerBin, unpackerInsecure, unpackerPublic, int64(unpackerMaxFileMB)*1024*1024)
	inProcessTrivy := scanner.NewTrivyScanner(registryAddr, trivyDB)

	// SCAN_WORKER_ACTIVE_DEADLINE_SECONDS bounds how long Kubernetes lets
	// each scan-worker Job's pod run before killing it outright (both the
	// unpacker and trivy Job shapes -- see IsolatedUnpackerConfig/
	// IsolatedTrivyConfig's own ActiveDeadlineSeconds comment). Raise this
	// for a cluster that's routinely scanning heavier images (more OS
	// packages for trivy to walk/query -- e.g. mysql/postgres-sized
	// images) and/or running many scans concurrently, where per-Job
	// scheduling delay and CPU contention both push real runtime up.
	// SCAN_TIMEOUT_SECONDS is the API handler's own overall per-scan
	// budget (see internal/api/handlers.go's scanArtifact/scanTimeout) --
	// it must stay comfortably above the value above, or this handler
	// routinely reports "context deadline exceeded" before Kubernetes'
	// own ActiveDeadlineSeconds would even have killed a genuinely stuck
	// Job, which looks identical to a real hang but is actually just a
	// legitimately slow scan running out of a budget that was never long
	// enough for it. Validated (not silently clamped) so a misconfigured
	// pair fails loudly at startup instead of surfacing as confusing,
	// intermittent scan timeouts under load.
	scanWorkerActiveDeadlineSeconds := getenvInt("SCAN_WORKER_ACTIVE_DEADLINE_SECONDS", 600)
	scanTimeoutSeconds := getenvInt("SCAN_TIMEOUT_SECONDS", 660)
	if scanTimeoutSeconds <= scanWorkerActiveDeadlineSeconds {
		log.Fatalf("SCAN_TIMEOUT_SECONDS (%ds) must be greater than SCAN_WORKER_ACTIVE_DEADLINE_SECONDS (%ds) -- otherwise a scan gets reported as timed out before Kubernetes would even kill a genuinely stuck scan-worker Job", scanTimeoutSeconds, scanWorkerActiveDeadlineSeconds)
	}
	scanTimeout := time.Duration(scanTimeoutSeconds) * time.Second

	var isolatedUnpacker scanner.Scanner
	var isolatedTrivyImage scanner.Scanner
	var isolatedTrivySBOM scanner.Scanner
	if !disableScanIsolation {
		k8sClient, err := k8sjob.NewInClusterClient()
		if err != nil {
			log.Fatalf("could not create kubernetes client for scan-worker jobs: %v (set DISABLE_SCAN_ISOLATION=true to run without one -- see README)", err)
		}
		workerImage := getenv("SCAN_WORKER_IMAGE", "monitor-api:dev")
		isolatedUnpacker = scanner.NewIsolatedUnpackerScanner(k8sClient, scanner.IsolatedUnpackerConfig{
			Image:                 workerImage,
			ClamAddr:              clamAddr,
			UnpackerBin:           unpackerBin,
			UnpackerInsecure:      unpackerInsecure,
			UnpackerPublic:        unpackerPublic,
			UnpackerMaxFileMB:     unpackerMaxFileMB,
			VerboseLogs:           verboseScanLogs,
			ActiveDeadlineSeconds: int64(scanWorkerActiveDeadlineSeconds),
		})
		// Shares the same Kubernetes API client and worker image as
		// isolatedUnpacker above -- both are just different scan-worker
		// Job shapes the same monitor-api binary runs. See
		// IsolatedTrivyScanner's comment for why the DB cache is a
		// separately-refreshed PVC rather than downloaded per scan.
		isolatedTrivyImage = scanner.NewIsolatedTrivyScanner(k8sClient, scanner.IsolatedTrivyConfig{
			Image:                 workerImage,
			SubCommand:            "image",
			CacheClaimName:        getenv("TRIVY_CACHE_CLAIM", "scm-trivy-db-cache"),
			CacheMountPath:        getenv("TRIVY_CACHE_DIR", "/trivy-cache"),
			VerboseLogs:           verboseScanLogs,
			ActiveDeadlineSeconds: int64(scanWorkerActiveDeadlineSeconds),
		})
		// Same again for sbom-type artifacts (see docs/architecture.md,
		// "Isolating SBOM trivy scanning") -- FetchPlainHTTP is set here
		// (unlike isolatedTrivyImage above) because this Job has to fetch
		// the SBOM document itself before scanning it; see
		// IsolatedTrivyConfig.FetchPlainHTTP's own comment and
		// runScanWorker's "sbom" case for where that actually happens.
		isolatedTrivySBOM = scanner.NewIsolatedTrivyScanner(k8sClient, scanner.IsolatedTrivyConfig{
			Image:                 workerImage,
			SubCommand:            "sbom",
			CacheClaimName:        getenv("TRIVY_CACHE_CLAIM", "scm-trivy-db-cache"),
			CacheMountPath:        getenv("TRIVY_CACHE_DIR", "/trivy-cache"),
			FetchPlainHTTP:        fetchPlainHTTP,
			VerboseLogs:           verboseScanLogs,
			ActiveDeadlineSeconds: int64(scanWorkerActiveDeadlineSeconds),
		})
	} else {
		log.Printf("DISABLE_SCAN_ISOLATION=true: image malware scanning, trivy CVE scanning, and sbom trivy scanning will all run in-process, not in isolated Jobs -- see README, \"Running monitor-api outside a Kubernetes pod\"")
	}

	scanners := scanner.Registry{
		// image artifacts get both a CVE scan (trivy) and a malware scan
		// (unpack + ClamAV) -- both isolated into their own scan-worker
		// Job by default, both falling back in-process together under
		// DISABLE_SCAN_ISOLATION. See buildImageScanners.
		artifact.TypeImage: buildImageScanners(disableScanIsolation, inProcessTrivy, isolatedTrivyImage, inProcessUnpacker, isolatedUnpacker),
		artifact.TypeFile: {
			scanner.NewFetchingScanner(fetcher, scanner.NewClamAVScanner(clamAddr)),
		},
		// trivy sbom shares the same air-gapped DB-mirror config as the
		// image scanner above -- see internal/scanner/sbom.go. Isolated
		// into its own scan-worker Job by default now too (see
		// docs/architecture.md, "Isolating SBOM trivy scanning"): that
		// Job fetches its own copy of the SBOM (runScanWorker's "sbom"
		// case) rather than relying on a local path only this pod could
		// see, exactly mirroring how the in-process fallback below
		// (FetchingScanner+SBOMScanner, used under
		// DISABLE_SCAN_ISOLATION) already fetches it itself.
		artifact.TypeSBOM: buildSBOMScanners(disableScanIsolation, scanner.NewFetchingScanner(fetcher, scanner.NewSBOMScanner(trivyDB)), isolatedTrivySBOM),
		// SARIF is parsed, not re-scanned -- see internal/scanner/sarif.go.
		artifact.TypeSARIF: {
			scanner.NewFetchingScanner(fetcher, scanner.NewSARIFScanner()),
		},
	}

	// Operator-configured external scanners (a different CVE scanner
	// than trivy, a different SBOM tool, ...) on top of the built-in
	// ones above -- see docs/architecture.md ("Pluggable external
	// scanners") and README. Unset/empty by default, so nothing changes
	// for anyone not using this.
	if externalScannersEnv := getenv("EXTERNAL_SCANNERS", ""); externalScannersEnv != "" {
		var specs []scanner.ExternalScannerConfig
		if err := json.Unmarshal([]byte(externalScannersEnv), &specs); err != nil {
			log.Fatalf("EXTERNAL_SCANNERS is not valid JSON: %v", err)
		}
		if err := registerExternalScanners(scanners, specs, fetcher); err != nil {
			log.Fatalf("invalid EXTERNAL_SCANNERS config: %v", err)
		}
	}

	// Per-key request throttling -- see internal/api/ratelimit.go and
	// router.go's withRateLimit. RATE_LIMIT_RPS <= 0 (the default, 0)
	// disables it outright, since a lot of deployments (small clusters,
	// local dev, a single trusted CI caller) have no real need for this
	// and it shouldn't surprise anyone by throttling requests they never
	// asked to be throttled.
	rateLimitRPS := getenvFloat("RATE_LIMIT_RPS", 0)
	rateLimitBurst := getenvFloat("RATE_LIMIT_BURST", 0)

	// Best-effort duplicate-registration detection (see
	// internal/api/handlers.go's resolveDigest) -- oras is already baked
	// into this image (Dockerfile), the same binary fetcher above uses.
	// fetchPlainHTTP is the same flag already computed for fetcher, not
	// a second config surface -- see NewRouter's own comment for why
	// image refs never use it regardless of this setting.
	digestResolver := scanner.NewOrasDigestResolver()

	router := api.NewRouter(store, stageTracker, scanners, apiKey, rateLimitRPS, rateLimitBurst, digestResolver, fetchPlainHTTP, scanTimeout)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("monitor-api listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
