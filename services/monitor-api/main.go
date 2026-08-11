package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
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

// httpWriteTimeout bounds how long a handler has to write its response
// once the request's headers have been read. Named (not an inline
// literal on the http.Server below) because it's a real ceiling on
// other things: api.DefaultScanQueueWait has to fit inside it, or a
// queued scan's 429 races this deadline and the client sees a dropped
// connection instead of a status code -- see that constant's own
// comment, and TestScanQueueWaitFitsInsideWriteTimeout.
//
// Note this also caps every *successful* synchronous scan response: a
// scan that takes longer than this completes server-side (it runs on
// context.Background()) but its caller never receives the result. That
// predates the scan queue and is a bigger design question than a
// timeout value -- see docs/architecture.md's known limitations.
const httpWriteTimeout = 30 * time.Second

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

// buildDockerConfigJSON returns the docker CLI config.json content (an
// "auths" map, the same shape ~/.docker/config.json uses) unpacker's
// own --config flag expects -- the file-based credential mechanism
// unpacker takes, alongside oras's --username/--password flags
// (fetch.go) and trivy's native TRIVY_USERNAME/TRIVY_PASSWORD env vars,
// all three authenticating against the same scm-registry account. See
// docs/architecture.md's registry-auth section.
func buildDockerConfigJSON(registryAddr, username, password string) []byte {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	cfg := map[string]any{
		"auths": map[string]any{
			registryAddr: map[string]string{
				"username": username,
				"password": password,
				"auth":     auth,
			},
		},
	}
	b, _ := json.Marshal(cfg) // map[string]any of only strings/maps of strings never fails to marshal
	return b
}

// writeDockerConfig writes buildDockerConfigJSON's output to a file
// named "config.json" inside a fresh temp directory, and returns that
// file's path -- unpacker's --config flag needs a real file path, not
// inline JSON. Returns "" when username is empty (the "no registry
// credentials configured" default every deployment ran under before
// registry auth existed), which UnpackerScanner treats as "don't pass
// --config at all." Called once at startup (both here in
// runAPIServer's in-process fallback and in runScanWorker's isolated
// path), not per-scan, so the temp directory is deliberately never
// cleaned up -- it lives for this process's lifetime either way (a
// long-running pod that made this decision once at boot, or a
// scan-worker Job pod that exits shortly after and takes its whole
// filesystem with it).
//
// A directory containing a file literally named "config.json", not a
// bare temp file with a random name, because grype needs that exact
// shape: pointing the DOCKER_CONFIG env var at this file's parent
// directory (see GrypeScanner.registryEnv's comment for why grype
// needs this instead of a dedicated env var) is go-containerregistry's
// default credential-helper keychain lookup, and that lookup expects
// "config.json" specifically -- confirmed against the real grype
// binary. unpacker's own --config flag is unaffected by this shape
// change: it already took a full file path either way.
func writeDockerConfig(registryAddr, username, password string) string {
	if username == "" {
		return ""
	}
	dir, err := os.MkdirTemp("", "scm-dockerconfig-*")
	if err != nil {
		log.Fatalf("create docker config temp dir: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, buildDockerConfigJSON(registryAddr, username, password), 0o600); err != nil {
		log.Fatalf("write docker config temp file: %v", err)
	}
	return path
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
	// `monitor-api sweep-registered` is a third mode this same binary
	// runs as: a one-shot pass that scans a bounded batch of artifacts
	// still sitting at status "registered" (never scanned since
	// creation), then exits. Intended to run as a Kubernetes CronJob
	// (see charts/supply-chain-monitor/templates/monitor-api/
	// sweep-registered-cronjob.yaml) on a schedule, so artifacts
	// registered without a follow-up manual/CI-triggered scan don't just
	// sit unscanned forever. See runSweepRegistered's own comment.
	if len(os.Args) > 1 && os.Args[1] == "sweep-registered" {
		runSweepRegistered()
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
// SCM_SCAN_TOOL x SCM_SCAN_MODE select which scan this invocation
// actually runs: SCM_SCAN_TOOL unset (the default) means the original
// unpack+ClamAV malware scan, regardless of SCM_SCAN_MODE; "trivy" or
// "grype" (with SCM_SCAN_MODE "image" or "sbom") means a CVE scan
// using that tool instead. Renamed from the single SCM_TRIVY_MODE env
// var (which only ever carried "image"/"sbom", trivy being the only
// CVE scanner that existed) when grype was added as a second one -- a
// clean rename, not additive, since the chart and this binary always
// deploy together in one release. Every CVE-scan branch reuses
// TrivyScanner/SBOMScanner/GrypeScanner/GrypeSBOMScanner as-is -- the
// only thing that changes for the isolated path is each tool's DB
// config pointing at its own read-only shared cache mount instead of
// its default location, and always skipping DB updates (see below).
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
	// in-process (see internal/api/scan.go) -- the Job's own
	// activeDeadlineSeconds (the Job template built in internal/k8sjob,
	// scoped by charts/supply-chain-monitor/templates/monitor-api/rbac.yaml's Role) is set a
	// little longer than this as a
	// backstop, so this context timeout is what actually fires first
	// in the normal case.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var findings []artifact.Finding
	var scanErr error

	// Always-on activity markers, deliberately separate from
	// VerboseScanLogs (see that variable's own comment) -- this isn't
	// the CLI-tool firehose meant for deep debugging, it's the minimum
	// a human `kubectl logs`-ing a scm-scan-* pod needs to confirm the
	// right tool actually started and finished, rather than staring at
	// an empty stream until the final ResultMarker line (or forever, if
	// the pod is genuinely stuck). Two lines per scan: one here before
	// dispatch, one right after the switch below once findings/scanErr
	// are settled, regardless of which branch ran.
	switch tool, mode := os.Getenv("SCM_SCAN_TOOL"), os.Getenv("SCM_SCAN_MODE"); tool {
	case "trivy":
		log.Printf("scan-worker: starting trivy scan (mode=%s) for %q", mode, ref)
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
		if mode == "image" {
			var rawReport []byte
			findings, rawReport, scanErr = scanner.NewTrivyScanner("", trivyDB).ScanWithRaw(ctx, ref)
			if scanErr == nil {
				captureImageDocuments(ctx, rawReport)
			}
		} else {
			// sbom mode: ref may be an OCI registry reference (scm-registry
			// by default), not a path already inside this pod -- unlike
			// "image" mode, where trivy resolves ref itself, this Job has
			// no access to whatever monitor-api's own pod might have
			// already fetched (different pod, different filesystem), so
			// it fetches its own copy first via the same RegistryFetcher
			// the in-process path uses (internal/scanner/fetch.go). See
			// docs/architecture.md ("Isolating SBOM trivy scanning").
			fetcher := scanner.NewRegistryFetcher(getenvBool("FETCH_PLAIN_HTTP", true), os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"))
			path, cleanup, fetchErr := fetcher.Fetch(ctx, ref)
			defer cleanup()
			if fetchErr != nil {
				scanErr = fmt.Errorf("fetch sbom artifact %q: %w", ref, fetchErr)
			} else {
				findings, scanErr = scanner.NewSBOMScanner(trivyDB).Scan(ctx, path)
			}
		}
	case "grype":
		log.Printf("scan-worker: starting grype scan (mode=%s) for %q", mode, ref)
		// grype's own counterpart to trivy-db-cache above -- see
		// charts/supply-chain-monitor/templates/monitor-api/grype-db-cache-pvc.yaml.
		// Same "always skip, freshness is the primer/refresh Job's
		// problem" reasoning.
		grypeDB := scanner.GrypeDBConfig{
			SkipDBUpdate:      true,
			SkipAgeValidation: true,
			CacheDir:          getenv("GRYPE_CACHE_DIR", "/grype-cache"),
		}
		plainHTTP := getenvBool("FETCH_PLAIN_HTTP", true)
		// Same writeDockerConfig helper the default (unpacker) branch
		// below already uses -- REGISTRY_ADDR/USERNAME/PASSWORD are the
		// same trio IsolatedGrypeScanner forwards for exactly this
		// purpose (see that type's comment). GrypeScanner/GrypeSBOMScanner
		// don't take a bare env var the way trivy's
		// TRIVY_USERNAME/PASSWORD do -- grype's registry-auth env vars
		// turned out not to actually work (see grype.go's registryEnv
		// comment), so this dockerconfig.json + DOCKER_CONFIG is the
		// real mechanism.
		dockerConfigPath := writeDockerConfig(getenv("REGISTRY_ADDR", ""), os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"))
		var dockerConfigDir string
		if dockerConfigPath != "" {
			dockerConfigDir = filepath.Dir(dockerConfigPath)
		}
		if mode == "image" {
			findings, scanErr = scanner.NewGrypeScanner(grypeDB, plainHTTP, dockerConfigDir).Scan(ctx, ref)
		} else {
			// sbom mode: same fetch-then-scan shape as trivy's sbom
			// branch above -- see that branch's comment.
			fetcher := scanner.NewRegistryFetcher(plainHTTP, os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"))
			path, cleanup, fetchErr := fetcher.Fetch(ctx, ref)
			defer cleanup()
			if fetchErr != nil {
				scanErr = fmt.Errorf("fetch sbom artifact %q: %w", ref, fetchErr)
			} else {
				findings, scanErr = scanner.NewGrypeSBOMScanner(grypeDB).Scan(ctx, path)
			}
		}
	default:
		log.Printf("scan-worker: starting malware scan (unpacker + clamav) for %q", ref)
		clamAddr := getenv("CLAMAV_ADDR", "")
		unpackerBin := getenv("UNPACKER_BIN", "unpacker")
		unpackerInsecure := getenvBool("UNPACKER_INSECURE", true)
		unpackerPublic := getenvBool("UNPACKER_PUBLIC", true)
		unpackerMaxFileMB := getenvInt("UNPACKER_MAX_FILE_MB", 100)
		dockerConfigPath := writeDockerConfig(getenv("REGISTRY_ADDR", ""), os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"))

		s := scanner.NewUnpackerScanner(clamAddr, unpackerBin, unpackerInsecure, unpackerPublic, int64(unpackerMaxFileMB)*1024*1024, dockerConfigPath)
		findings, scanErr = s.Scan(ctx, ref)
	}

	if scanErr != nil {
		log.Printf("scan-worker: scan failed: %v", scanErr)
	} else {
		log.Printf("scan-worker: scan complete, %d finding(s)", len(findings))
	}

	result := scanner.WorkerResult{Findings: findings}
	if scanErr != nil {
		result.Error = scanErr.Error()
	}

	// Printed with scanner.ResultMarker as a prefix, not a bare
	// json.Encoder.Encode, so IsolatedTrivyScanner/IsolatedUnpackerScanner
	// (via scanner.ExtractWorkerResult) can find this exact line even
	// with other output mixed into the same pod log stream -- this
	// function's own always-on activity lines above, SCM_SCAN_VERBOSE's
	// tool-progress firehose when that's also on, or even just
	// cleanScanCache's own log.Printf on a cleanup failure, which
	// already bit this project once before ResultMarker existed (see
	// trivy.go's Scan). Kubernetes pod logs are a single combined
	// stdout+stderr stream, so without this anchor any extra output
	// could land ahead of or after the real result and break a naive
	// whole-body JSON parse.
	resultJSON, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan-worker: failed to marshal result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s%s\n", scanner.ResultMarker, resultJSON)
}

// captureImageDocuments best-effort generates and uploads a CycloneDX
// SBOM and a SARIF report derived from rawReport (an "image"-mode
// scan's own raw trivy JSON, from TrivyScanner.ScanWithRaw -- see
// GenerateImageDocuments' comment for why this is a conversion, not a
// second scan). Called from runScanWorker's image branch only when the
// scan itself succeeded.
//
// A no-op, not an error, when SCM_ARTIFACT_ID/SCM_API_BASE_URL/
// SCM_API_KEY aren't all set -- IsolatedTrivyScanner.ScanForArtifact
// only sets them when a caller actually asked for document capture
// (artifactID non-empty and APIBaseURL configured -- see that method's
// comment), so a plain Scan() call (any future caller of the base
// Scanner interface) or a deployment that hasn't configured this simply
// never attempts a capture.
//
// Every failure here is logged, never fatal to the worker -- see
// GenerateImageDocuments' own "best-effort, mirroring Artifact.Digest"
// comment for the same convention applied one level up: a document
// capture problem must never affect the scan's own findings/success,
// the same way an unresolvable digest never blocks registration. Safe
// to log freely here (unlike a bare log.Printf elsewhere in this file
// pre-VerboseScanLogs, see the historical note two comments above):
// ExtractWorkerResult only ever looks at the *last* ResultMarker-
// prefixed line in the combined pod log stream, so any amount of extra
// log.Printf noise here is simply ignored, never mistaken for the real
// result.
func captureImageDocuments(ctx context.Context, rawReport []byte) {
	artifactID := os.Getenv("SCM_ARTIFACT_ID")
	apiBaseURL := os.Getenv("SCM_API_BASE_URL")
	apiKey := os.Getenv("SCM_API_KEY")
	if artifactID == "" || apiBaseURL == "" || apiKey == "" {
		return
	}

	docs, genErrs := scanner.GenerateImageDocuments(ctx, rawReport, "/tmp")
	for _, err := range genErrs {
		log.Printf("scan-worker: document generation for artifact %s: %v (non-fatal, scan result unaffected)", artifactID, err)
	}
	for _, doc := range docs {
		if err := scanner.UploadDocument(ctx, apiBaseURL, apiKey, artifactID, doc.Kind, doc.ContentType, doc.Content); err != nil {
			log.Printf("scan-worker: upload %s document for artifact %s: %v (non-fatal, scan result unaffected)", doc.Kind, artifactID, err)
		}
	}
}

// runSweepRegistered lists every artifact via monitor-api's own
// GET /api/v1/artifacts, picks up to SWEEP_BATCH_SIZE that are still
// sitting at status "registered" (oldest first), and scans each one via
// POST .../scan -- the exact same endpoint a person clicking "Scan" in
// the dashboard hits, which now also opportunistically backfills a
// missing digest (see scanArtifact's own comment in
// internal/api/scan.go). Goes through the API rather than a direct Postgres
// connection deliberately: this mirrors how scan-worker Jobs already
// call back to monitor-api's own Service (see UploadDocument) instead of
// touching the database directly, so this is the second caller of that
// same established pattern, not a new one.
//
// A scan failure for one artifact (registry down, no scanner for its
// type, etc.) is logged and skipped -- never fatal to the rest of the
// batch, the same "one bad entry shouldn't block everything else"
// reasoning bulkCreateArtifacts already uses.
func runSweepRegistered() {
	apiBase := getenv("SWEEP_API_BASE_URL", "http://monitor-api:8080")
	apiKey := os.Getenv("SWEEP_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "sweep-registered: SWEEP_API_KEY is required")
		os.Exit(2)
	}
	batchSize := getenvInt("SWEEP_BATCH_SIZE", 5)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	all, err := listRegisteredFromAPI(ctx, apiBase, apiKey)
	if err != nil {
		log.Fatalf("sweep-registered: could not list artifacts: %v", err)
	}

	// Artifacts stuck at "scanning" get reclaimed here too. A scan runs
	// in a background goroutine now (the API answers 202 immediately),
	// so a pod restart mid-scan leaves its artifact marked scanning with
	// nothing left to finish it -- invisible forever otherwise, since
	// the normal sweep only looks at "registered". Re-scanning IS the
	// reclaim: POST /scan doesn't care what the current status is, and a
	// completed scan overwrites it.
	if stale, staleErr := listStaleScanningFromAPI(ctx, apiBase, apiKey); staleErr != nil {
		log.Printf("sweep-registered: could not list stuck scans (continuing with registered artifacts only): %v", staleErr)
	} else if len(stale) > 0 {
		log.Printf("sweep-registered: %d artifact(s) stuck in %q for over %s -- reclaiming by re-scanning", len(stale), artifact.StatusScanning, staleScanningAfter)
		all = append(all, stale...)
	}

	toScan := pickArtifactsToSweep(all, batchSize)
	log.Printf("sweep-registered: %d artifact(s) registered-but-unscanned, scanning %d (SWEEP_BATCH_SIZE=%d)", countByStatus(all, artifact.StatusRegistered), len(toScan), batchSize)

	missingDigest := 0
	for _, a := range toScan {
		updated, err := scanArtifactViaAPI(ctx, apiBase, apiKey, a.ID)
		if errors.Is(err, errScanCapSaturated) {
			log.Printf("sweep-registered: %s (%s) skipped -- scan concurrency limit reached, next run retries it", a.ID, a.Ref)
			continue
		}
		if err != nil {
			log.Printf("sweep-registered: scan %s (%s) failed: %v", a.ID, a.Ref, err)
			continue
		}
		if updated.Digest == "" {
			missingDigest++
			log.Printf("sweep-registered: %s (%s) scanned, digest still not resolved", a.ID, a.Ref)
		} else {
			log.Printf("sweep-registered: %s (%s) scanned, digest resolved", a.ID, a.Ref)
		}
	}
	log.Printf("sweep-registered: done -- %d scanned, %d still missing a digest", len(toScan), missingDigest)
}

// pickArtifactsToSweep selects up to batchSize artifacts at status
// "registered", oldest (by CreatedAt) first -- so a backlog bigger than
// one batch works through fairly over successive CronJob runs instead of
// the same few newest registrations winning every time. batchSize <= 0
// means "nothing to do" (fails closed rather than defaulting to
// unbounded), the same "cap rather than trust an unbounded number"
// reasoning maxBulkArtifacts already uses in internal/api/artifacts.go.
// Pure and side-effect-free -- unit-tested in main_test.go without any
// HTTP involved, the same pattern buildImageScanners/buildSBOMScanners
// already establish for this file.
func pickArtifactsToSweep(all []artifact.Artifact, batchSize int) []artifact.Artifact {
	if batchSize <= 0 {
		return nil
	}
	var registered []artifact.Artifact
	for _, a := range all {
		if a.Status == artifact.StatusRegistered {
			registered = append(registered, a)
		}
	}
	sort.Slice(registered, func(i, j int) bool {
		return registered[i].CreatedAt.Before(registered[j].CreatedAt)
	})
	if len(registered) > batchSize {
		registered = registered[:batchSize]
	}
	return registered
}

func countByStatus(all []artifact.Artifact, status artifact.Status) int {
	n := 0
	for _, a := range all {
		if a.Status == status {
			n++
		}
	}
	return n
}

// sweepPageSize is how many artifacts one listRegisteredFromAPI page
// request asks for -- monitor-api's own maximum (see maxListLimit in
// internal/api/artifacts.go), since this is a batch job that wants the
// whole backlog in as few round trips as it can get, not a UI paging
// through it.
const sweepPageSize = 200

// listRegisteredFromAPI calls GET /api/v1/artifacts against
// monitor-api's own Service -- see runSweepRegistered's own comment for
// why this goes through the API rather than a direct Postgres
// connection.
//
// That endpoint is paginated (50 per page by default, 200 max), so this
// walks every page rather than assuming one response holds the lot:
// pickArtifactsToSweep picks the *oldest* registered artifacts, and the
// API returns newest-first, so stopping after one page would starve
// exactly the artifacts the sweep exists to get to. The status filter
// is pushed server-side, so the pages only carry rows this actually
// wants -- countByStatus over the result is still correct, it just
// counts everything now.
func listRegisteredFromAPI(ctx context.Context, apiBase, apiKey string) ([]artifact.Artifact, error) {
	return listByStatusFromAPI(ctx, apiBase, apiKey, artifact.StatusRegistered)
}

// listByStatusFromAPI walks every page of GET /api/v1/artifacts for one
// status. Paging matters: the endpoint returns 50 per page by default
// (200 max) newest-first, while pickArtifactsToSweep wants the oldest,
// so stopping after one page would starve exactly the backlog the sweep
// exists to work through.
func listByStatusFromAPI(ctx context.Context, apiBase, apiKey string, status artifact.Status) ([]artifact.Artifact, error) {
	var all []artifact.Artifact
	for offset := 0; ; {
		url := fmt.Sprintf("%s/api/v1/artifacts?status=%s&limit=%d&offset=%d",
			strings.TrimRight(apiBase, "/"), status, sweepPageSize, offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build list request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list artifacts: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("list artifacts: server returned %d: %s", resp.StatusCode, string(body))
		}
		var page struct {
			Total     int                 `json:"total"`
			Artifacts []artifact.Artifact `json:"artifacts"`
		}
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode artifact list: %w", err)
		}

		all = append(all, page.Artifacts...)
		// Advance by what actually came back, and stop on an empty page
		// regardless of what Total claims -- the only guard against
		// looping forever if the two ever disagree (they can legitimately
		// disagree mid-sweep: artifacts get registered and scanned while
		// this runs).
		if len(page.Artifacts) == 0 || len(all) >= page.Total {
			return all, nil
		}
		offset += len(page.Artifacts)
	}
}

// staleScanningAfter is how long an artifact must have sat at
// "scanning" before the sweep treats it as abandoned rather than
// in-flight. Comfortably above SCAN_TIMEOUT_SECONDS' 660s default (the
// longest a live scan can legitimately take before the handler gives
// up), so a slow-but-healthy scan is never yanked out from under
// itself.
const staleScanningAfter = 20 * time.Minute

// listStaleScanningFromAPI returns artifacts stuck at "scanning" longer
// than staleScanningAfter -- see runSweepRegistered for why they exist
// and why re-scanning is the reclaim. Uses the same status filter and
// paging as listRegisteredFromAPI; UpdatedAt is when the status flipped
// to scanning, so it doubles as "when did this scan start".
func listStaleScanningFromAPI(ctx context.Context, apiBase, apiKey string) ([]artifact.Artifact, error) {
	scanning, err := listByStatusFromAPI(ctx, apiBase, apiKey, artifact.StatusScanning)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().Add(-staleScanningAfter)
	var stale []artifact.Artifact
	for _, a := range scanning {
		if a.UpdatedAt.Before(cutoff) {
			stale = append(stale, a)
		}
	}
	return stale, nil
}

// scanArtifactViaAPI calls POST /api/v1/artifacts/{id}/scan -- the same
// endpoint a person clicking "Scan" in the dashboard hits, so a swept
// artifact is scanned exactly the way a manual one is, including the
// opportunistic digest backfill that endpoint does.
//
// That endpoint is asynchronous now: it answers 202 the moment a scan
// starts, so this polls GET /api/v1/artifacts/{id} until the artifact
// leaves "scanning" before reporting. The sweep's entire output is
// "scanned, digest resolved / still not resolved", which read off the
// 202 body would describe an artifact whose scan hasn't run yet.
//
// A saturated scan cap answers 429. That is not a failure worth logging
// as one: the artifact stays where it was and the next run picks it up
// oldest-first, exactly as designed.
func scanArtifactViaAPI(ctx context.Context, apiBase, apiKey, id string) (*artifact.Artifact, error) {
	url := strings.TrimRight(apiBase, "/") + "/api/v1/artifacts/" + id + "/scan"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build scan request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, errScanCapSaturated
	}
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("scan: server returned %d: %s", resp.StatusCode, string(body))
	}
	return waitForScanToFinish(ctx, apiBase, apiKey, id)
}

// errScanCapSaturated marks the one "failure" the sweep treats as
// routine -- see scanArtifactViaAPI.
var errScanCapSaturated = errors.New("scan concurrency limit reached")

// scanPollInterval is how often the sweep re-checks one in-flight scan.
// Scans take minutes, so this is deliberately unhurried.
const scanPollInterval = 5 * time.Second

// waitForScanToFinish polls one artifact until it leaves "scanning".
// Bounded by ctx (runSweepRegistered gives the whole sweep 10 minutes),
// so a scan that outlives the sweep is reported as still in flight
// rather than blocking this run forever.
func waitForScanToFinish(ctx context.Context, apiBase, apiKey, id string) (*artifact.Artifact, error) {
	url := strings.TrimRight(apiBase, "/") + "/api/v1/artifacts/" + id
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build poll request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("poll scan status: %w", err)
		}
		var a artifact.Artifact
		decodeErr := json.NewDecoder(resp.Body).Decode(&a)
		status := resp.StatusCode
		resp.Body.Close()
		if status != http.StatusOK {
			return nil, fmt.Errorf("poll scan status: server returned %d", status)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("decode polled artifact: %w", decodeErr)
		}
		if a.Status != artifact.StatusScanning {
			return &a, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("gave up waiting for %s to finish scanning: %w", id, ctx.Err())
		case <-time.After(scanPollInterval):
		}
	}
}

// cveScannersFor picks which CVE scanner(s) a given cveScanner setting
// ("trivy", "grype", or "both") selects out of a trivy/grype pair --
// shared by buildImageScanners and buildSBOMScanners so the
// trivy/grype/both selection logic lives in exactly one place. Any
// value other than "grype"/"both" (including "trivy" and, as a fail-
// safe, anything unrecognized) falls back to trivy-only -- matching
// this project's usual "unrecognized env value defaults to the
// pre-existing safe behavior" convention, and, more importantly, this
// is what makes cveScanner="trivy" behaviorally identical to every
// deployment before this feature existed (see
// TestBuildImageScanners_CVEScannerTrivyIsUnchanged).
func cveScannersFor(cveScanner string, trivy, grype scanner.Scanner) []scanner.Scanner {
	switch cveScanner {
	case "grype":
		return []scanner.Scanner{grype}
	case "both":
		return []scanner.Scanner{trivy, grype}
	default:
		return []scanner.Scanner{trivy}
	}
}

// buildImageScanners picks the `image` artifact type's full scanner
// list -- cveScannersFor's pick of trivy/grype/both, plus the malware
// scanner (unpack + ClamAV) -- consistently: the isolated, Kubernetes-
// Job-per-scan path for every scanner by default, or the in-process
// fallback for every scanner when DISABLE_SCAN_ISOLATION is set. A
// single flag governing all of them keeps "isolation is on" vs.
// "isolation is off" one coherent mental model instead of several
// independently-toggleable ones (see DISABLE_SCAN_ISOLATION's own
// comment in runAPIServer). Split out from runAPIServer specifically
// so this decision is unit-testable (main_test.go) without needing a
// real Kubernetes API client or real trivy/grype binaries -- none of
// the scanner arguments is ever actually invoked by this function,
// just selected.
func buildImageScanners(disableScanIsolation bool, cveScanner string, trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcessUnpacker, isolatedUnpacker scanner.Scanner) []scanner.Scanner {
	if disableScanIsolation {
		return append(cveScannersFor(cveScanner, trivyInProcess, grypeInProcess), inProcessUnpacker)
	}
	return append(cveScannersFor(cveScanner, trivyIsolated, grypeIsolated), isolatedUnpacker)
}

// buildSBOMScanners picks the sbom artifact type's CVE scanner(s) the
// same way buildImageScanners picks image's: the isolated,
// Kubernetes-Job-per-scan path by default, or the in-process
// FetchingScanner+SBOMScanner/GrypeSBOMScanner fallback under
// DISABLE_SCAN_ISOLATION. Split out for the same reason
// buildImageScanners is: unit-testable (main_test.go) without needing
// a real Kubernetes API client.
func buildSBOMScanners(disableScanIsolation bool, cveScanner string, trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated scanner.Scanner) []scanner.Scanner {
	if disableScanIsolation {
		return cveScannersFor(cveScanner, trivyInProcess, grypeInProcess)
	}
	return cveScannersFor(cveScanner, trivyIsolated, grypeIsolated)
}

// registerPluggableScanners adds each operator-configured pluggable
// scanner (PLUGGABLE_SCANNERS -- see internal/scanner/pluggable.go and
// docs/architecture.md, "Pluggable scanners") into reg, once per
// artifact type it names. Additive, not replacing: this appends
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
// registrations are left unwrapped: a pluggable CVE scanner plugged in
// for images is expected to resolve an OCI ref itself, the same way
// trivy/unpacker already do -- wrapping it in FetchingScanner would
// hand it a single fetched blob path instead of the image reference it
// actually needs.
//
// Split out from runAPIServer specifically so the validation and
// per-type wrapping decision is unit-testable (main_test.go) without
// invoking any configured command -- registerPluggableScanners itself
// never calls Scan().
func registerPluggableScanners(reg scanner.Registry, specs []scanner.PluggableScannerConfig, fetcher scanner.Fetcher) error {
	for _, spec := range specs {
		if spec.Name == "" {
			return fmt.Errorf("pluggable scanner config missing required \"name\"")
		}
		if spec.Command == "" {
			return fmt.Errorf("pluggable scanner %q missing required \"command\"", spec.Name)
		}
		if len(spec.ArtifactTypes) == 0 {
			return fmt.Errorf("pluggable scanner %q must list at least one artifactType", spec.Name)
		}

		var s scanner.Scanner = scanner.NewPluggableScanner(spec)
		for _, at := range spec.ArtifactTypes {
			t := artifact.Type(at)
			if !t.Valid() {
				return fmt.Errorf("pluggable scanner %q: %q is not a valid artifactType (must be one of image, file, sbom, sarif)", spec.Name, at)
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

	// REGISTRY_USERNAME/PASSWORD authenticate every registry-facing pull
	// path (oras via RegistryFetcher, unpacker via a generated
	// dockerconfig.json, trivy via its own native TRIVY_USERNAME/
	// TRIVY_PASSWORD env vars set on isolated_trivy.go's scan-worker
	// Jobs) against scm-registry's token-auth -- see
	// docs/architecture.md's registry-auth section. Empty (the default
	// before registry auth existed) means every one of those falls back
	// to unauthenticated behavior unchanged.
	registryUsername := os.Getenv("REGISTRY_USERNAME")
	registryPassword := os.Getenv("REGISTRY_PASSWORD")
	// trivy reads its own native TRIVY_USERNAME/TRIVY_PASSWORD env vars
	// directly (os/exec inherits this process's environment automatically,
	// no explicit flag/arg needed -- see trivy.go's ScanRaw). Only
	// actually exercised when DISABLE_SCAN_ISOLATION runs TrivyScanner
	// in-process below; harmless to set unconditionally otherwise, since
	// the isolated path's own scan-worker Jobs get these set independently
	// via isolated_trivy.go's SecretEnvVars.
	if registryUsername != "" {
		os.Setenv("TRIVY_USERNAME", registryUsername)
		os.Setenv("TRIVY_PASSWORD", registryPassword)
	}

	// unpacker (github.com/Sifungurux/unpacker) config, passed through
	// to each scan-worker Job's env -- see IsolatedUnpackerScanner.
	// Defaults assume a local, plain-HTTP dev registry (scm-registry);
	// tighten these before pointing at anything else.
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

	// grype's own counterpart to trivyDB above (no separate Java DB the
	// way trivy has). CacheDir stays unset here -- that's only for the
	// isolated path's shared read-only mount (see IsolatedGrypeConfig.
	// CacheMountPath); in-process grype uses its own default cache
	// location, the same relationship trivyDB/TrivyScanner("", trivyDB)
	// above already has.
	grypeDB := scanner.GrypeDBConfig{
		SkipDBUpdate:      getenvBool("GRYPE_SKIP_DB_UPDATE", false),
		SkipAgeValidation: getenvBool("GRYPE_SKIP_AGE_VALIDATION", false),
	}

	// Selects which CVE scanner(s) actually run for `image`/`sbom`
	// artifacts -- see buildImageScanners/buildSBOMScanners and
	// values.yaml's monitorApi.cveScanner comment. Validated (not
	// silently clamped) so a typo'd value fails loudly at startup
	// instead of silently falling back to trivy-only and leaving
	// whoever configured "grype" wondering why grype never ran --
	// same "fail closed, fail loud" convention scanTimeoutSeconds'
	// validation below uses.
	cveScanner := getenv("CVE_SCANNER", "trivy")
	switch cveScanner {
	case "trivy", "grype", "both":
	default:
		log.Fatalf(`CVE_SCANNER=%q is invalid -- must be "trivy", "grype", or "both"`, cveScanner)
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
	fetcher := scanner.NewRegistryFetcher(fetchPlainHTTP, registryUsername, registryPassword)

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
	// Computed once and reused for both unpacker's --config flag and
	// grype's DOCKER_CONFIG below -- both authenticate against the same
	// scm-registry account, no reason to write two separate temp
	// dockerconfig.json files for it.
	dockerConfigPath := writeDockerConfig(registryAddr, registryUsername, registryPassword)
	inProcessUnpacker := scanner.NewUnpackerScanner(clamAddr, unpackerBin, unpackerInsecure, unpackerPublic, int64(unpackerMaxFileMB)*1024*1024, dockerConfigPath)
	inProcessTrivy := scanner.NewTrivyScanner(registryAddr, trivyDB)
	var grypeDockerConfigDir string
	if dockerConfigPath != "" {
		grypeDockerConfigDir = filepath.Dir(dockerConfigPath)
	}
	inProcessGrype := scanner.NewGrypeScanner(grypeDB, fetchPlainHTTP, grypeDockerConfigDir)

	// SCAN_WORKER_ACTIVE_DEADLINE_SECONDS bounds how long Kubernetes lets
	// each scan-worker Job's pod run before killing it outright (both the
	// unpacker and trivy Job shapes -- see IsolatedUnpackerConfig/
	// IsolatedTrivyConfig's own ActiveDeadlineSeconds comment). Raise this
	// for a cluster that's routinely scanning heavier images (more OS
	// packages for trivy to walk/query -- e.g. mysql/postgres-sized
	// images) and/or running many scans concurrently, where per-Job
	// scheduling delay and CPU contention both push real runtime up.
	// SCAN_TIMEOUT_SECONDS is the API handler's own overall per-scan
	// budget (see internal/api/scan.go's scanArtifact/scanTimeout) --
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
	var isolatedGrypeImage scanner.Scanner
	var isolatedGrypeSBOM scanner.Scanner
	if !disableScanIsolation {
		k8sClient, err := k8sjob.NewInClusterClient()
		if err != nil {
			log.Fatalf("could not create kubernetes client for scan-worker jobs: %v (set DISABLE_SCAN_ISOLATION=true to run without one -- see README)", err)
		}
		workerImage := getenv("SCAN_WORKER_IMAGE", "monitor-api:dev")
		// Empty (the pre-registry-auth default) when scm-registry has no
		// auth configured -- every isolated Job's *CredentialsSecretName
		// field below stays "" too, so none of them mount anything new.
		// See docs/architecture.md's registry-auth section and
		// charts/supply-chain-monitor/templates/registry-credentials-secret.yaml.
		registryCredentialsSecretName := getenv("REGISTRY_CREDENTIALS_SECRET", "")
		isolatedUnpacker = scanner.NewIsolatedUnpackerScanner(k8sClient, scanner.IsolatedUnpackerConfig{
			Image:                         workerImage,
			ClamAddr:                      clamAddr,
			UnpackerBin:                   unpackerBin,
			UnpackerInsecure:              unpackerInsecure,
			UnpackerPublic:                unpackerPublic,
			UnpackerMaxFileMB:             unpackerMaxFileMB,
			VerboseLogs:                   verboseScanLogs,
			ActiveDeadlineSeconds:         int64(scanWorkerActiveDeadlineSeconds),
			RegistryAddr:                  registryAddr,
			RegistryCredentialsSecretName: registryCredentialsSecretName,
		})
		// Shares the same Kubernetes API client and worker image as
		// isolatedUnpacker above -- both are just different scan-worker
		// Job shapes the same monitor-api binary runs. See
		// IsolatedTrivyScanner's comment for why the DB cache is a
		// separately-refreshed PVC rather than downloaded per scan.
		isolatedTrivyImage = scanner.NewIsolatedTrivyScanner(k8sClient, scanner.IsolatedTrivyConfig{
			Image:                         workerImage,
			SubCommand:                    "image",
			CacheClaimName:                getenv("TRIVY_CACHE_CLAIM", "scm-trivy-db-cache"),
			CacheMountPath:                getenv("TRIVY_CACHE_DIR", "/trivy-cache"),
			VerboseLogs:                   verboseScanLogs,
			ActiveDeadlineSeconds:         int64(scanWorkerActiveDeadlineSeconds),
			RegistryCredentialsSecretName: registryCredentialsSecretName,
			// Lets each "image" scan-worker Job upload a generated
			// SBOM/SARIF document back to this Service once it's done
			// scanning (see IsolatedTrivyConfig.APIBaseURL's comment) --
			// "monitor-api" is this chart's own Service name/port (see
			// charts/supply-chain-monitor/templates/monitor-api/service.yaml), reachable from
			// any pod in the same namespace via cluster DNS. Empty
			// disables document capture entirely, e.g. for a deployment
			// where the scan-worker Job's network policy can't reach the
			// API server pod.
			APIBaseURL: getenv("SCAN_WORKER_API_BASE_URL", "http://monitor-api:8080"),
		})
		// Same again for sbom-type artifacts (see docs/architecture.md,
		// "Isolating SBOM trivy scanning") -- FetchPlainHTTP is set here
		// (unlike isolatedTrivyImage above) because this Job has to fetch
		// the SBOM document itself before scanning it; see
		// IsolatedTrivyConfig.FetchPlainHTTP's own comment and
		// runScanWorker's "sbom" case for where that actually happens.
		isolatedTrivySBOM = scanner.NewIsolatedTrivyScanner(k8sClient, scanner.IsolatedTrivyConfig{
			Image:                         workerImage,
			SubCommand:                    "sbom",
			CacheClaimName:                getenv("TRIVY_CACHE_CLAIM", "scm-trivy-db-cache"),
			CacheMountPath:                getenv("TRIVY_CACHE_DIR", "/trivy-cache"),
			FetchPlainHTTP:                fetchPlainHTTP,
			VerboseLogs:                   verboseScanLogs,
			ActiveDeadlineSeconds:         int64(scanWorkerActiveDeadlineSeconds),
			RegistryCredentialsSecretName: registryCredentialsSecretName,
		})
		// Only actually constructed when something will use them --
		// cheap either way (no real API calls happen at construction
		// time, just config storage), but there's no reason to build a
		// grype Job shape nothing ever selects (see cveScannersFor).
		if cveScanner != "trivy" {
			isolatedGrypeImage = scanner.NewIsolatedGrypeScanner(k8sClient, scanner.IsolatedGrypeConfig{
				Image:                         workerImage,
				SubCommand:                    "image",
				CacheClaimName:                getenv("GRYPE_CACHE_CLAIM", "scm-grype-db-cache"),
				CacheMountPath:                getenv("GRYPE_CACHE_DIR", "/grype-cache"),
				FetchPlainHTTP:                fetchPlainHTTP,
				VerboseLogs:                   verboseScanLogs,
				ActiveDeadlineSeconds:         int64(scanWorkerActiveDeadlineSeconds),
				RegistryAddr:                  registryAddr,
				RegistryCredentialsSecretName: registryCredentialsSecretName,
			})
			// Same shape as isolatedTrivySBOM above -- the worker fetches
			// its own copy of the SBOM before scanning it (runScanWorker's
			// "grype"+"sbom" case).
			isolatedGrypeSBOM = scanner.NewIsolatedGrypeScanner(k8sClient, scanner.IsolatedGrypeConfig{
				Image:                         workerImage,
				SubCommand:                    "sbom",
				CacheClaimName:                getenv("GRYPE_CACHE_CLAIM", "scm-grype-db-cache"),
				CacheMountPath:                getenv("GRYPE_CACHE_DIR", "/grype-cache"),
				FetchPlainHTTP:                fetchPlainHTTP,
				VerboseLogs:                   verboseScanLogs,
				ActiveDeadlineSeconds:         int64(scanWorkerActiveDeadlineSeconds),
				RegistryAddr:                  registryAddr,
				RegistryCredentialsSecretName: registryCredentialsSecretName,
			})
		}
	} else {
		log.Printf("DISABLE_SCAN_ISOLATION=true: image malware scanning, trivy CVE scanning, and sbom trivy scanning will all run in-process, not in isolated Jobs -- see README, \"Running monitor-api outside a Kubernetes pod\"")
	}

	scanners := scanner.Registry{
		// image artifacts get a CVE scan (trivy/grype/both, per
		// cveScanner) and a malware scan (unpack + ClamAV) -- all
		// isolated into their own scan-worker Job by default, all
		// falling back in-process together under DISABLE_SCAN_ISOLATION.
		// See buildImageScanners/cveScannersFor.
		artifact.TypeImage: buildImageScanners(disableScanIsolation, cveScanner, inProcessTrivy, isolatedTrivyImage, inProcessGrype, isolatedGrypeImage, inProcessUnpacker, isolatedUnpacker),
		artifact.TypeFile: {
			scanner.NewFetchingScanner(fetcher, scanner.NewClamAVScanner(clamAddr)),
		},
		// trivy/grype sbom share the same air-gapped DB-mirror config as
		// their image counterparts above -- see internal/scanner/sbom.go/
		// grype_sbom.go. Isolated into its own scan-worker Job by default
		// (see docs/architecture.md, "Isolating SBOM trivy scanning"):
		// that Job fetches its own copy of the SBOM (runScanWorker's
		// "sbom" mode) rather than relying on a local path only this pod
		// could see, exactly mirroring how the in-process fallback below
		// (FetchingScanner+SBOMScanner/GrypeSBOMScanner, used under
		// DISABLE_SCAN_ISOLATION) already fetches it itself.
		artifact.TypeSBOM: buildSBOMScanners(disableScanIsolation, cveScanner,
			scanner.NewFetchingScanner(fetcher, scanner.NewSBOMScanner(trivyDB)), isolatedTrivySBOM,
			scanner.NewFetchingScanner(fetcher, scanner.NewGrypeSBOMScanner(grypeDB)), isolatedGrypeSBOM,
		),
		// SARIF is parsed, not re-scanned -- see internal/scanner/sarif.go.
		artifact.TypeSARIF: {
			scanner.NewFetchingScanner(fetcher, scanner.NewSARIFScanner()),
		},
	}

	// Operator-configured pluggable scanners (a different CVE scanner
	// than trivy, a different SBOM tool, ...) on top of the built-in
	// ones above -- see docs/architecture.md ("Pluggable scanners") and
	// README. Unset/empty by default, so nothing changes for anyone not
	// using this.
	if pluggableScannersEnv := getenv("PLUGGABLE_SCANNERS", ""); pluggableScannersEnv != "" {
		var specs []scanner.PluggableScannerConfig
		if err := json.Unmarshal([]byte(pluggableScannersEnv), &specs); err != nil {
			log.Fatalf("PLUGGABLE_SCANNERS is not valid JSON: %v", err)
		}
		if err := registerPluggableScanners(scanners, specs, fetcher); err != nil {
			log.Fatalf("invalid PLUGGABLE_SCANNERS config: %v", err)
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
	// internal/api/handler.go's resolveDigest) -- oras is already baked
	// into this image (Dockerfile), the same binary fetcher above uses.
	// fetchPlainHTTP is the same flag already computed for fetcher, not
	// a second config surface -- see NewRouter's own comment for why
	// image refs never use it regardless of this setting.
	digestResolver := scanner.NewOrasDigestResolver()

	// REQUIRE_DIGEST -- see NewRouter's own comment for the full
	// behavior this gates. Off by default: turning it on is a real
	// policy change (expected_digest becomes a required field on every
	// registration), not something an existing deployment should pick up
	// silently.
	requireDigest := getenvBool("REQUIRE_DIGEST", false)

	// SCAN_CONCURRENCY caps how many scans run at once across this
	// process (see internal/api's ScanLimits). Nothing bounded this
	// before: every scan spawns an isolated scan-worker Job that
	// extracts the whole image under scan to disk (measured up to
	// ~2.4Gi), so a client firing 50 scans at once was 50 Jobs
	// competing for node disk -- the resource exhaustion the scan-Job
	// ephemeral-storage sizing can only survive, not prevent.
	// 0 (the default) is unlimited, the same "zero-or-negative reads as
	// off" convention RATE_LIMIT_RPS above uses -- the chart ships a
	// real value (monitorApi.scanConcurrency) so a deployed cluster gets
	// the bound without a bare `go run` silently changing behavior.
	// Deliberately not validated against anything: unlike the
	// SCAN_TIMEOUT/ACTIVE_DEADLINE pair above, no other setting can
	// contradict it.
	scanConcurrency := getenvInt("SCAN_CONCURRENCY", 0)
	if scanConcurrency > 0 {
		log.Printf("scan concurrency capped at %d concurrent scans (SCAN_CONCURRENCY)", scanConcurrency)
	}

	// Outbound notifications -- off unless a destination is configured,
	// so a deployment that sets none behaves exactly as before. See
	// internal/notify and internal/api's notifyNewFindings for what
	// counts as "new" (only findings this scan round introduced) and why
	// a failing destination can never fail a scan.
	notifyMinSeverity := getenv("NOTIFY_MIN_SEVERITY", notify.DefaultMinSeverity)
	if !notify.ValidSeverity(notifyMinSeverity) {
		// Fail loudly rather than silently notifying on everything (an
		// unrecognized threshold ranks 0) -- a typo'd threshold that
		// quietly pages on every low-severity finding is worse than a
		// refused startup.
		log.Fatalf("NOTIFY_MIN_SEVERITY=%q is not a known severity (critical, high, medium, low, negligible, unknown)", notifyMinSeverity)
	}
	var notifiers []notify.Notifier
	if url := os.Getenv("NOTIFY_WEBHOOK_URL"); url != "" {
		notifiers = append(notifiers, notify.NewWebhook(url, os.Getenv("NOTIFY_WEBHOOK_SECRET")))
		signed := "unsigned"
		if os.Getenv("NOTIFY_WEBHOOK_SECRET") != "" {
			signed = "HMAC-SHA256 signed"
		}
		log.Printf("notifications: generic webhook enabled (%s), min severity %q", signed, notifyMinSeverity)
	}
	if url := os.Getenv("NOTIFY_SLACK_URL"); url != "" {
		notifiers = append(notifiers, notify.NewSlack(url))
		log.Printf("notifications: slack enabled, min severity %q", notifyMinSeverity)
	}

	router := api.NewRouter(store, stageTracker, scanners, apiKey, rateLimitRPS, rateLimitBurst, digestResolver, fetchPlainHTTP, scanTimeout, requireDigest,
		api.ScanLimits{Concurrency: scanConcurrency},
		api.Notifications{Notifiers: notifiers, MinSeverity: notifyMinSeverity})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: httpWriteTimeout,
	}

	log.Printf("monitor-api listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
