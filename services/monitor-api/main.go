package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
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
// missing digest (see scanArtifact's own comment in internal/api/
// handlers.go). Goes through the API rather than a direct Postgres
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

	all, err := listArtifactsFromAPI(ctx, apiBase, apiKey)
	if err != nil {
		log.Fatalf("sweep-registered: could not list artifacts: %v", err)
	}

	toScan := pickArtifactsToSweep(all, batchSize)
	log.Printf("sweep-registered: %d artifact(s) registered-but-unscanned, scanning %d (SWEEP_BATCH_SIZE=%d)", countByStatus(all, artifact.StatusRegistered), len(toScan), batchSize)

	missingDigest := 0
	for _, a := range toScan {
		updated, err := scanArtifactViaAPI(ctx, apiBase, apiKey, a.ID)
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
// reasoning maxBulkArtifacts already uses in internal/api/handlers.go.
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

// listArtifactsFromAPI calls GET /api/v1/artifacts against monitor-api's
// own Service -- see runSweepRegistered's own comment for why this goes
// through the API rather than a direct Postgres connection.
func listArtifactsFromAPI(ctx context.Context, apiBase, apiKey string) ([]artifact.Artifact, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/artifacts", nil)
	if err != nil {
		return nil, fmt.Errorf("build list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("list artifacts: server returned %d: %s", resp.StatusCode, string(body))
	}

	var all []artifact.Artifact
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		return nil, fmt.Errorf("decode artifact list: %w", err)
	}
	return all, nil
}

// scanArtifactViaAPI calls POST /api/v1/artifacts/{id}/scan -- the same
// endpoint a person clicking "Scan" in the dashboard hits, so a swept
// artifact is scanned exactly the way a manual one is, including the
// opportunistic digest backfill scanArtifact now does.
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("scan: server returned %d: %s", resp.StatusCode, string(body))
	}

	var a artifact.Artifact
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return nil, fmt.Errorf("decode scan response: %w", err)
	}
	return &a, nil
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
