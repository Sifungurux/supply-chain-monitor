package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
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
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/policy"
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

// singleAuth is the in-cluster registry's "auths" entry -- the one
// credential that arrives as an env pair rather than as a mounted
// Secret, because the chart derives it from dockerAuth.accounts.reader
// (templates/monitor-api/registry-credentials-secret.yaml) instead of
// from monitorApi.registryCredentials. Same shape as every other entry;
// mergeRegistryAuths folds it in alongside them. See
// docs/architecture.md's registry-auth section.
func singleAuth(registryAddr, username, password string) map[string]any {
	if username == "" {
		return map[string]any{}
	}
	return map[string]any{registryAddr: map[string]string{
		"username": username,
		"password": password,
		"auth":     base64.StdEncoding.EncodeToString([]byte(username + ":" + password)),
	}}
}

// dockerConfigFileNames are the two names a mounted registry credential
// can arrive under: "config.json" is what a docker CLI config uses, and
// ".dockerconfigjson" is the key -- and therefore the file name -- of a
// kubernetes.io/dockerconfigjson Secret mounted as a volume. Both hold
// the same JSON shape, so both are read.
var dockerConfigFileNames = map[string]bool{"config.json": true, ".dockerconfigjson": true}

// registryUsernameFile / registryPasswordFile are the two file names a
// monitorApi.registryCredentials entry using usernameSecretRef arrives
// under. The chart projects whatever keys the operator's Secret
// actually uses onto exactly these two names
// (templates/monitor-api/deployment.yaml), so this side never has to
// know what they were called in the Secret.
//
// THE DIRECTORY NAME IS THE HOST. A dockerconfigjson carries its own
// host inside the JSON; a bare username/password pair does not, so the
// only place left to put it is the mount path -- the chart mounts each
// pair at <authDir>/<host>. A host is allowed to contain a colon
// ("registry.internal:5000") and a path component never contains a
// slash, so the host survives the round trip verbatim.
const (
	registryUsernameFile = "username"
	registryPasswordFile = "password"
)

// authSource is one mounted credential: either a docker config file or
// the directory of a username/password pair. Both carry their path so
// the merge below can order every source, of both kinds, by one rule.
type authSource struct {
	path     string
	userPair bool
}

// readUserPair builds an "auths" entry from a username/password pair
// mounted in dir, taking the host from dir's own name.
//
// Trailing newlines are stripped, and that is not cosmetic: `kubectl
// create secret generic --from-file` keeps the newline the editor put
// at the end of the file, and a password with a stray "\n" fails
// authentication with a 401 that looks exactly like a wrong password.
// Only CR/LF go -- a password may legitimately end in a space, and
// TrimSpace would silently corrupt it.
func readUserPair(dir string) (host string, entry map[string]string, err error) {
	user, err := os.ReadFile(filepath.Join(dir, registryUsernameFile))
	if err != nil {
		return "", nil, err
	}
	pass, err := os.ReadFile(filepath.Join(dir, registryPasswordFile))
	if err != nil {
		return "", nil, err
	}
	u := strings.TrimRight(string(user), "\r\n")
	p := strings.TrimRight(string(pass), "\r\n")
	return filepath.Base(dir), map[string]string{
		"username": u,
		"password": p,
		"auth":     base64.StdEncoding.EncodeToString([]byte(u + ":" + p)),
	}, nil
}

// mergeRegistryAuths merges the legacy single-registry credential pair
// with every docker config mounted under authDir, and returns the
// combined "auths" map.
//
// The merge happens HERE, at runtime, rather than in the chart, and
// that is a deliberate constraint rather than a preference: an entry
// naming a Secret the operator manages themselves (an existing
// ghcr.io pull secret, say) has contents Helm cannot see. `lookup`
// returns nil under `helm template`, so a chart-side merge would render
// an empty auths map in exactly the case CI renders -- a test that
// certifies nothing. Mounting each source and merging them in the pod
// is the only shape where an externally-managed Secret works at all.
//
// Sources are merged in sorted path order and a later host entry wins,
// so the result does not depend on directory iteration order. Docker
// configs and username/password pairs are sorted TOGETHER, by path,
// rather than one kind after the other: two rules would mean the
// winner between a dockerconfigjson and a usernameSecretRef for the
// same host depended on which kind it was, which is not something an
// operator reading values.yaml top to bottom would predict.
//
// The legacy pair goes first: an explicitly configured entry for the
// same host is meant to override the account the chart derives from
// dockerAuth.
func mergeRegistryAuths(registryAddr, username, password, authDir string) map[string]any {
	auths := singleAuth(registryAddr, username, password)

	var sources []authSource
	if authDir != "" {
		// A missing directory is the normal "no extra registries
		// configured" case, not an error -- WalkDir reports it through
		// the callback, which skips it below.
		_ = filepath.WalkDir(authDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable entry is skipped, not fatal -- see below
			}
			if d.IsDir() {
				// A Kubernetes Secret volume is not a flat directory:
				// the atomic writer keeps the real files in a
				// timestamped "..2026_08_22_15_44_23.381250005"
				// directory and symlinks "..data" at it, so every key
				// is visible TWICE -- once at <dir>/username and once
				// at <dir>/..2026_.../username. WalkDir does not follow
				// the "..data" symlink, but the timestamped directory
				// is real and it does descend into that.
				//
				// Harmless for a docker config (the same hosts merged
				// twice), fatal for a username/password pair, whose
				// HOST IS ITS DIRECTORY NAME: the second copy would
				// register credentials for a registry called
				// "..2026_08_22_15_44_23.381250005". Verified against a
				// real kubelet, not reasoned about.
				if path != authDir && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			switch {
			case dockerConfigFileNames[d.Name()]:
				sources = append(sources, authSource{path: path})
			case d.Name() == registryUsernameFile:
				// Keyed off the username file, not the directory, so a
				// half-populated mount (a Secret missing the password
				// key) is reported below rather than skipped in
				// silence -- the whole point of the error legs here.
				sources = append(sources, authSource{path: filepath.Dir(path), userPair: true})
			}
			return nil
		})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].path < sources[j].path })

	for _, src := range sources {
		if src.userPair {
			host, entry, err := readUserPair(src.path)
			if err != nil {
				// Same reasoning as the docker config legs below: loud,
				// because the symptom otherwise arrives much later as a
				// 401 from a registry nobody connected to this mount.
				slog.Error("registry auth: could not read mounted username/password pair", "dir", src.path, "err", err)
				continue
			}
			auths[host] = entry
			continue
		}
		path := src.path
		data, err := os.ReadFile(path)
		if err != nil {
			// Skipped rather than fatal, but LOUDLY: a credential that
			// silently fails to load turns into a 401 from a registry
			// at scan time, which is a much harder thing to trace back
			// to a mount than one line at startup.
			slog.Error("registry auth: could not read mounted docker config", "path", path, "err", err)
			continue
		}
		var cfg struct {
			Auths map[string]json.RawMessage `json:"auths"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			slog.Error("registry auth: mounted docker config is not valid JSON", "path", path, "err", err)
			continue
		}
		for host, entry := range cfg.Auths {
			auths[host] = entry
		}
	}
	return auths
}

// writeDockerConfig writes the merged "auths" map to a file
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
func writeDockerConfig(registryAddr, username, password, authDir string) string {
	auths := mergeRegistryAuths(registryAddr, username, password, authDir)
	if len(auths) == 0 {
		return ""
	}
	dir, err := os.MkdirTemp("", "scm-dockerconfig-*")
	if err != nil {
		fatal("could not create the docker config temp dir", "err", err)
	}
	path := filepath.Join(dir, "config.json")
	body, _ := json.Marshal(map[string]any{"auths": auths})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		fatal("could not write the docker config temp file", "err", err)
	}
	hosts := make([]string, 0, len(auths))
	for h := range auths {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	// Hosts only, never the credentials themselves. Which registries
	// this pod can authenticate to is the thing an operator needs to
	// confirm from a log line, and it is the thing that silently
	// disagrees with values.yaml when a mount is wrong.
	slog.Info("registry auth: docker config written", "hosts", hosts, "path", path)
	return path
}

// registryFetcher and digestResolverFor pick between the merged docker
// config and the legacy single credential pair.
//
// Both exist so the choice is made in ONE place per type rather than at
// each of the four call sites: a call site that forgot the config path
// would fall back to scm-registry's account and 401 against every other
// registry, which surfaces as a failed scan rather than anything
// visible at startup.
func registryFetcher(plainHTTP bool, dockerConfigPath, username, password string) *scanner.RegistryFetcher {
	if dockerConfigPath != "" {
		return scanner.NewRegistryFetcherWithConfig(plainHTTP, dockerConfigPath)
	}
	return scanner.NewRegistryFetcher(plainHTTP, username, password)
}

// mirrorDockerConfig returns the docker config `oras copy` authenticates
// with, which is NOT the one every other registry path here shares.
//
// Copying PUSHES, and the shared REGISTRY_USERNAME/PASSWORD pair is
// deliberately the read-only account: those exact two Secret keys are
// also read by every scan-worker Job (see isolated_trivy.go /
// isolated_grype.go), and a Job running scanner binaries over untrusted
// image content must not be able to write to the registry whose contents
// this service then scans. So the push credential lives in its own pair,
// mounted only on the API pod, and is merged into its own config file
// that only this one caller is ever handed.
//
// Falls back to the shared config when the pair is unset -- a deployment
// that has wired one push-capable account everywhere (or is using
// dockerAuth.existingSecret) keeps working, it just does not get the
// separation.
func mirrorDockerConfig(registryAddr, sharedConfigPath string) string {
	username := os.Getenv("MIRROR_REGISTRY_USERNAME")
	if username == "" {
		return sharedConfigPath
	}
	// authDir "" on purpose: this file exists to authenticate the
	// DESTINATION, which is always scm-registry. The source side of a
	// copy is covered by the shared config's other hosts -- see
	// OrasMirror.copyArgs, which passes them as two different flags.
	return writeDockerConfig(registryAddr, username, os.Getenv("MIRROR_REGISTRY_PASSWORD"), "")
}

func digestResolverFor(dockerConfigPath, username, password string) *scanner.OrasDigestResolver {
	if dockerConfigPath != "" {
		return scanner.NewOrasDigestResolverWithConfig(dockerConfigPath)
	}
	return scanner.NewOrasDigestResolver(username, password)
}

// exportDockerConfig points DOCKER_CONFIG at the directory holding the
// merged config.json, so every tool this process execs authenticates
// from it without each call site having to pass anything.
//
// DOCKER_CONFIG names a DIRECTORY containing a file literally called
// "config.json" -- go-containerregistry's keychain looks for that exact
// name, which is why writeDockerConfig builds a directory rather than a
// bare temp file. Process-wide on purpose: the alternative is every
// exec site remembering to set it, and the failure mode of forgetting
// is an anonymous pull that 401s at scan time rather than anything
// visible at startup.
func exportDockerConfig(dockerConfigPath string) {
	if dockerConfigPath == "" {
		return
	}
	os.Setenv("DOCKER_CONFIG", filepath.Dir(dockerConfigPath))
}

// registryAuthDir is the directory the chart mounts each configured
// registry's credentials under, one subdirectory per Secret. Read from
// the environment so a local run without the chart simply finds
// nothing there and falls back to the legacy single-registry pair.
func registryAuthDir() string { return getenv("REGISTRY_AUTH_DIR", "/etc/scm/registry-auth") }

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

	// sslrootcert only when there is one. Emitting an empty
	// sslrootcert= is not harmlessly ignored -- libpq/pgx read it as
	// "the CA bundle lives at the empty path", so a stray one turns
	// verify-full into a connection that cannot succeed at all. Absent
	// is the correct representation of "not configured".
	//
	// Only sslmode=verify-ca/verify-full actually check it; the chart
	// sets it exactly when it sets one of those (see
	// templates/monitor-api/configmap.yaml).
	if root := os.Getenv("POSTGRES_SSLROOTCERT"); root != "" {
		query += "&sslrootcert=" + root
	}

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

// logFieldKeys documents the field names this service logs, so the same
// fact is queryable by the same key across every package. Three
// packages spelling the artifact id three ways is the failure mode here,
// and nothing in the toolchain catches it -- structured logs are only
// worth the change if `artifact_id=abc` finds everything about abc.
//
//	artifact_id  the artifact an event concerns
//	ref          its OCI ref / path
//	err          the error, always the LAST pair on a line
//	scanner      which scanner ("trivy", "clamav", ...)
//	status       an artifact status, or an HTTP status
//	job          a Kubernetes Job name
//	host         a hostname being resolved or refused
//	count        how many of whatever the message names
//
// Not enforced by anything -- a linter for this would cost more than it
// saves at this size. It is a convention, written down once.
const logFieldKeys = "artifact_id, ref, err, scanner, status, job, host, count"

// setupLogging installs a JSON slog handler as the process-wide default.
//
// stderr, not stdout, matching where the stdlib log package already
// wrote: `monitor-api scan-worker` prints its WorkerResult JSON to
// stdout and the parent parses it back out of the Job pod's logs. That
// parse is anchored on scanner.ResultMarker and reads the combined
// stream, so it would survive log lines either way -- but keeping the
// result on its own stream means the two never have to be untangled in
// the first place.
//
// slog.SetDefault also redirects the stdlib log package through this
// handler, which is what makes a partial migration safe: a log.Printf
// this change did not convert still comes out as JSON with its text in
// "msg", rather than leaving two formats interleaved in one stream.
// fatal logs at error level and exits non-zero -- what log.Fatalf did,
// minus the part that made it wrong here. log.Fatalf still works
// through the slog bridge, but everything it writes arrives at INFO,
// so a startup misconfiguration that stops the process would be
// indistinguishable from a routine "listening on :8080" to anything
// filtering by level. Which is the one line you would filter for.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func setupLogging() {
	level := slog.LevelInfo
	// Parsed leniently: an unset or unrecognized LOG_LEVEL keeps info
	// rather than refusing to start. A typo in a log-verbosity env var
	// is not a reason to fail a deployment, and info is the level that
	// was effectively in force before this existed.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func main() {
	// Before the mode dispatch below, so scan-worker and
	// sweep-registered log the same way the API server does -- the
	// scan-worker's output is the one a human actually reads under
	// `kubectl logs`, so it is the last mode that should be left on a
	// different format.
	setupLogging()

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
	// `monitor-api prune` is a fourth mode: delete artifacts nothing has
	// touched in RETENTION_DAYS, then exit. Intended as a CronJob, off
	// unless configured -- see runPrune.
	if len(os.Args) > 1 && os.Args[1] == "prune" {
		runPrune()
		return
	}
	// `monitor-api enrich-refresh` is a fifth mode: download CISA KEV
	// and FIRST EPSS and replace the stored copies, then exit. A
	// CronJob, like the trivy/grype DB refreshes it sits beside -- and
	// for the same reason: the data is shared, changes daily, and has
	// no business being fetched on a request path. See runEnrichRefresh.
	if len(os.Args) > 1 && os.Args[1] == "enrich-refresh" {
		runEnrichRefresh()
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

	// One merged docker config for this whole Job, exported as
	// DOCKER_CONFIG so every tool the branches below exec inherits it:
	// trivy, grype and cosign all read go-containerregistry's keychain
	// from it, and unpacker takes the same file through --config. Set
	// here rather than per-branch so a new scan tool cannot be added
	// without credentials.
	workerDockerConfigPath := writeDockerConfig(getenv("REGISTRY_ADDR", ""), os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"), registryAuthDir())
	exportDockerConfig(workerDockerConfigPath)

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
			fetcher := registryFetcher(getenvBool("FETCH_PLAIN_HTTP", true), workerDockerConfigPath, os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"))
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
		dockerConfigPath := workerDockerConfigPath
		var dockerConfigDir string
		if dockerConfigPath != "" {
			dockerConfigDir = filepath.Dir(dockerConfigPath)
		}
		if mode == "image" {
			findings, scanErr = scanner.NewGrypeScanner(grypeDB, plainHTTP, dockerConfigDir).Scan(ctx, ref)
		} else {
			// sbom mode: same fetch-then-scan shape as trivy's sbom
			// branch above -- see that branch's comment.
			fetcher := registryFetcher(plainHTTP, workerDockerConfigPath, os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"))
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
		dockerConfigPath := workerDockerConfigPath

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
	// SCM_SCAN_TOKEN is the per-Job upload credential (report S3);
	// SCM_API_KEY is the pre-migration fallback for a Job minted before
	// this landed, or by a deployment whose store cannot mint.
	apiKey := os.Getenv("SCM_SCAN_TOKEN")
	if apiKey == "" {
		apiKey = os.Getenv("SCM_API_KEY")
	}
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
// retentionMinDays is the floor `monitor-api prune` refuses to go
// below. Retention is expressed in days and deletes irreversibly, so
// the difference between "1" and "0" is the difference between a
// conservative setting and deleting everything -- and a value that low
// is far more likely to be a mistake (a units mix-up, an unset variable
// expanding to nothing, a template rendering "0") than a real intent to
// keep one day of history. Refusing is recoverable; deleting is not.
const retentionMinDays = 1

func runPrune() {
	days := getenvInt("RETENTION_DAYS", 0)
	// Unset or zero means retention is OFF, not "delete everything with
	// a cutoff of now". This is the single most important line in this
	// function: the CronJob that runs it can be scheduled before anyone
	// sets a period, and the failure mode of guessing wrong here is an
	// empty database.
	if days <= 0 {
		slog.Info("prune: RETENTION_DAYS is unset or zero -- retention is disabled, nothing to do")
		return
	}
	if days < retentionMinDays {
		fatal("prune: RETENTION_DAYS is below the minimum and looks like a mistake -- refusing to run",
			"retention_days", days, "minimum", retentionMinDays)
	}
	maxPerRun := getenvInt("RETENTION_MAX_PER_RUN", 500)
	if maxPerRun <= 0 {
		fatal("prune: RETENTION_MAX_PER_RUN must be positive", "retention_max_per_run", maxPerRun)
	}
	dryRun := getenvBool("RETENTION_DRY_RUN", false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	store, err := connectStoreWithRetry(ctx, buildPostgresDSN(), 12, 5*time.Second)
	if err != nil {
		fatal("prune: could not connect to postgres", "err", err)
	}
	defer store.Close()

	// Truncated to the day the cutoff is expressed in, so two runs on
	// the same day agree on what "90 days old" means regardless of what
	// time the CronJob happened to fire.
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	eligible, err := store.CountOlderThan(cutoff)
	if err != nil {
		fatal("prune: could not count stale artifacts", "err", err)
	}
	slog.Info("prune: artifacts eligible for deletion",
		"count", eligible, "retention_days", days,
		"cutoff", cutoff.Format(time.RFC3339), "max_per_run", maxPerRun, "dry_run", dryRun)

	if dryRun {
		slog.Info("prune: RETENTION_DRY_RUN=true -- nothing deleted")
		return
	}
	if eligible == 0 {
		return
	}

	deleted, err := store.DeleteOlderThan(cutoff, maxPerRun)
	if err != nil {
		fatal("prune: delete failed", "err", err)
	}
	// Deliberately loud about the remainder: a run that hit its cap has
	// not finished the job, and silence would read as "everything old is
	// gone" when the next run still has work.
	slog.Info("prune: done",
		"deleted", deleted, "remaining", eligible-deleted,
		"capped", deleted >= maxPerRun)
}

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
		fatal("sweep-registered: could not list artifacts", "err", err)
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

	// Artifacts whose last scan FAILED, retried on every sweep run
	// regardless of age or of whether auto-rescan is on.
	//
	// Staleness cannot cover this and never will: last_scan_at is set
	// when a scan COMPLETES, including a failed one, so an artifact
	// failing repeatedly refreshes its own freshness clock and never
	// looks stale. Left to staleness alone, a broken artifact would be
	// retried exactly never -- which is the opposite of what it needs.
	//
	// Paced by SWEEP_BATCH_SIZE like everything else, and ordered by
	// least-recently-attempted (see pickArtifactsToSweep), so a
	// permanently-broken artifact cannot monopolise the batch: once
	// retried it goes to the back of the queue behind everything that
	// has waited longer.
	if failed, err := listByStatusFromAPI(ctx, apiBase, apiKey, artifact.StatusFailed); err != nil {
		log.Printf("sweep-registered: could not list failed artifacts to retry (continuing): %v", err)
	} else if len(failed) > 0 {
		log.Printf("sweep-registered: %d artifact(s) at %q -- retrying", len(failed), artifact.StatusFailed)
		all = append(all, failed...)
	}

	// Artifacts whose last scan has aged out (SWEEP_RESCAN_STALE_AFTER_DAYS).
	// Off unless configured -- the staleness WARNING is independent of
	// this and shows regardless; this only decides whether anything
	// automatically fixes it.
	//
	// Paced by SWEEP_BATCH_SIZE like everything else here, which
	// matters more than it looks: enabling this against a fleet that
	// has never been swept finds nearly all of it stale at once, and
	// those rescans then all age out together on the same future day.
	// The batch is what keeps that from becoming a thundering herd
	// against the (now cluster-wide) scan concurrency cap.
	// The two passes below both work off the SAME population -- every
	// artifact at status "scanned" -- so it is listed once and shared.
	// Listing it twice would be two full paginations of the largest
	// status there is, and ListPage batch-loads each artifact's findings
	// and stage history (see listArtifacts' own comment on why that
	// payload is worth not asking for twice).
	staleDays := getenvInt("SWEEP_RESCAN_STALE_AFTER_DAYS", 0)
	mirrorBackfill := getenvBool("SWEEP_MIRROR_BACKFILL", false)
	if staleDays > 0 || mirrorBackfill {
		scanned, err := listByStatusFromAPI(ctx, apiBase, apiKey, artifact.StatusScanned)
		if err != nil {
			log.Printf("sweep-registered: could not list scanned artifacts (continuing without stale rescan or mirror backfill): %v", err)
		} else {
			if staleDays > 0 {
				cutoff := time.Now().UTC().AddDate(0, 0, -staleDays)
				if stale := staleScans(scanned, cutoff); len(stale) > 0 {
					log.Printf("sweep-registered: %d artifact(s) last scanned before %s -- rescanning (SWEEP_RESCAN_STALE_AFTER_DAYS=%d)",
						len(stale), cutoff.Format(time.RFC3339), staleDays)
					all = append(all, stale...)
				}
				// No separate pass for "failed" here: every failed
				// artifact is already collected above, on every run,
				// rather than only once it has aged out.
			}
			// Artifacts that have never had mirroring settled (source_ref
			// empty).
			//
			// THIS IS THE BACKFILL FOR THE FLEET THAT ALREADY EXISTS.
			// Mirroring happens as a side effect of registration and of
			// scanning, so an artifact registered before the feature was
			// turned on -- or in bulk, which never copies inline -- sits
			// at "scanned" and is touched by none of the passes above:
			// staleness is off by default, and a successfully-scanned
			// artifact is neither "registered" nor "failed". Without this
			// pass, "copy what is already registered" would simply never
			// happen for the population it was about.
			//
			// Converges as WORK, though not as a query: every scan
			// settles source_ref one way or the other -- to the mirrored
			// ref, or (for a local path or a ref already in this
			// registry) to the ref itself, see internal/api's
			// mirrorArtifact -- so this stops queueing anything. The
			// listing itself still happens each run; sharing it with the
			// stale pass above is what keeps that from costing anything
			// extra. Paced by SWEEP_BATCH_SIZE like every other pass, so
			// turning mirroring on does not rescan the whole fleet at
			// once.
			if mirrorBackfill {
				if unmirrored := unmirroredArtifacts(scanned); len(unmirrored) > 0 {
					log.Printf("sweep-registered: %d scanned artifact(s) not mirrored into the local registry yet -- rescanning to mirror them", len(unmirrored))
					all = append(all, unmirrored...)
				}
			}
		}
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

// pickArtifactsToSweep selects up to batchSize artifacts to rescan,
// oldest (by CreatedAt) first -- so a backlog bigger than one batch
// works through fairly over successive CronJob runs instead of the same
// few newest registrations winning every time. batchSize <= 0 means
// "nothing to do" (fails closed rather than defaulting to unbounded),
// the same "cap rather than trust an unbounded number" reasoning
// maxBulkArtifacts already uses in internal/api/artifacts.go.
//
// ELIGIBILITY IS THE CALLER'S, not this function's. It used to filter
// to status "registered" itself, which silently broke the reclaim of
// artifacts stuck at "scanning": runSweepRegistered listed those,
// logged "reclaiming by re-scanning", appended them to the same
// slice -- and then this dropped every one of them on the status
// filter. The log line was the only evidence anything happened, and
// nothing did. Now the caller decides what is eligible and this only
// orders and caps it, which is also what lets stale artifacts (status
// "scanned"/"failed", which no status filter could distinguish from
// fresh ones) be swept at all.
//
// Pure and side-effect-free -- unit-tested in main_test.go without any
// HTTP involved, the same pattern buildImageScanners/buildSBOMScanners
// already establish for this file.
func pickArtifactsToSweep(all []artifact.Artifact, batchSize int) []artifact.Artifact {
	if batchSize <= 0 {
		return nil
	}
	// Deduplicated by id, because the passes feeding `all` are no longer
	// disjoint. They used to be -- one per status, with an explicit
	// "failed artifacts are already collected above" note keeping it that
	// way -- but the mirror backfill selects on source_ref, not status,
	// so an artifact that is BOTH stale and unmirrored arrives twice.
	// Left in, it would eat two of the batch's slots and be POSTed to
	// /scan twice in one run, the second call racing the first for a
	// scan slot it does not need.
	seen := make(map[string]struct{}, len(all))
	eligible := make([]artifact.Artifact, 0, len(all))
	for _, a := range all {
		if _, dup := seen[a.ID]; dup {
			continue
		}
		seen[a.ID] = struct{}{}
		eligible = append(eligible, a)
	}
	sort.Slice(eligible, func(i, j int) bool {
		// LEAST RECENTLY ATTEMPTED first, which is what keeps a
		// permanently-broken artifact from monopolising every batch.
		// Ordering by CreatedAt alone would let one old, always-failing
		// artifact win the same slot on every single run -- it is
		// retried, stays failed, keeps its CreatedAt, and sorts first
		// again fifteen minutes later, while newer registrations behind
		// it are never reached.
		//
		// Never-attempted (nil) sorts before everything: an artifact
		// nobody has scanned once outranks retrying one that has been
		// scanned recently, however old the registration.
		ai, aj := eligible[i].LastScanAt, eligible[j].LastScanAt
		switch {
		case ai == nil && aj != nil:
			return true
		case ai != nil && aj == nil:
			return false
		case ai != nil && aj != nil && !ai.Equal(*aj):
			return ai.Before(*aj)
		}
		// Same attempt time (or both never attempted): oldest
		// registration first, preserving the fairness this had before
		// failed retries joined the queue.
		if !eligible[i].CreatedAt.Equal(eligible[j].CreatedAt) {
			return eligible[i].CreatedAt.Before(eligible[j].CreatedAt)
		}
		// Stable tie-break, so a batch is deterministic when several
		// artifacts were registered in the same instant (routine in a
		// bulk registration).
		return eligible[i].ID < eligible[j].ID
	})
	if len(eligible) > batchSize {
		eligible = eligible[:batchSize]
	}
	return eligible
}

// staleScans returns artifacts last scanned before cutoff -- the
// auto-rescan population (SWEEP_RESCAN_STALE_AFTER_DAYS).
//
// Never-scanned artifacts are excluded: they are status "registered"
// and this sweep already collects them separately, so including them
// here would just double-count. Same rule Store.CountStaleScans and the
// dashboard badge apply, so the number an operator sees and the set
// this rescans are the same set.
func staleScans(all []artifact.Artifact, cutoff time.Time) []artifact.Artifact {
	var out []artifact.Artifact
	for _, a := range all {
		if a.LastScanAt != nil && a.LastScanAt.Before(cutoff) {
			out = append(out, a)
		}
	}
	return out
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
// unmirroredArtifacts returns the artifacts whose mirroring has never
// been settled. Empty source_ref means exactly that -- not "could not be
// mirrored", which mirrorArtifact records by setting source_ref to the
// ref itself precisely so this filter terminates.
func unmirroredArtifacts(list []artifact.Artifact) []artifact.Artifact {
	var out []artifact.Artifact
	for _, a := range list {
		if a.SourceRef == "" {
			out = append(out, a)
		}
	}
	return out
}

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

// malwareScannersFor picks which malware-bucket scanner(s) a given
// malwareScanner setting selects, the direct counterpart of
// cveScannersFor above: "malcontent" swaps ClamAV out, "both" runs the
// two together, and anything else (including "clamav" and, as a
// fail-safe, an unrecognized value) is ClamAV alone.
//
// That default is what makes this feature inert on every existing
// deployment: with malwareScanner unset, the image scanner list is
// byte-for-byte what it was before malcontent existed -- see
// TestMalwareScannersFor_ClamAVIsUnchanged.
//
// The two answer different questions and are worth running together
// rather than instead of each other: ClamAV matches signatures of known
// malware, malcontent matches behaviours a compromised package would
// exhibit. See scanner.MalcontentScanner's own comment, including the
// measured false-positive profile that decides the minRisk default.
func malwareScannersFor(malwareScanner string, clamav, malcontent scanner.Scanner) []scanner.Scanner {
	switch malwareScanner {
	case "malcontent":
		return []scanner.Scanner{malcontent}
	case "both":
		return []scanner.Scanner{clamav, malcontent}
	default:
		return []scanner.Scanner{clamav}
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
func buildImageScanners(disableScanIsolation bool, cveScanner, malwareScanner string, trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcessUnpacker, isolatedUnpacker, inProcessMalcontent, isolatedMalcontent scanner.Scanner) []scanner.Scanner {
	if disableScanIsolation {
		return append(
			cveScannersFor(cveScanner, trivyInProcess, grypeInProcess),
			malwareScannersFor(malwareScanner, inProcessUnpacker, inProcessMalcontent)...,
		)
	}
	return append(
		cveScannersFor(cveScanner, trivyIsolated, grypeIsolated),
		malwareScannersFor(malwareScanner, isolatedUnpacker, isolatedMalcontent)...,
	)
}

// buildSBOMScanners picks the sbom artifact type's CVE scanner(s) the
// same way buildImageScanners picks image's: the isolated,
// Kubernetes-Job-per-scan path by default, or the in-process
// FetchingScanner+SBOMScanner/GrypeSBOMScanner fallback under
// DISABLE_SCAN_ISOLATION. Split out for the same reason
// buildImageScanners is: unit-testable (main_test.go) without needing
// a real Kubernetes API client.
// scanKinds is every scanner kind that can be capped independently --
// the suffixes SCAN_CONCURRENCY_<KIND> accepts. Enumerated rather than
// discovered from the registry so an unset variable can still be
// reported at startup, and so a typo in one is a variable that visibly
// does nothing rather than a silently-ignored setting.
var scanKinds = []string{"trivy", "grype", "clamav", "unpacker", "malcontent"}

// readPerKindScanCaps reads SCAN_CONCURRENCY_TRIVY,
// SCAN_CONCURRENCY_MALCONTENT and friends.
//
// UNSET inherits the global SCAN_CONCURRENCY, which is a no-op in
// practice (a scan takes the global slot too, so an equal per-kind cap
// never binds first) and becomes meaningful the moment it is lowered.
// That is the point: the memory cost of a scan belongs to the tool, and
// malcontent has OOMKilled at 2-8Gi on ordinary language-runtime images
// where trivy on the same image is comfortable -- so without this, the
// one global cap has to be set for malcontent's worst case and
// throttles every other scanner with it.
//
// An explicit 0 or negative means UNLIMITED for that kind, matching
// what the same value means for SCAN_CONCURRENCY itself. So
// SCAN_CONCURRENCY=8 with SCAN_CONCURRENCY_TRIVY=0 is "eight scans at
// once, and trivy is never the reason one is refused".
func readPerKindScanCaps(global int) map[string]int {
	caps := make(map[string]int, len(scanKinds))
	for _, kind := range scanKinds {
		env := "SCAN_CONCURRENCY_" + strings.ToUpper(kind)
		value := getenvInt(env, global)
		if value <= 0 {
			continue
		}
		caps[kind] = value
		if value != global {
			log.Printf("%s scans capped at %d concurrently (%s)", kind, value, env)
		}
	}
	return caps
}

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
	// dockerconfig.json, and trivy/grype/cosign via DOCKER_CONFIG)
	// against scm-registry's token-auth -- see
	// docs/architecture.md's registry-auth section. Empty (the default
	// before registry auth existed) means every one of those falls back
	// to unauthenticated behavior unchanged.
	registryUsername := os.Getenv("REGISTRY_USERNAME")
	registryPassword := os.Getenv("REGISTRY_PASSWORD")
	// trivy is NOT given TRIVY_USERNAME/TRIVY_PASSWORD any more, and
	// that is the point rather than an omission. Those two are applied
	// to whatever registry trivy happens to talk to -- measured against
	// a probe registry that the credentials were never configured for:
	// they authenticated it. With one registry that was merely untidy;
	// with several it means scm-registry's account is offered to
	// ghcr.io, docker.io and every other host a scan touches.
	//
	// DOCKER_CONFIG carries the same credentials keyed BY HOST, and
	// trivy honours it -- confirmed against the real binary: with the
	// pair unset and DOCKER_CONFIG pointing at a merged config, an
	// authenticated pull succeeds; with neither, it fails. It is
	// exported once dockerConfigPath exists, below.

	// Computed once, here, and reused by every registry-facing path
	// below: unpacker's --config, oras's --registry-config, and
	// grype/trivy/cosign's DOCKER_CONFIG. One merged file rather than
	// one per consumer -- they all authenticate against the same set of
	// registries, and a second write path is a second thing to forget.
	dockerConfigPath := writeDockerConfig(registryAddr, registryUsername, registryPassword, registryAuthDir())
	exportDockerConfig(dockerConfigPath)

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
	// Scan scratch space: an emptyDir on the node's disk by default, or
	// a per-Job PVC from a StorageClass when one is named here. Set once
	// for the whole process (k8sjob's package-level default) rather than
	// per-scanner, since it is one cluster-wide decision about where
	// extracted images land -- see k8sjob.ScratchStorageClass.
	//
	// Worth setting on any cluster where scan Jobs and the kubelet share
	// a filesystem: an image extraction measured at 2395Mi lands on the
	// node otherwise, and a full node evicts pods that have nothing to
	// do with scanning.
	k8sjob.ScratchStorageClass = getenv("SCAN_SCRATCH_STORAGE_CLASS", "")
	k8sjob.ScratchSize = getenv("SCAN_SCRATCH_SIZE", "")
	if k8sjob.ScratchStorageClass != "" {
		log.Printf("scan Jobs will take their /tmp scratch space from StorageClass %q (size %s) instead of a node-disk emptyDir",
			k8sjob.ScratchStorageClass, getenv("SCAN_SCRATCH_SIZE", "3Gi default"))
	}

	// MALWARE_SCANNER is cveScanner's counterpart for the malware
	// bucket: "clamav" (the default, and what every deployment did
	// before this existed), "malcontent", or "both". MALCONTENT_MIN_RISK
	// defaults to "critical" rather than the tool's own "low" -- a stock
	// alpine reports four HIGH behaviours, so anything below critical
	// puts malware findings on most of a normal fleet. See
	// scanner.MalcontentScanner.
	malwareScanner := getenv("MALWARE_SCANNER", "clamav")
	malcontentBin := getenv("MALCONTENT_BIN", "mal")
	malcontentMinRisk := getenv("MALCONTENT_MIN_RISK", "critical")
	switch cveScanner {
	case "trivy", "grype", "both":
	default:
		fatal(`CVE_SCANNER is invalid -- must be "trivy", "grype", or "both"`, "cve_scanner", cveScanner)
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
	// API_KEYS holds additional NAMED keys as "name:key,name:key" -- one
	// per consumer, so each authenticates as itself, appears by name in
	// the audit log, and can be revoked without re-keying every other
	// client. See internal/api.ParseAPIKeys.
	apiKeys := api.ParseAPIKeys(os.Getenv("API_KEYS"))
	// EITHER satisfies the requirement. Demanding API_KEY even when
	// named keys are configured would force every deployment to keep a
	// shared key alive forever, which is the thing named keys exist to
	// retire.
	if apiKey == "" && !apiKeys.Enabled() {
		fatal("no API key configured -- set API_KEY, or API_KEYS as \"name:key,name:key\"")
	}

	// API_KEY_SCOPES limits what each named key may do (report H1).
	//
	// REFUSES TO START on an unknown scope name. A typo'd "reader"
	// grants nothing and looks like a working configuration until
	// somebody hits a 403 they cannot explain -- and the opposite typo,
	// in a deployment that meant to restrict a key, would leave it
	// unrestricted instead. Neither is worth discovering at runtime.
	keyScopes, invalidScopes := api.ParseKeyScopes(os.Getenv("API_KEY_SCOPES"))
	if len(invalidScopes) > 0 {
		fatal("API_KEY_SCOPES contains entries that are not valid scopes -- refusing to start rather than enforce a permission model with holes in it",
			"invalid", strings.Join(invalidScopes, ", "),
			"valid_scopes", strings.Join(api.AllScopes, ", "))
	}
	if keyScopes.Enforced() {
		// Every client that authenticates, including the legacy shared
		// key's "default" identity.
		clients := append(apiKeys.Names(), legacyClientNameForLog(apiKey))
		if unscoped := keyScopes.Unscoped(clients); len(unscoped) > 0 {
			// NAMED, not counted. An unlisted client runs unrestricted
			// so that enabling scopes cannot lock out a deployment
			// mid-upgrade -- but that is a hole, and a hole nobody can
			// see is one nobody closes.
			slog.Warn("some API keys have no scopes configured and run UNRESTRICTED -- give them an entry in monitorApi.apiKeyScopes to close this",
				"unscoped_clients", strings.Join(unscoped, ", "))
		}
		slog.Info("API key scopes are enforced", "clients", len(clients))
	}
	// A SHORT KEY IS A WARNING, NOT A REFUSAL. Fataling here would brick
	// a running deployment on upgrade over a key that is weak but
	// working -- turning a security note into an outage, which is a
	// worse outcome than the weakness. It is loud, and it says what to
	// do about it.
	//
	// 32 bytes because that is what chart-secrets.sh generates
	// (openssl rand -hex 32 -> 64 characters) and roughly where guessing
	// stops being arithmetic worth doing. Named keys are generated the
	// same way, so they are not checked individually here.
	if apiKey != "" && len(apiKey) < 32 {
		slog.Warn("API_KEY is shorter than 32 characters -- weak against guessing; regenerate with `make chart-secrets`",
			"length", len(apiKey), "recommended_minimum", 32)
	}
	// TRUSTED_PROXY_CIDRS decides whether X-Forwarded-For is believed
	// when keying the failed-auth throttle. Empty keeps the original
	// behaviour (every peer's header honoured) -- see
	// api.ClientAddress for the trade-off that represents.
	//
	// A parse error is FATAL rather than skipped: silently dropping a
	// malformed entry could empty the set, and an empty set means
	// "trust everyone's header". A typo would then widen trust while
	// reading like a narrowing, which is the one way a security setting
	// must not fail.
	trustedProxies, err := api.ParseTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		fatal("TRUSTED_PROXY_CIDRS is invalid", "err", err)
	}
	if trustedProxies.Configured() {
		slog.Info("X-Forwarded-For is honoured only from trusted proxy CIDRs", "trusted_proxy_cidrs", os.Getenv("TRUSTED_PROXY_CIDRS"))
	} else {
		slog.Warn("TRUSTED_PROXY_CIDRS is unset -- X-Forwarded-For is honoured from ANY peer, so the failed-auth throttle can be evaded by rotating that header")
	}

	if apiKeys.Enabled() {
		// Names only, never the keys themselves: a key logged once
		// lives in the log aggregator forever.
		slog.Info("named API keys configured", "clients", apiKeys.Names(), "shared_key_also_active", apiKey != "")
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
		fatal("could not connect to postgres", "err", err)
	}

	stageTracker := pipeline.NewTracker(stages)

	// file/sbom/sarif artifacts can now be OCI registry references
	// (scm-registry by default), not just paths already sitting inside
	// this pod -- FetchingScanner below pulls them via `oras pull`
	// first. image artifacts don't need this: unpacker and trivy both
	// already fetch the image themselves. See internal/scanner/fetch.go.
	fetchPlainHTTP := getenvBool("FETCH_PLAIN_HTTP", true)
	// The merged docker config rather than the single pair: it holds
	// every configured registry's credentials keyed by host, so a
	// file/sbom/sarif ref naming ghcr.io authenticates with ghcr.io's
	// entry instead of scm-registry's. Falls back to the pair when
	// nothing is configured -- writeDockerConfig returns "" then.
	fetcher := registryFetcher(fetchPlainHTTP, dockerConfigPath, registryUsername, registryPassword)

	// Announced at startup for the same reason DISABLE_SCAN_ISOLATION is
	// (below): it re-enables a convention that is off by default because
	// ungated it let any ref name any file this pod could read. Logged
	// whichever way it's set, so "is this on?" is answerable from the
	// pod's first few log lines rather than by reading its env.
	if getenvBool("ALLOW_LOCAL_ARTIFACT_PATHS", false) {
		log.Printf("ALLOW_LOCAL_ARTIFACT_PATHS=true: refs may name files under LOCAL_ARTIFACT_ROOT=%q (empty means local paths stay refused) -- see README, \"Local filesystem paths as refs\"", os.Getenv("LOCAL_ARTIFACT_ROOT"))
	}

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
	// k8sjob.NewInClusterClient entirely (so the error it returns for a
	// missing KUBERNETES_SERVICE_HOST / ServiceAccount token, which
	// this file turns into a fatal, never happens) and falls back to
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
	inProcessUnpacker := scanner.NewUnpackerScanner(clamAddr, unpackerBin, unpackerInsecure, unpackerPublic, int64(unpackerMaxFileMB)*1024*1024, dockerConfigPath)
	// Signature/SLSA-provenance verification (report H2). Runs
	// IN-PROCESS rather than in an isolated Job: unlike trivy or
	// unpacker it parses no untrusted artifact content -- it makes
	// network calls and checks signatures -- so the isolation those
	// need buys nothing here, and a Job per verification would triple
	// the cost of a scan for no security gain.
	//
	// nil unless an identity AND issuer are configured; see
	// NewSigstoreScanner for why verifying without them is worse than
	// not verifying at all.
	sigstoreScanner := scanner.NewSigstoreScanner(scanner.SigstoreConfig{
		CertIdentityRegexp: os.Getenv("COSIGN_CERT_IDENTITY_REGEXP"),
		CertOIDCIssuer:     os.Getenv("COSIGN_CERT_OIDC_ISSUER"),
		RequireAttestation: getenvBool("COSIGN_REQUIRE_ATTESTATION", false),
		TrustedRootPath:    os.Getenv("COSIGN_TRUSTED_ROOT"),
		TUFMirror:          os.Getenv("COSIGN_TUF_MIRROR"),
		TUFRootPath:        os.Getenv("COSIGN_TUF_ROOT"),
		// Same directory grype is pointed at -- both use
		// go-containerregistry's keychain, which reads config.json from
		// DOCKER_CONFIG.
		DockerConfigDir: cosignDockerConfigDir(dockerConfigPath),
	})
	if getenvBool("COSIGN_ENABLED", false) && sigstoreScanner == nil {
		// Enabled but unusable. Refusing to start beats running with
		// provenance checking silently absent -- an artifact list with
		// no provenance findings would look like "everything is
		// signed".
		fatal("COSIGN_ENABLED is set but COSIGN_CERT_IDENTITY_REGEXP/COSIGN_CERT_OIDC_ISSUER are not -- " +
			"verifying without them only proves somebody signed the image, which anybody can arrange")
	}
	if !getenvBool("COSIGN_ENABLED", false) {
		sigstoreScanner = nil
	}
	if sigstoreScanner != nil {
		// TUF initialisation happens once, here, rather than on a scan
		// path: it writes a cache and talks to the mirror.
		if err := sigstoreScanner.Initialize(context.Background()); err != nil {
			fatal("could not initialise cosign against the configured Sigstore TUF mirror", "err", err)
		}
		slog.Info("provenance verification enabled", "trust_root", cosignTrustDescription())
	}

	inProcessTrivy := scanner.NewTrivyScanner(registryAddr, trivyDB)
	var grypeDockerConfigDir string
	if dockerConfigPath != "" {
		grypeDockerConfigDir = filepath.Dir(dockerConfigPath)
	}
	inProcessGrype := scanner.NewGrypeScanner(grypeDB, fetchPlainHTTP, grypeDockerConfigDir)
	// The second malware scanner, inert unless MALWARE_SCANNER selects
	// it (malwareScannersFor). Shares grype's dockerconfig dir for the
	// same reason: both pull the image themselves rather than being
	// handed a local path.
	inProcessMalcontent := scanner.NewMalcontentScanner(malcontentBin, malcontentMinRisk, grypeDockerConfigDir)
	// The in-process path needs a `mal` binary this image does not ship
	// (glibc vs musl -- see the Dockerfile). Said out loud at startup
	// rather than left to surface as an exec error on the first scan,
	// since the fix is to build a derived image, not to retry.
	if disableScanIsolation && (malwareScanner == "malcontent" || malwareScanner == "both") {
		log.Printf("MALWARE_SCANNER=%q with DISABLE_SCAN_ISOLATION=true requires a %q binary on PATH -- this image does not ship one (see the Dockerfile's malcontent note); scans will report an exec failure until you provide it in a derived image",
			malwareScanner, malcontentBin)
	}

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
		fatal("SCAN_TIMEOUT_SECONDS must be greater than SCAN_WORKER_ACTIVE_DEADLINE_SECONDS -- otherwise a scan gets reported as timed out before Kubernetes would even kill a genuinely stuck scan-worker Job",
			"scan_timeout_seconds", scanTimeoutSeconds,
			"scan_worker_active_deadline_seconds", scanWorkerActiveDeadlineSeconds)
	}
	scanTimeout := time.Duration(scanTimeoutSeconds) * time.Second

	var isolatedUnpacker scanner.Scanner
	// nil unless isolation is on, exactly like isolatedUnpacker above --
	// and only ever reached when MALWARE_SCANNER selects it, so a
	// DISABLE_SCAN_ISOLATION deployment never touches it.
	var isolatedMalcontent scanner.Scanner
	var isolatedTrivyImage scanner.Scanner
	var isolatedTrivySBOM scanner.Scanner
	var isolatedGrypeImage scanner.Scanner
	var isolatedGrypeSBOM scanner.Scanner
	if !disableScanIsolation {
		k8sClient, err := k8sjob.NewInClusterClient()
		if err != nil {
			fatal("could not create the kubernetes client for scan-worker jobs (set DISABLE_SCAN_ISOLATION=true to run without one -- see README)", "err", err)
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
		// Note the Image: upstream's malcontent, NOT workerImage. Every
		// other isolated scanner runs `monitor-api scan-worker` out of
		// this project's own image; malcontent's binary is glibc-linked
		// and cannot live in it (see the Dockerfile's note), so its Job
		// runs Chainguard's image directly.
		isolatedMalcontent = scanner.NewIsolatedMalcontentScanner(k8sClient, scanner.IsolatedMalcontentConfig{
			Image:                 getenv("MALCONTENT_IMAGE", scanner.DefaultMalcontentImage),
			MinRisk:               malcontentMinRisk,
			ActiveDeadlineSeconds: int64(scanWorkerActiveDeadlineSeconds),
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
			// Per-Job upload credential, minted at Job creation and
			// scoped to this one artifact. Lives slightly longer than
			// the Job's own deadline so a worker finishing right at the
			// limit can still post its SBOM.
			MintScanToken: func(artifactID string) (string, error) {
				token, hash, err := api.NewScanToken()
				if err != nil {
					return "", err
				}
				ttl := time.Duration(scanWorkerActiveDeadlineSeconds+300) * time.Second
				if err := store.CreateScanToken(artifactID, hash, time.Now().Add(ttl)); err != nil {
					return "", err
				}
				return token, nil
			},
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
		artifact.TypeImage: appendSigstore(buildImageScanners(disableScanIsolation, cveScanner, malwareScanner,
			inProcessTrivy, isolatedTrivyImage, inProcessGrype, isolatedGrypeImage,
			inProcessUnpacker, isolatedUnpacker, inProcessMalcontent, isolatedMalcontent), sigstoreScanner),
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
			fatal("PLUGGABLE_SCANNERS is not valid JSON", "err", err)
		}
		if err := registerPluggableScanners(scanners, specs, fetcher); err != nil {
			fatal("invalid PLUGGABLE_SCANNERS config", "err", err)
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
	digestResolver := digestResolverFor(dockerConfigPath, registryUsername, registryPassword)

	// MIRROR_ARTIFACTS: copy every registered artifact into this
	// cluster's own registry and scan the copy, instead of pulling from
	// docker.io/ghcr.io on every single scan. One switch, deliberately:
	// an empty REGISTRY_ADDR already means "there is no local registry",
	// and NewOrasMirror returns nil for it -- which is exactly what the
	// handler reads as "off". Off by default here so the chart, not the
	// binary's default, is what turns it on; see values.yaml for the
	// registry-disk cost it carries.
	//
	// The same merged docker config every other registry path uses:
	// `oras copy` has to authenticate to BOTH ends, and this one file
	// already holds the public source's credentials and scm-registry's
	// keyed by host.
	var artifactMirror scanner.Mirror
	if getenvBool("MIRROR_ARTIFACTS", false) {
		if m := scanner.NewOrasMirror(registryAddr, getenv("MIRROR_REPO_PREFIX", scanner.DefaultMirrorRepoPrefix), fetchPlainHTTP, dockerConfigPath, mirrorDockerConfig(registryAddr, dockerConfigPath), digestResolver); m != nil {
			artifactMirror = m
			slog.Info("artifact mirroring is on: registered artifacts are copied into the local registry and scanned from there",
				"registry", registryAddr, "repo_prefix", m.RepoPrefix)
		} else {
			log.Printf("MIRROR_ARTIFACTS=true but REGISTRY_ADDR is empty -- nothing to mirror into, artifacts keep their original refs")
		}
	}

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
	perKindConcurrency := readPerKindScanCaps(scanConcurrency)
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
		fatal("NOTIFY_MIN_SEVERITY is not a known severity (critical, high, medium, low, negligible, unknown)", "notify_min_severity", notifyMinSeverity)
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

	// Default true: on an artifact's first scan every finding is "new"
	// only because nobody had looked before, so leaving this on keeps
	// enabling notifications from paging once per already-registered
	// artifact. Turn it off where the first scan IS the interesting
	// event -- e.g. artifacts registered and scanned once at import.
	suppressFirstScan := getenvBool("NOTIFY_SUPPRESS_FIRST_SCAN", true)
	if len(notifiers) > 0 && !suppressFirstScan {
		log.Printf("notifications: first-scan suppression disabled -- an artifact's first scan will notify too")
	}

	// MAX_ARTIFACTS bounds how many artifacts may exist at all. Nothing
	// bounded this before: maxBulkArtifacts caps one request at 500 and
	// the body limits cap bytes per request, but a caller could repeat
	// either indefinitely, and every artifact costs a row, its findings,
	// its stage history, and a share of every List the dashboard polls.
	// 0 (the default) is unlimited, the same "zero reads as off"
	// convention RATE_LIMIT_RPS and SCAN_CONCURRENCY already use.
	maxArtifacts := getenvInt("MAX_ARTIFACTS", 0)
	if maxArtifacts > 0 {
		log.Printf("registration capped at %d artifacts (MAX_ARTIFACTS)", maxArtifacts)
	}

	// POLICY_JSON / monitorApi.policy -- the pass/fail rule set
	// GET /api/v1/artifacts/{id}/policy evaluates.
	//
	// REFUSES TO START on a policy that is set but unparseable, rather
	// than falling back to "no rules". The whole point of this endpoint
	// is to be a CI gate, and a gate that reports green while enforcing
	// nothing is worse than no gate -- nobody investigates a passing
	// build. Unset is the legitimate "no policy" case and starts fine.
	policyRules, err := policy.Load(os.Getenv("POLICY_JSON"))
	if err != nil {
		fatal("POLICY_JSON is set but could not be parsed -- refusing to start rather than run a policy gate that enforces nothing",
			"err", err)
	}
	slog.Info("policy gate", "configured", policyRules.Configured())

	router := api.NewRouter(api.Config{
		Store:          store,
		Tracker:        stageTracker,
		Scanners:       scanners,
		APIKey:         apiKey,
		APIKeys:        apiKeys,
		KeyScopes:      keyScopes,
		TrustedProxies: trustedProxies,
		// Validates a scan worker's per-Job upload token (report S3).
		ScanTokens: store.ConsumeScanToken,
		// Empty = same-origin only. The dashboard proxies through its
		// own nginx, so it needs no entry here.
		CORSAllowedOrigins: splitAndTrim(os.Getenv("CORS_ALLOWED_ORIGINS")),
		RateLimitRPS:       rateLimitRPS,
		RateLimitBurst:     rateLimitBurst,
		DigestResolver:     digestResolver,
		Mirror:             artifactMirror,
		FetchPlainHTTP:     fetchPlainHTTP,
		ScanTimeout:        scanTimeout,
		RequireDigest:      requireDigest,
		ScanLimits:         api.ScanLimits{Concurrency: scanConcurrency, PerKind: perKindConcurrency},
		Notifications:      api.Notifications{Notifiers: notifiers, MinSeverity: notifyMinSeverity, NotifyOnFirstScan: !suppressFirstScan},
		RegLimits:          api.RegistrationLimits{MaxArtifacts: maxArtifacts},
		// What GET /readyz actually checks. This is the only place a
		// concrete *PostgresStore is in scope -- api.Config takes a func
		// precisely so the Store interface doesn't have to grow a second
		// context-taking method to expose it.
		Ready: store.Ping,
		// Lets a scan of an sbom-type artifact index that artifact's own
		// component inventory -- see internal/api/scan.go's
		// indexSBOMTypeComponents. Same fetcher the file/sbom/sarif
		// scanners are already wrapped with.
		Fetcher: fetcher,
		// LICENSE_DENYLIST, e.g. "AGPL-3.0-only,SSPL-1.0". Empty (the
		// default) denies nothing and skips the evaluation entirely.
		LicenseDenylist: scanner.NewLicenseDenylist(os.Getenv("LICENSE_DENYLIST")),
		// 0 switches the staleness warning off entirely.
		StaleAfterDays: getenvInt("SCAN_STALE_AFTER_DAYS", 0),
		Policy:         policyRules,
		// KEV/EPSS annotation at scan time. Reads what the
		// enrich-refresh CronJob stored; with no refresh ever having
		// run it finds nothing and leaves findings untouched.
		Enricher: scanner.NewEnricher(store),
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: httpWriteTimeout,
	}

	log.Printf("monitor-api listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal("server error", "err", err)
	}
}

// splitAndTrim parses a comma-separated env list, dropping blanks so a
// trailing comma or an empty variable yields no entries rather than one
// empty entry -- an empty CORS origin would never match anything, but
// an empty entry in an allowlist is the kind of thing that quietly
// becomes a wildcard in a later refactor.
func splitAndTrim(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runEnrichRefresh downloads the KEV and EPSS feeds into the database.
//
// EXITS NON-ZERO ON ANY FEED FAILURE, even when the other feed
// succeeded and was stored. The CronJob's own success/failure is the
// only signal anybody watches for this, and a refresh that half-worked
// while reporting success is exactly how enrichment silently rots into
// a red badge that never appears -- which reads as good news.
func runEnrichRefresh() {
	setupLogging()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	store, err := connectStoreWithRetry(ctx, buildPostgresDSN(), 12, 5*time.Second)
	if err != nil {
		fatal("enrich-refresh: could not connect to postgres", "err", err)
	}
	defer store.Close()

	start := time.Now().UTC()
	enricher := scanner.NewEnricher(store)
	refreshErr := enricher.Refresh(ctx, start)

	status, statusErr := store.EnrichmentStatus()
	if statusErr != nil {
		slog.Warn("enrich-refresh: could not read back feed status", "err", statusErr)
	} else {
		slog.Info("enrich-refresh: feeds",
			"kev_entries", status.KEVEntries, "kev_updated_at", status.KEVUpdatedAt,
			"epss_entries", status.EPSSEntries, "epss_updated_at", status.EPSSUpdatedAt,
			"took", time.Since(start).Round(time.Second).String())
	}

	if refreshErr != nil {
		fatal("enrich-refresh: at least one feed failed -- enrichment is now stale for it", "err", refreshErr)
	}
	slog.Info("enrich-refresh: done")
}

// legacyClientNameForLog names the identity the single shared API_KEY
// authenticates as, or "" when no shared key is configured -- so the
// unscoped-clients warning covers it too. It is the one every existing
// consumer (dashboard, sweep CronJob) presents.
func legacyClientNameForLog(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	return "default"
}

// appendSigstore adds the provenance scanner to the image type's list
// when one is configured. Separate from buildImageScanners so that
// function keeps its single job -- choosing between the isolated and
// in-process variants of the CVE/malware scanners.
func appendSigstore(scanners []scanner.Scanner, sigstoreScanner *scanner.SigstoreScanner) []scanner.Scanner {
	if sigstoreScanner == nil {
		return scanners
	}
	return append(scanners, sigstoreScanner)
}

// cosignTrustDescription names which Sigstore is in force, for the
// startup log -- "public" versus a private deployment is the single
// most consequential thing about this configuration, and the least
// visible.
func cosignTrustDescription() string {
	switch {
	case os.Getenv("COSIGN_TRUSTED_ROOT") != "":
		return "private (trusted root " + os.Getenv("COSIGN_TRUSTED_ROOT") + ")"
	case os.Getenv("COSIGN_TUF_MIRROR") != "":
		return "private (TUF mirror " + os.Getenv("COSIGN_TUF_MIRROR") + ")"
	default:
		return "public Sigstore"
	}
}

// cosignDockerConfigDir mirrors the grypeDockerConfigDir derivation:
// DOCKER_CONFIG names a DIRECTORY containing config.json, while
// writeDockerConfig returns the path to the file itself.
func cosignDockerConfigDir(dockerConfigPath string) string {
	if dockerConfigPath == "" {
		return ""
	}
	return filepath.Dir(dockerConfigPath)
}
