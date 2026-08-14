package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// GrypeDBConfig configures where grype's vulnerability DB lives.
// Unlike trivy (dbArgs, trivy.go), grype exposes none of this as CLI
// flags -- it's entirely env-var driven (confirmed via `grype config
// --load`, which prints the exact env var bound to every config key).
// See env() below for the mapping.
type GrypeDBConfig struct {
	// CacheDir points grype at a specific DB cache directory instead of
	// its own default (~/.cache/grype/db), via GRYPE_DB_CACHE_DIR. Empty
	// for the in-process GrypeScanner (grype's own default is fine
	// there); set by IsolatedGrypeScanner to the shared, centrally-
	// refreshed PersistentVolumeClaim mounted read-only into each
	// scan-worker Job -- same pattern as TrivyDBConfig.CacheDir.
	CacheDir string
	// SkipDBUpdate disables grype's own auto-update-on-run check
	// (GRYPE_DB_AUTO_UPDATE=false) -- set once a DB is already
	// cached/mirrored, exactly like TrivyDBConfig.SkipDBUpdate.
	SkipDBUpdate bool
	// SkipAgeValidation disables grype's max-DB-age check
	// (GRYPE_DB_VALIDATE_AGE=false). A shared PVC's DB freshness is the
	// primer Job/refresh CronJob's responsibility, not this scan's --
	// same reasoning IsolatedTrivyScanner's worker path always forces
	// SkipDBUpdate/SkipJavaDBUpdate true regardless of what the
	// in-process fallback does.
	SkipAgeValidation bool
}

// env returns the GRYPE_DB_* overrides this config implies, to append
// to exec.Cmd.Env alongside os.Environ() -- never used to *replace*
// os.Environ(), since that would also drop PATH and any
// SYFT_REGISTRY_AUTH_* credentials the caller set (see ScanRaw).
func (db GrypeDBConfig) env() []string {
	var env []string
	if db.CacheDir != "" {
		env = append(env, "GRYPE_DB_CACHE_DIR="+db.CacheDir)
	}
	if db.SkipDBUpdate {
		env = append(env, "GRYPE_DB_AUTO_UPDATE=false")
	}
	if db.SkipAgeValidation {
		env = append(env, "GRYPE_DB_VALIDATE_AGE=false")
	}
	return env
}

// GrypeScanner shells out to the grype CLI (installed into the
// monitor-api image, see Dockerfile) to scan an OCI image reference for
// known CVEs -- an alternative to TrivyScanner (trivy.go), selectable
// via monitorApi.cveScanner (see main.go's buildImageScanners).
type GrypeScanner struct {
	db GrypeDBConfig

	// plainHTTP and dockerConfigDir configure GrypeScanner's own
	// registry pull -- see registryEnv's comment for what each actually
	// does and why both were verified against the real binary rather
	// than trusted from documentation.
	plainHTTP       bool
	dockerConfigDir string
}

// NewGrypeScanner. plainHTTP mirrors RegistryFetcher.PlainHTTP/
// TRIVY's own implicit https-only behavior -- true for scm-registry,
// which serves plain HTTP (see values.yaml's fetchPlainHTTP). If
// dockerConfigDir is non-empty, it must be a directory containing a
// file literally named "config.json" (main.go's writeDockerConfig
// produces exactly that shape) -- see registryEnv's comment.
func NewGrypeScanner(db GrypeDBConfig, plainHTTP bool, dockerConfigDir string) *GrypeScanner {
	return &GrypeScanner{db: db, plainHTTP: plainHTTP, dockerConfigDir: dockerConfigDir}
}

// registryEnv builds the env vars that actually control grype's
// registry pull (as opposed to db.env(), which controls its DB cache).
// Both fields here were verified empirically against the real grype
// binary, not assumed from documentation -- see this package's own
// history for how each was discovered:
//
//   - GRYPE_REGISTRY_INSECURE_USE_HTTP: confirmed via `grype config
//     --load` (a real, scalar boolean config key, unlike the auth
//     array below) AND by reading go-containerregistry's own
//     Registry.Scheme() (pkg/name/registry.go): it defaults to https
//     for any hostname that isn't literally "localhost", a loopback
//     address, or an RFC1918 private IP -- scm-registry's real
//     in-cluster DNS name (scm-registry.<ns>.svc.cluster.local) matches
//     none of those, so without this, every plain-HTTP scm-registry
//     pull would fail a TLS handshake against a server that was never
//     speaking TLS in the first place.
//   - DOCKER_CONFIG: NOT SYFT_REGISTRY_AUTH_AUTHORITY/USERNAME/PASSWORD.
//     Those env vars are documented in `grype config --load`'s output
//     (grype shares Syft's config struct, hence the "SYFT_" prefix),
//     but empirically do nothing: a probe registry confirmed grype
//     never sends an Authorization header with them set, because
//     they'd bind to a slice field (registry.auth[]) that plain env
//     vars can't populate element-by-element -- the documented env var
//     comment is aspirational, not wired up. What does work,
//     confirmed against the same probe: pointing DOCKER_CONFIG at a
//     directory containing a "config.json" (go-containerregistry's
//     default credential-helper keychain, the same mechanism `docker
//     login` itself would populate) -- grype picks that up
//     automatically with zero grype-specific configuration. This is
//     exactly the fallback this feature's plan flagged as a
//     possibility before any of grype.go was written, and it's the one
//     that turned out to be true.
func (g *GrypeScanner) registryEnv() []string {
	var env []string
	if g.plainHTTP {
		env = append(env, "GRYPE_REGISTRY_INSECURE_USE_HTTP=true")
	}
	if g.dockerConfigDir != "" {
		env = append(env, "DOCKER_CONFIG="+g.dockerConfigDir)
	}
	return env
}

// Bucket implements BucketAffinity: every finding comes from
// parseGrypeVulnerabilities, which always sets Source: "grype" --
// classifyBucket's default case, "cve".
func (g *GrypeScanner) Bucket() string { return "cve" }

// args builds the grype CLI invocation. The "registry:" source prefix
// forces a direct registry pull (confirmed via `grype --help`: "pull
// image directly from a registry (no container runtime required)")
// rather than grype's default of trying a local Docker daemon first --
// neither the in-process caller (monitor-api's own pod) nor the
// isolated scan-worker Job (isolated_grype.go) has a docker/containerd/
// podman socket available, so there's no daemon to try in the first
// place; skipping straight to the registry avoids a guaranteed-to-fail
// probe on every scan.
func (g *GrypeScanner) args(ref string) []string {
	args := []string{"registry:" + ref, "-o", "json"}
	if VerboseScanLogs {
		args = append(args, "-vv")
	} else {
		args = append(args, "-q")
	}
	return args
}

// grypeReport mirrors the subset of `grype -o json`'s real output
// (confirmed via an actual `grype registry:alpine:3.19 -o json` run,
// not a guessed shape) this package actually needs. vulnerability.fix
// and artifact carry more fields than used here; only the ones mapped
// into artifact.Finding are declared.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

// parseGrypeVulnerabilities decodes grype's `-o json` output into
// normalized Findings. Split out from Scan so it's unit-testable
// against a canned fixture without needing the real grype binary (see
// grype_test.go).
//
// Title uses the affected package's name+version, not
// vulnerability.description: description is long (a full CVE
// paragraph, unlike trivy's own short Title field) and, confirmed
// against a real scan, not even always present on every match --
// name+version is always populated and immediately tells a reader
// which package triggered the finding, the same information a
// person reading `grype`'s own table output would look at first.
func parseGrypeVulnerabilities(output []byte) ([]artifact.Finding, error) {
	var report grypeReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	var findings []artifact.Finding
	for _, m := range report.Matches {
		findings = append(findings, artifact.Finding{
			ID:       m.Vulnerability.ID,
			Severity: m.Vulnerability.Severity,
			Title:    fmt.Sprintf("%s %s", m.Artifact.Name, m.Artifact.Version),
			Source:   "grype",
		})
	}
	return findings, nil
}

func (g *GrypeScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	output, err := g.ScanRaw(ctx, ref)
	if err != nil {
		return nil, err
	}
	return parseGrypeVulnerabilities(output)
}

// ScanRaw runs the grype CLI invocation, returning grype's raw JSON
// report bytes before any parsing.
func (g *GrypeScanner) ScanRaw(ctx context.Context, ref string) ([]byte, error) {
	// See TrivyScanner.ScanRaw's comment: this is the function that
	// hands the ref to grype, so this is where it gets checked.
	if err := ValidateRef(ctx, ref); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "grype", g.args(ref)...)
	// Start from the process's own environment, then layer the DB and
	// registry overrides on top -- dropping to just db.env()/registryEnv()
	// would also drop PATH, silently breaking the exec entirely.
	cmd.Env = append(os.Environ(), append(g.db.env(), g.registryEnv()...)...)

	var stdout, stderr bytes.Buffer
	if VerboseScanLogs {
		// See TrivyScanner.ScanRaw's identical teeing (trivy.go) for the
		// full reasoning: os.Stderr only, os.Stdout stays reserved for
		// the worker's own final ResultMarker line.
		cmd.Stdout = io.MultiWriter(&stdout, os.Stderr)
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("grype scan failed for %q: %w (%s)", ref, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// Kind implements ScanKind: this scanner is capped independently of
// the global scan cap via SCAN_CONCURRENCY_GRYPE.
func (s *GrypeScanner) Kind() string { return "grype" }
