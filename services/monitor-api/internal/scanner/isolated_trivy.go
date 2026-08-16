package scanner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

// IsolatedTrivyConfig configures the Kubernetes Job IsolatedTrivyScanner
// creates per scan. Mirrors IsolatedUnpackerConfig's shape closely --
// see that type's comment for the general pattern this follows.
type IsolatedTrivyConfig struct {
	// Image is the container image the scan-worker Job runs -- almost
	// always monitor-api's own image (`monitor-api scan-worker` is the
	// same binary in a different mode), same as IsolatedUnpackerConfig.
	Image string
	// ServiceAccount is the Job pod's ServiceAccount -- scm-scan-worker,
	// same as every other scan-worker Job (no RBAC bound to it: this
	// pod only ever reads a mounted volume and calls `trivy`, it has no
	// reason to talk to the Kubernetes API itself).
	ServiceAccount string

	// SubCommand selects which trivy invocation the worker runs:
	// "image" (TrivyScanner, for `image`-type artifacts) or "sbom"
	// (SBOMScanner, for `sbom`-type artifacts). Forwarded to the
	// worker as SCM_SCAN_MODE (alongside SCM_SCAN_TOOL=trivy) -- see
	// main.go's runScanWorker.
	SubCommand string

	// FetchPlainHTTP only matters when SubCommand is "sbom": ref for an
	// sbom-type artifact may be an OCI registry reference (scm-registry
	// by default) rather than a path already inside this Job's pod --
	// unlike "image" mode, where trivy itself resolves the ref, the
	// worker has to fetch the SBOM document first (see main.go's
	// runScanWorker), exactly like FetchingScanner does for the
	// in-process path. Forwarded to the worker as FETCH_PLAIN_HTTP.
	FetchPlainHTTP bool

	// VerboseLogs, forwarded to the worker as SCM_SCAN_VERBOSE, makes
	// this Job set scanner.VerboseScanLogs at startup (see main.go's
	// runScanWorker) -- see VerboseScanLogs's own comment in scanner.go
	// for what that actually changes. Sourced from
	// SCAN_WORKER_VERBOSE_LOGS in runAPIServer (values.yaml's
	// monitorApi.scanWorker.verboseLogs), off by default.
	VerboseLogs bool

	// CacheClaimName is the shared, centrally-refreshed PersistentVolumeClaim
	// holding the pre-downloaded trivy vulnerability DB (see
	// charts/supply-chain-monitor/templates/monitor-api/trivy-db-cache-pvc.yaml
	// and its primer Job/refresh CronJob) -- mounted read-only into
	// this Job's pod. Required: an isolated Trivy worker with no DB to
	// read would fail every scan.
	CacheClaimName string
	// CacheMountPath is where CacheClaimName is mounted inside the Job
	// pod, and is passed to `trivy --cache-dir` (via
	// TrivyDBConfig.CacheDir) so it looks there instead of trying to
	// download anything itself. Defaults to /trivy-cache if empty.
	CacheMountPath string

	// PollInterval controls how often Scan checks the Job's status.
	// Defaults to 2s if zero.
	PollInterval time.Duration
	// ActiveDeadlineSeconds bounds how long Kubernetes lets the Job's
	// pod run before killing it outright. Defaults to 330 (5m30s) if
	// zero -- same reasoning as IsolatedUnpackerConfig.
	ActiveDeadlineSeconds int64

	CPURequest, MemoryRequest, EphemeralStorageRequest string
	CPULimit, MemoryLimit, EphemeralStorageLimit       string

	// APIBaseURL, APIKeySecretName, and APIKeySecretKey are only
	// consulted when SubCommand is "image" -- they let the scan-worker
	// Job upload a generated SBOM/SARIF document (see documents.go's
	// GenerateImageDocuments and main.go's runScanWorker) back to
	// monitor-api's own in-cluster Service once it's done, the only
	// return path available for a document this size (findings still
	// return via the existing pod-logs/WorkerResult channel, unchanged
	// -- see ArtifactAwareScanner's comment). APIBaseURL empty disables
	// document capture entirely (ScanForArtifact never sets the
	// SCM_ARTIFACT_ID/SCM_API_BASE_URL/SCM_API_KEY env vars), so a
	// deployment that doesn't set this just gets findings, exactly as
	// before this existed.
	APIBaseURL       string
	APIKeySecretName string
	APIKeySecretKey  string

	// MintScanToken issues a per-Job upload credential scoped to one
	// artifact, replacing the master API key in the Job's environment
	// (report S3). nil falls back to the old SCM_API_KEY behaviour,
	// which keeps a deployment that has not migrated working rather
	// than silently failing every document upload.
	MintScanToken func(artifactID string) (string, error)

	// RegistryCredentialsSecretName/UsernameKey/PasswordKey, when
	// SecretName is set, forward scm-registry's read-only credentials
	// into the Job as TRIVY_USERNAME/TRIVY_PASSWORD -- trivy's own
	// native registry-auth env vars (os/exec inherits them
	// automatically, see trivy.go's ScanRaw), needed once scm-registry
	// requires auth (see docs/architecture.md's registry-auth section).
	// Empty SecretName disables this, the pre-registry-auth default.
	RegistryCredentialsSecretName string
	RegistryUsernameKey           string
	RegistryPasswordKey           string
}

func (c IsolatedTrivyConfig) withDefaults() IsolatedTrivyConfig {
	if c.Image == "" {
		c.Image = "monitor-api:dev"
	}
	if c.ServiceAccount == "" {
		c.ServiceAccount = "scm-scan-worker"
	}
	if c.SubCommand == "" {
		c.SubCommand = "image"
	}
	if c.CacheMountPath == "" {
		c.CacheMountPath = "/trivy-cache"
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.ActiveDeadlineSeconds <= 0 {
		c.ActiveDeadlineSeconds = 330
	}
	if c.CPURequest == "" {
		c.CPURequest = "200m"
	}
	if c.MemoryRequest == "" {
		c.MemoryRequest = "512Mi"
	}
	if c.EphemeralStorageRequest == "" {
		c.EphemeralStorageRequest = ephemeralStorageRequestFor(c.SubCommand)
	}
	if c.CPULimit == "" {
		c.CPULimit = "1"
	}
	if c.MemoryLimit == "" {
		// trivy's own DB decompression/indexing is memory-hungry --
		// see monitorApi.resources' comment in values.yaml for the
		// exact "signal: killed" symptom this headroom avoids. This Job
		// only reads the DB (already decompressed by the primer/refresh
		// Job), but still needs enough to load and query it comfortably.
		c.MemoryLimit = "1Gi"
	}
	if c.EphemeralStorageLimit == "" {
		c.EphemeralStorageLimit = ephemeralStorageLimitFor(c.SubCommand)
	}
	if c.APIKeySecretName == "" {
		// Same Secret the dashboard's render-config initContainer and
		// this pod's own API server already read the shared API key
		// from -- see charts/supply-chain-monitor/templates/monitor-api/deployment.yaml.
		c.APIKeySecretName = "scm-monitor-api-auth"
	}
	if c.APIKeySecretKey == "" {
		c.APIKeySecretKey = "API_KEY"
	}
	if c.RegistryCredentialsSecretName != "" {
		if c.RegistryUsernameKey == "" {
			c.RegistryUsernameKey = "REGISTRY_USERNAME"
		}
		if c.RegistryPasswordKey == "" {
			c.RegistryPasswordKey = "REGISTRY_PASSWORD"
		}
	}
	return c
}

// IsolatedTrivyScanner scans an `image` or `sbom` artifact for known
// CVEs the same way TrivyScanner/SBOMScanner do, but runs that work in
// a dedicated, short-lived Kubernetes Job instead of inside monitor-api's
// own long-running process -- the same isolation IsolatedUnpackerScanner
// already gives the malware-scanning path, and for a similar reason:
// even though trivy only reads package metadata (a much smaller attack
// surface than unpacking arbitrary image content), it's still a
// third-party binary parsing untrusted input, and giving it its own
// pod means a crash or resource spike there can never affect the API
// server pod itself. See docs/architecture.md ("Isolating Trivy
// scanning").
//
// The vulnerability DB itself is not downloaded fresh per scan (that
// would make every scan slow and network-dependent). Instead, a shared
// PersistentVolumeClaim holds a DB kept warm by a separate primer
// Job/refresh CronJob, mounted read-only here. trivy's DB is opened
// read-only internally, so many of these Jobs can run concurrently
// against the same PVC with no lock contention -- see
// TrivyDBConfig.CacheDir's comment for the one piece of this that does
// need care (the scan cache, kept in-memory via --cache-backend memory
// specifically to avoid that lock).
type IsolatedTrivyScanner struct {
	client jobClient
	cfg    IsolatedTrivyConfig
}

func NewIsolatedTrivyScanner(client jobClient, cfg IsolatedTrivyConfig) *IsolatedTrivyScanner {
	return &IsolatedTrivyScanner{client: client, cfg: cfg.withDefaults()}
}

// Buckets implements MultiBucketAffinity, and is MODE-AWARE.
//
// The scan-worker Job runs TrivyScanner/SBOMScanner's own code and
// parses in-Job, handing back already-classified findings via
// WorkerResult (see runScanWorker in main.go) -- so whatever those
// scanners produce, this scanner produces, and the two must agree.
//
//   - "image" runs TrivyScanner, now `--scanners vuln,secret`: cve AND
//     secret.
//   - "sbom" runs SBOMScanner, `trivy sbom`: cve only. There are no
//     files in an SBOM to find secrets in.
//
// Split rather than returning both for both modes: declaring "secret"
// for the sbom mode would make an SBOM-scan failure block secret
// fix-detection for a bucket that mode can never contribute to --
// safe, but it would suppress real "fixed" transitions for no reason.
func (s *IsolatedTrivyScanner) Buckets() []string {
	if s.cfg.SubCommand == "sbom" {
		return []string{"cve"}
	}
	return []string{"cve", "secret"}
}

// Scan implements the base Scanner interface -- equivalent to
// ScanForArtifact with an empty artifactID, which never triggers
// document capture (see ScanForArtifact's comment). Kept as a thin
// wrapper so every existing caller (and test) that only knows about
// Scanner, not ArtifactAwareScanner, is unaffected.
func (s *IsolatedTrivyScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	return s.ScanForArtifact(ctx, ref, "")
}

// ScanForArtifact implements ArtifactAwareScanner: identical to Scan,
// except that when SubCommand is "image" and both artifactID and
// s.cfg.APIBaseURL are set, the Job also gets SCM_ARTIFACT_ID/
// SCM_API_BASE_URL/SCM_API_KEY env vars -- runScanWorker's image branch
// (main.go) uses those to best-effort upload a generated SBOM/SARIF
// document back to monitor-api once the scan itself is done. Findings
// still return exactly as before, via the pod-logs/WorkerResult channel
// -- the document upload is a separate, independent HTTP call the
// worker makes from inside the Job, not part of that channel's
// contract at all.
func (s *IsolatedTrivyScanner) ScanForArtifact(ctx context.Context, ref, artifactID string) ([]artifact.Finding, error) {
	name, err := randomJobName()
	if err != nil {
		return nil, fmt.Errorf("generate scan job name: %w", err)
	}

	const cacheVolumeName = "trivy-db-cache"

	env := map[string]string{
		"SCM_SCAN_REF":    ref,
		"SCM_SCAN_TOOL":   "trivy",
		"SCM_SCAN_MODE":   s.cfg.SubCommand,
		"TRIVY_CACHE_DIR": s.cfg.CacheMountPath,
		// Only actually consulted by the worker in "sbom" mode (see
		// FetchPlainHTTP's own comment) -- harmless to always set.
		"FETCH_PLAIN_HTTP": strconv.FormatBool(s.cfg.FetchPlainHTTP),
		// See VerboseLogs's own comment.
		"SCM_SCAN_VERBOSE": strconv.FormatBool(s.cfg.VerboseLogs),
	}
	// Forwarded, not plumbed through IsolatedTrivyConfig, so the Job and
	// this process can't disagree about it: the worker's "sbom" branch
	// calls the same RegistryFetcher.Fetch -> ValidateRef this process
	// does, reading the same variable. Without it a Job would refuse the
	// in-cluster registry it exists to pull the SBOM from.
	if allow := os.Getenv(RefHostAllowlistEnv); allow != "" {
		env[RefHostAllowlistEnv] = allow
	}
	var secretEnv []k8sjob.SecretEnvVar
	if s.cfg.SubCommand == "image" && artifactID != "" && s.cfg.APIBaseURL != "" {
		env["SCM_ARTIFACT_ID"] = artifactID
		env["SCM_API_BASE_URL"] = s.cfg.APIBaseURL
		// A per-Job token, not the master key. This pod is built to
		// process untrusted content -- handing it the credential that
		// can delete every artifact in the fleet defeated the isolation
		// it is wrapped in.
		//
		// Passed as a plain env var rather than through a Secret: it is
		// single-use per kind and expires with the Job, so a Secret
		// would add a create/delete lifecycle around a value that is
		// already worthless by the time anyone could read it back. The
		// tradeoff is that it appears in the Pod spec, readable by
		// anyone who can already read Pods in this namespace -- who can
		// also read the Secret.
		minted := false
		if s.cfg.MintScanToken != nil {
			if token, err := s.cfg.MintScanToken(artifactID); err == nil && token != "" {
				env["SCM_SCAN_TOKEN"] = token
				minted = true
			}
			// A minting failure falls through to the API key below
			// rather than producing a Job that cannot upload: losing
			// the SBOM is a worse outcome than the older credential.
		}
		if !minted {
			secretEnv = append(secretEnv, k8sjob.SecretEnvVar{Name: "SCM_API_KEY", SecretName: s.cfg.APIKeySecretName, SecretKey: s.cfg.APIKeySecretKey})
		}
	}
	if s.cfg.RegistryCredentialsSecretName != "" {
		secretEnv = append(secretEnv,
			// TRIVY_USERNAME/PASSWORD: trivy's own native registry-auth
			// env vars, for "image" mode's direct pull.
			k8sjob.SecretEnvVar{Name: "TRIVY_USERNAME", SecretName: s.cfg.RegistryCredentialsSecretName, SecretKey: s.cfg.RegistryUsernameKey},
			k8sjob.SecretEnvVar{Name: "TRIVY_PASSWORD", SecretName: s.cfg.RegistryCredentialsSecretName, SecretKey: s.cfg.RegistryPasswordKey},
			// REGISTRY_USERNAME/PASSWORD: consulted by runScanWorker's
			// "sbom" branch (main.go) for its own RegistryFetcher pull,
			// which happens before trivy ever runs -- a completely
			// separate credential consumer from the two above, just
			// sourced from the same Secret. Harmless in "image" mode,
			// where nothing reads these.
			k8sjob.SecretEnvVar{Name: "REGISTRY_USERNAME", SecretName: s.cfg.RegistryCredentialsSecretName, SecretKey: s.cfg.RegistryUsernameKey},
			k8sjob.SecretEnvVar{Name: "REGISTRY_PASSWORD", SecretName: s.cfg.RegistryCredentialsSecretName, SecretKey: s.cfg.RegistryPasswordKey},
		)
	}

	job := k8sjob.NewScanJob(k8sjob.ScanJobConfig{
		Name:                  name,
		Namespace:             s.client.Namespace(),
		Image:                 s.cfg.Image,
		ServiceAccount:        s.cfg.ServiceAccount,
		Command:               []string{"/usr/local/bin/monitor-api", "scan-worker"},
		ActiveDeadlineSeconds: s.cfg.ActiveDeadlineSeconds,
		Env:                   env,
		SecretEnvVars:         secretEnv,
		ExtraVolumes: []k8sjob.Volume{
			{
				Name: cacheVolumeName,
				PersistentVolumeClaim: &k8sjob.PVCVolumeSource{
					ClaimName: s.cfg.CacheClaimName,
					ReadOnly:  true,
				},
			},
		},
		ExtraVolumeMounts: []k8sjob.VolumeMount{
			{Name: cacheVolumeName, MountPath: s.cfg.CacheMountPath, ReadOnly: true},
		},
		CPURequest:              s.cfg.CPURequest,
		MemoryRequest:           s.cfg.MemoryRequest,
		EphemeralStorageRequest: s.cfg.EphemeralStorageRequest,
		CPULimit:                s.cfg.CPULimit,
		MemoryLimit:             s.cfg.MemoryLimit,
		EphemeralStorageLimit:   s.cfg.EphemeralStorageLimit,
		// "sbom" mode opts back into an emptyDir -- see scratchClassFor.
		ScratchStorageClass: scratchClassFor(s.cfg.SubCommand),
	})

	// See IsolatedUnpackerScanner.Scan's identical comment: this must be
	// registered *before* CreateJob is attempted, not after -- a defer
	// only runs if control actually reached the defer statement, so
	// registering it after a CreateJob error-check-and-return meant
	// cleanup silently never ran on a CreateJob failure. Runs on its
	// own short-lived context that's never already-canceled, since ctx
	// may be dead by the time we get here.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.client.DeleteJob(cleanupCtx, name)
	}()

	if err := s.client.CreateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("create trivy scan job for %q: %w", ref, err)
	}

	if err := s.waitForCompletion(ctx, name); err != nil {
		return nil, fmt.Errorf("trivy scan job for %q: %w", ref, err)
	}

	pod, err := s.client.FindPodForJob(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("find pod for finished trivy scan job %q: %w", name, err)
	}
	logs, err := s.client.PodLogs(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("read logs for trivy scan job %q: %w", name, err)
	}

	result, err := ExtractWorkerResult(logs)
	if err != nil {
		return nil, fmt.Errorf("trivy scan job %q %w", name, err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return result.Findings, nil
}

// waitForCompletion delegates to the shared wait loop -- see waitForJob
// in jobwait.go for the retry and backoff behaviour, and why polling
// every Job at a flat interval was enough to saturate this project's
// API server at SCAN_CONCURRENCY=8.
func (s *IsolatedTrivyScanner) waitForCompletion(ctx context.Context, name string) error {
	return waitForJob(ctx, s.client, name, "trivy scan job", s.cfg.PollInterval)
}

// Kind implements ScanKind. Same kind as the in-process trivy scanner:
// the cap bounds concurrent runs of the TOOL, and whether it runs in a
// Job or in this process does not change what it costs to run.
func (s *IsolatedTrivyScanner) Kind() string { return "trivy" }
