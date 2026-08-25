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

// IsolatedGrypeConfig configures the Kubernetes Job IsolatedGrypeScanner
// creates per scan. Mirrors IsolatedTrivyConfig's shape closely -- see
// that type's comment for the general pattern.
//
// APIBaseURL/MintScanToken are used by the "sbom-doc" SubCommand ONLY,
// and for the opposite reason trivy's identical pair exists: trivy's
// worker uploads a document it generated, this one DOWNLOADS a document
// somebody already stored. Both other SubCommands ("image", "sbom")
// leave them unset and never call back to the API at all.
type IsolatedGrypeConfig struct {
	// Image is the container image the scan-worker Job runs -- almost
	// always monitor-api's own image (`monitor-api scan-worker` is the
	// same binary in a different mode), same as IsolatedTrivyConfig.
	Image string
	// ServiceAccount is the Job pod's ServiceAccount -- scm-scan-worker,
	// same as every other scan-worker Job.
	ServiceAccount string

	// SubCommand selects which grype invocation the worker runs:
	// "image" (GrypeScanner, for `image`-type artifacts), "sbom"
	// (GrypeSBOMScanner against an SBOM the worker fetches from a
	// registry ref, for `sbom`-type artifacts), or "sbom-doc"
	// (GrypeSBOMScanner against the SBOM document already stored for an
	// `image` artifact, downloaded back from this API). Forwarded to
	// the worker as SCM_SCAN_MODE, alongside SCM_SCAN_TOOL=grype -- see
	// main.go's runScanWorker.
	SubCommand string

	// APIBaseURL is monitor-api's own Service URL, forwarded to the
	// worker as SCM_SCAN_API_BASE_URL. "sbom-doc" mode only: that is
	// where the worker GETs the stored SBOM from. Empty disables the
	// callback, which makes "sbom-doc" fail rather than silently scan
	// nothing.
	APIBaseURL string
	// MintScanToken issues the per-Job credential the worker presents
	// for that download, scoped to the one artifact being scanned (see
	// internal/api/scantoken.go). "sbom-doc" mode only. nil means no
	// token is minted and the download will be refused -- deliberately
	// a visible failure, not a fallback to the master API key.
	MintScanToken func(artifactID string) (string, error)

	// FetchPlainHTTP only matters when SubCommand is "sbom": same
	// reasoning as IsolatedTrivyConfig.FetchPlainHTTP -- the worker has
	// to fetch the SBOM document itself before grype can read it.
	// Forwarded to the worker as FETCH_PLAIN_HTTP.
	FetchPlainHTTP bool

	// VerboseLogs, forwarded to the worker as SCM_SCAN_VERBOSE. See
	// VerboseScanLogs's own comment in scanner.go.
	VerboseLogs bool

	// ByCVE, forwarded to the worker as GRYPE_BY_CVE. See
	// GrypeByCVE's own comment in scanner.go for why a deployment
	// wants this on.
	ByCVE bool

	// CacheClaimName is the shared, centrally-refreshed
	// PersistentVolumeClaim holding the pre-downloaded grype
	// vulnerability DB (see
	// charts/supply-chain-monitor/templates/monitor-api/grype-db-cache-pvc.yaml
	// and its primer Job/refresh CronJob) -- mounted read-only into this
	// Job's pod. Required: an isolated grype worker with no DB to read
	// would fail every scan.
	CacheClaimName string
	// CacheMountPath is where CacheClaimName is mounted inside the Job
	// pod, passed to the worker as GRYPE_CACHE_DIR (via
	// GrypeDBConfig.CacheDir). Defaults to /grype-cache if empty.
	CacheMountPath string

	// PollInterval controls how often Scan checks the Job's status.
	// Defaults to 2s if zero.
	PollInterval time.Duration
	// ActiveDeadlineSeconds bounds how long Kubernetes lets the Job's
	// pod run before killing it outright. Defaults to 330 (5m30s) if
	// zero -- same reasoning as IsolatedTrivyConfig.
	ActiveDeadlineSeconds int64

	CPURequest, MemoryRequest, EphemeralStorageRequest string
	CPULimit, MemoryLimit, EphemeralStorageLimit       string

	// RegistryAddr is forwarded to the worker as the plain env var
	// REGISTRY_ADDR -- exactly mirroring IsolatedUnpackerConfig's own
	// RegistryAddr/REGISTRY_ADDR. The worker uses it (alongside
	// REGISTRY_USERNAME/PASSWORD below) to build a dockerconfig.json via
	// main.go's writeDockerConfig, the same helper the default
	// (unpacker) branch of runScanWorker already calls -- then points
	// grype at it via DOCKER_CONFIG (see grype.go's registryEnv, whose
	// doc comment explains why this file does NOT set
	// SYFT_REGISTRY_AUTH_* here: that was the first design tried, and it
	// was verified -- against a real probe registry, not just read from
	// docs -- to never actually get sent, since it targets a config-file
	// array field env vars can't populate element-by-element).
	RegistryAddr string
	// RegistryCredentialsSecretName/UsernameKey/PasswordKey, when
	// SecretName is set, forward scm-registry's read-only credentials
	// into the Job as REGISTRY_USERNAME/PASSWORD -- consulted by the
	// worker for both grype's own dockerconfig.json (above) and, in
	// "sbom" mode, RegistryFetcher's own pull (same pair
	// IsolatedTrivyScanner's identical fields already forward for that
	// second purpose). Empty SecretName disables this.
	RegistryCredentialsSecretName string
	RegistryUsernameKey           string
	RegistryPasswordKey           string
}

func (c IsolatedGrypeConfig) withDefaults() IsolatedGrypeConfig {
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
		c.CacheMountPath = "/grype-cache"
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
		// Same headroom reasoning as IsolatedTrivyConfig.MemoryLimit --
		// loading and querying a decompressed vulnerability DB is
		// memory-hungry regardless of which scanner does it.
		c.MemoryLimit = "1Gi"
	}
	if c.EphemeralStorageLimit == "" {
		c.EphemeralStorageLimit = ephemeralStorageLimitFor(c.SubCommand)
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

// IsolatedGrypeScanner scans an `image` or `sbom` artifact for known
// CVEs the same way GrypeScanner/GrypeSBOMScanner do, but runs that
// work in a dedicated, short-lived Kubernetes Job instead of inside
// monitor-api's own long-running process -- the same isolation
// IsolatedTrivyScanner already gives trivy, for the same reason (a
// third-party binary parsing untrusted input gets its own pod). See
// IsolatedTrivyScanner's comment for the full reasoning, which applies
// here unchanged.
type IsolatedGrypeScanner struct {
	client jobClient
	cfg    IsolatedGrypeConfig
}

func NewIsolatedGrypeScanner(client jobClient, cfg IsolatedGrypeConfig) *IsolatedGrypeScanner {
	return &IsolatedGrypeScanner{client: client, cfg: cfg.withDefaults()}
}

// Bucket implements BucketAffinity: both SubCommand modes ("image" and
// "sbom") run GrypeScanner/GrypeSBOMScanner's own code inside the Job
// (see runScanWorker in main.go), which only ever produces "cve"
// findings.
func (s *IsolatedGrypeScanner) Bucket() string { return "cve" }

func (s *IsolatedGrypeScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	return s.scan(ctx, ref, "")
}

// ScanForArtifact implements ArtifactAwareScanner. Only "sbom-doc" mode
// has any use for the artifact ID -- it is what the worker downloads
// the stored SBOM by -- so the other modes ignore it and behave exactly
// as Scan does. scanArtifact (internal/api/scan.go) prefers this method
// whenever a scanner offers it, so both paths must stay equivalent for
// the modes that don't care.
func (s *IsolatedGrypeScanner) ScanForArtifact(ctx context.Context, ref, artifactID string) ([]artifact.Finding, error) {
	return s.scan(ctx, ref, artifactID)
}

func (s *IsolatedGrypeScanner) scan(ctx context.Context, ref, artifactID string) ([]artifact.Finding, error) {
	name, err := randomJobName()
	if err != nil {
		return nil, fmt.Errorf("generate scan job name: %w", err)
	}

	const cacheVolumeName = "grype-db-cache"

	env := map[string]string{
		"SCM_SCAN_REF":     ref,
		"SCM_SCAN_TOOL":    "grype",
		"SCM_SCAN_MODE":    s.cfg.SubCommand,
		"GRYPE_CACHE_DIR":  s.cfg.CacheMountPath,
		"FETCH_PLAIN_HTTP": strconv.FormatBool(s.cfg.FetchPlainHTTP),
		"SCM_SCAN_VERBOSE": strconv.FormatBool(s.cfg.VerboseLogs),
		"GRYPE_BY_CVE":     strconv.FormatBool(s.cfg.ByCVE),
	}
	if s.cfg.RegistryAddr != "" {
		env["REGISTRY_ADDR"] = s.cfg.RegistryAddr
	}
	// Same forwarding IsolatedTrivyScanner does, for the same reason --
	// see that Job's own comment on this variable.
	if allow := os.Getenv(RefHostAllowlistEnv); allow != "" {
		env[RefHostAllowlistEnv] = allow
	}
	// "sbom-doc" mode: the SBOM this re-evaluates lives in Postgres, not
	// in any registry, so unlike "sbom" mode there is no ref for the
	// worker to fetch. It downloads the document back from monitor-api
	// instead, which needs the artifact's ID and a credential.
	//
	// No fallback to the master API key, deliberately -- the opposite
	// of IsolatedTrivyScanner's identical-looking block. There, minting
	// failure falls back so a generated SBOM isn't lost; here the
	// download simply fails and the scan reports an error, which the
	// cve bucket then blocks on (see internal/api/scan.go). Losing one
	// re-evaluation round is cheap; handing untrusted-content pods the
	// fleet-wide key to avoid it is not.
	if s.cfg.SubCommand == "sbom-doc" && artifactID != "" && s.cfg.APIBaseURL != "" {
		env["SCM_ARTIFACT_ID"] = artifactID
		env["SCM_API_BASE_URL"] = s.cfg.APIBaseURL
		if s.cfg.MintScanToken != nil {
			token, err := s.cfg.MintScanToken(artifactID)
			if err != nil {
				return nil, fmt.Errorf("mint scan token for sbom re-evaluation of %q: %w", artifactID, err)
			}
			env["SCM_SCAN_TOKEN"] = token
		}
	}

	var secretEnv []k8sjob.SecretEnvVar
	if s.cfg.RegistryCredentialsSecretName != "" {
		// REGISTRY_USERNAME/PASSWORD: consulted by runScanWorker's grype
		// branches to build a dockerconfig.json (main.go's
		// writeDockerConfig, the same helper the default/unpacker branch
		// already calls) that grype gets pointed at via DOCKER_CONFIG --
		// see IsolatedGrypeConfig.RegistryAddr's comment for why this
		// file, not SYFT_REGISTRY_AUTH_*. In "sbom" mode this same pair
		// also feeds RegistryFetcher's own pull, same as
		// IsolatedTrivyScanner's identical pair.
		secretEnv = append(secretEnv,
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

	// See IsolatedTrivyScanner.ScanForArtifact's identical comment: must
	// be registered before CreateJob is attempted, not after.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.client.DeleteJob(cleanupCtx, name)
	}()

	if err := s.client.CreateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("create grype scan job for %q: %w", ref, err)
	}

	if err := s.waitForCompletion(ctx, name); err != nil {
		return nil, fmt.Errorf("grype scan job for %q: %w", ref, err)
	}

	pod, err := s.client.FindPodForJob(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("find pod for finished grype scan job %q: %w", name, err)
	}
	logs, err := s.client.PodLogs(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("read logs for grype scan job %q: %w", name, err)
	}

	result, err := ExtractWorkerResult(logs)
	if err != nil {
		return nil, fmt.Errorf("grype scan job %q %w", name, err)
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
func (s *IsolatedGrypeScanner) waitForCompletion(ctx context.Context, name string) error {
	return waitForJob(ctx, s.client, name, "grype scan job", s.cfg.PollInterval)
}

// Kind implements ScanKind. Same kind as the in-process grype scanner:
// the cap bounds concurrent runs of the TOOL, and whether it runs in a
// Job or in this process does not change what it costs to run.
func (s *IsolatedGrypeScanner) Kind() string { return "grype" }
