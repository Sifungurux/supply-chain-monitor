package scanner

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

// IsolatedGrypeConfig configures the Kubernetes Job IsolatedGrypeScanner
// creates per scan. Mirrors IsolatedTrivyConfig's shape closely -- see
// that type's comment for the general pattern. Deliberately has no
// APIBaseURL/APIKeySecret* fields: unlike trivy, grype doesn't generate
// an SBOM/SARIF document to upload back (see documents.go), so there's
// nothing for those fields to configure here.
type IsolatedGrypeConfig struct {
	// Image is the container image the scan-worker Job runs -- almost
	// always monitor-api's own image (`monitor-api scan-worker` is the
	// same binary in a different mode), same as IsolatedTrivyConfig.
	Image string
	// ServiceAccount is the Job pod's ServiceAccount -- scm-scan-worker,
	// same as every other scan-worker Job.
	ServiceAccount string

	// SubCommand selects which grype invocation the worker runs: "image"
	// (GrypeScanner, for `image`-type artifacts) or "sbom"
	// (GrypeSBOMScanner, for `sbom`-type artifacts). Forwarded to the
	// worker as SCM_SCAN_MODE, alongside SCM_SCAN_TOOL=grype -- see
	// main.go's runScanWorker.
	SubCommand string

	// FetchPlainHTTP only matters when SubCommand is "sbom": same
	// reasoning as IsolatedTrivyConfig.FetchPlainHTTP -- the worker has
	// to fetch the SBOM document itself before grype can read it.
	// Forwarded to the worker as FETCH_PLAIN_HTTP.
	FetchPlainHTTP bool

	// VerboseLogs, forwarded to the worker as SCM_SCAN_VERBOSE. See
	// VerboseScanLogs's own comment in scanner.go.
	VerboseLogs bool

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

	// RegistryAddr is set as SYFT_REGISTRY_AUTH_AUTHORITY (a plain env
	// var, not a Secret -- it's just a hostname, not a credential) so
	// grype's registry-auth library knows which registry
	// RegistryCredentialsSecretName's username/password apply to.
	// Confirmed via `grype config --load` against the real binary: grype
	// shares Syft's registry-auth code, so its env vars are
	// SYFT_REGISTRY_AUTH_*, not GRYPE_REGISTRY_AUTH_* -- see grype.go's
	// package comment.
	RegistryAddr string
	// RegistryCredentialsSecretName/UsernameKey/PasswordKey, when
	// SecretName is set, forward scm-registry's read-only credentials
	// into the Job as SYFT_REGISTRY_AUTH_USERNAME/PASSWORD. Empty
	// SecretName disables this.
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
		c.EphemeralStorageRequest = "128Mi"
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
		c.EphemeralStorageLimit = "256Mi"
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
	}
	if s.cfg.RegistryAddr != "" {
		env["SYFT_REGISTRY_AUTH_AUTHORITY"] = s.cfg.RegistryAddr
	}
	var secretEnv []k8sjob.SecretEnvVar
	if s.cfg.RegistryCredentialsSecretName != "" {
		secretEnv = append(secretEnv,
			// SYFT_REGISTRY_AUTH_USERNAME/PASSWORD: grype's own
			// registry-auth env vars (shared with Syft, see
			// IsolatedGrypeConfig.RegistryAddr's comment), for "image"
			// mode's direct pull.
			k8sjob.SecretEnvVar{Name: "SYFT_REGISTRY_AUTH_USERNAME", SecretName: s.cfg.RegistryCredentialsSecretName, SecretKey: s.cfg.RegistryUsernameKey},
			k8sjob.SecretEnvVar{Name: "SYFT_REGISTRY_AUTH_PASSWORD", SecretName: s.cfg.RegistryCredentialsSecretName, SecretKey: s.cfg.RegistryPasswordKey},
			// REGISTRY_USERNAME/PASSWORD: consulted by runScanWorker's
			// "sbom" branch for its own RegistryFetcher pull, same as
			// IsolatedTrivyScanner's identical pair -- see that type's
			// comment.
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

// waitForCompletion is identical to IsolatedTrivyScanner's -- see that
// method's comment for why this small amount of duplication is
// deliberate rather than shared.
func (s *IsolatedGrypeScanner) waitForCompletion(ctx context.Context, name string) error {
	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	for {
		succeeded, failed, err := s.client.JobStatus(ctx, name)
		if err != nil {
			return fmt.Errorf("check job status: %w", err)
		}
		if failed {
			return fmt.Errorf("grype scan job failed to run (crashed or was killed before producing a result)")
		}
		if succeeded {
			return nil
		}

		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for grype scan job to complete: %w", ctx.Err())
		}
	}
}
