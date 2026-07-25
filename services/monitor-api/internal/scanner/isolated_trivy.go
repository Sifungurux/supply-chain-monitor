package scanner

import (
	"context"
	"fmt"
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
	// worker as SCM_TRIVY_MODE -- see main.go's runScanWorker.
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
		c.EphemeralStorageRequest = "128Mi"
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
		// Small on purpose: --cache-backend memory means the scan cache
		// never touches disk, and the vulnerability DB itself is a
		// read-only mount, not something this Job writes -- there's
		// nothing here that should ever grow.
		c.EphemeralStorageLimit = "256Mi"
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

// Bucket implements BucketAffinity: both SubCommand modes ("image" and
// "sbom") run TrivyScanner/SBOMScanner's own code inside the Job (see
// runScanWorker in main.go), which only ever produces "cve" findings.
func (s *IsolatedTrivyScanner) Bucket() string { return "cve" }

func (s *IsolatedTrivyScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	name, err := randomJobName()
	if err != nil {
		return nil, fmt.Errorf("generate scan job name: %w", err)
	}

	const cacheVolumeName = "trivy-db-cache"

	job := k8sjob.NewScanJob(k8sjob.ScanJobConfig{
		Name:                  name,
		Namespace:             s.client.Namespace(),
		Image:                 s.cfg.Image,
		ServiceAccount:        s.cfg.ServiceAccount,
		Command:               []string{"/usr/local/bin/monitor-api", "scan-worker"},
		ActiveDeadlineSeconds: s.cfg.ActiveDeadlineSeconds,
		Env: map[string]string{
			"SCM_SCAN_REF":    ref,
			"SCM_TRIVY_MODE":  s.cfg.SubCommand,
			"TRIVY_CACHE_DIR": s.cfg.CacheMountPath,
			// Only actually consulted by the worker in "sbom" mode (see
			// FetchPlainHTTP's own comment) -- harmless to always set.
			"FETCH_PLAIN_HTTP": strconv.FormatBool(s.cfg.FetchPlainHTTP),
			// See VerboseLogs's own comment.
			"SCM_SCAN_VERBOSE": strconv.FormatBool(s.cfg.VerboseLogs),
		},
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

// waitForCompletion is identical to IsolatedUnpackerScanner's -- see
// that method's comment. Not shared as a free function only because
// each type still needs its own s.client/s.cfg.PollInterval; the logic
// itself is a few lines and not worth an extra abstraction for.
func (s *IsolatedTrivyScanner) waitForCompletion(ctx context.Context, name string) error {
	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	for {
		succeeded, failed, err := s.client.JobStatus(ctx, name)
		if err != nil {
			return fmt.Errorf("check job status: %w", err)
		}
		if failed {
			return fmt.Errorf("trivy scan job failed to run (crashed or was killed before producing a result)")
		}
		if succeeded {
			return nil
		}

		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for trivy scan job to complete: %w", ctx.Err())
		}
	}
}
