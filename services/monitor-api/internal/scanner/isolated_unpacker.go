package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

// jobClient is the slice of *k8sjob.Client this scanner needs --
// narrowed to an interface so IsolatedUnpackerScanner is unit-testable
// with a fake instead of a real Kubernetes API server (see
// isolated_unpacker_test.go). *k8sjob.Client satisfies this as-is.
type jobClient interface {
	CreateJob(ctx context.Context, job *k8sjob.Job) error
	JobStatus(ctx context.Context, name string) (succeeded, failed bool, err error)
	FindPodForJob(ctx context.Context, jobName string) (string, error)
	PodLogs(ctx context.Context, podName string) (string, error)
	DeleteJob(ctx context.Context, name string) error
	Namespace() string
}

// IsolatedUnpackerConfig configures the Kubernetes Job
// IsolatedUnpackerScanner creates per scan. Mirrors the env vars
// UnpackerScanner itself takes (see main.go's runAPIServer), since
// they're just forwarded into the Job's container -- the actual
// unpacking/scanning code (UnpackerScanner) is unchanged and runs
// inside the Job's pod via `monitor-api scan-worker`.
type IsolatedUnpackerConfig struct {
	// Image is the container image the scan-worker Job runs --
	// almost always the same image monitor-api itself runs from
	// (SCAN_WORKER_IMAGE env var, defaults to monitor-api's own image
	// tag), since `monitor-api scan-worker` is the same binary.
	Image string
	// ServiceAccount is the Job pod's ServiceAccount -- deliberately
	// NOT monitor-api's own (see the scm-scan-worker ServiceAccount in
	// charts/supply-chain-monitor/templates/monitor-api/serviceaccount.yaml, which has zero
	// RBAC bound to it).
	ServiceAccount string

	ClamAddr          string
	UnpackerBin       string
	UnpackerInsecure  bool
	UnpackerPublic    bool
	UnpackerMaxFileMB int

	// PollInterval controls how often Scan checks the Job's status.
	// Defaults to 2s if zero.
	PollInterval time.Duration
	// ActiveDeadlineSeconds bounds how long Kubernetes lets the Job's
	// pod run before killing it outright, as a backstop in addition to
	// the worker's own internal scan timeout (main.go's
	// runScanWorker). Defaults to 330 (5m30s -- 30s more than the
	// worker's own 5-minute timeout) if zero.
	ActiveDeadlineSeconds int64

	CPURequest, MemoryRequest, EphemeralStorageRequest string
	CPULimit, MemoryLimit, EphemeralStorageLimit        string
}

func (c IsolatedUnpackerConfig) withDefaults() IsolatedUnpackerConfig {
	if c.Image == "" {
		c.Image = "monitor-api:dev"
	}
	if c.ServiceAccount == "" {
		c.ServiceAccount = "scm-scan-worker"
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
		c.MemoryRequest = "256Mi"
	}
	if c.EphemeralStorageRequest == "" {
		c.EphemeralStorageRequest = "512Mi"
	}
	if c.CPULimit == "" {
		c.CPULimit = "1"
	}
	if c.MemoryLimit == "" {
		c.MemoryLimit = "1Gi"
	}
	if c.EphemeralStorageLimit == "" {
		c.EphemeralStorageLimit = "2Gi"
	}
	return c
}

// IsolatedUnpackerScanner scans an `image` artifact for malware the
// same way UnpackerScanner does (pull + unpack + stream every file to
// ClamAV), but runs that work in a dedicated, short-lived Kubernetes
// Job instead of inside monitor-api's own long-running process.
//
// Why: UnpackerScanner pulls and parses arbitrary, potentially
// malicious image content via third-party libraries (oras-go /
// go-containerregistry / umoci). Running that in-process meant a
// parsing bug in any of them had the same blast radius as a bug in
// monitor-api itself -- the same process that holds every artifact's
// findings and the Postgres connection. A Job-per-scan gives each scan
// its own pod: a read-only root filesystem, every Linux capability
// dropped, a non-root user, no ServiceAccount token, and resource/time
// limits that can't affect the API server pod at all. See
// docs/architecture.md ("Isolating the unpack+scan step").
type IsolatedUnpackerScanner struct {
	client jobClient
	cfg    IsolatedUnpackerConfig
}

func NewIsolatedUnpackerScanner(client jobClient, cfg IsolatedUnpackerConfig) *IsolatedUnpackerScanner {
	return &IsolatedUnpackerScanner{client: client, cfg: cfg.withDefaults()}
}

func randomJobName() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "scm-scan-" + hex.EncodeToString(b), nil
}

// Bucket implements BucketAffinity: this Job always runs
// UnpackerScanner's exact code (see runScanWorker in main.go), which
// only ever produces Source: "clamav" findings -- always "malware".
func (s *IsolatedUnpackerScanner) Bucket() string { return "malware" }

func (s *IsolatedUnpackerScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	name, err := randomJobName()
	if err != nil {
		return nil, fmt.Errorf("generate scan job name: %w", err)
	}

	job := k8sjob.NewScanJob(k8sjob.ScanJobConfig{
		Name:                  name,
		Namespace:             s.client.Namespace(),
		Image:                 s.cfg.Image,
		ServiceAccount:        s.cfg.ServiceAccount,
		Command:               []string{"/usr/local/bin/monitor-api", "scan-worker"},
		ActiveDeadlineSeconds: s.cfg.ActiveDeadlineSeconds,
		Env: map[string]string{
			"SCM_SCAN_REF":          ref,
			"CLAMAV_ADDR":           s.cfg.ClamAddr,
			"UNPACKER_BIN":          s.cfg.UnpackerBin,
			"UNPACKER_INSECURE":     strconv.FormatBool(s.cfg.UnpackerInsecure),
			"UNPACKER_PUBLIC":       strconv.FormatBool(s.cfg.UnpackerPublic),
			"UNPACKER_MAX_FILE_MB":  strconv.Itoa(s.cfg.UnpackerMaxFileMB),
		},
		CPURequest:              s.cfg.CPURequest,
		MemoryRequest:           s.cfg.MemoryRequest,
		EphemeralStorageRequest: s.cfg.EphemeralStorageRequest,
		CPULimit:                s.cfg.CPULimit,
		MemoryLimit:             s.cfg.MemoryLimit,
		EphemeralStorageLimit:   s.cfg.EphemeralStorageLimit,
	})

	// Cleanup always runs, and always with its own short-lived,
	// never-already-canceled context -- ctx may be at (or past) its
	// deadline by the time we get here (e.g. the poll loop below timed
	// out), and internal/api/handlers.go already learned this lesson
	// once: never make cleanup/completion depend on a context that
	// might already be dead. Registered *before* CreateJob is even
	// attempted, not after: a defer only runs if control reached the
	// defer statement, so registering it after the CreateJob
	// error-check meant a CreateJob failure returned before cleanup was
	// ever armed -- a real bug (caught by go test actually running for
	// the first time, not by this file's own review, since no Go
	// toolchain exists in the sandbox this project was originally built
	// in). CreateJob can fail after the Job was actually created
	// server-side (e.g. the response timed out but the API server still
	// processed it), so DeleteJob still needs to at least try.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.client.DeleteJob(cleanupCtx, name)
	}()

	if err := s.client.CreateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("create scan job for %q: %w", ref, err)
	}

	if err := s.waitForCompletion(ctx, name); err != nil {
		return nil, fmt.Errorf("scan job for %q: %w", ref, err)
	}

	pod, err := s.client.FindPodForJob(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("find pod for finished scan job %q: %w", name, err)
	}
	logs, err := s.client.PodLogs(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("read logs for scan job %q: %w", name, err)
	}

	var result WorkerResult
	if err := json.Unmarshal([]byte(logs), &result); err != nil {
		return nil, fmt.Errorf("scan job %q produced unparseable output: %w (output: %.200s)", name, err, logs)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return result.Findings, nil
}

// waitForCompletion polls JobStatus until the Job succeeds, fails, or
// ctx is done. A "failed" Job (non-zero exit from the worker process
// itself, e.g. it crashed before it could even print a WorkerResult --
// see main.go's runScanWorker, which exits non-zero only for genuine
// setup failures) is reported as an error directly, since there's no
// WorkerResult JSON worth trying to parse in that case.
func (s *IsolatedUnpackerScanner) waitForCompletion(ctx context.Context, name string) error {
	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	for {
		succeeded, failed, err := s.client.JobStatus(ctx, name)
		if err != nil {
			return fmt.Errorf("check job status: %w", err)
		}
		if failed {
			return fmt.Errorf("scan job failed to run (crashed or was killed before producing a result)")
		}
		if succeeded {
			return nil
		}

		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for scan job to complete: %w", ctx.Err())
		}
	}
}
