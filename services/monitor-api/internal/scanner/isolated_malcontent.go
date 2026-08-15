package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

// IsolatedMalcontentConfig configures the scan-worker Job
// IsolatedMalcontentScanner creates per scan. Mirrors
// IsolatedUnpackerConfig (the other malware-bucket scanner) rather than
// the trivy/grype ones, since this is the same kind of work: pull an
// image and read every file in it.
type IsolatedMalcontentConfig struct {
	// Image is Chainguard's malcontent image -- NOT monitor-api's own,
	// unlike every other isolated scanner here. malcontent publishes no
	// release binaries and its binary is glibc-linked, so it cannot be
	// copied into this project's musl/alpine image (see the Dockerfile's
	// own note). Running upstream's image directly avoids the problem
	// and gives the scan a smaller, purpose-built root filesystem than
	// monitor-api's.
	//
	// Pin it by digest. DefaultMalcontentImage below is what the chart
	// passes.
	Image          string
	ServiceAccount string

	// MinRisk becomes --min-risk. Empty means the binary's own default
	// ("low"), which the chart deliberately overrides -- see
	// MalcontentScanner's comment for the alpine measurement behind
	// that.
	MinRisk string

	// ponytail: no registry-credential plumbing. The other isolated
	// scanners run `monitor-api scan-worker`, which builds a
	// dockerconfig.json out of REGISTRY_USERNAME/PASSWORD before
	// scanning; this Job runs upstream's binary directly, with no such
	// step, so a private-registry pull would need a mounted
	// dockerconfig (malcontent reads DOCKER_CONFIG) rather than env
	// vars. Public images work today; add the volume mount when a
	// private one has to be scanned.

	PollInterval          time.Duration
	ActiveDeadlineSeconds int64

	CPURequest, MemoryRequest, EphemeralStorageRequest string
	CPULimit, MemoryLimit, EphemeralStorageLimit       string
}

func (c IsolatedMalcontentConfig) withDefaults() IsolatedMalcontentConfig {
	if c.Image == "" {
		c.Image = DefaultMalcontentImage
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
		// "image", not "sbom": malcontent pulls and extracts the image
		// the same way trivy/grype/unpacker do, so it needs the same
		// room. See isolated.go for the measurements -- the sbom sizing
		// (128Mi/256Mi) would kill this Job on anything but a tiny image.
		c.EphemeralStorageRequest = ephemeralStorageRequestFor("image")
	}
	if c.CPULimit == "" {
		c.CPULimit = "1"
	}
	if c.MemoryLimit == "" {
		// Measured, not guessed -- the 2Gi this shipped with was a guess
		// and it was wrong. Trial Jobs on the k3d cluster, one image per
		// run, `kubectl top` sampled every 2s:
		//
		//	alpine:3.19            2Gi   15s   ok     4 rules
		//	node-exporter:v1.8.1   2Gi   27s   ok     1 rule (1 CRITICAL)
		//	python:3.11-slim       2Gi   25s   ok    16 rules, 34 HIGH
		//	lambda/python:3.12     2Gi    --   OOMKilled
		//	rust:1.79              2Gi    --   OOMKilled
		//	rust:1.79              4Gi    --   OOMKilled
		//	rust:1.79              6Gi    --   OOMKilled
		//	rust:1.79              8Gi  119s   ok    28 rules, peak 6351Mi
		//	playwright:v1.44-jammy 8Gi    --   OOMKilled
		//
		// So a rust-sized image needs ~6.4Gi and the largest image in
		// this project's own test fleet needs more than 8Gi. YARA
		// matching over every file in an image is in a different league
		// from streaming those files to clamd, which does the same work
		// inside 1Gi.
		//
		// 8Gi is the limit, not a reservation: the request stays at
		// MemoryRequest (256Mi), so this does not change scheduling --
		// it changes how far a scan may grow before the kubelet kills
		// it. Two things follow, and neither is solved here:
		//
		//   - A node has to be able to give it. On the 15GiB podman VM
		//     this project develops against, one such scan is most of
		//     the machine.
		//   - SCAN_CONCURRENCY (8 by default) applies to every scanner
		//     equally, and eight concurrent 8Gi scans is not a thing any
		//     of these nodes can do. Enabling malcontent fleet-wide
		//     wants a per-scanner concurrency cap, which does not exist.
		//
		// Both are why monitorApi.malwareScanner still defaults to
		// "clamav". See the README's malcontent section.
		c.MemoryLimit = "8Gi"
	}
	if c.EphemeralStorageLimit == "" {
		c.EphemeralStorageLimit = ephemeralStorageLimitFor("image")
	}
	return c
}

// IsolatedMalcontentScanner runs MalcontentScanner's exact work in a
// dedicated Kubernetes Job, for the same reason IsolatedUnpackerScanner
// does: it pulls and parses arbitrary, potentially malicious image
// content, and a parsing bug in that path should not have the same blast
// radius as a bug in monitor-api itself. See docs/architecture.md
// ("Isolating the unpack+scan step").
//
// This is also why malcontent is wired as a first-class scanner rather
// than as a PLUGGABLE_SCANNERS entry: registerPluggableScanners
// registers `image`-type pluggable scanners in-process (main.go), so a
// pluggable malcontent would pull and extract images inside the
// monitor-api pod -- whose ephemeral-storage limit was deliberately
// reduced once that work moved out to Jobs.
type IsolatedMalcontentScanner struct {
	client jobClient
	cfg    IsolatedMalcontentConfig
}

func NewIsolatedMalcontentScanner(client jobClient, cfg IsolatedMalcontentConfig) *IsolatedMalcontentScanner {
	return &IsolatedMalcontentScanner{client: client, cfg: cfg.withDefaults()}
}

// Bucket implements BucketAffinity: this Job only ever runs
// MalcontentScanner, which only ever produces malware-bucket findings.
func (s *IsolatedMalcontentScanner) Bucket() string { return "malware" }

func (s *IsolatedMalcontentScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	name, err := randomJobName()
	if err != nil {
		return nil, fmt.Errorf("generate scan job name: %w", err)
	}

	// The Job runs upstream's binary directly -- there is no
	// `monitor-api scan-worker` in this image, so unlike every other
	// isolated scanner here the arguments, not an env var, say what to
	// do. Reusing MalcontentScanner.args keeps the isolated and
	// in-process invocations identical by construction.
	args := NewMalcontentScanner("", s.cfg.MinRisk, "").args(ref)

	job := k8sjob.NewScanJob(k8sjob.ScanJobConfig{
		Name:                    name,
		Namespace:               s.client.Namespace(),
		Image:                   s.cfg.Image,
		ServiceAccount:          s.cfg.ServiceAccount,
		Command:                 append([]string{malcontentBinPath}, args...),
		ActiveDeadlineSeconds:   s.cfg.ActiveDeadlineSeconds,
		CPURequest:              s.cfg.CPURequest,
		MemoryRequest:           s.cfg.MemoryRequest,
		EphemeralStorageRequest: s.cfg.EphemeralStorageRequest,
		CPULimit:                s.cfg.CPULimit,
		MemoryLimit:             s.cfg.MemoryLimit,
		EphemeralStorageLimit:   s.cfg.EphemeralStorageLimit,
	})

	// Same cleanup discipline as IsolatedUnpackerScanner: armed before
	// CreateJob is attempted, with its own context, since ctx may
	// already be dead by the time this runs. Read that file's comment
	// before changing this.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.client.DeleteJob(cleanupCtx, name)
	}()

	if err := s.client.CreateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("create malcontent scan job for %q: %w", ref, err)
	}
	if err := waitForJob(ctx, s.client, name, "malcontent scan job", s.cfg.PollInterval); err != nil {
		return nil, fmt.Errorf("malcontent scan job for %q: %w", ref, err)
	}

	pod, err := s.client.FindPodForJob(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("find pod for finished malcontent scan job %q: %w", name, err)
	}
	logs, err := s.client.PodLogs(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("read logs for malcontent scan job %q: %w", name, err)
	}

	// Pod logs are stdout+stderr combined, and this Job prints
	// malcontent's own report rather than the WorkerResult envelope the
	// other isolated scanners emit -- there is no monitor-api process in
	// this pod to write one. So the report is carved out of whatever
	// else landed in the stream.
	report, err := extractMalcontentJSON(logs)
	if err != nil {
		return nil, fmt.Errorf("malcontent scan job %q: %w (output: %s)", name, err, truncateForError(logs))
	}
	findings, err := ParseMalcontentReport(report)
	if err != nil {
		return nil, err
	}
	// The severity floor is applied here, not by the flag the Job was
	// given -- see MalcontentScanner.minRisk for the measurement showing
	// --min-risk changes nothing in scan mode.
	return FilterBySeverity(findings, s.cfg.MinRisk), nil
}

// malcontentBinPath is where the binary lives in Chainguard's image
// (its entrypoint is /usr/bin/mal). Named here because the Job
// overrides the entrypoint to pass arguments.
const malcontentBinPath = "/usr/bin/mal"

// DefaultMalcontentImage pins upstream's image by multi-arch index
// digest -- the tag moves, the digest does not, and the index resolves
// per architecture so this works on an arm64 dev cluster and amd64 CI
// alike. This digest is v1.25.9.
//
// Chainguard's free tier keeps only :latest, so a digest eventually
// stops being pullable and this needs bumping; that surfaces as an
// ImagePullBackOff on the Job, not as a wrong result.
const DefaultMalcontentImage = "cgr.dev/chainguard/malcontent@sha256:c71f2ff27243efb52494a468379a0182bfb304716b7139daf331d3b5db0416a6"

// extractMalcontentJSON finds the report inside a pod log stream. The
// report is one JSON object, so the first "{" to the last "}" is it --
// anything malcontent logged before or after is discarded. Deliberately
// not json.Decoder-on-the-whole-stream: leading non-JSON output would
// fail that immediately, which is exactly what happens the first time
// the tool logs a warning.
func extractMalcontentJSON(logs string) ([]byte, error) {
	start := strings.Index(logs, "{")
	end := strings.LastIndex(logs, "}")
	if start < 0 || end < start {
		return nil, fmt.Errorf("no JSON report found in the job's output")
	}
	return []byte(logs[start : end+1]), nil
}

func boolEnv(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Kind implements ScanKind. Same kind as the in-process malcontent scanner:
// the cap bounds concurrent runs of the TOOL, and whether it runs in a
// Job or in this process does not change what it costs to run.
func (s *IsolatedMalcontentScanner) Kind() string { return "malcontent" }
