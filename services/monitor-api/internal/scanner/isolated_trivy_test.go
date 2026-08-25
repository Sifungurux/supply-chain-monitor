package scanner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

// Reuses fakeJobClient from isolated_unpacker_test.go -- both types
// share the same jobClient interface, so the same fake covers both
// without duplicating it.

// recordingJobClient wraps fakeJobClient to additionally capture every
// Job passed to CreateJob -- needed for
// TestIsolatedTrivyScanner_Scan_MountsCacheVolumeReadOnly, which has to
// inspect the actual Job spec IsolatedTrivyScanner built (fakeJobClient
// alone discards it).
type recordingJobClient struct {
	fakeJobClient
	onCreate    func()
	createdJobs []*k8sjob.Job
}

func (f *recordingJobClient) CreateJob(ctx context.Context, job *k8sjob.Job) error {
	f.createdJobs = append(f.createdJobs, job)
	if f.onCreate != nil {
		f.onCreate()
	}
	return f.fakeJobClient.CreateJob(ctx, job)
}

func newTrivyScanner(t *testing.T, client jobClient) *IsolatedTrivyScanner {
	t.Helper()
	return NewIsolatedTrivyScanner(client, IsolatedTrivyConfig{
		Image:          "monitor-api:dev",
		CacheClaimName: "scm-trivy-db-cache",
		PollInterval:   time.Millisecond, // fast polling in tests
	})
}

func TestIsolatedTrivyScanner_Scan_HappyPath(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{}, {succeeded: true}}, // "still running" once, then done
		podName:        "scm-scan-abc-xyz",
		logs:           `{"findings":[{"id":"CVE-2024-1","severity":"HIGH","title":"some issue","source":"trivy"}]}`,
	}
	s := newTrivyScanner(t, client)

	findings, err := s.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "CVE-2024-1" {
		t.Fatalf("findings = %+v", findings)
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected the job to be deleted exactly once after a successful scan")
	}
}

func TestIsolatedTrivyScanner_Scan_CleansUpEvenOnFailure(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{failed: true}},
	}
	s := newTrivyScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job itself fails")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected cleanup (DeleteJob) even when the scan fails")
	}
}

func TestIsolatedTrivyScanner_Scan_CreateJobError(t *testing.T) {
	client := &fakeJobClient{
		namespace: "test-ns",
		createErr: errors.New("jobs.batch is forbidden"),
	}
	s := newTrivyScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job can't even be created")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected DeleteJob to still run as a harmless cleanup attempt")
	}
}

func TestIsolatedTrivyScanner_Scan_WorkerReportedError(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs:           `{"findings":null,"error":"trivy scan failed for \"alpine:3.19\": db not found"}`,
	}
	s := newTrivyScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected the worker-reported error to surface")
	}
}

// TestIsolatedTrivyScanner_Scan_VerboseLogsDontBreakParsing confirms the
// real reason ExtractWorkerResult/ResultMarker exist: with
// VerboseScanLogs on, a scan-worker Job's pod logs have trivy's own
// progress output mixed in ahead of the final result, and Scan must
// still find and use that result correctly rather than failing to
// parse the whole noisy log body as one JSON document.
func TestIsolatedTrivyScanner_Scan_VerboseLogsDontBreakParsing(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs: "INFO\tVulnerability scanning is enabled\n" +
			"INFO\tDetected OS: alpine\n" +
			ResultMarker + `{"findings":[{"id":"CVE-2024-9","severity":"LOW","title":"z","source":"trivy"}]}`,
	}
	s := newTrivyScanner(t, client)

	findings, err := s.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "CVE-2024-9" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestIsolatedTrivyScanner_Scan_UnparseableLogs(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs:           "not json at all",
	}
	s := newTrivyScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job's logs aren't valid WorkerResult JSON")
	}
}

func TestIsolatedTrivyScanner_Scan_TimesOutIfNeverFinishes(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{}}, // always "still running"
	}
	s := newTrivyScanner(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if _, err := s.Scan(ctx, "alpine:3.19"); err == nil {
		t.Fatal("expected a timeout error when the job never finishes")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected cleanup even after a timeout -- cleanup must use its own context, not the expired one")
	}
}

// Confirms the Job this scanner builds actually mounts the shared DB
// cache PVC read-only -- the whole point of this type versus just
// running IsolatedUnpackerConfig's Job builder with different env.
func TestIsolatedTrivyScanner_Scan_MountsCacheVolumeReadOnly(t *testing.T) {
	var seenJobViaCreate bool
	client := &recordingJobClient{
		fakeJobClient: fakeJobClient{
			namespace:      "test-ns",
			statusSequence: []jobStatusResult{{succeeded: true}},
			podName:        "scm-scan-abc-xyz",
			logs:           `{"findings":[]}`,
		},
		onCreate: func() { seenJobViaCreate = true },
	}
	s := newTrivyScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !seenJobViaCreate {
		t.Fatal("expected CreateJob to be called")
	}
	if len(client.createdJobs) != 1 {
		t.Fatalf("expected exactly 1 created job, got %d", len(client.createdJobs))
	}
	job := client.createdJobs[0]

	foundReadOnlyMount := false
	for _, vm := range job.Spec.Template.Spec.Containers[0].VolumeMounts {
		if vm.MountPath == "/trivy-cache" {
			if !vm.ReadOnly {
				t.Fatal("expected the trivy DB cache volume mount to be ReadOnly")
			}
			foundReadOnlyMount = true
		}
	}
	if !foundReadOnlyMount {
		t.Fatal("expected a volume mount at /trivy-cache")
	}

	foundPVCVolume := false
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			if v.PersistentVolumeClaim.ClaimName != "scm-trivy-db-cache" {
				t.Fatalf("claimName = %q, want scm-trivy-db-cache", v.PersistentVolumeClaim.ClaimName)
			}
			if !v.PersistentVolumeClaim.ReadOnly {
				t.Fatal("expected the PVC volume source itself to also be marked ReadOnly")
			}
			foundPVCVolume = true
		}
	}
	if !foundPVCVolume {
		t.Fatal("expected a persistentVolumeClaim-backed volume")
	}
}

// TestIsolatedTrivyScanner_Buckets confirms the declaration is
// MODE-AWARE, which is the whole point of it: the Job runs
// TrivyScanner's or SBOMScanner's own code (runScanWorker in main.go)
// and hands back already-classified findings, so what this declares has
// to match what that mode can actually produce.
//
// The "image" case is a safety property, not a cosmetic one. If it said
// only "cve", a failing image scan would leave the secret bucket
// unblocked and MergeFindings would mark every previously-open secret
// "fixed" because the scan that finds them never ran.
//
// The "sbom" case is the converse: `trivy sbom` has no secret scanner,
// so claiming "secret" there would block a bucket that mode can never
// contribute to and suppress real "fixed" transitions.
func TestIsolatedTrivyScanner_Buckets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		subCommand string
		want       []string
	}{
		{"image mode reports CVEs and secrets", "image", []string{"cve", "secret"}},
		{"default mode is image", "", []string{"cve", "secret"}},
		{"sbom mode cannot produce secrets", "sbom", []string{"cve"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewIsolatedTrivyScanner(&fakeJobClient{namespace: "test-ns"}, IsolatedTrivyConfig{
				Image:          "monitor-api:dev",
				CacheClaimName: "scm-trivy-db-cache",
				SubCommand:     tc.subCommand,
				PollInterval:   time.Millisecond,
			})
			got := s.Buckets()
			if len(got) != len(tc.want) {
				t.Fatalf("Buckets() = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("Buckets() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// An "sbom"-mode Job fetches one JSON document and spills nothing --
// it already carries the small 128Mi/256Mi sizing for that reason. So
// when a deployment moves scan scratch space onto a StorageClass, these
// Jobs opt back out: a PVC would add provisioning latency and a volume
// attach to buy storage they never write to.
//
// Asserted for both modes in one test, because the value of the rule is
// entirely in the contrast -- an implementation that opted EVERY Job out
// would pass a test that only looked at "sbom".
func TestIsolatedScanners_SBOMJobsKeepTheEmptyDirScratch(t *testing.T) {
	k8sjob.ScratchStorageClass, k8sjob.ScratchSize = "ceph-rbd", "10Gi"
	defer func() { k8sjob.ScratchStorageClass, k8sjob.ScratchSize = "", "" }()

	scratchOf := func(t *testing.T, job *k8sjob.Job) k8sjob.Volume {
		t.Helper()
		for _, v := range job.Spec.Template.Spec.Volumes {
			if v.Name == "scratch" {
				return v
			}
		}
		t.Fatal("no scratch volume on the job")
		return k8sjob.Volume{}
	}

	run := func(t *testing.T, s Scanner) *k8sjob.Job {
		t.Helper()
		client := &recordingJobClient{fakeJobClient: fakeJobClient{
			namespace:      "supply-chain-monitor",
			statusSequence: []jobStatusResult{{succeeded: true}},
			podName:        "p",
			logs:           `{"findings":[]}`,
		}}
		switch v := s.(type) {
		case *IsolatedTrivyScanner:
			v.client = client
		case *IsolatedGrypeScanner:
			v.client = client
		}
		if _, err := s.Scan(context.Background(), "alpine:3.19"); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		return client.createdJobs[0]
	}

	for _, tc := range []struct {
		name       string
		subCommand string
		wantPVC    bool
	}{
		{"trivy image mode takes the configured StorageClass", "image", true},
		{"trivy sbom mode keeps its emptyDir", "sbom", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewIsolatedTrivyScanner(nil, IsolatedTrivyConfig{Image: "monitor-api:dev", SubCommand: tc.subCommand})
			vol := scratchOf(t, run(t, s))
			if tc.wantPVC && vol.Ephemeral == nil {
				t.Fatalf("%s: want a volume claim template, got %+v", tc.subCommand, vol)
			}
			if !tc.wantPVC && vol.EmptyDir == nil {
				t.Fatalf("%s: want an emptyDir, got %+v", tc.subCommand, vol)
			}
		})
	}

	t.Run("grype sbom mode keeps its emptyDir too", func(t *testing.T) {
		s := NewIsolatedGrypeScanner(nil, IsolatedGrypeConfig{Image: "monitor-api:dev", SubCommand: "sbom"})
		if vol := scratchOf(t, run(t, s)); vol.EmptyDir == nil {
			t.Fatalf("want an emptyDir, got %+v", vol)
		}
	})
}

// TestIsolatedTrivy_NoHostAgnosticCredentialsInJobEnv is a regression
// guard on a credential-scoping fix, and the direction of its failure
// is why it exists at all.
//
// TRIVY_USERNAME/TRIVY_PASSWORD are applied by trivy to whatever
// registry it talks to, not to the one they were configured for --
// measured against a probe registry they were never meant for, which
// they authenticated. Setting them again would not break a single
// scan; it would silently start offering scm-registry's account to
// ghcr.io and docker.io. Nothing else in this suite would notice.
//
// The Job authenticates from the merged docker config instead
// (DOCKER_CONFIG, exported by runScanWorker), which is keyed by host.
func TestIsolatedTrivy_NoHostAgnosticCredentialsInJobEnv(t *testing.T) {
	client := &recordingJobClient{fakeJobClient: fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "p",
		logs:           `{"findings":[]}`,
	}}
	s := NewIsolatedTrivyScanner(client, IsolatedTrivyConfig{
		Image:                         "monitor-api:dev",
		PollInterval:                  time.Millisecond,
		RegistryCredentialsSecretName: "scm-registry-credentials",
		RegistryUsernameKey:           "REGISTRY_USERNAME",
		RegistryPasswordKey:           "REGISTRY_PASSWORD",
	})
	if _, err := s.Scan(context.Background(), "ghcr.io/org/app:1"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var sawRegistryPair bool
	for _, e := range client.createdJobs[0].Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TRIVY_USERNAME" || e.Name == "TRIVY_PASSWORD" {
			t.Errorf("%s is set on the scan Job: trivy sends it to every registry it talks to, not just the one it belongs to", e.Name)
		}
		if e.Name == "REGISTRY_USERNAME" {
			sawRegistryPair = true
		}
	}
	// The counterpart assertion: dropping the pair above must not have
	// taken the in-cluster registry's credentials with it. They are
	// what mergeRegistryAuths folds in as scm-registry's own entry, so
	// losing them would make every scm-registry pull anonymous.
	if !sawRegistryPair {
		t.Error("REGISTRY_USERNAME missing from the scan Job -- the in-cluster registry would be pulled anonymously")
	}
}

// REGISTRY_ADDR must reach the Job, because runScanWorker keys the
// docker config it builds BY HOST: without it, scm-registry's
// credentials are filed under "" and trivy -- looking them up by the
// host it is pulling from -- finds none and gets a 401.
//
// The credentials being present is not enough and was exactly the shape
// of the live defect: REGISTRY_USERNAME/PASSWORD were forwarded, this
// was not, and every scan of a mirrored artifact lost its trivy CVE
// coverage while still reporting "scanned". Asserted alongside the
// credentials so the three cannot drift apart again.
func TestIsolatedTrivyJobForwardsRegistryAddrWithCredentials(t *testing.T) {
	client := &recordingJobClient{fakeJobClient: fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "p",
		logs:           `{"findings":[]}`,
	}}
	s := NewIsolatedTrivyScanner(client, IsolatedTrivyConfig{
		Image:                         "monitor-api:dev",
		SubCommand:                    "image",
		PollInterval:                  time.Millisecond,
		RegistryAddr:                  "scm-registry.scm.svc.cluster.local:5000",
		RegistryCredentialsSecretName: "scm-registry-credentials",
		RegistryUsernameKey:           "REGISTRY_USERNAME",
		RegistryPasswordKey:           "REGISTRY_PASSWORD",
	})
	if _, err := s.Scan(context.Background(), "scm-registry.scm.svc.cluster.local:5000/mirror/app:1.0"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var addr string
	creds := map[string]bool{}
	for _, e := range client.createdJobs[0].Spec.Template.Spec.Containers[0].Env {
		if e.Name == "REGISTRY_ADDR" {
			addr = e.Value
		}
		if e.Name == "REGISTRY_USERNAME" || e.Name == "REGISTRY_PASSWORD" {
			creds[e.Name] = true
		}
	}
	if addr != "scm-registry.scm.svc.cluster.local:5000" {
		t.Errorf("REGISTRY_ADDR = %q -- the Job's docker config would key its credentials under the wrong host and trivy would 401", addr)
	}
	if len(creds) != 2 {
		t.Errorf("credentials missing from the Job env: %v", creds)
	}
}

// TestIsolatedTrivyScanner_SBOMDocJobShape covers the Job the sbom
// re-evaluation mode creates -- the one trivy mode that reads a
// document back OUT of monitor-api rather than uploading one, and the
// one that must not touch a registry.
func TestIsolatedTrivyScanner_SBOMDocJobShape(t *testing.T) {
	client := &recordingJobClient{
		fakeJobClient: fakeJobClient{
			namespace:      "test-ns",
			statusSequence: []jobStatusResult{{succeeded: true}},
			podName:        "scm-scan-abc-xyz",
			logs:           `{"findings":[]}`,
		},
	}
	var mintedFor string
	s := NewIsolatedTrivyScanner(client, IsolatedTrivyConfig{
		SubCommand:     "sbom-doc",
		CacheClaimName: "scm-trivy-db-cache",
		PollInterval:   time.Millisecond,
		APIBaseURL:     "http://monitor-api:8080",
		MintScanToken: func(artifactID string) (string, error) {
			mintedFor = artifactID
			return "tok-abc", nil
		},
	})

	if _, err := s.ScanForArtifact(context.Background(), "alpine:3.19", "artifact-7"); err != nil {
		t.Fatalf("ScanForArtifact: %v", err)
	}
	if mintedFor != "artifact-7" {
		t.Errorf("minted for %q, want %q", mintedFor, "artifact-7")
	}

	env := map[string]string{}
	for _, ev := range client.createdJobs[0].Spec.Template.Spec.Containers[0].Env {
		env[ev.Name] = ev.Value
	}
	for name, want := range map[string]string{
		"SCM_SCAN_TOOL":    "trivy",
		"SCM_SCAN_MODE":    "sbom-doc",
		"SCM_ARTIFACT_ID":  "artifact-7",
		"SCM_API_BASE_URL": "http://monitor-api:8080",
		"SCM_SCAN_TOKEN":   "tok-abc",
	} {
		if env[name] != want {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}
	if _, ok := env["REGISTRY_ADDR"]; ok {
		t.Errorf("REGISTRY_ADDR set on an sbom-doc Job, which never talks to a registry: %+v", env)
	}
}

// TestIsolatedTrivyScanner_SBOMDocMintFailureIsAnError proves the read
// path does NOT fall back to the master API key the way "image" mode
// does. That fallback exists so a generated SBOM is never lost; there
// is nothing to lose on a download, and a failed re-evaluation is
// retried next run.
func TestIsolatedTrivyScanner_SBOMDocMintFailureIsAnError(t *testing.T) {
	client := &recordingJobClient{
		fakeJobClient: fakeJobClient{
			namespace:      "test-ns",
			statusSequence: []jobStatusResult{{succeeded: true}},
			podName:        "scm-scan-abc-xyz",
			logs:           `{"findings":[]}`,
		},
	}
	s := NewIsolatedTrivyScanner(client, IsolatedTrivyConfig{
		SubCommand:       "sbom-doc",
		CacheClaimName:   "scm-trivy-db-cache",
		PollInterval:     time.Millisecond,
		APIBaseURL:       "http://monitor-api:8080",
		APIKeySecretName: "scm-monitor-api-auth",
		APIKeySecretKey:  "API_KEY",
		MintScanToken:    func(string) (string, error) { return "", errors.New("store unavailable") },
	})

	if _, err := s.ScanForArtifact(context.Background(), "alpine:3.19", "artifact-7"); err == nil {
		t.Fatal("expected an error when the scan token cannot be minted")
	}
	if len(client.createdJobs) != 0 {
		t.Errorf("created %d Job(s) despite failing to mint a token", len(client.createdJobs))
	}
}

// TestIsolatedTrivyScanner_ImageModeStillFallsBackToAPIKey guards the
// other half of that asymmetry: the upload path's fallback must stay.
func TestIsolatedTrivyScanner_ImageModeStillFallsBackToAPIKey(t *testing.T) {
	client := &recordingJobClient{
		fakeJobClient: fakeJobClient{
			namespace:      "test-ns",
			statusSequence: []jobStatusResult{{succeeded: true}},
			podName:        "scm-scan-abc-xyz",
			logs:           `{"findings":[]}`,
		},
	}
	s := NewIsolatedTrivyScanner(client, IsolatedTrivyConfig{
		SubCommand:       "image",
		CacheClaimName:   "scm-trivy-db-cache",
		PollInterval:     time.Millisecond,
		APIBaseURL:       "http://monitor-api:8080",
		APIKeySecretName: "scm-monitor-api-auth",
		APIKeySecretKey:  "API_KEY",
		MintScanToken:    func(string) (string, error) { return "", errors.New("store unavailable") },
	})

	if _, err := s.ScanForArtifact(context.Background(), "alpine:3.19", "artifact-7"); err != nil {
		t.Fatalf("image mode must not fail on a minting error: %v", err)
	}
	// SCM_API_KEY arrives as a secretKeyRef, never a plain value.
	var sawAPIKey bool
	for _, ev := range client.createdJobs[0].Spec.Template.Spec.Containers[0].Env {
		if ev.Name == "SCM_API_KEY" && ev.ValueFrom != nil && ev.ValueFrom.SecretKeyRef != nil {
			sawAPIKey = true
		}
	}
	if !sawAPIKey {
		t.Error("image mode should fall back to SCM_API_KEY so a generated SBOM is not lost")
	}
}
