package scanner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Reuses fakeJobClient/recordingJobClient from isolated_unpacker_test.go
// and isolated_trivy_test.go -- all three isolated scanners share the
// same jobClient interface.

func newGrypeScanner(t *testing.T, client jobClient) *IsolatedGrypeScanner {
	t.Helper()
	return NewIsolatedGrypeScanner(client, IsolatedGrypeConfig{
		Image:          "monitor-api:dev",
		CacheClaimName: "scm-grype-db-cache",
		PollInterval:   time.Millisecond, // fast polling in tests
	})
}

func TestIsolatedGrypeScanner_Scan_HappyPath(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{}, {succeeded: true}}, // "still running" once, then done
		podName:        "scm-scan-abc-xyz",
		logs:           `{"findings":[{"id":"CVE-2024-1","severity":"High","title":"openssl 3.0.9-r0","source":"grype"}]}`,
	}
	s := newGrypeScanner(t, client)

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

func TestIsolatedGrypeScanner_Scan_CleansUpEvenOnFailure(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{failed: true}},
	}
	s := newGrypeScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job itself fails")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected cleanup (DeleteJob) even when the scan fails")
	}
}

func TestIsolatedGrypeScanner_Scan_CreateJobError(t *testing.T) {
	client := &fakeJobClient{
		namespace: "test-ns",
		createErr: errors.New("jobs.batch is forbidden"),
	}
	s := newGrypeScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job can't even be created")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected DeleteJob to still run as a harmless cleanup attempt")
	}
}

func TestIsolatedGrypeScanner_Scan_WorkerReportedError(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs:           `{"findings":null,"error":"grype scan failed for \"alpine:3.19\": db not found"}`,
	}
	s := newGrypeScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected the worker-reported error to surface")
	}
}

func TestIsolatedGrypeScanner_Scan_UnparseableLogs(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs:           "not json at all",
	}
	s := newGrypeScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job's logs aren't valid WorkerResult JSON")
	}
}

func TestIsolatedGrypeScanner_Scan_TimesOutIfNeverFinishes(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{}}, // always "still running"
	}
	s := newGrypeScanner(t, client)

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
// cache PVC read-only -- mirrors
// TestIsolatedTrivyScanner_Scan_MountsCacheVolumeReadOnly.
func TestIsolatedGrypeScanner_Scan_MountsCacheVolumeReadOnly(t *testing.T) {
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
	s := newGrypeScanner(t, client)

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
		if vm.MountPath == "/grype-cache" {
			if !vm.ReadOnly {
				t.Fatal("expected the grype DB cache volume mount to be ReadOnly")
			}
			foundReadOnlyMount = true
		}
	}
	if !foundReadOnlyMount {
		t.Fatal("expected a volume mount at /grype-cache")
	}

	foundPVCVolume := false
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			if v.PersistentVolumeClaim.ClaimName != "scm-grype-db-cache" {
				t.Fatalf("claimName = %q, want scm-grype-db-cache", v.PersistentVolumeClaim.ClaimName)
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

// TestIsolatedGrypeScanner_Scan_RegistryAuthEnv confirms
// RegistryCredentialsSecretName wires REGISTRY_USERNAME/PASSWORD from
// the Secret and RegistryAddr forwards as the plain env var
// REGISTRY_ADDR -- NOT SYFT_REGISTRY_AUTH_* (a first design that was
// tried and then verified, against a real probe registry rather than
// just grype's own config-reference docs, to never actually get sent
// -- see IsolatedGrypeConfig.RegistryAddr's comment). The worker uses
// this trio to build a dockerconfig.json the same way the default
// (unpacker) branch of runScanWorker already does, then points grype
// at it via DOCKER_CONFIG (grype.go's registryEnv) -- main.go's
// concern, not this Job-building code's, so this test only confirms
// the env wiring reaches the pod.
func TestIsolatedGrypeScanner_Scan_RegistryAuthEnv(t *testing.T) {
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
	s := NewIsolatedGrypeScanner(client, IsolatedGrypeConfig{
		CacheClaimName:                "scm-grype-db-cache",
		PollInterval:                  time.Millisecond,
		RegistryAddr:                  "scm-registry:5000",
		RegistryCredentialsSecretName: "scm-registry-credentials",
	})

	if _, err := s.Scan(context.Background(), "scm-registry:5000/app:latest"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !seenJobViaCreate {
		t.Fatal("expected CreateJob to be called")
	}
	job := client.createdJobs[0]

	var addr string
	for _, ev := range job.Spec.Template.Spec.Containers[0].Env {
		if ev.Name == "REGISTRY_ADDR" {
			addr = ev.Value
		}
	}
	if addr != "scm-registry:5000" {
		t.Fatalf("REGISTRY_ADDR = %q, want %q", addr, "scm-registry:5000")
	}

	foundUsername, foundPassword := false, false
	for _, ev := range job.Spec.Template.Spec.Containers[0].Env {
		if ev.Name == "REGISTRY_USERNAME" {
			foundUsername = true
		}
		if ev.Name == "REGISTRY_PASSWORD" {
			foundPassword = true
		}
	}
	if !foundUsername || !foundPassword {
		t.Fatalf("expected REGISTRY_USERNAME/PASSWORD to be set from the Secret, got env %+v", job.Spec.Template.Spec.Containers[0].Env)
	}
}

// TestIsolatedGrypeScanner_Bucket confirms IsolatedGrypeScanner
// declares BucketAffinity as "cve", same as GrypeScanner/GrypeSBOMScanner
// -- it just runs their code inside a Job instead of in-process.
func TestIsolatedGrypeScanner_Bucket(t *testing.T) {
	s := newGrypeScanner(t, &fakeJobClient{namespace: "test-ns"})
	if got := s.Bucket(); got != "cve" {
		t.Errorf("Bucket() = %q, want %q", got, "cve")
	}
}
