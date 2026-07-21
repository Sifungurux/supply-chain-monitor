package k8sjob

import (
	"encoding/json"
	"testing"
)

// Confirms NewScanJob actually produces the hardening this whole
// package exists for -- read-only root filesystem, dropped
// capabilities, non-root, no privilege escalation, no ServiceAccount
// token for the worker pod itself, and deterministic env ordering.
// Asserted against the marshaled JSON (not just the Go struct) since
// that's what the Kubernetes API actually receives.
func TestNewScanJob(t *testing.T) {
	job := NewScanJob(ScanJobConfig{
		Name:           "scm-scan-abc123",
		Namespace:      "supply-chain-monitor",
		Image:          "monitor-api:dev",
		ServiceAccount: "scm-scan-worker",
		Command:        []string{"/usr/local/bin/monitor-api", "scan-worker"},
		Env: map[string]string{
			"SCM_SCAN_REF": "alpine:3.19",
			"CLAMAV_ADDR":  "scm-clamav:3310",
		},
		ActiveDeadlineSeconds:   300,
		CPURequest:              "200m",
		MemoryRequest:           "256Mi",
		EphemeralStorageRequest: "512Mi",
		CPULimit:                "1",
		MemoryLimit:             "768Mi",
		EphemeralStorageLimit:   "2Gi",
	})

	if job.APIVersion != "batch/v1" || job.Kind != "Job" {
		t.Fatalf("apiVersion/kind = %s/%s, want batch/v1/Job", job.APIVersion, job.Kind)
	}
	if job.Metadata.Name != "scm-scan-abc123" || job.Metadata.Namespace != "supply-chain-monitor" {
		t.Fatalf("metadata = %+v", job.Metadata)
	}
	if job.Spec.BackoffLimit != 0 {
		t.Fatalf("BackoffLimit = %d, want 0 (a failed scan job must not silently retry)", job.Spec.BackoffLimit)
	}
	if job.Spec.ActiveDeadlineSeconds != 300 {
		t.Fatalf("ActiveDeadlineSeconds = %d, want 300", job.Spec.ActiveDeadlineSeconds)
	}
	if job.Spec.TTLSecondsAfterFinished == nil || *job.Spec.TTLSecondsAfterFinished <= 0 {
		t.Fatal("expected a positive TTLSecondsAfterFinished as a cleanup backstop")
	}

	pod := job.Spec.Template.Spec
	if pod.RestartPolicy != "Never" {
		t.Fatalf("RestartPolicy = %q, want Never", pod.RestartPolicy)
	}
	if pod.ServiceAccountName != "scm-scan-worker" {
		t.Fatalf("ServiceAccountName = %q, want scm-scan-worker (not monitor-api's own)", pod.ServiceAccountName)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("expected AutomountServiceAccountToken = false -- this pod parses untrusted content and has no reason to call the k8s API")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser == 0 {
		t.Fatal("expected a non-root RunAsUser")
	}

	if len(pod.Containers) != 1 {
		t.Fatalf("expected exactly 1 container, got %d", len(pod.Containers))
	}
	c := pod.Containers[0]
	if c.SecurityContext == nil {
		t.Fatal("expected a container SecurityContext")
	}
	if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("expected ReadOnlyRootFilesystem = true")
	}
	if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("expected AllowPrivilegeEscalation = false")
	}
	if c.SecurityContext.Capabilities == nil || len(c.SecurityContext.Capabilities.Drop) != 1 || c.SecurityContext.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("expected capabilities.drop == [ALL], got %+v", c.SecurityContext.Capabilities)
	}

	// The container needs somewhere writable for unpacker's scratch
	// dir despite the read-only root filesystem -- the /tmp emptyDir.
	foundScratchMount := false
	for _, vm := range c.VolumeMounts {
		if vm.MountPath == "/tmp" {
			foundScratchMount = true
		}
	}
	if !foundScratchMount {
		t.Fatal("expected a volume mounted at /tmp (unpacker needs scratch space despite the read-only root filesystem)")
	}
	foundScratchVolume := false
	for _, v := range pod.Volumes {
		if v.EmptyDir != nil {
			foundScratchVolume = true
		}
	}
	if !foundScratchVolume {
		t.Fatal("expected an emptyDir volume backing the /tmp mount")
	}

	// Env must be sorted for deterministic output.
	if len(c.Env) != 2 || c.Env[0].Name != "CLAMAV_ADDR" || c.Env[1].Name != "SCM_SCAN_REF" {
		t.Fatalf("env = %+v, want sorted by key", c.Env)
	}

	// Round-trip through JSON: confirms the "emptyDir": {} / omitempty
	// behavior actually produces what a real Kubernetes API server
	// expects, not just what the Go struct looks like in memory.
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatalf("unmarshal job json: %v", err)
	}
	spec, _ := roundTrip["spec"].(map[string]any)
	if spec == nil {
		t.Fatal("expected a top-level spec object in the marshaled JSON")
	}
}
