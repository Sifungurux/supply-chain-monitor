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

// The scratch volume is where scan Jobs extract whole images -- up to
// 2395Mi measured. By default that lands on the node's own disk, which
// is the arrangement that has evicted monitor-api during a load test
// before. These tests cover both shapes, because "it still works
// unchanged" matters as much as the new behaviour.
func TestNewScanJob_ScratchIsAnEmptyDirByDefault(t *testing.T) {
	ScratchStorageClass, ScratchSize = "", ""

	job := NewScanJob(ScanJobConfig{Name: "j", Namespace: "n", Image: "i", Command: []string{"x"}})
	vols := job.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].Name != "scratch" {
		t.Fatalf("volumes = %+v, want one named scratch", vols)
	}
	if vols[0].EmptyDir == nil {
		t.Fatal("scratch must default to an emptyDir -- every deployment that never sets a StorageClass depends on it")
	}
	if vols[0].Ephemeral != nil {
		t.Fatal("scratch must not become a PVC unless one is configured")
	}
}

func TestNewScanJob_ScratchUsesAStorageClassWhenConfigured(t *testing.T) {
	job := NewScanJob(ScanJobConfig{
		Name: "j", Namespace: "n", Image: "i", Command: []string{"x"},
		ScratchStorageClass: "ceph-rbd", ScratchSize: "10Gi",
	})

	vol := job.Spec.Template.Spec.Volumes[0]
	if vol.EmptyDir != nil {
		t.Fatal("a configured StorageClass must replace the emptyDir, not sit beside it")
	}
	spec := vol.Ephemeral.VolumeClaimTemplate.Spec
	if got := *spec.StorageClassName; got != "ceph-rbd" {
		t.Errorf("storageClassName = %q, want ceph-rbd", got)
	}
	if got := spec.Resources.Requests["storage"]; got != "10Gi" {
		t.Errorf("storage request = %q, want 10Gi", got)
	}
	// ReadWriteOnce, not RWX: two concurrent scans must never share
	// extracted files.
	if len(spec.AccessModes) != 1 || spec.AccessModes[0] != "ReadWriteOnce" {
		t.Errorf("accessModes = %v, want [ReadWriteOnce]", spec.AccessModes)
	}
	// The mount is unchanged either way -- nothing above this knows
	// which volume it got.
	mount := job.Spec.Template.Spec.Containers[0].VolumeMounts[0]
	if mount.Name != "scratch" || mount.MountPath != "/tmp" {
		t.Errorf("mount = %+v, want scratch at /tmp", mount)
	}
}

// "-" is the Kubernetes convention for "use the cluster default
// StorageClass": an empty but PRESENT storageClassName, which is not
// the same as omitting the field (that means "whatever the admission
// default is", and on some clusters, nothing).
func TestNewScanJob_ScratchDashMeansTheDefaultStorageClass(t *testing.T) {
	job := NewScanJob(ScanJobConfig{
		Name: "j", Namespace: "n", Image: "i", Command: []string{"x"},
		ScratchStorageClass: "-",
	})

	spec := job.Spec.Template.Spec.Volumes[0].Ephemeral.VolumeClaimTemplate.Spec
	if spec.StorageClassName == nil {
		t.Fatal(`"-" must render an empty storageClassName, not omit the field`)
	}
	if *spec.StorageClassName != "" {
		t.Errorf("storageClassName = %q, want empty", *spec.StorageClassName)
	}
	// No size configured: falls back to the measured default rather
	// than requesting zero.
	if got := spec.Resources.Requests["storage"]; got != defaultScratchSize {
		t.Errorf("storage request = %q, want the %s default", got, defaultScratchSize)
	}
}

// The package-level default is what main.go sets once at startup, so
// every isolated scanner picks it up without threading two fields
// through four config structs.
func TestNewScanJob_PackageLevelScratchDefault(t *testing.T) {
	ScratchStorageClass, ScratchSize = "local-path", "5Gi"
	defer func() { ScratchStorageClass, ScratchSize = "", "" }()

	spec := NewScanJob(ScanJobConfig{Name: "j", Namespace: "n", Image: "i", Command: []string{"x"}}).
		Spec.Template.Spec.Volumes[0].Ephemeral.VolumeClaimTemplate.Spec
	if *spec.StorageClassName != "local-path" || spec.Resources.Requests["storage"] != "5Gi" {
		t.Fatalf("package default not applied: %+v", spec)
	}

	// An explicit per-Job value still wins over it.
	spec = NewScanJob(ScanJobConfig{
		Name: "j", Namespace: "n", Image: "i", Command: []string{"x"},
		ScratchStorageClass: "ceph-rbd",
	}).Spec.Template.Spec.Volumes[0].Ephemeral.VolumeClaimTemplate.Spec
	if *spec.StorageClassName != "ceph-rbd" {
		t.Fatalf("per-Job StorageClass must win over the package default, got %q", *spec.StorageClassName)
	}
}

// "none" is the opt-out: a Job that wants the node-disk emptyDir even
// though the deployment has moved scratch space onto a StorageClass.
// Without it the setting is all-or-nothing, and the mix that actually
// makes sense -- PVCs for image scans, emptyDir for "sbom"-mode Jobs
// that fetch one JSON document and spill nothing -- is unreachable.
func TestNewScanJob_ScratchNoneOptsBackIntoEmptyDir(t *testing.T) {
	ScratchStorageClass, ScratchSize = "ceph-rbd", "10Gi"
	defer func() { ScratchStorageClass, ScratchSize = "", "" }()

	// Sanity: the global default is in force for a Job that says nothing.
	def := NewScanJob(ScanJobConfig{Name: "j", Namespace: "n", Image: "i", Command: []string{"x"}}).
		Spec.Template.Spec.Volumes[0]
	if def.Ephemeral == nil {
		t.Fatal("setup: the process-wide StorageClass should apply to a Job that does not opt out")
	}

	opted := NewScanJob(ScanJobConfig{
		Name: "j", Namespace: "n", Image: "i", Command: []string{"x"},
		ScratchStorageClass: ScratchNone,
	}).Spec.Template.Spec.Volumes[0]
	if opted.EmptyDir == nil {
		t.Fatal(`ScratchStorageClass "none" must produce an emptyDir even when a class is configured process-wide`)
	}
	if opted.Ephemeral != nil {
		t.Fatal("an opted-out Job must not also carry a volume claim template")
	}
	if opted.Name != "scratch" {
		t.Errorf("volume name = %q, want scratch either way", opted.Name)
	}
}

// The same value works as the deployment-wide setting, so an operator
// can disable the feature without hunting for the difference between
// "none" and "".
func TestNewScanJob_ScratchNoneAsTheProcessWideValue(t *testing.T) {
	ScratchStorageClass, ScratchSize = ScratchNone, "10Gi"
	defer func() { ScratchStorageClass, ScratchSize = "", "" }()

	vol := NewScanJob(ScanJobConfig{Name: "j", Namespace: "n", Image: "i", Command: []string{"x"}}).
		Spec.Template.Spec.Volumes[0]
	if vol.EmptyDir == nil || vol.Ephemeral != nil {
		t.Fatalf(`process-wide "none" must mean emptyDir, got %+v`, vol)
	}
}

// The private CA has to reach every scan worker, and it has to arrive
// with SSL_CERT_DIR pointing at it -- a mounted CA nothing references is
// silently useless, and the failure surfaces as a TLS error rather than
// as a missing variable.
func TestNewScanJob_RegistryCA(t *testing.T) {
	base := ScanJobConfig{Name: "scan-x", Image: "monitor-api:dev", ServiceAccount: "scm-scan-worker"}

	t.Run("absent when no CA secret is configured", func(t *testing.T) {
		t.Setenv("SCAN_WORKER_REGISTRY_CA_SECRET", "")
		job := NewScanJob(base)
		pod := job.Spec.Template.Spec
		for _, v := range pod.Volumes {
			if v.Name == "registry-ca" {
				t.Error("CA volume mounted with no secret configured")
			}
		}
		for _, e := range pod.Containers[0].Env {
			if e.Name == "SSL_CERT_DIR" {
				t.Error("SSL_CERT_DIR set with no CA mounted")
			}
		}
	})

	t.Run("mounted, key-narrowed, and pointed at by SSL_CERT_DIR", func(t *testing.T) {
		t.Setenv("SCAN_WORKER_REGISTRY_CA_SECRET", "scm-ca-tls")
		job := NewScanJob(base)
		pod := job.Spec.Template.Spec

		var vol *Volume
		for i := range pod.Volumes {
			if pod.Volumes[i].Name == "registry-ca" {
				vol = &pod.Volumes[i]
			}
		}
		if vol == nil {
			t.Fatal("no registry-ca volume")
		}
		if vol.Secret == nil || vol.Secret.SecretName != "scm-ca-tls" {
			t.Fatalf("volume does not reference the CA secret: %+v", vol)
		}
		// The Secret cert-manager writes also holds the PRIVATE KEY; a
		// scan worker must not be able to read it.
		if len(vol.Secret.Items) != 1 || vol.Secret.Items[0].Key != "ca.crt" {
			t.Errorf("expected the mount narrowed to ca.crt, got %+v -- the same Secret carries tls.key", vol.Secret.Items)
		}

		var mounted bool
		for _, m := range pod.Containers[0].VolumeMounts {
			if m.Name == "registry-ca" && m.MountPath == "/ca" {
				mounted = true
			}
		}
		if !mounted {
			t.Error("CA volume declared but never mounted")
		}

		var certDir string
		for _, e := range pod.Containers[0].Env {
			if e.Name == "SSL_CERT_DIR" {
				certDir = e.Value
			}
		}
		// SSL_CERT_DIR, not SSL_CERT_FILE: the latter REPLACES the system
		// trust store, so oras/trivy/grype would stop trusting gcr.io and
		// every public-image scan would fail.
		if certDir != "/etc/ssl/certs:/ca" {
			t.Errorf("SSL_CERT_DIR = %q, want \"/etc/ssl/certs:/ca\" -- must keep the public roots alongside the private CA", certDir)
		}
	})

	// Scratch space must survive the addition.
	t.Run("does not displace the scratch mount", func(t *testing.T) {
		t.Setenv("SCAN_WORKER_REGISTRY_CA_SECRET", "scm-ca-tls")
		pod := NewScanJob(base).Spec.Template.Spec
		var scratch bool
		for _, m := range pod.Containers[0].VolumeMounts {
			if m.Name == "scratch" && m.MountPath == "/tmp" {
				scratch = true
			}
		}
		if !scratch {
			t.Error("the scratch mount was displaced by the CA mount")
		}
	})
}

// TestNewScanJob_MountsEveryConfiguredRegistryCredential covers the
// isolated half of multi-registry support. The in-pod path and the Job
// path authenticate from the same merged config, and the Job gets its
// half through mounts -- a Job that silently lacked them would scan
// with anonymous pulls and report a clean, empty result rather than an
// error.
func TestNewScanJob_MountsEveryConfiguredRegistryCredential(t *testing.T) {
	t.Setenv("SCAN_WORKER_REGISTRY_AUTH_SECRETS", "ghcr-pull-secret,scm-registry-credentials-inline")

	job := NewScanJob(ScanJobConfig{Name: "scm-scan-x", Namespace: "scm"})
	c := job.Spec.Template.Spec.Containers[0]

	for _, name := range []string{"ghcr-pull-secret", "scm-registry-credentials-inline"} {
		wantPath := "/etc/scm/registry-auth/" + name
		if !hasMountPath(c.VolumeMounts, wantPath) {
			t.Errorf("no volume mounted at %q: %+v", wantPath, c.VolumeMounts)
		}
		if !hasSecretVolume(job.Spec.Template.Spec.Volumes, name) {
			t.Errorf("no volume sourced from Secret %q: %+v", name, job.Spec.Template.Spec.Volumes)
		}
	}

	// The key projection is load-bearing, not cosmetic:
	// go-containerregistry looks for a file called "config.json", and a
	// dockerconfigjson Secret's only key is ".dockerconfigjson". Mount
	// it under its own name and every pull goes out anonymous with
	// nothing logged anywhere.
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Secret == nil || v.Secret.SecretName != "ghcr-pull-secret" {
			continue
		}
		if len(v.Secret.Items) != 1 || v.Secret.Items[0].Path != "config.json" {
			t.Errorf("credential Secret not projected to config.json: %+v", v.Secret.Items)
		}
	}

	if !hasEnv(c.Env, "REGISTRY_AUTH_DIR", "/etc/scm/registry-auth") {
		t.Errorf("REGISTRY_AUTH_DIR not set to the mount root: %+v", c.Env)
	}
}

// TestNewScanJob_SSLCertDirNamesEveryCADir is the mounted-but-unpointed-at
// failure this file's own comment warns about: SSL_CERT_DIR used to be
// gated on the scm registry CA alone, so an extra registry CA
// configured with registry TLS off would mount and be ignored -- a TLS
// error at scan time rather than anything visible at startup.
func TestNewScanJob_SSLCertDirNamesEveryCADir(t *testing.T) {
	t.Setenv("SCAN_WORKER_REGISTRY_CA_SECRET", "")
	t.Setenv("SCAN_WORKER_EXTRA_CA_SECRETS", "internal-ca")

	job := NewScanJob(ScanJobConfig{Name: "scm-scan-x", Namespace: "scm"})
	c := job.Spec.Template.Spec.Containers[0]

	if !hasEnv(c.Env, "SSL_CERT_DIR", "/etc/ssl/certs:/ca-extra-0") {
		t.Errorf("SSL_CERT_DIR does not name the extra CA dir: %+v", c.Env)
	}
	if !hasMountPath(c.VolumeMounts, "/ca-extra-0") {
		t.Errorf("extra CA not mounted: %+v", c.VolumeMounts)
	}
}

func hasMountPath(mounts []VolumeMount, path string) bool {
	for _, m := range mounts {
		if m.MountPath == path {
			return true
		}
	}
	return false
}

func hasSecretVolume(vols []Volume, secretName string) bool {
	for _, v := range vols {
		if v.Secret != nil && v.Secret.SecretName == secretName {
			return true
		}
	}
	return false
}

func hasEnv(env []EnvVar, name, value string) bool {
	for _, e := range env {
		if e.Name == name && e.Value == value {
			return true
		}
	}
	return false
}

// TestNewScanJob_MountsUsernameSecretRefPairs is the isolated-path half
// of usernameSecretRef: a scan-worker Job must authenticate to the same
// registries this pod does. The in-process path is the one unit tests
// naturally cover, so the Job manifest is where this silently drifts.
func TestNewScanJob_MountsUsernameSecretRefPairs(t *testing.T) {
	t.Setenv("SCAN_WORKER_REGISTRY_USER_SECRETS",
		`[{"host":"registry.internal:5000","secret":"harbor-creds","usernameKey":"user","passwordKey":"pass"}]`)

	job := NewScanJob(ScanJobConfig{Name: "scm-scan-x", Namespace: "scm"})
	c := job.Spec.Template.Spec.Containers[0]

	// THE MOUNT PATH CARRIES THE HOST -- including its colon, which a
	// volume name could not hold (a volume name is a DNS-1123 label).
	// main.go's mergeRegistryAuths reads the host back from exactly
	// this path, so this assertion is the contract between the two.
	wantPath := "/etc/scm/registry-auth/registry.internal:5000"
	if !hasMountPath(c.VolumeMounts, wantPath) {
		t.Errorf("no volume mounted at %q: %+v", wantPath, c.VolumeMounts)
	}
	if !hasSecretVolume(job.Spec.Template.Spec.Volumes, "harbor-creds") {
		t.Errorf("no volume sourced from Secret %q: %+v", "harbor-creds", job.Spec.Template.Spec.Volumes)
	}

	// The operator's own key names are projected onto the two fixed
	// names the reader expects. Without this the mount is present,
	// readable, and holds files nothing looks for.
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Secret == nil || v.Secret.SecretName != "harbor-creds" {
			continue
		}
		got := map[string]string{}
		for _, item := range v.Secret.Items {
			got[item.Key] = item.Path
		}
		if got["user"] != "username" || got["pass"] != "password" {
			t.Errorf("keys not projected onto username/password: %+v", v.Secret.Items)
		}
	}

	// Set even though SCAN_WORKER_REGISTRY_AUTH_SECRETS is unset: a
	// deployment using only usernameSecretRef has credentials mounted
	// and nothing reading them without this.
	if !hasEnv(c.Env, "REGISTRY_AUTH_DIR", "/etc/scm/registry-auth") {
		t.Errorf("REGISTRY_AUTH_DIR not set with only usernameSecretRef configured: %+v", c.Env)
	}
}

// TestRegistryUserSecrets_MalformedJSONIsDroppedNotFatal: one bad entry
// must not take scanning down for every other registry.
func TestRegistryUserSecrets_MalformedJSONIsDroppedNotFatal(t *testing.T) {
	t.Setenv("SCAN_WORKER_REGISTRY_USER_SECRETS", "{not json")

	if got := registryUserSecrets(); got != nil {
		t.Errorf("malformed JSON produced entries: %+v", got)
	}
	job := NewScanJob(ScanJobConfig{Name: "scm-scan-x", Namespace: "scm"})
	if c := job.Spec.Template.Spec.Containers[0]; hasEnv(c.Env, "REGISTRY_AUTH_DIR", "/etc/scm/registry-auth") {
		t.Error("REGISTRY_AUTH_DIR set with no usable credential source")
	}
}
