// Package k8sjob is a small, hand-rolled client for the one slice of
// the Kubernetes API this service needs: creating a Job, waiting for
// it to finish, reading its pod's logs, and deleting it. Deliberately
// not built on client-go -- that pulls in a large dependency graph
// (k8s.io/api, k8s.io/apimachinery, and their own transitive deps) for
// a handful of REST calls this package can make directly with
// net/http, matching this project's existing "stdlib first" approach
// (see docs/architecture.md's very first design decision). See
// IsolatedUnpackerScanner (internal/scanner/isolated_unpacker.go) for
// why this exists at all.
package k8sjob

import "sort"

// Job is a minimal representation of a batch/v1 Job manifest -- just
// the fields this project's scan-worker Jobs actually need. Typed
// structs rather than map[string]any so a typo in a field name is a
// compile error, and so the JSON this produces is unit-testable
// directly (see job_test.go) without a real cluster.
type Job struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       JobSpec    `json:"spec"`
}

type ObjectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type JobSpec struct {
	// 0: a scan Job that fails is reported as a scan failure (see
	// IsolatedUnpackerScanner), not silently retried against a target
	// that might behave differently the second time.
	BackoffLimit int32 `json:"backoffLimit"`
	// A hard backstop in addition to the worker's own internal scan
	// timeout (main.go's runScanWorker) -- if the process itself hangs
	// rather than timing out cleanly, Kubernetes kills the Job's pod
	// after this many seconds regardless.
	ActiveDeadlineSeconds int64 `json:"activeDeadlineSeconds"`
	// Safety net: even if IsolatedUnpackerScanner's own DeleteJob call
	// never runs (e.g. the monitor-api pod crashes mid-scan), the Job
	// and its pod are garbage-collected on their own after this many
	// seconds rather than accumulating forever.
	TTLSecondsAfterFinished *int32      `json:"ttlSecondsAfterFinished,omitempty"`
	Template                PodTemplate `json:"template"`
}

type PodTemplate struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
}

type PodSpec struct {
	RestartPolicy string `json:"restartPolicy"`
	// A separate, zero-RBAC ServiceAccount from monitor-api's own (see
	// the scm-scan-worker ServiceAccount in
	// charts/supply-chain-monitor/templates/monitor-api/serviceaccount.yaml) -- this pod
	// parses untrusted image content and has no business calling the
	// Kubernetes API itself.
	ServiceAccountName           string              `json:"serviceAccountName,omitempty"`
	AutomountServiceAccountToken *bool               `json:"automountServiceAccountToken,omitempty"`
	SecurityContext              *PodSecurityContext `json:"securityContext,omitempty"`
	Containers                   []Container         `json:"containers"`
	Volumes                      []Volume            `json:"volumes,omitempty"`
}

type PodSecurityContext struct {
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
	RunAsGroup   *int64 `json:"runAsGroup,omitempty"`
	FSGroup      *int64 `json:"fsGroup,omitempty"`
}

type Container struct {
	Name            string                    `json:"name"`
	Image           string                    `json:"image"`
	ImagePullPolicy string                    `json:"imagePullPolicy,omitempty"`
	Command         []string                  `json:"command,omitempty"`
	Env             []EnvVar                  `json:"env,omitempty"`
	Resources       ResourceRequirements      `json:"resources,omitempty"`
	SecurityContext *ContainerSecurityContext `json:"securityContext,omitempty"`
	VolumeMounts    []VolumeMount             `json:"volumeMounts,omitempty"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	// ValueFrom, when set, sources this env var from a Secret instead
	// of Value -- used for SCM_API_KEY (see ScanJobConfig.SecretEnvVars
	// and IsolatedTrivyConfig.APIKeySecretName/Key), matching the same
	// secretKeyRef pattern the dashboard's render-config initContainer
	// already uses (charts/supply-chain-monitor/templates/dashboard/deployment.yaml)
	// rather than putting a credential in a plain env value, which would
	// be readable in plaintext via `kubectl get job -o yaml`. Populated
	// by the kubelet directly from the Secret object at pod start --
	// this needs no RBAC on the pod's own ServiceAccount (scm-scan-worker
	// has none, deliberately, see PodSpec.ServiceAccountName's comment).
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

type EnvVarSource struct {
	SecretKeyRef *SecretKeySelector `json:"secretKeyRef,omitempty"`
}

type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ResourceRequirements struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// ContainerSecurityContext hardens the scan-worker container about as
// far as it can go while still letting `unpacker`/`umoci` do their
// job: no privilege escalation, every Linux capability dropped, and a
// read-only root filesystem (with an explicit writable emptyDir at
// /tmp for unpacking's scratch space -- see Volumes/VolumeMounts).
// This is exactly the hardening the long-running monitor-api pod
// itself can't have (it needs to write nothing to disk normally, but
// also can't tolerate being killed and restarted mid-request the way a
// one-shot Job can).
type ContainerSecurityContext struct {
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation,omitempty"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem,omitempty"`
	Capabilities             *Capabilities `json:"capabilities,omitempty"`
}

type Capabilities struct {
	Drop []string `json:"drop,omitempty"`
}

type Volume struct {
	Name                  string           `json:"name"`
	EmptyDir              *EmptyDirVolume  `json:"emptyDir,omitempty"`
	PersistentVolumeClaim *PVCVolumeSource `json:"persistentVolumeClaim,omitempty"`
}

// EmptyDirVolume has no fields yet -- its presence is what matters
// (serializes as "emptyDir": {}), not any options on it.
type EmptyDirVolume struct{}

// PVCVolumeSource references an existing PersistentVolumeClaim by name
// -- used by IsolatedTrivyScanner to mount the shared, centrally
// -refreshed vulnerability-DB cache (scm-trivy-db-cache) into each
// scan-worker Job. ReadOnly is set here AND on the VolumeMount below
// (belt-and-suspenders, matching ContainerSecurityContext's existing
// defense-in-depth style): a scan-worker Job has no business writing
// to the shared DB, only the dedicated primer Job/refresh CronJob do.
type PVCVolumeSource struct {
	ClaimName string `json:"claimName"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// SecretEnvVar is one Secret-sourced env var for ScanJobConfig.SecretEnvVars.
type SecretEnvVar struct {
	Name       string // env var name inside the pod, e.g. "SCM_API_KEY"
	SecretName string
	SecretKey  string
}

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }
func int32Ptr(i int32) *int32 { return &i }

// ScanJobConfig configures the Job NewScanJob builds. Env is sorted by
// key before being turned into the Job's (order-sensitive) env list,
// so the generated JSON -- and therefore job_test.go's assertions --
// is deterministic.
type ScanJobConfig struct {
	Name           string
	Namespace      string
	Image          string
	ServiceAccount string
	Command        []string
	Env            map[string]string
	// SecretEnvVars are appended after Env's sorted plain values --
	// Secret-sourced env vars (see EnvVar.ValueFrom's comment), for
	// values that shouldn't be readable in plaintext via `kubectl get
	// job -o yaml` the way a plain Env value is. Small enough (one entry
	// today: IsolatedTrivyScanner's SCM_API_KEY) that a slice with no
	// particular ordering guarantee is fine -- unlike Env, nothing here
	// depends on deterministic ordering for test assertions.
	SecretEnvVars         []SecretEnvVar
	ActiveDeadlineSeconds int64

	CPURequest              string
	MemoryRequest           string
	EphemeralStorageRequest string
	CPULimit                string
	MemoryLimit             string
	EphemeralStorageLimit   string

	// ExtraVolumes/ExtraVolumeMounts add to (never replace) the scratch
	// emptyDir every scan-worker Job already gets at /tmp. Introduced
	// for IsolatedTrivyScanner, which mounts the shared
	// scm-trivy-db-cache PVC read-only alongside it -- but deliberately
	// general (a []Volume/[]VolumeMount pair, not a single PVC-shaped
	// field) so this doesn't need to change again for whatever the next
	// isolated scanner turns out to need.
	ExtraVolumes      []Volume
	ExtraVolumeMounts []VolumeMount
}

// NewScanJob builds a hardened, single-container, single-run Job spec
// for one scan-worker invocation. See ContainerSecurityContext and
// PodSpec's field comments for what "hardened" means here concretely.
func NewScanJob(cfg ScanJobConfig) *Job {
	const scanWorkerUID = 65534 // alpine's built-in "nobody" user -- no Dockerfile change needed to run as non-root

	keys := make([]string, 0, len(cfg.Env))
	for k := range cfg.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]EnvVar, 0, len(keys)+len(cfg.SecretEnvVars))
	for _, k := range keys {
		env = append(env, EnvVar{Name: k, Value: cfg.Env[k]})
	}
	for _, sev := range cfg.SecretEnvVars {
		env = append(env, EnvVar{
			Name:      sev.Name,
			ValueFrom: &EnvVarSource{SecretKeyRef: &SecretKeySelector{Name: sev.SecretName, Key: sev.SecretKey}},
		})
	}

	labels := map[string]string{"app": "scm-scan-worker"}

	return &Job{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Metadata: ObjectMeta{
			Name:      cfg.Name,
			Namespace: cfg.Namespace,
			Labels:    labels,
		},
		Spec: JobSpec{
			BackoffLimit:            0,
			ActiveDeadlineSeconds:   cfg.ActiveDeadlineSeconds,
			TTLSecondsAfterFinished: int32Ptr(300),
			Template: PodTemplate{
				Metadata: ObjectMeta{Labels: labels},
				Spec: PodSpec{
					RestartPolicy:                "Never",
					ServiceAccountName:           cfg.ServiceAccount,
					AutomountServiceAccountToken: boolPtr(false),
					SecurityContext: &PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(scanWorkerUID),
						RunAsGroup:   int64Ptr(scanWorkerUID),
						FSGroup:      int64Ptr(scanWorkerUID),
					},
					Containers: []Container{
						{
							Name:            "scan-worker",
							Image:           cfg.Image,
							ImagePullPolicy: "IfNotPresent",
							Command:         cfg.Command,
							Env:             env,
							Resources: ResourceRequirements{
								Requests: map[string]string{
									"cpu":               cfg.CPURequest,
									"memory":            cfg.MemoryRequest,
									"ephemeral-storage": cfg.EphemeralStorageRequest,
								},
								Limits: map[string]string{
									"cpu":               cfg.CPULimit,
									"memory":            cfg.MemoryLimit,
									"ephemeral-storage": cfg.EphemeralStorageLimit,
								},
							},
							SecurityContext: &ContainerSecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								ReadOnlyRootFilesystem:   boolPtr(true),
								Capabilities:             &Capabilities{Drop: []string{"ALL"}},
							},
							VolumeMounts: append([]VolumeMount{
								{Name: "scratch", MountPath: "/tmp"},
							}, cfg.ExtraVolumeMounts...),
						},
					},
					Volumes: append([]Volume{
						{Name: "scratch", EmptyDir: &EmptyDirVolume{}},
					}, cfg.ExtraVolumes...),
				},
			},
		},
	}
}
