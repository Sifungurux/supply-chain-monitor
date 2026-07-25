package scanner

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Confirms the air-gapped DB-mirror flags are assembled the way trivy
// actually expects (--db-repository, --java-db-repository,
// --skip-db-update, --skip-java-db-update) without needing to execute
// the real trivy binary.
func TestTrivyScanner_Args(t *testing.T) {
	// VerboseScanLogs is shared, mutable package state (see its own
	// comment in scanner.go) -- reset explicitly rather than assuming
	// it's already false, so this test's outcome doesn't depend on
	// whatever ran before it in the same package test binary.
	VerboseScanLogs = false
	defer func() { VerboseScanLogs = false }()

	cases := []struct {
		name string
		db   TrivyDBConfig
		want []string
	}{
		{
			name: "no overrides falls back to trivy's own defaults",
			db:   TrivyDBConfig{},
			want: []string{"image", "--quiet", "--format", "json", "alpine:3.19"},
		},
		{
			name: "air-gapped mirror with both DBs and skip-update set",
			db: TrivyDBConfig{
				DBRepository:     "scm-registry:5000/aquasecurity/trivy-db:2",
				JavaDBRepository: "scm-registry:5000/aquasecurity/trivy-java-db:1",
				SkipDBUpdate:     true,
				SkipJavaDBUpdate: true,
			},
			want: []string{
				"image", "--quiet", "--format", "json",
				"--db-repository", "scm-registry:5000/aquasecurity/trivy-db:2",
				"--java-db-repository", "scm-registry:5000/aquasecurity/trivy-java-db:1",
				"--skip-db-update",
				"--skip-java-db-update",
				"alpine:3.19",
			},
		},
		{
			name: "db-repository without skip-update still just adds the flag",
			db: TrivyDBConfig{
				DBRepository: "scm-registry:5000/aquasecurity/trivy-db:2",
			},
			want: []string{
				"image", "--quiet", "--format", "json",
				"--db-repository", "scm-registry:5000/aquasecurity/trivy-db:2",
				"alpine:3.19",
			},
		},
		{
			// IsolatedTrivyScanner's shape: a shared, read-only cache dir
			// plus --cache-backend memory to avoid the scan-cache's
			// BoltDB single-process lock (see TrivyDBConfig.CacheDir's
			// comment).
			name: "cache-dir adds --cache-backend memory alongside it",
			db: TrivyDBConfig{
				SkipDBUpdate:     true,
				SkipJavaDBUpdate: true,
				CacheDir:         "/trivy-cache",
			},
			want: []string{
				"image", "--quiet", "--format", "json",
				"--skip-db-update",
				"--skip-java-db-update",
				"--cache-dir", "/trivy-cache",
				"--cache-backend", "memory",
				"alpine:3.19",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewTrivyScanner("", tc.db)
			got := s.args("alpine:3.19")
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("args = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestTrivyScanner_Args_Verbose confirms VerboseScanLogs swaps trivy's
// own "--quiet" for "--debug" -- the lever that actually makes trivy
// produce more log output in the first place (see VerboseScanLogs's
// comment in scanner.go and verbosityArgs).
func TestTrivyScanner_Args_Verbose(t *testing.T) {
	VerboseScanLogs = true
	defer func() { VerboseScanLogs = false }()

	s := NewTrivyScanner("", TrivyDBConfig{})
	got := s.args("alpine:3.19")
	want := []string{"image", "--debug", "--format", "json", "alpine:3.19"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

// Confirms trivy's --format json output is decoded into normalized
// Findings correctly -- this is pure JSON parsing (parseTrivyVulnerabilities
// has no dependency on the real trivy binary), unlike Scan() itself,
// so unlike most of this package's scanner tests, this one can
// actually run in any Go environment with no external tools installed.
func TestParseTrivyVulnerabilities(t *testing.T) {
	t.Run("multiple results and vulnerabilities", func(t *testing.T) {
		input := []byte(`{
			"Results": [
				{
					"Vulnerabilities": [
						{"VulnerabilityID": "CVE-2024-1", "Severity": "HIGH", "Title": "some issue"},
						{"VulnerabilityID": "CVE-2024-2", "Severity": "CRITICAL", "Title": "another issue"}
					]
				},
				{
					"Vulnerabilities": [
						{"VulnerabilityID": "CVE-2024-3", "Severity": "LOW", "Title": "third issue"}
					]
				}
			]
		}`)
		findings, err := parseTrivyVulnerabilities(input)
		if err != nil {
			t.Fatalf("parseTrivyVulnerabilities: %v", err)
		}
		want := []artifact.Finding{
			{ID: "CVE-2024-1", Severity: "HIGH", Title: "some issue", Source: "trivy"},
			{ID: "CVE-2024-2", Severity: "CRITICAL", Title: "another issue", Source: "trivy"},
			{ID: "CVE-2024-3", Severity: "LOW", Title: "third issue", Source: "trivy"},
		}
		if !reflect.DeepEqual(findings, want) {
			t.Fatalf("findings = %+v, want %+v", findings, want)
		}
	})

	t.Run("no vulnerabilities found", func(t *testing.T) {
		input := []byte(`{"Results": [{"Vulnerabilities": []}]}`)
		findings, err := parseTrivyVulnerabilities(input)
		if err != nil {
			t.Fatalf("parseTrivyVulnerabilities: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected no findings, got %+v", findings)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		if _, err := parseTrivyVulnerabilities([]byte("not json")); err == nil {
			t.Fatal("expected an error for invalid json")
		}
	})
}

// TestTrivyScanner_Bucket confirms TrivyScanner declares BucketAffinity
// as "cve" -- see its Bucket() comment for why that's a safe, static
// claim to make (every finding comes from parseTrivyVulnerabilities,
// which always sets Source: "trivy").
func TestTrivyScanner_Bucket(t *testing.T) {
	s := NewTrivyScanner("scm-registry:5000", TrivyDBConfig{})
	if got := s.Bucket(); got != "cve" {
		t.Errorf("Bucket() = %q, want %q", got, "cve")
	}
}

// TestWrapTrivyScanError_ManifestUnknown confirms a "manifest unknown"
// registry failure -- trivy's error when the requested tag/digest just
// doesn't exist -- gets collapsed to one plain-English line instead of
// surfacing trivy's full docker/containerd/podman/remote fallback dump
// verbatim. The stderr fixture below is trimmed from a real failure
// this project hit scanning a test image whose tag had been retagged
// upstream (see docs/architecture.md, "Bulk-registering artifacts").
func TestWrapTrivyScanError_ManifestUnknown(t *testing.T) {
	rawStderr := `FATAL	Fatal error	run error: image scan error: scan error: unable to initialize a scan service: unable to initialize artifact: unable to initialize container image: unable to find the specified image "gcr.io/kubebuilder/kube-rbac-proxy:v0.13.1" in ["docker" "containerd" "podman" "remote"]: 4 errors occurred:
	* docker error: unable to inspect the image (gcr.io/kubebuilder/kube-rbac-proxy:v0.13.1): failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory
	* containerd error: containerd socket not found: /run/containerd/containerd.sock
	* podman error: unable to initialize Podman client: no podman socket found: stat podman/podman.sock: no such file or directory
	* remote error: GET https://gcr.io/v2/kubebuilder/kube-rbac-proxy/manifests/v0.13.1: MANIFEST_UNKNOWN: Failed to fetch "v0.13.1"
`
	err := wrapTrivyScanError("trivy scan", "gcr.io/kubebuilder/kube-rbac-proxy:v0.13.1", errors.New("exit status 1"), rawStderr)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "gcr.io/kubebuilder/kube-rbac-proxy:v0.13.1") {
		t.Errorf("message %q should still name the ref that failed", msg)
	}
	if !strings.Contains(msg, "not found in the registry") {
		t.Errorf("message %q should give the simplified explanation", msg)
	}
	// The whole point: none of trivy's own fallback-attempt noise (the
	// docker/containerd/podman socket errors, which are expected and
	// irrelevant in an isolated scan-worker Job with none of those
	// runtimes present) should leak into the simplified message.
	for _, noisy := range []string{"docker error", "containerd error", "podman error", "docker.sock", "4 errors occurred"} {
		if strings.Contains(msg, noisy) {
			t.Errorf("message %q still contains raw trivy noise %q, want it collapsed away", msg, noisy)
		}
	}
}

// TestWrapTrivyScanError_OtherFailuresKeepRawStderr confirms this only
// special-cases "manifest unknown" -- every other kind of trivy failure
// (a real bug, a genuinely broken environment, an unexpected new error
// shape) still gets its raw stderr included, since collapsing an
// unfamiliar failure down to a generic message would throw away
// information nobody has decided yet is safe to discard.
func TestWrapTrivyScanError_OtherFailuresKeepRawStderr(t *testing.T) {
	rawStderr := "FATAL\tsome unrelated trivy failure that has nothing to do with a missing manifest\n"
	err := wrapTrivyScanError("trivy scan", "alpine:3.19", errors.New("exit status 1"), rawStderr)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	if !strings.Contains(err.Error(), "some unrelated trivy failure") {
		t.Errorf("message %q should still include the raw stderr for an unrecognized failure", err.Error())
	}
}

// TestWrapTrivyScanError_UnsupportedArtifactTypeIsNotManifestUnknown
// guards against over-matching: the AI-model-artifact media-type
// mismatch this project hit previously (see docs/architecture.md's
// Roadmap, "AI model artifact scanning") also comes from trivy's
// "remote error" fallback line and shares some surrounding text, but
// it is a different problem (an artifact trivy fundamentally can't
// scan, not a missing tag) and must not get relabeled as "not found in
// the registry" -- that would actively mislead whoever reads it into
// thinking a retry with a corrected ref would help.
func TestWrapTrivyScanError_UnsupportedArtifactTypeIsNotManifestUnknown(t *testing.T) {
	rawStderr := `* remote error: unsupported artifact type "application/vnd.cncf.model.manifest.v1+json" for image "ai/gemma4:e4b"`
	err := wrapTrivyScanError("trivy scan", "ai/gemma4:e4b", errors.New("exit status 1"), rawStderr)
	if strings.Contains(err.Error(), "not found in the registry") {
		t.Errorf("message %q should not be relabeled as a missing manifest -- this is an unsupported media type, a different problem", err.Error())
	}
	if !strings.Contains(err.Error(), "unsupported artifact type") {
		t.Errorf("message %q should keep the raw stderr for this unrecognized case", err.Error())
	}
}
