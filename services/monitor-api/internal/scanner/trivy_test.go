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
			want: []string{"image", "--quiet", "--format", "json", "--scanners", "vuln,secret", "--", "alpine:3.19"},
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
				"image", "--quiet", "--format", "json", "--scanners", "vuln,secret",
				"--db-repository", "scm-registry:5000/aquasecurity/trivy-db:2",
				"--java-db-repository", "scm-registry:5000/aquasecurity/trivy-java-db:1",
				"--skip-db-update",
				"--skip-java-db-update",
				"--",
				"alpine:3.19",
			},
		},
		{
			name: "db-repository without skip-update still just adds the flag",
			db: TrivyDBConfig{
				DBRepository: "scm-registry:5000/aquasecurity/trivy-db:2",
			},
			want: []string{
				"image", "--quiet", "--format", "json", "--scanners", "vuln,secret",
				"--db-repository", "scm-registry:5000/aquasecurity/trivy-db:2",
				"--",
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
				"image", "--quiet", "--format", "json", "--scanners", "vuln,secret",
				"--skip-db-update",
				"--skip-java-db-update",
				"--cache-dir", "/trivy-cache",
				"--cache-backend", "memory",
				"--",
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
	want := []string{"image", "--debug", "--format", "json", "--scanners", "vuln,secret", "--", "alpine:3.19"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

// Confirms trivy's --format json output is decoded into normalized
// Findings correctly -- this is pure JSON parsing (parseTrivyReport
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
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
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
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected no findings, got %+v", findings)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		if _, err := parseTrivyReport([]byte("not json")); err == nil {
			t.Fatal("expected an error for invalid json")
		}
	})
}

// TestTrivyScanner_Buckets confirms TrivyScanner declares BOTH buckets
// its single `trivy image --scanners vuln,secret` invocation can fill.
//
// This is a safety property, not bookkeeping. scanArtifact blocks
// fix-detection per bucket for a scanner that failed; if this returned
// only "cve", a trivy failure would leave the secret bucket unblocked
// and MergeFindings would mark every previously-open secret "fixed" --
// not because anyone removed a leaked credential, but because the scan
// that finds them didn't run.
func TestTrivyScanner_Buckets(t *testing.T) {
	s := NewTrivyScanner("scm-registry:5000", TrivyDBConfig{})
	want := []string{"cve", "secret"}
	got := s.Buckets()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Buckets() = %v, want %v", got, want)
	}
}

// TestParseTrivyReport_Secrets covers the secret half of the parser.
func TestParseTrivyReport_Secrets(t *testing.T) {
	t.Run("secrets are routed to the secret bucket, not cve", func(t *testing.T) {
		// Category MUST be set explicitly on a secret finding.
		// classifyBucket (internal/api/scan.go) falls back to Source
		// when Category is empty, and Source "trivy" hits its default
		// case -- "cve". Without it every exposed credential would be
		// filed as a vulnerability.
		input := []byte(`{
			"Results": [
				{
					"Target": "app/.env",
					"Secrets": [
						{"RuleID": "aws-access-key-id", "Category": "AWS", "Severity": "CRITICAL", "Title": "AWS Access Key ID", "StartLine": 3}
					]
				}
			]
		}`)
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("findings = %+v, want exactly 1", findings)
		}
		if findings[0].Category != "secret" {
			t.Errorf("Category = %q, want %q -- an empty Category makes classifyBucket file this as a CVE",
				findings[0].Category, "secret")
		}
		if findings[0].Source != "trivy" {
			t.Errorf("Source = %q, want %q", findings[0].Source, "trivy")
		}
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Severity = %q, want %q", findings[0].Severity, "CRITICAL")
		}
		// The file has to survive into the title: the ID is
		// machine-shaped, and "AWS Access Key ID" with no location is
		// not actionable.
		if !strings.Contains(findings[0].Title, "app/.env") {
			t.Errorf("Title = %q, want it to name the file the secret is in", findings[0].Title)
		}
	})

	t.Run("same rule in different files stays two findings", func(t *testing.T) {
		// THE test in this file. MergeFindings matches findings by ID,
		// so if the ID were just RuleID these two would collapse into
		// one -- one real leaked credential silently disappears, and
		// the survivor's title/severity flip-flops between scans with
		// decode order. One rule firing across several files in one
		// image is the normal case, not an edge case.
		input := []byte(`{
			"Results": [
				{
					"Target": "app/.env",
					"Secrets": [
						{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS Access Key ID", "StartLine": 3}
					]
				},
				{
					"Target": "etc/config/creds.ini",
					"Secrets": [
						{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS Access Key ID", "StartLine": 3}
					]
				}
			]
		}`)
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
		}
		if len(findings) != 2 {
			t.Fatalf("findings = %+v, want 2 -- the same rule in two files is two secrets", findings)
		}
		if findings[0].ID == findings[1].ID {
			t.Fatalf("both findings have ID %q -- MergeFindings matches by ID, so one of these two real secrets is lost", findings[0].ID)
		}
	})

	t.Run("same rule twice in one file stays two findings", func(t *testing.T) {
		// Which is why the line number is in the ID and not just the
		// target.
		input := []byte(`{
			"Results": [
				{
					"Target": "app/.env",
					"Secrets": [
						{"RuleID": "generic-api-key", "Severity": "HIGH", "Title": "Generic API Key", "StartLine": 3},
						{"RuleID": "generic-api-key", "Severity": "HIGH", "Title": "Generic API Key", "StartLine": 41}
					]
				}
			]
		}`)
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
		}
		if len(findings) != 2 || findings[0].ID == findings[1].ID {
			t.Fatalf("findings = %+v, want 2 distinct IDs", findings)
		}
	})

	t.Run("vulnerabilities and secrets from one report", func(t *testing.T) {
		// One trivy invocation produces both, which is the entire
		// reason TrivyScanner declares two buckets.
		input := []byte(`{
			"Results": [
				{
					"Target": "alpine:3.19 (alpine 3.19.1)",
					"Vulnerabilities": [
						{"VulnerabilityID": "CVE-2024-1", "Severity": "HIGH", "Title": "some issue"}
					]
				},
				{
					"Target": "app/.env",
					"Secrets": [
						{"RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL", "Title": "GitHub Personal Access Token", "StartLine": 1}
					]
				}
			]
		}`)
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
		}
		if len(findings) != 2 {
			t.Fatalf("findings = %+v, want 2", findings)
		}
		var cve, secret int
		for _, f := range findings {
			switch f.Category {
			case "":
				cve++
			case "secret":
				secret++
			}
		}
		if cve != 1 || secret != 1 {
			t.Fatalf("got %d cve-bound and %d secret-bound findings, want 1 and 1 (%+v)", cve, secret, findings)
		}
	})

	t.Run("a report with no Secrets block is unchanged", func(t *testing.T) {
		// `trivy sbom` output never carries Secrets, and SBOMScanner
		// shares this parser -- so this is the assertion that sharing
		// it is safe.
		input := []byte(`{"Results": [{"Target": "x", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-9", "Severity": "LOW", "Title": "t"}]}]}`)
		findings, err := parseTrivyReport(input)
		if err != nil {
			t.Fatalf("parseTrivyReport: %v", err)
		}
		want := []artifact.Finding{{ID: "CVE-2024-9", Severity: "LOW", Title: "t", Source: "trivy"}}
		if !reflect.DeepEqual(findings, want) {
			t.Fatalf("findings = %+v, want %+v", findings, want)
		}
	})
}

// TestParseTrivyReport_Sample parses the REAL trivy report fixture the
// document tests use, rather than another hand-written literal --
// hand-written JSON only ever proves the parser matches the author's
// idea of trivy's output, which is exactly the assumption worth
// checking against a real one.
func TestParseTrivyReport_Sample(t *testing.T) {
	findings, err := parseTrivyReport(loadSampleTrivyReport(t))
	if err != nil {
		t.Fatalf("parseTrivyReport: %v", err)
	}

	var secrets, cves []artifact.Finding
	for _, f := range findings {
		if f.Category == "secret" {
			secrets = append(secrets, f)
		} else {
			cves = append(cves, f)
		}
	}
	if len(cves) == 0 {
		t.Error("no CVE findings parsed -- secret support must not cost the vulnerability half")
	}
	// Two in app/.env (same rule, different lines) and one in
	// etc/app/credentials.ini (same rule again, different file).
	if len(secrets) != 3 {
		t.Fatalf("parsed %d secret findings, want 3: %+v", len(secrets), secrets)
	}
	seen := map[string]bool{}
	for _, f := range secrets {
		if seen[f.ID] {
			t.Errorf("duplicate secret finding ID %q -- MergeFindings matches by ID, so one real secret would be lost", f.ID)
		}
		seen[f.ID] = true
		if f.Source != "trivy" {
			t.Errorf("Source = %q, want %q", f.Source, "trivy")
		}
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

// TestWrapTrivyScanError_UnqualifiedRefNotFound is the exact bug report
// this classification pass was written for: a bare, unqualified ref
// (no registry/library prefix) fails to resolve on the remote leg
// without ever producing a MANIFEST_UNKNOWN error -- the pre-existing
// check required that exact code and missed this shape entirely, so the
// full docker/containerd/podman/remote FATAL dump leaked to the user
// verbatim. Fixture trimmed from the real failure reported for
// "cosign:latest".
func TestWrapTrivyScanError_UnqualifiedRefNotFound(t *testing.T) {
	rawStderr := `2026-08-04T22:00:05Z	FATAL	Fatal error	run error: image scan error: scan error: unable to initialize a scan service: unable to initialize artifact: unable to initialize container image: unable to find the specified image "cosign:latest" in ["docker" "containerd" "podman" "remote"]: 4 errors occurred:
	* docker error: unable to inspect the image (cosign:latest): failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory
	* containerd error: containerd socket not found: /run/containerd/containerd.sock
	* podman error: unable to initialize Podman client: no podman socket found: stat podman/podman.sock: no such file or directory
	* remote error: GET https://index.docker.io/v2/library/cosign/manifests/latest: unexpected status code 404 Not Found: NAME_UNKNOWN: repository name not known to registry
`
	err := wrapTrivyScanError("trivy scan", "cosign:latest", errors.New("exit status 1"), rawStderr)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not found in the registry") {
		t.Errorf("message %q should give the simplified explanation even without a MANIFEST_UNKNOWN error code", msg)
	}
	for _, noisy := range []string{"docker error", "containerd error", "podman error", "docker.sock", "4 errors occurred"} {
		if strings.Contains(msg, noisy) {
			t.Errorf("message %q still contains raw trivy noise %q, want it collapsed away", msg, noisy)
		}
	}
}

// TestWrapTrivyScanError_RegistryAuthFailure confirms a rejected pull
// (relevant once Part C's registry auth lands) gets its own distinct
// message instead of being misread as "not found" just because trivy's
// summary line can wrap both cases identically.
func TestWrapTrivyScanError_RegistryAuthFailure(t *testing.T) {
	rawStderr := `* remote error: GET https://scm-registry/v2/private/app/manifests/latest: UNAUTHORIZED: authentication required`
	err := wrapTrivyScanError("trivy scan", "scm-registry/private/app:latest", errors.New("exit status 1"), rawStderr)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "authentication failed") {
		t.Errorf("message %q should call out the authentication failure", msg)
	}
	if strings.Contains(msg, "not found in the registry") {
		t.Errorf("message %q should not be relabeled as not-found -- a bad credential is a different problem than a missing ref", msg)
	}
}
