package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Confirms the "registry:" source prefix and -o json/-q flags are
// assembled the way grype actually expects.
func TestGrypeScanner_Args(t *testing.T) {
	VerboseScanLogs = false
	defer func() { VerboseScanLogs = false }()

	s := NewGrypeScanner(GrypeDBConfig{}, false, "")
	got := s.args("alpine:3.19")
	want := []string{"registry:alpine:3.19", "-o", "json", "-q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestGrypeScanner_Args_Verbose(t *testing.T) {
	VerboseScanLogs = true
	defer func() { VerboseScanLogs = false }()

	s := NewGrypeScanner(GrypeDBConfig{}, false, "")
	got := s.args("alpine:3.19")
	want := []string{"registry:alpine:3.19", "-o", "json", "-vv"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

// TestGrypeScanner_RegistryEnv confirms registryEnv() maps to the two
// mechanisms that were actually verified against the real grype binary
// (see registryEnv's own comment): GRYPE_REGISTRY_INSECURE_USE_HTTP for
// plain-HTTP registries like scm-registry, and DOCKER_CONFIG (NOT
// SYFT_REGISTRY_AUTH_*, which a probe registry proved does nothing) for
// credentials.
func TestGrypeScanner_RegistryEnv(t *testing.T) {
	cases := []struct {
		name            string
		plainHTTP       bool
		dockerConfigDir string
		want            []string
	}{
		{name: "neither set", want: nil},
		{name: "plain http only", plainHTTP: true, want: []string{"GRYPE_REGISTRY_INSECURE_USE_HTTP=true"}},
		{name: "docker config dir only", dockerConfigDir: "/tmp/scm-dockerconfig-abc", want: []string{"DOCKER_CONFIG=/tmp/scm-dockerconfig-abc"}},
		{
			name:            "both set, matching scm-registry's real shape",
			plainHTTP:       true,
			dockerConfigDir: "/tmp/scm-dockerconfig-abc",
			want:            []string{"GRYPE_REGISTRY_INSECURE_USE_HTTP=true", "DOCKER_CONFIG=/tmp/scm-dockerconfig-abc"},
		},
	}

	// The ref is the in-cluster registry throughout, so these cases keep
	// testing what they always tested: the mapping from flags to env
	// vars. Whether plain-HTTP is permitted for a GIVEN ref is a
	// separate question with its own test -- see
	// TestGrypeScanner_RegistryEnv_PlainHTTPIsScopedToTheLocalRegistry.
	const localRef = "scm-registry.supply-chain-monitor.svc.cluster.local:5000/app:v1"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(RegistryAddrEnv, "scm-registry.supply-chain-monitor.svc.cluster.local:5000")
			s := NewGrypeScanner(GrypeDBConfig{}, tc.plainHTTP, tc.dockerConfigDir)
			got := s.registryEnv(localRef)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("registryEnv() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestGrypeScanner_RegistryEnv_PlainHTTPIsScopedToTheLocalRegistry is
// the S4 leg 3 fix at this call site: the switch is deployment-wide,
// the hosts are not.
//
// GRYPE_REGISTRY_INSECURE_USE_HTTP exists because scm-registry serves
// plain HTTP in a dev cluster. Applied to every pull, it also spoke
// plain HTTP to docker.io -- on the same code path, with nothing in the
// output saying so.
func TestGrypeScanner_RegistryEnv_PlainHTTPIsScopedToTheLocalRegistry(t *testing.T) {
	const addr = "scm-registry.supply-chain-monitor.svc.cluster.local:5000"

	cases := []struct {
		name string
		ref  string
		want bool
	}{
		{"the in-cluster registry gets plain HTTP", addr + "/app:v1", true},
		{"docker.io does not", "docker.io/library/alpine:3.19", false},
		{"a bare ref (docker hub) does not", "alpine:3.19", false},
		{"ghcr.io does not", "ghcr.io/aquasecurity/trivy-db:2", false},
		{"a lookalike host does not", "scm-registry.supply-chain-monitor.svc.cluster.local.evil.test/app:v1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(RegistryAddrEnv, addr)
			s := NewGrypeScanner(GrypeDBConfig{}, true, "")
			got := false
			for _, ev := range s.registryEnv(tc.ref) {
				if ev == "GRYPE_REGISTRY_INSECURE_USE_HTTP=true" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("plain HTTP for %q = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

// Confirms GrypeDBConfig's env() maps to grype's real GRYPE_DB_* env
// vars (confirmed via `grype config --load` against the real binary --
// grype's DB config is entirely env-driven, unlike trivy's CLI flags,
// see dbArgs in trivy.go).
func TestGrypeDBConfig_Env(t *testing.T) {
	cases := []struct {
		name string
		db   GrypeDBConfig
		want []string
	}{
		{
			name: "no overrides",
			db:   GrypeDBConfig{},
			want: nil,
		},
		{
			name: "isolated worker shape: cache dir, skip update and age validation",
			db: GrypeDBConfig{
				CacheDir:          "/grype-cache",
				SkipDBUpdate:      true,
				SkipAgeValidation: true,
			},
			want: []string{
				"GRYPE_DB_CACHE_DIR=/grype-cache",
				"GRYPE_DB_AUTO_UPDATE=false",
				"GRYPE_DB_VALIDATE_AGE=false",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.db.env()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("env() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// Confirms grype's `-o json` output is decoded into normalized Findings
// correctly, against inline JSON matching grype's real shape.
func TestParseGrypeVulnerabilities(t *testing.T) {
	t.Run("multiple matches", func(t *testing.T) {
		input := []byte(`{
			"matches": [
				{
					"vulnerability": {"id": "CVE-2024-1", "severity": "High"},
					"artifact": {"name": "openssl", "version": "3.0.9-r0"}
				},
				{
					"vulnerability": {"id": "CVE-2024-2", "severity": "Critical"},
					"artifact": {"name": "busybox", "version": "1.36.1-r20"}
				}
			]
		}`)
		findings, err := parseGrypeVulnerabilities(input)
		if err != nil {
			t.Fatalf("parseGrypeVulnerabilities: %v", err)
		}
		want := []artifact.Finding{
			{ID: "CVE-2024-1", Severity: "High", Title: "openssl 3.0.9-r0", Source: "grype"},
			{ID: "CVE-2024-2", Severity: "Critical", Title: "busybox 1.36.1-r20", Source: "grype"},
		}
		if !reflect.DeepEqual(findings, want) {
			t.Fatalf("findings = %+v, want %+v", findings, want)
		}
	})

	t.Run("no matches", func(t *testing.T) {
		findings, err := parseGrypeVulnerabilities([]byte(`{"matches": []}`))
		if err != nil {
			t.Fatalf("parseGrypeVulnerabilities: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected no findings, got %+v", findings)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		if _, err := parseGrypeVulnerabilities([]byte("not json")); err == nil {
			t.Fatal("expected an error for invalid json")
		}
	})
}

// TestParseGrypeVulnerabilities_RealFixture parses
// testdata/grype_report_sample.json -- three matches trimmed from a
// REAL `grype registry:alpine:3.19 -o json` run (not a guessed shape),
// covering all three fix.state values grype actually produces ("",
// "unknown", "fixed") and a match whose vulnerability.description is
// present (confirming Title deliberately does not depend on it -- see
// parseGrypeVulnerabilities' own comment).
func TestParseGrypeVulnerabilities_RealFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "grype_report_sample.json"))
	if err != nil {
		t.Fatalf("read testdata/grype_report_sample.json: %v", err)
	}
	// Sanity check the fixture itself still looks like real grype output
	// before trusting it as a parsing test.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	if _, ok := raw["matches"]; !ok {
		t.Fatal("fixture missing top-level \"matches\" key")
	}

	findings, err := parseGrypeVulnerabilities(data)
	if err != nil {
		t.Fatalf("parseGrypeVulnerabilities: %v", err)
	}
	want := []artifact.Finding{
		{ID: "CVE-2025-60876", Severity: "Medium", Title: "busybox 1.36.1-r20", Source: "grype"},
		{ID: "CVE-2026-40200", Severity: "High", Title: "musl 1.2.4_git20230717-r5", Source: "grype"},
		{ID: "CVE-2026-27171", Severity: "Medium", Title: "zlib 1.3.1-r0", Source: "grype"},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("findings = %+v, want %+v", findings, want)
	}
}

// TestGrypeScanner_Bucket confirms GrypeScanner declares BucketAffinity
// as "cve" -- every finding comes from parseGrypeVulnerabilities, which
// always sets Source: "grype".
func TestGrypeScanner_Bucket(t *testing.T) {
	s := NewGrypeScanner(GrypeDBConfig{}, false, "")
	if got := s.Bucket(); got != "cve" {
		t.Errorf("Bucket() = %q, want %q", got, "cve")
	}
}
