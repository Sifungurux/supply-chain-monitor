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

	s := NewGrypeScanner(GrypeDBConfig{})
	got := s.args("alpine:3.19")
	want := []string{"registry:alpine:3.19", "-o", "json", "-q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestGrypeScanner_Args_Verbose(t *testing.T) {
	VerboseScanLogs = true
	defer func() { VerboseScanLogs = false }()

	s := NewGrypeScanner(GrypeDBConfig{})
	got := s.args("alpine:3.19")
	want := []string{"registry:alpine:3.19", "-o", "json", "-vv"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
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
	s := NewGrypeScanner(GrypeDBConfig{})
	if got := s.Bucket(); got != "cve" {
		t.Errorf("Bucket() = %q, want %q", got, "cve")
	}
}
