package scanner

import (
	"reflect"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Confirms the air-gapped DB-mirror flags are assembled the way trivy
// actually expects (--db-repository, --java-db-repository,
// --skip-db-update, --skip-java-db-update) without needing to execute
// the real trivy binary.
func TestTrivyScanner_Args(t *testing.T) {
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
