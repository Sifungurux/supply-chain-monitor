package scanner

import (
	"reflect"
	"testing"
)

// Mirrors TestTrivyScanner_Args -- confirms the `trivy sbom` invocation
// (and its air-gapped DB-mirror flags, shared with `trivy image` via
// dbArgs) is assembled correctly without needing the real trivy binary.
func TestSBOMScanner_Args(t *testing.T) {
	// See TestTrivyScanner_Args's identical reset -- VerboseScanLogs is
	// shared package state.
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
			want: []string{"sbom", "--quiet", "--format", "json", "/tmp/app.cdx.json"},
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
				"sbom", "--quiet", "--format", "json",
				"--db-repository", "scm-registry:5000/aquasecurity/trivy-db:2",
				"--java-db-repository", "scm-registry:5000/aquasecurity/trivy-java-db:1",
				"--skip-db-update",
				"--skip-java-db-update",
				"/tmp/app.cdx.json",
			},
		},
		{
			// Mirrors TestTrivyScanner_Args' equivalent case -- confirms
			// `trivy sbom` gets the same --cache-dir/--cache-backend
			// memory pair `trivy image` does, since IsolatedTrivyScanner
			// uses this same SBOMScanner for SBOM-mode scan-worker Jobs.
			name: "cache-dir adds --cache-backend memory alongside it",
			db: TrivyDBConfig{
				SkipDBUpdate:     true,
				SkipJavaDBUpdate: true,
				CacheDir:         "/trivy-cache",
			},
			want: []string{
				"sbom", "--quiet", "--format", "json",
				"--skip-db-update",
				"--skip-java-db-update",
				"--cache-dir", "/trivy-cache",
				"--cache-backend", "memory",
				"/tmp/app.cdx.json",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSBOMScanner(tc.db)
			got := s.args("/tmp/app.cdx.json")
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("args = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestSBOMScanner_Args_Verbose mirrors TestTrivyScanner_Args_Verbose --
// `trivy sbom` shares verbosityArgs with `trivy image`, so this must
// swap "--quiet" for "--debug" too.
func TestSBOMScanner_Args_Verbose(t *testing.T) {
	VerboseScanLogs = true
	defer func() { VerboseScanLogs = false }()

	s := NewSBOMScanner(TrivyDBConfig{})
	got := s.args("/tmp/app.cdx.json")
	want := []string{"sbom", "--debug", "--format", "json", "/tmp/app.cdx.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

// TestSBOMScanner_Bucket confirms SBOMScanner declares BucketAffinity
// as "cve", same as TrivyScanner (both share parseTrivyVulnerabilities).
func TestSBOMScanner_Bucket(t *testing.T) {
	s := NewSBOMScanner(TrivyDBConfig{})
	if got := s.Bucket(); got != "cve" {
		t.Errorf("Bucket() = %q, want %q", got, "cve")
	}
}
