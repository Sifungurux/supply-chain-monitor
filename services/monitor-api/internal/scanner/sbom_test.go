package scanner

import (
	"reflect"
	"testing"
)

// Mirrors TestTrivyScanner_Args -- confirms the `trivy sbom` invocation
// (and its air-gapped DB-mirror flags, shared with `trivy image` via
// dbArgs) is assembled correctly without needing the real trivy binary.
func TestSBOMScanner_Args(t *testing.T) {
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
