package scanner

import (
	"reflect"
	"testing"
)

// Mirrors TestGrypeScanner_Args -- confirms the "sbom:" source prefix
// is used for GrypeSBOMScanner instead of GrypeScanner's "registry:".
func TestGrypeSBOMScanner_Args(t *testing.T) {
	VerboseScanLogs = false
	defer func() { VerboseScanLogs = false }()

	s := NewGrypeSBOMScanner(GrypeDBConfig{})
	got := s.args("/tmp/app.cdx.json")
	want := []string{"sbom:/tmp/app.cdx.json", "-o", "json", "-q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestGrypeSBOMScanner_Args_Verbose(t *testing.T) {
	VerboseScanLogs = true
	defer func() { VerboseScanLogs = false }()

	s := NewGrypeSBOMScanner(GrypeDBConfig{})
	got := s.args("/tmp/app.cdx.json")
	want := []string{"sbom:/tmp/app.cdx.json", "-o", "json", "-vv"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

// TestGrypeSBOMScanner_Bucket confirms GrypeSBOMScanner declares
// BucketAffinity as "cve", same as GrypeScanner (both share
// parseGrypeVulnerabilities).
func TestGrypeSBOMScanner_Bucket(t *testing.T) {
	s := NewGrypeSBOMScanner(GrypeDBConfig{})
	if got := s.Bucket(); got != "cve" {
		t.Errorf("Bucket() = %q, want %q", got, "cve")
	}
}
