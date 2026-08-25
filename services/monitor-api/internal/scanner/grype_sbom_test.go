package scanner

import (
	"reflect"
	"strings"
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

// TestGrypeSBOMScanner_ByCVEArg is the SBOM counterpart. Both grype
// entry points must agree on naming, or an image scan and an sbom
// re-evaluation of the same artifact would disagree about what its
// findings are called.
func TestGrypeSBOMScanner_ByCVEArg(t *testing.T) {
	prev := GrypeByCVE
	defer func() { GrypeByCVE = prev }()

	s := NewGrypeSBOMScanner(GrypeDBConfig{})

	GrypeByCVE = false
	if got := strings.Join(s.args("/tmp/sbom.json"), " "); strings.Contains(got, "--by-cve") {
		t.Errorf("args = %q, want no --by-cve when GrypeByCVE is false", got)
	}

	GrypeByCVE = true
	got := strings.Join(s.args("/tmp/sbom.json"), " ")
	if !strings.Contains(got, "--by-cve") {
		t.Errorf("args = %q, want --by-cve when GrypeByCVE is true", got)
	}
	if !strings.Contains(got, "sbom:/tmp/sbom.json") {
		t.Errorf("args = %q lost the sbom: prefix", got)
	}
}
