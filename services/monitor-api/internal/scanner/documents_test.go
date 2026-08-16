package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testdata/trivy_report_sample.json is a REAL trivy `--format json`
// report (captured from `trivy image alpine:3.19`, trimmed to one
// vulnerability + its matching package entry), not hand-written --
// `trivy convert --format cyclonedx` needs PkgID/PkgIdentifier on the
// vulnerability AND a matching entry in the Result's own Packages list
// to link a vulnerability to a BOM component; a hand-written report
// missing those fields converts without error but silently drops the
// vulnerability from the output, which a hand-rolled minimal fixture
// got wrong on the first pass of writing this test.
func loadSampleTrivyReport(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "trivy_report_sample.json"))
	if err != nil {
		t.Fatalf("read testdata/trivy_report_sample.json: %v", err)
	}
	return data
}

// requireTrivy skips the test if the real trivy CLI isn't on PATH --
// this exercises the actual `trivy convert` invocation
// (GenerateImageDocuments has no separate parsing step to test against
// canned output the way parseTrivyReport does, since trivy
// convert itself *is* the logic here), so it needs the real binary.
// Runs locally wherever trivy is installed (see Dockerfile's pinned
// TRIVY_VERSION); CI doesn't install it, so this skips cleanly there
// rather than failing the whole suite over a missing external tool.
func requireTrivy(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not installed, skipping (see this test's own comment)")
	}
}

func TestGenerateImageDocuments(t *testing.T) {
	requireTrivy(t)

	docs, errs := GenerateImageDocuments(context.Background(), loadSampleTrivyReport(t), t.TempDir())
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 documents (sbom, sarif), got %d", len(docs))
	}

	byKind := make(map[string]GeneratedDocument)
	for _, d := range docs {
		byKind[d.Kind] = d
	}

	sbom, ok := byKind["sbom"]
	if !ok {
		t.Fatal("missing sbom document")
	}
	if sbom.ContentType != "application/vnd.cyclonedx+json" {
		t.Errorf("sbom content type = %q", sbom.ContentType)
	}
	var sbomDoc struct {
		BOMFormat       string `json:"bomFormat"`
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(sbom.Content, &sbomDoc); err != nil {
		t.Fatalf("sbom content isn't valid JSON: %v", err)
	}
	if sbomDoc.BOMFormat != "CycloneDX" {
		t.Errorf("sbom bomFormat = %q, want CycloneDX", sbomDoc.BOMFormat)
	}
	foundVuln := false
	for _, v := range sbomDoc.Vulnerabilities {
		if v.ID == "CVE-2024-58251" {
			foundVuln = true
		}
	}
	if !foundVuln {
		t.Error("sbom should retain CVE-2024-58251 from the source report (--scanners vuln) but it's missing")
	}

	sarif, ok := byKind["sarif"]
	if !ok {
		t.Fatal("missing sarif document")
	}
	if sarif.ContentType != "application/sarif+json" {
		t.Errorf("sarif content type = %q", sarif.ContentType)
	}
	var sarifDoc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(sarif.Content, &sarifDoc); err != nil {
		t.Fatalf("sarif content isn't valid JSON: %v", err)
	}
	if sarifDoc.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", sarifDoc.Version)
	}
}

func TestGenerateImageDocuments_InvalidReportReturnsErrorsNotPanic(t *testing.T) {
	requireTrivy(t)

	docs, errs := GenerateImageDocuments(context.Background(), []byte("not valid json"), t.TempDir())
	if len(docs) != 0 {
		t.Errorf("expected no documents from an invalid report, got %d", len(docs))
	}
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors (sbom, sarif both fail), got %d: %v", len(errs), errs)
	}
}
