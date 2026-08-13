package scanner_test

import (
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// A real OpenVEX 0.2.0 document, in the shape `vexctl create` writes
// one -- object-form vulnerability, products, and a justification.
const openVEXDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
  "author": "sec@example.com",
  "timestamp": "2026-08-01T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-1111" },
      "products": [ { "@id": "pkg:oci/example@sha256:abc" } ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    },
    {
      "vulnerability": { "name": "CVE-2024-2222" },
      "status": "fixed"
    },
    {
      "vulnerability": { "name": "CVE-2024-3333" },
      "status": "under_investigation"
    }
  ]
}`

func TestParseVEX_OpenVEX(t *testing.T) {
	statements, err := scanner.ParseVEX([]byte(openVEXDoc))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	byID := artifact.VEXByID(statements)
	if len(byID) != 3 {
		t.Fatalf("parsed %d statements, want 3: %+v", len(byID), statements)
	}
	if got := byID["CVE-2024-1111"]; got.Status != artifact.FindingStatusNotAffected ||
		got.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("CVE-2024-1111 = %+v", got)
	}
	if got := byID["CVE-2024-2222"]; got.Status != artifact.FindingStatusFixed {
		t.Fatalf("CVE-2024-2222 status = %q, want fixed", got.Status)
	}
	if got := byID["CVE-2024-3333"]; got.Status != "under_investigation" {
		t.Fatalf("CVE-2024-3333 status = %q, want under_investigation passed through", got.Status)
	}
}

// OpenVEX 0.0.1 wrote `vulnerability` as a bare string, and documents
// in that shape are still in circulation.
func TestParseVEX_OpenVEXBareStringVulnerability(t *testing.T) {
	statements, err := scanner.ParseVEX([]byte(`{
	  "@context": "https://openvex.dev/ns/v0.0.1",
	  "statements": [
	    { "vulnerability": "CVE-2024-1111", "status": "not_affected", "impact_statement": "not reachable from any entrypoint" }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("parsed %+v, want 1 statement", statements)
	}
	if statements[0].VulnID != "CVE-2024-1111" {
		t.Fatalf("vuln id = %q, want the bare string form to be read", statements[0].VulnID)
	}
	if statements[0].Justification != "not reachable from any entrypoint" {
		t.Fatalf("justification = %q, want impact_statement used when justification is absent", statements[0].Justification)
	}
}

func TestParseVEX_CycloneDX(t *testing.T) {
	statements, err := scanner.ParseVEX([]byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "vulnerabilities": [
	    { "id": "CVE-2024-1111", "analysis": { "state": "not_affected", "justification": "code_not_reachable" } },
	    { "id": "CVE-2024-2222", "analysis": { "state": "resolved", "detail": "patched in 1.2.4" } },
	    { "id": "CVE-2024-3333", "analysis": { "state": "false_positive" } },
	    { "id": "CVE-2024-4444", "analysis": { "state": "exploitable" } },
	    { "id": "CVE-2024-5555", "analysis": { "state": "in_triage" } }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	byID := artifact.VEXByID(statements)
	want := map[string]string{
		"CVE-2024-1111": artifact.FindingStatusNotAffected,
		"CVE-2024-2222": artifact.FindingStatusFixed,
		"CVE-2024-3333": artifact.FindingStatusNotAffected, // a false positive was never a problem here
		"CVE-2024-4444": "affected",
		"CVE-2024-5555": "under_investigation",
	}
	for id, wantStatus := range want {
		if got := byID[id].Status; got != wantStatus {
			t.Errorf("%s status = %q, want %q", id, got, wantStatus)
		}
	}
	if got := byID["CVE-2024-2222"].Justification; got != "patched in 1.2.4" {
		t.Errorf("justification = %q, want analysis.detail used when justification is absent", got)
	}
}

func TestParseVEX_StatusSpellingIsNormalized(t *testing.T) {
	statements, err := scanner.ParseVEX([]byte(`{"statements":[
	  {"vulnerability":"CVE-1","status":"NOT_AFFECTED"},
	  {"vulnerability":"CVE-2","status":"not-affected"},
	  {"vulnerability":"CVE-3","status":" Not Affected "}
	]}`))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	for _, s := range statements {
		if s.Status != artifact.FindingStatusNotAffected {
			t.Errorf("%s status = %q, want %q", s.VulnID, s.Status, artifact.FindingStatusNotAffected)
		}
	}
}

func TestParseVEX_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"not json", "this is not a document"},
		{"json but neither format", `{"hello": "world"}`},
		{"an SBOM, not a VEX document", `{"bomFormat":"CycloneDX","components":[{"name":"openssl"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := scanner.ParseVEX([]byte(tt.content)); err == nil {
				t.Fatalf("ParseVEX(%q) = nil error, want a rejection", tt.content)
			}
		})
	}
}

// A statement with no vulnerability id can't be matched to anything, so
// it's skipped rather than failing the document it arrived in -- the
// other statements are still perfectly usable.
func TestParseVEX_SkipsStatementsWithoutAnID(t *testing.T) {
	statements, err := scanner.ParseVEX([]byte(`{"statements":[
	  {"status":"not_affected"},
	  {"vulnerability":{"name":""},"status":"not_affected"},
	  {"vulnerability":"CVE-2024-1111","status":"not_affected"}
	]}`))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if len(statements) != 1 || statements[0].VulnID != "CVE-2024-1111" {
		t.Fatalf("statements = %+v, want only the one with an id", statements)
	}
}
