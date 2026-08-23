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

// TestParseVEXProducts_BothProductShapes covers the two `products`
// encodings that exist in the wild together, since a fleet document is
// exactly where a 0.0.1-era bare purl and a 0.2.0 object turn up in the
// same file.
func TestParseVEXProducts_BothProductShapes(t *testing.T) {
	doc := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "statements": [
	    {
	      "vulnerability": {"name": "CVE-2024-1111"},
	      "status": "not_affected",
	      "justification": "vulnerable_code_not_in_execute_path",
	      "products": ["pkg:apk/wolfi/bash@1.0.0"]
	    },
	    {
	      "vulnerability": "CVE-2024-2222",
	      "status": "affected",
	      "products": [
	        {
	          "@id": "pkg:oci/app@sha256:aaaa",
	          "identifiers": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
	          "hashes": {"sha-256": "BBBB"}
	        }
	      ]
	    }
	  ]
	}`)

	got, err := scanner.ParseVEXProducts(doc)
	if err != nil {
		t.Fatalf("ParseVEXProducts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %+v", len(got), got)
	}

	if got[0].VulnID != "CVE-2024-1111" || got[0].Status != artifact.FindingStatusNotAffected {
		t.Errorf("first statement = %+v", got[0].VEXStatement)
	}
	if len(got[0].Products) != 1 || got[0].Products[0] != "pkg:apk/wolfi/bash@1.0.0" {
		t.Errorf("bare-string product not read: %+v", got[0].Products)
	}

	// The object form must yield ALL THREE identifiers: which one
	// matches an artifact is the store's decision, not the parser's.
	want := map[string]bool{
		"pkg:oci/app@sha256:aaaa":                              true,
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": true,
		// Hex lowercased and prefixed with the algorithm, so it is
		// directly comparable to Artifact.Digest.
		"sha256:bbbb": true,
	}
	for _, id := range got[1].Products {
		delete(want, id)
	}
	if len(want) != 0 {
		t.Errorf("object-form identifiers missing %v (got %v)", want, got[1].Products)
	}
	// "affected" must survive parsing verbatim -- it is what revokes an
	// earlier suppression in MergeFindings.
	if got[1].Status != artifact.VEXStatusAffected {
		t.Errorf("status = %q, want %q", got[1].Status, artifact.VEXStatusAffected)
	}
}

// TestParseVEXProducts_StatementWithNoProductMatchesNothing: an empty
// Products must NOT read as "applies to everything". Fleet-wide that
// would let one malformed document suppress the estate.
func TestParseVEXProducts_StatementWithNoProductMatchesNothing(t *testing.T) {
	got, err := scanner.ParseVEXProducts([]byte(`{"statements":[{"vulnerability":"CVE-2024-3333","status":"not_affected"}]}`))
	if err != nil {
		t.Fatalf("ParseVEXProducts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1", len(got))
	}
	// Kept, not dropped: the handler reports the count of statements
	// that matched nothing, which is how an operator finds out.
	if len(got[0].Products) != 0 {
		t.Errorf("Products = %v, want empty", got[0].Products)
	}
}

// TestParseVEXProducts_CycloneDXIsNotAnOpenVEXDocument: a CycloneDX VEX
// has no products array, and must fail loudly here rather than parse to
// zero statements that silently match nothing.
func TestParseVEXProducts_CycloneDXIsNotAnOpenVEXDocument(t *testing.T) {
	cdx := []byte(`{"vulnerabilities":[{"id":"CVE-2024-4444","analysis":{"state":"not_affected"}}]}`)
	if _, err := scanner.ParseVEXProducts(cdx); err == nil {
		t.Error("a CycloneDX document was accepted by the OpenVEX-only fleet parser")
	}
	// ...and the per-artifact parser must still take it, unchanged.
	if got, err := scanner.ParseVEX(cdx); err != nil || len(got) != 1 {
		t.Errorf("ParseVEX regressed on CycloneDX: %d statements, err=%v", len(got), err)
	}
}
