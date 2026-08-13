package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

const notAffectedVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-1" },
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}`

// uploadVEXResponse mirrors uploadVEX's response body.
type uploadVEXResponse struct {
	Status     string            `json:"status"`
	Statements int               `json:"statements"`
	Artifact   artifact.Artifact `json:"artifact"`
}

func decodeVEXResponse(t *testing.T, rec *httptest.ResponseRecorder) uploadVEXResponse {
	t.Helper()
	var out uploadVEXResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode VEX response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// The end-to-end shape of the feature: scan finds a CVE, an operator
// uploads a VEX document saying it doesn't apply, and the next scan --
// which still reports the CVE, because the image hasn't changed --
// leaves it suppressed.
func TestUploadVEX_SuppressesFindingAndSurvivesTheNextScan(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "critical", Source: "trivy"},
		{ID: "CVE-2024-2", Severity: "high", Source: "trivy"},
	}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if _, scanned := scanAndWait(t, h, store, created.ID); len(scanned.CVEFindings) != 2 {
		t.Fatalf("cve findings after first scan = %+v, want 2", scanned.CVEFindings)
	}

	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(notAffectedVEX))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeVEXResponse(t, rec)
	if resp.Statements != 1 {
		t.Fatalf("statements = %d, want 1", resp.Statements)
	}

	byID := func(a artifact.Artifact) map[string]artifact.Finding {
		out := make(map[string]artifact.Finding, len(a.CVEFindings))
		for _, f := range a.CVEFindings {
			out[f.ID] = f
		}
		return out
	}

	applied := byID(resp.Artifact)
	if got := applied["CVE-2024-1"]; got.Status != artifact.FindingStatusNotAffected ||
		got.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("CVE-2024-1 after VEX upload = %+v, want not_affected with the justification attached", got)
	}
	if got := applied["CVE-2024-2"]; got.Status != artifact.FindingStatusOpen {
		t.Fatalf("CVE-2024-2 = %+v, want left open -- the document said nothing about it", got)
	}

	// Second scan, same scanner, still reporting both.
	_, rescanned := scanAndWait(t, h, store, created.ID)
	after := byID(*rescanned)
	if got := after["CVE-2024-1"]; got.Status != artifact.FindingStatusNotAffected {
		t.Fatalf("CVE-2024-1 after rescan = %+v, want still not_affected", got)
	}
	if got := after["CVE-2024-1"]; got.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("justification after rescan = %q, want preserved", got.Justification)
	}
	if got := after["CVE-2024-2"]; got.Status != artifact.FindingStatusOpen {
		t.Fatalf("CVE-2024-2 after rescan = %+v, want open", got)
	}
}

// A VEX document uploaded before the vulnerability is ever reported has
// to be re-read at scan time, or the first scan to find it would leave
// it open until something else merged.
func TestUploadVEX_AppliesToFindingsDiscoveredLater(t *testing.T) {
	trivyLike := &fakeScanner{}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(notAffectedVEX))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// Only now does a scanner start reporting it.
	trivyLike.findings = []artifact.Finding{{ID: "CVE-2024-1", Severity: "critical", Source: "trivy"}}
	_, scanned := scanAndWait(t, h, store, created.ID)
	if len(scanned.CVEFindings) != 1 {
		t.Fatalf("cve findings = %+v, want 1", scanned.CVEFindings)
	}
	if got := scanned.CVEFindings[0]; got.Status != artifact.FindingStatusNotAffected {
		t.Fatalf("newly discovered finding = %+v, want it to land already suppressed", got)
	}
}

// submitFindings is the other write path into a bucket -- an external
// system has no idea what this artifact's operator already assessed, so
// it must not be a way around a VEX document.
func TestSubmitFindings_RespectsVEX(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(notAffectedVEX)); rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "cve",
		"findings": []map[string]string{
			{"id": "CVE-2024-1", "severity": "critical", "source": "external"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("submit status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.CVEFindings) != 1 {
		t.Fatalf("cve findings = %+v, want 1", got.CVEFindings)
	}
	if got.CVEFindings[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("submitted finding = %+v, want suppressed by the VEX document", got.CVEFindings[0])
	}
}

// Retracting through the endpoint, which is the only way anyone
// actually retracts. The merge-level test covers the same rule, but
// this is the round trip that was broken in practice: uploading an
// "affected" document returned 200 with "1 statement understood" and
// left the finding suppressed, because nothing is reported on the
// upload path.
func TestUploadVEX_AffectedRetractsAnEarlierSuppression(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "critical", Source: "trivy"},
	}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	scanAndWait(t, h, store, created.ID)

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(notAffectedVEX)); rec.Code != http.StatusOK {
		t.Fatalf("suppress status = %d, body=%s", rec.Code, rec.Body.String())
	}

	const affectedVEX = `{"statements":[{"vulnerability":{"name":"CVE-2024-1"},"status":"affected"}]}`
	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(affectedVEX))
	if rec.Code != http.StatusOK {
		t.Fatalf("retract status = %d, body=%s", rec.Code, rec.Body.String())
	}

	got := decodeVEXResponse(t, rec).Artifact
	if len(got.CVEFindings) != 1 {
		t.Fatalf("cve findings = %+v, want 1", got.CVEFindings)
	}
	f := got.CVEFindings[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q immediately after the retraction -- not at some later scan", f.Status, artifact.FindingStatusOpen)
	}
	if f.Justification != "" {
		t.Fatalf("justification = %q, want cleared along with the suppression", f.Justification)
	}

	// And it's actually persisted, not just reflected in the response.
	persisted, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if persisted.CVEFindings[0].Status != artifact.FindingStatusOpen {
		t.Fatalf("persisted status = %q, want open", persisted.CVEFindings[0].Status)
	}
}

func TestUploadVEX_RejectsUnparseableDocument(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	for _, body := range []string{"", "not json at all", `{"bomFormat":"CycloneDX","components":[]}`} {
		rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d for %q, want 400, body=%s", rec.Code, body, rec.Body.String())
		}
	}

	// Nothing was stored: a rejected upload must not replace whatever
	// document was already applied.
	doc, err := store.GetDocument(created.ID, artifact.DocumentKindVEX)
	if err != nil {
		t.Fatalf("GetDocument: %v", err)
	}
	if doc != nil {
		t.Fatalf("a rejected VEX upload stored a document anyway: %+v", doc)
	}
}

func TestUploadVEX_NonexistentArtifactReturns404(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/vex", "application/json", []byte(notAffectedVEX))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// The document is kept, so a later scan can re-read it (see vexFor) and
// an operator can see what was applied. It is deliberately NOT reachable
// through the generic documents endpoint, which only speaks sbom/sarif.
func TestUploadVEX_StoresTheDocumentButNotUnderTheDocumentsEndpoint(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", []byte(notAffectedVEX)); rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	doc, err := store.GetDocument(created.ID, artifact.DocumentKindVEX)
	if err != nil || doc == nil {
		t.Fatalf("GetDocument(vex) = %v, %v -- want the document stored", doc, err)
	}
	if string(doc.Content) != notAffectedVEX {
		t.Errorf("stored content = %q, want the uploaded bytes verbatim", doc.Content)
	}

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/documents/vex", "application/json", []byte(notAffectedVEX)); rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /documents/vex status = %d, want 400 -- VEX has its own endpoint that also applies it", rec.Code)
	}
}
