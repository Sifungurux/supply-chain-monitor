package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
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

// fleetVEXResponse mirrors uploadFleetVEX's response body.
type fleetVEXResponse struct {
	Status           string   `json:"status"`
	DocumentID       string   `json:"document_id"`
	Statements       int      `json:"statements"`
	ArtifactsUpdated int      `json:"artifacts_updated"`
	NoProduct        int      `json:"statements_naming_no_product"`
	Artifacts        []string `json:"artifacts"`
}

func decodeFleetVEX(t *testing.T, rec *httptest.ResponseRecorder) fleetVEXResponse {
	t.Helper()
	var out fleetVEXResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode fleet VEX response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func findingsByID(a artifact.Artifact) map[string]artifact.Finding {
	out := make(map[string]artifact.Finding, len(a.CVEFindings))
	for _, f := range a.CVEFindings {
		out[f.ID] = f
	}
	return out
}

// fleetDoc builds an OpenVEX document naming one product.
func fleetDoc(vulnID, status, product string) []byte {
	return []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "statements": [
	    {
	      "vulnerability": {"name": "` + vulnID + `"},
	      "status": "` + status + `",
	      "justification": "vulnerable_code_not_in_execute_path",
	      "products": [{"@id": "` + product + `"}]
	    }
	  ]
	}`)
}

// TestFleetVEX_MatchesByDigest: the narrow arm. The product identifier
// IS the artifact, so exactly the artifact carrying that digest is
// suppressed and its neighbour is untouched.
func TestFleetVEX_MatchesByDigest(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "critical", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})

	target := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	other := mustCreate(t, store, "debian:12", artifact.TypeImage)
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if _, err := store.Update(target.ID, func(a *artifact.Artifact) { a.Digest = digest }); err != nil {
		t.Fatal(err)
	}
	scanAndWait(t, h, store, target.ID)
	scanAndWait(t, h, store, other.ID)

	rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		fleetDoc("CVE-2024-1", "not_affected", "pkg:oci/app@"+digest))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeFleetVEX(t, rec)
	if resp.ArtifactsUpdated != 1 || len(resp.Artifacts) != 1 || resp.Artifacts[0] != target.ID {
		t.Fatalf("artifacts updated = %+v, want exactly [%s]", resp.Artifacts, target.ID)
	}

	got, err := store.Get(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*got)["CVE-2024-1"]; f.Status != artifact.FindingStatusNotAffected {
		t.Errorf("target CVE-2024-1 = %+v, want not_affected", f)
	}
	// The blast radius matters as much as the hit: a digest-scoped
	// document must not touch an artifact that merely has the same CVE.
	untouched, err := store.Get(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*untouched)["CVE-2024-1"]; f.Status != artifact.FindingStatusOpen {
		t.Errorf("other artifact CVE-2024-1 = %+v, want left open", f)
	}
}

// TestFleetVEX_MatchesByComponentPURL: the broad arm. The product is
// something artifacts CONTAIN, so every artifact shipping it is
// suppressed -- which is the point of a fleet document, and the reason
// the response reports how many it hit.
func TestFleetVEX_MatchesByComponentPURL(t *testing.T) {
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2021-44228", Severity: "critical", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})

	shipsIt := mustCreate(t, store, "app-a:1.0", artifact.TypeImage)
	alsoShipsIt := mustCreate(t, store, "app-b:1.0", artifact.TypeImage)
	clean := mustCreate(t, store, "app-c:1.0", artifact.TypeImage)
	for _, id := range []string{shipsIt.ID, alsoShipsIt.ID} {
		if err := store.SaveComponents(id, []artifact.Component{{PURL: purl, Name: "log4j-core", Version: "2.14.1"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveComponents(clean.ID, []artifact.Component{{PURL: "pkg:maven/com.example/other@1.0"}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{shipsIt.ID, alsoShipsIt.ID, clean.ID} {
		scanAndWait(t, h, store, id)
	}

	rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		fleetDoc("CVE-2021-44228", "not_affected", purl))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeFleetVEX(t, rec); resp.ArtifactsUpdated != 2 {
		t.Fatalf("artifacts updated = %d (%v), want 2", resp.ArtifactsUpdated, resp.Artifacts)
	}

	for _, id := range []string{shipsIt.ID, alsoShipsIt.ID} {
		got, err := store.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if f := findingsByID(*got)["CVE-2021-44228"]; f.Status != artifact.FindingStatusNotAffected {
			t.Errorf("artifact %s = %+v, want not_affected", id, f)
		}
	}
	got, err := store.Get(clean.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*got)["CVE-2021-44228"]; f.Status != artifact.FindingStatusOpen {
		t.Errorf("artifact without the component = %+v, want left open", f)
	}
}

// TestFleetVEX_StatementWithNoProductMatchesNothing: the safety
// property. A document whose statements name no product must suppress
// NOTHING, rather than reading as "applies to everything".
func TestFleetVEX_StatementWithNoProductMatchesNothing(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "critical", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	scanAndWait(t, h, store, created.ID)

	rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json", []byte(notAffectedVEX))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeFleetVEX(t, rec)
	if resp.ArtifactsUpdated != 0 {
		t.Errorf("artifacts updated = %d, want 0", resp.ArtifactsUpdated)
	}
	// Reported rather than silent: "my document did nothing" is the
	// common failure, and this is the number that explains it.
	if resp.NoProduct != 1 {
		t.Errorf("statements_naming_no_product = %d, want 1", resp.NoProduct)
	}

	got, err := store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*got)["CVE-2024-1"]; f.Status != artifact.FindingStatusOpen {
		t.Errorf("finding = %+v, want untouched", f)
	}
}

// TestFleetVEX_PerArtifactWinsOnConflict: the precedence rule, in the
// direction that actually matters -- a per-artifact "affected" must
// beat a fleet "not_affected", because the operator who assessed THIS
// image outranks a statement about a package it contains.
func TestFleetVEX_PerArtifactWinsOnConflict(t *testing.T) {
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2021-44228", Severity: "critical", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "app:1.0", artifact.TypeImage)
	if err := store.SaveComponents(created.ID, []artifact.Component{{PURL: purl}}); err != nil {
		t.Fatal(err)
	}
	scanAndWait(t, h, store, created.ID)

	// Fleet says not_affected...
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		fleetDoc("CVE-2021-44228", "not_affected", purl)); rec.Code != http.StatusOK {
		t.Fatalf("fleet upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got, err := store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*got)["CVE-2021-44228"]; f.Status != artifact.FindingStatusNotAffected {
		t.Fatalf("after fleet upload = %+v, want not_affected", f)
	}

	// ...and the per-artifact document says otherwise. It wins, AND the
	// "affected" status revokes the suppression already stamped on.
	perArtifact := []byte(`{"statements":[{"vulnerability":{"name":"CVE-2021-44228"},"status":"affected"}]}`)
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", perArtifact); rec.Code != http.StatusOK {
		t.Fatalf("per-artifact upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got, err = store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*got)["CVE-2021-44228"]; f.Status != artifact.FindingStatusOpen {
		t.Fatalf("per-artifact 'affected' did not revoke the fleet suppression: %+v", f)
	}

	// And it must SURVIVE the next scan -- runScan layers the
	// per-artifact document over the fleet one, so the fleet
	// "not_affected" must not quietly win again on the next round.
	_, rescanned := scanAndWait(t, h, store, created.ID)
	if f := findingsByID(*rescanned)["CVE-2021-44228"]; f.Status != artifact.FindingStatusOpen {
		t.Errorf("after rescan = %+v, want still open -- the fleet document re-suppressed it", f)
	}
}

// TestFleetVEX_AppliesToFindingsFirstSeenOnALaterScan: a fleet document
// uploaded BEFORE an artifact is ever scanned must suppress the finding
// the moment a scan first reports it -- that is the runScan half of the
// feature, and it is not covered by the upload-time apply above.
func TestFleetVEX_AppliesToFindingsFirstSeenOnALaterScan(t *testing.T) {
	const digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-9", Severity: "high", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(created.ID, func(a *artifact.Artifact) { a.Digest = digest }); err != nil {
		t.Fatal(err)
	}

	// Uploaded first, when the artifact has no findings at all.
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		fleetDoc("CVE-2024-9", "not_affected", digest)); rec.Code != http.StatusOK {
		t.Fatalf("fleet upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	_, scanned := scanAndWait(t, h, store, created.ID)
	if f := findingsByID(*scanned)["CVE-2024-9"]; f.Status != artifact.FindingStatusNotAffected {
		t.Errorf("first-ever scan of a fleet-suppressed CVE = %+v, want not_affected", f)
	}
}

// TestFleetVEX_RejectsCycloneDX: a CycloneDX document has no products
// array, so it can only ever match nothing. Refused with a message
// rather than accepted as a no-op.
func TestFleetVEX_RejectsCycloneDX(t *testing.T) {
	h, _ := newTestRouter(nil)
	rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		[]byte(`{"vulnerabilities":[{"id":"CVE-2024-1","analysis":{"state":"not_affected"}}]}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

// TestFleetVEX_UploadDoesNotOverrideAnExistingPerArtifactStatement is
// the OTHER ordering, and it is not the same test as the one above.
// There the fleet document arrived first; here the per-artifact
// assessment is already on record when the fleet document lands, so it
// is applyFleetVEX's own overlay -- not runScan's -- that has to hold
// the line.
//
// Found by deleting that overlay and watching every other test still
// pass.
func TestFleetVEX_UploadDoesNotOverrideAnExistingPerArtifactStatement(t *testing.T) {
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2021-44228", Severity: "critical", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "app:1.0", artifact.TypeImage)
	if err := store.SaveComponents(created.ID, []artifact.Component{{PURL: purl}}); err != nil {
		t.Fatal(err)
	}
	scanAndWait(t, h, store, created.ID)

	// The operator has assessed THIS image and says it IS affected.
	perArtifact := []byte(`{"statements":[{"vulnerability":{"name":"CVE-2021-44228"},"status":"affected"}]}`)
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/vex", "application/json", perArtifact); rec.Code != http.StatusOK {
		t.Fatalf("per-artifact upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// A fleet document about the package must not overturn that.
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		fleetDoc("CVE-2021-44228", "not_affected", purl)); rec.Code != http.StatusOK {
		t.Fatalf("fleet upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	got, err := store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f := findingsByID(*got)["CVE-2021-44228"]; f.Status != artifact.FindingStatusOpen {
		t.Errorf("fleet upload overrode the per-artifact assessment: %+v, want still open", f)
	}
}

// TestFleetVEX_MatchesTheDigestResolvedByThisVeryScan is the ordering
// trap in runScan: the digest is resolved into a LOCAL variable, and
// only written onto the artifact inside the store.Update callback that
// runs afterwards. Matching against the artifact struct loaded before
// the scan therefore sees the OLD digest -- empty, on the first scan of
// a freshly registered artifact, which is exactly when a fleet document
// naming it by digest most needs to apply.
//
// The sibling test above cannot catch this: it stamps the digest on via
// store.Update before scanning, so the loaded artifact already has one.
func TestFleetVEX_MatchesTheDigestResolvedByThisVeryScan(t *testing.T) {
	const digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": digest}}
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-7", Severity: "high", Source: "trivy"}}}
	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:          store,
		Tracker:        pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"}),
		Scanners:       scanner.Registry{artifact.TypeImage: {trivyLike}},
		APIKey:         testAPIKey,
		DigestResolver: resolver,
	})

	// Registered with NO digest on record. The scan below resolves it.
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if created.Digest != "" {
		t.Fatalf("fixture is wrong: artifact already has digest %q, so this proves nothing", created.Digest)
	}

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/vex", "application/json",
		fleetDoc("CVE-2024-7", "not_affected", digest)); rec.Code != http.StatusOK {
		t.Fatalf("fleet upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	_, scanned := scanAndWait(t, h, store, created.ID)
	if scanned.Digest != digest {
		t.Fatalf("scan did not resolve the digest (got %q) -- fixture broken", scanned.Digest)
	}
	if f := findingsByID(*scanned)["CVE-2024-7"]; f.Status != artifact.FindingStatusNotAffected {
		t.Errorf("finding = %+v, want not_affected -- the fleet document named the digest this scan resolved", f)
	}
}
