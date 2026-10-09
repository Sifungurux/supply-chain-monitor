package api_test

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestUploadAndDownloadDocument(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	sbomBody := []byte(`{"bomFormat":"CycloneDX"}`)
	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/vnd.cyclonedx+json", sbomBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// The artifact's own JSON now reports a document exists, without
	// embedding its (potentially large) content -- see Artifact.HasSBOM's
	// comment.
	getRec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID, nil)
	got := decodeArtifact(t, getRec)
	if !got.HasSBOM {
		t.Error("HasSBOM should be true after an sbom document upload")
	}
	if got.HasSARIF {
		t.Error("HasSARIF should still be false -- only sbom was uploaded")
	}

	dlRec := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "", nil)
	if dlRec.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200, body=%s", dlRec.Code, dlRec.Body.String())
	}
	if dlRec.Body.String() != string(sbomBody) {
		t.Errorf("downloaded content = %q, want %q", dlRec.Body.String(), string(sbomBody))
	}
	if ct := dlRec.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json" {
		t.Errorf("Content-Type = %q, want application/vnd.cyclonedx+json", ct)
	}
	if cd := dlRec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("expected a Content-Disposition header on a document download")
	}

	// Re-uploading the same kind overwrites, doesn't accumulate.
	newSBOM := []byte(`{"bomFormat":"CycloneDX","version":2}`)
	doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/vnd.cyclonedx+json", newSBOM)
	dlRec2 := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "", nil)
	if dlRec2.Body.String() != string(newSBOM) {
		t.Errorf("re-upload should overwrite the previous document, got %q", dlRec2.Body.String())
	}
}

func TestDownloadDocument_NotYetCapturedReturns404(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/documents/sarif", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a document that was never captured, body=%s", rec.Code, rec.Body.String())
	}
}

func TestDocumentEndpoints_RejectInvalidKind(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	uploadRec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/exe", "application/octet-stream", []byte("x"))
	if uploadRec.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d, want 400 for an invalid kind", uploadRec.Code)
	}

	downloadRec := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/documents/exe", "", nil)
	if downloadRec.Code != http.StatusBadRequest {
		t.Fatalf("download status = %d, want 400 for an invalid kind", downloadRec.Code)
	}
}

func TestUploadDocument_NonexistentArtifactReturns404(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/documents/sbom", "application/json", []byte("{}"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a nonexistent artifact, body=%s", rec.Code, rec.Body.String())
	}
}

// Scan workers upload with a per-Job token instead of the master API
// key (report S3). The worker pod exists to process UNTRUSTED content,
// so the credential it carries has to be worth stealing as little as
// possible.
func TestScanToken_UploadAuth(t *testing.T) {
	newSetup := func(t *testing.T) (http.Handler, *artifact.MemStore, string, string) {
		t.Helper()
		store := artifact.NewMemStore()
		a, err := store.Create("example.com/app:1", artifact.TypeImage)
		if err != nil {
			t.Fatalf("seed artifact: %v", err)
		}
		token, hash, err := api.NewScanToken()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if err := store.CreateScanToken(a.ID, hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("store token: %v", err)
		}
		h := api.NewRouter(api.Config{
			Store:      store,
			Tracker:    pipeline.NewTracker([]string{"build", "scan"}),
			APIKey:     testAPIKey,
			ScanTokens: store.ConsumeScanToken,
		})
		return h, store, a.ID, token
	}

	upload := func(h http.Handler, id, kind, cred string) int {
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/artifacts/"+id+"/documents/"+kind,
			strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`))
		req.Header.Set("Authorization", "Bearer "+cred)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("valid token uploads for its own artifact", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		if code := upload(h, id, "sbom", token); code != http.StatusOK {
			t.Errorf("got %d, want 200", code)
		}
	})

	t.Run("replay of the same kind is rejected", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		if code := upload(h, id, "sbom", token); code != http.StatusOK {
			t.Fatalf("first upload got %d, want 200", code)
		}
		// Single-use PER KIND: a compromised worker must not be able to
		// overwrite the SBOM it already submitted.
		if code := upload(h, id, "sbom", token); code != http.StatusUnauthorized {
			t.Errorf("replay got %d, want 401", code)
		}
		// ...but the other kind is still available to the same Job.
		if code := upload(h, id, "sarif", token); code != http.StatusOK {
			t.Errorf("sarif after sbom got %d, want 200 -- each kind is usable once, not the token as a whole", code)
		}
	})

	t.Run("token scoped to a different artifact is rejected", func(t *testing.T) {
		h, store, _, token := newSetup(t)
		other, err := store.Create("example.com/other:1", artifact.TypeImage)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		// THE POINT OF SCOPING. A worker that pops trivy must not be
		// able to write documents onto every other artifact.
		if code := upload(h, other.ID, "sbom", token); code != http.StatusUnauthorized {
			t.Errorf("cross-artifact upload got %d, want 401", code)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		store := artifact.NewMemStore()
		a, _ := store.Create("example.com/app:1", artifact.TypeImage)
		token, hash, _ := api.NewScanToken()
		_ = store.CreateScanToken(a.ID, hash, time.Now().Add(-time.Minute))
		h := api.NewRouter(api.Config{
			Store: store, Tracker: pipeline.NewTracker([]string{"build"}),
			APIKey: testAPIKey, ScanTokens: store.ConsumeScanToken,
		})
		if code := upload(h, a.ID, "sbom", token); code != http.StatusUnauthorized {
			t.Errorf("expired token got %d, want 401", code)
		}
	})

	t.Run("a scan token is not accepted anywhere else", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		// Scoped to the upload route ONLY -- it must not become a
		// general-purpose credential.
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/artifacts/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("DELETE with a scan token got %d, want 401", rec.Code)
		}
	})
}

// TestScanToken_DownloadAuth covers the read half of the scan-token
// grant, added for the sbom re-evaluation worker: that Job re-runs
// grype against an image's stored SBOM, and the document lives in
// Postgres, so downloading it is the only way into the Job.
//
// The security property worth pinning is that a read is not a write and
// vice versa: each direction is single-use in its own namespaced kind,
// so downloading the SBOM must not spend the upload the token was
// minted for, and neither must widen to another artifact.
func TestScanToken_DownloadAuth(t *testing.T) {
	newSetup := func(t *testing.T) (http.Handler, *artifact.MemStore, string, string) {
		t.Helper()
		store := artifact.NewMemStore()
		a, err := store.Create("example.com/app:1", artifact.TypeImage)
		if err != nil {
			t.Fatalf("seed artifact: %v", err)
		}
		if err := store.SaveDocument(a.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{"bomFormat":"CycloneDX"}`)); err != nil {
			t.Fatalf("seed document: %v", err)
		}
		token, hash, err := api.NewScanToken()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if err := store.CreateScanToken(a.ID, hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("store token: %v", err)
		}
		h := api.NewRouter(api.Config{
			Store:      store,
			Tracker:    pipeline.NewTracker([]string{"build", "scan"}),
			APIKey:     testAPIKey,
			ScanTokens: store.ConsumeScanToken,
		})
		return h, store, a.ID, token
	}

	download := func(h http.Handler, id, kind, cred string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+id+"/documents/"+kind, nil)
		req.Header.Set("Authorization", "Bearer "+cred)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	upload := func(h http.Handler, id, kind, cred string) int {
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/artifacts/"+id+"/documents/"+kind,
			strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`))
		req.Header.Set("Authorization", "Bearer "+cred)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("valid token downloads its own artifact's sbom", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		if code := download(h, id, "sbom", token); code != http.StatusOK {
			t.Errorf("got %d, want 200", code)
		}
	})

	t.Run("a download does not spend the upload", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		if code := download(h, id, "sbom", token); code != http.StatusOK {
			t.Fatalf("download got %d, want 200", code)
		}
		// The namespaced read kind is the whole point: without it the
		// download would burn "sbom" and this upload would 401.
		if code := upload(h, id, "sbom", token); code != http.StatusOK {
			t.Errorf("upload after download got %d, want 200 -- a read must not consume the write grant", code)
		}
	})

	t.Run("an upload does not grant a second download", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		if code := upload(h, id, "sbom", token); code != http.StatusOK {
			t.Fatalf("upload got %d, want 200", code)
		}
		if code := download(h, id, "sbom", token); code != http.StatusOK {
			t.Fatalf("download got %d, want 200", code)
		}
		if code := download(h, id, "sbom", token); code != http.StatusUnauthorized {
			t.Errorf("second download got %d, want 401 -- each direction is single-use", code)
		}
	})

	t.Run("single use", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		if code := download(h, id, "sbom", token); code != http.StatusOK {
			t.Fatalf("first download got %d, want 200", code)
		}
		if code := download(h, id, "sbom", token); code != http.StatusUnauthorized {
			t.Errorf("replayed download got %d, want 401", code)
		}
	})

	t.Run("wrong artifact is refused", func(t *testing.T) {
		h, store, _, token := newSetup(t)
		other, err := store.Create("example.com/other:1", artifact.TypeImage)
		if err != nil {
			t.Fatalf("seed second artifact: %v", err)
		}
		if code := download(h, other.ID, "sbom", token); code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401 -- a token is scoped to one artifact", code)
		}
	})

	t.Run("does not widen to other routes", func(t *testing.T) {
		h, _, id, token := newSetup(t)
		// The artifact itself, not a document under it. A scan token
		// must not be a read key for the whole API.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET artifact with a scan token got %d, want 401", rec.Code)
		}
		// And not the artifact list either.
		req = httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET artifact list with a scan token got %d, want 401", rec.Code)
		}
	})

	t.Run("garbage token is refused", func(t *testing.T) {
		h, _, id, _ := newSetup(t)
		if code := download(h, id, "sbom", "not-a-real-token"); code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", code)
		}
	})
}

// M-2's export endpoint. The annotator itself is covered in
// internal/artifact; these cover the HTTP contract around it.
func TestExportCycloneDX(t *testing.T) {
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,` +
		`"components":[{"type":"library","name":"busybox","purl":"pkg:apk/alpine/busybox@1.36.1-r20"}],` +
		`"vulnerabilities":[{"id":"CVE-2024-58251","ratings":[{"severity":"medium"}]}]}`)

	t.Run("overlays our state onto the stored document", func(t *testing.T) {
		h, store := newTestRouter(scanner.Registry{})
		a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
		doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/vnd.cyclonedx+json", sbom)

		// A suppression that exists only here -- the stored document
		// knows nothing about it.
		a.CVEFindings = []artifact.Finding{{
			ID: "CVE-2024-58251", Status: artifact.FindingStatusNotAffected,
			Justification: "vulnerable code is not in the execute path",
		}}
		if _, err := store.Update(a.ID, func(cur *artifact.Artifact) {
			cur.CVEFindings = a.CVEFindings
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}

		rec := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/export/cyclonedx", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "cyclonedx-vex.json") {
			t.Errorf("Content-Disposition = %q", cd)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "not_affected") || !strings.Contains(body, "execute path") {
			t.Errorf("the suppression did not reach the export: %s", body)
		}
		// The stored document must be untouched by an export of it.
		stored := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "", nil)
		if strings.Contains(stored.Body.String(), "not_affected") {
			t.Error("exporting mutated the stored document -- documents/sbom must keep returning what the scan stored")
		}
	})

	t.Run("no stored SBOM is a 409, not a 404", func(t *testing.T) {
		h, store := newTestRouter(scanner.Registry{})
		a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
		rec := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/export/cyclonedx", "", nil)
		// The artifact exists and the route is right; there is just
		// nothing to annotate yet.
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown artifact is a 404", func(t *testing.T) {
		h, _ := newTestRouter(scanner.Registry{})
		rec := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/does-not-exist/export/cyclonedx", "", nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestExportFindingsCSV(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	fixed := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	accepted := time.Now().Add(30 * 24 * time.Hour)
	if _, err := store.Update(a.ID, func(cur *artifact.Artifact) {
		cur.CVEFindings = []artifact.Finding{
			{ID: "CVE-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, EPSSScore: 0.42, KnownExploited: true},
			{ID: "CVE-2", Severity: "low", Source: "grype", Status: artifact.FindingStatusFixed, ResolvedAt: &fixed},
			{ID: "CVE-3", Severity: "critical", Source: "trivy", Status: artifact.FindingStatusOpen,
				AcceptedUntil: &accepted, AcceptedBy: "kirk", AcceptanceReason: "no upstream fix"},
		}
		// Every bucket, not just cve: a flat export is for sorting, and
		// malware is what somebody would sort to the top.
		cur.MalwareFindings = []artifact.Finding{
			{ID: "Eicar-Test-Signature", Severity: "critical", Source: "clamav", Status: artifact.FindingStatusOpen},
		}
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	t.Run("every bucket, one row per finding", func(t *testing.T) {
		rec := doRaw(t, h, http.MethodGet, "/api/v1/export/findings.csv", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Errorf("Content-Type = %q", ct)
		}
		rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("output is not valid CSV: %v", err)
		}
		if len(rows) != 5 { // header + 4 findings
			t.Fatalf("got %d rows (incl. header), want 5", len(rows))
		}
		// The bucket must be a COLUMN, or sorting malware to the top is
		// impossible and the export is cve-only in practice.
		header := rows[0]
		bucketCol := -1
		for i, h := range header {
			if h == "bucket" {
				bucketCol = i
			}
		}
		if bucketCol < 0 {
			t.Fatal("no bucket column")
		}
		buckets := map[string]bool{}
		for _, r := range rows[1:] {
			buckets[r[bucketCol]] = true
		}
		if !buckets["cve"] || !buckets["malware"] {
			t.Errorf("buckets present = %v, want both cve and malware", buckets)
		}
	})

	t.Run("active=true drops fixed and accepted", func(t *testing.T) {
		rec := doRaw(t, h, http.MethodGet, "/api/v1/export/findings.csv?active=true", "", nil)
		rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("not valid CSV: %v", err)
		}
		// CVE-1 and the malware one are active; CVE-2 is fixed and
		// CVE-3 has an in-force acceptance.
		if len(rows) != 3 {
			t.Fatalf("got %d rows (incl. header), want 3: %v", len(rows), rows)
		}
		body := rec.Body.String()
		if strings.Contains(body, "CVE-2") || strings.Contains(body, "CVE-3") {
			t.Errorf("active=true returned a fixed or accepted finding:\n%s", body)
		}
	})

	t.Run("the judgements that live only here survive the export", func(t *testing.T) {
		rec := doRaw(t, h, http.MethodGet, "/api/v1/export/findings.csv", "", nil)
		body := rec.Body.String()
		for _, want := range []string{"kirk", "no upstream fix", "0.42", "true"} {
			if !strings.Contains(body, want) {
				t.Errorf("export is missing %q -- that is data no scanner report carries", want)
			}
		}
	})
}

// Spreadsheet formula injection. This export exists to be opened in
// Excel/LibreOffice/Sheets, which evaluate a cell beginning with
// = + - @ tab or CR as a formula -- and Ref, Title and Justification are
// all caller-controlled (POST /artifacts, POST /findings, an uploaded
// VEX document respectively).
func TestExportFindingsCSV_NeutralisesFormulaInjection(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	// A ref a caller could genuinely register.
	a := mustCreate(t, store, `=cmd|'/c calc'!A1`, artifact.TypeImage)
	if _, err := store.Update(a.ID, func(cur *artifact.Artifact) {
		cur.CVEFindings = []artifact.Finding{{
			ID:            "CVE-1",
			Severity:      "high",
			Source:        "trivy",
			Title:         `@SUM(1+9)*cmd|' /C calc'!A0`,
			Status:        artifact.FindingStatusNotAffected,
			Justification: `+HYPERLINK("http://evil","click")`,
		}}
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	rec := doRaw(t, h, http.MethodGet, "/api/v1/export/findings.csv", "", nil)
	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want header + 1", len(rows))
	}

	for i, cell := range rows[1] {
		if cell == "" {
			continue
		}
		switch cell[0] {
		case '=', '+', '-', '@', '\t', '\r':
			t.Errorf("column %d (%q) begins with a formula character: %q",
				i, rows[0][i], cell)
		}
	}

	// Neutralised, not destroyed: the original text must still be
	// readable by a human, just not by the formula engine.
	body := rec.Body.String()
	for _, want := range []string{"calc", "HYPERLINK", "SUM"} {
		if !strings.Contains(body, want) {
			t.Errorf("the payload text %q was dropped rather than neutralised", want)
		}
	}
}
