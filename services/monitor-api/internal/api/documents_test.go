package api_test

import (
	"net/http"
	"testing"

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
