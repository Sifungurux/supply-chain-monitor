package api_test

import (
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
