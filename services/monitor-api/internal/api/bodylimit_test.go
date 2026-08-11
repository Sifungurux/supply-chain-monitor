package api_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// postRaw sends a body without going through json.Marshal, so a test
// can send something far larger than any struct it would build.
func postRaw(t *testing.T, h http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestWritePaths_RejectOversizedBodies covers every JSON write endpoint.
// Each decodes attacker-controllable input into memory, and the pod runs
// with a 256Mi limit -- an unbounded POST is an OOM, not a theoretical
// concern. The per-entry caps that already existed (maxBulkArtifacts,
// the findings validation) are checked only AFTER a full decode, so
// they never bounded this.
func TestWritePaths_RejectOversizedBodies(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	// Sized per endpoint: the ceilings differ by two orders of magnitude
	// (64KiB for a small JSON write, 64MiB for a document upload), so
	// one shared "huge" body would have been comfortably UNDER the
	// document limit and passed that case for the wrong reason -- which
	// is exactly what the first run of this test did.
	for _, tc := range []struct {
		name  string
		path  string
		bytes int
	}{
		{"createArtifact", "/api/v1/artifacts", 64 << 10},
		{"bulkCreateArtifacts", "/api/v1/artifacts/bulk", 4 << 20},
		{"submitFindings", "/api/v1/artifacts/" + created.ID + "/findings", 16 << 20},
		{"updateStage", "/api/v1/artifacts/" + created.ID + "/stage", 64 << 10},
		{"updateMaintainer", "/api/v1/artifacts/" + created.ID + "/maintainer", 64 << 10},
		{"uploadDocument", "/api/v1/artifacts/" + created.ID + "/documents/sbom", 64 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Just past this endpoint's own ceiling.
			body := []byte(`{"ref":"` + strings.Repeat("a", tc.bytes+1024) + `","type":"image"}`)
			rec := postRaw(t, h, tc.path, body)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413 -- an oversized body must be refused, not decoded", rec.Code)
			}
		})
	}
}

// TestWritePaths_NormalBodiesStillWork is the other half: the ceilings
// must be nowhere near what a real caller sends. Without this, a limit
// accidentally set to a few bytes would still pass the test above.
func TestWritePaths_NormalBodiesStillWork(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "busybox:1.36", "type": "image"}); rec.Code != http.StatusCreated {
		t.Fatalf("createArtifact = %d, want 201", rec.Code)
	}

	// A full-size bulk request: maxBulkArtifacts entries, which is the
	// largest legitimate call this endpoint accepts.
	entries := make([]map[string]string, 0, 500)
	for i := 0; i < 500; i++ {
		entries = append(entries, map[string]string{"ref": fmt.Sprintf("registry.example.com/team/some-fairly-long-image-name-%d:1.0.0", i), "type": "image"})
	}
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{"artifacts": entries}); rec.Code != http.StatusCreated {
		t.Fatalf("bulk with 500 entries = %d, want 201 -- the ceiling must not reject a legitimate maximum request", rec.Code)
	}

	// A large but plausible findings submission.
	findings := make([]map[string]string, 0, 5000)
	for i := 0; i < 5000; i++ {
		findings = append(findings, map[string]string{
			"id": fmt.Sprintf("CVE-2024-%05d", i), "severity": "HIGH",
			"title": "some package 1.2.3-4 is affected by a vulnerability", "source": "trivy",
		})
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings",
		map[string]any{"bucket": "cve", "findings": findings})
	if rec.Code != http.StatusOK {
		t.Fatalf("submitFindings with 5000 findings = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/stage", map[string]string{"stage": "build"}); rec.Code != http.StatusOK {
		t.Fatalf("updateStage = %d, want 200", rec.Code)
	}
	// team/email, not the maintainer_team/maintainer_email that
	// REGISTRATION uses -- see updateMaintainerRequest.
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/maintainer",
		map[string]string{"team": "platform", "email": "platform@example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("updateMaintainer = %d, want 200", rec.Code)
	}
}

// TestWritePaths_MalformedBodyIsStill400 -- the 413 must not swallow
// the ordinary "your JSON is broken" case, or a caller with a genuine
// syntax error gets told to send less data.
func TestWritePaths_MalformedBodyIsStill400(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	rec := postRaw(t, h, "/api/v1/artifacts", []byte(`{"ref": "alpine:3.19", "type":`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed JSON", rec.Code)
	}
}
