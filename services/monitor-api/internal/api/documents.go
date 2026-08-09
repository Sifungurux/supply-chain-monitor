package api

import (
	"io"
	"net/http"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// maxDocumentUploadBytes bounds a single SBOM/SARIF document upload --
// the only endpoint in this API that accepts raw, arbitrary-size bytes
// rather than a small JSON payload. 64MiB comfortably covers a
// real-world image's CycloneDX SBOM or SARIF report (commonly 10-20MB,
// see scanner.GenerateImageDocuments' comment) with headroom, while
// still bounding this new boundary rather than leaving it unbounded.
const maxDocumentUploadBytes = 64 << 20 // 64MiB

func validDocumentKind(kind string) bool {
	return kind == artifact.DocumentKindSBOM || kind == artifact.DocumentKindSARIF
}

// uploadDocument receives a generated SBOM/SARIF document -- today,
// only ever called by a scan-worker Job from inside
// captureImageDocuments (main.go), the return path for a document too
// large for the existing pod-logs/WorkerResult channel used for
// findings (see scanner.UploadDocument's comment). Authenticated the
// same way as every other request (withAuth wraps the whole mux) --
// no separate credential scheme for this internal caller.
func (h *handler) uploadDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	kind := r.PathValue("kind")
	if !validDocumentKind(kind) {
		writeError(w, http.StatusBadRequest, `kind must be "sbom" or "sarif"`)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentUploadBytes)
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body (too large, or connection dropped): "+err.Error())
		return
	}
	if len(content) == 0 {
		writeError(w, http.StatusBadRequest, "document body is empty")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if err := h.store.SaveDocument(id, kind, contentType, content); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "id": id, "kind": kind})
}

// downloadDocument returns a captured document's raw bytes -- the
// dashboard's download buttons (and any other API consumer) read a
// document here. 404 when none exists yet, the same "not found is the
// expected, common case" convention Store.GetDocument's own comment
// documents (e.g. before the first scan runs, or best-effort generation
// failed -- see GenerateImageDocuments).
func (h *handler) downloadDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	kind := r.PathValue("kind")
	if !validDocumentKind(kind) {
		writeError(w, http.StatusBadRequest, `kind must be "sbom" or "sarif"`)
		return
	}

	doc, err := h.store.GetDocument(id, kind)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if doc == nil {
		writeError(w, http.StatusNotFound, "no "+kind+" document has been captured for this artifact yet")
		return
	}

	ext := ".json"
	if kind == artifact.DocumentKindSARIF {
		ext = ".sarif"
	}

	w.Header().Set("Content-Type", doc.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+"-"+kind+ext+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc.Content)
}
