package api

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
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

	limitBody(w, r, maxDocumentUploadBytes)
	content, err := io.ReadAll(r.Body)
	if err != nil {
		// 413 for an oversized document, 400 for a dropped connection --
		// this used to answer 400 for both, telling a caller that had
		// simply sent too much that its request was malformed.
		writeBodyError(w, err, "failed to read request body (connection dropped): "+err.Error())
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
	if kind == artifact.DocumentKindSBOM {
		h.indexSBOMComponents(id, content)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "id": id, "kind": kind})
}

// storeGeneratedDocument persists a document this process derived
// itself (an in-process image scan -- see scan.go's captureDocuments)
// through exactly the steps an uploaded one goes through: store it,
// and if it is an SBOM, index its components, which in turn snapshots
// them and evaluates the license denylist.
//
// Shared with uploadDocument above deliberately. A generated SBOM that
// stored but never indexed would leave the component search, the diff
// endpoint and the license findings silently empty for every artifact
// scanned in-process -- which is the exact bug this whole change
// exists to fix, so reintroducing it via a parallel path would be
// unfortunate.
//
// Errors are logged, never returned: the caller has already persisted
// the scan result and must not fail it over a document.
func (h *handler) storeGeneratedDocument(id, kind, contentType string, content []byte) {
	if err := h.store.SaveDocument(id, kind, contentType, content); err != nil {
		slog.Error("could not store a document generated from the scan report",
			"artifact_id", id, "kind", kind, "err", err)
		return
	}
	if kind == artifact.DocumentKindSBOM {
		h.indexSBOMComponents(id, content)
	}
	slog.Info("stored a document generated from the scan report",
		"artifact_id", id, "kind", kind, "bytes", len(content))
}

// indexSBOMComponents parses an uploaded SBOM into the normalized
// components table, so "which artifacts contain this package" is
// answerable (see listByComponent in components.go) instead of the
// inventory staying locked inside a blob.
//
// Best-effort, and deliberately AFTER the document is stored, never
// before: this endpoint's actual job is to be the scan-worker's return
// path for a document too large for the findings channel, and
// scanner.UploadDocument treats any non-200 as an error that lands in
// the artifact's LastScanErrors. A malformed or unfamiliar SBOM would
// then read as a failed scan, and the document itself -- which is
// perfectly fine, and downloadable -- would be discarded with it. So a
// parse failure is logged and nothing else, the same convention
// resolveDigest already uses for its own best-effort work.
//
// (This is the opposite ordering from uploadVEX, which parses BEFORE
// storing. There, the parse IS the point: a VEX document that stored
// successfully but suppressed nothing would be worse than a rejection.)
func (h *handler) indexSBOMComponents(id string, content []byte) {
	components, err := scanner.ParseSBOMComponents(content)
	if err != nil {
		slog.Warn("could not parse the uploaded SBOM into components (the document itself is stored and downloadable)", "artifact_id", id, "err", err)
		return
	}
	if err := h.store.SaveComponents(id, components); err != nil {
		slog.Error("could not store the component inventory", "artifact_id", id, "err", err)
		return
	}
	slog.Info("indexed components from the uploaded SBOM", "artifact_id", id, "count", len(components))
	h.applyLicenseDenylist(id, components)
}

// applyLicenseDenylist records a finding per component carrying a
// denied license, and resolves the ones that no longer apply.
//
// Merged as a PARTITION of the "other" bucket, not against the whole of
// it. The bucket has two independent producers -- SARIF/pluggable
// scanners during a scan, and this during an SBOM index -- and
// MergeFindings treats `reported` as a complete picture of whatever it
// is merged against. Merging this against the whole bucket would mark
// every SARIF finding fixed, because the license evaluator reports
// none of them. See artifact.MergePartition, and scan.go for the
// complementary half.
//
// detectFixed is true: this inventory IS the complete current answer
// for license findings, so a package that is gone, or whose license is
// no longer denied, is genuinely resolved and should say so.
//
// Best-effort like the indexing it follows -- a failure here is logged
// and never turned into a failed upload or a failed scan.
func (h *handler) applyLicenseDenylist(id string, components []artifact.Component) {
	if !h.licenseDenylist.Enabled() {
		return
	}
	findings := h.licenseDenylist.Findings(components)
	now := time.Now().UTC()
	vex := h.vexFor(id)

	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		art.OtherFindings = artifact.MergePartition(
			art.OtherFindings, findings,
			func(f artifact.Finding) bool { return f.Source == artifact.LicenseFindingSource },
			now, true, vex)
	})
	if err != nil {
		slog.Error("could not record license findings", "artifact_id", id, "err", err)
		return
	}
	slog.Info("evaluated component licenses against the denylist",
		"artifact_id", id, "count", len(findings), "components", len(components),
		"other_findings", len(updated.OtherFindings))
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
