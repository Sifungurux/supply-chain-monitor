package api

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// uploadVEX ingests an OpenVEX or CycloneDX-VEX document for one
// artifact: "a scanner keeps reporting CVE-2024-1234 against this
// image, and we have assessed that it does not apply here."
//
// Stored the same way an SBOM/SARIF document is (Store.SaveDocument,
// kind "vex" -- see documents.go for the body-limit + document-store
// pattern this follows), and then immediately applied to the artifact's
// existing findings rather than waiting for the next scan: the whole
// reason to upload one is to stop looking at a finding you have already
// triaged, and "it will take effect next time somebody scans" is not
// that. Applying it is a merge with nothing reported and detectFixed
// false, which is precisely "change nothing except what VEX says" (see
// MergeFindings).
//
// Deliberately its own endpoint rather than another kind on
// POST /documents/{kind}: that one stores bytes, this one has to parse
// and act on them, and a document that silently stored but suppressed
// nothing would be the worst of both.
//
// The document is parsed BEFORE it is stored, so an unparseable upload
// is a 400 that leaves any previously-applied document in place, rather
// than overwriting a working one with something that does nothing.
func (h *handler) uploadVEX(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	limitBody(w, r, maxVEXBytes)
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeBodyError(w, err, "failed to read request body (connection dropped): "+err.Error())
		return
	}
	if len(content) == 0 {
		writeError(w, http.StatusBadRequest, "VEX document body is empty")
		return
	}

	statements, err := scanner.ParseVEX(content)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	if err := h.store.SaveDocument(id, artifact.DocumentKindVEX, contentType, content); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	now := time.Now().UTC()
	vex := artifact.VEXByID(statements)
	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		// Every bucket, not just CVEs: a SARIF-imported finding or a
		// pluggable scanner's result can carry a vulnerability ID a VEX
		// document speaks about just as legitimately as trivy's can, and
		// a statement about an ID that isn't in a bucket costs a map
		// lookup that misses.
		//
		// detectFixed is false on all five: nothing was reported this
		// round, and this call must never be read as "a scan found
		// nothing, so everything is fixed."
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, nil, now, false, vex)
		art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, nil, now, false, vex)
		art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, nil, now, false, vex)
		art.SecretFindings = artifact.MergeFindings(art.SecretFindings, nil, now, false, vex)
		art.OtherFindings = artifact.MergeFindings(art.OtherFindings, nil, now, false, vex)
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	slog.Info("VEX document applied", "artifact_id", id, "count", len(statements))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "applied",
		// How many statements were understood -- the one number that
		// tells an operator whether the document they uploaded actually
		// said anything this service could read. Zero is a successful
		// upload of a document that changed nothing, which is worth
		// being able to see without diffing the artifact.
		"statements": len(statements),
		"artifact":   updated,
	})
}

// vexFor loads the artifact's stored VEX document, if it has one, ready
// to pass to MergeFindings. Best-effort in the same spirit as
// resolveDigest: nil means "no VEX overlay for this merge" -- no
// document uploaded (much the most common case), or one that could not
// be read or parsed.
//
// Failing to nil is safe here specifically because suppression persists
// on the findings themselves (see MergeFindings): a scan that could not
// read the document does not un-suppress anything, it just can't apply
// a statement to a finding seen for the first time this round.
func (h *handler) vexFor(id string) map[string]artifact.VEXStatement {
	doc, err := h.store.GetDocument(id, artifact.DocumentKindVEX)
	if err != nil {
		slog.Warn("could not read the stored VEX document (continuing without it)", "artifact_id", id, "err", err)
		return nil
	}
	if doc == nil {
		return nil
	}
	statements, err := scanner.ParseVEX(doc.Content)
	if err != nil {
		// Only reachable if a document that parsed at upload time no
		// longer does -- worth a log line rather than a silent skip.
		slog.Warn("the stored VEX document no longer parses (continuing without it)", "artifact_id", id, "err", err)
		return nil
	}
	return artifact.VEXByID(statements)
}
