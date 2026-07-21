package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

type handler struct {
	store    artifact.Store
	tracker  *pipeline.Tracker
	scanners scanner.Registry
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) listStages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"stages": h.tracker.Stages()})
}

type createArtifactRequest struct {
	Ref  string `json:"ref"`
	Type string `json:"type"`
}

func (h *handler) createArtifact(w http.ResponseWriter, r *http.Request) {
	var req createArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}

	t := artifact.Type(req.Type)
	if !t.Valid() {
		writeError(w, http.StatusBadRequest, "type must be one of image, file, sbom, sarif")
		return
	}

	a, err := h.store.Create(req.Ref, t)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *handler) listArtifacts(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *handler) getArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// findByFindingID answers "every artifact still affected by finding
// X" -- the query internal/artifact's normalized findings table exists
// to make possible (see docs/architecture.md, "Normalizing findings
// and stage history into their own tables"). Returns an empty list
// (not a 404) when nothing matches, since "no artifacts affected" is a
// perfectly valid, non-error answer -- unlike getArtifact, this isn't
// asking about one specific ID that either exists or doesn't.
func (h *handler) findByFindingID(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if findingID == "" {
		writeError(w, http.StatusBadRequest, "finding id is required")
		return
	}

	list, err := h.store.FindByFindingID(findingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *handler) scanArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	scanners, ok := h.scanners.For(a.Type)
	if !ok || len(scanners) == 0 {
		writeError(w, http.StatusNotImplemented, "no scanner registered for type "+string(a.Type))
		return
	}

	_, _ = h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = artifact.StatusScanning
	})

	// Deliberately NOT derived from r.Context(): a scan can legitimately
	// run long (trivy's first-run vulnerability DB download alone can
	// take a couple of minutes), and net/http cancels r.Context() the
	// moment the client connection goes away for any reason -- a closed
	// tab, a network hiccup, a proxy's idle timeout. Tying the scan to
	// that meant an interrupted browser connection would SIGKILL
	// whatever scanner was mid-run (surfacing as "signal: killed") and
	// instantly fail every scanner after it in the loop ("context
	// canceled"), even though nothing about the scan itself was wrong.
	// Using context.Background() here means the scan runs to completion
	// and updates the store regardless of what the original HTTP client
	// does; the dashboard's own polling picks up the result afterward
	// either way.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Every scanner registered for this artifact type runs; findings are
	// sorted into CVE/malware/other buckets by Finding.Source rather
	// than by artifact type, since a single type (image) can produce
	// more than one kind. "sarif" is its own bucket (OtherFindings)
	// rather than folded into CVEFindings -- SARIF covers SAST issues,
	// secrets, IaC misconfigurations, and more, not just CVEs, so
	// calling it a CVE finding would mislabel it. Everything that isn't
	// explicitly clamav or sarif defaults to the CVE bucket, which
	// today just means "trivy" but keeps this open to future
	// CVE-flavored scanners without another switch-case edit.
	var cveFindings, malwareFindings, otherFindings []artifact.Finding
	var scanErrors []string

	for _, s := range scanners {
		findings, scanErr := s.Scan(ctx, a.Ref)
		if scanErr != nil {
			scanErrors = append(scanErrors, scanErr.Error())
		}
		for _, f := range findings {
			switch f.Source {
			case "clamav":
				malwareFindings = append(malwareFindings, f)
			case "sarif":
				otherFindings = append(otherFindings, f)
			default:
				cveFindings = append(cveFindings, f)
			}
		}
	}

	status := artifact.StatusScanned
	if len(scanErrors) == len(scanners) {
		status = artifact.StatusFailed
	}

	// Note: this replaces prior findings wholesale, including with
	// empty results if every scanner failed this round -- a known v1
	// limitation (see docs/architecture.md).
	updated, updErr := h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = status
		art.CVEFindings = cveFindings
		art.MalwareFindings = malwareFindings
		art.OtherFindings = otherFindings
		art.LastScanErrors = scanErrors
	})
	if updErr != nil {
		writeError(w, http.StatusInternalServerError, updErr.Error())
		return
	}

	if status == artifact.StatusFailed {
		writeJSON(w, http.StatusBadGateway, updated)
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

type updateStageRequest struct {
	Stage string `json:"stage"`
	Note  string `json:"note,omitempty"`
}

func (h *handler) updateStage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req updateStageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.tracker.Validate(req.Stage); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		art.CurrentStage = req.Stage
		art.StageHistory = append(art.StageHistory, artifact.StageEvent{
			Stage:     req.Stage,
			Timestamp: time.Now().UTC(),
			Note:      req.Note,
		})
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
