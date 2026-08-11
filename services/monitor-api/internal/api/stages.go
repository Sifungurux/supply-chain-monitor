package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

func (h *handler) listStages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"stages": h.tracker.Stages()})
}

type updateStageRequest struct {
	Stage string `json:"stage"`
	Note  string `json:"note,omitempty"`
}

func (h *handler) updateStage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	limitBody(w, r, maxSmallJSONBytes)
	var req updateStageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, "invalid request body")
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
