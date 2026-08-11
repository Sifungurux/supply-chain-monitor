package api

import (
	"encoding/json"
	"net/http"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

type updateMaintainerRequest struct {
	Team  string `json:"team"`
	Email string `json:"email"`
}

// updateMaintainer sets (or corrects) an artifact's maintainer info
// after registration -- the Register form can't always know a team/
// contact up front, and ownership changes over an artifact's lifetime
// regardless. Unlike createArtifact/bulkCreateArtifacts, both fields
// are required here: there's no "leave it as it was" partial-update
// semantics for this endpoint, only "set it to this pair" -- clearing
// it back to empty is the one case not supported today (not needed by
// the dashboard, which only ever offers Save with both fields filled).
func (h *handler) updateMaintainer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	limitBody(w, r, maxSmallJSONBytes)
	var req updateMaintainerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, "invalid request body")
		return
	}
	if req.Team == "" || req.Email == "" {
		writeError(w, http.StatusBadRequest, "team and email are both required")
		return
	}

	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		art.MaintainerTeam = req.Team
		art.MaintainerEmail = req.Email
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
