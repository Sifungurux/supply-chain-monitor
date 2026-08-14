package api

import (
	"net/http"
)

// getStats answers the dashboard's summary cards and pipeline strip in
// one aggregate call -- see artifact.Stats for what each map means.
//
// This exists because those numbers are fleet-wide and the dashboard
// only ever holds one page of artifacts (listArtifacts has been
// paginated since the artifact count outgrew a single response). Until
// this endpoint, "With CVEs" was computed from the artifacts on the
// current page, so a store with 800 artifacts and a page size of 50
// showed a card that read like a fleet number and meant "of these 50" --
// wrong in a direction that understates risk, and silently wrong, since
// nothing about the card said which population it was counting.
//
// No parameters, no filters: it's deliberately the one number set for
// the whole store. A stats call that took the same status/type filters
// as the list would answer a different question ("how much of this
// filtered view...") that the caller can already compute from the
// filtered list's own total.
//
// r.Context() is passed straight through, so a dashboard tab closed
// mid-poll cancels the two aggregate queries rather than leaving
// Postgres counting for a client that hung up.
func (h *handler) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
