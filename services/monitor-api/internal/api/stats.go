package api

import (
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
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
// statsResponse is artifact.Stats plus the two scan-freshness fields.
//
// They travel here rather than through a second config path to the
// dashboard because the dashboard already fetches /stats on every poll:
// it gets the threshold and the fleet count in a request it was making
// anyway, and there is one place the number is defined instead of a
// chart value rendered into both the API's ConfigMap and the
// dashboard's env.js, which could then disagree.
type statsResponse struct {
	artifact.Stats
	// StaleAfterDays is the configured freshness threshold. 0 means
	// staleness is switched off entirely, and the dashboard renders no
	// warning at all rather than treating every artifact as stale.
	StaleAfterDays int `json:"stale_after_days"`
	// Stale is how many artifacts were last scanned longer ago than
	// that. NEVER-scanned artifacts are excluded -- see
	// Store.CountStaleScans, and note the dashboard applies the same
	// rule per row so the count and the badges cannot disagree.
	Stale int `json:"stale"`
}

func (h *handler) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := statsResponse{Stats: stats, StaleAfterDays: h.staleAfterDays}
	if h.staleAfterDays > 0 {
		stale, err := h.store.CountStaleScans(h.staleCutoff())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out.Stale = stale
	}
	writeJSON(w, http.StatusOK, out)
}

// staleCutoff is the instant an artifact's last scan must be after to
// count as fresh.
func (h *handler) staleCutoff() time.Time {
	return time.Now().UTC().AddDate(0, 0, -h.staleAfterDays)
}
