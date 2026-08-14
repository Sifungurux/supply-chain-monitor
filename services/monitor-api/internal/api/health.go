package api

import (
	"context"
	"net/http"
	"time"
)

// readyProbeTimeout bounds the store check readyz makes. Short on
// purpose: this runs on every readiness poll (every few seconds, per
// pod), and the question is "can this process serve a request right
// now", which a database taking longer than this to answer has already
// failed in practice. Well under the probe's own timeoutSeconds, so the
// handler decides the answer rather than the kubelet timing out on a
// request still in flight.
const readyProbeTimeout = 2 * time.Second

// healthz is LIVENESS: is this process alive and serving HTTP. It
// deliberately checks nothing else -- in particular, not the database.
//
// That looks like an omission and is the opposite. A liveness failure
// makes the kubelet kill the container, so wiring a database check into
// this endpoint means an outage of Postgres restarts every monitor-api
// pod, repeatedly, for as long as it lasts -- turning a recoverable
// dependency outage into a crashloop that cannot recover on its own,
// and destroying the in-flight state and logs that would explain it.
// The distinction is the whole reason readyz below exists separately:
// readiness takes a pod out of the Service, liveness destroys it.
func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz is READINESS: can this process actually serve a request right
// now, which for this service means "is Postgres reachable". A pod
// failing this is removed from the Service's endpoints and stops
// receiving traffic, then rejoins on its own when the check passes
// again -- no restart, nothing lost.
//
// This is the gap it closes. Both probes used to point at healthz,
// which returns "ok" unconditionally, so a database that went away
// AFTER startup left every pod Ready and cheerfully serving 500s from
// every endpoint that touches the store. Startup was already covered
// (main.go blocks on connectStoreWithRetry before it ever opens the
// listener), so the hole was steady-state only, which is exactly the
// case nobody sees until it happens.
//
// h.ready == nil means "no backing store to check" and answers ready.
// That is the honest answer for MemStore, and it keeps every existing
// test's router -- none of which sets Config.Ready -- reporting ready
// rather than silently 503ing.
func (h *handler) readyz(w http.ResponseWriter, r *http.Request) {
	if h.ready == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), readyProbeTimeout)
	defer cancel()
	if err := h.ready(ctx); err != nil {
		// 503, not 500: this says "not right now, ask again", which is
		// what a readiness probe is asking and what the kubelet retries.
		// The error text goes in the body for whoever is reading
		// `kubectl describe pod`, and nowhere else -- a probe response
		// is not a request a client made.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
