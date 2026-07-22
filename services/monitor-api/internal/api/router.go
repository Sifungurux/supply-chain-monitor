package api

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// NewRouter wires up the v1 REST API. Uses Go 1.22's stdlib ServeMux
// method+wildcard routing, so no external router dependency is needed.
//
// apiKey is required (main.go fails to start rather than run with it
// empty -- see docs/architecture.md, "Adding API authentication") --
// every request must carry it as `Authorization: Bearer <apiKey>`,
// except /healthz (liveness/readiness probes shouldn't need
// credentials) and CORS preflight OPTIONS requests (browsers never
// attach custom headers to those).
func NewRouter(store artifact.Store, tracker *pipeline.Tracker, scanners scanner.Registry, apiKey string) http.Handler {
	h := &handler{store: store, tracker: tracker, scanners: scanners}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /api/v1/pipeline/stages", h.listStages)
	mux.HandleFunc("POST /api/v1/artifacts", h.createArtifact)
	mux.HandleFunc("GET /api/v1/artifacts", h.listArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", h.getArtifact)
	mux.HandleFunc("GET /api/v1/findings/{findingID}/artifacts", h.findByFindingID)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/scan", h.scanArtifact)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/stage", h.updateStage)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/findings", h.submitFindings)

	// withCORS must wrap withAuth, not the other way around: a CORS
	// preflight OPTIONS request never carries the Authorization header
	// (browsers don't attach custom headers to preflight requests at
	// all), so it has to be short-circuited before auth ever runs, or
	// every cross-origin call from the dashboard would fail preflight
	// with a 401 before the browser even attempts the real request.
	return withCORS(withAuth(mux, apiKey))
}

// withAuth requires `Authorization: Bearer <apiKey>` on every request
// except /healthz. Uses crypto/subtle.ConstantTimeCompare rather than
// == specifically to avoid a timing side-channel that could let an
// attacker guess the key one byte at a time -- overkill for a
// single-shared-key scheme against most threat models, but it's a
// one-line difference from a plain string comparison, so there's no
// real reason not to.
func withAuth(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		validLength := len(got) == len(prefix)+len(apiKey)
		hasPrefix := strings.HasPrefix(got, prefix)
		match := validLength && hasPrefix &&
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(apiKey)) == 1

		if !match {
			w.Header().Set("WWW-Authenticate", `Bearer realm="supply-chain-monitor"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withCORS lets the dashboard -- served from a different origin/port
// (its own nginx Deployment) -- call this API directly from the
// browser. Wide open origin (*) rather than an allowlist: with real
// auth now in place (withAuth above), the API key itself is what
// actually gates access, not the browser's Origin header -- an
// allowlisted CORS origin would be security theater on top of that,
// not a second real layer. Access-Control-Allow-Headers includes
// Authorization specifically so the browser is allowed to send the
// header withAuth requires.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
