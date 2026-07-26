package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

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
// rateLimitRPS/rateLimitBurst configure the per-key rate limiter (see
// withRateLimit below). rateLimitRPS <= 0 disables rate limiting
// entirely -- a nonsensical zero-or-negative rate reads more naturally
// as "off" than as a real limit, so callers that don't care about this
// (like most existing tests) can just pass 0 and get today's
// unthrottled behavior back.
// digestResolver enables best-effort duplicate-registration detection
// (see handlers.go's resolveDigest) -- pass nil to disable it entirely
// (every registration behaves exactly as it did before this existed).
// fetchPlainHTTP mirrors the same flag RegistryFetcher is already
// constructed with (FETCH_PLAIN_HTTP in main.go) -- see resolveDigest's
// comment for why it only ever applies to non-image artifact types.
// scanTimeout is the shared per-scan budget scanArtifact gives every
// scanner registered for one artifact type (see handler.scanTimeout's
// own comment) -- pass 0 to get the 5-minute default (what every caller
// got before this was configurable).
func NewRouter(store artifact.Store, tracker *pipeline.Tracker, scanners scanner.Registry, apiKey string, rateLimitRPS float64, rateLimitBurst float64, digestResolver scanner.DigestResolver, fetchPlainHTTP bool, scanTimeout time.Duration) http.Handler {
	h := &handler{store: store, tracker: tracker, scanners: scanners, digestResolver: digestResolver, fetchPlainHTTP: fetchPlainHTTP, scanTimeout: scanTimeout}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /api/v1/pipeline/stages", h.listStages)
	mux.HandleFunc("POST /api/v1/artifacts", h.createArtifact)
	mux.HandleFunc("POST /api/v1/artifacts/bulk", h.bulkCreateArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts", h.listArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", h.getArtifact)
	mux.HandleFunc("DELETE /api/v1/artifacts/{id}", h.deleteArtifact)
	mux.HandleFunc("GET /api/v1/findings/{findingID}/artifacts", h.findByFindingID)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/scan", h.scanArtifact)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/stage", h.updateStage)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/findings", h.submitFindings)

	var top http.Handler = mux
	if rateLimitRPS > 0 {
		// Sits between withAuth and mux (wired below), not outside
		// withAuth -- see withRateLimit's own comment for why.
		top = withRateLimit(top, newRateLimiter(rateLimitRPS, rateLimitBurst))
	}

	// withCORS must wrap withAuth, not the other way around: a CORS
	// preflight OPTIONS request never carries the Authorization header
	// (browsers don't attach custom headers to preflight requests at
	// all), so it has to be short-circuited before auth ever runs, or
	// every cross-origin call from the dashboard would fail preflight
	// with a 401 before the browser even attempts the real request.
	return withCORS(withAuth(top, apiKey))
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withRateLimit throttles requests per API key using limiter (a token
// bucket -- see ratelimit.go), so one caller (buggy, compromised, or
// just a runaway retry loop) can't monopolize the scan pipeline or
// database at every other caller's expense. Today that's effectively a
// single global bucket, since every request shares the one apiKey
// withAuth checks (see docs/architecture.md's Roadmap, "AuthN/Z is a
// single shared key, not per-client identity") -- but keying by the
// presented Authorization header rather than e.g. remote address means
// this keeps working correctly, per-caller, the moment that changes,
// with no changes needed here.
//
// This is wired in NewRouter *inside* withAuth (i.e. only requests that
// already passed auth ever reach it), deliberately: keying by an
// unauthenticated, attacker-controlled header value would let anyone
// grow the limiter's internal bucket map without bound just by sending
// requests with a different bogus key each time. Requiring auth first
// means the map can have at most as many entries as there are valid
// keys.
func withRateLimit(next http.Handler, limiter *rateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /healthz is normally unreachable here anyway (withAuth returns
		// before calling this handler for that path), but it's cheap and
		// clearer to also exempt it explicitly, so a liveness/readiness
		// probe can never be the thing that trips this limiter even if
		// the wiring above ever changes.
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		if !limiter.allow(r.Header.Get("Authorization")) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded, slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}
