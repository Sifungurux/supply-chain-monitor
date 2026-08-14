package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// Config is everything NewRouter needs. It replaces what had grown into
// a thirteen-parameter positional signature -- the consolidation that
// signature's own comment asked for at the next knob, done when that
// knob (Ready, below) arrived.
//
// Every field's zero value is the behavior this service had before that
// field existed, which is what makes `NewRouter(Config{Store: s,
// Tracker: t, APIKey: k})` a valid call: a test that doesn't care about
// rate limiting, dedup, notifications or quotas simply doesn't mention
// them, instead of passing a row of zeros and nils positionally.
type Config struct {
	Store    artifact.Store
	Tracker  *pipeline.Tracker
	Scanners scanner.Registry
	// APIKey is required (main.go fails to start rather than run with it
	// empty -- see docs/architecture.md, "Adding API authentication") --
	// every request must carry it as `Authorization: Bearer <apiKey>`,
	// except the unauthenticated routes listed in withAuth below and
	// CORS preflight OPTIONS requests (browsers never attach custom
	// headers to those).
	APIKey string
	// RateLimitRPS/RateLimitBurst configure the per-key rate limiter (see
	// withRateLimit below). RateLimitRPS <= 0 disables rate limiting
	// entirely -- a nonsensical zero-or-negative rate reads more
	// naturally as "off" than as a real limit, so callers that don't care
	// about this (like most tests) leave it unset and get unthrottled
	// behavior.
	RateLimitRPS   float64
	RateLimitBurst float64
	// DigestResolver enables best-effort duplicate-registration detection
	// (see handler.go's resolveDigest) -- nil disables it entirely (every
	// registration behaves exactly as it did before this existed).
	DigestResolver scanner.DigestResolver
	// FetchPlainHTTP mirrors the same flag RegistryFetcher is already
	// constructed with (FETCH_PLAIN_HTTP in main.go) -- see resolveDigest's
	// comment for why it only ever applies to non-image artifact types.
	FetchPlainHTTP bool
	// ScanTimeout is the shared per-scan budget scanArtifact gives every
	// scanner registered for one artifact type (see handler.scanTimeout's
	// own comment) -- zero gets the 5-minute default.
	ScanTimeout time.Duration
	// RequireDigest is a deployment-wide policy (monitorApi.requireDigest /
	// REQUIRE_DIGEST): false preserves today's behavior exactly (a
	// request's own expected_digest is optional, checked only if provided,
	// and registration is refused outright on a mismatch). true makes
	// expected_digest a required field on every registration, and turns a
	// mismatch (or an unresolvable ref) into Artifact.Unsafe = true instead
	// of a rejection -- see createArtifact/bulkCreateArtifacts and
	// Artifact.Unsafe's own comment for why this is a mark, not a block.
	RequireDigest bool
	// ScanLimits caps concurrent scanning -- the zero value is unlimited.
	ScanLimits ScanLimits
	// Notifications is optional: a zero value (no notifiers) leaves the
	// service behaving exactly as it did before outbound notifications
	// existed -- nothing is sent, and nothing can fail.
	Notifications Notifications
	// RegLimits bounds how many artifacts may exist at all -- the zero
	// value is unlimited.
	RegLimits RegistrationLimits
	// Ready reports whether this process's backing store is actually
	// usable right now, for GET /readyz (see readyz in health.go). nil
	// means "nothing to check, always ready" -- which is both the honest
	// answer for MemStore and what every test gets by not setting it.
	//
	// Deliberately a func rather than a method on the Store interface:
	// only PostgresStore has anything to check (main.go passes its Ping),
	// and adding a second context-taking method to that interface would
	// entrench the wart Stats(ctx) already documents as one.
	Ready func(context.Context) error
}

// NewRouter wires up the v1 REST API. Uses Go 1.22's stdlib ServeMux
// method+wildcard routing, so no external router dependency is needed.
// See Config for what each field does and what its zero value means.
func NewRouter(cfg Config) http.Handler {
	h := &handler{store: cfg.Store, tracker: cfg.Tracker, scanners: cfg.Scanners, digestResolver: cfg.DigestResolver, fetchPlainHTTP: cfg.FetchPlainHTTP, scanTimeout: cfg.ScanTimeout, requireDigest: cfg.RequireDigest, notifiers: cfg.Notifications.Notifiers, notifyMinSeverity: cfg.Notifications.MinSeverity, notifyOnFirstScan: cfg.Notifications.NotifyOnFirstScan, maxArtifacts: cfg.RegLimits.MaxArtifacts, ready: cfg.Ready}
	if cfg.ScanLimits.Concurrency > 0 {
		h.scanSlots = make(chan struct{}, cfg.ScanLimits.Concurrency)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /swagger", h.swaggerUI)
	mux.HandleFunc("GET /openapi.yaml", h.openapiSpec)
	mux.HandleFunc("GET /api/v1/pipeline/stages", h.listStages)
	// Not exempted in withAuth below, so it requires the API key like
	// every other /api/v1 route -- deliberate: unlike /healthz and the
	// swagger pages (which describe the API's shape), this reports how
	// many artifacts carry active malware and CVE findings, which is
	// data about the fleet, not documentation.
	mux.HandleFunc("GET /api/v1/stats", h.getStats)
	mux.HandleFunc("POST /api/v1/artifacts", h.createArtifact)
	mux.HandleFunc("POST /api/v1/artifacts/bulk", h.bulkCreateArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts", h.listArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", h.getArtifact)
	mux.HandleFunc("DELETE /api/v1/artifacts/{id}", h.deleteArtifact)
	mux.HandleFunc("GET /api/v1/findings", h.searchFindings)
	mux.HandleFunc("GET /api/v1/findings/{findingID}/artifacts", h.findByFindingID)
	mux.HandleFunc("GET /api/v1/components", h.listByComponent)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/scan", h.scanArtifact)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/stage", h.updateStage)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/maintainer", h.updateMaintainer)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/documents/{kind}", h.uploadDocument)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/documents/{kind}", h.downloadDocument)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/findings", h.submitFindings)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/vex", h.uploadVEX)

	var top http.Handler = mux
	if cfg.RateLimitRPS > 0 {
		// Sits between withAuth and mux (wired below), not outside
		// withAuth -- see withRateLimit's own comment for why.
		top = withRateLimit(top, newRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst))
	}

	// withCORS must wrap withAuth, not the other way around: a CORS
	// preflight OPTIONS request never carries the Authorization header
	// (browsers don't attach custom headers to preflight requests at
	// all), so it has to be short-circuited before auth ever runs, or
	// every cross-origin call from the dashboard would fail preflight
	// with a 401 before the browser even attempts the real request.
	return withCORS(withAuth(top, cfg.APIKey))
}

// withAuth requires `Authorization: Bearer <apiKey>` on every request
// except /healthz, /readyz, /swagger, and /openapi.yaml. Uses
// crypto/subtle.ConstantTimeCompare rather than == specifically to avoid
// a timing side-channel that could let an attacker guess the key one
// byte at a time -- overkill for a single-shared-key scheme against most
// threat models, but it's a one-line difference from a plain string
// comparison, so there's no real reason not to.
//
// /swagger and /openapi.yaml are exempt for the same reason /healthz is:
// they describe the API's shape, not any of its data -- unauthenticated
// access to "here are the routes and request/response schemas" isn't a
// real exposure, and requiring a key just to read the docs page (as
// opposed to actually calling an endpoint through it) would be an
// annoyance with no corresponding security benefit. Swagger UI's own
// "Authorize" button is still where a real API key goes before "Try it
// out" against any actual endpoint works.
func withAuth(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz", "/swagger", "/openapi.yaml":
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
		// Without this, a cross-origin browser fetch can read the
		// response body but not these two headers -- the pagination
		// metadata listArtifacts sets would be invisible to exactly the
		// client (the dashboard) it exists for.
		w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count, Link")
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
		// /healthz, /swagger, and /openapi.yaml all skip the auth check in
		// withAuth (see its own comment) and still flow through to here --
		// exempted explicitly for the same reasons: a liveness/readiness
		// probe can never be the thing that trips this limiter, and every
		// unauthenticated caller sharing one bucket keyed by an empty
		// Authorization header (see limiter.allow below) shouldn't be able
		// to lock other anonymous callers out of the API docs page.
		switch r.URL.Path {
		case "/healthz", "/readyz", "/swagger", "/openapi.yaml":
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
