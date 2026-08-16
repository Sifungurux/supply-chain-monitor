package api_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// newRateLimitedTestRouter is separate from newTestRouter (handler_test.go)
// specifically so the ~10 existing handler tests keep running with rate
// limiting off, while these tests exercise it deliberately.
func newRateLimitedTestRouter(t *testing.T, rps, burst float64) http.Handler {
	t.Helper()
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(api.Config{Store: store, Tracker: tracker, APIKey: testAPIKey, RateLimitRPS: rps, RateLimitBurst: burst})
}

func TestRateLimit_ExceedingBurstReturns429(t *testing.T) {
	h := newRateLimitedTestRouter(t, 1, 2)

	var last *httptest.ResponseRecorder
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (within burst of 2)", i, rec.Code)
		}
		last = rec
	}
	_ = last

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (burst of 2 already spent)", rec.Code)
	}
}

func TestRateLimit_DisabledWhenRPSIsZero(t *testing.T) {
	h := newRateLimitedTestRouter(t, 0, 0)

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (rate limiting disabled via rps=0)", i, rec.Code)
		}
	}
}

func TestRateLimit_UnauthenticatedRequestsAreNotRateLimitedFirst(t *testing.T) {
	// Requests that fail auth must get 401, not 429 -- withRateLimit is
	// wired inside withAuth specifically so an unauthenticated caller
	// can't burn through (or be blocked by) the rate limit budget at
	// all, let alone before auth even runs.
	h := newRateLimitedTestRouter(t, 1, 1)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
		// no Authorization header
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: status = %d, want 401 for every unauthenticated request, regardless of rate limit state", i, rec.Code)
		}
	}
}

func TestRateLimit_HealthzExemptEvenUnderExhaustedBurst(t *testing.T) {
	h := newRateLimitedTestRouter(t, 1, 1)

	// Spend the one available token on a real endpoint first.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup request: status = %d, want 200", rec.Code)
	}

	// /healthz must still succeed even though the burst is now spent --
	// a liveness/readiness probe must never be the request that trips
	// this limiter.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/healthz request %d: status = %d, want 200 (must be exempt from rate limiting)", i, rec.Code)
		}
	}
}

func TestCORSHeaders(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodGet, "/healthz", nil)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/artifacts", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("expected Access-Control-Allow-Methods header on preflight response")
	}
}

// TestAuth_HealthzExempt: liveness/readiness probes have no way to
// carry a bearer token, so /healthz must stay reachable without one.

func TestAuth_HealthzExempt(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no Authorization header sent)", rec.Code)
	}
}

// TestAuth_SwaggerRoutesExempt: the docs page and its spec describe the
// API's shape, not any of its data, so both must be readable with no API
// key -- the same "unauthenticated is fine, this isn't data" reasoning as
// TestAuth_HealthzExempt above.

func TestAuth_SwaggerRoutesExempt(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	for _, path := range []string{"/swagger", "/openapi.yaml"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200 (no Authorization header sent)", path, rec.Code)
		}
	}
}

// TestSwaggerUI_ReferencesOpenAPISpec is a smoke check that the served
// HTML actually points at the spec route this same router serves --
// catches a typo'd URL in swaggerUIHTML that would otherwise only show
// up as a blank Swagger UI page in a browser, never as a test failure.

func TestAuth_OptionsPreflightExempt(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (no Authorization header sent)", rec.Code)
	}
	// Regression check: DELETE must be in the preflight's allowed
	// methods, or a browser's real DELETE /api/v1/artifacts/{id} call
	// from the dashboard would fail preflight before it's even
	// attempted -- the same reasoning GET/POST are already listed here.
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "DELETE") {
		t.Fatalf("Access-Control-Allow-Methods = %q, want it to include DELETE", got)
	}
}

func TestAuth_MissingKeyRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no Authorization header at all)", rec.Code)
	}
}

func TestAuth_WrongKeyRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer not-the-right-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong key)", rec.Code)
	}
}

func TestAuth_MalformedHeaderRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", testAPIKey) // missing "Bearer " prefix
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (missing Bearer prefix)", rec.Code)
	}
}

func TestAuth_CorrectKeyAccepted(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// doRaw is doJSON's raw-body counterpart -- the document upload/
// download endpoints deal in arbitrary bytes with a caller-chosen
// Content-Type, not a JSON payload, so doJSON's always-JSON marshaling
// doesn't fit.
func doRaw(t *testing.T, h http.Handler, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// authRouter builds a router with a known key, for the auth-failure
// throttle tests below.
func authRouter() http.Handler {
	return api.NewRouter(api.Config{
		Store:   artifact.NewMemStore(),
		Tracker: pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:  testAPIKey,
	})
}

// req issues one GET with the given key and source address.
func req(h http.Handler, key, xff string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// Blind credential stuffing has to stop being free. The burst is 10, so
// the eleventh consecutive wrong key from one address is throttled.
func TestAuthThrottle_SustainedWrongKeysGet429(t *testing.T) {
	h := authRouter()

	var got429At int
	for i := 1; i <= 20; i++ {
		rec := req(h, "wrong-key", "203.0.113.9")
		if rec.Code == http.StatusTooManyRequests {
			got429At = i
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After -- a client cannot tell how long to wait")
			}
			break
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401 before the limit trips", i, rec.Code)
		}
	}
	if got429At == 0 {
		t.Fatal("20 consecutive wrong keys were never throttled")
	}
	if got429At <= 10 {
		t.Errorf("throttled at attempt %d, expected the burst of 10 to be allowed first", got429At)
	}
}

// The limiter is consulted ONLY on the rejection path, so a valid key
// cannot be throttled by it -- including from an address that has just
// been throttled into the ground.
func TestAuthThrottle_CorrectKeyUnaffected(t *testing.T) {
	h := authRouter()

	for i := 0; i < 30; i++ {
		req(h, "wrong-key", "203.0.113.10")
	}
	if rec := req(h, "wrong-key", "203.0.113.10"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("precondition: this address should be throttled, got %d", rec.Code)
	}

	// Same address, right key, far more requests than the failure burst.
	for i := 0; i < 50; i++ {
		if rec := req(h, testAPIKey, "203.0.113.10"); rec.Code != http.StatusOK {
			t.Fatalf("request %d with the CORRECT key got %d, want 200 -- failed-auth throttling must never touch valid traffic", i+1, rec.Code)
		}
	}
}

// One noisy source must not lock out everyone else, which is the whole
// reason this is keyed per address rather than globally.
func TestAuthThrottle_IsPerAddress(t *testing.T) {
	h := authRouter()

	for i := 0; i < 30; i++ {
		req(h, "wrong-key", "203.0.113.11")
	}
	if rec := req(h, "wrong-key", "203.0.113.11"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("precondition: first address should be throttled, got %d", rec.Code)
	}

	if rec := req(h, "wrong-key", "198.51.100.7"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a different address got %d, want 401 -- one attacker must not lock out other callers", rec.Code)
	}
}

// X-Forwarded-For carries a proxy chain; the ORIGINAL client is first.
// Keying on the whole header, or on the last hop, would put everyone
// behind one proxy in the same bucket.
func TestAuthThrottle_UsesFirstForwardedForValue(t *testing.T) {
	h := authRouter()

	for i := 0; i < 30; i++ {
		req(h, "wrong-key", "203.0.113.12, 10.0.0.1, 10.0.0.2")
	}
	if rec := req(h, "wrong-key", "203.0.113.12, 10.0.0.1, 10.0.0.2"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("precondition: throttling should apply, got %d", rec.Code)
	}

	// Same proxy chain, different original client: must be its own bucket.
	if rec := req(h, "wrong-key", "203.0.113.13, 10.0.0.1, 10.0.0.2"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a different original client behind the same proxies got %d, want 401", rec.Code)
	}
}

// Probes and docs skip auth entirely, so they can never be throttled by
// it -- a liveness probe must not be able to trip a security limiter.
func TestAuthThrottle_ExemptPathsUnaffected(t *testing.T) {
	h := authRouter()

	for i := 0; i < 30; i++ {
		req(h, "wrong-key", "203.0.113.14")
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("X-Forwarded-For", "203.0.113.14")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("%s got %d, want 200 even from a throttled address", path, rec.Code)
		}
	}
}

// trustedRouter builds a router whose failed-auth throttle only believes
// X-Forwarded-For from the given CIDRs.
func trustedRouter(t *testing.T, cidrs string) http.Handler {
	t.Helper()
	trusted, err := api.ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", cidrs, err)
	}
	return api.NewRouter(api.Config{
		Store:          artifact.NewMemStore(),
		Tracker:        pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:         testAPIKey,
		TrustedProxies: trusted,
	})
}

// wrongKeyFrom sends one bad-key request from a specific socket peer,
// optionally forging X-Forwarded-For.
func wrongKeyFrom(h http.Handler, peer, xff string) int {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	r.RemoteAddr = peer
	r.Header.Set("Authorization", "Bearer wrong-key")
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// THE PROPERTY THE SETTING EXISTS FOR. An attacker who rotates
// X-Forwarded-For gets a fresh bucket per request while the header is
// trusted unconditionally, which means the failed-auth throttle
// throttles nobody.
func TestAuthThrottle_ForgedXFFCannotEscapeThrottle(t *testing.T) {
	h := trustedRouter(t, "10.42.0.0/16")

	// Not a trusted proxy, and a different forged header every time.
	var got429 bool
	for i := 0; i < 25; i++ {
		code := wrongKeyFrom(h, "198.51.100.66:40000", fmt.Sprintf("203.0.113.%d", i+1))
		if code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("25 failures from one socket peer were never throttled -- a rotated X-Forwarded-For escaped the limiter")
	}
}

// The other half: a real proxy's header must still be believed, or every
// caller behind it shares one bucket and one attacker locks out the rest.
func TestAuthThrottle_TrustedProxyStillIsolatesClients(t *testing.T) {
	h := trustedRouter(t, "10.42.0.0/16")

	// Exhaust one client's allowance, as reported by the trusted proxy.
	for i := 0; i < 25; i++ {
		wrongKeyFrom(h, "10.42.0.7:54321", "203.0.113.9")
	}
	if code := wrongKeyFrom(h, "10.42.0.7:54321", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("precondition: that client should be throttled, got %d", code)
	}

	// A different client behind the SAME proxy must be unaffected.
	if code := wrongKeyFrom(h, "10.42.0.7:54321", "198.51.100.7"); code != http.StatusUnauthorized {
		t.Errorf("a different client behind the same proxy got %d, want 401 -- one attacker must not lock out everyone behind the ingress", code)
	}
}

// Unset preserves the old behaviour exactly, so enabling this is opt-in.
func TestAuthThrottle_UnconfiguredTrustsAnyXFF(t *testing.T) {
	h := trustedRouter(t, "")

	for i := 0; i < 25; i++ {
		wrongKeyFrom(h, "198.51.100.66:40000", "203.0.113.9")
	}
	if code := wrongKeyFrom(h, "198.51.100.66:40000", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("precondition: that XFF value should be throttled, got %d", code)
	}
	// Same untrusted socket, different header -> a fresh bucket, because
	// nothing is configured. This is the documented trade-off.
	if code := wrongKeyFrom(h, "198.51.100.66:40000", "192.0.2.77"); code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401 -- with no trusted CIDRs the header is believed from any peer, unchanged from before", code)
	}
}
