package api_test

import (
	"bytes"
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
	return api.NewRouter(store, tracker, scanner.Registry{}, testAPIKey, rps, burst, nil, false, 0, false, api.ScanLimits{}, api.Notifications{})
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
