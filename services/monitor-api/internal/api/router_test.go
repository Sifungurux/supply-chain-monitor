package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// newRateLimitedTestRouter is separate from newTestRouter (handlers_test.go)
// specifically so the ~10 existing handler tests keep running with rate
// limiting off, while these tests exercise it deliberately.
func newRateLimitedTestRouter(t *testing.T, rps, burst float64) http.Handler {
	t.Helper()
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(store, tracker, scanner.Registry{}, testAPIKey, rps, burst, nil, false, 0)
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
