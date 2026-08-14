package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
)

// newHealthRouter builds a router whose Config.Ready is exactly what a
// test wants it to be -- nil for "no backing store to check", or a func
// returning a specific error to stand in for a database that has gone
// away. A func rather than a fake store because that is the real shape:
// main.go passes *PostgresStore.Ping, and nothing about readiness goes
// through the Store interface.
func newHealthRouter(ready func(context.Context) error) http.Handler {
	return api.NewRouter(api.Config{
		Store:   artifact.NewMemStore(),
		Tracker: pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:  testAPIKey,
		Ready:   ready,
	})
}

func probe(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	// No Authorization header anywhere in this file: a kubelet cannot
	// present one, so both probe endpoints having to work without it is
	// part of what these tests assert.
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz_IsUnauthenticatedAndIgnoresTheStore(t *testing.T) {
	// A store that is definitively broken. /healthz must not care: it
	// answers for the process, and a liveness failure kills the pod --
	// see health.go for why checking the database here would convert a
	// Postgres outage into a fleet-wide crashloop.
	h := newHealthRouter(func(context.Context) error {
		return errors.New("postgres is gone")
	})

	rec := probe(t, h, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200 even with the store unreachable -- liveness must not depend on a dependency (body=%s)",
			rec.Code, rec.Body.String())
	}
}

// The bug this whole split exists to fix. Both probes used to point at
// /healthz, which returns "ok" unconditionally, so a database that went
// away AFTER startup left the pod Ready and serving 500s from every
// endpoint that touches the store. If readiness ever stops consulting
// the store, this is the test that fails.
func TestReadyz_ReportsUnavailableWhenTheStoreIsUnreachable(t *testing.T) {
	h := newHealthRouter(func(context.Context) error {
		return errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	})

	rec := probe(t, h, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503 when the store can't be reached (body=%s)", rec.Code, rec.Body.String())
	}
	// The reason travels with it, for whoever is reading `kubectl
	// describe pod` -- a bare 503 says "not ready" without saying why.
	if body := rec.Body.String(); !strings.Contains(body, "connection refused") {
		t.Errorf("/readyz body = %s, want the underlying reason included", body)
	}
}

func TestReadyz_ReadyWhenTheStoreAnswers(t *testing.T) {
	h := newHealthRouter(func(context.Context) error { return nil })

	rec := probe(t, h, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200 when the store answers (body=%s)", rec.Code, rec.Body.String())
	}
}

// nil Ready means "nothing to check" -- the honest answer for MemStore,
// and what every other test's router gets by not setting the field. If
// this ever 503s, every handler test in this package starts failing for
// a reason that has nothing to do with what it was testing.
func TestReadyz_NoReadyFuncMeansReady(t *testing.T) {
	rec := probe(t, newHealthRouter(nil), "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200 when no readiness check is configured (body=%s)", rec.Code, rec.Body.String())
	}
}

// A probe that trips the rate limiter fails the pod, so /readyz has to
// be exempt the same way /healthz already is -- an easy exemption to
// miss, since it lives in a different list from the auth one.
func TestReadyz_ExemptFromRateLimiting(t *testing.T) {
	h := api.NewRouter(api.Config{
		Store:   artifact.NewMemStore(),
		Tracker: pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:  testAPIKey,
		// Burst of 1: the second unexempted request through this router
		// would be a 429.
		RateLimitRPS:   1,
		RateLimitBurst: 1,
		Ready:          func(context.Context) error { return nil },
	})

	for i := 0; i < 5; i++ {
		if rec := probe(t, h, "/readyz"); rec.Code != http.StatusOK {
			t.Fatalf("/readyz call %d = %d, want 200 -- probes must not be rate limited", i+1, rec.Code)
		}
		if rec := probe(t, h, "/healthz"); rec.Code != http.StatusOK {
			t.Fatalf("/healthz call %d = %d, want 200 -- probes must not be rate limited", i+1, rec.Code)
		}
	}
}
