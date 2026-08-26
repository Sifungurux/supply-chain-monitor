package api_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// scrape fetches /metrics with no Authorization header -- part of what
// these tests assert is that a scraper doesn't need one.
func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200 without an API key (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("/metrics Content-Type = %q, want the text exposition format", ct)
	}
	return rec.Body.String()
}

// metricValue pulls one sample out of the exposition text. Deliberately
// parses the rendered output rather than reading the counters directly:
// the format is the contract Prometheus consumes, and a counter that
// increments correctly but renders wrong is still broken.
func metricValue(t *testing.T, body, sample string) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(sample) + ` (\S+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no sample %q in:\n%s", sample, body)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("sample %q has unparseable value %q", sample, m[1])
	}
	return v
}

func TestMetrics_ExposesTypeAndHelpForEverySample(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	body := scrape(t, h)

	// Every metric name must carry both HELP and TYPE -- a scrape
	// without them parses, but the metric arrives untyped and
	// undocumented, which is how a counter ends up graphed as a gauge.
	for _, name := range []string{
		"scm_scans_started_total",
		"scm_scans_succeeded_total",
		"scm_scans_failed_total",
		"scm_http_responses_total",
		"scm_process_uptime_seconds",
		"go_goroutines",
		"go_memstats_heap_alloc_bytes",
	} {
		if !strings.Contains(body, "# HELP "+name+" ") {
			t.Errorf("no HELP line for %s", name)
		}
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("no TYPE line for %s", name)
		}
	}
}

func TestMetrics_CountsResponsesByStatusClass(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	before2xx := metricValue(t, scrape(t, h), `scm_http_responses_total{class="2xx"}`)
	before4xx := metricValue(t, scrape(t, h), `scm_http_responses_total{class="4xx"}`)

	doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID, nil)          // 200
	doJSON(t, h, http.MethodGet, "/api/v1/artifacts/does-not-exist", nil) // 404
	doJSON(t, h, http.MethodGet, "/api/v1/components", nil)               // 400

	body := scrape(t, h)
	if got := metricValue(t, body, `scm_http_responses_total{class="2xx"}`) - before2xx; got != 1 {
		t.Errorf("2xx moved by %v, want 1", got)
	}
	if got := metricValue(t, body, `scm_http_responses_total{class="4xx"}`) - before4xx; got != 2 {
		t.Errorf("4xx moved by %v, want 2 (a 404 and a 400)", got)
	}
}

// A 401 is produced by withAuth, so it is only countable if the metrics
// middleware wraps auth rather than sitting inside it -- and a spike of
// them is exactly what this counter is for.
func TestMetrics_CountsUnauthorizedResponses(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	before := metricValue(t, scrape(t, h), `scm_http_responses_total{class="4xx"}`)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil) // no key
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("setup: status = %d, want 401", rec.Code)
	}

	if got := metricValue(t, scrape(t, h), `scm_http_responses_total{class="4xx"}`) - before; got != 1 {
		t.Errorf("4xx moved by %v after a 401, want 1 -- withMetrics must wrap withAuth, not sit inside it", got)
	}
}

// Probes and scrapes must not inflate the counters: they run every few
// seconds forever, so counting them turns any request-rate panel into a
// measurement of the monitoring rather than the service.
func TestMetrics_ExcludesProbeAndScrapeTraffic(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	before := metricValue(t, scrape(t, h), `scm_http_responses_total{class="2xx"}`)

	for i := 0; i < 3; i++ {
		if rec := probe(t, h, "/healthz"); rec.Code != http.StatusOK {
			t.Fatalf("setup: /healthz = %d", rec.Code)
		}
		if rec := probe(t, h, "/readyz"); rec.Code != http.StatusOK {
			t.Fatalf("setup: /readyz = %d", rec.Code)
		}
		scrape(t, h)
	}

	if got := metricValue(t, scrape(t, h), `scm_http_responses_total{class="2xx"}`) - before; got != 0 {
		t.Errorf("2xx moved by %v after only probe/scrape traffic, want 0", got)
	}
}

func TestMetrics_CountsScanOutcomes(t *testing.T) {
	// One scanner that works and one artifact type that uses it, so a
	// scan runs to completion synchronously enough to observe.
	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:    store,
		Tracker:  pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:   testAPIKey,
		Scanners: scanner.Registry{artifact.TypeImage: {&fakeScanner{}}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil)
	if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := waitForScan(t, store, a.ID); got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusScanned)
	}

	body := scrape(t, h)
	if got := metricValue(t, body, "scm_scans_started_total"); got != 1 {
		t.Errorf("scm_scans_started_total = %v, want 1", got)
	}
	if got := metricValue(t, body, "scm_scans_succeeded_total"); got != 1 {
		t.Errorf("scm_scans_succeeded_total = %v, want 1", got)
	}
	if got := metricValue(t, body, "scm_scans_failed_total"); got != 0 {
		t.Errorf("scm_scans_failed_total = %v, want 0", got)
	}
}

// Every scan must land in exactly one of succeeded/failed, so started
// never outruns succeeded+failed -- a drift nothing else would notice.
//
// Note what this does and does not cover: a scanner that panics is
// recovered inside its own goroutine and reported as a scan error, so
// this exercises the NORMAL outcome path with every scanner failed.
// runScan's own recover() -- for a panic in runScan itself -- records
// its outcome separately and is not reached from here; it is defensive
// code for a case no test currently provokes.
func TestMetrics_EveryScanRecordsExactlyOneOutcome(t *testing.T) {
	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:    store,
		Tracker:  pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:   testAPIKey,
		Scanners: scanner.Registry{artifact.TypeImage: {&panickingScanner{}}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil)
	if got := waitForScan(t, store, a.ID); got.Status != artifact.StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusFailed)
	}

	body := scrape(t, h)
	started := metricValue(t, body, "scm_scans_started_total")
	succeeded := metricValue(t, body, "scm_scans_succeeded_total")
	failed := metricValue(t, body, "scm_scans_failed_total")
	if started != succeeded+failed {
		t.Errorf("started=%v but succeeded+failed=%v -- every scan must record exactly one outcome",
			started, succeeded+failed)
	}
	if failed != 1 {
		t.Errorf("scm_scans_failed_total = %v, want 1", failed)
	}
}

// scrape reads /metrics and returns the value of a named counter.
func scrapeCounter(t *testing.T, h http.Handler, name string) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics got %d, want 200", rec.Code)
	}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, name+" ") {
			var v int64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, name+" "), "%d", &v); err != nil {
				t.Fatalf("could not parse %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("counter %q not present in /metrics", name)
	return 0
}

// The whole reason these counters exist: scm_http_responses_total buckets
// by class, so a 401 from credential guessing and a 404 from a typo are
// the same number there. These separate the two, and separate a
// throttled attempt from a merely rejected one.
func TestMetrics_AuthFailuresAndThrottlingAreCountedSeparately(t *testing.T) {
	h := authRouter()

	if got := scrapeCounter(t, h, "scm_auth_failures_total"); got != 0 {
		t.Fatalf("precondition: failures start at %d, want 0", got)
	}

	// 10 rejections, then the 11th is refused before the key is checked.
	for i := 0; i < 10; i++ {
		if rec := req(h, "wrong-key", "203.0.113.60"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d got %d, want 401", i+1, rec.Code)
		}
	}
	if rec := req(h, "wrong-key", "203.0.113.60"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 11 got %d, want 429", rec.Code)
	}

	if got := scrapeCounter(t, h, "scm_auth_failures_total"); got != 10 {
		t.Errorf("scm_auth_failures_total = %d, want 10", got)
	}
	// DISJOINT: a throttled attempt never had its key checked, so it is
	// not also a failure.
	if got := scrapeCounter(t, h, "scm_auth_throttled_total"); got != 1 {
		t.Errorf("scm_auth_throttled_total = %d, want 1", got)
	}
}

// A valid key must move neither counter, however much traffic it sends.
func TestMetrics_SuccessfulAuthTouchesNeitherCounter(t *testing.T) {
	h := authRouter()

	for i := 0; i < 20; i++ {
		if rec := req(h, testAPIKey, "203.0.113.61"); rec.Code != http.StatusOK {
			t.Fatalf("request %d got %d, want 200", i+1, rec.Code)
		}
	}
	if got := scrapeCounter(t, h, "scm_auth_failures_total"); got != 0 {
		t.Errorf("scm_auth_failures_total = %d after only valid requests, want 0", got)
	}
	if got := scrapeCounter(t, h, "scm_auth_throttled_total"); got != 0 {
		t.Errorf("scm_auth_throttled_total = %d after only valid requests, want 0", got)
	}
}

// TestMetrics_BuildInfo covers the metric that makes "which commit is
// running" answerable from a scrape.
//
// It follows the Prometheus build-metadata convention: a gauge fixed at
// 1 whose LABEL carries the information, so the value is useless and
// the label is joinable. A version change shows as a new series rather
// than a value change nobody can alert on.
func TestMetrics_BuildInfo(t *testing.T) {
	t.Run("reports the configured version", func(t *testing.T) {
		h := api.NewRouter(api.Config{
			Store:        artifact.NewMemStore(),
			Tracker:      pipeline.NewTracker([]string{"build", "scan"}),
			APIKey:       testAPIKey,
			BuildVersion: "abc1234",
		})
		body := scrapeMetrics(t, h)
		if !strings.Contains(body, `scm_build_info{version="abc1234"} 1`) {
			t.Errorf("missing or wrong scm_build_info line:\n%s", body)
		}
	})

	// An unstamped build must say "unknown" rather than render an empty
	// label -- a build that cannot say what it is should say so, not
	// look like a build whose version happens to be blank.
	t.Run("unset renders unknown", func(t *testing.T) {
		h := api.NewRouter(api.Config{
			Store:   artifact.NewMemStore(),
			Tracker: pipeline.NewTracker([]string{"build", "scan"}),
			APIKey:  testAPIKey,
		})
		body := scrapeMetrics(t, h)
		if !strings.Contains(body, `scm_build_info{version="unknown"} 1`) {
			t.Errorf("expected version=\"unknown\", got:\n%s", body)
		}
	})
}

func scrapeMetrics(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d", rec.Code)
	}
	return rec.Body.String()
}

// TestMetrics_TokenGate covers the optional /metrics bearer token
// (report S4).
//
// The endpoint is exempt from API-key auth so an in-cluster Prometheus
// can scrape it, which also means anything that can reach the API can
// read scan counts, artifact totals and the build version. Not
// credentials, but reconnaissance -- so a deployment that wants it
// closed gets its own token, separate from the API keys because the
// scrape is a different principal: sharing one would make "let
// Prometheus scrape" mean "give Prometheus an API key".
func TestMetrics_TokenGate(t *testing.T) {
	newRouter := func(token string) http.Handler {
		return api.NewRouter(api.Config{
			Store:        artifact.NewMemStore(),
			Tracker:      pipeline.NewTracker([]string{"build", "scan"}),
			APIKey:       testAPIKey,
			MetricsToken: token,
		})
	}
	scrape := func(h http.Handler, auth string) int {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Unset: open, exactly as every existing deployment behaves. An
	// upgrade must not start refusing its own Prometheus.
	t.Run("unset leaves it open", func(t *testing.T) {
		h := newRouter("")
		if code := scrape(h, ""); code != http.StatusOK {
			t.Errorf("no token configured, no auth: got %d, want 200", code)
		}
	})

	t.Run("set requires the token", func(t *testing.T) {
		h := newRouter("scrape-secret")
		if code := scrape(h, ""); code != http.StatusUnauthorized {
			t.Errorf("no auth: got %d, want 401", code)
		}
		if code := scrape(h, "Bearer wrong"); code != http.StatusUnauthorized {
			t.Errorf("wrong token: got %d, want 401", code)
		}
		if code := scrape(h, "Bearer scrape-secret"); code != http.StatusOK {
			t.Errorf("correct token: got %d, want 200", code)
		}
	})

	// The metrics token must NOT be an API key in disguise, in either
	// direction -- that separation is the whole reason it exists.
	t.Run("api key does not open metrics and vice versa", func(t *testing.T) {
		h := newRouter("scrape-secret")
		if code := scrape(h, "Bearer "+testAPIKey); code != http.StatusUnauthorized {
			t.Errorf("API key on /metrics: got %d, want 401", code)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
		req.Header.Set("Authorization", "Bearer scrape-secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("metrics token on the API: got %d, want 401", rec.Code)
		}
	})

	// The probes stay open regardless -- a gated /metrics must not take
	// liveness with it.
	t.Run("probes stay open", func(t *testing.T) {
		h := newRouter("scrape-secret")
		for _, p := range []string{"/healthz", "/readyz"} {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s: got %d, want 200", p, rec.Code)
			}
		}
	})
}
