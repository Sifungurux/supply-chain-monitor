package api_test

import (
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
