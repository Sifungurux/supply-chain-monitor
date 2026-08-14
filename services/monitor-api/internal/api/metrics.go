package api

import (
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// The Prometheus text exposition format, written by hand rather than
// with prometheus/client_golang.
//
// That is a deliberate dependency call, not laziness. go.mod says pgx
// is "the one non-stdlib dependency in this module", and this package
// already hand-rolls its router (stdlib ServeMux) and its rate limiter
// for the same reason. client_golang would pull in client_model,
// prometheus/common, procfs and protobuf to publish a handful of
// counters in a format that is line-oriented text with a documented
// grammar. If this ever needs histograms, exemplars, or native
// histograms, take the dependency then -- those are worth it and this
// is not.
//
// What is exposed here is deliberately PROCESS state, never fleet
// state: request and scan counters, goroutines, heap. Fleet gauges
// ("how many artifacts carry active malware") would be far more useful
// on a dashboard and must NOT be added here as-is -- see the auth note
// on /metrics in router.go, and metricsHandler below.

// metrics is the whole registry: a fixed set of counters incremented on
// hot paths and read at scrape time. Atomics rather than a mutex
// because every write is an independent increment and no reader needs a
// consistent snapshot across counters -- a scrape that catches one
// counter a microsecond before another is indistinguishable from a
// scrape a microsecond earlier.
type metrics struct {
	scansStarted   atomic.Int64
	scansSucceeded atomic.Int64
	scansFailed    atomic.Int64
	// httpResponses is indexed by status class (index = status / 100),
	// so index 2 is every 2xx. Classes, not individual codes: this is a
	// fixed-size array with no allocation and no map lock on a path
	// every request takes, and "how many 5xx" is the question anyone
	// actually asks of this number. Per-route/per-code breakdowns are
	// what a real metrics library is for -- see the note above.
	httpResponses [6]atomic.Int64
	startedAt     time.Time
}

func newMetrics() *metrics {
	return &metrics{startedAt: time.Now()}
}

// recordScan* are called from runScan (scan.go), the one funnel every
// scan passes through, including the recovered-panic path.
func (m *metrics) recordScanStarted() { m.scansStarted.Add(1) }
func (m *metrics) recordScanResult(failed bool) {
	if failed {
		m.scansFailed.Add(1)
		return
	}
	m.scansSucceeded.Add(1)
}

func (m *metrics) recordResponse(status int) {
	class := status / 100
	if class < 0 || class >= len(m.httpResponses) {
		return
	}
	m.httpResponses[class].Add(1)
}

// statusRecorder captures the status code for withMetrics. net/http
// gives a middleware no way to read what the handler below it wrote,
// so the ResponseWriter has to be wrapped.
//
// A handler that never calls WriteHeader has implicitly sent 200, which
// is why the zero value here is 200 rather than 0 -- otherwise every
// plain writeJSON response (the common case) would land in class 0 and
// be dropped by recordResponse.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// withMetrics counts every response by status class.
//
// Wired OUTSIDE withAuth so a 401 is counted -- a spike of them is
// exactly the kind of thing this is for, and a middleware inside auth
// would never see one.
//
// Infrastructure polling is excluded: the probes run every few seconds
// per pod and Prometheus scrapes /metrics itself on its own interval,
// so counting them buries real API traffic under a constant floor of
// machine chatter and makes any request-rate panel a measurement of the
// monitoring, not the service.
func withMetrics(next http.Handler, m *metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.recordResponse(rec.status)
	})
}

// metricsHandler writes the exposition format. Every value here is read
// from memory -- nothing touches the database, deliberately: a scrape
// endpoint that queries Postgres would fail exactly when the database
// is down, which is precisely when the scrape data still needs to
// arrive, and would put two full table scans on the same process
// serving the dashboard's poll.
//
// Fleet counts live at GET /api/v1/stats instead, which is
// authenticated and asked for by a human. Wiring those in here would
// need a cached or background-refreshed read AND would change what this
// endpoint discloses, which is the basis for it being unauthenticated
// at all.
func (h *handler) metricsHandler(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	// Stops the world briefly. At a scrape interval measured in tens of
	// seconds and this service's heap, that is microseconds and not
	// worth the extra code of runtime/metrics -- revisit if either the
	// heap or the scrape rate grows a lot.
	runtime.ReadMemStats(&mem)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	counter := func(name, help string, value int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}
	gauge := func(name, help string, value float64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
	}

	counter("scm_scans_started_total", "Scans started since process start.", h.metrics.scansStarted.Load())
	counter("scm_scans_succeeded_total", "Scans that completed with at least one scanner succeeding.", h.metrics.scansSucceeded.Load())
	counter("scm_scans_failed_total", "Scans where every scanner failed, including panics.", h.metrics.scansFailed.Load())

	// One metric with a class label rather than five separate names, so
	// a query can sum over classes or pick one.
	fmt.Fprintf(w, "# HELP scm_http_responses_total HTTP responses by status class, excluding probe and scrape endpoints.\n# TYPE scm_http_responses_total counter\n")
	for class := 1; class < len(h.metrics.httpResponses); class++ {
		fmt.Fprintf(w, "scm_http_responses_total{class=\"%dxx\"} %d\n", class, h.metrics.httpResponses[class].Load())
	}

	gauge("scm_process_uptime_seconds", "Seconds since this process started.", time.Since(h.metrics.startedAt).Seconds())
	gauge("go_goroutines", "Goroutines currently running.", float64(runtime.NumGoroutine()))
	gauge("go_memstats_heap_alloc_bytes", "Heap bytes allocated and in use.", float64(mem.HeapAlloc))
	gauge("go_memstats_sys_bytes", "Total bytes obtained from the OS.", float64(mem.Sys))
}
