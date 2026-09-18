package api

import (
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
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
	// authFailures and authThrottled are DISJOINT, and both exist
	// because httpResponses cannot answer the question either one is
	// for: a 401 from credential guessing and a 404 from a typo are the
	// same "4xx" there, so a spike that matters is indistinguishable
	// from routine client error.
	//
	// authFailures counts credentials that were checked and rejected.
	// authThrottled counts attempts refused BEFORE the key was checked,
	// because that address had already failed too often -- so a rising
	// authThrottled means someone is being slowed down, which is the
	// signal the throttle exists to produce and the only place it is
	// visible outside the pod logs.
	authFailures  atomic.Int64
	authThrottled atomic.Int64
	// scanTokenMintFailures counts scans REFUSED because the per-Job
	// upload credential could not be minted.
	//
	// It exists because that refusal is otherwise silent. An image scan
	// used to fall back to the master API key here, on the argument
	// that losing the SBOM was worse than using the older credential;
	// that trade was inverted and the fallback removed, so the scan now
	// fails closed instead of putting the fleet-wide key inside a pod
	// built to process untrusted content.
	//
	// Failing closed is the right outcome and an invisible one: the
	// artifact keeps its previous status and the sweep re-queues it, so
	// a minter that is broken for everything looks like scans being
	// slightly slow. This counter is what makes it look like a problem.
	//
	// mintWithRetry has already absorbed the transient case before this
	// moves, so any sustained rate is a real failure, not a blip.
	scanTokenMintFailures atomic.Int64
	// scanDurations is the wall-clock time of the last few completed
	// full scans, oldest first -- the one thing in here that is not an
	// atomic, because it is the one thing that is not an independent
	// increment. A mean needs every sample in the window read as one
	// consistent set, which is exactly what the note above says no
	// reader needs and what atomics therefore cannot give; the lock is
	// taken once per completed scan and once per scrape, so it is
	// never contended.
	//
	// PROCESS state, not fleet state, like everything else here: these
	// are the last N scans THIS pod ran, not this artifact's history
	// and not the fleet's. A per-artifact duration series would put an
	// unbounded label set on an unauthenticated endpoint and disclose
	// the fleet's contents -- see the note at the top of this file.
	// The per-artifact numbers live on the artifact instead
	// (artifact.ScanDurationsMs) behind the authenticated API.
	durationsMu   sync.Mutex
	scanDurations []time.Duration
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

// recordScanDuration records one completed full scan's wall-clock time,
// dropping the oldest once the window is full. Called from runScan for
// successful AND failed scans alike, matching what LastScanAt records:
// a scan that timed out still took five minutes of this pod's life, and
// hiding that would make the mean look healthiest exactly when scans
// are grinding to a halt.
//
// An sbom-only re-evaluation never reaches here -- see the caller.
func (m *metrics) recordScanDuration(d time.Duration) {
	m.durationsMu.Lock()
	defer m.durationsMu.Unlock()
	m.scanDurations = append(m.scanDurations, d)
	if len(m.scanDurations) > artifact.ScanDurationWindow {
		m.scanDurations = m.scanDurations[len(m.scanDurations)-artifact.ScanDurationWindow:]
	}
}

// scanDurationStats returns the most recent scan's duration, the mean
// over the window, and how many samples that mean covers. n == 0 means
// no full scan has completed in this process yet, and the caller
// publishes nothing at all in that case rather than a zero -- "no scan
// has run" and "a scan took no time" must not look the same to an
// alert.
func (m *metrics) scanDurationStats() (last, mean time.Duration, n int) {
	m.durationsMu.Lock()
	defer m.durationsMu.Unlock()
	if len(m.scanDurations) == 0 {
		return 0, 0, 0
	}
	var total time.Duration
	for _, d := range m.scanDurations {
		total += d
	}
	n = len(m.scanDurations)
	return m.scanDurations[n-1], total / time.Duration(n), n
}

// recordAuth* are called from withAuth's rejection path only -- a
// successful authentication touches neither.
func (m *metrics) recordAuthFailure()   { m.authFailures.Add(1) }
func (m *metrics) recordAuthThrottled() { m.authThrottled.Add(1) }

// recordScanTokenMintFailure is called from runScan's error
// classification loop (scan.go), where every scan error from every
// layer already converges -- so counting there costs no new plumbing
// and cannot miss a path that reports the failure differently.
//
// Counted per FAILING SCANNER rather than per scan: two scanners
// failing to mint in one round is two failures, which is what a _total
// on a failure counter should mean and what rate() reads correctly.
func (m *metrics) recordScanTokenMintFailure() { m.scanTokenMintFailures.Add(1) }

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

	// The Prometheus convention for build metadata: a gauge fixed at 1
	// whose LABEL carries the information. That makes the value
	// useless and the label joinable -- `scm_build_info * on(instance)
	// group_left(version) ...` attributes any other series to a
	// specific commit, and a version change shows as a new series
	// rather than a value nobody can alert on.
	version := h.buildVersion
	if version == "" {
		version = "unknown"
	}
	fmt.Fprintf(w, "# HELP scm_build_info The commit this binary was built from.\n# TYPE scm_build_info gauge\nscm_build_info{version=%q} 1\n", version)

	counter("scm_scans_started_total", "Scans started since process start.", h.metrics.scansStarted.Load())
	counter("scm_scans_succeeded_total", "Scans that completed with at least one scanner succeeding.", h.metrics.scansSucceeded.Load())
	counter("scm_scans_failed_total", "Scans where every scanner failed, including panics.", h.metrics.scansFailed.Load())

	// One metric with a class label rather than five separate names, so
	// a query can sum over classes or pick one.
	fmt.Fprintf(w, "# HELP scm_http_responses_total HTTP responses by status class, excluding probe and scrape endpoints.\n# TYPE scm_http_responses_total counter\n")
	for class := 1; class < len(h.metrics.httpResponses); class++ {
		fmt.Fprintf(w, "scm_http_responses_total{class=\"%dxx\"} %d\n", class, h.metrics.httpResponses[class].Load())
	}

	counter("scm_scan_token_mint_failures_total", "Scans refused because the per-Job upload credential could not be minted. The scan fails closed rather than falling back to the master API key.", h.metrics.scanTokenMintFailures.Load())

	counter("scm_auth_failures_total", "Requests rejected with 401 because the API key was missing or wrong.", h.metrics.authFailures.Load())
	counter("scm_auth_throttled_total", "Requests refused with 429 because that client address had already failed authentication too often.", h.metrics.authThrottled.Load())

	// Published only once a scan has actually finished in this process:
	// a pod that has never scanned would otherwise report a flat 0 and
	// read as "scans are instant" rather than "there is nothing to
	// report". The window resets on restart, like every other value
	// here -- for history across restarts, graph these over time.
	if last, mean, n := h.metrics.scanDurationStats(); n > 0 {
		gauge("scm_scan_duration_seconds", "Wall-clock seconds the most recently completed full scan took in this process, successful or failed.", last.Seconds())
		// The NAME is a literal, not built from ScanDurationWindow: a
		// metric name is a contract with every dashboard and alert
		// that already references it, and generating it from the
		// constant means raising the window to 20 silently renames the
		// series and breaks them all with no error anywhere. Only the
		// HELP text tracks the constant.
		gauge(
			"scm_scan_duration_mean10_seconds",
			fmt.Sprintf("Mean wall-clock seconds over the last %d full scans completed in this process (fewer until %d have run).", artifact.ScanDurationWindow, artifact.ScanDurationWindow),
			mean.Seconds(),
		)
	}

	gauge("scm_process_uptime_seconds", "Seconds since this process started.", time.Since(h.metrics.startedAt).Seconds())
	gauge("go_goroutines", "Goroutines currently running.", float64(runtime.NumGoroutine()))
	gauge("go_memstats_heap_alloc_bytes", "Heap bytes allocated and in use.", float64(mem.HeapAlloc))
	gauge("go_memstats_sys_bytes", "Total bytes obtained from the OS.", float64(mem.Sys))
}
