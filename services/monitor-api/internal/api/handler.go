package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

type handler struct {
	store    artifact.Store
	tracker  *pipeline.Tracker
	scanners scanner.Registry
	// digestResolver and fetchPlainHTTP power best-effort duplicate-
	// registration detection (see resolveDigest below, and
	// createArtifact/bulkCreateArtifacts in artifacts.go) --
	// digestResolver is nil in tests that don't care about this (see
	// newTestRouter), which resolveDigest treats as "dedup disabled,"
	// not an error.
	digestResolver scanner.DigestResolver
	fetchPlainHTTP bool
	// scanTimeout bounds the shared budget scanArtifact gives every
	// scanner registered for one artifact type (see that method's own
	// comment on why it's deliberately not derived from r.Context()).
	// Must be configured >= the isolated scan-worker Jobs' own
	// ActiveDeadlineSeconds (main.go validates this at startup) --
	// otherwise this handler routinely gives up and reports "context
	// deadline exceeded" before Kubernetes' own ActiveDeadlineSeconds
	// would even have killed a genuinely stuck Job, which is exactly
	// what a heavier image (more OS packages for trivy to walk/query --
	// e.g. mysql/postgres-sized images) under concurrent scan load looks
	// like: still legitimately running, not actually stuck. Falls back
	// to 5 minutes if zero (e.g. in tests that don't care about this).
	scanTimeout time.Duration
	// requireDigest is monitorApi.requireDigest / REQUIRE_DIGEST -- see
	// NewRouter's own comment for the full behavior this gates.
	requireDigest bool
	// scanSlots caps how many scans run at once across the whole
	// process: one buffered slot per permitted concurrent scan, taken
	// for the duration of a scan and released when it finishes. nil
	// means unlimited (the behavior before this existed) -- see
	// ScanLimits and acquireScanSlot.
	scanSlots chan struct{}
	// scanQueueWait bounds how long a scan request waits for a slot
	// before giving up with a 429. Falls back to
	// DefaultScanQueueWait if zero.
	scanQueueWait time.Duration
}

// DefaultScanQueueWait is how long a scan request waits for a free slot
// before being rejected. Long enough that a burst slightly wider than
// the cap (the dashboard's Scan buttons clicked in quick succession,
// cluster/load-test-clamav.sh's PARALLELISM) mostly just queues and
// succeeds; short enough that a genuinely saturated server sheds load
// instead of accumulating connections that will each wait out a
// multi-minute scan.
//
// It must stay comfortably BELOW main.go's http.Server WriteTimeout,
// and that ceiling is the whole reason this isn't 30s: WriteTimeout
// starts when the request headers are read, so a request that waits the
// full queue wait and only then writes its 429 races the write deadline
// -- and loses. At 30s against a 30s WriteTimeout the 429 was never
// observable at all: a rejected client saw a dropped connection
// (curl reports 000) instead of the status code and Retry-After it was
// supposed to act on. Measured in-cluster, not theorized. main_test.go
// asserts the relationship so a future edit to either value fails a
// test rather than silently making rejections invisible again.
const DefaultScanQueueWait = 10 * time.Second

// errScanQueueFull means the wait above elapsed with every scan slot
// still busy -- distinct from ctx.Err(), which means the client gave up
// on its own while queued.
var errScanQueueFull = errors.New("scan queue full")

// ScanLimits bounds concurrent scanning. Zero value = unlimited, which
// is exactly the behavior every caller had before this existed.
//
// This exists because nothing server-side bounded concurrent scans:
// each one spawns an isolated scan-worker Job that extracts the whole
// image under scan to disk (up to ~2.4Gi -- see
// charts/supply-chain-monitor's scan-Job ephemeral sizing), so the only
// thing standing between the cluster and node-level disk exhaustion was
// however many scans a client chose to fire at once.
type ScanLimits struct {
	// Concurrency is the maximum number of scans running at once.
	// <= 0 means unlimited, the same "a nonsensical zero-or-negative
	// value reads as off" convention rateLimitRPS already uses.
	Concurrency int
	// QueueWait is how long a scan waits for a free slot before a 429.
	// <= 0 means DefaultScanQueueWait, matching how scanTimeout treats
	// a zero value.
	QueueWait time.Duration
}

// acquireScanSlot blocks until a scan slot is free, the queue wait
// elapses (errScanQueueFull -> the caller should answer 429), or ctx is
// done (the client hung up while queued -- there's nobody left to
// answer, so the slot is deliberately never taken). Returns the
// function that releases the slot.
//
// ctx here is the *request* context, unlike the scan itself, which
// deliberately runs on context.Background() so a disconnect can't kill
// a scan already in progress (see scanArtifact). Watching it while
// merely queued is the opposite case: nothing has started yet, so a
// client that walked away should free its place rather than have a scan
// run for it anyway.
func (h *handler) acquireScanSlot(ctx context.Context) (func(), error) {
	if h.scanSlots == nil {
		return func() {}, nil
	}
	wait := h.scanQueueWait
	if wait <= 0 {
		wait = DefaultScanQueueWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case h.scanSlots <- struct{}{}:
		return func() { <-h.scanSlots }, nil
	case <-timer.C:
		return nil, errScanQueueFull
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// digestResolveTimeout bounds how long a single registry manifest call
// can take during registration. Registration used to be instant and
// dependency-free (no network call at all -- see docs/architecture.md);
// this is what keeps a slow or hanging registry from turning that into
// a hung request instead of just skipping dedup for that one entry.
const digestResolveTimeout = 8 * time.Second

// resolveDigest is best-effort: it never returns an error. "" means "no
// digest available" -- digestResolver not configured, ref is a local
// path (not a registry reference), or resolution failed for any reason
// (unreachable/rate-limited registry, retagged or missing ref). A real
// failure is logged here and nowhere else -- callers should never treat
// an empty result as a reason to fail the registration it's part of
// (see Artifact.Digest's own comment).
func (h *handler) resolveDigest(ctx context.Context, ref string, t artifact.Type) string {
	if h.digestResolver == nil {
		return ""
	}
	// Image refs point at real, HTTPS-by-default registries (Docker
	// Hub, ghcr.io, ...). FETCH_PLAIN_HTTP only ever describes the one
	// local, unauthenticated scm-registry that file/sbom/sarif
	// registry refs point at (see RegistryFetcher's own comment) --
	// applying it to image refs too would mean trying plain HTTP
	// against a real registry and failing every single time.
	plainHTTP := t != artifact.TypeImage && h.fetchPlainHTTP

	rctx, cancel := context.WithTimeout(ctx, digestResolveTimeout)
	defer cancel()
	digest, err := h.digestResolver.Resolve(rctx, ref, plainHTTP)
	if err != nil {
		log.Printf("digest resolution failed for %q (continuing without dedup for this artifact): %v", ref, err)
		return ""
	}
	return digest
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
