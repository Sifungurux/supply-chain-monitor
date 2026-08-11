package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
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
	// notifiers receive a ScanEvent when a scan introduces new findings
	// at or above notifyMinSeverity. Empty (the default) means
	// notifications are off entirely -- see internal/notify.
	notifiers []notify.Notifier
	// notifyMinSeverity is the threshold a new finding must meet to be
	// worth notifying about ("critical" > "high" > "medium" > "low").
	// Compared case-insensitively -- scanners disagree on spelling, see
	// notify.SeverityRank.
	notifyMinSeverity string
	// notifyOnFirstScan opts INTO notifying for an artifact's first ever
	// scan. Phrased as the opt-in rather than the suppression so the
	// zero value (false = suppress) is the safe default: a handler built
	// without thinking about this behaves the way an operator would
	// want, instead of paging once per artifact through a backlog. The
	// chart exposes it the other way round (suppressFirstScan: true),
	// which reads better as a setting.
	notifyOnFirstScan bool
	// scanSlots caps how many scans run at once across the whole
	// process: one buffered slot per permitted concurrent scan, taken
	// for the duration of a scan and released when it finishes. nil
	// means unlimited (the behavior before this existed) -- see
	// ScanLimits and acquireScanSlot.
	scanSlots chan struct{}
}

// scanRetryAfter is the Retry-After (seconds) sent with the 429 a
// saturated scan cap returns. Advisory: a scan runs for minutes, so
// there is no exact right answer -- short enough that a caller retrying
// on it makes progress as slots free up, without hammering.
const scanRetryAfter = 10 * time.Second

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
}

// tryAcquireScanSlot takes a scan slot if one is free right now, and
// reports whether it got one. Non-blocking on purpose: scans are
// asynchronous (see scanArtifact), so there is no client waiting whose
// experience a short queue would improve -- a saturated cap answers 429
// immediately, and the in-flight set stays hard-bounded with no
// server-side backlog to lose on a restart.
//
// (This replaced a queue-then-reject wait that existed only because the
// caller used to block on the response. That wait had to be kept below
// main.go's http.Server WriteTimeout or its own 429 raced the write
// deadline -- a constraint asynchronous scanning removes outright, since
// every response is now written in milliseconds.)
func (h *handler) tryAcquireScanSlot() (func(), bool) {
	if h.scanSlots == nil {
		return func() {}, true
	}
	select {
	case h.scanSlots <- struct{}{}:
		return func() { <-h.scanSlots }, true
	default:
		return nil, false
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

// Notifications configures outbound scan notifications. The zero value
// disables them: no notifiers means scanArtifact's notify step is
// skipped entirely, which is exactly how the service behaved before
// this existed.
type Notifications struct {
	Notifiers []notify.Notifier
	// MinSeverity is the threshold a NEW finding must meet before
	// anything is sent. Empty means notify.DefaultMinSeverity.
	MinSeverity string
	// NotifyOnFirstScan sends notifications for an artifact's first ever
	// scan as well. The zero value (false) suppresses them, which is the
	// default and the reason this is expressed as an opt-in: on a first
	// scan every finding is "new" only because nobody had looked before,
	// so enabling notifications on an existing deployment would page
	// once per already-registered artifact as the sweep drains the
	// backlog.
	//
	// Set it when you do want that -- a deployment where every artifact
	// is registered and scanned once at import time, where the first
	// scan IS the interesting event.
	NotifyOnFirstScan bool
}
