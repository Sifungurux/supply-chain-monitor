package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
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
	// maxArtifacts caps how many artifacts may exist at once. <= 0 is
	// unlimited (the behaviour before this existed). See
	// RegistrationLimits.
	maxArtifacts int
	// scanCaps bounds concurrent scanning, per scanner kind plus a
	// global cap under artifact.GlobalScanSlotKind. Enforced through
	// the store (artifact.ScanSlotRequest), not in this process: the
	// buffered channel this replaced capped each REPLICA separately, so
	// two pods allowed twice the configured concurrency.
	scanCaps map[string]int
	// ready reports whether the backing store is usable right now, for
	// GET /readyz. nil means "nothing to check, always ready" -- see
	// Config.Ready for why this is a func rather than a Store method.
	ready func(context.Context) error
	// metrics holds the process counters GET /metrics exposes. Always
	// non-nil (NewRouter constructs one), so hot paths increment
	// without a nil check.
	metrics *metrics
	// fetcher resolves an sbom-type artifact's ref to a local file so
	// its components can be indexed after a scan (see
	// indexSBOMTypeComponents). nil disables that -- every test that
	// doesn't care about it, and any deployment without a registry
	// fetcher configured, behaves exactly as before it existed.
	fetcher scanner.Fetcher
	// licenseDenylist flags components whose license this deployment
	// refuses (LICENSE_DENYLIST). The zero value denies nothing, which
	// is what every caller that doesn't configure it gets.
	licenseDenylist scanner.LicenseDenylist
	// staleAfterDays is how long since an artifact's last scan before
	// it is reported as stale (SCAN_STALE_AFTER_DAYS). 0 switches the
	// warning off entirely.
	staleAfterDays int
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
	// Concurrency is the maximum number of scans running at once,
	// across every replica. <= 0 means unlimited, the same "a
	// nonsensical zero-or-negative value reads as off" convention
	// rateLimitRPS already uses.
	Concurrency int
	// PerKind caps concurrent scans of one scanner kind
	// (SCAN_CONCURRENCY_MALCONTENT and friends), keyed by
	// scanner.ScanKind's Kind(). A kind absent here inherits nothing --
	// it is bounded only by Concurrency, which is what every scanner
	// got before per-kind caps existed.
	//
	// The point is that the memory cost of a scan belongs to the TOOL:
	// malcontent has OOMKilled at 2-8Gi on ordinary images (README,
	// "malcontent") where trivy on the same image is fine, so one global
	// cap has to be set for the worst case and throttles everything
	// else with it.
	PerKind map[string]int
}

// caps flattens ScanLimits into the kind -> cap map the store's slot
// accounting takes, with the global cap stored under its pseudo-kind so
// one mechanism serves both instead of two that can disagree.
func (l ScanLimits) caps() map[string]int {
	out := make(map[string]int, len(l.PerKind)+1)
	for kind, n := range l.PerKind {
		out[kind] = n
	}
	if l.Concurrency > 0 {
		out[artifact.GlobalScanSlotKind] = l.Concurrency
	}
	return out
}

// tryAcquireScanSlots takes one slot for the global cap and one per
// distinct scanner kind this scan will run, all or nothing, and returns
// a release func plus the result.
//
// Non-blocking: scans are asynchronous (see scanArtifact), so there is
// no client waiting whose experience a short queue would improve -- a
// saturated cap answers 429 immediately, and the in-flight set stays
// hard-bounded with no server-side backlog to lose on a restart.
//
// All-or-nothing across kinds, so a scan is accepted or rejected as a
// unit. The alternative -- letting a scan start and skipping the
// scanner whose cap was full -- would be worse than a 429: a skipped
// scanner's bucket would have to be marked blocked or fix-detection
// would mark its findings "fixed" on a round where it never ran (see
// scan.go's blockedBuckets).
//
// The release func is always safe to call, including for a rejected
// acquisition: ReleaseScanSlots on a holder with no slots is a no-op,
// which is what lets every path release unconditionally.
func (h *handler) tryAcquireScanSlots(scanners []scanner.Scanner) (func(), artifact.ScanSlotResult, error) {
	holderID := newScanHolderID()
	kinds := []string{artifact.GlobalScanSlotKind}
	for _, s := range scanners {
		if k := scanner.KindOf(s); k != "" {
			kinds = append(kinds, k)
		}
	}

	release := func() {
		if err := h.store.ReleaseScanSlots(holderID); err != nil {
			// Logged, never propagated: the scan itself is done, and the
			// stale-slot reaping in AcquireScanSlots is the backstop
			// that stops a failed release from saturating a cap forever.
			slog.Error("could not release scan slots", "holder_id", holderID, "err", err)
		}
	}

	result, err := h.store.AcquireScanSlots(artifact.ScanSlotRequest{
		HolderID:   holderID,
		Kinds:      kinds,
		Caps:       h.scanCaps,
		StaleAfter: h.scanSlotStaleAfter(),
	})
	if err != nil || !result.Acquired {
		return release, result, err
	}
	return release, result, nil
}

// effectiveScanTimeout is the configured per-scan budget, or the
// default when unset. Shared by the scan itself and by the slot
// staleness threshold derived from it, so the two cannot drift into
// reaping a slot from a scan that is still legitimately running.
func (h *handler) effectiveScanTimeout() time.Duration {
	if h.scanTimeout <= 0 {
		return defaultScanTimeout
	}
	return h.scanTimeout
}

// scanSlotStaleAfter is how long a slot may sit before it is treated as
// abandoned. Derived from the scan timeout rather than fixed, and
// deliberately sitting BETWEEN two other timings:
//
//   - Above scanTimeout, or a slow-but-healthy scan would have its slot
//     reaped out from under it and a cap+1th scan could start -- the one
//     thing this whole mechanism exists to prevent.
//   - Below the sweep CronJob's own staleScanningAfter (20 minutes),
//     which reclaims artifacts stuck at "scanning" by re-scanning them.
//     If the slot outlived that, the reclaim's own POST /scan would be
//     429'd by the dead scan's slot and the artifact would stay stuck
//     for another sweep interval.
//
// With the 660s default that is 11m < 16m < 20m.
func (h *handler) scanSlotStaleAfter() time.Duration {
	return h.effectiveScanTimeout() + scanSlotReapMargin
}

// scanSlotReapMargin is the headroom over the scan timeout before a
// slot is considered abandoned -- see scanSlotStaleAfter.
const scanSlotReapMargin = 5 * time.Minute

// newScanHolderID tags one scan's slots so they can be released
// together and nothing else can free them.
func newScanHolderID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
		slog.Warn("digest resolution failed (continuing without dedup for this artifact)", "ref", ref, "err", err)
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

// healthz and readyz live in health.go -- see that file for why they
// are two different endpoints checking two different things.

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

// RegistrationLimits bounds how much a caller can put INTO this service,
// as opposed to ScanLimits which bounds what it does with what is
// already there. The zero value is unlimited, exactly the behaviour
// before this existed.
//
// Nothing bounded registration before: maxBulkArtifacts caps one
// request at 500 entries and the body limits cap bytes per request
// (see bodylimit.go), but a caller could repeat either indefinitely.
// Every artifact costs a row, findings, stage history, and a share of
// every List/ListPage the dashboard polls -- so "unbounded rows" is a
// slow resource leak with an authenticated client at the other end of
// it. Note the API key is a single shared one, so this is a bound on
// the deployment, not per-caller: there is no caller identity to meter.
type RegistrationLimits struct {
	// MaxArtifacts is the total number of artifacts allowed to exist.
	// Registrations that would exceed it are refused; deleting
	// artifacts frees the quota again. <= 0 means unlimited.
	MaxArtifacts int
}
