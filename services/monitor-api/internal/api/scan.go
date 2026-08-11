package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

const defaultScanTimeout = 5 * time.Minute

// scanArtifact starts a scan and returns 202 immediately -- it does not
// wait for the scan to finish. The scan runs in a background goroutine
// and the caller polls GET /api/v1/artifacts/{id} (the Location header
// points there) until status leaves "scanning".
//
// This used to block until every scanner finished, which never actually
// worked end to end: main.go's http.Server sets WriteTimeout, the
// deadline starts when the request headers are read, and a real scan
// runs 30-330s -- so the server tore down the connection before the
// response could be written and the caller saw a dropped connection
// (curl reports 000) for anything but the fastest scans. The work always
// completed server-side; only the answer was lost. Returning 202 up
// front means the response is written in milliseconds, well inside any
// write deadline, and "how do I learn the result" becomes a poll of the
// endpoint the dashboard already polls every 10s.
func (h *handler) scanArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	scanners, ok := h.scanners.For(a.Type)
	if !ok || len(scanners) == 0 {
		writeError(w, http.StatusNotImplemented, "no scanner registered for type "+string(a.Type))
		return
	}

	// Take a scan slot before touching anything -- deliberately after
	// the 404/501 checks above (a request that was never going to scan
	// shouldn't burn a slot) and before the status flips to "scanning"
	// (an artifact must never be left marked scanning by a request that
	// ended in a 429).
	//
	// Non-blocking now: the queue-then-reject wait this used to do only
	// existed because a client was blocked on the response. Nobody waits
	// any more, so either a slot is free or the caller is told to retry
	// -- which keeps the in-flight set hard-bounded by SCAN_CONCURRENCY
	// with no server-side backlog that a pod restart could silently drop.
	release, ok := h.tryAcquireScanSlot()
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(scanRetryAfter.Seconds())))
		// Names the scan cap specifically: withRateLimit answers 429 too,
		// and an operator reading a load-test log can't tell the two
		// apart from the status code alone.
		writeError(w, http.StatusTooManyRequests,
			fmt.Sprintf("scan concurrency limit reached (%d scans already in flight) -- retry shortly", cap(h.scanSlots)))
		return
	}

	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = artifact.StatusScanning
	})
	if err != nil {
		release()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The slot is released by runScan itself, not deferred here: it has
	// to travel with the work, or it would cap request duration
	// (milliseconds) instead of concurrent scans.
	go h.runScan(a, scanners, release)

	w.Header().Set("Location", "/api/v1/artifacts/"+id)
	writeJSON(w, http.StatusAccepted, updated)
}

// runScan is everything the old synchronous handler did after the status
// flip, minus the HTTP response. It owns the scan slot and must release
// it on every path, including a panic -- a leaked slot permanently
// shrinks the cap, and enough of them would stop scanning entirely.
func (h *handler) runScan(a *artifact.Artifact, scanners []scanner.Scanner, release func()) {
	defer release()
	defer func() {
		if rec := recover(); rec != nil {
			// Nothing is listening on an HTTP response any more, so an
			// unrecovered panic here would take the whole process down
			// rather than failing one request. Mark the artifact failed
			// and keep serving.
			log.Printf("scan for artifact %s panicked: %v", a.ID, rec)
			if _, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
				art.Status = artifact.StatusFailed
				art.LastScanErrors = []string{"scan panicked -- see server logs"}
			}); err != nil {
				log.Printf("could not mark artifact %s failed after a panic: %v", a.ID, err)
			}
		}
	}()

	id := a.ID

	// Deliberately NOT derived from any request context: the request
	// that started this scan has already been answered with a 202, and a
	// scan can legitimately run long (trivy's first-run vulnerability DB
	// download alone can take a couple of minutes). Tying it to a client
	// connection used to mean an interrupted browser SIGKILLed whatever
	// scanner was mid-run; now there is no connection to tie it to at
	// all. scanTimeout is the only bound.
	scanTimeout := h.scanTimeout
	if scanTimeout <= 0 {
		scanTimeout = defaultScanTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Every scanner registered for this artifact type runs concurrently,
	// not one after another: they're independent (each gets the same ref
	// and ctx, none depends on another's output), and a single shared
	// 5-minute budget above means a slow scanner used to eat directly
	// into every scanner after it in the list -- with trivy, unpacker,
	// and now an arbitrary number of operator-configured pluggable
	// scanners (see internal/scanner/pluggable.go) all potentially
	// registered for one type, that's no longer a two-scanner corner
	// case. Findings are sorted into one of five buckets by
	// classifyBucket below, exactly as before -- only *when* each
	// scanner runs changed, not what happens to what it returns.
	//
	// results is indexed by scanner position and only ever written to
	// by the one goroutine that owns that index, so no shared-state
	// synchronization (mutex/channel) is needed for the writes
	// themselves -- distinct slice elements are independent memory, and
	// wg.Wait() below is the one synchronization point that has to
	// happen before anything reads results.
	type scanResult struct {
		findings []artifact.Finding
		err      error
	}
	results := make([]scanResult, len(scanners))
	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Add(1)
		go func(i int, s scanner.Scanner) {
			defer wg.Done()
			// A panic from a Scanner implementation (in-process code, or
			// a bug surfaced by an operator's own PluggableScanner
			// command) must not take down the whole monitor-api
			// process just because it now runs on its own goroutine
			// rather than inline in this request's handler goroutine --
			// net/http's per-connection panic recovery only covers the
			// handler goroutine itself, not goroutines a handler spawns.
			// Recovered as an ordinary scan error instead: exactly as
			// safe as a scanner returning an error, just no longer
			// fatal to every other in-flight request.
			defer func() {
				if r := recover(); r != nil {
					results[i] = scanResult{err: fmt.Errorf("scanner panicked: %v", r)}
				}
			}()
			var findings []artifact.Finding
			var scanErr error
			if aware, ok := s.(scanner.ArtifactAwareScanner); ok {
				findings, scanErr = aware.ScanForArtifact(ctx, a.Ref, a.ID)
			} else {
				findings, scanErr = s.Scan(ctx, a.Ref)
			}
			results[i] = scanResult{findings: findings, err: scanErr}
		}(i, s)
	}
	wg.Wait()

	var cveFindings, malwareFindings, misconfigFindings, secretFindings, otherFindings []artifact.Finding
	var scanErrors []string

	for _, res := range results {
		if res.err != nil {
			scanErrors = append(scanErrors, res.err.Error())
		}
		for _, f := range res.findings {
			switch classifyBucket(f) {
			case "malware":
				malwareFindings = append(malwareFindings, f)
			case "misconfiguration":
				misconfigFindings = append(misconfigFindings, f)
			case "secret":
				secretFindings = append(secretFindings, f)
			case "other":
				otherFindings = append(otherFindings, f)
			default: // "cve"
				cveFindings = append(cveFindings, f)
			}
		}
	}

	status := artifact.StatusScanned
	if len(scanErrors) == len(scanners) {
		status = artifact.StatusFailed
	}

	// Every scan error, from whichever layer it originated at (an
	// in-process scanner, a scan-worker Job's own orchestration
	// failure, a pre-scan fetch, a recovered panic -- see
	// scanner.ClassifyScanError's own comment for why this is the one
	// place all of those converge), gets classified here rather than
	// stored raw: raw text is a multi-line trivy/k8s dump nobody but an
	// operator reading server logs should ever see. The raw string is
	// still logged server-side (kubectl logs / this pod's own stdout)
	// so nothing is lost, just kept out of the API response and
	// dashboard. failureReason picks the single most-specific reason
	// across every failed scanner this round (classifyReasonRank),
	// and is only meaningful -- so only persisted -- when every scanner
	// failed (status == StatusFailed); a partial failure's LastScanErrors
	// still gets the friendly per-scanner messages, but LastScanFailureReason
	// stays cleared, matching "this scan overall still counts as
	// scanned."
	cleanErrors := make([]string, len(scanErrors))
	var failureReason string
	for i, raw := range scanErrors {
		log.Printf("scan error for artifact %s: %s", a.ID, raw)
		reason, message := scanner.ClassifyScanError(raw)
		cleanErrors[i] = message
		if failureReason == "" || scanner.ReasonRank(reason) < scanner.ReasonRank(failureReason) {
			failureReason = reason
		}
	}
	scanErrors = cleanErrors
	if status != artifact.StatusFailed {
		failureReason = ""
	}

	// blockedBuckets gates, per bucket, whether MergeFindings is allowed
	// to mark anything as fixed this round -- a bucket in this set had
	// at least one scanner fail that could have contributed to it, so a
	// missing finding there can't be trusted as "actually fixed" rather
	// than "the scanner that would have reported it just didn't run."
	//
	// A scanner that implements scanner.BucketAffinity (TrivyScanner,
	// SBOMScanner, ClamAVScanner, UnpackerScanner, and their isolated
	// equivalents -- see each one's own Bucket() comment) only blocks
	// the one bucket it declared on failure: a ClamAV error no longer
	// blocks CVE fix-detection just because it happened in the same
	// round. A scanner that *doesn't* implement it (SARIFScanner, an
	// operator's PluggableScanner) blocks every bucket on failure,
	// exactly like every scanner used to before this existed -- neither
	// can honestly promise which bucket(s) it would have affected
	// (SARIF mixes categories in one document; a PluggableScanner's own
	// wire contract lets each finding set its own category independent
	// of any configured default), so guessing would risk a real false
	// "fixed" instead of just being coarse. See merge.go's own doc
	// comment for what "fixed" means once a bucket isn't blocked.
	blockedBuckets := make(map[string]bool)
	for i, res := range results {
		if res.err == nil {
			continue
		}
		if ba, ok := scanners[i].(scanner.BucketAffinity); ok {
			if b := ba.Bucket(); validFindingsBucket(b) {
				blockedBuckets[b] = true
				continue
			}
		}
		for _, b := range []string{"cve", "malware", "misconfiguration", "secret", "other"} {
			blockedBuckets[b] = true
		}
	}
	detectFixedFor := func(bucket string) bool { return !blockedBuckets[bucket] }

	// Backfill a missing digest opportunistically on every scan -- see
	// resolveDigest's own comment for why registration-time resolution
	// can fail (rate-limited/unreachable registry) and never retries on
	// its own once that request returns. A routine scan of an already-
	// registered artifact is a natural, low-cost second chance to fill
	// it in later, using the exact same best-effort helper createArtifact
	// uses. Resolved here (before store.Update below, not inside its
	// closure) since this can take up to digestResolveTimeout (8s) of
	// real network I/O, which shouldn't happen while holding whatever
	// lock/transaction Update takes. A no-op when a.Digest is already
	// set (digest just passes through unchanged) or resolution fails
	// again (digest stays "", same as before this scan).
	digest := a.Digest
	if digest == "" {
		// context.Background(), not a request context: the HTTP request
		// that started this scan returned 202 long ago.
		digest = h.resolveDigest(context.Background(), a.Ref, a.Type)
	}

	now := time.Now().UTC()
	// Two CVE scanners (trivy, grype) can both report the same CVE ID in
	// one round -- coalesce their Source values into one finding before
	// merging, so the second scanner's result doesn't just overwrite the
	// first's Source. Malware/misconfig/secret/other buckets only ever
	// have one scanner each today, so they don't need this.
	cveFindings = artifact.CoalesceSameIDSources(cveFindings)
	updated, updErr := h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = status
		art.Digest = digest
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, cveFindings, now, detectFixedFor("cve"))
		art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, malwareFindings, now, detectFixedFor("malware"))
		art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, misconfigFindings, now, detectFixedFor("misconfiguration"))
		art.SecretFindings = artifact.MergeFindings(art.SecretFindings, secretFindings, now, detectFixedFor("secret"))
		art.OtherFindings = artifact.MergeFindings(art.OtherFindings, otherFindings, now, detectFixedFor("other"))
		art.LastScanErrors = scanErrors
		art.LastScanFailureReason = failureReason
		art.LastScanAt = &now
	})
	if updErr != nil {
		// Nobody to return a 500 to -- the artifact is left at whatever
		// the store last persisted (status "scanning"), which the sweep
		// CronJob reclaims once it goes stale.
		log.Printf("could not persist scan results for artifact %s: %v", id, updErr)
		return
	}
	log.Printf("scan finished for artifact %s (%s): status=%s, %d scan error(s)", id, updated.Ref, updated.Status, len(updated.LastScanErrors))

	h.notifyNewFindings(updated, now)
}

// notifyNewFindings fires the configured notifiers when this scan round
// introduced findings at or above the configured severity threshold.
//
// "New this round" is decided by FirstSeenAt == roundStamp, not by
// anything recomputed here: MergeFindings (merge.go) is the single place
// that decides whether a reported finding is brand new, still open, or
// newly fixed, and it stamps genuinely-new findings with exactly the
// timestamp passed to it. Comparing against that stamp reuses that one
// decision instead of second-guessing it -- a finding carried over from
// a previous scan keeps its original FirstSeenAt and so is correctly
// ignored here, including one that went fixed and came back.
//
// Delivery is fire-and-forget on its own goroutine: notifications are
// not part of a scan's result. A slow or broken receiver must not delay
// the scan's own completion, and a panicking Notifier must not take the
// process down -- runScan's recover covers its own goroutine, not the
// ones spawned here.
func (h *handler) notifyNewFindings(a *artifact.Artifact, roundStamp time.Time) {
	if len(h.notifiers) == 0 {
		return
	}
	threshold := h.notifyMinSeverity
	if threshold == "" {
		threshold = notify.DefaultMinSeverity
	}

	var newFindings []artifact.Finding
	for _, bucket := range [][]artifact.Finding{
		a.CVEFindings, a.MalwareFindings, a.MisconfigFindings, a.SecretFindings, a.OtherFindings,
	} {
		for _, f := range bucket {
			if f.Status != artifact.FindingStatusOpen || !f.FirstSeenAt.Equal(roundStamp) {
				continue
			}
			if notify.AtOrAbove(f.Severity, threshold) {
				newFindings = append(newFindings, f)
			}
		}
	}
	if len(newFindings) == 0 {
		return
	}

	event := notify.ScanEvent{
		ArtifactID:  a.ID,
		ArtifactRef: a.Ref,
		NewFindings: newFindings,
		Severity:    notify.Worst(newFindings),
	}
	log.Printf("scan for artifact %s introduced %d new finding(s) at or above %q -- notifying %d destination(s)",
		a.ID, len(newFindings), threshold, len(h.notifiers))

	for _, n := range h.notifiers {
		go func(n notify.Notifier) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("notifier panicked for artifact %s: %v", a.ID, rec)
				}
			}()
			// Its own context, not the scan's: the scan's is already
			// cancelled by the time this runs (runScan defers cancel).
			ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
			defer cancel()
			// Error deliberately discarded -- notifiers log their own
			// failures, and a failed notification is not a failed scan.
			_ = n.Notify(ctx, event)
		}(n)
	}
}

// notifyTimeout bounds one notifier's whole attempt, including its
// internal retry. Comfortably above the per-attempt HTTP timeout in
// internal/notify so a retry isn't cut off mid-flight.
const notifyTimeout = 30 * time.Second

// classifyBucket decides which of the five finding buckets (cve,
// malware, misconfiguration, secret, other) a scanner's finding
// belongs in.
//
// A Scanner that already knows its own category -- currently just
// SARIFScanner, since a single SARIF document can mix CVEs, IaC
// misconfigurations, secrets, and generic SAST issues all in one file
// -- sets Finding.Category directly (see internal/scanner/sarif.go's
// classifySarifCategory), and that's authoritative here. Most
// scanners (TrivyScanner, ClamAVScanner, ...) each only ever produce
// one kind of result and don't bother setting it, so this falls back
// to the original Source-based heuristic: "clamav" is malware, "sarif"
// (with no Category set -- e.g. an older/adjacent SARIF-producing
// Scanner that hasn't been taught to classify itself) defaults to
// other rather than cve, since a SARIF result could be anything.
// Everything else defaults to cve (today just means "trivy", but
// stays open to future CVE-flavored scanners without another
// switch-case edit here).
func classifyBucket(f artifact.Finding) string {
	switch f.Category {
	case "cve", "malware", "misconfiguration", "secret", "other":
		return f.Category
	}
	switch f.Source {
	case "clamav":
		return "malware"
	case "sarif":
		return "other"
	default:
		return "cve"
	}
}
