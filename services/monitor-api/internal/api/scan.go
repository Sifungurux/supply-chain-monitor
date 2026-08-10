package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

const defaultScanTimeout = 5 * time.Minute

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
	// shouldn't sit in the queue, or occupy a slot) and before the
	// status flips to "scanning" (an artifact must never be left marked
	// scanning by a request that ended in a 429).
	//
	// `defer release()` caps concurrent *scans* only because this
	// handler is fully synchronous: wg.Wait() below joins every scanner
	// goroutine before this function returns. If scanning ever becomes
	// asynchronous (return 202, finish in the background), this defer
	// silently degrades into a cap on request duration instead -- the
	// release has to move with the work.
	release, err := h.acquireScanSlot(r.Context())
	if err != nil {
		if errors.Is(err, errScanQueueFull) {
			wait := h.scanQueueWait
			if wait <= 0 {
				wait = DefaultScanQueueWait
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
			// Names the scan cap specifically: withRateLimit answers 429
			// too, and an operator reading a load-test log can't tell the
			// two apart from the status code alone.
			writeError(w, http.StatusTooManyRequests,
				fmt.Sprintf("scan concurrency limit reached (%d scans already in flight) -- retry shortly", cap(h.scanSlots)))
			return
		}
		// The client hung up while queued -- there's nothing to write a
		// response to, and this is the only trace it happened.
		log.Printf("scan request for artifact %s abandoned while queued for a scan slot: %v", id, err)
		return
	}
	defer release()

	_, _ = h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = artifact.StatusScanning
	})

	// Deliberately NOT derived from r.Context(): a scan can legitimately
	// run long (trivy's first-run vulnerability DB download alone can
	// take a couple of minutes), and net/http cancels r.Context() the
	// moment the client connection goes away for any reason -- a closed
	// tab, a network hiccup, a proxy's idle timeout. Tying the scan to
	// that meant an interrupted browser connection would SIGKILL
	// whatever scanner was mid-run (surfacing as "signal: killed") and
	// instantly fail every scanner after it in the loop ("context
	// canceled"), even though nothing about the scan itself was wrong.
	// Using context.Background() here means the scan runs to completion
	// and updates the store regardless of what the original HTTP client
	// does; the dashboard's own polling picks up the result afterward
	// either way.
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
		digest = h.resolveDigest(r.Context(), a.Ref, a.Type)
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
		writeError(w, http.StatusInternalServerError, updErr.Error())
		return
	}

	if status == artifact.StatusFailed {
		writeJSON(w, http.StatusBadGateway, updated)
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

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
