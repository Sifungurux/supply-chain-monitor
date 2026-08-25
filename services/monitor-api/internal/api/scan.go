package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

const defaultScanTimeout = 5 * time.Minute

// Scan modes, selected by the `mode` query parameter on POST
// /api/v1/artifacts/{id}/scan.
//
// scanModeFull is the default and is what this endpoint has always
// done: every scanner registered for the artifact's type.
//
// scanModeSBOMOnly re-derives CVEs for an `image` artifact from the
// SBOM document a previous full scan already stored, against today's
// vulnerability DB -- no image pull, no unpack, no malware scan. It is
// a CHEAP REFRESH OF ONE BUCKET, not a scan, and everything below that
// treats it differently follows from that one sentence.
const (
	scanModeFull     = "full"
	scanModeSBOMOnly = "sbom-only"
)

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

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = scanModeFull
	}
	if mode != scanModeFull && mode != scanModeSBOMOnly {
		writeError(w, http.StatusBadRequest, "unknown scan mode "+mode+" (want "+scanModeFull+" or "+scanModeSBOMOnly+")")
		return
	}

	// Re-validate the ref at scan time, not just at registration.
	//
	// Registration has refused inward-pointing refs since ValidateRef
	// landed, but rows created BEFORE that are still in the database
	// with whatever ref they were registered with -- and an `image`
	// artifact never goes through Fetch or Resolve, the two places that
	// carry their own check. trivy/grype/unpacker pull the image
	// themselves, straight from wherever the ref points, so without this
	// a pre-existing row is still a way to make this service connect
	// somewhere it should not.
	//
	// Refused here, before the status flips to "scanning", so the
	// artifact keeps whatever status it already had and its findings are
	// left completely alone. That matters more than it looks: the
	// alternative (fail inside runScan) would run MergeFindings with no
	// scanner results, and a bucket that is not blocked would mark every
	// existing finding "fixed" -- turning a refused scan into silent
	// data loss.
	//
	// 400 rather than a quieter status: the ref is the problem, the
	// caller supplied it, and re-registering or deleting the artifact is
	// the fix. A scan that cannot legally run should say so out loud.
	if err := scanner.ValidateRef(r.Context(), a.Ref); err != nil {
		writeError(w, http.StatusBadRequest, "refusing to scan: "+err.Error())
		return
	}

	scanners, ok := h.scanners.For(a.Type)
	if !ok || len(scanners) == 0 {
		writeError(w, http.StatusNotImplemented, "no scanner registered for type "+string(a.Type))
		return
	}

	if mode == scanModeSBOMOnly {
		// EVERY refusal here is a refusal, never a quiet fall back to a
		// full scan. This mode exists to be cheap; silently upgrading it
		// would turn one nightly CronJob into a full re-scan of the
		// whole fleet -- exactly the IO the caller asked to avoid, and
		// invisible in the sweep's own logs.
		if a.Type != artifact.TypeImage {
			writeError(w, http.StatusBadRequest, "sbom-only scans apply to image artifacts, not "+string(a.Type))
			return
		}
		if !a.HasSBOM {
			// Not an error state: an image registered but never fully
			// scanned has no SBOM yet, and the full sweep is what gets
			// it one. 409 rather than 400 -- the request is well-formed,
			// the artifact just is not ready for it.
			writeError(w, http.StatusConflict, "artifact has no stored SBOM document to re-evaluate -- a full scan generates one")
			return
		}
		if h.sbomReeval == nil {
			writeError(w, http.StatusNotImplemented, "sbom re-evaluation is not configured on this deployment")
			return
		}
		scanners = []scanner.Scanner{h.sbomReeval}
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
	release, slots, err := h.tryAcquireScanSlots(scanners)
	if err != nil {
		release()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !slots.Acquired {
		release()
		w.Header().Set("Retry-After", strconv.Itoa(int(scanRetryAfter.Seconds())))
		// Names the cap that actually refused, not just "concurrency":
		// withRateLimit answers 429 too, and an operator reading a
		// load-test log needs to know whether to raise SCAN_CONCURRENCY
		// or SCAN_CONCURRENCY_MALCONTENT.
		writeError(w, http.StatusTooManyRequests, scanCapMessage(slots))
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
	go h.runScan(a, scanners, release, mode)

	w.Header().Set("Location", "/api/v1/artifacts/"+id)
	writeJSON(w, http.StatusAccepted, updated)
}

// runScan scans, then mirrors -- in that order, and with the scan slot
// held only for the first half.
//
// MIRRORING AFTER THE SCAN, NOT BEFORE, IS THE WHOLE POINT OF THE SPLIT.
// A copy is a full pull-and-push bounded by mirrorTimeout; run inside
// the slot it would, on any artifact whose copy is slow or failing (an
// unreachable registry, a full PVC, credentials without push), hold that
// slot for up to fifteen minutes without scanning anything -- and the
// sweep CronJob would re-enter it every fifteen minutes on every
// un-mirrored artifact at once, jamming the cap with work that produces
// no findings.
//
// Scanning first costs one upstream pull on an artifact's FIRST scan,
// which is exactly what happens today; every scan after it reads the
// mirrored ref and never leaves the cluster.
func (h *handler) runScan(a *artifact.Artifact, scanners []scanner.Scanner, release func(), mode string) {
	h.scanHoldingSlot(a, scanners, release, mode)
	if mode == scanModeSBOMOnly {
		// No mirroring on a re-evaluation. Mirroring is a full
		// pull-and-push of the artifact -- the single most expensive
		// thing this service does, and the exact IO an sbom-only round
		// exists to avoid. It is also converging work owned by the full
		// sweep (SWEEP_MIRROR_BACKFILL), so skipping it here delays
		// nothing: the next full scan still settles source_ref.
		return
	}
	// Deliberately not derived from any request context, and outside the
	// slot: see mirrorArtifact, which is also what registration calls.
	// This is the backfill path -- bulk-registered artifacts, artifacts
	// that predate the feature, and copies that failed last time.
	h.mirrorArtifact(context.Background(), a)
}

// scanHoldingSlot is everything the old synchronous handler did after
// the status flip, minus the HTTP response. It owns the scan slot and
// must release it on every path, including a panic -- a leaked slot
// permanently shrinks the cap, and enough of them would stop scanning
// entirely.
func (h *handler) scanHoldingSlot(a *artifact.Artifact, scanners []scanner.Scanner, release func(), mode string) {
	defer release()
	// See scanModeSBOMOnly. Read once into a local so every branch below
	// asks the same question the same way.
	sbomOnly := mode == scanModeSBOMOnly
	// Counted here rather than in scanArtifact: this is the funnel every
	// scan actually passes through, and a request that was rejected
	// (bad type, saturated cap) never started a scan to count.
	//
	// AN SBOM-ONLY ROUND IS NOT COUNTED, consistent with it not
	// setting a status or stamping the scan clock -- it is a refresh
	// of one bucket, not a scan. The concrete reason is the
	// ScanFailureRate alert, which compares
	// rate(scm_scans_failed_total) against
	// rate(scm_scans_succeeded_total): a nightly fleet-wide burst of
	// re-evaluations lands in one 30m window and would move that
	// ratio, diluting a genuine run of scan failures happening at the
	// same time. A broken re-evaluation is reported by its own
	// CronJob's exit status and run summary, and per-artifact in
	// LastScanErrors.
	if !sbomOnly {
		h.metrics.recordScanStarted()
	}
	defer func() {
		if rec := recover(); rec != nil {
			// Nothing is listening on an HTTP response any more, so an
			// unrecovered panic here would take the whole process down
			// rather than failing one request. Mark the artifact failed
			// and keep serving.
			slog.Error("scan panicked", "artifact_id", a.ID, "err", rec)
			// A panic short-circuits the normal outcome below, so it has
			// to record its own -- otherwise started would outrun
			// succeeded+failed by exactly the number of panics, which is
			// the one failure mode nobody would think to look for.
			// Skipped for an sbom-only round, which recorded no start.
			if !sbomOnly {
				h.metrics.recordScanResult(true)
			}
			if _, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
				art.Status = artifact.StatusFailed
				art.LastScanErrors = []string{"scan panicked -- see server logs"}
			}); err != nil {
				slog.Error("could not mark artifact failed after a panic", "artifact_id", a.ID, "err", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), h.effectiveScanTimeout())
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
		// raw is the scanner's own report, kept only when this scan can
		// derive documents from it -- see captureDocuments below.
		raw []byte
		// provenance is the verdict a ProvenanceScanner reached,
		// carried back WITH its findings rather than read off the
		// scanner afterwards: one scanner instance is shared by every
		// artifact and these goroutines run concurrently, so a field on
		// the scanner would let one artifact's verdict be read for
		// another.
		provenance, provenanceTrustRoot string
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
			var rawReport []byte
			var provenance, provenanceTrustRoot string
			switch impl := s.(type) {
			case scanner.ProvenanceScanner:
				// Reports a VERDICT as well as findings. "Verified" has
				// no natural representation as a finding -- emitting one
				// per signed image would bury the unsigned ones -- so
				// without this a signed image is indistinguishable from
				// this scanner being switched off.
				// provenanceRef, not a.Ref: a mirrored copy does not
				// carry cosign's sibling .sig tag, and the signature was
				// made about the original identity anyway. See
				// mirror.go's provenanceRef.
				findings, provenance, provenanceTrustRoot, scanErr = impl.ScanProvenance(ctx, provenanceRef(a))
			case scanner.ArtifactAwareScanner:
				// Isolated scanners: the Job uploads its own documents
				// back through POST /documents (main.go's
				// captureImageDocuments), so nothing to capture here.
				findings, scanErr = impl.ScanForArtifact(ctx, a.Ref, a.ID)
			case scanner.RawImageScanner:
				// In-process, image only. Gated on the artifact TYPE as
				// well as the interface: this report is an image trivy
				// report, and GenerateImageDocuments converts nothing
				// else. A file/sbom/sarif scanner reaching here would
				// produce garbage documents rather than none.
				if a.Type == artifact.TypeImage {
					findings, rawReport, scanErr = impl.ScanWithRaw(ctx, a.Ref)
				} else {
					findings, scanErr = impl.Scan(ctx, a.Ref)
				}
			default:
				findings, scanErr = s.Scan(ctx, a.Ref)
			}
			results[i] = scanResult{findings: findings, err: scanErr, raw: rawReport,
				provenance: provenance, provenanceTrustRoot: provenanceTrustRoot}
		}(i, s)
	}
	wg.Wait()

	var cveFindings, malwareFindings, misconfigFindings, secretFindings, otherFindings []artifact.Finding
	var scanErrors []string
	// Stays ProvenanceUnknown when no ProvenanceScanner ran, which is
	// exactly the right record: not verified, not unsigned, not checked.
	provenance, provenanceTrustRoot := artifact.ProvenanceUnknown, ""

	for _, res := range results {
		if res.err != nil {
			scanErrors = append(scanErrors, res.err.Error())
		}
		if res.provenance != artifact.ProvenanceUnknown {
			provenance, provenanceTrustRoot = res.provenance, res.provenanceTrustRoot
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
	// "Failed" here means EVERY scanner failed, matching the status the
	// artifact gets -- a partial failure is a successful scan that
	// recorded scan errors, and counting it as failed would make the
	// failure rate track "any scanner had a bad day" instead of "this
	// scan produced nothing".
	if !sbomOnly {
		h.metrics.recordScanResult(status == artifact.StatusFailed)
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
		slog.Warn("scan error", "artifact_id", a.ID, "err", raw)
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
		// MultiBucketAffinity first: TrivyScanner produces CVEs AND
		// secrets from one `trivy image --scanners vuln,secret` run, so
		// its failure has to block both. Preferred over BucketAffinity
		// when a scanner somehow offers both, since the multi-bucket
		// answer is the complete one.
		if mba, ok := scanners[i].(scanner.MultiBucketAffinity); ok {
			// An EMPTY result falls through to the checks below rather
			// than blocking nothing -- FetchingScanner implements this
			// unconditionally and returns nil when the scanner it wraps
			// has no multi-bucket opinion, so "no buckets" here means
			// "no answer", never "this failure is harmless".
			if bs := mba.Buckets(); len(bs) > 0 && allValidFindingsBuckets(bs) {
				for _, b := range bs {
					blockedBuckets[b] = true
				}
				continue
			}
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
	detectFixedFor := func(bucket string) bool {
		// AN SBOM-ONLY ROUND MAY NEVER MARK ANYTHING FIXED.
		//
		// It runs one scanner -- grype against the stored SBOM -- and
		// reports only what that finds. But the cve bucket it is
		// merging into was built by whatever CVE_SCANNER selects, and
		// with "both" (the deployment default here) most of it comes
		// from trivy scanning the image filesystem directly. Measured
		// on this project's own fleet: 35,195 of 46,728 open CVE
		// findings are trivy-only, against 4,557 grype-only.
		//
		// With fix-detection on, every one of those trivy-only
		// findings is absent from the re-evaluation's results and so
		// gets marked "fixed" -- 75% of the bucket silently resolved,
		// nightly, on every artifact. Even a grype-only deployment
		// would lose findings, since image-mode grype and SBOM-mode
		// grype do not match identically.
		//
		// This is the SAME rule blockedBuckets already encodes: a
		// scanner that cannot honestly promise it would have reported
		// everything in a bucket must not let that bucket conclude
		// anything is resolved. The other four buckets express it by
		// skipping the merge entirely (see the store.Update below);
		// cve still needs merging -- that is how new CVEs and refreshed
		// KEV/EPSS annotations land -- so it expresses it here instead.
		//
		// The cost is that a genuinely-fixed CVE stays open until the
		// next FULL scan notices. That is the right trade: a stale
		// "open" is visible and self-corrects, a wrong "fixed" is
		// invisible and does not.
		if sbomOnly {
			return false
		}
		return !blockedBuckets[bucket]
	}

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
	if digest == "" && !sbomOnly {
		// context.Background(), not a request context: the HTTP request
		// that started this scan returned 202 long ago.
		//
		// Skipped entirely on an sbom-only round, which is the same
		// judgement the mirroring skip in runScan makes: this is a real
		// registry round-trip (up to digestResolveTimeout, 8s) per
		// artifact, the re-evaluation never writes the result anyway
		// (see the Update below), and digest backfill is converging
		// work the full sweep already owns. Nightly across a whole
		// fleet it would be the single most expensive thing the cheap
		// path does. `digest` therefore stays whatever the artifact
		// already has, which is exactly what fleetVEXFor wants.
		digest = h.resolveDigest(context.Background(), a.Ref)
	}

	now := time.Now().UTC()
	// Two CVE scanners (trivy, grype) can both report the same CVE ID in
	// one round -- coalesce their Source values into one finding before
	// merging, so the second scanner's result doesn't just overwrite the
	// first's Source. Malware/misconfig/secret/other buckets still have
	// only one scanner each per artifact type, so they don't need this.
	//
	// "Per artifact type" is now load-bearing wording. TrivyScanner
	// feeds two buckets (cve and secret, from one `--scanners
	// vuln,secret` run), so "one scanner per bucket" no longer follows
	// from "one bucket per scanner" the way it used to. It still holds:
	// for image artifacts trivy is the only secret producer, and
	// SARIFScanner -- the other thing that can emit Category "secret" --
	// is registered against the SARIF artifact type, never alongside
	// trivy. Coalescing would be a no-op regardless, since a secret
	// finding's ID is composed from trivy's own target/rule/line
	// (secretFindingID) and nothing else generates that shape. If a
	// second secret-producing scanner is ever registered for the same
	// type, this needs the same treatment the CVE bucket gets.
	cveFindings = artifact.CoalesceSameIDSources(cveFindings)

	// Enriched BEFORE the store.Update below, never inside its mutate
	// closure. MemStore.Update holds a write lock for the duration of
	// that closure and LookupEnrichment takes a read lock on the same
	// mutex, which sync.RWMutex does not allow to re-enter -- an
	// enrichment lookup in there deadlocks the whole request. (It went
	// unnoticed at first because every existing test builds a router
	// with no enricher, making the call a no-op.) Doing network/database
	// work while holding the store's lock would be wrong regardless.
	//
	// Enriching the INCOMING set is sufficient: MergeFindings copies
	// every field except the lifecycle ones from the reported finding,
	// so anything still open is re-enriched on each scan, and anything
	// no longer reported is being marked fixed anyway.
	//
	// A failure is logged and swallowed: enrichment is annotation, and
	// losing a scan's actual findings because a lookup failed would be
	// a far worse trade.
	if err := h.enrich(cveFindings); err != nil {
		slog.Warn("could not enrich findings with KEV/EPSS (scan result unaffected)",
			"artifact_id", a.ID, "err", err)
	}
	// A finding this scan is seeing for the first time can already be
	// covered by a VEX document uploaded earlier -- read it here so it
	// lands suppressed rather than paging somebody about a vulnerability
	// that was assessed weeks ago. Findings suppressed on a previous
	// round stay suppressed with or without this (see MergeFindings), so
	// a missing or unreadable document costs nothing already decided.
	//
	// Fleet documents (POST /api/v1/vex) are consulted alongside the
	// per-artifact one, and the per-artifact one is layered ON TOP: it
	// is the more specific claim, so an operator who assessed THIS
	// image is never overridden by a fleet statement about a package it
	// happens to contain.
	//
	// Layering rather than filtering is also what makes revocation work
	// across the two. MergeFindings revokes an earlier suppression when
	// it sees status "affected" (see its `revoked` branch), so a
	// per-artifact "affected" over a fleet "not_affected" un-suppresses
	// exactly as it would over a per-artifact one -- there is no
	// separate retraction path to keep in step.
	vex := h.fleetVEXFor(a, digest)
	if perArtifact := h.vexFor(id); len(perArtifact) > 0 {
		if vex == nil {
			vex = make(map[string]artifact.VEXStatement, len(perArtifact))
		}
		for vulnID, st := range perArtifact {
			vex[vulnID] = st
		}
	}
	updated, updErr := h.store.Update(id, func(art *artifact.Artifact) {
		if sbomOnly {
			// A re-evaluation does not change what we know about the
			// artifact's SCAN state, only about its CVEs, so it restores
			// the status the artifact already had instead of reporting
			// one of its own. Two things break if it does not:
			//
			//   - On success it would be indistinguishable from a full
			//     scan, and the full sweep's own populations (failed,
			//     stale) are keyed off exactly this.
			//   - On failure it would flip a perfectly healthy artifact
			//     to "failed", which the full sweep then retries with a
			//     COMPLETE scan -- turning the cheap path into an IO
			//     amplifier for the fleet.
			//
			// The errors are still recorded below, so a broken
			// re-evaluation is visible without being mistaken for a
			// broken artifact.
			//
			// StatusScanning as the prior value would be a snapshot
			// taken mid-scan (this handler sets it before dispatching);
			// restoring it would strand the artifact. It cannot happen
			// on the eligible population -- HasSBOM implies a completed
			// scan -- but failing to "scanned" is the recoverable
			// answer if it ever does.
			if a.Status == artifact.StatusScanning {
				art.Status = artifact.StatusScanned
			} else {
				art.Status = a.Status
			}
		} else {
			art.Status = status
			art.Digest = digest
		}
		// Recorded only when a check actually ran. A scan where the
		// provenance scanner is disabled must not overwrite a verdict
		// an earlier scan reached -- and must not replace it with
		// "unknown", which reads as "we never looked" and would make
		// disabling cosign silently erase every previous answer.
		if provenance != artifact.ProvenanceUnknown {
			art.Provenance = provenance
			art.ProvenanceTrustRoot = provenanceTrustRoot
			checked := now
			art.ProvenanceCheckedAt = &checked
		}

		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, cveFindings, now, detectFixedFor("cve"), vex)
		// Only overwrite when this scan actually produced errors. An
		// unconditional assignment meant a clean scan's empty slice
		// erased the previous failure, so an artifact that broke and
		// recovered looked like it had never broken at all. The record
		// is replaced by the NEXT failure, never by a success --
		// LastScanErrorAt vs LastScanAt tells the two apart.
		if len(scanErrors) > 0 {
			art.LastScanErrors = scanErrors
			art.LastScanErrorAt = &now
		}
		if sbomOnly {
			// THE OTHER FOUR BUCKETS ARE NOT MERGED AT ALL. This is the
			// single most important line in this mode, and skipping the
			// calls is the only correct way to express it.
			//
			// Bucket()/blockedBuckets governs what a FAILED scanner
			// blocks; it says nothing about a scanner that never ran. A
			// successful sbom-only round has no failures, so
			// detectFixedFor("malware") is true, and merging an empty
			// malware set against it marks every existing malware
			// finding FIXED -- silently, on every artifact, every night.
			// Same for misconfiguration, secret, and the non-license
			// half of other.
			//
			// Declaring the grype scanner's Bucket() is necessary but
			// nowhere near sufficient: it only helps on the failure
			// path. Success is what does the damage.
			return
		}
		art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, malwareFindings, now, detectFixedFor("malware"), vex)
		art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, misconfigFindings, now, detectFixedFor("misconfiguration"), vex)
		art.SecretFindings = artifact.MergeFindings(art.SecretFindings, secretFindings, now, detectFixedFor("secret"), vex)
		// A PARTITION of the bucket, not the whole of it: license
		// findings are produced when an SBOM is indexed, never by a
		// scanner, so they are absent from otherFindings every single
		// scan. Merging against the whole bucket would therefore mark
		// every license finding "fixed" on the next scan of the
		// artifact -- silently, since the findings remain visible and
		// simply claim to be resolved. The complementary half lives in
		// documents.go's applyLicenseDenylist; between them the bucket
		// is partitioned exactly once. See artifact.MergePartition.
		art.OtherFindings = artifact.MergePartition(
			art.OtherFindings, otherFindings,
			func(f artifact.Finding) bool { return f.Source != artifact.LicenseFindingSource },
			now, detectFixedFor("other"), vex)
		// Unlike the errors above, this one tracks CURRENT status and
		// must still clear: leaving it set would badge a healthy
		// artifact with the reason it failed last week.
		art.LastScanFailureReason = failureReason
		// FULL SCANS ONLY (the sbom-only path returned above).
		// LastScanAt is the freshness clock the staleness badge,
		// Store.CountStaleScans and the full sweep's own rescan
		// population all read. A nightly re-evaluation that stamped it
		// would make every artifact look permanently freshly-scanned,
		// the full sweep would stop finding anything stale, and malware
		// coverage would quietly decay while the dashboard stayed
		// green. The cheap path must not be able to satisfy the
		// expensive path's clock.
		art.LastScanAt = &now
	})

	if updErr != nil {
		// Nobody to return a 500 to -- the artifact is left at whatever
		// the store last persisted (status "scanning"), which the sweep
		// CronJob reclaims once it goes stale.
		slog.Error("could not persist scan results", "artifact_id", id, "err", updErr)
		return
	}
	slog.Info("scan finished",
		"artifact_id", id, "ref", updated.Ref,
		"status", updated.Status, "scan_errors", len(updated.LastScanErrors))

	// Revoke this artifact's upload tokens now the scan is over. They
	// expire on their own, but a token that outlives the Job it was
	// minted for is a credential nobody is watching -- and this is the
	// one moment we know the Job is done. Also sweeps expired rows
	// anywhere, so no CronJob is needed for it.
	//
	// After the results are persisted, deliberately: a worker racing to
	// post its SBOM as the scan closes should win, not lose its
	// credential mid-upload.
	if err := h.store.DeleteScanTokens(id); err != nil {
		// Not fatal to the scan, which has already succeeded. The
		// tokens expire regardless.
		slog.Warn("could not revoke scan upload tokens", "artifact_id", id, "err", err)
	}

	// An artifact whose own TYPE is sbom never had its components
	// indexed. Indexing has only ever been triggered by an SBOM arriving
	// at POST /artifacts/{id}/documents/sbom -- which is how an IMAGE
	// gets one (the scan-worker generates a CycloneDX document from the
	// trivy report and uploads it back, see GenerateImageDocuments). An
	// sbom-type artifact IS the document: nothing generates one for it
	// and nothing uploads one, so it stayed invisible to component
	// search and to the diff endpoint, despite being the one artifact
	// type that is definitionally a component inventory.
	//
	// Deliberately here in the API rather than in the scan-worker's own
	// sbom branch, where the bytes are already in hand: that branch only
	// runs for ISOLATED scans. With DISABLE_SCAN_ISOLATION the
	// in-process FetchingScanner fetches, scans and discards -- which is
	// the local dev path and the one cluster/test-swagger-docs.sh
	// exercises, so the gap would have survived exactly where it gets
	// run most.
	if updated.Status != artifact.StatusFailed {
		h.indexSBOMTypeComponents(ctx, updated)
		for _, res := range results {
			if res.err == nil && len(res.raw) > 0 {
				h.captureDocuments(ctx, updated, res.raw)
			}
		}
	}

	// a is the pre-scan snapshot taken before this scan started, so
	// a.LastScanAt == nil means this was the artifact's first ever scan
	// -- see notifyNewFindings for why that suppresses notification.
	h.notifyNewFindings(updated, now, a.LastScanAt == nil)
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
func (h *handler) notifyNewFindings(a *artifact.Artifact, roundStamp time.Time, firstScan bool) {
	if len(h.notifiers) == 0 {
		return
	}
	// An artifact's first ever scan is suppressed. Every finding it
	// reports is "new" only in the sense that nobody had looked before
	// -- they are not a change in the artifact, which is what this
	// notification is meant to signal. Without this, enabling
	// notifications on an existing deployment pages once per
	// already-registered artifact as the sweep works through the
	// backlog, and re-registering anything re-pages it.
	//
	// The cost, accepted deliberately: importing an image that already
	// carries a critical CVE stays quiet until a later scan changes
	// something. "This image is new to us" is a registration event, not
	// a scan-result change, and the artifact's own findings are on the
	// API and dashboard immediately either way.
	//
	// Note a first scan that FAILED still stamps LastScanAt, so the
	// following successful scan is not treated as a first scan and does
	// notify -- which is right: we did look, and this is the first time
	// we have actually seen the contents.
	if firstScan && !h.notifyOnFirstScan {
		slog.Info("first scan -- notifications suppressed (every finding is new on a first look; set notifications.suppressFirstScan=false to send these)", "artifact_id", a.ID)
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
		// Counted once here so the event and every notifier agree.
		KnownExploitedCount: notify.CountKnownExploited(newFindings),
		Severity:            notify.Worst(newFindings),
	}
	slog.Info("scan introduced new findings at or above the notify threshold",
		"artifact_id", a.ID, "count", len(newFindings),
		"threshold", threshold, "destinations", len(h.notifiers))

	for _, n := range h.notifiers {
		go func(n notify.Notifier) {
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("notifier panicked", "artifact_id", a.ID, "err", rec)
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

// captureDocuments derives a CycloneDX SBOM and a SARIF report from an
// in-process image scan's raw trivy report and stores them, exactly as
// an isolated scan-worker Job does by uploading them back.
//
// This closes a gap that made a whole feature invisible on one
// deployment path. Document capture lived only in the worker's image
// branch (main.go's captureImageDocuments), so with
// DISABLE_SCAN_ISOLATION -- the local dev path, and the one
// cluster/test-swagger-docs.sh runs -- an image scan produced no SBOM
// document at all. And because component indexing is triggered BY that
// document arriving, those artifacts also got no component inventory,
// no snapshot history for the diff endpoint, and no license findings.
// Every scan looked completely healthy while three features silently
// did nothing.
//
// Persisted through the same helper the upload endpoint uses rather
// than a parallel path, so an SBOM captured here indexes components,
// snapshots them, and runs the license denylist identically to one
// somebody uploaded. A second path would drift from that within a
// release.
//
// Best-effort, matching the worker's own contract: the scan is already
// persisted by the time this runs, so a conversion or store failure is
// logged and nothing more. A document problem must never turn a good
// scan into a failed one.
func (h *handler) captureDocuments(ctx context.Context, a *artifact.Artifact, rawReport []byte) {
	docs, genErrs := scanner.GenerateImageDocuments(ctx, rawReport, os.TempDir())
	for _, err := range genErrs {
		slog.Warn("could not generate a document from the scan report (the scan itself succeeded)",
			"artifact_id", a.ID, "err", err)
	}
	for _, doc := range docs {
		h.storeGeneratedDocument(a.ID, doc.Kind, doc.ContentType, doc.Content)
	}
}

// indexSBOMTypeComponents fetches an sbom-type artifact's own document
// and indexes it through the same path an uploaded SBOM takes.
//
// Best-effort throughout, matching indexSBOMComponents' own contract:
// the scan already succeeded and has been persisted by the time this
// runs, so nothing here may turn a good scan into a visible failure.
// A ref that will not fetch, or bytes that will not parse, are logged
// and dropped.
//
// Deliberately does NOT store the fetched bytes as the artifact's sbom
// document. artifact_documents keeps a latest-document contract fed by
// uploads, and writing one here would flip HasSBOM -- surfacing a
// download button for a whole artifact type that has never had one --
// which is a bigger change than indexing needs. The diff endpoint reads
// components_history, not documents.
func (h *handler) indexSBOMTypeComponents(ctx context.Context, a *artifact.Artifact) {
	if a.Type != artifact.TypeSBOM {
		return
	}
	if h.fetcher == nil {
		// No fetcher configured (most tests, and any deployment that
		// never set one up) -- nothing to do, and not an error.
		return
	}

	path, cleanup, err := h.fetcher.Fetch(ctx, a.Ref)
	// Always called, including on error, per Fetcher's own contract.
	defer cleanup()
	if err != nil {
		slog.Warn("could not fetch an sbom-type artifact to index its components (the scan itself succeeded)",
			"artifact_id", a.ID, "ref", a.Ref, "err", err)
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		slog.Warn("could not read a fetched sbom-type artifact to index its components (the scan itself succeeded)",
			"artifact_id", a.ID, "ref", a.Ref, "err", err)
		return
	}
	h.indexSBOMComponents(a.ID, content)
}

// scanCapMessage names the cap that refused. The global cap is stored
// under a pseudo-kind, so it needs translating back into the env var an
// operator would actually reach for.
func scanCapMessage(slots artifact.ScanSlotResult) string {
	if slots.BlockedKind == artifact.GlobalScanSlotKind {
		return fmt.Sprintf("scan concurrency limit reached (%d scans already in flight, SCAN_CONCURRENCY) -- retry shortly",
			slots.BlockedCap)
	}
	return fmt.Sprintf("scan concurrency limit reached for %s (%d already in flight, SCAN_CONCURRENCY_%s) -- retry shortly",
		slots.BlockedKind, slots.BlockedCap, strings.ToUpper(slots.BlockedKind))
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
