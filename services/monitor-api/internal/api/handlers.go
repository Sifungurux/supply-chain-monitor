package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
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
	// registration detection (see createArtifact/bulkCreateArtifacts
	// and resolveDigest below) -- digestResolver is nil in tests that
	// don't care about this (see newTestRouter), which resolveDigest
	// treats as "dedup disabled," not an error.
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
}

const defaultScanTimeout = 5 * time.Minute

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

func (h *handler) listStages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"stages": h.tracker.Stages()})
}

type createArtifactRequest struct {
	Ref  string `json:"ref"`
	Type string `json:"type"`
	// ExpectedDigest, if set, gates registration on digest pinning: the
	// ref's digest is resolved the same way the duplicate check below
	// resolves it, and registration only proceeds if that resolved
	// digest equals this one exactly. Lets a caller pin "only register
	// this if it's still the exact image I saw earlier" instead of
	// trusting a mutable tag -- see checkExpectedDigest.
	ExpectedDigest string `json:"expected_digest,omitempty"`
	// MaintainerTeam/MaintainerEmail optionally set Artifact's fields of
	// the same name at registration time -- see validateMaintainerPair
	// for why they're rejected unless both are set or both are empty.
	MaintainerTeam  string `json:"maintainer_team,omitempty"`
	MaintainerEmail string `json:"maintainer_email,omitempty"`
}

// validateMaintainerPair enforces that maintainer team/email are
// provided together or not at all: a team name with no way to reach
// them, or a contact address with no team context, isn't meaningful
// ownership info, so this rejects a half-filled pair up front instead
// of silently persisting it. Shared by createArtifact,
// bulkCreateArtifacts, and updateMaintainer so the three entry points
// can't drift into enforcing this differently.
func validateMaintainerPair(team, email string) error {
	if (team == "") != (email == "") {
		return errors.New("maintainer_team and maintainer_email must both be set, or both left empty")
	}
	return nil
}

// digestMatchesExpected is the shared pass/fail rule for digest pinning,
// used by both createArtifact and bulkCreateArtifacts so the single-
// artifact and bulk registration endpoints can't drift into enforcing
// this differently. expectedDigest == "" means no pin was requested
// (always passes). resolvedDigest == "" (couldn't resolve at all, e.g.
// registry unreachable or ref is a local path) is treated the same as a
// mismatch when a pin *was* requested: there's nothing to verify it
// against, so this fails closed rather than silently registering
// unverified.
func digestMatchesExpected(resolvedDigest, expectedDigest string) bool {
	if expectedDigest == "" {
		return true
	}
	return resolvedDigest != "" && resolvedDigest == expectedDigest
}

// checkExpectedDigest is createArtifact's single-artifact wrapper around
// digestMatchesExpected -- writes the 409 response and returns false
// when the pin fails, so the caller can just return.
func checkExpectedDigest(w http.ResponseWriter, ref, resolvedDigest, expectedDigest string) bool {
	if digestMatchesExpected(resolvedDigest, expectedDigest) {
		return true
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"error":           "resolved digest does not match the expected digest -- registration refused",
		"ref":             ref,
		"expected_digest": expectedDigest,
		"resolved_digest": resolvedDigest,
	})
	return false
}

func (h *handler) createArtifact(w http.ResponseWriter, r *http.Request) {
	var req createArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}

	t := artifact.Type(req.Type)
	if !t.Valid() {
		writeError(w, http.StatusBadRequest, "type must be one of image, file, sbom, sarif")
		return
	}
	if err := validateMaintainerPair(req.MaintainerTeam, req.MaintainerEmail); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.requireDigest && req.ExpectedDigest == "" {
		writeError(w, http.StatusBadRequest, "expected_digest is required (REQUIRE_DIGEST is enabled)")
		return
	}

	// Best-effort digest resolution + duplicate check, before Create --
	// see resolveDigest's own comment for why an empty digest here just
	// means "proceed without dedup," not a failure.
	digest := h.resolveDigest(r.Context(), req.Ref, t)

	// unsafe (REQUIRE_DIGEST only) and the reject-on-mismatch path below
	// (the pre-existing, opt-in-per-request behavior) are mutually
	// exclusive: h.requireDigest already guaranteed ExpectedDigest is set
	// above, so a mismatch here always marks the artifact rather than
	// ever falling through to checkExpectedDigest's 409 -- see
	// Artifact.Unsafe's own comment for why a deployment-wide policy
	// registers-and-flags instead of rejecting outright.
	var unsafe bool
	if h.requireDigest {
		unsafe = !digestMatchesExpected(digest, req.ExpectedDigest)
	} else if !checkExpectedDigest(w, req.Ref, digest, req.ExpectedDigest) {
		return
	}
	if digest != "" {
		existing, err := h.store.FindByDigest(digest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if existing != nil {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":                 "an artifact with this digest is already registered",
				"digest":                digest,
				"existing_artifact_id":  existing.ID,
				"existing_artifact_ref": existing.Ref,
			})
			return
		}
	}

	a, err := h.store.Create(req.Ref, t)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if digest != "" || unsafe {
		if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
			art.Digest = digest
			art.Unsafe = unsafe
		}); err != nil {
			// The artifact itself was created successfully; only the
			// digest/unsafe metadata failed to persist. Log rather than
			// fail a registration that otherwise succeeded.
			log.Printf("failed to persist resolved digest for artifact %s: %v", a.ID, err)
		} else {
			a = updated
		}
	}
	if req.MaintainerTeam != "" || req.MaintainerEmail != "" {
		if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
			art.MaintainerTeam = req.MaintainerTeam
			art.MaintainerEmail = req.MaintainerEmail
		}); err != nil {
			log.Printf("failed to persist maintainer info for artifact %s: %v", a.ID, err)
		} else {
			a = updated
		}
	}
	writeJSON(w, http.StatusCreated, a)
}

type bulkCreateArtifactsRequest struct {
	Artifacts []createArtifactRequest `json:"artifacts"`
}

type bulkCreateArtifactsResult struct {
	Ref      string             `json:"ref"`
	Type     string             `json:"type"`
	Artifact *artifact.Artifact `json:"artifact,omitempty"`
	Error    string             `json:"error,omitempty"`
	// Duplicate marks an entry whose resolved digest already matches an
	// existing artifact -- either one registered in an earlier request,
	// or another entry earlier in this same batch. Artifact is still
	// populated (with the *existing* artifact, not a new one) so a
	// caller that just wants an id per ref -- e.g.
	// cluster/load-test-clamav.sh re-registering the same 100-image
	// batch on every run -- keeps working unchanged; Error explains
	// which one it duplicates. Not counted in Failed: the artifact
	// genuinely exists, this isn't a validation problem.
	Duplicate bool `json:"duplicate,omitempty"`
}

// Created + Failed + Duplicates always equals len(Results).
type bulkCreateArtifactsResponse struct {
	Created    int                         `json:"created"`
	Failed     int                         `json:"failed"`
	Duplicates int                         `json:"duplicates"`
	Results    []bulkCreateArtifactsResult `json:"results"`
}

// bulkDigestResolveConcurrency bounds how many `oras manifest fetch`
// calls run at once during one bulk registration. Resolving digests one
// at a time for e.g. testdata/bulk-test-images.json's 100 entries would
// add tens of seconds to what was previously an instant, dependency-free
// endpoint -- cluster/load-test-clamav.sh depends on this staying fast.
const bulkDigestResolveConcurrency = 10

// maxBulkArtifacts caps how many artifacts one bulkCreateArtifacts
// request can register. Without a cap, a single oversized request body
// could tie up the store/DB the same way withRateLimit exists to stop
// one caller monopolizing the scan pipeline (see ratelimit.go) -- this
// is the equivalent guard for the registration path.
const maxBulkArtifacts = 500

// bulkCreateArtifacts registers many artifacts from a single request --
// see docs/architecture.md, "Bulk-registering artifacts", added
// specifically so seeding/testing a batch of artifacts (e.g. a list of
// 100 images to scan) doesn't require one HTTP round trip per artifact
// via POST /api/v1/artifacts.
//
// This is deliberately best-effort, not all-or-nothing: one malformed
// ref or invalid type in a batch of 100 shouldn't block the other 99
// from registering, so each entry is validated and created
// independently, and the response reports success/failure per entry
// instead of failing the whole request on the first bad one -- the same
// "one failure shouldn't block everything else" reasoning
// scanArtifact's own per-scanner error handling already uses.
func (h *handler) bulkCreateArtifacts(w http.ResponseWriter, r *http.Request) {
	var req bulkCreateArtifactsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Artifacts) == 0 {
		writeError(w, http.StatusBadRequest, "artifacts must be a non-empty array")
		return
	}
	if len(req.Artifacts) > maxBulkArtifacts {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many artifacts in one request (max %d)", maxBulkArtifacts))
		return
	}

	// Phase 1: resolve every entry's digest concurrently (bounded), so
	// registering 100 artifacts doesn't mean 100 sequential registry
	// round trips. Invalid entries (empty ref/bad type) are skipped here
	// -- they're rejected in phase 2 below before their digest (still ""
	// in that case) is ever looked at.
	digests := make([]string, len(req.Artifacts))
	{
		sem := make(chan struct{}, bulkDigestResolveConcurrency)
		var wg sync.WaitGroup
		for i, item := range req.Artifacts {
			t := artifact.Type(item.Type)
			if item.Ref == "" || !t.Valid() {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, ref string, t artifact.Type) {
				defer wg.Done()
				defer func() { <-sem }()
				digests[i] = h.resolveDigest(r.Context(), ref, t)
			}(i, item.Ref, t)
		}
		wg.Wait()
	}

	// Phase 2: sequential Create/duplicate-check pass -- every digest is
	// already resolved, so this is just store calls, no more network
	// I/O. Sequential (not concurrent) deliberately: seenInBatch needs a
	// fixed processing order to catch two entries in the *same* request
	// sharing a digest (e.g. the same image listed under two tags), not
	// just duplicates of something registered in an earlier request.
	seenInBatch := make(map[string]*artifact.Artifact) // digest -> artifact created earlier in this batch
	results := make([]bulkCreateArtifactsResult, 0, len(req.Artifacts))
	created, failed, duplicates := 0, 0, 0
	for i, item := range req.Artifacts {
		res := bulkCreateArtifactsResult{Ref: item.Ref, Type: item.Type}

		if item.Ref == "" {
			res.Error = "ref is required"
			failed++
			results = append(results, res)
			continue
		}
		t := artifact.Type(item.Type)
		if !t.Valid() {
			res.Error = "type must be one of image, file, sbom, sarif"
			failed++
			results = append(results, res)
			continue
		}
		if err := validateMaintainerPair(item.MaintainerTeam, item.MaintainerEmail); err != nil {
			res.Error = err.Error()
			failed++
			results = append(results, res)
			continue
		}
		if h.requireDigest && item.ExpectedDigest == "" {
			res.Error = "expected_digest is required (REQUIRE_DIGEST is enabled)"
			failed++
			results = append(results, res)
			continue
		}

		digest := digests[i]
		// unsafe mirrors createArtifact's own requireDigest handling --
		// see that function's comment and Artifact.Unsafe's for why a
		// deployment-wide policy marks rather than rejects.
		var unsafe bool
		if h.requireDigest {
			unsafe = !digestMatchesExpected(digest, item.ExpectedDigest)
		} else if !digestMatchesExpected(digest, item.ExpectedDigest) {
			res.Error = fmt.Sprintf("resolved digest does not match expected digest %q -- registration refused", item.ExpectedDigest)
			failed++
			results = append(results, res)
			continue
		}
		if digest != "" {
			if dup, ok := seenInBatch[digest]; ok {
				res.Artifact = dup
				res.Error = fmt.Sprintf("duplicate of %q earlier in this same batch (artifact %s, same digest)", dup.Ref, dup.ID)
				res.Duplicate = true
				duplicates++
				results = append(results, res)
				continue
			}
			existing, err := h.store.FindByDigest(digest)
			if err != nil {
				res.Error = err.Error()
				failed++
				results = append(results, res)
				continue
			}
			if existing != nil {
				res.Artifact = existing
				res.Error = fmt.Sprintf("duplicate of existing artifact %s (same digest)", existing.ID)
				res.Duplicate = true
				duplicates++
				results = append(results, res)
				continue
			}
		}

		a, err := h.store.Create(item.Ref, t)
		if err != nil {
			res.Error = err.Error()
			failed++
			results = append(results, res)
			continue
		}
		if digest != "" || unsafe {
			if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
				art.Digest = digest
				art.Unsafe = unsafe
			}); err != nil {
				log.Printf("failed to persist resolved digest for artifact %s: %v", a.ID, err)
			} else {
				a = updated
			}
		}
		if digest != "" {
			seenInBatch[digest] = a
		}
		if item.MaintainerTeam != "" || item.MaintainerEmail != "" {
			if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
				art.MaintainerTeam = item.MaintainerTeam
				art.MaintainerEmail = item.MaintainerEmail
			}); err != nil {
				log.Printf("failed to persist maintainer info for artifact %s: %v", a.ID, err)
			} else {
				a = updated
				if digest != "" {
					seenInBatch[digest] = a
				}
			}
		}
		res.Artifact = a
		created++
		results = append(results, res)
	}

	// 201 as long as at least one artifact registered or matched an
	// existing one -- a request that's entirely bad input (e.g. every
	// entry missing a ref) is the one case that should read as a client
	// error rather than "created, but check the per-entry results,"
	// since nothing in it was ever valid. Re-registering an already-seen
	// batch (created == 0, duplicates == len(results)) is NOT that case
	// -- see cluster/load-test-clamav.sh, which re-submits the same 100
	// images on every run and expects a normal, successful response
	// back with usable artifact ids, not a 400.
	status := http.StatusCreated
	if created == 0 && duplicates == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, bulkCreateArtifactsResponse{Created: created, Failed: failed, Duplicates: duplicates, Results: results})
}

func (h *handler) listArtifacts(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *handler) getArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// deleteArtifact permanently removes an artifact -- its stage history,
// findings, and scan errors go with it (PostgresStore relies on
// ON DELETE CASCADE for the child tables; MemStore just drops the map
// entry). There is no undo and no soft-delete/archive semantics -- see
// docs/architecture.md ("Deleting an artifact") for that reasoning.
// Returns 404 for an id that doesn't exist, the same convention
// getArtifact/updateStage already use, rather than treating "already
// gone" as a successful no-op the way some DELETE APIs do -- consistent
// with every other id-scoped endpoint in this file.
func (h *handler) deleteArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.Delete(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

// findByFindingID answers "every artifact still affected by finding
// X" -- the query internal/artifact's normalized findings table exists
// to make possible (see docs/architecture.md, "Normalizing findings
// and stage history into their own tables"). Returns an empty list
// (not a 404) when nothing matches, since "no artifacts affected" is a
// perfectly valid, non-error answer -- unlike getArtifact, this isn't
// asking about one specific ID that either exists or doesn't.
func (h *handler) findByFindingID(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if findingID == "" {
		writeError(w, http.StatusBadRequest, "finding id is required")
		return
	}

	list, err := h.store.FindByFindingID(findingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

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
	// and now an arbitrary number of operator-configured external
	// scanners (see internal/scanner/external.go) all potentially
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
			// a bug surfaced by an operator's own ExternalScanner
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
	// operator's ExternalScanner) blocks every bucket on failure,
	// exactly like every scanner used to before this existed -- neither
	// can honestly promise which bucket(s) it would have affected
	// (SARIF mixes categories in one document; an ExternalScanner's own
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

type updateStageRequest struct {
	Stage string `json:"stage"`
	Note  string `json:"note,omitempty"`
}

func (h *handler) updateStage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req updateStageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.tracker.Validate(req.Stage); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		art.CurrentStage = req.Stage
		art.StageHistory = append(art.StageHistory, artifact.StageEvent{
			Stage:     req.Stage,
			Timestamp: time.Now().UTC(),
			Note:      req.Note,
		})
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

type updateMaintainerRequest struct {
	Team  string `json:"team"`
	Email string `json:"email"`
}

// updateMaintainer sets (or corrects) an artifact's maintainer info
// after registration -- the Register form can't always know a team/
// contact up front, and ownership changes over an artifact's lifetime
// regardless. Unlike createArtifact/bulkCreateArtifacts, both fields
// are required here: there's no "leave it as it was" partial-update
// semantics for this endpoint, only "set it to this pair" -- clearing
// it back to empty is the one case not supported today (not needed by
// the dashboard, which only ever offers Save with both fields filled).
func (h *handler) updateMaintainer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req updateMaintainerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Team == "" || req.Email == "" {
		writeError(w, http.StatusBadRequest, "team and email are both required")
		return
	}

	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		art.MaintainerTeam = req.Team
		art.MaintainerEmail = req.Email
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

// maxDocumentUploadBytes bounds a single SBOM/SARIF document upload --
// the only endpoint in this API that accepts raw, arbitrary-size bytes
// rather than a small JSON payload. 64MiB comfortably covers a
// real-world image's CycloneDX SBOM or SARIF report (commonly 10-20MB,
// see scanner.GenerateImageDocuments' comment) with headroom, while
// still bounding this new boundary rather than leaving it unbounded.
const maxDocumentUploadBytes = 64 << 20 // 64MiB

func validDocumentKind(kind string) bool {
	return kind == artifact.DocumentKindSBOM || kind == artifact.DocumentKindSARIF
}

// uploadDocument receives a generated SBOM/SARIF document -- today,
// only ever called by a scan-worker Job from inside
// captureImageDocuments (main.go), the return path for a document too
// large for the existing pod-logs/WorkerResult channel used for
// findings (see scanner.UploadDocument's comment). Authenticated the
// same way as every other request (withAuth wraps the whole mux) --
// no separate credential scheme for this internal caller.
func (h *handler) uploadDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	kind := r.PathValue("kind")
	if !validDocumentKind(kind) {
		writeError(w, http.StatusBadRequest, `kind must be "sbom" or "sarif"`)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentUploadBytes)
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body (too large, or connection dropped): "+err.Error())
		return
	}
	if len(content) == 0 {
		writeError(w, http.StatusBadRequest, "document body is empty")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if err := h.store.SaveDocument(id, kind, contentType, content); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "id": id, "kind": kind})
}

// downloadDocument returns a captured document's raw bytes -- the
// dashboard's download buttons (and any other API consumer) read a
// document here. 404 when none exists yet, the same "not found is the
// expected, common case" convention Store.GetDocument's own comment
// documents (e.g. before the first scan runs, or best-effort generation
// failed -- see GenerateImageDocuments).
func (h *handler) downloadDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	kind := r.PathValue("kind")
	if !validDocumentKind(kind) {
		writeError(w, http.StatusBadRequest, `kind must be "sbom" or "sarif"`)
		return
	}

	doc, err := h.store.GetDocument(id, kind)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if doc == nil {
		writeError(w, http.StatusNotFound, "no "+kind+" document has been captured for this artifact yet")
		return
	}

	ext := ".json"
	if kind == artifact.DocumentKindSARIF {
		ext = ".sarif"
	}

	w.Header().Set("Content-Type", doc.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+"-"+kind+ext+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc.Content)
}

// validFindingsBucket checks the bucket name submitFindings was given.
// These five literal strings are an API-contract detail of this
// package -- kept separate from internal/artifact/postgres_store.go's
// own bucketCVE/bucketMalware/bucketMisconfiguration/bucketSecret/
// bucketOther constants, which exist for a different reason (Postgres
// table rows) and MemStore doesn't use at all. Matches the same
// vocabulary classifyBucket above already sorts findings into, just
// made explicit here instead of inferred from a Source/Category.
func validFindingsBucket(bucket string) bool {
	switch bucket {
	case "cve", "malware", "misconfiguration", "secret", "other":
		return true
	default:
		return false
	}
}

type submitFindingsRequest struct {
	// Bucket picks which of the artifact's five finding buckets this
	// call writes into ("cve", "malware", "misconfiguration", "secret",
	// or "other" -- see artifact.Artifact's CVEFindings/
	// MalwareFindings/MisconfigFindings/SecretFindings/OtherFindings).
	Bucket   string             `json:"bucket"`
	Findings []artifact.Finding `json:"findings"`
}

// submitFindings lets a system other than monitor-api's own registered
// scanners -- an external pipeline's malware scanner, a SAST tool run
// in CI, anything that already produced results elsewhere -- record
// those results directly against an artifact, with no fetch or re-scan
// of Ref involved at all.
//
// This exists because scanArtifact (the only other write path into
// CVEFindings/MalwareFindings/MisconfigFindings/SecretFindings/
// OtherFindings) always calls a registered Scanner's Scan(ctx, ref),
// which always does its own fetch+scan of ref internally -- there was
// previously no path for "here are findings I already computed, just
// store them." See docs/architecture.md ("Submitting external findings
// directly") for the full reasoning, including why this is a new
// endpoint rather than another Scanner implementation (a Scanner's
// contract is "given a ref, go compute findings" -- this handler's
// input already *is* the findings, so it doesn't fit that shape).
//
// Deliberately touches only the one bucket named in the request,
// unlike scanArtifact (which merges into all five buckets every call,
// since it always re-runs every registered scanner for the type at
// once). An external system submitting its own malware results has no
// way to know what Trivy or a SARIF import already found for this same
// artifact, so touching the other buckets here would risk corrupting
// real data.
//
// The one bucket it does touch is merged, not replaced, via
// MergeFindings -- exactly like scanArtifact, so a finding that stops
// being reported shows up as fixed (with ResolvedAt set) rather than
// just vanishing, and a finding reported again keeps its original
// FirstSeenAt rather than looking newly discovered. Always merges with
// detectFixed=true: unlike scanArtifact (which has to worry about a
// scanner erroring mid-run), this endpoint's contract is that the
// caller is asserting a complete current result for the bucket it
// named, so "not in this report" always safely means "fixed."
func (h *handler) submitFindings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req submitFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validFindingsBucket(req.Bucket) {
		writeError(w, http.StatusBadRequest, "bucket must be one of cve, malware, misconfiguration, secret, other")
		return
	}
	if req.Findings == nil {
		req.Findings = []artifact.Finding{}
	}

	now := time.Now().UTC()
	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		switch req.Bucket {
		case "cve":
			art.CVEFindings = artifact.MergeFindings(art.CVEFindings, req.Findings, now, true)
		case "malware":
			art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, req.Findings, now, true)
		case "misconfiguration":
			art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, req.Findings, now, true)
		case "secret":
			art.SecretFindings = artifact.MergeFindings(art.SecretFindings, req.Findings, now, true)
		case "other":
			art.OtherFindings = artifact.MergeFindings(art.OtherFindings, req.Findings, now, true)
		}
		// A registered-but-never-scanned artifact submitting findings
		// this way has meaningfully been scanned now, even though
		// scanArtifact never ran -- reflect that in Status so it shows
		// up correctly in the dashboard/list views. An artifact that's
		// already scanning/scanned/failed keeps its existing status;
		// this call only ever touches one bucket, so it shouldn't
		// override a status a fuller scan already set.
		if art.Status == artifact.StatusRegistered {
			art.Status = artifact.StatusScanned
		}
		art.LastScanAt = &now
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
