package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

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

// findDuplicate returns the artifact this registration duplicates, or
// nil. digest wins when it resolved; ref is the fallback when it didn't.
//
// Falling back to ref matters because an unresolvable digest is routine,
// not exceptional -- a dead or moved ref, a rate-limited registry, or a
// ref that is a local filesystem path and never had a digest at all.
// Skipping the check in that case (the previous behaviour) meant every
// re-registration created a new artifact: a live deployment accumulated
// 43 duplicate rows from 5 unresolvable refs across ~9 runs.
//
// The fallback matches ANY artifact with that ref, including one that
// already has a digest. That's deliberate: if we cannot resolve a digest
// now, we have no evidence this is different content, and creating an
// unscannable second row is worse than pointing at the one that exists.
// The narrower "only match other digest-less artifacts" rule would have
// left exactly the case this project hit -- artifacts registered fine,
// then re-registered during a registry rate-limit window -- still
// duplicating.
func (h *handler) findDuplicate(ref, digest string) (*artifact.Artifact, error) {
	if digest != "" {
		return h.store.FindByDigest(digest)
	}
	return h.store.FindByRef(ref)
}

// artifactQuota reports how many more artifacts may be created before
// the configured cap is reached. remaining is only meaningful when
// unlimited is false.
//
// Counted per REQUEST, not per entry: a bulk registration of 500 asks
// once and then decrements locally, so the quota check costs one
// COUNT(*) rather than five hundred.
func (h *handler) artifactQuota() (remaining int, unlimited bool, err error) {
	if h.maxArtifacts <= 0 {
		return 0, true, nil
	}
	existing, err := h.store.Count()
	if err != nil {
		return 0, false, err
	}
	r := h.maxArtifacts - existing
	if r < 0 {
		r = 0
	}
	return r, false, nil
}

func (h *handler) createArtifact(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r, maxSmallJSONBytes)
	var req createArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, "invalid request body")
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
	// Before resolveDigest, deliberately: that is the first thing to
	// make an outbound request with this ref, and a ref pointing at
	// link-local/RFC1918/in-cluster space must never get that far. See
	// scanner.ValidateRef. bulkCreateArtifacts orders it the same way,
	// in the phase that resolves digests.
	if err := scanner.ValidateRef(r.Context(), req.Ref); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Best-effort digest resolution + duplicate check, before Create --
	// see resolveDigest's own comment for why an empty digest here just
	// means "proceed without dedup," not a failure.
	digest := h.resolveDigest(r.Context(), req.Ref)

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
	// Duplicate detection. Digest is the right key when we have one --
	// only a digest can tell "the same image registered twice" from "a
	// mutable tag whose content changed". When resolution came back
	// empty we have no such evidence, and the fallback is the ref
	// itself: see findDuplicate.
	existing, err := h.findDuplicate(req.Ref, digest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing != nil {
		reason := "an artifact with this digest is already registered"
		if digest == "" {
			reason = "an artifact with this ref is already registered (its digest could not be resolved, so the ref is the only thing to match on)"
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                 reason,
			"digest":                digest,
			"existing_artifact_id":  existing.ID,
			"existing_artifact_ref": existing.Ref,
		})
		return
	}

	// Quota check goes AFTER dedup, deliberately: a duplicate creates
	// nothing and so consumes no quota, and re-registering something
	// that already exists must stay the idempotent 409 it is today even
	// at the cap. Gating earlier would save a registry round trip, but
	// that round trip is precisely what proves the request is a no-op.
	// bulkCreateArtifacts orders it the same way, inside its loop.
	//
	// 403, not 429: a quota is not a rate limit. Retrying later does not
	// help -- only deleting artifacts does -- so answering 429 (with the
	// Retry-After that implies) would tell a client to do the one thing
	// that cannot work. This matches Kubernetes' own ResourceQuota
	// behaviour, which is the convention operators here already know.
	remaining, unlimited, qerr := h.artifactQuota()
	if qerr != nil {
		writeError(w, http.StatusInternalServerError, qerr.Error())
		return
	}
	if !unlimited && remaining < 1 {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":         fmt.Sprintf("artifact limit reached (%d) -- delete artifacts to free capacity, or raise monitorApi.maxArtifacts", h.maxArtifacts),
			"max_artifacts": h.maxArtifacts,
		})
		return
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
			slog.Error("could not persist the resolved digest", "artifact_id", a.ID, "err", err)
		} else {
			a = updated
		}
	}
	if req.MaintainerTeam != "" || req.MaintainerEmail != "" {
		if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
			art.MaintainerTeam = req.MaintainerTeam
			art.MaintainerEmail = req.MaintainerEmail
		}); err != nil {
			slog.Error("could not persist maintainer info", "artifact_id", a.ID, "err", err)
		} else {
			a = updated
		}
	}
	// Copy it into the in-cluster registry and answer with the rewritten
	// ref, so the caller can see immediately what its artifact will
	// actually be scanned from. Inline (and therefore slow -- this is a
	// full pull and push) only on this single-artifact path;
	// bulkCreateArtifacts cannot afford it and leaves the copy to the
	// first scan instead. Best-effort either way: see mirrorArtifact.
	a = h.mirrorArtifact(r.Context(), a)
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
//
// DOES NOT MIRROR, unlike createArtifact. Copying an image into the
// local registry is a full pull-and-push; 500 of them inside one HTTP
// request is not a slow endpoint, it is a broken one (see
// cluster/load-test-clamav.sh, which re-registers 100 images on every
// run and expects this to stay fast). Entries register with their
// original ref and the first scan mirrors them -- runScan calls
// mirrorArtifact too, which makes the sweep-registered CronJob the
// backfill for the whole batch. See mirror.go.
func (h *handler) bulkCreateArtifacts(w http.ResponseWriter, r *http.Request) {
	// maxBulkArtifacts (500) below bounds the number of entries, but
	// only once the whole body is already decoded into memory -- this
	// bounds the bytes it takes to get there.
	limitBody(w, r, maxBulkArtifactsBytes)
	var req bulkCreateArtifactsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, "invalid request body")
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

	// Phase 1: validate every entry's ref and resolve its digest
	// concurrently (bounded), so registering 100 artifacts doesn't mean
	// 100 sequential registry round trips. Invalid entries (empty
	// ref/bad type) are skipped here -- they're rejected in phase 2
	// below before their digest (still "" in that case) is ever looked
	// at. A ref that fails scanner.ValidateRef never reaches
	// resolveDigest, which is the point: validation has to come before
	// the first outbound request, exactly as in createArtifact. Its
	// error is carried to phase 2 in refErrs and reported per entry
	// there, alongside every other reason one entry can't register.
	digests := make([]string, len(req.Artifacts))
	refErrs := make([]error, len(req.Artifacts))
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
				if err := scanner.ValidateRef(r.Context(), ref); err != nil {
					refErrs[i] = err
					return
				}
				digests[i] = h.resolveDigest(r.Context(), ref)
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
	// Two maps, because an entry is keyed by whichever evidence it has.
	// seenInBatch catches the same image listed twice under different
	// tags; seenRefsInBatch catches the same REF listed twice when no
	// digest resolved -- without it a batch containing one unresolvable
	// ref twice creates two artifacts in a single request, the same
	// accumulation bug the store-level check fixes across requests.
	seenInBatch := make(map[string]*artifact.Artifact)     // digest -> artifact created earlier in this batch
	seenRefsInBatch := make(map[string]*artifact.Artifact) // ref    -> ditto, for entries with no digest
	results := make([]bulkCreateArtifactsResult, 0, len(req.Artifacts))

	// One quota check for the whole batch, decremented locally as
	// entries are created below -- see artifactQuota. Entries that turn
	// out to be duplicates never consume quota, because they create
	// nothing.
	remaining, unlimited, qerr := h.artifactQuota()
	if qerr != nil {
		writeError(w, http.StatusInternalServerError, qerr.Error())
		return
	}
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
		// Refused in phase 1 by scanner.ValidateRef -- nothing outbound
		// ever happened for this entry.
		if err := refErrs[i]; err != nil {
			res.Error = err.Error()
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
		// Same-batch duplicate, keyed by digest when there is one and by
		// ref when there isn't.
		if dup, ok := seenInBatch[digest]; ok && digest != "" {
			res.Artifact = dup
			res.Error = fmt.Sprintf("duplicate of %q earlier in this same batch (artifact %s, same digest)", dup.Ref, dup.ID)
			res.Duplicate = true
			duplicates++
			results = append(results, res)
			continue
		}
		if dup, ok := seenRefsInBatch[item.Ref]; ok && digest == "" {
			res.Artifact = dup
			res.Error = fmt.Sprintf("duplicate of the same ref earlier in this batch (artifact %s; no digest resolved, so the ref is the only thing to match on)", dup.ID)
			res.Duplicate = true
			duplicates++
			results = append(results, res)
			continue
		}
		// Already registered by an earlier request. Reported as a
		// duplicate result rather than a failure: re-submitting a batch
		// is normal (cluster/load-test-clamav.sh does it every run) and
		// must stay a successful no-op.
		existing, err := h.findDuplicate(item.Ref, digest)
		if err != nil {
			res.Error = err.Error()
			failed++
			results = append(results, res)
			continue
		}
		if existing != nil {
			res.Artifact = existing
			why := "same digest"
			if digest == "" {
				why = "same ref; no digest resolved"
			}
			res.Error = fmt.Sprintf("duplicate of existing artifact %s (%s)", existing.ID, why)
			res.Duplicate = true
			duplicates++
			results = append(results, res)
			continue
		}

		// Out of quota: reported per entry like every other reason an
		// entry cannot be registered, so a batch that half fits still
		// registers the half that does -- the same best-effort shape
		// this endpoint already uses for bad refs and invalid types.
		if !unlimited && remaining < 1 {
			res.Error = fmt.Sprintf("artifact limit reached (%d) -- delete artifacts to free capacity", h.maxArtifacts)
			failed++
			results = append(results, res)
			continue
		}

		a, err := h.store.Create(item.Ref, t)
		if err != nil {
			res.Error = err.Error()
			failed++
			results = append(results, res)
			continue
		}
		remaining--
		if digest != "" || unsafe {
			if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
				art.Digest = digest
				art.Unsafe = unsafe
			}); err != nil {
				slog.Error("could not persist the resolved digest", "artifact_id", a.ID, "err", err)
			} else {
				a = updated
			}
		}
		if digest != "" {
			seenInBatch[digest] = a
		} else {
			seenRefsInBatch[item.Ref] = a
		}
		if item.MaintainerTeam != "" || item.MaintainerEmail != "" {
			if updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
				art.MaintainerTeam = item.MaintainerTeam
				art.MaintainerEmail = item.MaintainerEmail
			}); err != nil {
				slog.Error("could not persist maintainer info", "artifact_id", a.ID, "err", err)
			} else {
				a = updated
				if digest != "" {
					seenInBatch[digest] = a
				} else {
					seenRefsInBatch[item.Ref] = a
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

// defaultListLimit/maxListLimit bound one page of GET
// /api/v1/artifacts. The endpoint used to return every artifact in the
// store on every call -- with the dashboard polling it every 10s, that
// grows without bound as artifacts accumulate, dragging every
// artifact's full findings/stage history through the wire each time.
// maxListLimit is the same "cap rather than trust an unbounded number"
// reasoning maxBulkArtifacts already applies to the registration path,
// and it's enforced as a 400 rather than a silent clamp so a caller
// asking for 1000 finds out it isn't getting 1000.
const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// parseListBound parses one non-negative integer query param, returning
// def when it's absent/empty. Rejects anything non-numeric or negative
// -- neither store can do anything sensible with a negative offset
// (Postgres errors, a slice panics), so this is the trust boundary that
// keeps them from ever seeing one.
func parseListBound(raw string, def int) (int, error) {
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a non-negative integer, got %q", raw)
	}
	return n, nil
}

// pageLink builds one RFC 5988 Link header entry, as a relative
// reference (`</api/v1/artifacts?limit=50&offset=50>`) rather than an
// absolute URL: monitor-api sits behind a Kubernetes Service and, in
// the dashboard's case, is reached at whatever base the browser was
// pointed at, so it can't know its own scheme/host -- and a relative
// reference is a perfectly valid link target (RFC 3986 §4.2).
// Preserves the caller's filters so paging doesn't silently drop them.
func pageLink(r *http.Request, limit, offset int, rel string) string {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	// q rides along with status/type so paging through a SEARCH keeps
	// searching. A next link that silently dropped it would page into
	// the unfiltered list while X-Total-Count still described the
	// filtered one -- the counts and the rows would disagree from page
	// two onwards.
	for _, name := range []string{"status", "type", "q"} {
		if v := r.URL.Query().Get(name); v != "" {
			q.Set(name, v)
		}
	}
	return fmt.Sprintf("<%s?%s>; rel=%q", r.URL.Path, q.Encode(), rel)
}

type listArtifactsResponse struct {
	// Total is how many artifacts match the filters, not how many are
	// in this page -- what a caller needs to render "50 of 812" or
	// decide whether another page exists. Mirrors the X-Total-Count
	// header for callers that can't read response headers (a
	// cross-origin browser fetch only sees headers named in
	// Access-Control-Expose-Headers -- see withCORS).
	Total     int                  `json:"total"`
	Artifacts []*artifact.Artifact `json:"artifacts"`
}

// listArtifacts returns one page of artifacts, newest first. The
// response is an object wrapping the array (rather than the bare array
// it used to return) specifically so the total can travel in the body
// -- see listArtifactsResponse.Total.
func (h *handler) listArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, err := parseListBound(q.Get("limit"), defaultListLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit "+err.Error())
		return
	}
	offset, err := parseListBound(q.Get("offset"), 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "offset "+err.Error())
		return
	}
	if limit < 1 {
		writeError(w, http.StatusBadRequest, "limit must be at least 1")
		return
	}
	if limit > maxListLimit {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be %d or less", maxListLimit))
		return
	}

	// status/type are passed through to the store unvalidated: they're
	// bound as query parameters (never interpolated into SQL), and an
	// unrecognized value legitimately matches nothing -- an empty page
	// is a truthful answer to "show me artifacts with status=banana,"
	// where a 400 would just be a second enum to keep in sync.
	//
	// q is the same: a case-insensitive substring across ref, digest,
	// maintainer team/email and current stage, bound as a parameter
	// with its LIKE metacharacters escaped by the store. Total counts
	// the SEARCH result, so X-Total-Count and the Link headers all
	// describe the same filtered set.
	list, total, err := h.store.ListPage(limit, offset, q.Get("status"), q.Get("type"), q.Get("q"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	links := make([]string, 0, 2)
	if offset+limit < total {
		links = append(links, pageLink(r, limit, offset+limit, "next"))
	}
	if offset > 0 {
		prev := offset - limit
		if prev < 0 {
			prev = 0
		}
		links = append(links, pageLink(r, limit, prev, "prev"))
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	if len(links) > 0 {
		w.Header().Set("Link", strings.Join(links, ", "))
	}
	writeJSON(w, http.StatusOK, listArtifactsResponse{Total: total, Artifacts: list})
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
