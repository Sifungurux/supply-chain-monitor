package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
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
