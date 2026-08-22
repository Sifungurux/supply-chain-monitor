package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// findByFindingID answers "every artifact still affected by finding
// X" -- the query internal/artifact's normalized findings table exists
// to make possible (see docs/architecture.md, "Normalizing findings
// and stage history into their own tables"). Returns an empty list
// (not a 404) when nothing matches, since "no artifacts affected" is a
// perfectly valid, non-error answer -- unlike getArtifact, this isn't
// asking about one specific ID that either exists or doesn't.
// maxFindingMatches bounds one finding-search response, for the same
// reason maxComponentMatches does: "cve" or "2024" legitimately matches
// thousands of ids, and the total is always reported alongside so a
// capped answer says so.
const maxFindingMatches = 200

// findingSearchResponse is the ?q= answer: distinct finding ids, not
// artifacts.
type findingSearchResponse struct {
	Total    int                     `json:"total"`
	Findings []artifact.FindingMatch `json:"findings"`
}

// searchFindings is the discovery step in front of findByFindingID,
// and the direct mirror of the component search (components.go): you
// know "log4j" or "that spring thing", not "CVE-2021-44228", so this
// answers with the finding ids that actually exist -- each with its
// worst-seen severity, a title, and how many artifacts are affected --
// and the id picked from that goes to
// GET /api/v1/findings/{findingID}/artifacts for the exact list.
//
// Both halves count the same population: findings that are neither
// fixed nor VEX-suppressed. A search that said "41 artifacts" and a
// click-through that returned 45 would be worse than no count at all.
func (h *handler) searchFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeError(w, http.StatusBadRequest, `q query parameter is required, e.g. ?q=log4j`)
		return
	}

	matches, total, err := h.store.SearchFindings(q, maxFindingMatches)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findingSearchResponse{Total: total, Findings: matches})
}

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

// validFindingsBucket checks the bucket name submitFindings was given.
// These five literal strings are an API-contract detail of this
// package -- kept separate from internal/artifact/postgres_store.go's
// own bucketCVE/bucketMalware/bucketMisconfiguration/bucketSecret/
// bucketOther constants, which exist for a different reason (Postgres
// table rows) and MemStore doesn't use at all. Matches the same
// vocabulary classifyBucket (scan.go) already sorts findings into,
// just made explicit here instead of inferred from a Source/Category.
func validFindingsBucket(bucket string) bool {
	switch bucket {
	case "cve", "malware", "misconfiguration", "secret", "other":
		return true
	default:
		return false
	}
}

// allValidFindingsBuckets reports whether EVERY bucket in the set is a
// real one. All-or-nothing deliberately: this gates
// scanner.MultiBucketAffinity in scanArtifact, where a partially-valid
// answer must not be partially honoured. A scanner that names one good
// bucket and one typo'd bucket has demonstrated it does not know what
// it produces, and the safe reading of that is "block everything",
// which is what the caller falls through to.
func allValidFindingsBuckets(buckets []string) bool {
	for _, b := range buckets {
		if !validFindingsBucket(b) {
			return false
		}
	}
	return len(buckets) > 0
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

	limitBody(w, r, maxFindingsBytes)
	var req submitFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, "invalid request body")
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
	// A caller does not get to assert KEV/EPSS. These are derived facts
	// about a CVE, not observations about this artifact, so a submitter
	// claiming known_exploited=false for its own findings would be
	// asserting something it has no standing to know -- the same
	// reasoning that makes MergeFindings recompute Status and
	// Justification rather than trust them. Cleared here and re-derived
	// from the feeds below.
	for i := range req.Findings {
		req.Findings[i].EPSSScore = 0
		req.Findings[i].KnownExploited = false
	}
	// Re-derived from the feeds, before the store.Update below rather
	// than inside its closure -- see scanArtifact's own comment for why
	// a lookup in there deadlocks MemStore. Only the CVE bucket carries
	// CVE ids; Apply skips the rest anyway.
	if req.Bucket == "cve" {
		if err := h.enrich(req.Findings); err != nil {
			slog.Warn("could not enrich submitted findings with KEV/EPSS (submission unaffected)",
				"artifact_id", id, "err", err)
		}
	}

	// Same VEX overlay scanArtifact applies (see vexFor): an external
	// system submitting findings has no idea what this artifact's
	// operator has already assessed, so a submission must not be a way
	// around a VEX document.
	vex := h.vexFor(id)
	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		switch req.Bucket {
		case "cve":
			art.CVEFindings = artifact.MergeFindings(art.CVEFindings, req.Findings, now, true, vex)
		case "malware":
			art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, req.Findings, now, true, vex)
		case "misconfiguration":
			art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, req.Findings, now, true, vex)
		case "secret":
			art.SecretFindings = artifact.MergeFindings(art.SecretFindings, req.Findings, now, true, vex)
		case "other":
			art.OtherFindings = artifact.MergeFindings(art.OtherFindings, req.Findings, now, true, vex)
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

// maxAcceptanceDays bounds how far into the future a risk acceptance
// may run.
//
// The cap is the point of the feature. An acceptance is a decision to
// ship a known vulnerability, and the only thing separating that from
// quietly deleting the finding is that it comes back on its own and
// somebody has to look again. A ten-year "until" is a deletion with
// extra steps, so the ceiling is a year: long enough for the legitimate
// "we cannot upgrade this until the next major release" case, short
// enough that every acceptance is re-examined within one.
const maxAcceptanceDays = 365

type acceptFindingRequest struct {
	// Until is when the acceptance expires, RFC3339
	// ("2026-12-31T00:00:00Z"). Decoded as a string rather than a
	// time.Time so a malformed timestamp gets a message naming the
	// field and the format, instead of the generic "invalid request
	// body" a decode failure into a time.Time would produce -- the two
	// are indistinguishable to a caller staring at a 400, and this is
	// the field most likely to be got wrong.
	Until string `json:"until"`
	// Reason is why this risk is being accepted, in the accepter's own
	// words. Required: see AcceptanceReason.
	Reason string `json:"reason"`
}

// acceptFinding records a time-boxed risk acceptance against one
// finding: "this is real, we know, and we are choosing to live with it
// until <date>."
//
// The gap this fills sits between the two things that already existed.
// A VEX "not_affected" says the finding does not apply here, which is a
// technical assertion and often untrue of the thing an operator
// actually wants to say; deleting the artifact or ignoring the
// dashboard says nothing at all and leaves the policy gate red forever,
// which is how a team learns to stop reading it. An acceptance is the
// honest middle: the finding stays on record, visibly accepted, out of
// the counts and the policy gate, and RETURNS on its own when the
// acceptance lapses.
//
// Admin-scoped, unlike the findings and VEX endpoints next to it (which
// are ScopeScan, since submitting results is what a CI scanner does).
// Accepting risk is not a scan result -- it is a decision about what
// this organization will tolerate, and a CI scanner holding the ability
// to make it would mean any compromised pipeline could silence its own
// findings. AcceptedBy comes from the authenticated client rather than
// the body for the same reason: an accountability record a caller can
// write is not one.
//
// Applied to EVERY bucket carrying the id, not just the first found.
// One id legitimately appears in more than one bucket (a CVE arriving
// both from trivy and inside a SARIF import lands in "cve" and "other"
// -- see classifyBucket), and an acceptance that silenced one of them
// while the other kept failing the policy gate would look like the
// endpoint had simply not worked. Same reason uploadVEX applies a
// statement across all five.
func (h *handler) acceptFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	findingID := r.PathValue("findingID")

	limitBody(w, r, maxSmallJSONBytes)
	var req acceptFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, "invalid request body")
		return
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required: an acceptance with no stated reason is indistinguishable from hiding the finding")
		return
	}
	if strings.TrimSpace(req.Until) == "" {
		writeError(w, http.StatusBadRequest, `until is required, as an RFC3339 timestamp (e.g. "2026-12-31T00:00:00Z")`)
		return
	}
	until, err := time.Parse(time.RFC3339, req.Until)
	if err != nil {
		writeError(w, http.StatusBadRequest, `until must be an RFC3339 timestamp (e.g. "2026-12-31T00:00:00Z"): `+err.Error())
		return
	}
	until = until.UTC()

	now := time.Now().UTC()
	// An already-expired acceptance would be recorded, change nothing,
	// and read to whoever set it as though the finding had been
	// suppressed -- the worst failure direction this feature has.
	if !until.After(now) {
		writeError(w, http.StatusBadRequest, "until must be in the future -- an acceptance that has already expired suppresses nothing")
		return
	}
	if until.After(now.Add(maxAcceptanceDays * 24 * time.Hour)) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("until may be at most %d days out -- a longer acceptance is a deletion with extra steps", maxAcceptanceDays))
		return
	}

	// Never from the body. See the handler comment.
	acceptedBy := ClientFromContext(r.Context())

	found := false
	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		found = applyToFindingID(art, findingID, func(f *artifact.Finding) {
			f.AcceptedUntil = &until
			f.AcceptedBy = acceptedBy
			f.AcceptanceReason = reason
		})
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no finding "+findingID+" on artifact "+id)
		return
	}

	slog.Info("finding risk accepted",
		"artifact_id", id, "finding_id", findingID,
		"accepted_by", acceptedBy, "accepted_until", until.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, updated)
}

// revokeFindingAcceptance ends an acceptance early, putting the finding
// straight back into every count and policy evaluation.
//
// Idempotent: revoking an acceptance that isn't there is a 200, not a
// 404. The caller asked for a state ("this finding is not accepted")
// and that state holds when the call returns, which is the only thing
// it can act on -- and an acceptance that lapsed on its own between the
// decision to revoke and the call arriving is not an error anybody can
// do anything about. A 404 is reserved for the two things that really
// are the caller's mistake: an artifact or a finding id that does not
// exist.
//
// Clears the reason and accepter alongside the expiry rather than
// leaving them as a partial record: they describe an acceptance that is
// no longer in force, and a finding showing "accepted by X because Y"
// with no date would read as a suppression with no end.
func (h *handler) revokeFindingAcceptance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	findingID := r.PathValue("findingID")

	found := false
	updated, err := h.store.Update(id, func(art *artifact.Artifact) {
		found = applyToFindingID(art, findingID, func(f *artifact.Finding) {
			f.AcceptedUntil = nil
			f.AcceptedBy = ""
			f.AcceptanceReason = ""
		})
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no finding "+findingID+" on artifact "+id)
		return
	}

	slog.Info("finding risk acceptance revoked",
		"artifact_id", id, "finding_id", findingID,
		"client", ClientFromContext(r.Context()))
	writeJSON(w, http.StatusOK, updated)
}

// applyToFindingID runs apply against every finding carrying findingID,
// in all five buckets, and reports whether it matched anything.
//
// Takes a *Artifact and indexes the slices rather than ranging over
// copies -- `for _, f := range art.CVEFindings` hands out a copy per
// iteration, so mutating it would write to nothing at all, silently.
func applyToFindingID(art *artifact.Artifact, findingID string, apply func(*artifact.Finding)) bool {
	found := false
	for _, bucket := range [][]artifact.Finding{
		art.CVEFindings, art.MalwareFindings, art.MisconfigFindings,
		art.SecretFindings, art.OtherFindings,
	} {
		for i := range bucket {
			if bucket[i].ID == findingID {
				apply(&bucket[i])
				found = true
			}
		}
	}
	return found
}
