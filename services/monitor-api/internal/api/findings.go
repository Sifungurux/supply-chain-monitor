package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
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
