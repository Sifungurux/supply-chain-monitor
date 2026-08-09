package api

import (
	"encoding/json"
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
