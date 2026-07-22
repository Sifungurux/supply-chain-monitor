package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

type handler struct {
	store    artifact.Store
	tracker  *pipeline.Tracker
	scanners scanner.Registry
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

	a, err := h.store.Create(req.Ref, t)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Every scanner registered for this artifact type runs; findings are
	// sorted into CVE/malware/other buckets by Finding.Source rather
	// than by artifact type, since a single type (image) can produce
	// more than one kind. "sarif" is its own bucket (OtherFindings)
	// rather than folded into CVEFindings -- SARIF covers SAST issues,
	// secrets, IaC misconfigurations, and more, not just CVEs, so
	// calling it a CVE finding would mislabel it. Everything that isn't
	// explicitly clamav or sarif defaults to the CVE bucket, which
	// today just means "trivy" but keeps this open to future
	// CVE-flavored scanners without another switch-case edit.
	var cveFindings, malwareFindings, otherFindings []artifact.Finding
	var scanErrors []string

	for _, s := range scanners {
		findings, scanErr := s.Scan(ctx, a.Ref)
		if scanErr != nil {
			scanErrors = append(scanErrors, scanErr.Error())
		}
		for _, f := range findings {
			switch f.Source {
			case "clamav":
				malwareFindings = append(malwareFindings, f)
			case "sarif":
				otherFindings = append(otherFindings, f)
			default:
				cveFindings = append(cveFindings, f)
			}
		}
	}

	status := artifact.StatusScanned
	if len(scanErrors) == len(scanners) {
		status = artifact.StatusFailed
	}

	// detectFixed gates whether MergeFindings is allowed to mark
	// anything as fixed this round: if any registered scanner errored,
	// this round's report can't be trusted as a complete picture of
	// every bucket (e.g. Trivy erroring while ClamAV succeeds would
	// otherwise make every previously-open CVE look "fixed" just
	// because Trivy didn't run, not because any of them got patched).
	// A fully clean run (no scanErrors at all) is the only time a
	// missing finding safely means "actually fixed." See merge.go's own
	// doc comment for the full reasoning, including the corresponding
	// per-bucket-not-per-scanner precision this simplification gives
	// up (documented as a roadmap item, not silently ignored).
	now := time.Now().UTC()
	detectFixed := len(scanErrors) == 0
	updated, updErr := h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = status
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, cveFindings, now, detectFixed)
		art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, malwareFindings, now, detectFixed)
		art.OtherFindings = artifact.MergeFindings(art.OtherFindings, otherFindings, now, detectFixed)
		art.LastScanErrors = scanErrors
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

// validFindingsBucket checks the bucket name submitFindings was given.
// These three literal strings are an API-contract detail of this
// package -- kept separate from internal/artifact/postgres_store.go's
// own bucketCVE/bucketMalware/bucketOther constants, which exist for a
// different reason (Postgres table rows) and MemStore doesn't use at
// all. Matches the same "cve"/"malware"/"other" vocabulary scanArtifact
// already sorts Finding.Source into above, just made explicit here
// instead of inferred from a Source string.
func validFindingsBucket(bucket string) bool {
	switch bucket {
	case "cve", "malware", "other":
		return true
	default:
		return false
	}
}

type submitFindingsRequest struct {
	// Bucket picks which of the artifact's three finding buckets this
	// call writes into ("cve", "malware", or "other" -- see
	// artifact.Artifact's CVEFindings/MalwareFindings/OtherFindings).
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
// CVEFindings/MalwareFindings/OtherFindings) always calls a registered
// Scanner's Scan(ctx, ref), which always does its own fetch+scan of ref
// internally -- there was previously no path for "here are findings I
// already computed, just store them." See docs/architecture.md
// ("Submitting external findings directly") for the full reasoning,
// including why this is a new endpoint rather than another Scanner
// implementation (a Scanner's contract is "given a ref, go compute
// findings" -- this handler's input already *is* the findings, so it
// doesn't fit that shape).
//
// Deliberately touches only the one bucket named in the request,
// unlike scanArtifact (which merges into all three buckets every call,
// since it always re-runs every registered scanner for the type at
// once). An external system submitting its own malware results has no
// way to know what Trivy or a SARIF import already found for this same
// artifact, so touching the other two buckets here would risk
// corrupting real data.
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
		writeError(w, http.StatusBadRequest, "bucket must be one of cve, malware, other")
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
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
