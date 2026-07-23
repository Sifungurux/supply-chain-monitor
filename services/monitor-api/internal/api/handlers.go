package api

import (
	"context"
	"encoding/json"
	"fmt"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
			findings, scanErr := s.Scan(ctx, a.Ref)
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

	now := time.Now().UTC()
	updated, updErr := h.store.Update(id, func(art *artifact.Artifact) {
		art.Status = status
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, cveFindings, now, detectFixedFor("cve"))
		art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, malwareFindings, now, detectFixedFor("malware"))
		art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, misconfigFindings, now, detectFixedFor("misconfiguration"))
		art.SecretFindings = artifact.MergeFindings(art.SecretFindings, secretFindings, now, detectFixedFor("secret"))
		art.OtherFindings = artifact.MergeFindings(art.OtherFindings, otherFindings, now, detectFixedFor("other"))
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
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
