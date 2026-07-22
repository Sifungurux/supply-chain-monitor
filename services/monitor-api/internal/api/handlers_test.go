package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// fakeScanner lets tests exercise the multi-scanner-per-type routing in
// scanArtifact without needing real trivy/clamav/unpacker binaries.
type fakeScanner struct {
	findings []artifact.Finding
	err      error
}

func (f *fakeScanner) Scan(_ context.Context, _ string) ([]artifact.Finding, error) {
	return f.findings, f.err
}

// testAPIKey is the shared key every test router is constructed with.
// doJSON below attaches it to every request automatically, so the ~10
// existing tests that only care about handler behavior (not auth
// itself) didn't need individual edits when auth was added -- see
// TestAuth* below for the auth behavior itself.
const testAPIKey = "test-api-key"

func newTestRouter(scanners scanner.Registry) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(store, tracker, scanners, testAPIKey), store
}

// mustCreate is a test helper wrapping store.Create's now-error-returning
// signature (needed for the Postgres-backed Store interface), since
// most of these tests just want a valid artifact and would rather fail
// loudly than thread the error through every call site.
func mustCreate(t *testing.T, store *artifact.MemStore, ref string, ty artifact.Type) *artifact.Artifact {
	t.Helper()
	a, err := store.Create(ref, ty)
	if err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	return a
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeArtifact(t *testing.T, rec *httptest.ResponseRecorder) artifact.Artifact {
	t.Helper()
	var a artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode artifact response: %v (body=%s)", err, rec.Body.String())
	}
	return a
}

func TestHealthz(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	rec := doJSON(t, h, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestListStages(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	rec := doJSON(t, h, http.MethodGet, "/api/v1/pipeline/stages", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Stages []string `json:"stages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Stages) != 7 {
		t.Fatalf("stages = %v, want 7 entries", body.Stages)
	}
}

func TestCreateArtifact(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	t.Run("valid", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "alpine:3.19", "type": "image"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		a := decodeArtifact(t, rec)
		if a.ID == "" {
			t.Fatal("expected a generated id")
		}
		if a.Status != artifact.StatusRegistered {
			t.Fatalf("status = %q, want %q", a.Status, artifact.StatusRegistered)
		}
	})

	t.Run("missing ref", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"type": "image"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "x", "type": "binary"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestListAndGetArtifact(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var list []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}

	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec = doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := decodeArtifact(t, rec)
	if got.ID != created.ID {
		t.Fatalf("id = %q, want %q", got.ID, created.ID)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/artifacts/does-not-exist", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestFindByFindingID exercises the endpoint that exists specifically
// because findings live in their own table now (see
// docs/architecture.md, "Normalizing findings and stage history into
// their own tables") -- MemStore's FindByFindingID is a linear scan,
// PostgresStore's is an indexed query, but handlers.go doesn't know or
// care which Store it's talking to.
func TestFindByFindingID(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-9999", Severity: "high", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})

	affected := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustCreate(t, store, "debian:12", artifact.TypeImage) // never scanned -- must not show up below

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+affected.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/findings/CVE-2024-9999/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var list []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 || list[0].ID != affected.ID {
		t.Fatalf("findings-by-id list = %+v, want just %q", list, affected.ID)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/findings/CVE-does-not-exist/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty list, not an error)", rec.Code)
	}
	var empty []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &empty); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected an empty list for an unmatched finding id, got %+v", empty)
	}
}

func TestScanArtifact_NoScannerRegistered(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "some.sbom.json", artifact.TypeSBOM)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501, body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanArtifact_MergesFindingsBySource(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}}}
	clamavLike := &fakeScanner{findings: []artifact.Finding{{ID: "clamav-signature-match", Severity: "critical", Source: "clamav"}}}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {trivyLike, clamavLike},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusScanned)
	}
	if len(got.CVEFindings) != 1 || got.CVEFindings[0].Source != "trivy" {
		t.Fatalf("cve findings = %+v", got.CVEFindings)
	}
	if len(got.MalwareFindings) != 1 || got.MalwareFindings[0].Source != "clamav" {
		t.Fatalf("malware findings = %+v", got.MalwareFindings)
	}
	if len(got.LastScanErrors) != 0 {
		t.Fatalf("expected no scan errors, got %v", got.LastScanErrors)
	}
}

// Regression test: SARIF findings (Finding.Source == "sarif") must land
// in OtherFindings, not CVEFindings -- SARIF covers SAST issues,
// secrets, and misconfigurations, not just CVEs, so folding it into
// the CVE bucket would mislabel it (see SARIFScanner's doc comment).
func TestScanArtifact_SARIFFindingsGoToOtherBucket(t *testing.T) {
	sarifLike := &fakeScanner{findings: []artifact.Finding{{ID: "no-hardcoded-secret", Severity: "high", Source: "sarif"}}}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeSARIF: {sarifLike},
	})
	created := mustCreate(t, store, "/tmp/results.sarif", artifact.TypeSARIF)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.OtherFindings) != 1 || got.OtherFindings[0].ID != "no-hardcoded-secret" {
		t.Fatalf("other findings = %+v, want the sarif finding", got.OtherFindings)
	}
	if len(got.CVEFindings) != 0 {
		t.Fatalf("expected sarif findings to stay out of cve_findings, got %+v", got.CVEFindings)
	}
}

func TestScanArtifact_PartialFailureStillReportsSuccessfulFindings(t *testing.T) {
	ok := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-2", Source: "trivy"}}}
	broken := &fakeScanner{err: errors.New("unpacker: pull failed")}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {ok, broken},
	})
	created := mustCreate(t, store, "ghcr.io/example/app:latest", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (one of two scanners still succeeded), body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusScanned)
	}
	if len(got.CVEFindings) != 1 {
		t.Fatalf("expected the successful scanner's finding to survive, got %+v", got.CVEFindings)
	}
	if len(got.LastScanErrors) != 1 {
		t.Fatalf("expected the failed scanner's error to be recorded, got %v", got.LastScanErrors)
	}
}

func TestScanArtifact_AllScannersFail(t *testing.T) {
	broken1 := &fakeScanner{err: errors.New("trivy: exec failed")}
	broken2 := &fakeScanner{err: errors.New("unpacker: pull failed")}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {broken1, broken2},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.Status != artifact.StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusFailed)
	}
	if len(got.LastScanErrors) != 2 {
		t.Fatalf("expected both scanner errors recorded, got %v", got.LastScanErrors)
	}
}

// sequenceScanner returns a different result on each successive call --
// lets a test simulate "the same artifact, scanned twice, with a
// different result the second time" (a finding disappearing, a scanner
// starting to fail) against a single router/registry, since fakeScanner
// always returns the same fixed result every call.
type sequenceScanner struct {
	calls   int
	results [][]artifact.Finding
	errs    []error
}

func (s *sequenceScanner) Scan(_ context.Context, _ string) ([]artifact.Finding, error) {
	i := s.calls
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	s.calls++
	var err error
	if i < len(s.errs) {
		err = s.errs[i]
	}
	return s.results[i], err
}

// TestScanArtifact_SecondScanMarksMissingFindingAsFixed is the core
// behavior MergeFindings exists for: a CVE that stops being reported
// must show up as fixed (with ResolvedAt set), not just silently
// disappear the way a naive "replace the bucket" implementation would.
func TestScanArtifact_SecondScanMarksMissingFindingAsFixed(t *testing.T) {
	trivy := &sequenceScanner{
		results: [][]artifact.Finding{
			{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}},
			{}, // second scan: CVE-2024-1 no longer present
		},
	}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivy}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.CVEFindings) != 1 || got.CVEFindings[0].Status != artifact.FindingStatusOpen {
		t.Fatalf("after first scan, cve findings = %+v", got.CVEFindings)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("second scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got = decodeArtifact(t, rec)
	if len(got.CVEFindings) != 1 {
		t.Fatalf("expected the CVE to still be present (fixed, not deleted), got %+v", got.CVEFindings)
	}
	f := got.CVEFindings[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil {
		t.Fatal("resolved_at is nil, want it set once the CVE stopped being reported")
	}
}

// TestScanArtifact_PartialFailureDoesNotMarkFindingsFixed is the flip
// side: a scan round where some other scanner errored must not mark a
// bucket's missing findings as fixed just because that round's report
// can't be trusted as complete. Without this, one flaky scanner run
// could make a real, still-present CVE look resolved.
func TestScanArtifact_PartialFailureDoesNotMarkFindingsFixed(t *testing.T) {
	trivy := &sequenceScanner{
		results: [][]artifact.Finding{
			{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}},
			{}, // trivy itself reports nothing this round
		},
	}
	broken := &sequenceScanner{
		results: [][]artifact.Finding{{}, {}},
		errs:    []error{nil, errors.New("clamav: connection refused")},
	}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivy, broken}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// Second scan: trivy no longer reports CVE-2024-1, AND the other
	// scanner errors this round -- a partial failure. If the CVE bucket
	// were merged as if this round were trustworthy, the missing CVE
	// would look "fixed" even though nothing about it actually changed
	// -- the only real event this round is an unrelated scanner breaking.
	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("second scan status = %d, want 200 (one of two scanners still ran), body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.CVEFindings) != 1 {
		t.Fatalf("expected the CVE to survive untouched despite the partial failure, got %+v", got.CVEFindings)
	}
	if got.CVEFindings[0].Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q (a partial-failure round must not mark findings fixed)", got.CVEFindings[0].Status, artifact.FindingStatusOpen)
	}
	if got.CVEFindings[0].ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil", got.CVEFindings[0].ResolvedAt)
	}
	if len(got.LastScanErrors) != 1 {
		t.Fatalf("expected the broken scanner's error recorded, got %v", got.LastScanErrors)
	}
}

// ctxCapturingScanner records whether the context it was handed was
// already canceled, without actually depending on real time passing.
type ctxCapturingScanner struct {
	sawCanceledCtx bool
}

func (c *ctxCapturingScanner) Scan(ctx context.Context, _ string) ([]artifact.Finding, error) {
	if ctx.Err() != nil {
		c.sawCanceledCtx = true
		return nil, ctx.Err()
	}
	return []artifact.Finding{{ID: "CVE-OK", Source: "trivy"}}, nil
}

// Regression test: scanArtifact used to derive the scan's context from
// r.Context(), so a client that disconnected mid-scan (idle timeout,
// closed tab) would cancel every scanner still running or yet to run --
// surfacing as spurious "signal: killed" / "context canceled" errors on
// a scan that was otherwise working fine. The scan must run to
// completion (and the store must reflect that) regardless of what
// happens to the original HTTP request.
func TestScanArtifact_SurvivesCanceledRequestContext(t *testing.T) {
	s := &ctxCapturingScanner{}
	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {s},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	cancelReq() // simulate the client disconnecting before the handler even starts scanning

	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", bytes.NewReader(nil)).WithContext(reqCtx)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if s.sawCanceledCtx {
		t.Fatal("scanner saw an already-canceled context -- scanArtifact must not derive the scan's context from r.Context()")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q (scan should complete despite the canceled request context)", got.Status, artifact.StatusScanned)
	}
}

func TestUpdateStage(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/stage", map[string]string{"stage": "build", "note": "CI job #1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.CurrentStage != "build" {
		t.Fatalf("current_stage = %q, want %q", got.CurrentStage, "build")
	}
	if len(got.StageHistory) != 1 || got.StageHistory[0].Note != "CI job #1" {
		t.Fatalf("stage_history = %+v", got.StageHistory)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/stage", map[string]string{"stage": "not-a-real-stage"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown stage", rec.Code)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/stage", map[string]string{"stage": "build"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestSubmitFindings covers the happy path an external pipeline (its
// own malware scanner, its own SAST tool) would actually take: a
// freshly-registered artifact that never went through scanArtifact at
// all, submitting findings directly into one bucket.
func TestSubmitFindings(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "docker.io/cloudelements/eicar:latest", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "malware",
		"findings": []map[string]string{
			{"id": "eicar-test-signature", "severity": "critical", "title": "EICAR test file detected", "source": "external-clamav"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MalwareFindings) != 1 || got.MalwareFindings[0].ID != "eicar-test-signature" {
		t.Fatalf("malware_findings = %+v", got.MalwareFindings)
	}
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q (a registered artifact that just received findings has meaningfully been scanned)", got.Status, artifact.StatusScanned)
	}
	if len(got.CVEFindings) != 0 || len(got.OtherFindings) != 0 {
		t.Fatalf("expected the other two buckets to stay untouched, got cve=%+v other=%+v", got.CVEFindings, got.OtherFindings)
	}
}

// TestSubmitFindings_LeavesOtherBucketsAlone is the specific behavior
// that makes this safe to use alongside monitor-api's own scanArtifact:
// submitting external malware results must never disturb CVE findings
// a real Trivy scan already produced (unlike scanArtifact, which
// touches all three buckets on every call).
func TestSubmitFindings_LeavesOtherBucketsAlone(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "malware",
		"findings": []map[string]string{
			{"id": "eicar-test-signature", "severity": "critical", "source": "external-clamav"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("findings status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MalwareFindings) != 1 {
		t.Fatalf("malware_findings = %+v", got.MalwareFindings)
	}
	if len(got.CVEFindings) != 1 || got.CVEFindings[0].ID != "CVE-2024-1" {
		t.Fatalf("expected the earlier trivy-sourced CVE finding to survive, got %+v", got.CVEFindings)
	}
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q (already scanned; submitFindings shouldn't change it)", got.Status, artifact.StatusScanned)
	}
}

// TestSubmitFindings_SecondCallMarksMissingFindingAsFixed proves
// /findings gets the same fixed-not-deleted behavior as /scan: an
// external pipeline reporting a clean second result (no more malware
// found) must show the earlier finding as fixed, not just erase it.
func TestSubmitFindings_SecondCallMarksMissingFindingAsFixed(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "docker.io/cloudelements/eicar:latest", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "malware",
		"findings": []map[string]string{
			{"id": "eicar-test-signature", "severity": "critical", "source": "external-clamav"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("first submission status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// Re-scanned externally, clean this time.
	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket":   "malware",
		"findings": []map[string]string{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("second submission status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MalwareFindings) != 1 {
		t.Fatalf("expected the earlier malware finding to still be present (fixed, not deleted), got %+v", got.MalwareFindings)
	}
	f := got.MalwareFindings[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil {
		t.Fatal("resolved_at is nil, want it set once the second submission stopped reporting it")
	}
}

func TestSubmitFindings_InvalidBucket(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket":   "not-a-real-bucket",
		"findings": []map[string]string{},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown bucket", rec.Code)
	}
}

func TestSubmitFindings_UnknownArtifact(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/findings", map[string]any{
		"bucket":   "malware",
		"findings": []map[string]string{},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestCORSHeaders(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodGet, "/healthz", nil)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/artifacts", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("expected Access-Control-Allow-Methods header on preflight response")
	}
}

// TestAuth_HealthzExempt: liveness/readiness probes have no way to
// carry a bearer token, so /healthz must stay reachable without one.
func TestAuth_HealthzExempt(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no Authorization header sent)", rec.Code)
	}
}

// TestAuth_OptionsPreflightExempt: real browsers never attach an
// Authorization header to a CORS preflight OPTIONS request, so it
// must be handled before withAuth ever runs (see router.go's ordering
// comment) or every cross-origin call from the dashboard would fail
// preflight before the real request is even attempted.
func TestAuth_OptionsPreflightExempt(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (no Authorization header sent)", rec.Code)
	}
}

func TestAuth_MissingKeyRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no Authorization header at all)", rec.Code)
	}
}

func TestAuth_WrongKeyRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer not-the-right-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong key)", rec.Code)
	}
}

func TestAuth_MalformedHeaderRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", testAPIKey) // missing "Bearer " prefix
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (missing Bearer prefix)", rec.Code)
	}
}

func TestAuth_CorrectKeyAccepted(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}
