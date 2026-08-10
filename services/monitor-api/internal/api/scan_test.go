package api_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestScanArtifact_NoScannerRegistered(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "some.sbom.json", artifact.TypeSBOM)

	rec, _ := scanAndWait(t, h, store, created.ID)
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

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
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

// TestScanArtifact_CoalescesSameCVEAcrossScanners covers trivy+grype (or
// any two CVE scanners) both reporting the same CVE ID in one round --
// it must land as one finding with a joined Source, not two findings
// where the second silently overwrites the first.
func TestScanArtifact_CoalescesSameCVEAcrossScanners(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}}}
	grypeLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "high", Source: "grype"}}}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {trivyLike, grypeLike},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if len(got.CVEFindings) != 1 {
		t.Fatalf("cve findings = %+v, want 1 coalesced finding", got.CVEFindings)
	}
	if got.CVEFindings[0].Source != "grype, trivy" {
		t.Fatalf("source = %q, want %q", got.CVEFindings[0].Source, "grype, trivy")
	}
}

// TestScanArtifact_BackfillsMissingDigest covers the actual real-world
// gap this exists to close: registration-time digest resolution is
// best-effort and never retried on its own (see resolveDigest's own
// comment) -- a registry that's rate-limited or briefly unreachable at
// registration time leaves an artifact's digest empty forever, even
// though the exact same ref resolves fine moments later. A routine scan
// is a natural second chance to fill it in.
func TestScanArtifact_BackfillsMissingDigest(t *testing.T) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:backfilled"}}
	h := api.NewRouter(store, tracker, scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
	}, testAPIKey, 0, 0, resolver, false, 0, false, api.ScanLimits{})

	// mustCreate goes straight through the store, bypassing
	// createArtifact's own registration-time resolveDigest call --
	// simulating exactly the artifact this feature targets: registered
	// with no digest, because resolution wasn't attempted or failed.
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if created.Digest != "" {
		t.Fatalf("test setup: expected no digest yet, got %q", created.Digest)
	}

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if got.Digest != "sha256:backfilled" {
		t.Fatalf("digest = %q, want the resolver's value backfilled by the scan", got.Digest)
	}
}

// TestScanArtifact_DoesNotReResolveAnAlreadySetDigest proves the backfill
// is opportunistic, not a re-verification on every scan: an artifact that
// already has a digest must never trigger a second registry round trip
// just because it got scanned again.
func TestScanArtifact_DoesNotReResolveAnAlreadySetDigest(t *testing.T) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:should-never-be-fetched"}}
	h := api.NewRouter(store, tracker, scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
	}, testAPIKey, 0, 0, resolver, false, 0, false, api.ScanLimits{})

	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(created.ID, func(a *artifact.Artifact) { a.Digest = "sha256:already-set" }); err != nil {
		t.Fatalf("store.Update: %v", err)
	}

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if got.Digest != "sha256:already-set" {
		t.Fatalf("digest = %q, want the pre-existing digest left untouched", got.Digest)
	}
	if resolver.calls.Load() != 0 {
		t.Fatalf("resolver.Resolve called %d times, want 0 -- an already-resolved digest must not trigger a redundant registry call", resolver.calls.Load())
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

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if len(got.OtherFindings) != 1 || got.OtherFindings[0].ID != "no-hardcoded-secret" {
		t.Fatalf("other findings = %+v, want the sarif finding", got.OtherFindings)
	}
	if len(got.CVEFindings) != 0 {
		t.Fatalf("expected sarif findings to stay out of cve_findings, got %+v", got.CVEFindings)
	}
}

// TestScanArtifact_CategoryRoutesToMisconfigAndSecretBuckets covers
// the new classifier-driven routing: a Scanner (SARIFScanner in
// practice) that sets Finding.Category explicitly should land in that
// bucket regardless of Source, splitting misconfiguration and secret
// findings out of the OtherFindings catch-all.
func TestScanArtifact_CategoryRoutesToMisconfigAndSecretBuckets(t *testing.T) {
	sarifLike := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2023-1", Severity: "high", Source: "sarif", Category: "cve"},
		{ID: "AVD-AWS-1", Severity: "medium", Source: "sarif", Category: "misconfiguration"},
		{ID: "aws-secret", Severity: "critical", Source: "sarif", Category: "secret"},
		{ID: "license-gpl", Severity: "low", Source: "sarif", Category: "other"},
	}}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeSARIF: {sarifLike},
	})
	created := mustCreate(t, store, "/tmp/results.sarif", artifact.TypeSARIF)

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned

	if len(got.CVEFindings) != 1 || got.CVEFindings[0].ID != "CVE-2023-1" {
		t.Fatalf("cve findings = %+v", got.CVEFindings)
	}
	if len(got.MisconfigFindings) != 1 || got.MisconfigFindings[0].ID != "AVD-AWS-1" {
		t.Fatalf("misconfiguration findings = %+v", got.MisconfigFindings)
	}
	if len(got.SecretFindings) != 1 || got.SecretFindings[0].ID != "aws-secret" {
		t.Fatalf("secret findings = %+v", got.SecretFindings)
	}
	if len(got.OtherFindings) != 1 || got.OtherFindings[0].ID != "license-gpl" {
		t.Fatalf("other findings = %+v", got.OtherFindings)
	}
	if len(got.MalwareFindings) != 0 {
		t.Fatalf("expected no malware findings, got %+v", got.MalwareFindings)
	}
}

func TestScanArtifact_PartialFailureStillReportsSuccessfulFindings(t *testing.T) {
	ok := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-2", Source: "trivy"}}}
	broken := &fakeScanner{err: errors.New("unpacker: pull failed")}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {ok, broken},
	})
	created := mustCreate(t, store, "ghcr.io/example/app:latest", artifact.TypeImage)

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (one of two scanners still succeeded), body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
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

// TestScanArtifact_ScannersRunConcurrently is the regression test for
// the fix itself: scanArtifact used to run every registered scanner
// for a type one after another, so N scanners each taking `delay`
// added up to N*delay of total wall-clock time. Three scanners each
// sleeping 150ms would take ~450ms sequentially but should take barely
// more than 150ms running concurrently -- generous enough headroom
// (400ms) to not be flaky on a loaded CI machine while still clearly
// distinguishing "ran in parallel" from "ran one after another".
func TestScanArtifact_ScannersRunConcurrently(t *testing.T) {
	delay := 150 * time.Millisecond
	s1 := &sleepingScanner{delay: delay, findings: []artifact.Finding{{ID: "CVE-1", Source: "trivy"}}}
	s2 := &sleepingScanner{delay: delay, findings: []artifact.Finding{{ID: "eicar", Source: "clamav"}}}
	s3 := &sleepingScanner{delay: delay}

	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {s1, s2, s3}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	start := time.Now()
	rec, scanned := scanAndWait(t, h, store, created.ID)
	elapsed := time.Since(start)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("scan took %v, want well under %v (three %v scanners should overlap, not run one after another)", elapsed, 400*time.Millisecond, delay)
	}

	got := *scanned
	if len(got.CVEFindings) != 1 || len(got.MalwareFindings) != 1 {
		t.Fatalf("expected both scanners' findings to still land in the right buckets, got cve=%+v malware=%+v", got.CVEFindings, got.MalwareFindings)
	}
}

// TestScanArtifact_ScannerPanicIsRecovered proves a bug in one
// Scanner (in-process code, or an operator's own PluggableScanner
// command misbehaving) can't crash the whole monitor-api process now
// that scanners run on their own goroutines -- net/http's per-request
// panic recovery covers this handler's own goroutine, not one it
// spawns itself, so scanArtifact has to recover from a scanner panic
// itself and turn it into an ordinary scan error instead.
func TestScanArtifact_ScannerPanicIsRecovered(t *testing.T) {
	ok := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Source: "trivy"}}}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {ok, panickingScanner{}},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (one of two scanners still succeeded), body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if len(got.CVEFindings) != 1 {
		t.Fatalf("expected the non-panicking scanner's finding to survive, got %+v", got.CVEFindings)
	}
	if len(got.LastScanErrors) != 1 {
		t.Fatalf("expected the panic to be recorded as a scan error, got %v", got.LastScanErrors)
	}

	// The test process itself reaching this line at all is most of what
	// this test is proving -- an unrecovered panic in a spawned
	// goroutine would have crashed the whole test binary, not just
	// failed this one assertion.
	//
	// The recorded error is the classified, friendly message (see
	// scanner.ClassifyScanError) -- never the raw "boom: this scanner
	// has a bug" panic text, which is logged server-side instead of
	// returned to the caller.
	if bytes.Contains(rec.Body.Bytes(), []byte("boom: this scanner has a bug")) {
		t.Fatalf("expected the raw panic text to be classified away, got body=%s", rec.Body.String())
	}
	if got.LastScanErrors[0] != "Scanner encountered an internal error" {
		t.Fatalf("expected the classified panic message, got %q", got.LastScanErrors[0])
	}
	if got.LastScanFailureReason != "" {
		t.Fatalf("one of two scanners still succeeded, LastScanFailureReason should stay unset, got %q", got.LastScanFailureReason)
	}
}

func TestScanArtifact_AllScannersFail(t *testing.T) {
	broken1 := &fakeScanner{err: errors.New("trivy: exec failed")}
	broken2 := &fakeScanner{err: errors.New("unpacker: pull failed")}

	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {broken1, broken2},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	// The 502 this used to answer is gone with the 202: by the time
	// every scanner has failed, the response was written long ago. The
	// failure surfaces as the artifact's own status instead, which is
	// what a polling caller reads.
	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if got.Status != artifact.StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, artifact.StatusFailed)
	}
	if len(got.LastScanErrors) != 2 {
		t.Fatalf("expected both scanner errors recorded, got %v", got.LastScanErrors)
	}
	// Neither raw scanner error string should ever reach the API
	// response -- only the classified, friendly message. Both fixtures
	// here don't match any known pattern, so both should land on the
	// "unknown" reason/message rather than leaking their raw text.
	for _, raw := range []string{"trivy: exec failed", "unpacker: pull failed"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(raw)) {
			t.Fatalf("raw scanner error %q leaked into the response, body=%s", raw, rec.Body.String())
		}
	}
	if got.LastScanFailureReason != "unknown" {
		t.Fatalf("LastScanFailureReason = %q, want %q (every scanner failed, neither error matched a known pattern)", got.LastScanFailureReason, "unknown")
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
	// bucket, if set, makes this double implement scanner.BucketAffinity
	// (see TestScanArtifact_FailureOnlyBlocksItsOwnBucket) -- left unset
	// ("") by every other test using this double, which Bucket()
	// faithfully returns, so those tests keep exercising the "unknown
	// affinity blocks every bucket" fallback path exactly as before this
	// field existed.
	bucket string
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

func (s *sequenceScanner) Bucket() string { return s.bucket }

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

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if len(got.CVEFindings) != 1 || got.CVEFindings[0].Status != artifact.FindingStatusOpen {
		t.Fatalf("after first scan, cve findings = %+v", got.CVEFindings)
	}

	rec, scanned = scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("second scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got = *scanned
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

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}

	// Second scan: trivy no longer reports CVE-2024-1, AND the other
	// scanner errors this round -- a partial failure. If the CVE bucket
	// were merged as if this round were trustworthy, the missing CVE
	// would look "fixed" even though nothing about it actually changed
	// -- the only real event this round is an unrelated scanner breaking.
	rec, scanned = scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("second scan status = %d, want 202 (one of two scanners still ran), body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
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

// TestScanArtifact_FailureOnlyBlocksItsOwnBucket is the fix-detection
// precision improvement over TestScanArtifact_PartialFailureDoesNotMarkFindingsFixed
// just above: that test's doubles don't declare a bucket, so a failure
// conservatively blocks every bucket -- the correct, safe fallback for
// a scanner that can't honestly say which bucket(s) it would have
// affected. This test's doubles DO declare one (via sequenceScanner's
// bucket field, mirroring scanner.BucketAffinity's real implementers --
// TrivyScanner, ClamAVScanner, etc.), so a malware scanner erroring must
// no longer block CVE fix-detection: the two are unrelated buckets, and
// scanArtifact now knows that instead of assuming the worst everywhere.
func TestScanArtifact_FailureOnlyBlocksItsOwnBucket(t *testing.T) {
	trivy := &sequenceScanner{
		bucket: "cve",
		results: [][]artifact.Finding{
			{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}},
			{}, // second scan: CVE-2024-1 no longer present -- should be marked fixed
		},
	}
	broken := &sequenceScanner{
		bucket:  "malware",
		results: [][]artifact.Finding{{}, {}},
		errs:    []error{nil, errors.New("clamav: connection refused")},
	}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivy, broken}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}

	// Second scan: trivy (bucket "cve") succeeds and no longer reports
	// CVE-2024-1; the malware-bucket scanner errors. Only the malware
	// bucket should be blocked from fix-detection -- CVE-2024-1 should
	// still be marked fixed, since the scanner that failed couldn't have
	// produced a CVE finding anyway.
	rec, scanned = scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("second scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned
	if len(got.CVEFindings) != 1 {
		t.Fatalf("expected CVE-2024-1 to still be present (fixed, not deleted), got %+v", got.CVEFindings)
	}
	if got.CVEFindings[0].Status != artifact.FindingStatusFixed {
		t.Fatalf("CVE status = %q, want %q -- a malware scanner failing shouldn't block CVE fix-detection", got.CVEFindings[0].Status, artifact.FindingStatusFixed)
	}
	if got.CVEFindings[0].ResolvedAt == nil {
		t.Fatal("resolved_at is nil, want it set now that the CVE bucket was free to detect the fix")
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
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := waitForScan(t, store, created.ID)
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q (scan should complete despite the canceled request context)", got.Status, artifact.StatusScanned)
	}
}

// newScanCappedRouter builds a router with a scan concurrency cap.
func newScanCappedRouter(scanners scanner.Registry, concurrency int) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(store, tracker, scanners, testAPIKey, 0, 0, nil, false, 0, false,
		api.ScanLimits{Concurrency: concurrency}), store
}

// TestScanArtifact_ConcurrencyCapRejectsWhenSaturated -- with scans
// asynchronous, a saturated cap answers 429 immediately rather than
// queueing: nobody is blocked on the response, so there is no client
// experience a wait would improve, and no server-side backlog to lose
// on a restart. The artifact must also NOT be left marked "scanning",
// which is what taking the slot after the status flip would cause.
func TestScanArtifact_ConcurrencyCapRejectsWhenSaturated(t *testing.T) {
	slow := &sleepingScanner{delay: 2 * time.Second}
	h, store := newScanCappedRouter(scanner.Registry{artifact.TypeImage: {slow}}, 1)
	first := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	second := mustCreate(t, store, "busybox:latest", artifact.TypeImage)

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+first.ID+"/scan", nil); rec.Code != http.StatusAccepted {
		t.Fatalf("first scan status = %d, want 202", rec.Code)
	}

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+second.ID+"/scan", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second scan status = %d, want 429, body=%s", rec.Code, rec.Body.String())
	}
	retryAfter, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || retryAfter <= 0 {
		t.Fatalf("Retry-After = %q, want a positive integer (err=%v)", rec.Header().Get("Retry-After"), err)
	}
	if !strings.Contains(rec.Body.String(), "scan concurrency") {
		t.Fatalf("429 body = %s, want it to name the scan cap (withRateLimit answers 429 too)", rec.Body.String())
	}

	rejected, getErr := store.Get(second.ID)
	if getErr != nil {
		t.Fatalf("store.Get: %v", getErr)
	}
	if rejected.Status == artifact.StatusScanning {
		t.Fatalf("a rejected scan left artifact %s marked %q -- the slot must be taken before the status flips", second.ID, rejected.Status)
	}
}

// TestScanArtifact_ConcurrencyCapReleasesSlotWhenScanFinishes is the
// test that catches a leaked slot. runScan owns the release now (the
// handler returns long before the scan does), so a missed release would
// permanently shrink the cap -- and with cap 1, 429 every scan from
// then on, forever. Nothing else in this suite would notice.
func TestScanArtifact_ConcurrencyCapReleasesSlotWhenScanFinishes(t *testing.T) {
	quick := &sleepingScanner{delay: 20 * time.Millisecond}
	h, store := newScanCappedRouter(scanner.Registry{artifact.TypeImage: {quick}}, 1)
	first := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	second := mustCreate(t, store, "busybox:latest", artifact.TypeImage)

	if _, a := scanAndWait(t, h, store, first.ID); a.Status != artifact.StatusScanned {
		t.Fatalf("first scan ended %q, want scanned", a.Status)
	}
	// The slot the first scan held must be back in the pool.
	rec, a := scanAndWait(t, h, store, second.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("second scan status = %d, want 202 -- the first scan's slot was never released", rec.Code)
	}
	if a.Status != artifact.StatusScanned {
		t.Fatalf("second scan ended %q, want scanned", a.Status)
	}
}

// TestScanArtifact_NoCapAcceptsConcurrentScans pins the zero value:
// ScanLimits{} means unlimited, so scans that overlap in time are all
// accepted and all complete -- the behavior every caller had before the
// cap existed.
func TestScanArtifact_NoCapAcceptsConcurrentScans(t *testing.T) {
	slow := &sleepingScanner{delay: 100 * time.Millisecond}
	h, store := newScanCappedRouter(scanner.Registry{artifact.TypeImage: {slow}}, 0)
	ids := []string{
		mustCreate(t, store, "alpine:3.19", artifact.TypeImage).ID,
		mustCreate(t, store, "busybox:latest", artifact.TypeImage).ID,
		mustCreate(t, store, "debian:12", artifact.TypeImage).ID,
	}

	for _, id := range ids {
		if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+id+"/scan", nil); rec.Code != http.StatusAccepted {
			t.Fatalf("scan of %s status = %d, want 202 -- an uncapped router must never reject", id, rec.Code)
		}
	}
	for _, id := range ids {
		if a := waitForScan(t, store, id); a.Status != artifact.StatusScanned {
			t.Fatalf("artifact %s ended %q, want scanned", id, a.Status)
		}
	}
}
