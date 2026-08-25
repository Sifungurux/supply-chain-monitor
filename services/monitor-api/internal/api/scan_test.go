package api_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
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
	h := api.NewRouter(api.Config{
		Store: store, Tracker: tracker, APIKey: testAPIKey, DigestResolver: resolver,
		Scanners: scanner.Registry{artifact.TypeImage: {&fakeScanner{}}},
	})

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
	h := api.NewRouter(api.Config{
		Store: store, Tracker: tracker, APIKey: testAPIKey, DigestResolver: resolver,
		Scanners: scanner.Registry{artifact.TypeImage: {&fakeScanner{}}},
	})

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
	created := mustCreate(t, store, "scm-registry.example/scans/app-sarif:1", artifact.TypeSARIF)

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
	created := mustCreate(t, store, "scm-registry.example/scans/app-sarif:1", artifact.TypeSARIF)

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
	// buckets, if set, additionally makes this double implement
	// scanner.MultiBucketAffinity -- the shape TrivyScanner has since
	// `trivy image --scanners vuln,secret` started reporting CVEs and
	// exposed secrets from one invocation. Left nil by every other test,
	// which Buckets() returns faithfully; scanArtifact treats a nil/empty
	// result as "no answer" and falls through to Bucket(), so those tests
	// are unaffected.
	buckets []string
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

func (s *sequenceScanner) Buckets() []string { return s.buckets }

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

// TestScanArtifact_MultiBucketFailureBlocksEveryBucketItDeclares is the
// safety property behind scanner.MultiBucketAffinity.
//
// TrivyScanner produces CVEs *and* secrets from one `trivy image
// --scanners vuln,secret` run. If it declared only "cve", a trivy
// failure would leave the secret bucket unblocked, and MergeFindings
// would mark every previously-open secret "fixed" -- reporting that a
// leaked credential had been removed when nothing of the sort happened
// and the scan simply never ran. A false "fixed" on a secret is worse
// than a stale one: it is an all-clear nobody earned.
//
// Mutating Buckets() back to []string{"cve"} must fail this test.
func TestScanArtifact_MultiBucketFailureBlocksEveryBucketItDeclares(t *testing.T) {
	trivy := &sequenceScanner{
		buckets: []string{"cve", "secret"},
		results: [][]artifact.Finding{
			{
				{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
				{ID: "secret:app/.env:aws-access-key-id:3", Severity: "critical", Source: "trivy", Category: "secret"},
			},
			{}, // second scan reports nothing -- but it also errored
		},
		errs: []error{nil, errors.New("trivy: exit status 1")},
	}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivy}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec, scanned := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	if len(scanned.SecretFindings) != 1 {
		t.Fatalf("first scan: SecretFindings = %+v, want the secret routed there (not into CVEFindings %+v)",
			scanned.SecretFindings, scanned.CVEFindings)
	}

	rec, scanned = scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("second scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	got := *scanned

	if len(got.SecretFindings) != 1 {
		t.Fatalf("SecretFindings = %+v, want the secret still on record", got.SecretFindings)
	}
	if got.SecretFindings[0].Status == artifact.FindingStatusFixed {
		t.Error("the secret was marked FIXED after the only scanner that reports secrets failed -- " +
			"a false all-clear on a leaked credential; Buckets() must declare \"secret\" as well as \"cve\"")
	}
	if got.CVEFindings[0].Status == artifact.FindingStatusFixed {
		t.Error("the CVE was marked fixed even though the scanner that reports CVEs failed")
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
	return api.NewRouter(api.Config{
		Store: store, Tracker: tracker, Scanners: scanners, APIKey: testAPIKey,
		ScanLimits: api.ScanLimits{Concurrency: concurrency},
	}), store
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

// fakeNotifier records delivered events and can be made to fail or
// panic, so the "a broken destination must never affect a scan"
// guarantee is actually exercised rather than assumed.
type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.ScanEvent
	err    error
	panics bool
	got    chan struct{}
}

func newFakeNotifier() *fakeNotifier { return &fakeNotifier{got: make(chan struct{}, 10)} }

func (f *fakeNotifier) Notify(_ context.Context, e notify.ScanEvent) error {
	if f.panics {
		panic("notifier exploded")
	}
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
	f.got <- struct{}{}
	return f.err
}

func (f *fakeNotifier) delivered() []notify.ScanEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notify.ScanEvent(nil), f.events...)
}

// waitForNotify waits for one delivery. Notifications are fired on
// their own goroutine (they must not delay a scan), so tests have to
// synchronize rather than assume.
func (f *fakeNotifier) waitForNotify(t *testing.T) bool {
	t.Helper()
	select {
	case <-f.got:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func newNotifyingRouter(t *testing.T, scanners scanner.Registry, n notify.Notifier, minSeverity string) (http.Handler, *artifact.MemStore) {
	t.Helper()
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(api.Config{
		Store: store, Tracker: tracker, Scanners: scanners, APIKey: testAPIKey,
		Notifications: api.Notifications{Notifiers: []notify.Notifier{n}, MinSeverity: minSeverity},
	}), store
}

// TestScanArtifact_SuppressesNotificationOnFirstScan -- every finding
// on an artifact's first scan is "new" only because nobody had looked
// before. Without this, enabling notifications on an existing
// deployment pages once per already-registered artifact as the sweep
// works through the backlog.
func TestScanArtifact_SuppressesNotificationOnFirstScan(t *testing.T) {
	trivy := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-CRIT", Severity: "CRITICAL", Title: "openssl", Source: "trivy"},
	}}
	n := newFakeNotifier()
	h, store := newNotifyingRouter(t, scanner.Registry{artifact.TypeImage: {trivy}}, n, "high")
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	_, final := scanAndWait(t, h, store, created.ID)
	if final.Status != artifact.StatusScanned || len(final.CVEFindings) != 1 {
		t.Fatalf("scan itself should be unaffected: status=%q findings=%+v", final.Status, final.CVEFindings)
	}
	select {
	case <-n.got:
		t.Fatal("notified on an artifact's first ever scan -- that is a backlog pager, not a change signal")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestScanArtifact_NotifiesOnNewFindingsAtOrAboveThreshold covers the
// real signal: an artifact already has scan history, and a later scan
// introduces something new.
func TestScanArtifact_NotifiesOnNewFindingsAtOrAboveThreshold(t *testing.T) {
	trivy := &sequenceScanner{results: [][]artifact.Finding{
		// First scan: establishes history. Suppressed.
		{{ID: "CVE-2024-OLD", Severity: "CRITICAL", Title: "known already", Source: "trivy"}},
		// Second: the old one persists, two arrive.
		{
			{ID: "CVE-2024-OLD", Severity: "CRITICAL", Title: "known already", Source: "trivy"},
			{ID: "CVE-2024-NEW", Severity: "CRITICAL", Title: "openssl", Source: "trivy"},
			{ID: "CVE-2024-NOISE", Severity: "LOW", Title: "zlib", Source: "trivy"},
		},
	}}
	n := newFakeNotifier()
	h, store := newNotifyingRouter(t, scanner.Registry{artifact.TypeImage: {trivy}}, n, "high")
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	scanAndWait(t, h, store, created.ID) // first scan: suppressed
	scanAndWait(t, h, store, created.ID)
	if !n.waitForNotify(t) {
		t.Fatal("no notification for a newly introduced CRITICAL finding")
	}

	events := n.delivered()
	if len(events) != 1 {
		t.Fatalf("delivered %d events, want 1", len(events))
	}
	e := events[0]
	if e.ArtifactID != created.ID || e.ArtifactRef != "alpine:3.19" {
		t.Fatalf("event identifies the wrong artifact: %+v", e)
	}
	// Only the genuinely-new, at-or-above-threshold finding: not the
	// CVE carried over from the first scan, and not the new LOW one.
	if len(e.NewFindings) != 1 || e.NewFindings[0].ID != "CVE-2024-NEW" {
		t.Fatalf("new findings = %+v, want only CVE-2024-NEW", e.NewFindings)
	}
	if e.Severity != "CRITICAL" {
		t.Fatalf("worst severity = %q, want CRITICAL", e.Severity)
	}
}

// TestScanArtifact_DoesNotNotifyForPreExistingFindings -- a re-scan
// reporting the same findings must be silent, or a nightly sweep pages
// about a CVE that has been known for weeks.
func TestScanArtifact_DoesNotNotifyForPreExistingFindings(t *testing.T) {
	trivy := &sequenceScanner{results: [][]artifact.Finding{
		{}, // 1st: no findings, establishes history
		{{ID: "CVE-2024-CRIT", Severity: "CRITICAL", Source: "trivy"}}, // 2nd: new -> notifies
		{{ID: "CVE-2024-CRIT", Severity: "CRITICAL", Source: "trivy"}}, // 3rd: same -> silent
	}}
	n := newFakeNotifier()
	h, store := newNotifyingRouter(t, scanner.Registry{artifact.TypeImage: {trivy}}, n, "high")
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	scanAndWait(t, h, store, created.ID)
	scanAndWait(t, h, store, created.ID)
	if !n.waitForNotify(t) {
		t.Fatal("the scan that introduced the CVE should have notified")
	}

	scanAndWait(t, h, store, created.ID)
	select {
	case <-n.got:
		t.Fatalf("re-scan notified about a pre-existing finding: %+v", n.delivered())
	case <-time.After(500 * time.Millisecond):
	}
	if len(n.delivered()) != 1 {
		t.Fatalf("delivered %d events across three scans, want 1", len(n.delivered()))
	}
}

func TestScanArtifact_DoesNotNotifyBelowThreshold(t *testing.T) {
	// Two scans on purpose: a single scan of a fresh artifact would be
	// suppressed as a first scan, and this test would pass even if the
	// severity filter were broken.
	trivy := &sequenceScanner{results: [][]artifact.Finding{
		{}, // 1st: establishes history
		{
			{ID: "CVE-2024-MED", Severity: "MEDIUM", Source: "trivy"},
			{ID: "CVE-2024-UNK", Severity: "UNKNOWN", Source: "trivy"},
		},
	}}
	n := newFakeNotifier()
	h, store := newNotifyingRouter(t, scanner.Registry{artifact.TypeImage: {trivy}}, n, "high")
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	scanAndWait(t, h, store, created.ID)
	_, final := scanAndWait(t, h, store, created.ID)
	if final.Status != artifact.StatusScanned {
		t.Fatalf("scan status = %q, want scanned", final.Status)
	}
	select {
	case <-n.got:
		t.Fatal("notified for findings below the configured threshold")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestScanArtifact_NotifierFailureDoesNotAffectTheScan covers the whole
// point of fire-and-forget: a destination that errors, and one that
// panics outright, must both leave the scan's own result untouched.
func TestScanArtifact_NotifierFailureDoesNotAffectTheScan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		broken *fakeNotifier
	}{
		{"returns an error", &fakeNotifier{got: make(chan struct{}, 10), err: errors.New("receiver down")}},
		{"panics", &fakeNotifier{got: make(chan struct{}, 10), panics: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Two scans: the notifier is never reached on a first scan
			// (suppressed), so a single scan here would exercise nothing.
			trivy := &sequenceScanner{results: [][]artifact.Finding{
				{},
				{{ID: "CVE-2024-CRIT", Severity: "CRITICAL", Source: "trivy"}},
			}}
			h, store := newNotifyingRouter(t, scanner.Registry{artifact.TypeImage: {trivy}}, tc.broken, "high")
			created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

			scanAndWait(t, h, store, created.ID)
			_, final := scanAndWait(t, h, store, created.ID)
			if final.Status != artifact.StatusScanned {
				t.Fatalf("scan status = %q, want scanned -- a broken notifier must not fail a scan", final.Status)
			}
			if len(final.CVEFindings) != 1 {
				t.Fatalf("findings = %+v, want the scan's results persisted regardless", final.CVEFindings)
			}
			// Give the notifier goroutine time to panic if it's going to;
			// an unrecovered panic there would take the process down and
			// this test with it.
			time.Sleep(200 * time.Millisecond)
		})
	}
}

// TestScanArtifact_NoNotifiersConfiguredIsSilent pins the zero value:
// every other test in this package passes api.Notifications{}, and must
// keep behaving exactly as it did before notifications existed.
func TestScanArtifact_NoNotifiersConfiguredIsSilent(t *testing.T) {
	trivy := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-CRIT", Severity: "CRITICAL", Source: "trivy"},
	}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivy}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	_, final := scanAndWait(t, h, store, created.ID)
	if final.Status != artifact.StatusScanned {
		t.Fatalf("scan status = %q, want scanned", final.Status)
	}
}

// TestScanArtifact_NotifiesOnFirstScanWhenSuppressionDisabled is the
// opt-out path: a deployment where artifacts are registered and scanned
// once at import time wants that first scan to notify, since it IS the
// interesting event.
func TestScanArtifact_NotifiesOnFirstScanWhenSuppressionDisabled(t *testing.T) {
	trivy := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-CRIT", Severity: "CRITICAL", Title: "openssl", Source: "trivy"},
	}}
	n := newFakeNotifier()
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	h := api.NewRouter(api.Config{
		Store: store, Tracker: tracker, APIKey: testAPIKey,
		Scanners:      scanner.Registry{artifact.TypeImage: {trivy}},
		Notifications: api.Notifications{Notifiers: []notify.Notifier{n}, MinSeverity: "high", NotifyOnFirstScan: true},
	})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	scanAndWait(t, h, store, created.ID)
	if !n.waitForNotify(t) {
		t.Fatal("first scan should notify when NotifyOnFirstScan is set")
	}
	events := n.delivered()
	if len(events) != 1 || len(events[0].NewFindings) != 1 || events[0].NewFindings[0].ID != "CVE-2024-CRIT" {
		t.Fatalf("delivered %+v, want the one CRITICAL finding", events)
	}
}

// TestNotifications_ZeroValueSuppressesFirstScan pins the default the
// other way round: the field is an opt-IN precisely so a caller that
// doesn't think about it gets suppression rather than a backlog pager.
func TestNotifications_ZeroValueSuppressesFirstScan(t *testing.T) {
	if (api.Notifications{}).NotifyOnFirstScan {
		t.Fatal("the zero value must suppress first-scan notifications")
	}
}

// countingScanner records whether it ever ran. The point of the tests
// below is not just that a refused scan answers 400 -- it is that
// nothing downstream of the check executed.
type countingScanner struct {
	calls atomic.Int64
}

func (c *countingScanner) Scan(_ context.Context, _ string) ([]artifact.Finding, error) {
	c.calls.Add(1)
	return nil, nil
}

// A ref that was registered before ValidateRef existed is still in the
// database, and an `image` artifact never passes through Fetch or
// Resolve -- trivy/grype/unpacker pull it themselves. So the scan path
// has to re-check rather than trusting registration to have done it.
func TestScanArtifact_RefusesRefsPointingInward(t *testing.T) {
	t.Setenv("REF_HOST_ALLOWLIST", "")

	for _, tc := range []struct{ name, ref string }{
		{"cloud metadata IP", "169.254.169.254/latest/meta-data:1"},
		{"in-cluster service", "scm-registry.supply-chain-monitor.svc.cluster.local:5000/app:1"},
		{"RFC1918 address", "10.0.0.5:5000/app:1.0"},
		{"local filesystem path", "/proc/self/environ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &countingScanner{}
			h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {sc}})
			// Written straight to the store, exactly as a row registered
			// before the guard existed would be -- registering through
			// the API would (correctly) refuse it and prove nothing.
			created := mustCreate(t, store, tc.ref, artifact.TypeImage)

			rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
			if n := sc.calls.Load(); n != 0 {
				t.Fatalf("scanner ran %d time(s) for a refused ref -- the check must come before dispatch", n)
			}

			// Status untouched: the artifact was never marked scanning,
			// so nothing has to reclaim it later.
			after, err := store.Get(created.ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if after.Status != artifact.StatusRegistered {
				t.Fatalf("status = %q, want it left at %q", after.Status, artifact.StatusRegistered)
			}
		})
	}
}

// The subtle half. Failing INSIDE runScan instead would call
// MergeFindings with no scanner results, and any bucket not marked
// blocked would mark every existing finding "fixed" -- a refused scan
// silently destroying history. Refusing before the dispatch is what
// keeps that from being possible, so it gets its own test.
func TestScanArtifact_RefusedScanLeavesFindingsIntact(t *testing.T) {
	t.Setenv("REF_HOST_ALLOWLIST", "")
	sc := &countingScanner{}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {sc}})
	created := mustCreate(t, store, "169.254.169.254/latest/meta-data:1", artifact.TypeImage)

	if _, err := store.Update(created.ID, func(art *artifact.Artifact) {
		art.Status = artifact.StatusScanned
		art.CVEFindings = []artifact.Finding{{ID: "CVE-2024-0001", Severity: "high", Status: "open"}}
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	after, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(after.CVEFindings) != 1 {
		t.Fatalf("findings = %+v, want the existing one untouched", after.CVEFindings)
	}
	if after.CVEFindings[0].Status != "open" {
		t.Fatalf("finding status = %q, want it still open -- a refused scan must not mark anything fixed", after.CVEFindings[0].Status)
	}
	if after.Status != artifact.StatusScanned {
		t.Fatalf("artifact status = %q, want it unchanged at %q", after.Status, artifact.StatusScanned)
	}
}

// An ordinary public ref still scans -- the guard must not cost the
// normal path anything.
func TestScanArtifact_OrdinaryRefStillScans(t *testing.T) {
	t.Setenv("REF_HOST_ALLOWLIST", "")
	sc := &countingScanner{}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {sc}})
	created := mustCreate(t, store, "ghcr.io/example/app:1.0", artifact.TypeImage)

	rec, _ := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	if n := sc.calls.Load(); n != 1 {
		t.Fatalf("scanner ran %d time(s), want 1", n)
	}
}

// fakeProvenanceScanner implements scanner.ProvenanceScanner so
// scanArtifact's verdict plumbing can be exercised without cosign.
type fakeProvenanceScanner struct {
	status    string
	trustRoot string
	findings  []artifact.Finding
	err       error
}

func (f *fakeProvenanceScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	fs, _, _, err := f.ScanProvenance(ctx, ref)
	return fs, err
}

func (f *fakeProvenanceScanner) ScanProvenance(_ context.Context, _ string) ([]artifact.Finding, string, string, error) {
	return f.findings, f.status, f.trustRoot, f.err
}

// TestScanArtifact_RecordsProvenanceVerdict is why the verdict exists
// as a field rather than as the absence of a finding.
//
// A verified image produces NO finding, so without this "signed" would
// be indistinguishable from "cosign is switched off" and from "never
// scanned since it was switched on".
func TestScanArtifact_RecordsProvenanceVerdict(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scanner   *fakeProvenanceScanner
		wantState string
	}{
		{
			name:      "verified is recorded even though it produces no finding",
			scanner:   &fakeProvenanceScanner{status: artifact.ProvenanceVerified, trustRoot: "public Sigstore"},
			wantState: artifact.ProvenanceVerified,
		},
		{
			name: "unsigned is recorded alongside its finding",
			scanner: &fakeProvenanceScanner{
				status:    artifact.ProvenanceUnsigned,
				trustRoot: "public Sigstore",
				findings:  []artifact.Finding{{ID: "provenance:unsigned", Severity: "high", Source: "cosign"}},
			},
			wantState: artifact.ProvenanceUnsigned,
		},
		{
			// An outage must not read as an accusation, at the artifact
			// level either.
			name:      "could-not-verify is its own state",
			scanner:   &fakeProvenanceScanner{status: artifact.ProvenanceUnverified, trustRoot: "public Sigstore"},
			wantState: artifact.ProvenanceUnverified,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {tc.scanner}})
			a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

			rec, scanned := scanAndWait(t, h, store, a.ID)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("scan status = %d, want 202", rec.Code)
			}
			if scanned.Provenance != tc.wantState {
				t.Fatalf("provenance = %q, want %q", scanned.Provenance, tc.wantState)
			}
			if scanned.ProvenanceCheckedAt == nil {
				t.Error("provenance_checked_at is nil -- a verdict with no timestamp cannot be told from a stale one")
			}
			if scanned.ProvenanceTrustRoot == "" {
				t.Error("provenance_trust_root is empty -- verified against WHICH Sigstore is part of the claim")
			}
		})
	}
}

// With no provenance scanner registered, the field stays unknown. That
// is the state of every artifact in a deployment that never enabled
// cosign, and it must not read as either verified or unsigned.
func TestScanArtifact_NoProvenanceScannerLeavesItUnknown(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {&fakeScanner{}}})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	_, scanned := scanAndWait(t, h, store, a.ID)
	if scanned.Provenance != artifact.ProvenanceUnknown {
		t.Fatalf("provenance = %q, want unknown when nothing checked it", scanned.Provenance)
	}
	if scanned.ProvenanceCheckedAt != nil {
		t.Error("provenance_checked_at was set without a check having run")
	}
}

// Disabling cosign must not ERASE a verdict an earlier scan reached --
// replacing "verified" with "unknown" would read as "we never looked"
// and quietly discard the answer.
func TestScanArtifact_LaterScanWithoutProvenanceKeepsTheVerdict(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{
		artifact.TypeImage: {&fakeProvenanceScanner{status: artifact.ProvenanceVerified, trustRoot: "public Sigstore"}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	_, scanned := scanAndWait(t, h, store, a.ID)
	if scanned.Provenance != artifact.ProvenanceVerified {
		t.Fatalf("first scan: provenance = %q", scanned.Provenance)
	}

	// Re-scan with cosign gone from the registry.
	h2, _ := newTestRouterWithStore(store, scanner.Registry{artifact.TypeImage: {&fakeScanner{}}})
	_, rescanned := scanAndWait(t, h2, store, a.ID)
	if rescanned.Provenance != artifact.ProvenanceVerified {
		t.Fatalf("provenance = %q after a scan with no provenance scanner, want the earlier verdict kept", rescanned.Provenance)
	}
}

// flakyScanner fails the first N calls, then succeeds -- the shape of a
// registry entry that was broken once and has since recovered.
type flakyScanner struct {
	mu        sync.Mutex
	failsLeft int
	findings  []artifact.Finding
}

func (f *flakyScanner) Scan(_ context.Context, _ string) ([]artifact.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failsLeft > 0 {
		f.failsLeft--
		return nil, errors.New("unpacker: pull failed")
	}
	return f.findings, nil
}

// A clean scan must not erase the record of the previous failure. Before
// this, scanArtifact assigned LastScanErrors unconditionally, so the
// empty slice from a successful scan wiped the only evidence that the
// artifact had ever failed -- the operator saw a green artifact and no
// way to know it had been broken an hour earlier.
func TestScanArtifact_CleanScanKeepsPreviousErrors(t *testing.T) {
	sc := &flakyScanner{failsLeft: 1, findings: []artifact.Finding{{ID: "CVE-2024-9", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {sc}})
	created := mustCreate(t, store, "public.ecr.aws/docker/library/redis:7-alpine", artifact.TypeImage)

	_, failed := scanAndWait(t, h, store, created.ID)
	if failed.Status != artifact.StatusFailed {
		t.Fatalf("first scan status = %q, want %q", failed.Status, artifact.StatusFailed)
	}
	if len(failed.LastScanErrors) != 1 {
		t.Fatalf("expected the failure recorded, got %v", failed.LastScanErrors)
	}
	if failed.LastScanErrorAt == nil {
		t.Fatal("expected LastScanErrorAt to be stamped on a failed scan")
	}
	firstErr := append([]string(nil), failed.LastScanErrors...)
	firstAt := *failed.LastScanErrorAt

	_, clean := scanAndWait(t, h, store, created.ID)
	if clean.Status != artifact.StatusScanned {
		t.Fatalf("second scan status = %q, want %q", clean.Status, artifact.StatusScanned)
	}
	if len(clean.CVEFindings) != 1 {
		t.Fatalf("expected the recovered scanner's finding, got %+v", clean.CVEFindings)
	}
	if !reflect.DeepEqual(clean.LastScanErrors, firstErr) {
		t.Fatalf("a clean scan erased the previous errors: got %v, want %v", clean.LastScanErrors, firstErr)
	}
	if clean.LastScanErrorAt == nil || !clean.LastScanErrorAt.Equal(firstAt) {
		t.Fatalf("LastScanErrorAt moved on a clean scan: got %v, want %v", clean.LastScanErrorAt, firstAt)
	}
	// The pair is what lets the dashboard tell "failing now" from
	// "failed once, fine since" without another stored flag.
	if clean.LastScanAt == nil || !clean.LastScanAt.After(*clean.LastScanErrorAt) {
		t.Fatalf("expected last_scan_at (%v) to be after last_scan_error_at (%v)", clean.LastScanAt, clean.LastScanErrorAt)
	}
	// A total failure still clears on recovery -- that one tracks
	// current status, not history.
	if clean.LastScanFailureReason != "" {
		t.Fatalf("LastScanFailureReason should clear on a clean scan, got %q", clean.LastScanFailureReason)
	}
}

// ...and a fresh failure must replace the old record rather than
// accumulate: the field holds the LAST failure, not every one.
func TestScanArtifact_NewFailureReplacesPreviousErrors(t *testing.T) {
	sc := &flakyScanner{failsLeft: 1}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {sc}})
	created := mustCreate(t, store, "public.ecr.aws/docker/library/redis:7-alpine", artifact.TypeImage)

	_, first := scanAndWait(t, h, store, created.ID)
	firstAt := *first.LastScanErrorAt

	sc.mu.Lock()
	sc.failsLeft = 1
	sc.mu.Unlock()

	_, second := scanAndWait(t, h, store, created.ID)
	if len(second.LastScanErrors) != 1 {
		t.Fatalf("expected exactly one error after a second failure, got %v", second.LastScanErrors)
	}
	if second.LastScanErrorAt == nil || !second.LastScanErrorAt.After(firstAt) {
		t.Fatalf("expected LastScanErrorAt to advance on a new failure: got %v, previous %v", second.LastScanErrorAt, firstAt)
	}
}

// --- sbom-only re-evaluation (POST .../scan?mode=sbom-only) ---

// newSBOMReevalRouter builds a router with both a full image scanner set
// and an sbom re-evaluation scanner, which is the only configuration in
// which the two modes are distinguishable.
func newSBOMReevalRouter(full scanner.Registry, reeval scanner.Scanner) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(api.Config{
		Store: store, Tracker: tracker, Scanners: full,
		SBOMReevalScanner: reeval, APIKey: testAPIKey,
	}), store
}

// scanModeAndWait is scanAndWait with an explicit ?mode=.
func scanModeAndWait(t *testing.T, h http.Handler, store *artifact.MemStore, id, mode string) (*httptest.ResponseRecorder, *artifact.Artifact) {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+id+"/scan?mode="+mode, nil)
	if rec.Code != http.StatusAccepted {
		return rec, nil
	}
	return rec, waitForScan(t, store, id)
}

// grypeSBOMLike stands in for the isolated grype sbom-doc scanner. It
// mirrors the real one's INTERFACE SET, not just its behaviour:
// Bucket() "cve" like GrypeSBOMScanner/IsolatedGrypeScanner, and
// ScanForArtifact because scanArtifact type-switches on
// scanner.ArtifactAwareScanner and production takes that branch. A fake
// implementing only Scan would send every test down the `default:` arm
// instead, so the artifact ID could stop being threaded to the Job --
// the one hop between "the API picked the scanner" and "the Job can
// find the document" -- with every test still green.
type grypeSBOMLike struct {
	findings []artifact.Finding
	err      error

	mu             sync.Mutex
	gotArtifactID  string
	gotRef         string
	scanForCalls   int
	plainScanCalls int
}

func (g *grypeSBOMLike) Scan(_ context.Context, ref string) ([]artifact.Finding, error) {
	g.mu.Lock()
	g.plainScanCalls++
	g.gotRef = ref
	g.mu.Unlock()
	return g.findings, g.err
}

func (g *grypeSBOMLike) ScanForArtifact(_ context.Context, ref, artifactID string) ([]artifact.Finding, error) {
	g.mu.Lock()
	g.scanForCalls++
	g.gotArtifactID = artifactID
	g.gotRef = ref
	g.mu.Unlock()
	return g.findings, g.err
}

func (g *grypeSBOMLike) Bucket() string { return "cve" }

func (g *grypeSBOMLike) observed() (artifactID string, scanFor, plain int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gotArtifactID, g.scanForCalls, g.plainScanCalls
}

// TestScanArtifact_SBOMOnlyLeavesOtherBucketsUntouched is the test the
// whole mode hinges on.
//
// A successful sbom-only round runs ONE scanner, which reports only
// CVEs. Nothing fails, so blockedBuckets is empty and detectFixedFor
// returns true for every bucket -- which means that if the malware,
// secret, misconfiguration and other buckets were merged against that
// round's (empty) results, every finding in them would be marked
// "fixed". Silently, on every artifact, every night the CronJob runs.
//
// Declaring Bucket() "cve" on the scanner does NOT prevent this:
// bucket affinity only governs what a FAILED scanner blocks. Success is
// what does the damage, which is why this test drives a SUCCESSFUL
// re-evaluation and not a failing one.
func TestScanArtifact_SBOMOnlyLeavesOtherBucketsUntouched(t *testing.T) {
	// A full image scan first, so there is something in every bucket to
	// lose. One scanner per bucket, sorted by classifyBucket.
	trivyLike := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
		{ID: "generic-api-key", Severity: "critical", Source: "trivy", Category: "secret"},
		{ID: "KSV001", Severity: "medium", Source: "trivy", Category: "misconfiguration"},
		{ID: "SAST-1", Severity: "low", Source: "trivy", Category: "other"},
	}}
	clamavLike := &fakeScanner{findings: []artifact.Finding{
		{ID: "Eicar-Test-Signature", Severity: "critical", Source: "clamav"},
	}}
	reeval := &grypeSBOMLike{findings: []artifact.Finding{
		{ID: "CVE-2024-2", Severity: "critical", Source: "grype"},
	}}

	h, store := newSBOMReevalRouter(scanner.Registry{
		artifact.TypeImage: {trivyLike, clamavLike},
	}, reeval)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if _, full := scanAndWait(t, h, store, created.ID); full.Status != artifact.StatusScanned {
		t.Fatalf("full scan status = %q, want %q", full.Status, artifact.StatusScanned)
	}
	// HasSBOM is the eligibility gate, and it is set by a document
	// arriving -- the same way a real image gets one (the scan-worker
	// generates a CycloneDX document and uploads it back).
	if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{"bomFormat":"CycloneDX"}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	before, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if len(before.MalwareFindings) != 1 || len(before.SecretFindings) != 1 ||
		len(before.MisconfigFindings) != 1 || len(before.OtherFindings) != 1 {
		t.Fatalf("precondition: want one finding in each non-cve bucket, got malware=%d secret=%d misconfig=%d other=%d",
			len(before.MalwareFindings), len(before.SecretFindings),
			len(before.MisconfigFindings), len(before.OtherFindings))
	}

	rec, after := scanModeAndWait(t, h, store, created.ID, "sbom-only")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}

	// THE ASSERTION THIS TEST EXISTS FOR.
	for _, b := range []struct {
		name string
		got  []artifact.Finding
	}{
		{"malware", after.MalwareFindings},
		{"secret", after.SecretFindings},
		{"misconfiguration", after.MisconfigFindings},
		{"other", after.OtherFindings},
	} {
		if len(b.got) != 1 {
			t.Fatalf("%s bucket = %d findings after an sbom-only scan, want 1 (untouched)", b.name, len(b.got))
		}
		if b.got[0].Status != artifact.FindingStatusOpen {
			t.Errorf("%s finding %q status = %q after an sbom-only scan, want %q -- a re-evaluation that never looked at this bucket must not resolve it",
				b.name, b.got[0].ID, b.got[0].Status, artifact.FindingStatusOpen)
		}
	}

	// And the cve bucket IS the one an sbom-only round merges into, so
	// the newly-reported CVE lands. What it must NOT do is resolve the
	// CVE the previous round reported: this round ran one scanner
	// against an SBOM and cannot speak for what trivy found in the
	// image filesystem. See
	// TestScanArtifact_SBOMOnlyNeverResolvesCVEs for the full
	// reasoning and the measured numbers behind it.
	var sawNew bool
	for _, f := range after.CVEFindings {
		if f.ID == "CVE-2024-2" && f.Status == artifact.FindingStatusOpen {
			sawNew = true
		}
		if f.ID == "CVE-2024-1" && f.Status != artifact.FindingStatusOpen {
			t.Errorf("CVE-2024-1 status = %q, want %q -- an sbom-only round adds and updates, it never resolves",
				f.Status, artifact.FindingStatusOpen)
		}
	}
	if !sawNew {
		t.Errorf("cve findings = %+v, want the re-evaluation's CVE-2024-2 open among them", after.CVEFindings)
	}
}

// TestScanArtifact_SBOMOnlyDoesNotRefreshTheScanClock pins the other
// half of the trade-off: a re-evaluation must not satisfy the full
// sweep's freshness clock.
//
// LastScanAt drives the staleness badge, Store.CountStaleScans, and the
// full sweep's own rescan population. If a nightly sbom-only round
// stamped it, every artifact would look permanently freshly-scanned,
// the full sweep would stop finding anything stale, and malware
// coverage would decay while the dashboard stayed green.
func TestScanArtifact_SBOMOnlyDoesNotRefreshTheScanClock(t *testing.T) {
	reeval := &grypeSBOMLike{findings: []artifact.Finding{{ID: "CVE-2024-9", Source: "grype"}}}
	h, store := newSBOMReevalRouter(scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
	}, reeval)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	_, full := scanAndWait(t, h, store, created.ID)
	if full.LastScanAt == nil {
		t.Fatal("precondition: a full scan must stamp LastScanAt")
	}
	stamped := *full.LastScanAt
	if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	_, after := scanModeAndWait(t, h, store, created.ID, "sbom-only")
	if after.LastScanAt == nil || !after.LastScanAt.Equal(stamped) {
		t.Errorf("LastScanAt = %v after an sbom-only scan, want it unchanged at %v", after.LastScanAt, stamped)
	}
	// The artifact also keeps the status it had -- a re-evaluation
	// reports on CVEs, not on whether the artifact scans.
	if after.Status != artifact.StatusScanned {
		t.Errorf("status = %q after an sbom-only scan, want %q", after.Status, artifact.StatusScanned)
	}
}

// TestScanArtifact_SBOMOnlyRefusesRatherThanFallingBack covers the three
// refusals, all of which exist for the same reason: an sbom-only
// request that quietly ran a FULL scan would turn one nightly CronJob
// into a complete re-scan of the fleet -- the exact IO the mode exists
// to avoid, and invisible in the sweep's own logs.
func TestScanArtifact_SBOMOnlyRefusesRatherThanFallingBack(t *testing.T) {
	reeval := &grypeSBOMLike{}
	full := scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
		artifact.TypeSBOM:  {&fakeScanner{}},
	}

	t.Run("no stored sbom", func(t *testing.T) {
		h, store := newSBOMReevalRouter(full, reeval)
		created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan?mode=sbom-only", nil)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("not an image", func(t *testing.T) {
		h, store := newSBOMReevalRouter(full, reeval)
		created := mustCreate(t, store, "some.sbom.json", artifact.TypeSBOM)
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan?mode=sbom-only", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("mode not configured", func(t *testing.T) {
		h, store := newSBOMReevalRouter(full, nil)
		created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
		if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{}`)); err != nil {
			t.Fatalf("SaveDocument: %v", err)
		}
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan?mode=sbom-only", nil)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown mode", func(t *testing.T) {
		h, store := newSBOMReevalRouter(full, reeval)
		created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan?mode=everything", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// TestScanArtifact_SBOMOnlyDoesNotResolveDigests pins the other IO an
// sbom-only round deliberately skips.
//
// Digest resolution is a real registry round trip (up to 8s) that the
// re-evaluation never records anyway -- and this mode is meant to run
// nightly across an entire fleet, so it would be the single most
// expensive thing the cheap path does. Backfill is converging work the
// full sweep already owns.
func TestScanArtifact_SBOMOnlyDoesNotResolveDigests(t *testing.T) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:should-never-be-fetched"}}
	h := api.NewRouter(api.Config{
		Store: store, Tracker: tracker, APIKey: testAPIKey, DigestResolver: resolver,
		Scanners:          scanner.Registry{artifact.TypeImage: {&fakeScanner{}}},
		SBOMReevalScanner: &grypeSBOMLike{findings: []artifact.Finding{{ID: "CVE-2024-3", Source: "grype"}}},
	})

	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	_, after := scanModeAndWait(t, h, store, created.ID, "sbom-only")
	if n := resolver.calls.Load(); n != 0 {
		t.Errorf("digest resolver called %d time(s) during an sbom-only scan, want 0", n)
	}
	if after.Digest != "" {
		t.Errorf("digest = %q after an sbom-only scan, want it left empty -- backfill belongs to the full sweep", after.Digest)
	}
}

// TestScanArtifact_SBOMOnlyPassesTheArtifactID pins the hop between the
// API selecting the re-evaluation scanner and the scan-worker Job being
// able to find the document.
//
// The real scanner is an ArtifactAwareScanner: the SBOM lives in
// Postgres keyed by artifact ID, and the Job downloads it by that ID,
// so a re-evaluation that only ever received a ref could not do its
// job at all. scanArtifact type-switches to decide which method to
// call, which means this is a wiring property no assertion about
// findings can reach.
func TestScanArtifact_SBOMOnlyPassesTheArtifactID(t *testing.T) {
	reeval := &grypeSBOMLike{findings: []artifact.Finding{{ID: "CVE-2024-4", Source: "grype"}}}
	h, store := newSBOMReevalRouter(scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
	}, reeval)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	// A full scan first, so the artifact reaches the state a real
	// re-evaluation target is in: scanned, with a stored SBOM. (An
	// artifact that never had one has status "registered", and
	// sbom-only correctly restores that -- see
	// TestScanArtifact_SBOMOnlyDoesNotRefreshTheScanClock.)
	if _, full := scanAndWait(t, h, store, created.ID); full.Status != artifact.StatusScanned {
		t.Fatalf("full scan status = %q, want %q", full.Status, artifact.StatusScanned)
	}
	if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	if _, after := scanModeAndWait(t, h, store, created.ID, "sbom-only"); after.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q", after.Status, artifact.StatusScanned)
	}

	gotID, scanFor, plain := reeval.observed()
	if scanFor != 1 {
		t.Errorf("ScanForArtifact called %d time(s), want 1 -- scanArtifact must take the ArtifactAwareScanner branch", scanFor)
	}
	if plain != 0 {
		t.Errorf("plain Scan called %d time(s), want 0 -- the artifact ID would be lost on that path", plain)
	}
	if gotID != created.ID {
		t.Errorf("ScanForArtifact got artifact id %q, want %q", gotID, created.ID)
	}
}

// TestScanArtifact_SBOMOnlyDoesNotMoveScanMetrics pins that a
// re-evaluation stays out of the scm_scans_* counters.
//
// The ScanFailureRate alert compares rate(scm_scans_failed_total)
// against rate(scm_scans_succeeded_total). A nightly fleet-wide burst
// of re-evaluations lands inside one 30m window, so counting them would
// move that ratio and could mask a genuine run of scan failures
// happening at the same time.
func TestScanArtifact_SBOMOnlyDoesNotMoveScanMetrics(t *testing.T) {
	reeval := &grypeSBOMLike{findings: []artifact.Finding{{ID: "CVE-2024-5", Source: "grype"}}}
	h, store := newSBOMReevalRouter(scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
	}, reeval)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, full := scanAndWait(t, h, store, created.ID); full.Status != artifact.StatusScanned {
		t.Fatal("precondition: the full scan must succeed")
	}
	if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	scrape := func() string {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	countersLine := func(body, metric string) string {
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, metric+" ") {
				return l
			}
		}
		return ""
	}

	before := scrape()
	startedBefore := countersLine(before, "scm_scans_started_total")
	succeededBefore := countersLine(before, "scm_scans_succeeded_total")
	if startedBefore == "" || succeededBefore == "" {
		t.Fatalf("precondition: expected scan counters in /metrics, got:\n%s", before)
	}

	if _, after := scanModeAndWait(t, h, store, created.ID, "sbom-only"); after.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q", after.Status, artifact.StatusScanned)
	}

	got := scrape()
	if l := countersLine(got, "scm_scans_started_total"); l != startedBefore {
		t.Errorf("scm_scans_started_total moved on an sbom-only scan: %q -> %q", startedBefore, l)
	}
	if l := countersLine(got, "scm_scans_succeeded_total"); l != succeededBefore {
		t.Errorf("scm_scans_succeeded_total moved on an sbom-only scan: %q -> %q", succeededBefore, l)
	}
}

// TestScanArtifact_SBOMOnlyNeverResolvesCVEs is the counterpart to
// TestScanArtifact_SBOMOnlyLeavesOtherBucketsUntouched, for the one
// bucket an sbom-only round DOES merge.
//
// The re-evaluation runs grype against the stored SBOM and reports only
// what that finds. The bucket it merges into was built by whatever
// CVE_SCANNER selects -- with "both", most of it is trivy scanning the
// image filesystem directly. Measured on this project's own fleet:
// 35,195 of 46,728 open CVE findings are trivy-only. With fix-detection
// on, every one of those is absent from the re-evaluation's results and
// gets marked "fixed" -- 75% of the bucket silently resolved, nightly.
//
// So the round may ADD and UPDATE, never RESOLVE.
func TestScanArtifact_SBOMOnlyNeverResolvesCVEs(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{
		// The trivy-only majority: found by an image scan, absent from
		// anything grype derives from the SBOM.
		{ID: "CVE-TRIVY-ONLY", Severity: "critical", Source: "trivy"},
		{ID: "CVE-BOTH", Severity: "high", Source: "trivy"},
	}}
	reeval := &grypeSBOMLike{findings: []artifact.Finding{
		{ID: "CVE-BOTH", Severity: "high", Source: "grype"},
		// A CVE published since the last full scan -- the entire point
		// of the mode, so it must still land.
		{ID: "CVE-BRAND-NEW", Severity: "critical", Source: "grype"},
	}}

	h, store := newSBOMReevalRouter(scanner.Registry{
		artifact.TypeImage: {trivyLike},
	}, reeval)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, full := scanAndWait(t, h, store, created.ID); full.Status != artifact.StatusScanned {
		t.Fatal("precondition: the full scan must succeed")
	}
	if err := store.SaveDocument(created.ID, artifact.DocumentKindSBOM, "application/json", []byte(`{}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	_, after := scanModeAndWait(t, h, store, created.ID, "sbom-only")

	byID := map[string]artifact.Finding{}
	for _, f := range after.CVEFindings {
		byID[f.ID] = f
	}

	// THE ASSERTION THIS TEST EXISTS FOR.
	if f, ok := byID["CVE-TRIVY-ONLY"]; !ok {
		t.Fatalf("CVE-TRIVY-ONLY disappeared entirely: %+v", after.CVEFindings)
	} else if f.Status != artifact.FindingStatusOpen {
		t.Errorf("CVE-TRIVY-ONLY status = %q, want %q -- an sbom-only round did not look at the image filesystem and must not resolve what trivy found there",
			f.Status, artifact.FindingStatusOpen)
	}
	// Still open, obviously -- it was re-reported.
	if f := byID["CVE-BOTH"]; f.Status != artifact.FindingStatusOpen {
		t.Errorf("CVE-BOTH status = %q, want %q", f.Status, artifact.FindingStatusOpen)
	}
	// And the mode still does its actual job: new CVEs arrive.
	if f, ok := byID["CVE-BRAND-NEW"]; !ok || f.Status != artifact.FindingStatusOpen {
		t.Errorf("CVE-BRAND-NEW missing or not open (%+v) -- blocking fix-detection must not block new findings", f)
	}
}
