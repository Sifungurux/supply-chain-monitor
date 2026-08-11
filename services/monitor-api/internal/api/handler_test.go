package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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

// sleepingScanner blocks for a fixed duration before returning --
// used to prove scanArtifact's scanners actually run concurrently
// (TestScanArtifact_ScannersRunConcurrently), not one after another.
type sleepingScanner struct {
	delay    time.Duration
	findings []artifact.Finding
}

func (s *sleepingScanner) Scan(ctx context.Context, _ string) ([]artifact.Finding, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.findings, nil
}

// panickingScanner always panics -- used to prove a single Scanner's
// bug can't take down the whole server now that scanners run on their
// own goroutines (TestScanArtifact_ScannerPanicIsRecovered).
type panickingScanner struct{}

func (panickingScanner) Scan(context.Context, string) ([]artifact.Finding, error) {
	panic("boom: this scanner has a bug")
}

// testAPIKey is the shared key every test router is constructed with.
// doJSON below attaches it to every request automatically, so the ~10
// existing tests that only care about handler behavior (not auth
// itself) didn't need individual edits when auth was added -- see
// TestAuth* in router_test.go for the auth behavior itself.
const testAPIKey = "test-api-key"

func newTestRouter(scanners scanner.Registry) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	// Rate limiting disabled (0) for the ~10 existing tests that only
	// care about handler behavior -- see TestRateLimit* for the rate
	// limiter's own behavior, which builds its router directly instead.
	// digestResolver nil: dedup disabled by default here too -- see
	// TestCreateArtifact_Duplicate* for the tests that exercise it
	// deliberately with a fake resolver instead.
	return api.NewRouter(store, tracker, scanners, testAPIKey, 0, 0, nil, false, 0, false, api.ScanLimits{}, api.Notifications{}), store
}

// newTestRouterWithDigestResolver is newTestRouter plus a digest
// resolver, for the duplicate-registration tests specifically -- kept
// separate so the other ~10 existing tests are unaffected by dedup
// behavior they don't care about.
func newTestRouterWithDigestResolver(resolver scanner.DigestResolver) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(store, tracker, scanner.Registry{}, testAPIKey, 0, 0, resolver, false, 0, false, api.ScanLimits{}, api.Notifications{}), store
}

// newTestRouterWithRequireDigest is newTestRouterWithDigestResolver plus
// REQUIRE_DIGEST enabled, for the TestCreateArtifact_RequireDigest* /
// TestBulkCreateArtifacts_RequireDigest* tests specifically -- kept
// separate for the same reason newTestRouterWithDigestResolver itself is.
func newTestRouterWithRequireDigest(resolver scanner.DigestResolver) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(store, tracker, scanner.Registry{}, testAPIKey, 0, 0, resolver, false, 0, true, api.ScanLimits{}, api.Notifications{}), store
}

// fakeDigestResolver lets tests exercise duplicate-registration
// detection without shelling out to a real `oras` binary against a real
// registry. digests maps ref -> digest; a ref with no entry resolves to
// "" (same as a local-path ref oras would never contact a registry
// for), and errRef (if set) makes Resolve return an error for that one
// ref, so resolution-failure-shouldn't-block-registration behavior is
// testable too.
type fakeDigestResolver struct {
	digests map[string]string
	errRef  string
	// calls counts every Resolve invocation -- used by
	// TestScanArtifact_DoesNotReResolveAnAlreadySetDigest to prove an
	// already-resolved digest never triggers a redundant registry call.
	// Zero value is fine for every other test using this type; none of
	// them read it. Atomic because bulkCreateArtifacts resolves a
	// batch's digests concurrently (bulkDigestResolveConcurrency), so
	// the bulk tests call this from several goroutines at once -- a
	// plain int++ here is a real data race under `go test -race`.
	calls atomic.Int64
}

func (f *fakeDigestResolver) Resolve(_ context.Context, ref string, _ bool) (string, error) {
	f.calls.Add(1)
	if ref == f.errRef {
		return "", errors.New("fake registry unreachable")
	}
	return f.digests[ref], nil
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

// artifactPage mirrors GET /api/v1/artifacts' paginated response body
// (see listArtifactsResponse) -- total plus one page of artifacts,
// rather than the bare array the endpoint used to return.
type artifactPage struct {
	Total     int                 `json:"total"`
	Artifacts []artifact.Artifact `json:"artifacts"`
}

func decodeArtifactPage(t *testing.T, rec *httptest.ResponseRecorder) artifactPage {
	t.Helper()
	var page artifactPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode artifact page response: %v (body=%s)", err, rec.Body.String())
	}
	return page
}

func TestHealthz(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	rec := doJSON(t, h, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// scanAndWait fires POST /scan and blocks until the artifact leaves
// status "scanning", returning the POST's response recorder and the
// artifact's final state.
//
// Scanning is asynchronous now (202 + poll -- see scanArtifact), so a
// test that asserted on the POST response's body is asserting on the
// artifact as it looked the instant the scan *started*. Everything that
// used to read findings straight off that response goes through here
// instead. Polls the store directly rather than the HTTP endpoint:
// tests already hold the MemStore, and this keeps the wait cheap.
func scanAndWait(t *testing.T, h http.Handler, store *artifact.MemStore, id string) (*httptest.ResponseRecorder, *artifact.Artifact) {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+id+"/scan", nil)
	if rec.Code != http.StatusAccepted {
		return rec, nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, err := store.Get(id)
		if err != nil {
			t.Fatalf("store.Get while waiting for scan: %v", err)
		}
		if a.Status != artifact.StatusScanning {
			return rec, a
		}
		if time.Now().After(deadline) {
			t.Fatalf("artifact %s still %q after 5s -- the background scan never finished", id, a.Status)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForScan blocks until an artifact leaves status "scanning" and
// returns its final state -- the same wait scanAndWait does, for tests
// that issue the POST themselves rather than through doJSON.
func waitForScan(t *testing.T, store *artifact.MemStore, id string) *artifact.Artifact {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, err := store.Get(id)
		if err != nil {
			t.Fatalf("store.Get while waiting for scan: %v", err)
		}
		if a.Status != artifact.StatusScanning {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("artifact %s still %q after 5s -- the background scan never finished", id, a.Status)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
