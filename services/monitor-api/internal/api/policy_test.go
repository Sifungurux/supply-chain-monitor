package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/policy"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// newPolicyRouter is newTestRouter plus a policy, kept separate so the
// existing tests keep exercising the no-policy default.
func newPolicyRouter(t *testing.T, raw string) (http.Handler, *artifact.MemStore) {
	t.Helper()
	p, err := policy.Load(raw)
	if err != nil {
		t.Fatalf("policy.Load(%s): %v", raw, err)
	}
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(api.Config{Store: store, Tracker: tracker, APIKey: testAPIKey, Policy: p, Enricher: scanner.NewEnricher(store)}), store
}

func getPolicy(t *testing.T, h http.Handler, id string) (int, policy.Result) {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+id+"/policy", nil)
	var got policy.Result
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
		}
	}
	return rec.Code, got
}

// TestGetPolicy_AlwaysHTTP200 is the endpoint's whole contract for its
// intended caller.
//
// A CI step running `curl --fail` cannot tell a non-2xx meaning "this
// artifact violates the policy" from one meaning "the API is down, the
// id is wrong, or my key is invalid" -- and the first must block a
// release while the others must be investigated rather than silently
// treated as a failed gate. So a violation is reported in the BODY
// with a 200.
func TestGetPolicy_AlwaysHTTP200(t *testing.T) {
	h, store := newPolicyRouter(t, `{"maxSeverity": {"cve": "high"}}`)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	a.CVEFindings = []artifact.Finding{{ID: "CVE-2024-BAD", Severity: "critical", Title: "very bad"}}
	if _, err := store.Update(a.ID, func(cur *artifact.Artifact) { cur.CVEFindings = a.CVEFindings }); err != nil {
		t.Fatalf("update: %v", err)
	}

	code, got := getPolicy(t, h, a.ID)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when the policy FAILS -- the caller reads .pass from the body", code)
	}
	if got.Pass {
		t.Fatal("pass = true for an artifact with a critical CVE under a high threshold")
	}
	if len(got.Violations) != 1 || got.Violations[0].FindingID != "CVE-2024-BAD" {
		t.Fatalf("violations = %+v, want the critical CVE named", got.Violations)
	}
}

func TestGetPolicy_Pass(t *testing.T) {
	h, store := newPolicyRouter(t, `{"maxSeverity": {"cve": "high"}}`)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(a.ID, func(cur *artifact.Artifact) {
		cur.CVEFindings = []artifact.Finding{{ID: "CVE-1", Severity: "medium"}}
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	code, got := getPolicy(t, h, a.ID)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !got.Pass {
		t.Fatalf("pass = false, want true: %+v", got.Violations)
	}
	// Encoded as [], never null -- a CI script doing `| length` on the
	// violations array should not have to special-case null.
	if got.Violations == nil {
		t.Error("violations decoded as nil; the response must carry an empty array")
	}
}

// A VEX-suppressed critical must not fail the gate, end to end through
// the handler -- not just in the policy package's own unit test.
// Otherwise assessing a finding buys nothing and people route around
// the gate.
func TestGetPolicy_VEXSuppressedFindingDoesNotFail(t *testing.T) {
	h, store := newPolicyRouter(t, `{"maxSeverity": {"cve": "high"}}`)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(a.ID, func(cur *artifact.Artifact) {
		cur.CVEFindings = []artifact.Finding{
			{ID: "CVE-ASSESSED", Severity: "critical", Status: artifact.FindingStatusNotAffected},
			{ID: "CVE-GONE", Severity: "critical", Status: artifact.FindingStatusFixed},
		}
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	code, got := getPolicy(t, h, a.ID)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !got.Pass {
		t.Fatalf("a VEX-suppressed and a fixed critical failed the gate: %+v", got.Violations)
	}
}

// With no policy configured every artifact passes -- which is why the
// dashboard distinguishes "no policy" from "passed", see policyBadge.
func TestGetPolicy_NoPolicyConfiguredPassesEverything(t *testing.T) {
	h, store := newPolicyRouter(t, "")
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(a.ID, func(cur *artifact.Artifact) {
		cur.Unsafe = true
		cur.CVEFindings = []artifact.Finding{{ID: "CVE-1", Severity: "critical"}}
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	code, got := getPolicy(t, h, a.ID)
	if code != http.StatusOK || !got.Pass || len(got.Violations) != 0 {
		t.Fatalf("code=%d result=%+v, want 200 and a clean pass", code, got)
	}
}

// A missing artifact is a question about an id that does not exist,
// not a policy outcome -- so this one IS a 404.
func TestGetPolicy_UnknownArtifactIs404(t *testing.T) {
	h, _ := newPolicyRouter(t, `{"disallowUnsafe": true}`)
	if code, _ := getPolicy(t, h, "does-not-exist"); code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}

func TestGetPolicy_RequiresAuth(t *testing.T) {
	h, store := newPolicyRouter(t, `{"disallowUnsafe": true}`)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+a.ID+"/policy", nil)
	// no Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d without a key, want 401", rec.Code)
	}
}

// TestPolicyBucketsMatchAPI keeps internal/policy's bucket vocabulary
// in agreement with this package's validFindingsBucket.
//
// policy cannot import api (api imports policy), so the list is
// duplicated there the same way internal/artifact duplicates
// internal/notify's severity table -- and, like that one, the
// duplication is only safe because a test asserts they agree. A policy
// naming a bucket the API does not recognize would gate nothing.
func TestPolicyBucketsMatchAPI(t *testing.T) {
	for _, b := range policy.Buckets {
		if !api.ValidFindingsBucketForTest(b) {
			t.Errorf("policy.Buckets has %q, which internal/api does not recognize as a findings bucket", b)
		}
	}
	if got, want := len(policy.Buckets), 5; got != want {
		t.Errorf("policy.Buckets has %d entries, want %d -- a bucket added to the API needs adding here too", got, want)
	}
}

// TestSubmitFindings_CallerCannotAssertEnrichment is a provenance
// rule, not a formatting one.
//
// epss_score and known_exploited are derived facts about a CVE, not
// observations about this artifact. A submitter claiming
// known_exploited=false for its own findings would be asserting
// something it has no standing to know -- and the direction of that lie
// is always "this is fine". Same reasoning that makes MergeFindings
// recompute Status and Justification rather than trust a caller.
func TestSubmitFindings_CallerCannotAssertEnrichment(t *testing.T) {
	h, store := newPolicyRouter(t, "")
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	// The store knows this CVE IS exploited; the caller claims it is not.
	if err := store.ReplaceEnrichment(
		[]string{"CVE-2024-9999"},
		map[string]float64{"CVE-2024-9999": 0.94},
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("ReplaceEnrichment: %v", err)
	}

	body := map[string]any{
		"bucket": "cve",
		"findings": []map[string]any{
			{
				// The feed says this one IS exploited; the caller says
				// it is not.
				"id":              "CVE-2024-9999",
				"severity":        "high",
				"title":           "something",
				"epss_score":      0.0,
				"known_exploited": false,
			},
			{
				// And the reverse, which is the case the clearing
				// actually exists for: a CVE the feeds have never heard
				// of, where the caller asserts a scary flag. Apply
				// deliberately leaves unknown CVEs alone, so without the
				// clearing this value would simply be persisted as
				// submitted -- letting any caller stamp KEV on anything.
				"id":              "CVE-1999-0001",
				"severity":        "low",
				"title":           "invented",
				"epss_score":      0.99,
				"known_exploited": true,
			},
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/findings", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	got, err := store.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	byID := map[string]artifact.Finding{}
	for _, f := range got.CVEFindings {
		byID[f.ID] = f
	}
	if len(byID) != 2 {
		t.Fatalf("findings = %+v", got.CVEFindings)
	}

	known := byID["CVE-2024-9999"]
	if !known.KnownExploited {
		t.Error("the caller's known_exploited=false was accepted over the KEV catalog")
	}
	if known.EPSSScore != 0.94 {
		t.Errorf("epss_score = %v, want 0.94 from the feed rather than the caller's 0", known.EPSSScore)
	}

	invented := byID["CVE-1999-0001"]
	if invented.KnownExploited {
		t.Error("a caller stamped known_exploited on a CVE the feeds have never heard of")
	}
	if invented.EPSSScore != 0 {
		t.Errorf("epss_score = %v, want 0 -- a caller does not get to invent a score", invented.EPSSScore)
	}
}
