package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
)

func namedKeyRouter(t *testing.T, raw, sharedKey string) http.Handler {
	t.Helper()
	return api.NewRouter(api.Config{
		Store:   artifact.NewMemStore(),
		Tracker: pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:  sharedKey,
		APIKeys: api.ParseAPIKeys(raw),
	})
}

func getWithKey(h http.Handler, key string) int {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	if key != "<omit>" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// THE SECURITY PROPERTY THIS FEATURE COULD MOST EASILY GET WRONG.
//
// A blank key is a real input, not a hypothetical: the chart renders one
// entry per configured client, and an account that was removed (or whose
// password was never generated) renders as "name:". If that entry were
// accepted, it would be compared against the empty string a caller
// presents with a bare "Bearer " -- matching, and authenticating EVERY
// anonymous request as that client. Removing a consumer would silently
// open the API to the world.
func TestAPIKeys_BlankKeyNeverAuthenticates(t *testing.T) {
	h := namedKeyRouter(t, "retired-client:,ci:realkey123456", "")

	for _, presented := range []string{"", " ", "<omit>"} {
		if code := getWithKey(h, presented); code != http.StatusUnauthorized {
			t.Errorf("presenting %q got %d, want 401 -- a blank configured key must never match", presented, code)
		}
	}
	// The real key alongside it still works, so this isn't just "everything is rejected".
	if code := getWithKey(h, "realkey123456"); code != http.StatusOK {
		t.Errorf("the valid key got %d, want 200", code)
	}
}

func TestAPIKeys_NamedAndLegacyKeysBothAuthenticate(t *testing.T) {
	h := namedKeyRouter(t, "ci:cikey1234567890,dashboard:dashkey123456", "legacy-shared-key")

	cases := map[string]int{
		"cikey1234567890":   http.StatusOK,
		"dashkey123456":     http.StatusOK,
		"legacy-shared-key": http.StatusOK, // upgrading must not lock out an existing deployment
		"not-a-key":         http.StatusUnauthorized,
		// A NAME is not a credential -- presenting one must not work.
		"ci": http.StatusUnauthorized,
	}
	for key, want := range cases {
		if got := getWithKey(h, key); got != want {
			t.Errorf("key %q: got %d, want %d", key, got, want)
		}
	}
}

// Revocation is the point of naming keys: dropping one entry must stop
// exactly that client and leave the others working.
func TestAPIKeys_RevokingOneLeavesOthersWorking(t *testing.T) {
	before := namedKeyRouter(t, "ci:cikey1234567890,dashboard:dashkey123456", "")
	if got := getWithKey(before, "cikey1234567890"); got != http.StatusOK {
		t.Fatalf("precondition: ci key got %d, want 200", got)
	}

	after := namedKeyRouter(t, "dashboard:dashkey123456", "")
	if got := getWithKey(after, "cikey1234567890"); got != http.StatusUnauthorized {
		t.Errorf("revoked key got %d, want 401", got)
	}
	if got := getWithKey(after, "dashkey123456"); got != http.StatusOK {
		t.Errorf("surviving key got %d, want 200 -- revoking one client must not re-key the others", got)
	}
}

func TestParseAPIKeys_SkipsWhatCannotBeACredential(t *testing.T) {
	keys := api.ParseAPIKeys(" ci : cikey1 , malformed-no-colon , :keywithoutname , namewithoutkey: ,, dup:one,dup:two")
	got := strings.Join(keys.Names(), ",")
	// "dup:two" loses to "dup:one" -- a repeated name would make
	// attribution ambiguous.
	if want := "ci,dup"; got != want {
		t.Fatalf("names = %q, want %q", got, want)
	}
	if name, ok := keys.Lookup("cikey1"); !ok || name != "ci" {
		t.Errorf("Lookup(cikey1) = %q,%v -- surrounding whitespace must be trimmed", name, ok)
	}
	if _, ok := keys.Lookup("two"); ok {
		t.Error("the losing half of a duplicated name must not authenticate")
	}
}

// Attribution is only real once it reaches a log line.
func TestAudit_MutationsCarryTheClientName(t *testing.T) {
	logs := captureLogs(t)
	h := namedKeyRouter(t, "ci:cikey1234567890", "")

	body := strings.NewReader(`{"ref":"example.com/app:1.0","type":"image"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts", body)
	req.Header.Set("Authorization", "Bearer cikey1234567890")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register got %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil || entry["msg"] != "request" {
			continue
		}
		found = true
		if entry["client"] != "ci" {
			t.Errorf("client = %v, want \"ci\" -- an audit line that cannot name the caller is not an audit line", entry["client"])
		}
		if entry["method"] != "POST" || entry["path"] != "/api/v1/artifacts" {
			t.Errorf("method/path = %v %v, want POST /api/v1/artifacts", entry["method"], entry["path"])
		}
	}
	if !found {
		t.Fatal("no audit line was logged for a mutation")
	}
}

// Reads are excluded deliberately -- the dashboard polls several GETs
// every ten seconds per open tab, and an audit trail nobody can grep is
// not an audit trail.
func TestAudit_ReadsAreNotLogged(t *testing.T) {
	logs := captureLogs(t)
	h := namedKeyRouter(t, "ci:cikey1234567890", "")

	if code := getWithKey(h, "cikey1234567890"); code != http.StatusOK {
		t.Fatalf("GET got %d, want 200", code)
	}
	if strings.Contains(logs.String(), `"msg":"request"`) {
		t.Error("a GET produced an audit line; reads would drown the mutations this exists to record")
	}
}
