package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// newScopedRouter builds a router with named keys and their scopes.
func newScopedRouter(t *testing.T, keys, scopeSpec string) (http.Handler, *artifact.MemStore) {
	t.Helper()
	scopes, invalid := api.ParseKeyScopes(scopeSpec)
	if len(invalid) > 0 {
		t.Fatalf("ParseKeyScopes(%q) rejected %v", scopeSpec, invalid)
	}
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	h := api.NewRouter(api.Config{
		Store:   store,
		Tracker: tracker,
		// A registered scanner, so a permitted scan is a 202 rather
		// than the 501 an empty registry returns -- otherwise the
		// allowed and denied cases would be indistinguishable.
		Scanners:  scanner.Registry{artifact.TypeImage: {&fakeScanner{}}},
		APIKeys:   api.ParseAPIKeys(keys),
		KeyScopes: scopes,
	})
	return h, store
}

func callWithKey(t *testing.T, h http.Handler, method, path, key string, body string) int {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

const (
	readerKey = "readerkey1234567890"
	scanKey   = "scannerkey1234567890"
	adminKey  = "adminkey1234567890"
)

const scopedKeys = "reader:" + readerKey + ";scanner:" + scanKey + ";boss:" + adminKey

// TestScopes_Denial is the point of the feature: a key that may read
// must not be able to trigger work or delete anything.
func TestScopes_Denial(t *testing.T) {
	spec := "reader=read;scanner=read|scan;boss=admin"
	h, store := newScopedRouter(t, scopedKeys, spec)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	for _, tc := range []struct {
		name, method, path, key string
		body                    string
		want                    int
	}{
		{"reader can read", http.MethodGet, "/api/v1/artifacts", readerKey, "", http.StatusOK},
		{"reader cannot scan", http.MethodPost, "/api/v1/artifacts/" + a.ID + "/scan", readerKey, "", http.StatusForbidden},
		{"reader cannot register", http.MethodPost, "/api/v1/artifacts", readerKey, `{"ref":"x:1","type":"image"}`, http.StatusForbidden},
		{"reader cannot delete", http.MethodDelete, "/api/v1/artifacts/" + a.ID, readerKey, "", http.StatusForbidden},

		{"scanner can read", http.MethodGet, "/api/v1/artifacts", scanKey, "", http.StatusOK},
		{"scanner can scan", http.MethodPost, "/api/v1/artifacts/" + a.ID + "/scan", scanKey, "", http.StatusAccepted},
		{"scanner cannot register", http.MethodPost, "/api/v1/artifacts", scanKey, `{"ref":"y:1","type":"image"}`, http.StatusForbidden},
		{"scanner cannot delete", http.MethodDelete, "/api/v1/artifacts/" + a.ID, scanKey, "", http.StatusForbidden},

		// admin implies every scope EXPLICITLY -- not because the route
		// table happens to list it.
		{"admin can read", http.MethodGet, "/api/v1/artifacts", adminKey, "", http.StatusOK},
		{"admin can register", http.MethodPost, "/api/v1/artifacts", adminKey, `{"ref":"z:1","type":"image"}`, http.StatusCreated},
		{"admin can scan", http.MethodPost, "/api/v1/artifacts/" + a.ID + "/scan", adminKey, "", http.StatusAccepted},
		{"admin can delete", http.MethodDelete, "/api/v1/artifacts/" + a.ID, adminKey, "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := callWithKey(t, h, tc.method, tc.path, tc.key, tc.body); got != tc.want {
				t.Fatalf("%s %s as %q = %d, want %d", tc.method, tc.path, tc.key, got, tc.want)
			}
		})
	}
}

// A denial is 403, never 401: the credential is valid and identified,
// it simply may not do this. 401 would tell the caller to fix its key,
// which is the wrong instruction and sends them rotating a credential
// that was fine.
func TestScopes_DenialIsForbiddenNotUnauthorized(t *testing.T) {
	h, store := newScopedRouter(t, scopedKeys, "reader=read")
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if got := callWithKey(t, h, http.MethodDelete, "/api/v1/artifacts/"+a.ID, readerKey, ""); got != http.StatusForbidden {
		t.Fatalf("denied request = %d, want 403", got)
	}
	// ...and a genuinely bad key is still 401.
	if got := callWithKey(t, h, http.MethodGet, "/api/v1/artifacts", "not-a-key", ""); got != http.StatusUnauthorized {
		t.Fatalf("invalid key = %d, want 401", got)
	}
}

// THE UPGRADE PATH. With no scopes configured, every key does what it
// did before this feature existed. Enforcement switching itself on
// during an upgrade would lock out the dashboard, the sweep CronJob and
// every CI consumer at once.
func TestScopes_UnconfiguredEnforcesNothing(t *testing.T) {
	h, store := newScopedRouter(t, scopedKeys, "")
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/artifacts", http.StatusOK},
		{http.MethodPost, "/api/v1/artifacts/" + a.ID + "/scan", http.StatusAccepted},
		{http.MethodDelete, "/api/v1/artifacts/" + a.ID, http.StatusOK},
	} {
		// readerKey has no scopes and no entry -- unconfigured means
		// unrestricted, for every key.
		if got := callWithKey(t, h, tc.method, tc.path, readerKey, ""); got != tc.want {
			t.Fatalf("with no scopes configured, %s %s = %d, want %d", tc.method, tc.path, got, tc.want)
		}
	}
}

// A client with no entry while enforcement IS on runs unrestricted --
// the compatibility hole main.go warns about by name at startup.
func TestScopes_UnlistedClientIsUnrestricted(t *testing.T) {
	h, store := newScopedRouter(t, scopedKeys, "reader=read")
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if got := callWithKey(t, h, http.MethodDelete, "/api/v1/artifacts/"+a.ID, adminKey, ""); got != http.StatusOK {
		t.Fatalf("unlisted client was denied (%d) -- enabling scopes must not lock out consumers that have no entry yet", got)
	}
	names, _ := api.ParseKeyScopes("reader=read")
	unscoped := names.Unscoped([]string{"reader", "scanner", "boss"})
	if len(unscoped) != 2 || unscoped[0] != "boss" || unscoped[1] != "scanner" {
		t.Fatalf("Unscoped = %v, want boss and scanner named so the warning can list them", unscoped)
	}
}

func TestParseKeyScopes(t *testing.T) {
	t.Run("semicolons between clients, pipes between scopes", func(t *testing.T) {
		ks, invalid := api.ParseKeyScopes("ci=read|scan;dash=read")
		if len(invalid) > 0 {
			t.Fatalf("unexpected invalid: %v", invalid)
		}
		if !ks.Enforced() {
			t.Fatal("Enforced() = false with two clients configured")
		}
		if !ks.For("ci").Allows(api.ScopeScan) || !ks.For("ci").Allows(api.ScopeRead) {
			t.Errorf("ci scopes = %v", ks.For("ci").List())
		}
		if ks.For("dash").Allows(api.ScopeScan) {
			t.Error("dash was granted scan")
		}
	})

	// Commas are accepted for a hand-set value, the same courtesy
	// ParseAPIKeys extends -- but semicolon/pipe are canonical because
	// Flux's strvals parser eats commas.
	t.Run("commas still parse", func(t *testing.T) {
		ks, _ := api.ParseKeyScopes("ci=read,scan")
		if !ks.For("ci").Allows(api.ScopeScan) {
			t.Error("comma-separated scopes did not parse")
		}
	})

	// An unknown scope is REPORTED, so main.go can refuse to start. A
	// typo'd "reader" grants nothing and looks like working config
	// until somebody hits a 403 they cannot explain.
	t.Run("unknown scopes are reported, not ignored", func(t *testing.T) {
		_, invalid := api.ParseKeyScopes("ci=reader")
		if len(invalid) != 1 || !strings.Contains(invalid[0], "reader") {
			t.Fatalf("invalid = %v, want the typo named", invalid)
		}
	})

	t.Run("an entry with no scopes grants none", func(t *testing.T) {
		ks, _ := api.ParseKeyScopes("ci=")
		// Explicitly listed means somebody thought about this client,
		// so the safe reading of "ci=" is nothing, not everything.
		if ks.For("ci").Allows(api.ScopeRead) {
			t.Error("an explicit empty scope list granted read")
		}
	})

	t.Run("admin implies every scope", func(t *testing.T) {
		ks, _ := api.ParseKeyScopes("boss=admin")
		for _, s := range api.AllScopes {
			if !ks.For("boss").Allows(s) {
				t.Errorf("admin does not imply %q", s)
			}
		}
	})
}

// TestScopes_RecommendedGrantsMatchConsumerNeeds pins the scope map
// this project's own deployment ships against what its in-cluster
// consumers actually call.
//
// Getting this wrong is not a subtle failure: too narrow and the sweep
// CronJob 403s on every artifact nightly, too wide and the whole point
// of scoping is lost. Both are configuration, not code, so nothing
// else in the test suite would notice -- which is exactly why the
// values.yaml recommendation is asserted here rather than trusted.
func TestScopes_RecommendedGrantsMatchConsumerNeeds(t *testing.T) {
	// The recommendation documented at monitorApi.apiKeyScopes.
	scopes, invalid := api.ParseKeyScopes("dashboard=read|scan;sweep=read|scan")
	if len(invalid) > 0 {
		t.Fatalf("the recommended grant string does not parse: %v", invalid)
	}

	for _, tc := range []struct {
		client string
		scope  string
		want   bool
		why    string
	}{
		// The sweep lists artifacts (GET /artifacts, GET
		// /artifacts/{id}) and triggers scans (POST .../scan).
		{"sweep", api.ScopeRead, true, "lists artifacts every run"},
		{"sweep", api.ScopeScan, true, "posts .../scan for each artifact it picks"},
		{"sweep", api.ScopeAdmin, false, "never deletes, stages or accepts risk"},
		{"sweep", api.ScopeRegister, false, "the sweep scans what exists, it does not register"},

		// The dashboard reads every view and has a Scan button.
		{"dashboard", api.ScopeRead, true, "every view is a GET"},
		{"dashboard", api.ScopeScan, true, "the Scan button"},
		// The one that matters: its key is attached by a proxy anyone
		// who can reach the dashboard can drive (report S1).
		{"dashboard", api.ScopeAdmin, false, "delete/maintainer/stage/acceptance must be refused"},
		{"dashboard", api.ScopeDocumentsWrite, false, "scan workers upload documents, not the dashboard"},
	} {
		if got := scopes.For(tc.client).Allows(tc.scope); got != tc.want {
			t.Errorf("%s allowed %q = %v, want %v -- %s", tc.client, tc.scope, got, tc.want, tc.why)
		}
	}
}

// TestScopes_UnscopedNamesEveryHole covers the input to the
// API_KEY_SCOPES_STRICT refusal: strict mode is only as good as
// Unscoped's answer, and a client it fails to name is a client that
// keeps running unrestricted while the deployment believes it is
// locked down.
func TestScopes_UnscopedNamesEveryHole(t *testing.T) {
	scopes, _ := api.ParseKeyScopes("dashboard=read|scan")
	got := scopes.Unscoped([]string{"dashboard", "sweep", "ci", "default"})

	want := map[string]bool{"sweep": true, "ci": true, "default": true}
	if len(got) != len(want) {
		t.Fatalf("unscoped = %v, want the three clients with no entry", got)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unscoped names %q, which has an entry", c)
		}
	}

	// With nothing enforced there are no holes to report -- every key
	// is unrestricted by design, and naming them all would be noise
	// that trains people to ignore the warning.
	none, _ := api.ParseKeyScopes("")
	if got := none.Unscoped([]string{"dashboard", "sweep"}); len(got) != 0 {
		t.Errorf("unenforced scopes reported %v, want none", got)
	}
}
