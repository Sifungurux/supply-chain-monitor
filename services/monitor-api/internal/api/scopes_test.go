package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	readerKey   = "readerkey1234567890"
	scanKey     = "scannerkey1234567890"
	adminKey    = "adminkey1234567890"
	reporterKey = "reporterkey1234567890"
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

// With no scopes configured, every key does what it did before this
// feature existed -- the zero value still disables enforcement, which
// is what keeps a single-key deployment working.
//
// This is no longer the path a CHART upgrade takes: values.yaml now
// ships scopes, and main.go refuses to start with none while several
// clients authenticate. It remains reachable for a single-key install
// and for anything driving the binary directly, so the router must
// still behave.
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

// DEFAULT-CLOSED. A client with no entry while enforcement is on gets
// NOTHING -- not the unrestricted access it used to get.
//
// The old behaviour existed so that scoping one consumer could not
// break the others, but it meant a consumer added and forgotten held
// full authority, and a working deployment never revealed it. The
// failure now costs that one consumer its access instead of costing
// everyone else their isolation.
func TestScopes_UnlistedClientGetsNothing(t *testing.T) {
	h, store := newScopedRouter(t, scopedKeys, "reader=read")
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	// Every route, not just the destructive one: "nothing" has to mean
	// nothing, or this is just a differently-shaped hole.
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/v1/artifacts", ""},
		{http.MethodPost, "/api/v1/artifacts", `{"ref":"x:1","type":"image"}`},
		{http.MethodPost, "/api/v1/artifacts/" + a.ID + "/scan", ""},
		{http.MethodPost, "/api/v1/artifacts/" + a.ID + "/findings", `{"findings":[]}`},
		{http.MethodPost, "/api/v1/artifacts/" + a.ID + "/stage", `{"stage":"build"}`},
		{http.MethodDelete, "/api/v1/artifacts/" + a.ID, ""},
	} {
		// adminKey authenticates as "boss", which has no entry.
		if got := callWithKey(t, h, tc.method, tc.path, adminKey, tc.body); got != http.StatusForbidden {
			t.Fatalf("unlisted client %s %s = %d, want 403 -- an unlisted client must be able to do nothing", tc.method, tc.path, got)
		}
	}

	names, _ := api.ParseKeyScopes("reader=read")
	unscoped := names.Unscoped([]string{"reader", "scanner", "boss"})
	if len(unscoped) != 2 || unscoped[0] != "boss" || unscoped[1] != "scanner" {
		t.Fatalf("Unscoped = %v, want boss and scanner named so the warning can list them", unscoped)
	}
}

// THE SPLIT. "scan" asks for a scan; "results:write" asserts what was
// found. Sharing one scope made those the same permission, which handed
// fleet-wide finding suppression to the dashboard key.
//
// Tested in BOTH directions deliberately. A one-way test here would
// pass against the very bug the split exists to fix: a scan-only key
// that could still post findings.
func TestScopes_ScanDoesNotImplyResultsWrite(t *testing.T) {
	const spec = "scanner=read|scan;reporter=read|results:write"
	h, store := newScopedRouter(t, scopedKeys+";reporter:"+reporterKey, spec)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	resultRoutes := []struct {
		name, path, body string
	}{
		{"findings", "/api/v1/artifacts/" + a.ID + "/findings", `{"findings":[]}`},
		{"artifact vex", "/api/v1/artifacts/" + a.ID + "/vex", `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`},
		{"fleet vex", "/api/v1/vex", `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`},
	}

	for _, r := range resultRoutes {
		t.Run(r.name+" refused to a scan-only key", func(t *testing.T) {
			if got := callWithKey(t, h, http.MethodPost, r.path, scanKey, r.body); got != http.StatusForbidden {
				t.Fatalf("POST %s as scan-only = %d, want 403 -- triggering a scan must not imply asserting its results", r.path, got)
			}
		})
		t.Run(r.name+" allowed to a results:write key", func(t *testing.T) {
			if got := callWithKey(t, h, http.MethodPost, r.path, reporterKey, r.body); got == http.StatusForbidden {
				t.Fatalf("POST %s as results:write = 403, want it permitted", r.path)
			}
		})
	}

	// The reverse direction: results:write must not confer the trigger.
	if got := callWithKey(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", reporterKey, ""); got != http.StatusForbidden {
		t.Fatalf("POST scan as results:write-only = %d, want 403", got)
	}
	// ...and the trigger still works for the key that owns it.
	if got := callWithKey(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", scanKey, ""); got != http.StatusAccepted {
		t.Fatalf("POST scan as scan = %d, want 202", got)
	}
}

// A scan worker authenticates with a per-Job token, not a key, and so
// has no client name and no scopes entry. Enforcement being
// default-closed must NOT reach it.
//
// This combination had no coverage: the scope tests configure no scan
// tokens, and the scan-token tests configure no scopes, so nothing
// exercised a token while enforcement was on. The failure it guards
// against is quiet in the worst way -- uploads start failing AFTER a
// scan succeeds, and an artifact with no documents still reports
// "scanned".
func TestScopes_ScanTokenIsNotScopeChecked(t *testing.T) {
	store := artifact.NewMemStore()
	a, err := store.Create("example.com/app:1", artifact.TypeImage)
	if err != nil {
		t.Fatalf("seed artifact: %v", err)
	}
	token, hash, err := api.NewScanToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := store.CreateScanToken(a.ID, hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("store token: %v", err)
	}

	// Scopes enforced, and deliberately naming nobody the worker could
	// be mistaken for.
	scopes, invalid := api.ParseKeyScopes("reader=read")
	if len(invalid) > 0 {
		t.Fatalf("ParseKeyScopes rejected %v", invalid)
	}
	h := api.NewRouter(api.Config{
		Store:      store,
		Tracker:    pipeline.NewTracker([]string{"build", "scan"}),
		APIKeys:    api.ParseAPIKeys(scopedKeys),
		KeyScopes:  scopes,
		ScanTokens: store.ConsumeScanToken,
	})

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/artifacts/"+a.ID+"/documents/sbom",
		strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scan-token upload with scopes enforced = %d, want 200 -- the token path must not be scope-checked, or every isolated scan loses its documents", rec.Code)
	}
}

// stage:write is carved out of admin so a build pipeline can report
// progress without also being able to delete artifacts or accept risk.
func TestScopes_StageWrite(t *testing.T) {
	const spec = "scanner=read|scan;reporter=read|stage:write;boss=admin"
	h, store := newScopedRouter(t, scopedKeys+";reporter:"+reporterKey, spec)
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	stage := "/api/v1/artifacts/" + a.ID + "/stage"

	if got := callWithKey(t, h, http.MethodPost, stage, reporterKey, `{"stage":"build"}`); got != http.StatusOK {
		t.Fatalf("stage as stage:write = %d, want 200", got)
	}
	// admin implies it explicitly, as it does every other scope.
	if got := callWithKey(t, h, http.MethodPost, stage, adminKey, `{"stage":"test"}`); got != http.StatusOK {
		t.Fatalf("stage as admin = %d, want 200", got)
	}
	if got := callWithKey(t, h, http.MethodPost, stage, scanKey, `{"stage":"test"}`); got != http.StatusForbidden {
		t.Fatalf("stage as scan = %d, want 403", got)
	}
	// The carve-out is only worth having if it stops short of the rest
	// of admin -- otherwise it is admin with a longer name.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodDelete, "/api/v1/artifacts/" + a.ID, ""},
		{http.MethodPost, "/api/v1/artifacts/" + a.ID + "/maintainer", `{"team":"platform"}`},
	} {
		if got := callWithKey(t, h, tc.method, tc.path, reporterKey, tc.body); got != http.StatusForbidden {
			t.Fatalf("%s %s as stage:write = %d, want 403", tc.method, tc.path, got)
		}
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
		{"sweep", api.ScopeResultsWrite, false, "it asks for scans; the workers report what they find"},

		// The dashboard reads every view and has a Scan button.
		{"dashboard", api.ScopeRead, true, "every view is a GET"},
		{"dashboard", api.ScopeScan, true, "the Scan button"},
		// The one that matters: its key is attached by a proxy anyone
		// who can reach the dashboard can drive (report S1).
		{"dashboard", api.ScopeAdmin, false, "delete/maintainer/stage/acceptance must be refused"},
		{"dashboard", api.ScopeDocumentsWrite, false, "scan workers upload documents, not the dashboard"},
		// THE POINT OF THE SPLIT. Before it, "scan" carried this, so
		// anyone who could reach the dashboard could suppress a finding
		// on every artifact in the fleet.
		{"dashboard", api.ScopeResultsWrite, false, "must not be able to post findings or VEX"},
		{"dashboard", api.ScopeStageWrite, false, "the dashboard does not move artifacts through the pipeline"},
	} {
		if got := scopes.For(tc.client).Allows(tc.scope); got != tc.want {
			t.Errorf("%s allowed %q = %v, want %v -- %s", tc.client, tc.scope, got, tc.want, tc.why)
		}
	}
}

// TestScopes_UnscopedNamesEveryHole covers the input to the startup
// warning. Under default-closed enforcement an unnamed client is not a
// client running unrestricted -- it is one that can do nothing, and
// whose every request answers 403. Either way the warning is only as
// good as Unscoped's answer, and a client it fails to name is a
// consumer that looks broken for no discoverable reason.
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
