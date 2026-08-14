package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// The real CycloneDX fixture the SBOM parser is already tested against.
// Go's testdata is per-package, so internal/api reaches internal/scanner's
// copy by path rather than keeping a second one that could drift from
// the parser it is meant to exercise.
const sbomFixture = "../scanner/testdata/cyclonedx_sbom_sample.json"

func readSBOMFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(sbomFixture)
	if err != nil {
		t.Fatalf("read %s: %v", sbomFixture, err)
	}
	return b
}

// mutateSBOM returns the fixture with one package upgraded, one dropped
// and one added -- the three things a diff has to tell apart. Done as a
// string edit on the real document rather than by hand-writing a second
// fixture, so the "before" and "after" cannot drift apart in any way
// except the changes named here.
func mutateSBOM(t *testing.T, original []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(original, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	components, ok := doc["components"].([]any)
	if !ok || len(components) < 3 {
		t.Fatalf("fixture has too few components to mutate: %v", doc["components"])
	}

	// Upgrade alpine-keys 2.4-r1 -> 2.5-r0 (purl carries the version, so
	// both fields move).
	upgraded := false
	kept := make([]any, 0, len(components))
	for _, raw := range components {
		c, _ := raw.(map[string]any)
		name, _ := c["name"].(string)
		switch name {
		case "alpine-keys":
			c["version"] = "2.5-r0"
			if purl, _ := c["purl"].(string); purl != "" {
				c["purl"] = strings.Replace(purl, "2.4-r1", "2.5-r0", 1)
			}
			upgraded = true
			kept = append(kept, c)
		case "apk-tools":
			// dropped
		default:
			kept = append(kept, c)
		}
	}
	if !upgraded {
		t.Fatalf("fixture no longer contains alpine-keys -- update this test's mutation")
	}
	// And one brand new package.
	kept = append(kept, map[string]any{
		"type":    "library",
		"name":    "curl",
		"version": "8.5.0-r0",
		"purl":    "pkg:apk/alpine/curl@8.5.0-r0?arch=x86_64&distro=3.19.9",
	})
	doc["components"] = kept

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode mutated fixture: %v", err)
	}
	return out
}

func fetchDiff(t *testing.T, h http.Handler, id, query string) map[string]any {
	t.Helper()
	path := "/api/v1/artifacts/" + id + "/components/diff"
	if query != "" {
		path += "?" + query
	}
	rec := doJSON(t, h, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("diff status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode diff: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func names(t *testing.T, list any) []string {
	t.Helper()
	items, ok := list.([]any)
	if !ok {
		t.Fatalf("expected a list, got %T", list)
	}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		c, _ := raw.(map[string]any)
		n, _ := c["name"].(string)
		out = append(out, n)
	}
	return out
}

func uploadSBOM(t *testing.T, h http.Handler, id string, body []byte) {
	t.Helper()
	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+id+"/documents/sbom", "application/vnd.cyclonedx+json", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// waitForComponentSnapshots polls until the artifact has at least want
// snapshots. Necessary because indexing happens AFTER runScan persists
// the artifact -- so waitForScan (which returns as soon as the status
// stops being "scanning") returns before the components are indexed.
// Deliberately a wait rather than reordering production code: indexing
// after the scan result is persisted is the right order, since it must
// never delay or endanger the scan's own outcome.
func waitForComponentSnapshots(t *testing.T, store *artifact.MemStore, id string, want int) []time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		snaps, err := store.ComponentSnapshots(id, 0)
		if err != nil {
			t.Fatalf("ComponentSnapshots: %v", err)
		}
		if len(snaps) >= want {
			return snaps
		}
		if time.Now().After(deadline) {
			t.Fatalf("artifact %s has %d component snapshots after 5s, want %d", id, len(snaps), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestComponentDiff_AcrossTwoUploads(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	original := readSBOMFixture(t)
	uploadSBOM(t, h, a.ID, original)
	uploadSBOM(t, h, a.ID, mutateSBOM(t, original))

	diff := fetchDiff(t, h, a.ID, "")

	if got := names(t, diff["added"]); len(got) != 1 || got[0] != "curl" {
		t.Errorf("added = %v, want [curl]", got)
	}
	if got := names(t, diff["removed"]); len(got) != 1 || got[0] != "apk-tools" {
		t.Errorf("removed = %v, want [apk-tools]", got)
	}
	changed, _ := diff["version_changed"].([]any)
	if len(changed) != 1 {
		t.Fatalf("version_changed = %v, want exactly one entry", diff["version_changed"])
	}
	vc, _ := changed[0].(map[string]any)
	if vc["from"] != "2.4-r1" || vc["to"] != "2.5-r0" {
		t.Errorf("version_changed = %v, want alpine-keys 2.4-r1 -> 2.5-r0", vc)
	}
	// An upgrade must NOT also appear as an add plus a remove -- the
	// failure a purl-keyed diff produces, since a purl embeds its version.
	if strings.Contains(strings.Join(names(t, diff["added"]), ","), "alpine-keys") ||
		strings.Contains(strings.Join(names(t, diff["removed"]), ","), "alpine-keys") {
		t.Error("the upgraded package also showed up in added/removed")
	}

	// The snapshots compared are echoed back, so a caller knows what it
	// got without having to guess.
	if diff["from"] == nil || diff["to"] == nil {
		t.Errorf("from/to = %v/%v, want both populated", diff["from"], diff["to"])
	}
}

// One snapshot means nothing has changed yet -- a real answer, not a
// 404. A brand-new artifact must not look broken on the dashboard.
func TestComponentDiff_SingleSnapshotIsEmptyNot404(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	uploadSBOM(t, h, a.ID, readSBOMFixture(t))

	diff := fetchDiff(t, h, a.ID, "")
	for _, key := range []string{"added", "removed", "version_changed"} {
		if list, _ := diff[key].([]any); len(list) != 0 {
			t.Errorf("%s = %v, want empty with only one snapshot", key, list)
		}
		// Empty, never null: the dashboard iterates these.
		if diff[key] == nil {
			t.Errorf("%s is null, want an empty array", key)
		}
	}
	if diff["from"] != nil || diff["to"] != nil {
		t.Errorf("from/to = %v/%v, want null when there is no pair to compare", diff["from"], diff["to"])
	}
}

func TestComponentDiff_NeverIndexedIsEmpty(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	diff := fetchDiff(t, h, a.ID, "")
	if list, _ := diff["added"].([]any); len(list) != 0 {
		t.Errorf("added = %v, want empty for an artifact with no SBOM", list)
	}
}

func TestComponentDiff_ExplicitFromTo(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	original := readSBOMFixture(t)
	uploadSBOM(t, h, a.ID, original)
	uploadSBOM(t, h, a.ID, mutateSBOM(t, original))
	// A third upload identical to the first, so the DEFAULT pair (the
	// two most recent) differs from the explicit pair asked for below.
	uploadSBOM(t, h, a.ID, original)

	snaps, err := store.ComponentSnapshots(a.ID, 0)
	if err != nil {
		t.Fatalf("ComponentSnapshots: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("got %d snapshots, want 3", len(snaps))
	}
	// snaps is newest-first: compare the OLDEST pair explicitly.
	oldest, middle := snaps[2], snaps[1]
	diff := fetchDiff(t, h, a.ID,
		"from="+oldest.Format(time.RFC3339Nano)+"&to="+middle.Format(time.RFC3339Nano))

	if got := names(t, diff["added"]); len(got) != 1 || got[0] != "curl" {
		t.Errorf("added = %v, want [curl] for the explicitly requested pair", got)
	}
}

func TestComponentDiff_BadRange(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	cases := []struct{ name, query string }{
		{"from without to", "from=2026-08-15T10:00:00Z"},
		{"to without from", "to=2026-08-15T10:00:00Z"},
		{"unparseable", "from=yesterday&to=today"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID+"/components/diff?"+tc.query, nil)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestComponentDiff_UnknownArtifactIs404(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	rec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts/does-not-exist/components/diff", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestComponentDiff_RequiresAPIKey(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/"+a.ID+"/components/diff", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without an API key", rec.Code)
	}
}

// Only the newest MaxComponentSnapshots are kept, so the diff endpoint
// can't be asked about a snapshot that has aged out -- and the store
// must not grow without bound as an artifact is rescanned.
func TestComponentDiff_HistoryIsCapped(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	body := readSBOMFixture(t)
	for i := 0; i < artifact.MaxComponentSnapshots+5; i++ {
		uploadSBOM(t, h, a.ID, body)
	}
	snaps, err := store.ComponentSnapshots(a.ID, 0)
	if err != nil {
		t.Fatalf("ComponentSnapshots: %v", err)
	}
	if len(snaps) != artifact.MaxComponentSnapshots {
		t.Errorf("kept %d snapshots after %d uploads, want the cap of %d",
			len(snaps), artifact.MaxComponentSnapshots+5, artifact.MaxComponentSnapshots)
	}
}

// fakeFetcher hands back a file already on disk, standing in for
// RegistryFetcher without a registry.
type fakeFetcher struct {
	path string
	err  error
}

func (f *fakeFetcher) Fetch(_ context.Context, _ string) (string, func(), error) {
	return f.path, func() {}, f.err
}

// The gap this change closes: an artifact whose own TYPE is sbom never
// had its components indexed, because indexing only ever fired on an
// SBOM being uploaded to /documents/sbom -- which is how an IMAGE gets
// one, and nothing does for an sbom-type artifact.
func TestScan_IndexesComponentsForSBOMTypeArtifacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(path, readSBOMFixture(t), 0o600); err != nil {
		t.Fatalf("write temp sbom: %v", err)
	}

	h, store := newTestRouterWithFetcher(&fakeFetcher{path: path}, scanner.Registry{
		artifact.TypeSBOM: {&fakeScanner{}},
	})
	a := mustCreate(t, store, "scm-registry:5000/app-sbom:1", artifact.TypeSBOM)

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil); rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := waitForScan(t, store, a.ID); got.Status == artifact.StatusFailed {
		t.Fatalf("scan failed: %v", got.LastScanErrors)
	}

	if snaps := waitForComponentSnapshots(t, store, a.ID, 1); len(snaps) != 1 {
		t.Fatalf("got %d component snapshots after scanning an sbom-type artifact, want 1", len(snaps))
	}
	// And they are searchable, the same as an uploaded SBOM's would be.
	found, err := store.FindByComponentPURL("pkg:apk/alpine/alpine-keys@2.4-r1?arch=x86_64&distro=3.19.9")
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(found) != 1 || found[0].ID != a.ID {
		t.Errorf("component search found %+v, want the sbom-type artifact %s", found, a.ID)
	}
}

// An image-type artifact must NOT be fetched-and-indexed by this path --
// its components arrive by upload from the scan-worker.
func TestScan_DoesNotIndexNonSBOMTypesFromTheRef(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(path, readSBOMFixture(t), 0o600); err != nil {
		t.Fatalf("write temp sbom: %v", err)
	}

	h, store := newTestRouterWithFetcher(&fakeFetcher{path: path}, scanner.Registry{
		artifact.TypeImage: {&fakeScanner{}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil)
	waitForScan(t, store, a.ID)

	if snaps, _ := store.ComponentSnapshots(a.ID, 0); len(snaps) != 0 {
		t.Errorf("an image-type artifact got %d component snapshots from its ref; only sbom-type should", len(snaps))
	}
}
