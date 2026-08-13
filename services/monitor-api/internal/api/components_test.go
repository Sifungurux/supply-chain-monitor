package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// A CycloneDX SBOM in the shape trivy actually emits (see
// internal/scanner/testdata for the full, real fixtures the parser is
// tested against) -- trimmed here to the two packages these tests care
// about.
const cycloneDXUpload = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "container", "name": "alpine:3.19", "purl": "pkg:oci/alpine@sha256:abc" } },
  "components": [
    { "type": "library", "name": "openssl", "version": "3.1.4-r5", "purl": "pkg:apk/alpine/openssl@3.1.4-r5" },
    { "type": "library", "name": "busybox", "version": "1.36.1-r15", "purl": "pkg:apk/alpine/busybox@1.36.1-r15" }
  ]
}`

func componentSearch(t *testing.T, h http.Handler, purl string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodGet, "/api/v1/components?purl="+url.QueryEscape(purl), nil)
}

func decodeArtifacts(t *testing.T, rec *httptest.ResponseRecorder) []artifact.Artifact {
	t.Helper()
	var out []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode artifact list: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func TestUploadSBOM_IndexesComponentsAndTheyAreSearchable(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	alpine := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	other := mustCreate(t, store, "debian:12", artifact.TypeImage)

	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+alpine.ID+"/documents/sbom", "application/vnd.cyclonedx+json", []byte(cycloneDXUpload))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	found := decodeArtifacts(t, componentSearch(t, h, "pkg:apk/alpine/openssl@3.1.4-r5"))
	if len(found) != 1 || found[0].ID != alpine.ID {
		t.Fatalf("search = %+v, want just the artifact whose SBOM lists it (%s, not %s)", found, alpine.ID, other.ID)
	}
	// The document itself is still stored and downloadable -- indexing
	// components is in addition to the endpoint's existing job, not
	// instead of it.
	if dl := doRaw(t, h, http.MethodGet, "/api/v1/artifacts/"+alpine.ID+"/documents/sbom", "", nil); dl.Code != http.StatusOK {
		t.Fatalf("download status = %d, want the uploaded SBOM still retrievable", dl.Code)
	}

	// The subject of the SBOM is not a component of itself.
	if subject := decodeArtifacts(t, componentSearch(t, h, "pkg:oci/alpine@sha256:abc")); len(subject) != 0 {
		t.Fatalf("search for the document's own subject = %+v, want no matches", subject)
	}
}

// Two artifacts sharing a package is the whole point of the query --
// "which of our images ship this".
func TestComponentSearch_ReturnsEveryArtifactContainingIt(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	b := mustCreate(t, store, "alpine:3.19-slim", artifact.TypeImage)

	for _, id := range []string{a.ID, b.ID} {
		if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+id+"/documents/sbom", "application/json", []byte(cycloneDXUpload)); rec.Code != http.StatusOK {
			t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	found := decodeArtifacts(t, componentSearch(t, h, "pkg:apk/alpine/busybox@1.36.1-r15"))
	if len(found) != 2 {
		t.Fatalf("search = %+v, want both artifacts", found)
	}
}

// A re-uploaded SBOM replaces the inventory. Without that, the query
// keeps returning an artifact for a package a rebuild removed -- which
// is worse than not having the feature, since it reads as current fact.
func TestUploadSBOM_ReUploadReplacesTheInventory(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	const oldSBOM = `{"bomFormat":"CycloneDX","components":[{"name":"openssl","version":"1.1.1","purl":"pkg:apk/alpine/openssl@1.1.1"}]}`
	const newSBOM = `{"bomFormat":"CycloneDX","components":[{"name":"openssl","version":"3.0.0","purl":"pkg:apk/alpine/openssl@3.0.0"}]}`

	for _, body := range []string{oldSBOM, newSBOM} {
		if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/json", []byte(body)); rec.Code != http.StatusOK {
			t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	if stale := decodeArtifacts(t, componentSearch(t, h, "pkg:apk/alpine/openssl@1.1.1")); len(stale) != 0 {
		t.Fatalf("search for the replaced version = %+v, want no matches", stale)
	}
	if fresh := decodeArtifacts(t, componentSearch(t, h, "pkg:apk/alpine/openssl@3.0.0")); len(fresh) != 1 {
		t.Fatalf("search for the current version = %+v, want the artifact", fresh)
	}
}

// An SBOM this service can't parse must not fail the upload:
// scanner.UploadDocument treats any non-200 as an error that lands in
// the artifact's LastScanErrors, so a rejection here would turn a
// perfectly good scan into a failed one AND discard a document that is
// itself fine.
func TestUploadSBOM_UnparseableDocumentStillStores(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/json", []byte(`{"not":"an sbom"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200 -- an unparseable SBOM is not a failed upload, body=%s", rec.Code, rec.Body.String())
	}

	doc, err := store.GetDocument(a.ID, artifact.DocumentKindSBOM)
	if err != nil || doc == nil {
		t.Fatalf("GetDocument = %v, %v -- the document itself should still be stored", doc, err)
	}
	got := decodeArtifact(t, doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+a.ID, nil))
	if !got.HasSBOM {
		t.Error("HasSBOM should be true -- the document was stored")
	}
}

// A SARIF upload goes through the same handler and must not be parsed
// as an SBOM.
func TestUploadSARIF_DoesNotIndexComponents(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sarif", "application/sarif+json", []byte(cycloneDXUpload)); rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if found := decodeArtifacts(t, componentSearch(t, h, "pkg:apk/alpine/openssl@3.1.4-r5")); len(found) != 0 {
		t.Fatalf("search = %+v, want no matches -- only sbom documents carry a component inventory", found)
	}
}

func TestComponentSearch_RequiresAPurlOrQuery(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	for _, path := range []string{"/api/v1/components", "/api/v1/components?purl=", "/api/v1/components?q="} {
		rec := doJSON(t, h, http.MethodGet, path, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s = %d, want 400, body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

type packageSearchResponse struct {
	Total    int                       `json:"total"`
	Packages []artifact.ComponentMatch `json:"packages"`
}

func packageSearch(t *testing.T, h http.Handler, q string) packageSearchResponse {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/v1/components?q="+url.QueryEscape(q), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("q=%q status = %d, want 200, body=%s", q, rec.Code, rec.Body.String())
	}
	var out packageSearchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode package search: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// The two-stage flow this endpoint exists for: nobody knows they want
// "pkg:apk/alpine/openssl@3.1.4-r5" -- they know "openssl". So a
// substring finds the packages that exist, and the purl picked from
// that goes back through the exact query.
func TestComponentSearch_DiscoverByNameThenNarrowToOnePurl(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	alpine := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	slim := mustCreate(t, store, "alpine:3.19-slim", artifact.TypeImage)
	debian := mustCreate(t, store, "debian:12", artifact.TypeImage)

	const alpineSBOM = `{"bomFormat":"CycloneDX","components":[
	  {"name":"openssl","version":"3.1.4-r5","purl":"pkg:apk/alpine/openssl@3.1.4-r5"},
	  {"name":"busybox","version":"1.36.1-r15","purl":"pkg:apk/alpine/busybox@1.36.1-r15"}]}`
	const debianSBOM = `{"bomFormat":"CycloneDX","components":[
	  {"name":"openssl","version":"3.0.11-1","purl":"pkg:deb/debian/openssl@3.0.11-1"}]}`

	for _, up := range []struct {
		id, body string
	}{{alpine.ID, alpineSBOM}, {slim.ID, alpineSBOM}, {debian.ID, debianSBOM}} {
		if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+up.id+"/documents/sbom", "application/json", []byte(up.body)); rec.Code != http.StatusOK {
			t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	// Stage 1: the search a person actually types.
	found := packageSearch(t, h, "openssl")
	if found.Total != 2 || len(found.Packages) != 2 {
		t.Fatalf("packages = %+v (total %d), want the 2 distinct openssl purls -- not one entry per artifact", found.Packages, found.Total)
	}
	if found.Packages[0].PURL != "pkg:apk/alpine/openssl@3.1.4-r5" || found.Packages[0].Artifacts != 2 {
		t.Fatalf("packages[0] = %+v, want the alpine purl (2 artifacts) ranked first", found.Packages[0])
	}
	if found.Packages[1].Artifacts != 1 {
		t.Fatalf("packages[1] = %+v, want 1 artifact", found.Packages[1])
	}

	// Stage 2: narrowing to one of them is still the exact query, so the
	// debian openssl doesn't come along.
	narrowed := decodeArtifacts(t, componentSearch(t, h, found.Packages[0].PURL))
	if len(narrowed) != 2 {
		t.Fatalf("artifacts = %+v, want the 2 alpine images", narrowed)
	}
	for _, a := range narrowed {
		if a.ID == debian.ID {
			t.Fatalf("narrowing to the alpine purl returned the debian artifact -- the second stage must stay exact")
		}
	}
}

func TestComponentSearch_QueryMatchesPurlAndIsCaseInsensitive(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/json", []byte(cycloneDXUpload)); rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d", rec.Code)
	}

	// By ecosystem/namespace rather than package name -- the other way
	// people look ("what apk packages do we ship").
	if got := packageSearch(t, h, "pkg:apk/alpine/"); got.Total != 2 {
		t.Fatalf("q=pkg:apk/alpine/ total = %d, want both components", got.Total)
	}
	if got := packageSearch(t, h, "OPENSSL"); got.Total != 1 {
		t.Fatalf("q=OPENSSL total = %d, want 1 (case-insensitive)", got.Total)
	}
	if got := packageSearch(t, h, "nothing-like-this"); got.Total != 0 || len(got.Packages) != 0 {
		t.Fatalf("no-match search = %+v, want an empty list and total 0", got)
	}
}

// A caller sending both has already made its choice: purl is the more
// specific request and wins, rather than the answer depending on
// parameter order.
func TestComponentSearch_PurlWinsOverQuery(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/json", []byte(cycloneDXUpload)); rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d", rec.Code)
	}

	rec := doJSON(t, h, http.MethodGet,
		"/api/v1/components?purl="+url.QueryEscape("pkg:apk/alpine/openssl@3.1.4-r5")+"&q=busybox", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	// An artifact list (the purl answer), not a {total, packages} object.
	got := decodeArtifacts(t, rec)
	if len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("got %+v, want the exact-purl answer", got)
	}
}

// "Nothing ships this package" is a valid answer, not a 404 -- the same
// convention findByFindingID uses.
func TestComponentSearch_NoMatchesIsAnEmptyList(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := componentSearch(t, h, "pkg:apk/alpine/nothing@1.0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if found := decodeArtifacts(t, rec); len(found) != 0 {
		t.Fatalf("found = %+v, want an empty list", found)
	}
}

// A purl carries slashes, "@" and its own query string -- the reason
// this endpoint takes it as a query parameter rather than a path
// segment. Round-trip the qualifier form to prove nothing mangles it.
func TestComponentSearch_MatchesAPurlWithQualifiers(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	const qualified = "pkg:apk/alpine/apk-tools@2.14.4-r0?arch=x86_64&distro=3.19.9"
	body := `{"bomFormat":"CycloneDX","components":[{"name":"apk-tools","version":"2.14.4-r0","purl":"` + qualified + `"}]}`
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/documents/sbom", "application/json", []byte(body)); rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}

	if found := decodeArtifacts(t, componentSearch(t, h, qualified)); len(found) != 1 {
		t.Fatalf("search = %+v, want the artifact -- qualifiers must survive the round trip", found)
	}
	// Same package, no qualifiers: a different purl, and this endpoint
	// matches exactly.
	if found := decodeArtifacts(t, componentSearch(t, h, "pkg:apk/alpine/apk-tools@2.14.4-r0")); len(found) != 0 {
		t.Fatalf("search without qualifiers = %+v, want no matches (exact match, documented)", found)
	}
}
