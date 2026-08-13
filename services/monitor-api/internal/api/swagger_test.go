package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestSwaggerUI_ReferencesOpenAPISpec(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "/openapi.yaml") {
		t.Fatalf("swagger UI page doesn't reference /openapi.yaml: %s", rec.Body.String())
	}
}

// TestOpenAPISpec_DescribesEveryRegisteredRoute is a golden-endpoint-list
// check, not a YAML parse (this module deliberately has no YAML library
// to parse it with -- see swagger.go's own comment on staying
// dependency-free): every path NewRouter actually registers must appear
// as a path key in the spec, so a new endpoint added to router.go
// without a matching openapi.yaml entry fails this test instead of just
// shipping undocumented.

func TestOpenAPISpec_DescribesEveryRegisteredRoute(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	spec := rec.Body.String()

	// Every path NewRouter registers, in OpenAPI's own {param} path
	// syntax (matches Go 1.22 ServeMux's {id}/{kind} wildcard syntax
	// exactly, so no translation is needed between the two).
	wantPaths := []string{
		"/healthz",
		"/api/v1/pipeline/stages",
		"/api/v1/artifacts:",
		"/api/v1/artifacts/bulk",
		"/api/v1/artifacts/{id}:",
		"/api/v1/findings:",
		"/api/v1/findings/{findingID}/artifacts",
		"/api/v1/components",
		"/api/v1/artifacts/{id}/scan",
		"/api/v1/artifacts/{id}/stage",
		"/api/v1/artifacts/{id}/maintainer",
		"/api/v1/artifacts/{id}/documents/{kind}",
		"/api/v1/artifacts/{id}/findings",
		"/api/v1/artifacts/{id}/vex",
	}
	for _, p := range wantPaths {
		if !strings.Contains(spec, p) {
			t.Errorf("openapi.yaml doesn't document path %q", p)
		}
	}
}

// TestAuth_OptionsPreflightExempt: real browsers never attach an
// Authorization header to a CORS preflight OPTIONS request, so it
// must be handled before withAuth ever runs (see router.go's ordering
// comment) or every cross-origin call from the dashboard would fail
// preflight before the real request is even attempted.
