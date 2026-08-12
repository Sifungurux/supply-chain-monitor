package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Both registration endpoints enforce the same rule, so both are
// asserted in ONE function: the last time a rule lived in two handlers
// with a test for only one of them (the artifact quota), the two
// silently drifted and every test still passed. If a third registration
// path ever appears, it belongs in this loop too.
//
// The resolver call count is the load-bearing assertion. A 400 alone
// would also be produced by validating AFTER digest resolution -- by
// which point `oras` has already made the outbound request this exists
// to prevent. Zero calls is what proves the ordering.
func TestRegistration_RefusesRefsPointingInward(t *testing.T) {
	// Explicitly empty: this must not pass or fail based on whatever
	// REF_HOST_ALLOWLIST happens to be exported in a developer's shell.
	t.Setenv("REF_HOST_ALLOWLIST", "")

	for _, tc := range []struct{ name, ref string }{
		{"cloud metadata IP", "169.254.169.254/latest/meta-data:1"},
		{"in-cluster service", "scm-registry.supply-chain-monitor.svc.cluster.local:5000/sboms/app:1.0"},
		{"RFC1918 address", "10.0.0.5:5000/app:1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fakeDigestResolver{}
			h, store := newTestRouterWithDigestResolver(resolver)

			rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": tc.ref, "type": "image"})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST /artifacts = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}

			// The bulk endpoint reports per entry rather than failing the
			// whole request -- but with this as the only entry, nothing
			// registered, so the request as a whole is a 400 too.
			rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{
				"artifacts": []map[string]string{{"ref": tc.ref, "type": "image"}},
			})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST /artifacts/bulk = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Failed  int `json:"failed"`
				Results []struct {
					Error string `json:"error"`
				} `json:"results"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode bulk response: %v", err)
			}
			if resp.Failed != 1 || len(resp.Results) != 1 || resp.Results[0].Error == "" {
				t.Fatalf("bulk should report the refused entry, got %s", rec.Body.String())
			}

			if n := resolver.calls.Load(); n != 0 {
				t.Fatalf("digest resolution ran %d time(s) for a refused ref -- validation must come BEFORE the first outbound request, on both endpoints", n)
			}
			if all, _ := store.List(); len(all) != 0 {
				t.Fatalf("store holds %d artifacts, want 0 -- a refused ref must never register", len(all))
			}
		})
	}
}

// The guard is not allowed to cost the normal path anything: an
// ordinary public registry ref still registers, and still gets its
// digest resolved.
func TestRegistration_OrdinaryRefStillRegisters(t *testing.T) {
	t.Setenv("REF_HOST_ALLOWLIST", "")
	resolver := &fakeDigestResolver{digests: map[string]string{"ghcr.io/example/app:1.0": "sha256:abc"}}
	h, _ := newTestRouterWithDigestResolver(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "ghcr.io/example/app:1.0", "type": "image"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Digest != "sha256:abc" {
		t.Fatalf("digest = %q, want the resolved digest -- validation must not short-circuit resolution", got.Digest)
	}
}
