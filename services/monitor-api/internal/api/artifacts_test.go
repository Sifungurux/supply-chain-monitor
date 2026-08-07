package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestCreateArtifact(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	t.Run("valid", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "alpine:3.19", "type": "image"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		a := decodeArtifact(t, rec)
		if a.ID == "" {
			t.Fatal("expected a generated id")
		}
		if a.Status != artifact.StatusRegistered {
			t.Fatalf("status = %q, want %q", a.Status, artifact.StatusRegistered)
		}
	})

	t.Run("missing ref", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"type": "image"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "x", "type": "binary"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestBulkCreateArtifacts_Success(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image"},
			{"ref": "/tmp/report.sarif", "type": "sarif"},
			{"ref": "ghcr.io/example/app:1.0", "type": "image"},
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
		Failed  int `json:"failed"`
		Results []struct {
			Ref      string `json:"ref"`
			Error    string `json:"error"`
			Artifact struct {
				ID string `json:"id"`
			} `json:"artifact"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if resp.Created != 3 || resp.Failed != 0 {
		t.Fatalf("created=%d failed=%d, want 3/0", resp.Created, resp.Failed)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("results len = %d, want 3", len(resp.Results))
	}
	for _, r := range resp.Results {
		if r.Artifact.ID == "" {
			t.Fatalf("expected an id for ref %q, got none (error=%q)", r.Ref, r.Error)
		}
	}

	// Confirm they actually landed in the store, not just echoed back.
	listRec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts", nil)
	var list []artifact.Artifact
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("store has %d artifacts, want 3", len(list))
	}
}

func TestBulkCreateArtifacts_PartialFailureStillCreatesTheGoodOnes(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image"},
			{"ref": "", "type": "image"},            // missing ref
			{"ref": "x", "type": "not-a-real-type"}, // invalid type
			{"ref": "busybox:latest", "type": "image"},
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	// At least one entry succeeded, so this is still 201, not 400 -- a
	// batch shouldn't read as an overall failure just because some
	// entries were bad (see bulkCreateArtifacts's own comment on this).
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 2 || resp.Failed != 2 {
		t.Fatalf("created=%d failed=%d, want 2/2", resp.Created, resp.Failed)
	}
}

func TestBulkCreateArtifacts_ExpectedDigestMismatchNotCreated(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{
		"alpine:3.19":    "sha256:aaa",
		"busybox:latest": "sha256:bbb",
	}}
	h, store := newTestRouterWithDigestResolver(resolver)

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:aaa"},      // matches -- should register
			{"ref": "busybox:latest", "type": "image", "expected_digest": "sha256:wrong"}, // mismatch -- must not register
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (one entry still succeeded), body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 1 || resp.Failed != 1 {
		t.Fatalf("created=%d failed=%d, want 1/1", resp.Created, resp.Failed)
	}

	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store has %d artifacts, want 1 -- the mismatched entry must not have registered", len(all))
	}
	if all[0].Ref != "alpine:3.19" {
		t.Fatalf("registered ref = %q, want alpine:3.19", all[0].Ref)
	}
}

// TestBulkCreateArtifacts_RequireDigest_MismatchRegistersUnsafeInsteadOfFailing
// is the bulk-endpoint counterpart to
// TestCreateArtifact_RequireDigest_MismatchStillRegistersButMarkedUnsafe:
// under REQUIRE_DIGEST, a per-entry mismatch is created (Unsafe=true),
// not counted in Failed the way it is without the flag (compare
// TestBulkCreateArtifacts_ExpectedDigestMismatchNotCreated above).

func TestBulkCreateArtifacts_RequireDigest_MismatchRegistersUnsafeInsteadOfFailing(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{
		"alpine:3.19":    "sha256:aaa",
		"busybox:latest": "sha256:actual",
	}}
	h, store := newTestRouterWithRequireDigest(resolver)

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:aaa"},        // matches -- safe
			{"ref": "busybox:latest", "type": "image", "expected_digest": "sha256:claimed"}, // mismatch -- unsafe, still created
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
		Failed  int `json:"failed"`
		Results []struct {
			Ref      string `json:"ref"`
			Artifact *struct {
				Unsafe bool   `json:"unsafe"`
				Digest string `json:"digest"`
			} `json:"artifact"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 2 || resp.Failed != 0 {
		t.Fatalf("created=%d failed=%d, want 2/0 -- a mismatch under REQUIRE_DIGEST registers, it doesn't fail", resp.Created, resp.Failed)
	}

	all, _ := store.List()
	if len(all) != 2 {
		t.Fatalf("store has %d artifacts, want 2", len(all))
	}
	for _, r := range resp.Results {
		if r.Artifact == nil {
			t.Fatalf("entry %q: no artifact in result", r.Ref)
		}
		wantUnsafe := r.Ref == "busybox:latest"
		if r.Artifact.Unsafe != wantUnsafe {
			t.Fatalf("entry %q: Unsafe = %v, want %v", r.Ref, r.Artifact.Unsafe, wantUnsafe)
		}
	}
}

// TestBulkCreateArtifacts_RequireDigest_MissingExpectedDigestFailsThatEntryOnly
// mirrors TestCreateArtifact_RequireDigest_MissingExpectedDigestRejected,
// but per-entry: one bad entry (no expected_digest) must not block a
// well-formed sibling entry in the same batch.

func TestBulkCreateArtifacts_RequireDigest_MissingExpectedDigestFailsThatEntryOnly(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa"}}
	h, store := newTestRouterWithRequireDigest(resolver)

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:aaa"}, // has it -- should register
			{"ref": "busybox:latest", "type": "image"},                               // missing it -- should fail
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (one entry still succeeded), body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 1 || resp.Failed != 1 {
		t.Fatalf("created=%d failed=%d, want 1/1", resp.Created, resp.Failed)
	}
	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store has %d artifacts, want 1", len(all))
	}
}

func TestBulkCreateArtifacts_AllInvalidReturns400(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "", "type": "image"},
			{"ref": "x", "type": "not-a-real-type"},
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (nothing was actually created), body=%s", rec.Code, rec.Body.String())
	}
}

func TestBulkCreateArtifacts_EmptyArrayRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{"artifacts": []map[string]string{}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an empty artifacts array", rec.Code)
	}
}

func TestBulkCreateArtifacts_TooManyRejected(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	items := make([]map[string]string, 501)
	for i := range items {
		items[i] = map[string]string{"ref": "alpine:3.19", "type": "image"}
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{"artifacts": items})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a batch over the cap", rec.Code)
	}
}

func TestCreateArtifact_DuplicateDigestReturns409(t *testing.T) {
	// Both refs resolve to the same digest -- simulating two tags of the
	// same underlying image -- since dedup has to be keyed on digest, not
	// on the literal ref string being repeated.
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa", "alpine:latest": "sha256:aaa"}}
	h, _ := newTestRouterWithDigestResolver(resolver)

	first := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "alpine:3.19", "type": "image"})
	if first.Code != http.StatusCreated {
		t.Fatalf("first registration status = %d, want 201, body=%s", first.Code, first.Body.String())
	}
	firstArtifact := decodeArtifact(t, first)
	if firstArtifact.Digest != "sha256:aaa" {
		t.Fatalf("digest = %q, want sha256:aaa", firstArtifact.Digest)
	}

	// Same digest, different ref (e.g. a different tag of the same
	// image) -- still a duplicate, since dedup is keyed on digest, not
	// the literal ref string.
	second := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "alpine:latest", "type": "image"})
	if second.Code != http.StatusConflict {
		t.Fatalf("second registration status = %d, want 409, body=%s", second.Code, second.Body.String())
	}
	var body struct {
		ExistingArtifactID string `json:"existing_artifact_id"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if body.ExistingArtifactID != firstArtifact.ID {
		t.Fatalf("existing_artifact_id = %q, want %q", body.ExistingArtifactID, firstArtifact.ID)
	}
}

func TestCreateArtifact_DigestResolutionFailureStillSucceeds(t *testing.T) {
	// Best-effort: a registry that's unreachable/rate-limited/whatever
	// must never block registration -- it just means no dedup for this
	// one entry, the same as if digestResolver weren't configured.
	resolver := &fakeDigestResolver{errRef: "unreachable-registry.example/app:1.0"}
	h, _ := newTestRouterWithDigestResolver(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "unreachable-registry.example/app:1.0", "type": "image"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 even though digest resolution failed, body=%s", rec.Code, rec.Body.String())
	}
	a := decodeArtifact(t, rec)
	if a.Digest != "" {
		t.Fatalf("digest = %q, want empty (resolution failed)", a.Digest)
	}
}

func TestCreateArtifact_ExpectedDigestMatchRegisters(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa"}}
	h, store := newTestRouterWithDigestResolver(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:aaa",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 when resolved digest matches expected, body=%s", rec.Code, rec.Body.String())
	}
	a := decodeArtifact(t, rec)
	if a.Digest != "sha256:aaa" {
		t.Fatalf("digest = %q, want sha256:aaa", a.Digest)
	}
	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store has %d artifacts, want 1", len(all))
	}
}

func TestCreateArtifact_ExpectedDigestMismatchRefusesRegistration(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa"}}
	h, store := newTestRouterWithDigestResolver(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:different",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 on digest mismatch, body=%s", rec.Code, rec.Body.String())
	}
	all, _ := store.List()
	if len(all) != 0 {
		t.Fatalf("store has %d artifacts, want 0 -- mismatched registration must not register anything", len(all))
	}
}

func TestCreateArtifact_ExpectedDigestSetButUnresolvableRefusesRegistration(t *testing.T) {
	// No digest available at all (resolution failed) with an expected
	// digest pinned: fails closed rather than registering unverified.
	resolver := &fakeDigestResolver{errRef: "unreachable-registry.example/app:1.0"}
	h, store := newTestRouterWithDigestResolver(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "unreachable-registry.example/app:1.0", "type": "image", "expected_digest": "sha256:aaa",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 when digest can't be resolved to verify against, body=%s", rec.Code, rec.Body.String())
	}
	all, _ := store.List()
	if len(all) != 0 {
		t.Fatalf("store has %d artifacts, want 0", len(all))
	}
}

// TestCreateArtifact_RequireDigest_MissingExpectedDigestRejected: with
// REQUIRE_DIGEST on, expected_digest stops being optional -- a request
// that omits it is a 400, before any registry call is even attempted.

func TestCreateArtifact_RequireDigest_MissingExpectedDigestRejected(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa"}}
	h, store := newTestRouterWithRequireDigest(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (expected_digest required when REQUIRE_DIGEST is on), body=%s", rec.Code, rec.Body.String())
	}
	all, _ := store.List()
	if len(all) != 0 {
		t.Fatalf("store has %d artifacts, want 0", len(all))
	}
}

// TestCreateArtifact_RequireDigest_MatchRegistersSafely: the happy path
// under REQUIRE_DIGEST -- a correct expected_digest registers exactly
// like today, just with Unsafe left false.

func TestCreateArtifact_RequireDigest_MatchRegistersSafely(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa"}}
	h, _ := newTestRouterWithRequireDigest(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:aaa",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.Unsafe {
		t.Fatalf("Unsafe = true, want false -- the expected digest matched")
	}
	if got.Digest != "sha256:aaa" {
		t.Fatalf("digest = %q, want %q", got.Digest, "sha256:aaa")
	}
}

// TestCreateArtifact_RequireDigest_MismatchStillRegistersButMarkedUnsafe
// is the core behavior this feature exists for: unlike the pre-existing,
// opt-in expected_digest pin (409, nothing registered -- see
// TestCreateArtifact_ExpectedDigestMismatchRefusesRegistration just
// above), REQUIRE_DIGEST is a deployment-wide policy that still
// registers the artifact on a mismatch, just marked Unsafe.

func TestCreateArtifact_RequireDigest_MismatchStillRegistersButMarkedUnsafe(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:actual"}}
	h, store := newTestRouterWithRequireDigest(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image", "expected_digest": "sha256:claimed",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (registered, not refused), body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if !got.Unsafe {
		t.Fatalf("Unsafe = false, want true -- resolved digest didn't match expected_digest")
	}
	if got.Digest != "sha256:actual" {
		t.Fatalf("digest = %q, want the real resolved value %q (not the caller's mismatched claim)", got.Digest, "sha256:actual")
	}
	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store has %d artifacts, want 1 -- REQUIRE_DIGEST must not refuse a mismatched registration", len(all))
	}
}

// TestCreateArtifact_RequireDigest_UnresolvableStillRegistersButMarkedUnsafe
// covers the other unsafe path: no digest resolves at all (registry
// unreachable), yet expected_digest was required and provided.

func TestCreateArtifact_RequireDigest_UnresolvableStillRegistersButMarkedUnsafe(t *testing.T) {
	resolver := &fakeDigestResolver{errRef: "unreachable-registry.example/app:1.0"}
	h, store := newTestRouterWithRequireDigest(resolver)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "unreachable-registry.example/app:1.0", "type": "image", "expected_digest": "sha256:aaa",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (registered, not refused), body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if !got.Unsafe {
		t.Fatalf("Unsafe = false, want true -- nothing resolved to verify expected_digest against")
	}
	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store has %d artifacts, want 1", len(all))
	}
}

func TestCreateArtifact_MaintainerTeamAndEmailPersisted(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image",
		"maintainer_team": "platform-security", "maintainer_email": "platform-security@example.com",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	a := decodeArtifact(t, rec)
	if a.MaintainerTeam != "platform-security" || a.MaintainerEmail != "platform-security@example.com" {
		t.Fatalf("maintainer = %q/%q, want platform-security/platform-security@example.com", a.MaintainerTeam, a.MaintainerEmail)
	}
}

func TestCreateArtifact_MaintainerOneFieldWithoutTheOtherRejected(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image", "maintainer_team": "platform-security",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when only maintainer_team is set, body=%s", rec.Code, rec.Body.String())
	}
	all, _ := store.List()
	if len(all) != 0 {
		t.Fatalf("store has %d artifacts, want 0", len(all))
	}

	rec2 := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{
		"ref": "alpine:3.19", "type": "image", "maintainer_email": "platform-security@example.com",
	})
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when only maintainer_email is set, body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestBulkCreateArtifacts_MaintainerPersistedAndOneFieldRejected(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image", "maintainer_team": "platform-security", "maintainer_email": "platform-security@example.com"},
			{"ref": "busybox:latest", "type": "image", "maintainer_team": "orphaned-team"}, // email missing -- must be rejected
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (one entry still succeeded), body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Created int `json:"created"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 1 || resp.Failed != 1 {
		t.Fatalf("created=%d failed=%d, want 1/1", resp.Created, resp.Failed)
	}

	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store has %d artifacts, want 1", len(all))
	}
	if all[0].MaintainerTeam != "platform-security" || all[0].MaintainerEmail != "platform-security@example.com" {
		t.Fatalf("maintainer = %q/%q, want platform-security/platform-security@example.com", all[0].MaintainerTeam, all[0].MaintainerEmail)
	}
}

func TestBulkCreateArtifacts_DuplicatesAcrossRequestsMarkedNotFailed(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa", "busybox:latest": "sha256:bbb"}}
	h, _ := newTestRouterWithDigestResolver(resolver)

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image"},
			{"ref": "busybox:latest", "type": "image"},
		},
	}
	first := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first bulk status = %d, want 201, body=%s", first.Code, first.Body.String())
	}

	// Re-submit the exact same batch, as cluster/load-test-clamav.sh
	// does on every run -- this must NOT come back as 400/all-failed.
	second := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if second.Code != http.StatusCreated {
		t.Fatalf("second (duplicate) bulk status = %d, want 201, body=%s", second.Code, second.Body.String())
	}
	var resp struct {
		Created    int `json:"created"`
		Failed     int `json:"failed"`
		Duplicates int `json:"duplicates"`
		Results    []struct {
			Duplicate bool `json:"duplicate"`
			Artifact  struct {
				ID string `json:"id"`
			} `json:"artifact"`
		} `json:"results"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, second.Body.String())
	}
	if resp.Created != 0 || resp.Failed != 0 || resp.Duplicates != 2 {
		t.Fatalf("created=%d failed=%d duplicates=%d, want 0/0/2", resp.Created, resp.Failed, resp.Duplicates)
	}
	for _, r := range resp.Results {
		if !r.Duplicate {
			t.Fatal("expected every result marked duplicate")
		}
		// Still get a usable id back -- a caller that only wants ids to
		// scan against (the load-test script) keeps working unchanged.
		if r.Artifact.ID == "" {
			t.Fatal("expected the existing artifact's id even for a duplicate result")
		}
	}
}

func TestBulkCreateArtifacts_DuplicateWithinSameBatchMarkedNotFailed(t *testing.T) {
	resolver := &fakeDigestResolver{digests: map[string]string{"alpine:3.19": "sha256:aaa", "alpine:latest": "sha256:aaa"}}
	h, _ := newTestRouterWithDigestResolver(resolver)

	body := map[string]any{
		"artifacts": []map[string]string{
			{"ref": "alpine:3.19", "type": "image"},
			{"ref": "alpine:latest", "type": "image"}, // same digest, different tag, same request
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Created    int `json:"created"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 1 || resp.Duplicates != 1 {
		t.Fatalf("created=%d duplicates=%d, want 1/1", resp.Created, resp.Duplicates)
	}
}

func TestListAndGetArtifact(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodGet, "/api/v1/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var list []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}

	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec = doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := decodeArtifact(t, rec)
	if got.ID != created.ID {
		t.Fatalf("id = %q, want %q", got.ID, created.ID)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/artifacts/does-not-exist", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestDeleteArtifact_Success confirms a successful delete: 200 with a
// small confirmation body, the artifact then 404s on Get, and it's
// gone from List too -- not just "the row still exists but is
// hidden," an actual removal.

func TestDeleteArtifact_Success(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodDelete, "/api/v1/artifacts/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "deleted" || body["id"] != created.ID {
		t.Fatalf("response body = %+v, want status=deleted and id=%q", body, created.ID)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/artifacts/"+created.ID, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("Get after delete: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/artifacts", nil)
	var list []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	for _, a := range list {
		if a.ID == created.ID {
			t.Fatalf("List after delete still includes the deleted artifact: %+v", a)
		}
	}
}

// TestDeleteArtifact_MissingIDReturns404 matches getArtifact's own
// convention for an unknown id -- a DELETE on something that was never
// there (or already deleted) is a 404, not a successful no-op.

func TestDeleteArtifact_MissingIDReturns404(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodDelete, "/api/v1/artifacts/does-not-exist", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestDeleteArtifact_DeletingTwiceReturns404TheSecondTime guards
// against a regression where Delete might treat "already gone" as
// success on a second call (some DELETE APIs are deliberately
// idempotent that way -- this one isn't, matching every other
// id-scoped endpoint's 404-on-unknown-id behavior).

func TestDeleteArtifact_DeletingTwiceReturns404TheSecondTime(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodDelete, "/api/v1/artifacts/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first delete: status = %d, want 200", rec.Code)
	}

	rec = doJSON(t, h, http.MethodDelete, "/api/v1/artifacts/"+created.ID, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: status = %d, want 404", rec.Code)
	}
}

// TestFindByFindingID exercises the endpoint that exists specifically
// because findings live in their own table now (see
// docs/architecture.md, "Normalizing findings and stage history into
// their own tables") -- MemStore's FindByFindingID is a linear scan,
// PostgresStore's is an indexed query, but findings.go doesn't know or
// care which Store it's talking to.
