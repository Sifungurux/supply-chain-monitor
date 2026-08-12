package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func newCappedRouter(t *testing.T, max int) (http.Handler, *artifact.MemStore) {
	t.Helper()
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(store, tracker, scanner.Registry{}, testAPIKey, 0, 0, nil, false, 0, false,
		api.ScanLimits{}, api.Notifications{},
		api.RegistrationLimits{MaxArtifacts: max}), store
}

// A quota is not a rate limit: 403, not 429. Retrying cannot help --
// only deleting artifacts can -- so a Retry-After would tell the caller
// to do the one thing that does not work.
func TestCreateArtifact_RefusedAtTheArtifactLimit(t *testing.T) {
	h, store := newCappedRouter(t, 2)

	for i, ref := range []string{"a:1", "b:1"} {
		if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": ref, "type": "image"}); rec.Code != http.StatusCreated {
			t.Fatalf("registration %d = %d, want 201", i+1, rec.Code)
		}
	}

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "c:1", "type": "image"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["max_artifacts"] != float64(2) {
		t.Fatalf("response should report the limit, got %v", body)
	}
	all, _ := store.List()
	if len(all) != 2 {
		t.Fatalf("store holds %d artifacts, want 2 -- the refused registration must not have created one", len(all))
	}
}

// Deleting frees quota again: the cap is on what exists, not on how
// many registrations have ever been attempted.
func TestCreateArtifact_DeletingFreesQuota(t *testing.T) {
	h, store := newCappedRouter(t, 1)

	first := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "a:1", "type": "image"})
	if first.Code != http.StatusCreated {
		t.Fatalf("first = %d, want 201", first.Code)
	}
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "b:1", "type": "image"}); rec.Code != http.StatusForbidden {
		t.Fatalf("second = %d, want 403", rec.Code)
	}

	created := decodeArtifact(t, first)
	if rec := doJSON(t, h, http.MethodDelete, "/api/v1/artifacts/"+created.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200", rec.Code)
	}
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "b:1", "type": "image"}); rec.Code != http.StatusCreated {
		t.Fatalf("after delete = %d, want 201 -- freed quota must be reusable", rec.Code)
	}
	all, _ := store.List()
	if len(all) != 1 {
		t.Fatalf("store holds %d artifacts, want 1", len(all))
	}
}

// Bulk fills to the cap and reports the rest per entry, matching this
// endpoint's existing best-effort shape rather than failing the whole
// batch.
func TestBulkCreateArtifacts_FillsToTheLimitThenReportsPerEntry(t *testing.T) {
	h, store := newCappedRouter(t, 3)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{
		"artifacts": []map[string]string{
			{"ref": "a:1", "type": "image"},
			{"ref": "b:1", "type": "image"},
			{"ref": "c:1", "type": "image"},
			{"ref": "d:1", "type": "image"},
			{"ref": "e:1", "type": "image"},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (three entries did register)", rec.Code)
	}
	var resp struct {
		Created, Failed, Duplicates int
		Results                     []struct{ Error string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 3 || resp.Failed != 2 {
		t.Fatalf("created=%d failed=%d, want 3/2", resp.Created, resp.Failed)
	}
	if resp.Results[4].Error == "" || resp.Results[3].Error == "" {
		t.Fatalf("the refused entries should say why: %+v", resp.Results)
	}
	all, _ := store.List()
	if len(all) != 3 {
		t.Fatalf("store holds %d artifacts, want exactly the cap (3)", len(all))
	}
}

// Duplicates create nothing, so they must not consume quota -- otherwise
// re-submitting the same batch (which cluster/load-test-clamav.sh does
// every run) would eat the limit without registering anything.
func TestBulkCreateArtifacts_DuplicatesDoNotConsumeQuota(t *testing.T) {
	h, store := newCappedRouter(t, 2)
	batch := map[string]any{"artifacts": []map[string]string{
		{"ref": "a:1", "type": "image"},
		{"ref": "b:1", "type": "image"},
	}}

	for i := 0; i < 4; i++ {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", batch)
		if rec.Code != http.StatusCreated {
			t.Fatalf("submission %d = %d, want 201", i+1, rec.Code)
		}
		var resp struct{ Created, Failed, Duplicates int }
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if i > 0 && (resp.Created != 0 || resp.Duplicates != 2 || resp.Failed != 0) {
			t.Fatalf("re-submission %d: created=%d duplicates=%d failed=%d, want 0/2/0", i, resp.Created, resp.Duplicates, resp.Failed)
		}
	}
	all, _ := store.List()
	if len(all) != 2 {
		t.Fatalf("store holds %d artifacts after 4 submissions, want 2", len(all))
	}
}

// The zero value is unlimited -- every other test in this package passes
// RegistrationLimits{} and must be unaffected.
func TestRegistrationLimits_ZeroValueIsUnlimited(t *testing.T) {
	h, store := newCappedRouter(t, 0)
	for i := 0; i < 25; i++ {
		ref := "img:" + string(rune('a'+i))
		if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": ref, "type": "image"}); rec.Code != http.StatusCreated {
			t.Fatalf("registration %d = %d, want 201 with no cap configured", i+1, rec.Code)
		}
	}
	all, _ := store.List()
	if len(all) != 25 {
		t.Fatalf("store holds %d artifacts, want 25", len(all))
	}
}
