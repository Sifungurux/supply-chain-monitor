package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestListStages(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})
	rec := doJSON(t, h, http.MethodGet, "/api/v1/pipeline/stages", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Stages []string `json:"stages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Stages) != 7 {
		t.Fatalf("stages = %v, want 7 entries", body.Stages)
	}
}

func TestUpdateStage(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/stage", map[string]string{"stage": "build", "note": "CI job #1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if got.CurrentStage != "build" {
		t.Fatalf("current_stage = %q, want %q", got.CurrentStage, "build")
	}
	if len(got.StageHistory) != 1 || got.StageHistory[0].Note != "CI job #1" {
		t.Fatalf("stage_history = %+v", got.StageHistory)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/stage", map[string]string{"stage": "not-a-real-stage"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown stage", rec.Code)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/stage", map[string]string{"stage": "build"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestSubmitFindings covers the happy path an external pipeline (its
// own malware scanner, its own SAST tool) would actually take: a
// freshly-registered artifact that never went through scanArtifact at
// all, submitting findings directly into one bucket.
