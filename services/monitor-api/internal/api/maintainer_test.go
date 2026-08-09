package api_test

import (
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestUpdateMaintainer(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/maintainer", map[string]string{
		"team": "platform-security", "email": "platform-security@example.com",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	updated := decodeArtifact(t, rec)
	if updated.MaintainerTeam != "platform-security" || updated.MaintainerEmail != "platform-security@example.com" {
		t.Fatalf("maintainer = %q/%q, want platform-security/platform-security@example.com", updated.MaintainerTeam, updated.MaintainerEmail)
	}

	// A follow-up call with only one field must be rejected (not clear
	// the other one out from under it).
	rec2 := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/maintainer", map[string]string{"team": "new-team"})
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when email is missing, body=%s", rec2.Code, rec2.Body.String())
	}

	rec3 := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/maintainer", map[string]string{
		"team": "x", "email": "x@example.com",
	})
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a nonexistent artifact, body=%s", rec3.Code, rec3.Body.String())
	}
}
