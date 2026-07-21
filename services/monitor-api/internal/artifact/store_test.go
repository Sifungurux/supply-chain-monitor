package artifact_test

import (
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

func TestStoreCreateGetListUpdate(t *testing.T) {
	s := artifact.NewMemStore()

	if got, err := s.List(); err != nil || len(got) != 0 {
		t.Fatalf("expected empty store, got %d (err=%v)", len(got), err)
	}

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.ID == "" {
		t.Fatal("expected a generated id")
	}
	if a.Status != artifact.StatusRegistered {
		t.Fatalf("status = %q, want %q", a.Status, artifact.StatusRegistered)
	}

	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Ref != "alpine:3.19" {
		t.Fatalf("ref = %q, want %q", got.Ref, "alpine:3.19")
	}

	if _, err := s.Get("does-not-exist"); err == nil {
		t.Fatal("expected an error for a missing id")
	}

	updated, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.Status = artifact.StatusScanned
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Status != artifact.StatusScanned {
		t.Fatalf("status after update = %q, want %q", updated.Status, artifact.StatusScanned)
	}
	if updated.UpdatedAt.Before(updated.CreatedAt) {
		t.Fatalf("expected UpdatedAt (%v) >= CreatedAt (%v)", updated.UpdatedAt, updated.CreatedAt)
	}

	if list, err := s.List(); err != nil || len(list) != 1 {
		t.Fatalf("expected 1 artifact in store, got %d (err=%v)", len(list), err)
	}

	if _, err := s.Update("does-not-exist", func(*artifact.Artifact) {}); err == nil {
		t.Fatal("expected an error updating a missing id")
	}
}

func TestMemStore_FindByFindingID(t *testing.T) {
	s := artifact.NewMemStore()

	affected, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create("debian:12", artifact.TypeImage); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.Update(affected.ID, func(a *artifact.Artifact) {
		a.CVEFindings = append(a.CVEFindings, artifact.Finding{ID: "CVE-2024-1234", Source: "trivy"})
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	matches, err := s.FindByFindingID("CVE-2024-1234")
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != affected.ID {
		t.Fatalf("matches = %+v, want just %q", matches, affected.ID)
	}

	none, err := s.FindByFindingID("CVE-does-not-exist")
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no matches, got %+v", none)
	}
}

func TestTypeValid(t *testing.T) {
	valid := []artifact.Type{artifact.TypeImage, artifact.TypeFile, artifact.TypeSBOM, artifact.TypeSARIF}
	for _, ty := range valid {
		if !ty.Valid() {
			t.Errorf("%q should be valid", ty)
		}
	}
	if artifact.Type("binary").Valid() {
		t.Error(`"binary" should not be a valid type`)
	}
}
