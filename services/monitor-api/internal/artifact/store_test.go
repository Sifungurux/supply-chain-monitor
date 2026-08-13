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

func TestMemStore_FindByDigest(t *testing.T) {
	s := artifact.NewMemStore()

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create("debian:12", artifact.TypeImage); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Not found yet -- digest hasn't been set on anything.
	none, err := s.FindByDigest("sha256:aaa")
	if err != nil {
		t.Fatalf("FindByDigest: %v", err)
	}
	if none != nil {
		t.Fatalf("expected no match before any digest is set, got %+v", none)
	}

	if _, err := s.Update(a.ID, func(art *artifact.Artifact) { art.Digest = "sha256:aaa" }); err != nil {
		t.Fatalf("Update: %v", err)
	}

	match, err := s.FindByDigest("sha256:aaa")
	if err != nil {
		t.Fatalf("FindByDigest: %v", err)
	}
	if match == nil || match.ID != a.ID {
		t.Fatalf("match = %+v, want %q", match, a.ID)
	}

	// Empty digest is never a valid search key -- it means "no digest
	// resolved," not a wildcard, so it must never match.
	if got, err := s.FindByDigest(""); err != nil || got != nil {
		t.Fatalf("FindByDigest(\"\") = %+v, %v, want nil, nil", got, err)
	}
}

func TestMemStore_Delete(t *testing.T) {
	s := artifact.NewMemStore()

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Get(a.ID); err == nil {
		t.Fatal("expected Get to fail for a deleted artifact")
	}

	if list, err := s.List(); err != nil || len(list) != 0 {
		t.Fatalf("expected an empty store after delete, got %d (err=%v)", len(list), err)
	}

	if err := s.Delete("does-not-exist"); err == nil {
		t.Fatal("expected an error deleting a missing id")
	}

	if err := s.Delete(a.ID); err == nil {
		t.Fatal("expected an error deleting the same id twice")
	}
}

func TestMemStore_FindByComponentPURL(t *testing.T) {
	s := artifact.NewMemStore()

	const openssl = "pkg:apk/alpine/openssl@3.1.4-r5"
	alpine, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	debian, err := s.Create("debian:12", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.SaveComponents(alpine.ID, []artifact.Component{
		{PURL: openssl, Name: "openssl", Version: "3.1.4-r5"},
		{PURL: "pkg:apk/alpine/busybox@1.36.1-r15", Name: "busybox", Version: "1.36.1-r15"},
	}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}
	if err := s.SaveComponents(debian.ID, []artifact.Component{
		{PURL: "pkg:deb/debian/openssl@3.0.11-1", Name: "openssl", Version: "3.0.11-1"},
	}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}

	matches, err := s.FindByComponentPURL(openssl)
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != alpine.ID {
		t.Fatalf("matches = %+v, want just %q -- debian's openssl is a different purl", matches, alpine.ID)
	}

	if none, err := s.FindByComponentPURL("pkg:apk/alpine/nothing@1.0"); err != nil || len(none) != 0 {
		t.Fatalf("FindByComponentPURL(unknown) = %+v, %v, want no matches", none, err)
	}
	// An empty purl is not a wildcard -- same convention FindByDigest
	// uses for an empty digest.
	if none, err := s.FindByComponentPURL(""); err != nil || len(none) != 0 {
		t.Fatalf(`FindByComponentPURL("") = %+v, %v, want no matches`, none, err)
	}

	if err := s.SaveComponents("does-not-exist", nil); err == nil {
		t.Fatal("expected an error saving components against a missing artifact")
	}
}

// A re-uploaded SBOM REPLACES the inventory, it doesn't add to it --
// SaveDocument already overwrites the document itself, so appending
// here would keep answering queries for a package a rebuild removed.
func TestMemStore_SaveComponentsReplaces(t *testing.T) {
	s := artifact.NewMemStore()

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const old = "pkg:apk/alpine/openssl@1.1.1"
	const updated = "pkg:apk/alpine/openssl@3.0.0"
	if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: old, Name: "openssl", Version: "1.1.1"}}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}
	if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: updated, Name: "openssl", Version: "3.0.0"}}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}

	if stale, err := s.FindByComponentPURL(old); err != nil || len(stale) != 0 {
		t.Fatalf("FindByComponentPURL(%q) = %+v, %v -- the previous SBOM's components must not survive a re-upload", old, stale, err)
	}
	if fresh, err := s.FindByComponentPURL(updated); err != nil || len(fresh) != 1 {
		t.Fatalf("FindByComponentPURL(%q) = %+v, %v, want the artifact", updated, fresh, err)
	}
}

// Components are keyed to an artifact that no longer exists once it's
// deleted -- MemStore has to drop them the way PostgresStore's
// ON DELETE CASCADE does, or a purl query answers with a ghost.
func TestMemStore_DeleteDropsComponents(t *testing.T) {
	s := artifact.NewMemStore()

	const purl = "pkg:apk/alpine/openssl@3.1.4-r5"
	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: purl, Name: "openssl"}}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}
	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if ghosts, err := s.FindByComponentPURL(purl); err != nil || len(ghosts) != 0 {
		t.Fatalf("FindByComponentPURL after delete = %+v, %v, want nothing", ghosts, err)
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
