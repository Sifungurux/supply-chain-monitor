package artifact_test

import (
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
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
// The discovery half: a human types "openssl", not a purl with
// qualifiers. Every assertion here has a mirror in the Postgres
// integration test, since the two implementations have to agree on
// exactly what the picker shows.
func TestMemStore_SearchComponents(t *testing.T) {
	s := artifact.NewMemStore()

	alpine, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	slim, err := s.Create("alpine:3.19-slim", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	debian, err := s.Create("debian:12", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const alpineSSL = "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64"
	const debianSSL = "pkg:deb/debian/openssl@3.0.11-1"
	shared := []artifact.Component{
		{PURL: alpineSSL, Name: "openssl", Version: "3.1.4-r5"},
		{PURL: "pkg:apk/alpine/busybox@1.36.1-r15", Name: "busybox", Version: "1.36.1-r15"},
	}
	for _, id := range []string{alpine.ID, slim.ID} {
		if err := s.SaveComponents(id, shared); err != nil {
			t.Fatalf("SaveComponents: %v", err)
		}
	}
	if err := s.SaveComponents(debian.ID, []artifact.Component{
		{PURL: debianSSL, Name: "openssl", Version: "3.0.11-1"},
	}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}

	matches, total, err := s.SearchComponents("openssl", 50)
	if err != nil {
		t.Fatalf("SearchComponents: %v", err)
	}
	// Two DISTINCT packages, not three rows -- the alpine purl exists in
	// two artifacts and must collapse to one match carrying the count.
	if total != 2 || len(matches) != 2 {
		t.Fatalf("matches = %+v (total %d), want 2 distinct openssl packages", matches, total)
	}
	if matches[0].PURL != alpineSSL || matches[0].Artifacts != 2 {
		t.Fatalf("matches[0] = %+v, want the alpine purl first with 2 artifacts (ordered by count)", matches[0])
	}
	if matches[1].PURL != debianSSL || matches[1].Artifacts != 1 {
		t.Fatalf("matches[1] = %+v, want the debian purl with 1 artifact", matches[1])
	}
	if matches[0].Name != "openssl" || matches[0].Version != "3.1.4-r5" {
		t.Fatalf("matches[0] = %+v, want name/version carried for display", matches[0])
	}

	// Substring of the purl, not just the name -- searching an ecosystem
	// or namespace is the other half of how people look.
	if m, _, err := s.SearchComponents("pkg:deb/", 50); err != nil || len(m) != 1 || m[0].PURL != debianSSL {
		t.Fatalf("SearchComponents(\"pkg:deb/\") = %+v, %v, want the one debian package", m, err)
	}
	// Case-insensitive.
	if m, _, err := s.SearchComponents("OpenSSL", 50); err != nil || len(m) != 2 {
		t.Fatalf("SearchComponents(\"OpenSSL\") = %+v, %v, want the same 2 matches", m, err)
	}
	// No match, and an empty query, are both empty answers rather than
	// errors or (much worse) everything.
	if m, total, err := s.SearchComponents("nothing-like-this", 50); err != nil || len(m) != 0 || total != 0 {
		t.Fatalf("SearchComponents(unknown) = %+v (total %d), %v", m, total, err)
	}
	if m, total, err := s.SearchComponents("  ", 50); err != nil || len(m) != 0 || total != 0 {
		t.Fatalf("SearchComponents(blank) = %+v (total %d), %v, want nothing -- blank is not a wildcard", m, total, err)
	}

	// The cap reports what it dropped, so a caller can say "showing 1 of
	// 2" rather than presenting a truncated list as complete.
	capped, total, err := s.SearchComponents("openssl", 1)
	if err != nil || len(capped) != 1 || total != 2 {
		t.Fatalf("SearchComponents(limit 1) = %+v (total %d), %v, want 1 match but a total of 2", capped, total, err)
	}
}

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

// The picker's count and the list you get by clicking it must describe
// the same set. They're computed by two different queries, so nothing
// but a test keeps them honest -- and the failure mode is quiet: a
// search saying "3 artifacts" that opens onto 4 rows.
func TestMemStore_SearchFindingsCountMatchesFindByFindingID(t *testing.T) {
	s := artifact.NewMemStore()

	const cve = "CVE-2021-44228"
	affected, err := s.Create("app:1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	alsoAffected, err := s.Create("app:1.1", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	suppressed, err := s.Create("app:2.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	patched, err := s.Create("app:3.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	set := func(id string, f artifact.Finding) {
		t.Helper()
		if _, err := s.Update(id, func(a *artifact.Artifact) {
			a.CVEFindings = append(a.CVEFindings, f)
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}
	set(affected.ID, artifact.Finding{ID: cve, Title: "log4j RCE", Severity: "critical", Status: artifact.FindingStatusOpen})
	set(alsoAffected.ID, artifact.Finding{ID: cve, Title: "log4j RCE", Severity: "high", Status: artifact.FindingStatusOpen})
	set(suppressed.ID, artifact.Finding{ID: cve, Title: "log4j RCE", Severity: "critical", Status: artifact.FindingStatusNotAffected, Justification: "not reachable"})
	set(patched.ID, artifact.Finding{ID: cve, Title: "log4j RCE", Severity: "critical", Status: artifact.FindingStatusFixed})

	matches, total, err := s.SearchFindings("log4j", 50)
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if total != 1 || len(matches) != 1 {
		t.Fatalf("matches = %+v (total %d), want the one distinct id", matches, total)
	}
	if matches[0].Artifacts != 2 {
		t.Fatalf("artifacts = %d, want 2 -- the suppressed and the fixed one are not still affected", matches[0].Artifacts)
	}
	// Worst severity seen, not whichever artifact was scanned last.
	if matches[0].Severity != "critical" {
		t.Fatalf("severity = %q, want the worst seen across artifacts", matches[0].Severity)
	}

	list, err := s.FindByFindingID(cve)
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(list) != matches[0].Artifacts {
		t.Fatalf("search counted %d artifacts but FindByFindingID returned %d -- the two halves must count the same population",
			matches[0].Artifacts, len(list))
	}

	// By id as well as title, and case-insensitively.
	if m, _, err := s.SearchFindings("cve-2021", 50); err != nil || len(m) != 1 || m[0].ID != cve {
		t.Fatalf("id-substring search = %+v, %v", m, err)
	}
	if m, total, err := s.SearchFindings("nothing-like-this", 50); err != nil || len(m) != 0 || total != 0 {
		t.Fatalf("no-match search = %+v (total %d), %v", m, total, err)
	}
	if m, total, err := s.SearchFindings("  ", 50); err != nil || len(m) != 0 || total != 0 {
		t.Fatalf("blank search = %+v (total %d), %v, want nothing -- blank is not a wildcard", m, total, err)
	}
}

// A finding in the misconfiguration or secret bucket is as real as a
// CVE. MemStore's lookup used to scan three of the five buckets while
// Postgres queried one table covering all of them -- so the two
// disagreed about whether an artifact was affected, which is exactly
// the kind of difference that only shows up in production.
func TestMemStore_FindByFindingIDCoversEveryBucket(t *testing.T) {
	s := artifact.NewMemStore()
	a, err := s.Create("app:1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.MisconfigFindings = append(art.MisconfigFindings, artifact.Finding{ID: "AVD-KSV-0001", Title: "runs as root", Status: artifact.FindingStatusOpen})
		art.SecretFindings = append(art.SecretFindings, artifact.Finding{ID: "gitleaks-aws-key", Title: "AWS key", Status: artifact.FindingStatusOpen})
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	for _, id := range []string{"AVD-KSV-0001", "gitleaks-aws-key"} {
		got, err := s.FindByFindingID(id)
		if err != nil || len(got) != 1 {
			t.Fatalf("FindByFindingID(%q) = %+v, %v, want the artifact", id, got, err)
		}
	}
	if m, _, err := s.SearchFindings("gitleaks", 50); err != nil || len(m) != 1 {
		t.Fatalf("search across buckets = %+v, %v", m, err)
	}
}

// artifact.SeverityRank is a deliberate duplicate of notify's table (an
// import back into artifact would be a cycle). If they drift, the
// picker calls something "high" that notifications treat as critical.
func TestSeverityRankMatchesNotify(t *testing.T) {
	for _, s := range []string{"critical", "high", "medium", "low", "negligible", "unknown", "CRITICAL", " High ", "", "not-a-severity"} {
		if got, want := artifact.SeverityRank(s), notify.SeverityRank(s); got != want {
			t.Errorf("SeverityRank(%q) = %d, notify says %d", s, got, want)
		}
	}
}

// The bug this test exists for was found on live data, not here: one
// CVE is recorded with whichever package title each scanner reported --
// "openssl: SSL_select_next_proto buffer overread" in most artifacts,
// "libcrypto3 3.1.4-r5" in others -- so counting the rows that MATCHED
// the query reported 21 artifacts for a CVE that 23 artifacts carried.
// The picker undercounting its own click-through is precisely the
// mismatch this feature was built to avoid.
func TestMemStore_SearchFindingsCountsEveryArtifactWithTheID(t *testing.T) {
	s := artifact.NewMemStore()

	const cve = "CVE-2024-5535"
	mk := func(ref, title string) {
		t.Helper()
		a, err := s.Create(ref, artifact.TypeImage)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
			art.CVEFindings = append(art.CVEFindings, artifact.Finding{
				ID: cve, Title: title, Severity: "critical", Status: artifact.FindingStatusOpen,
			})
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}
	// Only the first title contains "openssl".
	mk("app:1.0", "openssl: SSL_select_next_proto buffer overread")
	mk("app:2.0", "libcrypto3 3.1.4-r5")
	mk("app:3.0", "libssl1.0.0 1.0.2g-1ubuntu4.8")

	matches, _, err := s.SearchFindings("openssl", 50)
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want the one id", matches)
	}
	if matches[0].Artifacts != 3 {
		t.Fatalf("artifacts = %d, want 3 -- the count must cover every artifact carrying the id, not just the rows whose title matched the query",
			matches[0].Artifacts)
	}

	list, err := s.FindByFindingID(cve)
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(list) != matches[0].Artifacts {
		t.Fatalf("search promised %d artifacts, the exact lookup returned %d", matches[0].Artifacts, len(list))
	}
}

// The same shape for components: an artifact whose SBOM spells the name
// differently for the same purl must still be counted.
func TestMemStore_SearchComponentsCountsEveryArtifactWithThePURL(t *testing.T) {
	s := artifact.NewMemStore()

	const purl = "pkg:apk/alpine/openssl@3.1.4-r5"
	mk := func(ref, name string) {
		t.Helper()
		a, err := s.Create(ref, artifact.TypeImage)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: purl, Name: name, Version: "3.1.4-r5"}}); err != nil {
			t.Fatalf("SaveComponents: %v", err)
		}
	}
	mk("app:1.0", "openssl")
	mk("app:2.0", "libcrypto3") // same purl, different name

	matches, _, err := s.SearchComponents("openssl", 50)
	if err != nil {
		t.Fatalf("SearchComponents: %v", err)
	}
	if len(matches) != 1 || matches[0].Artifacts != 2 {
		t.Fatalf("matches = %+v, want one purl in 2 artifacts", matches)
	}

	containing, err := s.FindByComponentPURL(purl)
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(containing) != matches[0].Artifacts {
		t.Fatalf("search promised %d artifacts, the exact lookup returned %d", matches[0].Artifacts, len(containing))
	}
}

// mustCreateStore is Create with the error handling these retention
// tests would otherwise repeat at every call.
func mustCreateStore(t *testing.T, s *artifact.MemStore, ref string) *artifact.Artifact {
	t.Helper()
	a, err := s.Create(ref, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create(%s): %v", ref, err)
	}
	return a
}

// Retention tests use a cutoff in the FUTURE rather than aging
// artifacts into the past. Update() stamps UpdatedAt = now after
// running its mutate callback, so there is no way to make an artifact
// old through the Store interface at all -- and a cutoff of now+1h
// means "everything is older than this", which exercises the same
// comparison without reaching into the store's internals or waiting.
func futureCutoff() time.Time { return time.Now().UTC().Add(time.Hour) }

func TestMemStore_CountAndDeleteOlderThan(t *testing.T) {
	s := artifact.NewMemStore()
	mustCreateStore(t, s, "one:1.0")
	mustCreateStore(t, s, "two:1.0")

	n, err := s.CountOlderThan(futureCutoff())
	if err != nil {
		t.Fatalf("CountOlderThan: %v", err)
	}
	if n != 2 {
		t.Fatalf("CountOlderThan = %d, want 2", n)
	}
	// Counting must not delete -- the dry run depends on exactly this.
	if all, _ := s.List(); len(all) != 2 {
		t.Fatalf("after CountOlderThan there are %d artifacts, want 2 -- counting must not delete", len(all))
	}

	// Nothing is older than a cutoff in the distant past.
	if n, err := s.CountOlderThan(time.Now().UTC().Add(-365 * 24 * time.Hour)); err != nil || n != 0 {
		t.Fatalf("CountOlderThan(a year ago) = %d, %v -- want 0", n, err)
	}

	deleted, err := s.DeleteOlderThan(futureCutoff(), 100)
	if err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("DeleteOlderThan = %d, want 2", deleted)
	}
	if all, _ := s.List(); len(all) != 0 {
		t.Fatalf("%d artifacts survived, want 0", len(all))
	}
}

// A capped run must take the OLDEST first. One that deleted an
// arbitrary subset would still report a plausible number while leaving
// the actually-stale rows behind and removing newer ones instead.
func TestMemStore_DeleteOlderThanTakesOldestFirst(t *testing.T) {
	s := artifact.NewMemStore()
	// Created in order, so their UpdatedAt increases in the same order.
	oldest := mustCreateStore(t, s, "oldest:1.0")
	middle := mustCreateStore(t, s, "middle:1.0")
	newest := mustCreateStore(t, s, "newest:1.0")

	deleted, err := s.DeleteOlderThan(futureCutoff(), 1)
	if err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1 (the cap)", deleted)
	}
	if _, err := s.Get(oldest.ID); err == nil {
		t.Error("the oldest artifact should have been the one deleted")
	}
	for _, id := range []string{middle.ID, newest.ID} {
		if _, err := s.Get(id); err != nil {
			t.Errorf("artifact %s should have survived a limit-1 prune: %v", id, err)
		}
	}
}

// A limit of zero or less deletes NOTHING. It must not read as
// "unlimited" the way a zero does elsewhere in this codebase (rate
// limits, quotas) -- here that convention would empty the store.
func TestMemStore_DeleteOlderThanZeroLimitDeletesNothing(t *testing.T) {
	s := artifact.NewMemStore()
	mustCreateStore(t, s, "keep-me:1.0")

	for _, limit := range []int{0, -1} {
		deleted, err := s.DeleteOlderThan(futureCutoff(), limit)
		if err != nil || deleted != 0 {
			t.Fatalf("DeleteOlderThan(limit=%d) = %d, %v -- want 0 deleted", limit, deleted, err)
		}
	}
	if all, _ := s.List(); len(all) != 1 {
		t.Fatalf("%d artifacts remain, want 1 -- a non-positive limit must never delete", len(all))
	}
}

// Retention keys on UpdatedAt, not CreatedAt: an artifact registered
// two years ago that is still being re-scanned is in active use, and
// deleting it would be the worst bug this feature could have.
func TestMemStore_DeleteOlderThanIgnoresOldButActiveArtifacts(t *testing.T) {
	s := artifact.NewMemStore()
	a := mustCreateStore(t, s, "ancient-but-busy:1.0")
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.CreatedAt = time.Now().UTC().Add(-700 * 24 * time.Hour)
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Cutoff well in the past: this artifact was CREATED long before it
	// and UPDATED just now, so it must not be eligible.
	n, err := s.CountOlderThan(time.Now().UTC().Add(-90 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("CountOlderThan: %v", err)
	}
	if n != 0 {
		t.Fatalf("CountOlderThan = %d, want 0 -- a two-year-old artifact updated today is not stale", n)
	}
}

// Deleting an artifact takes its documents and components with it (the
// cascade Delete already relies on), so a pruned artifact must not keep
// answering component searches from a map nothing else can reach.
func TestMemStore_DeleteOlderThanCascades(t *testing.T) {
	s := artifact.NewMemStore()
	a := mustCreateStore(t, s, "with-children:1.0")
	if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: "pkg:apk/alpine/openssl@3.1.4-r5", Name: "openssl"}}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}
	if err := s.SaveDocument(a.ID, artifact.DocumentKindSBOM, "application/json", []byte("{}")); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}

	if _, err := s.DeleteOlderThan(futureCutoff(), 10); err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	found, err := s.FindByComponentPURL("pkg:apk/alpine/openssl@3.1.4-r5")
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("a pruned artifact still answers component search: %+v", found)
	}
	if doc, _ := s.GetDocument(a.ID, artifact.DocumentKindSBOM); doc != nil {
		t.Error("a pruned artifact still has its SBOM document")
	}
}
