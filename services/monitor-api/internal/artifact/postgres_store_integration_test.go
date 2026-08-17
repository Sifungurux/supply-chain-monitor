//go:build postgres_integration

// This file only builds/runs with `-tags=postgres_integration` (see
// `make test-postgres`), so the default `go test ./...` used by
// `make test-api` -- and by CI, whenever that's wired up against the
// user's own git server -- never needs a live Postgres. That's a
// deliberate split: PostgresStore's SQL is worth verifying against a
// real database, but every other test in this repo runs with nothing
// but `go test` and no external services, and this shouldn't change
// that.
package artifact_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set -- run via `make test-postgres`")
	}
	return dsn
}

// newTestPostgresStore connects with a short retry loop of its own,
// since `make test-postgres` starts the Percona container and this
// test back to back -- there's no guarantee Postgres is accepting
// connections yet on the first attempt.
func newTestPostgresStore(t *testing.T) *artifact.PostgresStore {
	t.Helper()
	dsn := testDSN(t)

	ctx := context.Background()
	var store *artifact.PostgresStore
	var err error
	for i := 0; i < 20; i++ {
		store, err = artifact.NewPostgresStore(ctx, dsn)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		t.Fatalf("connect to test postgres at %s: %v", dsn, err)
	}
	t.Cleanup(store.Close)
	return store
}

func TestPostgresStore_CreateGetListUpdate(t *testing.T) {
	s := newTestPostgresStore(t)

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
		art.CVEFindings = append(art.CVEFindings, artifact.Finding{ID: "CVE-2024-1", Source: "trivy"})
		art.StageHistory = append(art.StageHistory, artifact.StageEvent{Stage: "build", Timestamp: time.Now().UTC()})
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Status != artifact.StatusScanned {
		t.Fatalf("status after update = %q, want %q", updated.Status, artifact.StatusScanned)
	}
	if len(updated.CVEFindings) != 1 || updated.CVEFindings[0].ID != "CVE-2024-1" {
		t.Fatalf("cve findings did not round-trip through the JSONB column: %+v", updated.CVEFindings)
	}
	if len(updated.StageHistory) != 1 || updated.StageHistory[0].Stage != "build" {
		t.Fatalf("stage history did not round-trip through the JSONB column: %+v", updated.StageHistory)
	}

	// Re-fetch with a fresh Get to prove the update was actually
	// persisted to Postgres, not just mutated on the in-memory struct
	// Update() happened to return.
	refetched, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if refetched.Status != artifact.StatusScanned || len(refetched.CVEFindings) != 1 {
		t.Fatalf("update did not persist: %+v", refetched)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, item := range list {
		if item.ID == a.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("List did not include the created artifact: %+v", list)
	}

	if _, err := s.Update("does-not-exist", func(*artifact.Artifact) {}); err == nil {
		t.Fatal("expected an error updating a missing id")
	}
}

// TestPostgresStore_Delete confirms Delete actually removes the
// artifacts row AND that the ON DELETE CASCADE foreign keys on
// stage_history/findings/scan_errors do their job -- not just that
// Get/List stop seeing the artifact (which cascading alone wouldn't
// prove), but that no orphaned child rows are left behind either. Uses
// its own raw pgxpool connection (same pattern
// TestPostgresStore_MigratesLegacyJSONBSchema uses) to query those
// child tables directly, since Store's own interface has no way to ask
// "how many rows exist for this artifact_id."
func TestPostgresStore_Delete(t *testing.T) {
	dsn := testDSN(t)
	s := newTestPostgresStore(t)

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer admin.Close()

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = append(art.CVEFindings, artifact.Finding{ID: "CVE-2024-1", Source: "trivy"})
		art.StageHistory = append(art.StageHistory, artifact.StageEvent{Stage: "build", Timestamp: time.Now().UTC()})
		art.LastScanErrors = append(art.LastScanErrors, "clamav: connection refused")
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.SaveDocument(a.ID, artifact.DocumentKindSBOM, "application/vnd.cyclonedx+json", []byte(`{"bomFormat":"CycloneDX"}`)); err != nil {
		t.Fatalf("SaveDocument: %v", err)
	}
	if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: "pkg:apk/alpine/openssl@3.1.4-r5", Name: "openssl", Version: "3.1.4-r5"}}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}

	countRows := func(table string) int {
		t.Helper()
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE artifact_id = $1", a.ID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}

	if countRows("findings") == 0 || countRows("stage_history") == 0 || countRows("scan_errors") == 0 || countRows("artifact_documents") == 0 || countRows("components") == 0 {
		t.Fatal("expected child rows to exist before delete (test setup didn't work)")
	}

	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Get(a.ID); err == nil {
		t.Fatal("expected Get to fail for a deleted artifact")
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, item := range list {
		if item.ID == a.ID {
			t.Fatalf("List still includes the deleted artifact: %+v", item)
		}
	}

	for _, table := range []string{"findings", "stage_history", "scan_errors", "artifact_documents", "components"} {
		if n := countRows(table); n != 0 {
			t.Fatalf("expected ON DELETE CASCADE to remove every %s row for the deleted artifact, found %d left behind", table, n)
		}
	}

	if err := s.Delete("does-not-exist"); err == nil {
		t.Fatal("expected an error deleting a missing id")
	}

	if err := s.Delete(a.ID); err == nil {
		t.Fatal("expected an error deleting the same id twice")
	}
}

// TestPostgresStore_UpdateSerializesConcurrentWritesToSameArtifact
// exercises the one behavior MemStore's mutex gave for free and
// PostgresStore has to earn deliberately: two goroutines racing to
// Update the *same* artifact must not silently drop one of the two
// mutations. Update()'s SELECT ... FOR UPDATE row lock inside a
// transaction is what's supposed to guarantee this.
func TestPostgresStore_UpdateSerializesConcurrentWritesToSameArtifact(t *testing.T) {
	s := newTestPostgresStore(t)
	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := s.Update(a.ID, func(art *artifact.Artifact) {
				art.StageHistory = append(art.StageHistory, artifact.StageEvent{
					Stage:     "build",
					Timestamp: time.Now().UTC(),
				})
			})
			errs <- err
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Update: %v", err)
		}
	}

	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.StageHistory) != n {
		t.Fatalf("stage_history has %d entries, want %d -- a concurrent update was lost", len(got.StageHistory), n)
	}
}

// TestPostgresStore_FindByFindingID exercises the query the findings
// table's normalization exists to make possible -- see
// docs/architecture.md, "Normalizing findings and stage history into
// their own tables." A JSONB-blob-per-artifact schema could only
// answer "which artifacts have CVE X" by scanning and JSON-decoding
// every single row; this uses the findings.finding_id index instead.
func TestPostgresStore_FindByFindingID(t *testing.T) {
	s := newTestPostgresStore(t)

	affected, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create("debian:12", artifact.TypeImage); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A unique finding ID per test run avoids collisions with rows any
	// other test in this file leaves behind in the same shared
	// database (none of these tests clean up after themselves today).
	findingID := fmt.Sprintf("CVE-test-%d", time.Now().UnixNano())

	if _, err := s.Update(affected.ID, func(a *artifact.Artifact) {
		a.CVEFindings = append(a.CVEFindings, artifact.Finding{ID: findingID, Severity: "high", Source: "trivy"})
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	matches, err := s.FindByFindingID(findingID)
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != affected.ID {
		t.Fatalf("matches = %+v, want just %q", matches, affected.ID)
	}
	if len(matches[0].CVEFindings) != 1 || matches[0].CVEFindings[0].ID != findingID {
		t.Fatalf("matched artifact's findings = %+v", matches[0].CVEFindings)
	}

	none, err := s.FindByFindingID("CVE-definitely-does-not-exist")
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no matches for an unused finding id, got %+v", none)
	}
}

// TestPostgresStore_FindByDigest proves digest round-trips through
// Update's SET clause and FindByDigest's WHERE against a real database
// -- the one place that would catch a mistake like forgetting to add
// `digest` to Update's UPDATE statement (see postgres_store.go's own
// comment on that trap: MemStore's Update wouldn't show this bug at
// all, since it mutates the stored struct directly).
func TestPostgresStore_FindByDigest(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create("debian:12", artifact.TypeImage); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A unique digest per test run avoids collisions with rows any
	// other test in this file leaves behind in the same shared database.
	digest := fmt.Sprintf("sha256:test-%d", time.Now().UnixNano())

	if got, err := s.FindByDigest(digest); err != nil || got != nil {
		t.Fatalf("FindByDigest before Update = %+v, %v, want nil, nil", got, err)
	}

	if _, err := s.Update(a.ID, func(art *artifact.Artifact) { art.Digest = digest }); err != nil {
		t.Fatalf("Update: %v", err)
	}

	match, err := s.FindByDigest(digest)
	if err != nil {
		t.Fatalf("FindByDigest: %v", err)
	}
	if match == nil || match.ID != a.ID {
		t.Fatalf("match = %+v, want %q", match, a.ID)
	}

	if got, err := s.FindByDigest(""); err != nil || got != nil {
		t.Fatalf("FindByDigest(\"\") = %+v, %v, want nil, nil", got, err)
	}
}

// TestPostgresStore_SaveAndGetDocument is the one place that would
// catch a real bug in artifact_documents' BYTEA round-trip (content
// bytes surviving Postgres exactly, not mangled by an encoding
// mismatch) or in loadDocumentFlags/fillChildrenBatch's HasSBOM/HasSARIF
// wiring -- pure-Go tests against MemStore can't exercise either, since
// MemStore just holds the same []byte in memory and Get/List return the
// live pointer directly.
func TestPostgresStore_SaveAndGetDocument(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got, err := s.GetDocument(a.ID, artifact.DocumentKindSBOM); err != nil || got != nil {
		t.Fatalf("GetDocument before any save = %+v, %v, want nil, nil", got, err)
	}

	sbomContent := []byte(`{"bomFormat":"CycloneDX","version":1}`)
	if err := s.SaveDocument(a.ID, artifact.DocumentKindSBOM, "application/vnd.cyclonedx+json", sbomContent); err != nil {
		t.Fatalf("SaveDocument(sbom): %v", err)
	}
	sarifContent := []byte(`{"version":"2.1.0"}`)
	if err := s.SaveDocument(a.ID, artifact.DocumentKindSARIF, "application/sarif+json", sarifContent); err != nil {
		t.Fatalf("SaveDocument(sarif): %v", err)
	}

	doc, err := s.GetDocument(a.ID, artifact.DocumentKindSBOM)
	if err != nil {
		t.Fatalf("GetDocument(sbom): %v", err)
	}
	if doc == nil || string(doc.Content) != string(sbomContent) || doc.ContentType != "application/vnd.cyclonedx+json" {
		t.Fatalf("GetDocument(sbom) = %+v, content mismatch or wrong content type", doc)
	}

	// Get/List both report HasSBOM/HasSARIF without embedding content.
	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.HasSBOM || !got.HasSARIF {
		t.Fatalf("Get: HasSBOM=%v HasSARIF=%v, want both true", got.HasSBOM, got.HasSARIF)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, item := range list {
		if item.ID == a.ID {
			found = true
			if !item.HasSBOM || !item.HasSARIF {
				t.Fatalf("List: HasSBOM=%v HasSARIF=%v, want both true", item.HasSBOM, item.HasSARIF)
			}
		}
	}
	if !found {
		t.Fatal("List didn't include the artifact under test")
	}

	// Re-saving the same kind overwrites, doesn't duplicate the row.
	updatedContent := []byte(`{"bomFormat":"CycloneDX","version":2}`)
	if err := s.SaveDocument(a.ID, artifact.DocumentKindSBOM, "application/vnd.cyclonedx+json", updatedContent); err != nil {
		t.Fatalf("SaveDocument(sbom) overwrite: %v", err)
	}
	doc2, err := s.GetDocument(a.ID, artifact.DocumentKindSBOM)
	if err != nil {
		t.Fatalf("GetDocument(sbom) after overwrite: %v", err)
	}
	if string(doc2.Content) != string(updatedContent) {
		t.Fatalf("GetDocument(sbom) after overwrite = %q, want %q", string(doc2.Content), string(updatedContent))
	}
}

// TestPostgresStore_FindingLifecycleRoundTrips proves MergeFindings'
// Status/FirstSeenAt/ResolvedAt actually persist and reload correctly
// through the findings table's new columns, not just in the pure-Go
// unit tests in merge_test.go -- this is the one place that would catch
// a column ordering mistake in insertFinding/loadFindings/
// fillChildrenBatch (see postgres_store.go), which the pure-Go tests
// can't, since they never touch SQL at all.
func TestPostgresStore_FindingLifecycleRoundTrips(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	firstScan := time.Now().UTC()
	_, err = s.Update(a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, []artifact.Finding{
			{ID: "CVE-lifecycle-1", Severity: "high", Source: "trivy"},
		}, firstScan, true, nil)
	})
	if err != nil {
		t.Fatalf("Update (first scan): %v", err)
	}

	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get after first scan: %v", err)
	}
	if len(got.CVEFindings) != 1 {
		t.Fatalf("cve findings after first scan = %+v", got.CVEFindings)
	}
	f := got.CVEFindings[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusOpen)
	}
	if f.ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil", f.ResolvedAt)
	}
	// Postgres TIMESTAMPTZ has microsecond precision; allow a small
	// tolerance rather than requiring bit-for-bit equality with the
	// Go-side time.Time that was written.
	if diff := f.FirstSeenAt.Sub(firstScan); diff < -time.Second || diff > time.Second {
		t.Fatalf("first_seen_at = %v, want close to %v", f.FirstSeenAt, firstScan)
	}
	originalFirstSeen := f.FirstSeenAt

	// Second scan, later: CVE-lifecycle-1 no longer reported -> fixed.
	secondScan := firstScan.Add(1 * time.Hour)
	_, err = s.Update(a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, nil, secondScan, true, nil)
	})
	if err != nil {
		t.Fatalf("Update (second scan): %v", err)
	}

	got, err = s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get after second scan: %v", err)
	}
	if len(got.CVEFindings) != 1 {
		t.Fatalf("expected the fixed finding to still be present (not deleted), got %+v", got.CVEFindings)
	}
	f = got.CVEFindings[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil {
		t.Fatal("resolved_at is nil, want it set once the finding stopped being reported")
	}
	if diff := f.ResolvedAt.Sub(secondScan); diff < -time.Second || diff > time.Second {
		t.Fatalf("resolved_at = %v, want close to %v", f.ResolvedAt, secondScan)
	}
	if diff := f.FirstSeenAt.Sub(originalFirstSeen); diff < -time.Second || diff > time.Second {
		t.Fatalf("first_seen_at changed across the second scan: got %v, want unchanged %v", f.FirstSeenAt, originalFirstSeen)
	}
}

// TestPostgresStore_VEXSuppressionRoundTrips is the same argument as
// TestPostgresStore_FindingLifecycleRoundTrips, for the justification
// column: a suppressed finding has to come back suppressed *with its
// reason* through BOTH read paths. Get uses loadFindings, List/ListPage
// use fillChildrenBatch's own separate SELECT -- miss the column in the
// second and the justification is present on the detail page and empty
// in the list the dashboard actually polls.
func TestPostgresStore_VEXSuppressionRoundTrips(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19-vex", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	now := time.Now().UTC()
	vex := artifact.VEXByID([]artifact.VEXStatement{{
		VulnID:        "CVE-vex-1",
		Status:        artifact.FindingStatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	}})
	_, err = s.Update(a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, []artifact.Finding{
			{ID: "CVE-vex-1", Severity: "critical", Source: "trivy"},
		}, now, true, vex)
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	assertSuppressed := func(where string, findings []artifact.Finding) {
		t.Helper()
		if len(findings) != 1 {
			t.Fatalf("%s: cve findings = %+v, want 1", where, findings)
		}
		f := findings[0]
		if f.Status != artifact.FindingStatusNotAffected {
			t.Errorf("%s: status = %q, want %q", where, f.Status, artifact.FindingStatusNotAffected)
		}
		if f.Justification != "vulnerable_code_not_in_execute_path" {
			t.Errorf("%s: justification = %q, want it persisted", where, f.Justification)
		}
		if f.ResolvedAt != nil {
			t.Errorf("%s: resolved_at = %v, want nil for not_affected", where, f.ResolvedAt)
		}
	}

	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertSuppressed("Get (loadFindings)", got.CVEFindings)

	// ListPage, not List: it's the batch loader the dashboard's own poll
	// goes through.
	page, _, err := s.ListPage(100, 0, "", "")
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	var listed *artifact.Artifact
	for _, art := range page {
		if art.ID == a.ID {
			listed = art
		}
	}
	if listed == nil {
		t.Fatalf("artifact %s not in the first page of ListPage", a.ID)
	}
	assertSuppressed("ListPage (fillChildrenBatch)", listed.CVEFindings)
}

// TestPostgresStore_ComponentInventory exercises the components table
// end to end against a real database -- the migration, the purl index's
// query, the replace-on-re-upload transaction, and the foreign key's
// ON DELETE CASCADE. The MemStore tests in store_test.go cover the same
// contract in pure Go, but only this one can catch a SQL or schema
// mistake, which is exactly where this feature's risk is.
func TestPostgresStore_ComponentInventory(t *testing.T) {
	s := newTestPostgresStore(t)

	const openssl = "pkg:apk/alpine/openssl@3.1.4-r5"
	// A purl with qualifiers, which is what real SBOMs carry -- stored
	// and matched verbatim, "?" and "&" included.
	const qualified = "pkg:apk/alpine/apk-tools@2.14.4-r0?arch=x86_64&distro=3.19.9"

	a, err := s.Create("alpine:3.19-components", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	other, err := s.Create("debian:12-components", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.SaveComponents(a.ID, []artifact.Component{
		{PURL: openssl, Name: "openssl", Version: "3.1.4-r5"},
		{PURL: qualified, Name: "apk-tools", Version: "2.14.4-r0"},
		// The same purl twice in one document: UNIQUE (artifact_id,
		// purl) plus ON CONFLICT DO NOTHING must make this a no-op, not
		// an error and not a duplicate row.
		{PURL: openssl, Name: "openssl", Version: "3.1.4-r5"},
	}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}
	if err := s.SaveComponents(other.ID, []artifact.Component{{PURL: openssl, Name: "openssl", Version: "3.1.4-r5"}}); err != nil {
		t.Fatalf("SaveComponents (other): %v", err)
	}

	matches, err := s.FindByComponentPURL(openssl)
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	ids := map[string]bool{}
	for _, m := range matches {
		ids[m.ID] = true
	}
	if !ids[a.ID] || !ids[other.ID] {
		t.Fatalf("matches = %+v, want both artifacts sharing the package", matches)
	}
	// One row per artifact, even though one of them reported the purl
	// twice -- a duplicate would show up here as the same artifact
	// returned more than once.
	if len(matches) != len(ids) {
		t.Fatalf("FindByComponentPURL returned %d rows for %d distinct artifacts -- duplicates leaked", len(matches), len(ids))
	}

	if got, err := s.FindByComponentPURL(qualified); err != nil || len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("FindByComponentPURL(qualified) = %+v, %v, want just %s", got, err, a.ID)
	}
	if got, err := s.FindByComponentPURL("pkg:apk/alpine/nothing@1.0"); err != nil || len(got) != 0 {
		t.Fatalf("FindByComponentPURL(unknown) = %+v, %v, want no matches", got, err)
	}
	if got, err := s.FindByComponentPURL(""); err != nil || len(got) != 0 {
		t.Fatalf(`FindByComponentPURL("") = %+v, %v, want no matches`, got, err)
	}

	// Re-upload: the previous inventory must be gone, not added to.
	if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: "pkg:apk/alpine/openssl@3.2.0-r0", Name: "openssl", Version: "3.2.0-r0"}}); err != nil {
		t.Fatalf("SaveComponents (re-upload): %v", err)
	}
	after, err := s.FindByComponentPURL(openssl)
	if err != nil {
		t.Fatalf("FindByComponentPURL after re-upload: %v", err)
	}
	for _, m := range after {
		if m.ID == a.ID {
			t.Fatalf("%s still matches %q after an SBOM that no longer lists it", a.ID, openssl)
		}
	}
	if got, err := s.FindByComponentPURL("pkg:apk/alpine/openssl@3.2.0-r0"); err != nil || len(got) != 1 {
		t.Fatalf("FindByComponentPURL(new version) = %+v, %v, want the artifact", got, err)
	}

	// ON DELETE CASCADE: deleting the artifact takes its inventory with
	// it, rather than leaving rows that answer a query with a ghost.
	if err := s.Delete(other.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ghosts, err := s.FindByComponentPURL(openssl)
	if err != nil {
		t.Fatalf("FindByComponentPURL after delete: %v", err)
	}
	if len(ghosts) != 0 {
		t.Fatalf("matches after deleting the only artifact left with %q = %+v, want none", openssl, ghosts)
	}

	if err := s.SaveComponents("does-not-exist", []artifact.Component{{PURL: openssl}}); err == nil {
		t.Fatal("expected an error saving components against a missing artifact")
	}
	// The same call with an empty inventory has no INSERT to trip the
	// foreign key, so it needs the explicit existence check to fail.
	if err := s.SaveComponents("does-not-exist", nil); err == nil {
		t.Fatal("expected an error saving an EMPTY inventory against a missing artifact")
	}
}

// TestPostgresStore_SearchComponents mirrors MemStore's own search test
// against real SQL, where the risk actually lives: the GROUP BY, the
// count(DISTINCT artifact_id) (count(*) would report one match per
// artifact instead of one match with a count), the ordering the picker
// depends on, and LIKE's own wildcards inside a user-typed query.
func TestPostgresStore_SearchComponents(t *testing.T) {
	s := newTestPostgresStore(t)

	// A prefix unique to this test: the database is shared with every
	// other test in this file, so a substring search would otherwise
	// match whatever they left behind.
	const ns = "searchtest"
	alpineSSL := "pkg:apk/" + ns + "/openssl@3.1.4-r5?arch=x86_64"
	debianSSL := "pkg:deb/" + ns + "/openssl@3.0.11-1"
	oddName := ns + "_under%score"

	a1, err := s.Create("alpine:3.19-"+ns, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	a2, err := s.Create("alpine:3.19-slim-"+ns, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	a3, err := s.Create("debian:12-"+ns, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, id := range []string{a1.ID, a2.ID} {
		if err := s.SaveComponents(id, []artifact.Component{
			{PURL: alpineSSL, Name: "openssl-" + ns, Version: "3.1.4-r5"},
		}); err != nil {
			t.Fatalf("SaveComponents: %v", err)
		}
	}
	if err := s.SaveComponents(a3.ID, []artifact.Component{
		{PURL: debianSSL, Name: "openssl-" + ns, Version: "3.0.11-1"},
		{PURL: "pkg:generic/" + oddName + "@1.0", Name: oddName, Version: "1.0"},
	}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}

	matches, total, err := s.SearchComponents("openssl-"+ns, 50)
	if err != nil {
		t.Fatalf("SearchComponents: %v", err)
	}
	if total != 2 || len(matches) != 2 {
		t.Fatalf("matches = %+v (total %d), want 2 distinct packages, not one row per artifact", matches, total)
	}
	if matches[0].PURL != alpineSSL || matches[0].Artifacts != 2 {
		t.Fatalf("matches[0] = %+v, want the purl in 2 artifacts first", matches[0])
	}
	if matches[1].PURL != debianSSL || matches[1].Artifacts != 1 {
		t.Fatalf("matches[1] = %+v, want the single-artifact purl second", matches[1])
	}
	if matches[0].Name != "openssl-"+ns || matches[0].Version != "3.1.4-r5" {
		t.Fatalf("matches[0] = %+v, want name/version carried through the GROUP BY", matches[0])
	}

	// Case-insensitive, and matches the purl as well as the name.
	if m, _, err := s.SearchComponents("OPENSSL-"+ns, 50); err != nil || len(m) != 2 {
		t.Fatalf("case-insensitive search = %+v, %v, want the same 2", m, err)
	}
	if m, _, err := s.SearchComponents("pkg:deb/"+ns, 50); err != nil || len(m) != 1 || m[0].PURL != debianSSL {
		t.Fatalf("purl-substring search = %+v, %v", m, err)
	}

	// A query containing LIKE's own wildcards must match those
	// characters literally, not act as a pattern -- without the escaping,
	// "%" here would match every component in the table.
	if m, _, err := s.SearchComponents(oddName, 50); err != nil || len(m) != 1 {
		t.Fatalf("SearchComponents(%q) = %+v, %v, want exactly the one package containing that literal string", oddName, m, err)
	}
	if m, _, err := s.SearchComponents(ns+"_under%", 50); err != nil || len(m) != 1 {
		t.Fatalf("wildcard-containing query = %+v, %v, want it treated as literal text", m, err)
	}

	if m, total, err := s.SearchComponents("openssl-"+ns, 1); err != nil || len(m) != 1 || total != 2 {
		t.Fatalf("capped search = %+v (total %d), %v, want 1 returned but total 2", m, total, err)
	}
	if m, total, err := s.SearchComponents("   ", 50); err != nil || len(m) != 0 || total != 0 {
		t.Fatalf("blank query = %+v (total %d), %v, want nothing", m, total, err)
	}
}

// The live bug, against real SQL: one id recorded with different titles
// across artifacts. Counting matched rows reported 21 for a CVE that 23
// artifacts carried.
func TestPostgresStore_SearchCountsEveryArtifactWithTheKey(t *testing.T) {
	s := newTestPostgresStore(t)

	const ns = "titlespread"
	const cve = "CVE-2024-" + ns
	const purl = "pkg:apk/" + ns + "/openssl@3.1.4-r5"

	mkFinding := func(ref, title string) {
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
		if err := s.SaveComponents(a.ID, []artifact.Component{{PURL: purl, Name: title, Version: "3.1.4-r5"}}); err != nil {
			t.Fatalf("SaveComponents: %v", err)
		}
	}
	// Only the first carries the search term in its title/name.
	mkFinding("app:1.0-"+ns, "openssl"+ns+" buffer overread")
	mkFinding("app:2.0-"+ns, "libcrypto3 3.1.4-r5")
	mkFinding("app:3.0-"+ns, "libssl1.0.0 1.0.2g")

	matches, _, err := s.SearchFindings("openssl"+ns, 50)
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(matches) != 1 || matches[0].Artifacts != 3 {
		t.Fatalf("finding matches = %+v, want the id counted across all 3 artifacts, not just the row whose title matched", matches)
	}
	affected, err := s.FindByFindingID(cve)
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(affected) != matches[0].Artifacts {
		t.Fatalf("search promised %d artifacts, exact lookup returned %d", matches[0].Artifacts, len(affected))
	}

	comps, _, err := s.SearchComponents("openssl"+ns, 50)
	if err != nil {
		t.Fatalf("SearchComponents: %v", err)
	}
	if len(comps) != 1 || comps[0].Artifacts != 3 {
		t.Fatalf("component matches = %+v, want the purl counted across all 3 artifacts", comps)
	}
	containing, err := s.FindByComponentPURL(purl)
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(containing) != comps[0].Artifacts {
		t.Fatalf("search promised %d artifacts, exact lookup returned %d", comps[0].Artifacts, len(containing))
	}
}

// dsnWithSearchPath points a DSN at a specific Postgres schema via the
// search_path connection parameter, so a test can create its own
// artifacts table (in its own schema, via the admin connection) and
// then hand a scoped DSN to NewPostgresStore -- giving it full control
// of exactly what "the existing schema" looks like at connect time,
// isolated from whatever other tests in this same run have already
// done against the default "public" schema. Assumes dsn already has a
// query string (true for every DSN this project's own docs/Makefile
// ever construct, e.g. "...?sslmode=disable"); appends with "?"
// instead of "&" if not.
func dsnWithSearchPath(dsn, schema string) string {
	sep := "&"
	if !strings.Contains(dsn, "?") {
		sep = "?"
	}
	return dsn + sep + "search_path=" + schema
}

// TestPostgresStore_MigratesLegacyJSONBSchema proves the migration
// path in migrateLegacyJSONBColumns actually works against a real
// database: build the OLD single-table JSONB schema by hand (exactly
// what PostgresStore used to create, before normalization), seed it
// with data through every column including one the old schema never
// had a column for at all (other_findings/SARIF -- see the comment on
// migrateLegacyJSONBColumns), then let NewPostgresStore's migration
// run and verify the data survived the move into the new normalized
// tables and the old JSONB columns are actually gone afterward, not
// just unused.
func TestPostgresStore_MigratesLegacyJSONBSchema(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer admin.Close()
	var pingErr error
	for i := 0; i < 20; i++ {
		if pingErr = admin.Ping(ctx); pingErr == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if pingErr != nil {
		t.Fatalf("ping: %v", pingErr)
	}

	schemaName := fmt.Sprintf("migration_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schemaName); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE")
	})

	// The exact old single-table shape (see postgres_store.go's git
	// history / docs/architecture.md), built by hand inside the
	// dedicated schema rather than by an older version of this code,
	// since that code no longer exists to call.
	_, err = admin.Exec(ctx, `CREATE TABLE `+schemaName+`.artifacts (
		id                TEXT PRIMARY KEY,
		ref               TEXT NOT NULL,
		type              TEXT NOT NULL,
		status            TEXT NOT NULL,
		current_stage     TEXT NOT NULL DEFAULT '',
		stage_history     JSONB NOT NULL DEFAULT '[]',
		cve_findings      JSONB NOT NULL DEFAULT '[]',
		malware_findings  JSONB NOT NULL DEFAULT '[]',
		last_scan_errors  JSONB NOT NULL DEFAULT '[]',
		created_at        TIMESTAMPTZ NOT NULL,
		updated_at        TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create legacy table: %v", err)
	}

	const legacyID = "legacy-artifact-1"
	now := time.Now().UTC()
	_, err = admin.Exec(ctx, `
		INSERT INTO `+schemaName+`.artifacts
			(id, ref, type, status, current_stage, stage_history, cve_findings, malware_findings, last_scan_errors, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
	`,
		legacyID, "alpine:3.19", "image", "scanned", "scan",
		`[{"stage":"build","timestamp":"2026-01-01T00:00:00Z","note":"CI job #1"}]`,
		`[{"id":"CVE-2024-9999","severity":"high","title":"legacy finding","source":"trivy"}]`,
		`[{"id":"clamav-signature-match","severity":"critical","title":"legacy malware","source":"clamav"}]`,
		`["legacy scanner error"]`,
		now,
	)
	if err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	schemaDSN := dsnWithSearchPath(dsn, schemaName)
	store, err := artifact.NewPostgresStore(ctx, schemaDSN)
	if err != nil {
		t.Fatalf("NewPostgresStore against legacy schema: %v", err)
	}
	defer store.Close()

	got, err := store.Get(legacyID)
	if err != nil {
		t.Fatalf("Get migrated artifact: %v", err)
	}
	if len(got.StageHistory) != 1 || got.StageHistory[0].Stage != "build" || got.StageHistory[0].Note != "CI job #1" {
		t.Fatalf("migrated stage_history = %+v", got.StageHistory)
	}
	if len(got.CVEFindings) != 1 || got.CVEFindings[0].ID != "CVE-2024-9999" {
		t.Fatalf("migrated cve_findings = %+v", got.CVEFindings)
	}
	if len(got.MalwareFindings) != 1 || got.MalwareFindings[0].ID != "clamav-signature-match" {
		t.Fatalf("migrated malware_findings = %+v", got.MalwareFindings)
	}
	// The legacy JSONB blobs never had Status/FirstSeenAt/ResolvedAt at
	// all -- insertFinding must default them sensibly (open, stamped
	// with roughly the migration time) rather than leaving a zero-value
	// FirstSeenAt sitting in the new NOT NULL column.
	if got.CVEFindings[0].Status != artifact.FindingStatusOpen {
		t.Fatalf("migrated finding status = %q, want %q", got.CVEFindings[0].Status, artifact.FindingStatusOpen)
	}
	if got.CVEFindings[0].FirstSeenAt.IsZero() {
		t.Fatal("migrated finding has a zero first_seen_at -- insertFinding should have defaulted it")
	}
	if len(got.LastScanErrors) != 1 || got.LastScanErrors[0] != "legacy scanner error" {
		t.Fatalf("migrated last_scan_errors = %+v", got.LastScanErrors)
	}
	// The old schema never had a column for this at all -- nothing to
	// migrate, but the new normalized table must still work for it
	// going forward.
	if len(got.OtherFindings) != 0 {
		t.Fatalf("expected no other_findings (the old schema had nowhere to store them), got %+v", got.OtherFindings)
	}

	var stillHasLegacyColumn bool
	err = admin.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_attribute
			WHERE attrelid = ($1 || '.artifacts')::regclass
			  AND attname = 'stage_history'
			  AND NOT attisdropped
		)
	`, schemaName).Scan(&stillHasLegacyColumn)
	if err != nil {
		t.Fatalf("check legacy column: %v", err)
	}
	if stillHasLegacyColumn {
		t.Fatal("expected the legacy stage_history JSONB column to be dropped after migration")
	}

	// Reconnecting against the now-migrated schema must be a no-op --
	// not an error, and not a second attempt to migrate data that's
	// already been migrated.
	store2, err := artifact.NewPostgresStore(ctx, schemaDSN)
	if err != nil {
		t.Fatalf("NewPostgresStore a second time (already migrated): %v", err)
	}
	defer store2.Close()
	if _, err := store2.Get(legacyID); err != nil {
		t.Fatalf("Get after reconnecting to an already-migrated schema: %v", err)
	}
}

// TestPostgresStore_ListPage exercises the SQL that MemStore's own
// ListPage can't: the built-up WHERE clause, its matching COUNT(*), and
// LIMIT/OFFSET. Every assertion is scoped to the artifacts this test
// creates (by ref prefix and by filtering on a type nothing else here
// uses) so it doesn't fight the other tests sharing this database.
func TestPostgresStore_ListPage(t *testing.T) {
	s := newTestPostgresStore(t)

	created := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		a, err := s.Create(fmt.Sprintf("listpage-test-%d:1.0", i), artifact.TypeSARIF)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		created = append(created, a.ID)
		t.Cleanup(func() { _ = s.Delete(a.ID) })
	}
	// One of them scanned, so the status filter has something to select
	// on that the other four don't match.
	if _, err := s.Update(created[0], func(a *artifact.Artifact) { a.Status = artifact.StatusScanned }); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Type filter: total counts all five matches, the page holds two.
	page, total, err := s.ListPage(2, 0, "", string(artifact.TypeSARIF))
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5 -- COUNT(*) must apply the same filter as the page query", total)
	}
	if len(page) != 2 {
		t.Fatalf("page has %d artifacts, want 2 (LIMIT)", len(page))
	}

	// Paging with the same filter must partition the set: every id once,
	// none missing.
	seen := map[string]bool{}
	for offset := 0; offset < total; offset += 2 {
		p, _, err := s.ListPage(2, offset, "", string(artifact.TypeSARIF))
		if err != nil {
			t.Fatalf("ListPage(offset=%d): %v", offset, err)
		}
		for _, a := range p {
			if seen[a.ID] {
				t.Fatalf("artifact %s appeared on more than one page", a.ID)
			}
			seen[a.ID] = true
		}
	}
	for _, id := range created {
		if !seen[id] {
			t.Fatalf("artifact %s never appeared on any page", id)
		}
	}

	// Both filters together, and the batched child-loading still runs
	// (Update above left a stage history behind to load).
	page, total, err = s.ListPage(50, 0, string(artifact.StatusScanned), string(artifact.TypeSARIF))
	if err != nil {
		t.Fatalf("ListPage(status+type): %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].ID != created[0] {
		t.Fatalf("status+type filter returned total=%d len=%d, want exactly the scanned artifact %s", total, len(page), created[0])
	}

	// An offset past the end is an empty page, not an error.
	page, total, err = s.ListPage(50, 500, "", string(artifact.TypeSARIF))
	if err != nil {
		t.Fatalf("ListPage(offset past end): %v", err)
	}
	if len(page) != 0 || total != 5 {
		t.Fatalf("offset past the end: len=%d total=%d, want 0 and 5", len(page), total)
	}
}

// TestPostgresStore_FindByRef exercises the dedup fallback's SQL --
// including the oldest-wins tie-break, which is what makes repeated
// registrations converge on the original row rather than chaining off
// the most recent one.
func TestPostgresStore_FindByRef(t *testing.T) {
	s := newTestPostgresStore(t)
	ref := fmt.Sprintf("findbyref-test-%d:1.0", time.Now().UnixNano())

	first, err := s.Create(ref, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(first.ID) })

	// A second row with the same ref is exactly what this fallback
	// exists to prevent, but the store must still answer deterministically
	// if one is already there.
	time.Sleep(10 * time.Millisecond) // ensure a distinct created_at
	second, err := s.Create(ref, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create (second): %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(second.ID) })

	got, err := s.FindByRef(ref)
	if err != nil {
		t.Fatalf("FindByRef: %v", err)
	}
	if got == nil {
		t.Fatal("FindByRef returned nothing for a ref that exists")
	}
	if got.ID != first.ID {
		t.Fatalf("FindByRef returned %s, want the OLDEST (%s) -- repeated registrations must converge on the original", got.ID, first.ID)
	}

	// Not found is (nil, nil), the same convention FindByDigest uses.
	missing, err := s.FindByRef(ref + "-does-not-exist")
	if err != nil {
		t.Fatalf("FindByRef(missing): %v", err)
	}
	if missing != nil {
		t.Fatalf("FindByRef(missing) = %+v, want nil", missing)
	}
	if empty, err := s.FindByRef(""); err != nil || empty != nil {
		t.Fatalf(`FindByRef("") = %+v, %v -- an empty ref must never match`, empty, err)
	}
}

func TestPostgresStore_Count(t *testing.T) {
	s := newTestPostgresStore(t)

	// Asserted as a DELTA, not an absolute: this database is shared with
	// every other test in the file, so the only stable claim is that
	// Count moves by exactly what this test creates and deletes.
	before, err := s.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	ref := fmt.Sprintf("count-test-%d:1.0", time.Now().UnixNano())
	a, err := s.Create(ref, artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	after, err := s.Count()
	if err != nil {
		t.Fatalf("Count (after create): %v", err)
	}
	if after != before+1 {
		t.Fatalf("Count = %d after creating one artifact, want %d", after, before+1)
	}

	// Deleting must free the quota again -- that is the whole reason the
	// registration limit answers 403 rather than 429.
	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	freed, err := s.Count()
	if err != nil {
		t.Fatalf("Count (after delete): %v", err)
	}
	if freed != before {
		t.Fatalf("Count = %d after deleting the artifact, want %d -- deletion must free quota", freed, before)
	}
}

// TestPostgresStore_SearchFindings mirrors the MemStore search test
// against real SQL, where the aggregation risk is: the GROUP BY, the
// severity CASE, count(DISTINCT artifact_id), and -- most importantly --
// that the count agrees with what FindByFindingID actually returns.
func TestPostgresStore_SearchFindings(t *testing.T) {
	s := newTestPostgresStore(t)

	// Unique to this test: the database is shared with every other test
	// in this file, so a substring search would otherwise match their
	// leftovers.
	const cve = "CVE-2021-SEARCHTEST"
	const title = "log4jsearchtest RCE via JNDI"

	mk := func(ref string, f artifact.Finding) string {
		t.Helper()
		a, err := s.Create(ref, artifact.TypeImage)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
			art.CVEFindings = append(art.CVEFindings, f)
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		return a.ID
	}

	mk("app:1.0-searchtest", artifact.Finding{ID: cve, Title: title, Severity: "high", Status: artifact.FindingStatusOpen})
	mk("app:1.1-searchtest", artifact.Finding{ID: cve, Title: title, Severity: "critical", Status: artifact.FindingStatusOpen})
	mk("app:2.0-searchtest", artifact.Finding{ID: cve, Title: title, Severity: "critical", Status: artifact.FindingStatusNotAffected, Justification: "not reachable"})
	mk("app:3.0-searchtest", artifact.Finding{ID: cve, Title: title, Severity: "critical", Status: artifact.FindingStatusFixed})

	matches, total, err := s.SearchFindings("log4jsearchtest", 50)
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if total != 1 || len(matches) != 1 {
		t.Fatalf("matches = %+v (total %d), want one distinct id, not one row per artifact", matches, total)
	}
	if matches[0].ID != cve {
		t.Fatalf("id = %q, want %q", matches[0].ID, cve)
	}
	if matches[0].Artifacts != 2 {
		t.Fatalf("artifacts = %d, want 2 -- suppressed and fixed are not still affected", matches[0].Artifacts)
	}
	if matches[0].Severity != "critical" {
		t.Fatalf("severity = %q, want the worst seen (the two open rows are high and critical)", matches[0].Severity)
	}
	if matches[0].Title != title {
		t.Fatalf("title = %q, want %q", matches[0].Title, title)
	}

	list, err := s.FindByFindingID(cve)
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(list) != matches[0].Artifacts {
		t.Fatalf("search counted %d artifacts, FindByFindingID returned %d -- both halves must count the same population",
			matches[0].Artifacts, len(list))
	}

	// Searching the id itself, case-insensitively, and LIKE wildcards
	// treated as literal text.
	if m, _, err := s.SearchFindings("cve-2021-searchtest", 50); err != nil || len(m) != 1 {
		t.Fatalf("id search = %+v, %v", m, err)
	}
	if m, _, err := s.SearchFindings("log4jsearchtest%RCE", 50); err != nil || len(m) != 0 {
		t.Fatalf("wildcard-containing query = %+v, %v, want it treated literally (no match)", m, err)
	}
	if m, total, err := s.SearchFindings("log4jsearchtest", 0); err != nil || len(m) != 0 || total != 1 {
		t.Fatalf("limit 0 = %+v (total %d), %v, want the total still reported", m, total, err)
	}
	if m, total, err := s.SearchFindings("  ", 50); err != nil || len(m) != 0 || total != 0 {
		t.Fatalf("blank query = %+v (total %d), %v", m, total, err)
	}
}

// TestPostgresStore_Stats mirrors internal/api's MemStore stats tests
// against real SQL, where the aggregation risk lives: the two GROUP BYs,
// the active-finding predicate, and count(DISTINCT artifact_id). The two
// backends feed the same dashboard cards, so a disagreement between them
// is a number that changes meaning depending on which store is wired up.
//
// Everything is asserted as a DELTA, like TestPostgresStore_Count above:
// this database is shared with every other test in this file, so the
// only stable claim is how much this test's own rows moved each number.
func TestPostgresStore_Stats(t *testing.T) {
	s := newTestPostgresStore(t)

	before, err := s.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats (before): %v", err)
	}

	// A stage name nothing else in this file uses, so the by_stage
	// assertions below can't be confused by another test's leftovers.
	stage := fmt.Sprintf("statstest-%d", time.Now().UnixNano())

	mk := func(ref string, ty artifact.Type, mutate func(*artifact.Artifact)) string {
		t.Helper()
		a, err := s.Create(ref, ty)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if mutate != nil {
			if _, err := s.Update(a.ID, mutate); err != nil {
				t.Fatalf("Update: %v", err)
			}
		}
		return a.ID
	}

	// Three open CVEs on ONE artifact: the case that separates
	// count(DISTINCT artifact_id) from count(*). Also carries a malware
	// finding, so the per-bucket split can't be right by accident.
	mk(fmt.Sprintf("stats-multi-%d:1.0", time.Now().UnixNano()), artifact.TypeImage, func(a *artifact.Artifact) {
		a.Status = artifact.StatusScanned
		a.CurrentStage = stage
		a.CVEFindings = []artifact.Finding{
			{ID: "CVE-2024-STATS-1", Status: artifact.FindingStatusOpen},
			{ID: "CVE-2024-STATS-2", Status: artifact.FindingStatusOpen},
			{ID: "CVE-2024-STATS-3", Status: artifact.FindingStatusOpen},
		}
		a.MalwareFindings = []artifact.Finding{{ID: "Eicar-Stats-Test", Status: artifact.FindingStatusOpen}}
	})

	// Only resolved findings: on record, but not something this artifact
	// is still affected by, so it must not appear in with_findings at
	// all -- the case a missing active-finding predicate gets wrong.
	mk(fmt.Sprintf("stats-resolved-%d:1.0", time.Now().UnixNano()), artifact.TypeFile, func(a *artifact.Artifact) {
		a.Status = artifact.StatusScanned
		a.CurrentStage = stage
		a.CVEFindings = []artifact.Finding{
			{ID: "CVE-2024-STATS-4", Status: artifact.FindingStatusFixed},
			{ID: "CVE-2024-STATS-5", Status: artifact.FindingStatusNotAffected},
		}
	})

	// Left exactly as registered: no findings, no stage. Proves an
	// unstaged artifact lands under the empty-string key rather than
	// being dropped from by_stage entirely.
	mk(fmt.Sprintf("stats-bare-%d:1.0", time.Now().UnixNano()), artifact.TypeImage, nil)

	after, err := s.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats (after): %v", err)
	}

	if got := after.Total - before.Total; got != 3 {
		t.Fatalf("total moved by %d, want 3", got)
	}
	if got := after.ByStatus["scanned"] - before.ByStatus["scanned"]; got != 2 {
		t.Errorf("by_status[scanned] moved by %d, want 2", got)
	}
	if got := after.ByStatus["registered"] - before.ByStatus["registered"]; got != 1 {
		t.Errorf("by_status[registered] moved by %d, want 1", got)
	}
	if got := after.ByType["image"] - before.ByType["image"]; got != 2 {
		t.Errorf("by_type[image] moved by %d, want 2", got)
	}
	if got := after.ByType["file"] - before.ByType["file"]; got != 1 {
		t.Errorf("by_type[file] moved by %d, want 1", got)
	}

	// A stage nobody else used, so this is an absolute, not a delta.
	if after.ByStage[stage] != 2 {
		t.Errorf("by_stage[%q] = %d, want 2 (got %v)", stage, after.ByStage[stage], after.ByStage)
	}
	// current_stage is NOT NULL DEFAULT '', so the unstaged artifact is
	// counted under "" -- the same key MemStore uses, and deliberately
	// not a placeholder name that could collide with a configured stage.
	if got := after.ByStage[""] - before.ByStage[""]; got != 1 {
		t.Errorf("by_stage[\"\"] moved by %d, want 1 -- an unstaged artifact belongs under the empty key", got)
	}

	// One artifact with three open CVEs is ONE artifact with CVEs.
	if got := after.WithFindings["cve"] - before.WithFindings["cve"]; got != 1 {
		t.Errorf("with_findings[cve] moved by %d, want 1 -- three open CVEs on one artifact is one affected artifact", got)
	}
	if got := after.WithFindings["malware"] - before.WithFindings["malware"]; got != 1 {
		t.Errorf("with_findings[malware] moved by %d, want 1", got)
	}
	// The fixed/not_affected artifact contributed nothing, even though
	// both of its findings are still on record.
	for _, bucket := range []string{"misconfiguration", "secret", "other"} {
		if got := after.WithFindings[bucket] - before.WithFindings[bucket]; got != 0 {
			t.Errorf("with_findings[%s] moved by %d, want 0", bucket, got)
		}
	}

	// All five buckets are always present, zero included -- the one
	// closed set this endpoint reports in full. See artifact.Stats.
	for _, bucket := range []string{"cve", "malware", "misconfiguration", "secret", "other"} {
		if _, ok := after.WithFindings[bucket]; !ok {
			t.Errorf("with_findings has no %q key: %v", bucket, after.WithFindings)
		}
	}
}

// TestPostgresStore_CountAndDeleteOlderThan mirrors the MemStore
// retention tests against real SQL, where the risks are different: the
// bounded subselect (Postgres has no DELETE ... LIMIT), the ORDER BY
// that makes a capped run take the oldest, and ON DELETE CASCADE
// actually removing the children.
//
// Uses a cutoff in the FUTURE, like the MemStore tests: Update() stamps
// updated_at itself, so there is no way to write an old row through the
// store, and "everything is older than now+1h" exercises the same
// comparison. The shared database means every assertion here is scoped
// to rows this test created.
func TestPostgresStore_CountAndDeleteOlderThan(t *testing.T) {
	s := newTestPostgresStore(t)

	// A cutoff in the past that nothing in this database can be older
	// than, so the "not eligible" assertions can't be confused by other
	// tests' leftovers.
	longAgo := time.Now().UTC().Add(-3650 * 24 * time.Hour)
	if n, err := s.CountOlderThan(longAgo); err != nil {
		t.Fatalf("CountOlderThan: %v", err)
	} else if n != 0 {
		t.Fatalf("CountOlderThan(10 years ago) = %d, want 0", n)
	}

	prefix := fmt.Sprintf("prune-test-%d", time.Now().UnixNano())
	first, err := s.Create(prefix+"-a:1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Children, to prove the cascade fires for a pruned artifact the
	// same way it does for an explicit Delete.
	if _, err := s.Update(first.ID, func(a *artifact.Artifact) {
		a.CVEFindings = []artifact.Finding{{ID: prefix + "-CVE", Status: artifact.FindingStatusOpen}}
		a.StageHistory = []artifact.StageEvent{{Stage: "build", Timestamp: time.Now().UTC()}}
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.SaveComponents(first.ID, []artifact.Component{{PURL: prefix + "-purl", Name: "pkg"}}); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}
	second, err := s.Create(prefix+"-b:1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	before, err := s.CountOlderThan(futureCutoffPG())
	if err != nil {
		t.Fatalf("CountOlderThan: %v", err)
	}
	if before < 2 {
		t.Fatalf("CountOlderThan = %d, want at least the 2 rows this test created", before)
	}
	// Counting must not delete: the dry run is the only safety net for
	// an operation with no undo.
	if _, err := s.Get(first.ID); err != nil {
		t.Fatalf("artifact disappeared after a count: %v", err)
	}

	// Capped at one, and it must be the older of this test's two rows.
	// Scoped by checking which of ITS OWN rows survived -- the cap may
	// well consume another test's older row first, which is correct
	// behavior and not something to assert against.
	deleted, err := s.DeleteOlderThan(futureCutoffPG(), 1)
	if err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("DeleteOlderThan(limit 1) = %d, want exactly 1", deleted)
	}

	// Now remove everything, and verify this test's rows and their
	// children are gone.
	if _, err := s.DeleteOlderThan(futureCutoffPG(), 10000); err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	for _, id := range []string{first.ID, second.ID} {
		if _, err := s.Get(id); err == nil {
			t.Errorf("artifact %s survived a full prune", id)
		}
	}
	// The cascade: findings and components must not outlive the row.
	affected, err := s.FindByFindingID(prefix + "-CVE")
	if err != nil {
		t.Fatalf("FindByFindingID: %v", err)
	}
	if len(affected) != 0 {
		t.Errorf("pruned artifact's findings survived: %+v", affected)
	}
	containing, err := s.FindByComponentPURL(prefix + "-purl")
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(containing) != 0 {
		t.Errorf("pruned artifact's components survived: %+v", containing)
	}

	// A non-positive limit must never delete -- zero means "unlimited"
	// elsewhere in this codebase, and here that convention would empty
	// the table.
	other, err := s.Create(prefix+"-c:1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(other.ID) })
	for _, limit := range []int{0, -1} {
		if n, err := s.DeleteOlderThan(futureCutoffPG(), limit); err != nil || n != 0 {
			t.Fatalf("DeleteOlderThan(limit=%d) = %d, %v -- want 0", limit, n, err)
		}
	}
	if _, err := s.Get(other.ID); err != nil {
		t.Errorf("a non-positive limit deleted something: %v", err)
	}
}

func futureCutoffPG() time.Time { return time.Now().UTC().Add(time.Hour) }

// TestPostgresStore_ComponentHistory covers what only real SQL can get
// wrong here: the snapshot rows landing in the same transaction as the
// replace, the DISTINCT-scan_at retention DELETE (Postgres has no
// DELETE ... LIMIT, and the unit kept is a SNAPSHOT, not a row), and
// ON DELETE CASCADE taking the history with the artifact.
func TestPostgresStore_ComponentHistory(t *testing.T) {
	s := newTestPostgresStore(t)

	prefix := fmt.Sprintf("hist-%d", time.Now().UnixNano())
	a, err := s.Create(prefix+":1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(a.ID) })

	first := []artifact.Component{
		{PURL: prefix + "/openssl@3.1.4-r5", Name: "openssl", Version: "3.1.4-r5"},
		{PURL: prefix + "/busybox@1.36.1-r15", Name: "busybox", Version: "1.36.1-r15"},
	}
	second := []artifact.Component{
		{PURL: prefix + "/openssl@3.1.4-r6", Name: "openssl", Version: "3.1.4-r6"},
		{PURL: prefix + "/zlib@1.3-r0", Name: "zlib", Version: "1.3-r0"},
	}
	for _, set := range [][]artifact.Component{first, second} {
		if err := s.SaveComponents(a.ID, set); err != nil {
			t.Fatalf("SaveComponents: %v", err)
		}
	}

	snaps, err := s.ComponentSnapshots(a.ID, 0)
	if err != nil {
		t.Fatalf("ComponentSnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("got %d snapshots, want 2 -- two SaveComponents calls must not collapse into one", len(snaps))
	}
	// Newest first.
	if !snaps[0].After(snaps[1]) {
		t.Fatalf("snapshots not newest-first: %s then %s", snaps[0], snaps[1])
	}

	older, err := s.ComponentsAt(a.ID, snaps[1])
	if err != nil {
		t.Fatalf("ComponentsAt(older): %v", err)
	}
	newer, err := s.ComponentsAt(a.ID, snaps[0])
	if err != nil {
		t.Fatalf("ComponentsAt(newer): %v", err)
	}
	// The same diff the MemStore test asserts, so the two backends
	// cannot disagree about what a snapshot pair means.
	diff := artifact.DiffComponents(older, newer)
	if len(diff.Added) != 1 || diff.Added[0].Name != "zlib" {
		t.Errorf("added = %+v, want just zlib", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Name != "busybox" {
		t.Errorf("removed = %+v, want just busybox", diff.Removed)
	}
	if len(diff.VersionChanged) != 1 || diff.VersionChanged[0].To != "3.1.4-r6" {
		t.Errorf("version_changed = %+v, want openssl -> 3.1.4-r6", diff.VersionChanged)
	}

	// The current inventory is still latest-only: the history is
	// additional, not a replacement for the components table's contract.
	if containing, err := s.FindByComponentPURL(prefix + "/busybox@1.36.1-r15"); err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	} else if len(containing) != 0 {
		t.Errorf("a package only present in an OLD snapshot still answers component search: %+v", containing)
	}

	// Retention: past the cap, the oldest snapshots are evicted and
	// exactly MaxComponentSnapshots distinct scan_at values remain.
	for i := 0; i < artifact.MaxComponentSnapshots+3; i++ {
		if err := s.SaveComponents(a.ID, first); err != nil {
			t.Fatalf("SaveComponents (retention loop): %v", err)
		}
	}
	capped, err := s.ComponentSnapshots(a.ID, 0)
	if err != nil {
		t.Fatalf("ComponentSnapshots: %v", err)
	}
	if len(capped) != artifact.MaxComponentSnapshots {
		t.Fatalf("got %d snapshots, want the cap of %d", len(capped), artifact.MaxComponentSnapshots)
	}
	// The very first snapshot must be gone, and the newest must survive
	// -- the DELETE runs after the insert precisely so the row being
	// written is among the ones it keeps.
	for _, ts := range capped {
		if ts.Equal(snaps[1]) {
			t.Errorf("the oldest snapshot survived past the cap")
		}
	}
	if rows, err := s.ComponentsAt(a.ID, capped[0]); err != nil || len(rows) == 0 {
		t.Errorf("the newest snapshot has no rows (%v, %v) -- the retention DELETE ran before the insert", rows, err)
	}

	// ON DELETE CASCADE.
	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gone, err := s.ComponentSnapshots(a.ID, 0); err != nil || len(gone) != 0 {
		t.Errorf("component history survived the artifact: %v (%v)", gone, err)
	}
}

// Licenses have to survive the round trip through both component
// tables, and FindByLicense's per-identifier matching is SQL
// (unnest + string_to_array) that no MemStore test exercises.
func TestPostgresStore_ComponentLicenses(t *testing.T) {
	s := newTestPostgresStore(t)

	prefix := fmt.Sprintf("lic-%d", time.Now().UnixNano())
	a, err := s.Create(prefix+":1.0", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(a.ID) })

	components := []artifact.Component{
		{PURL: prefix + "/bad@1", Name: "bad", Version: "1", Licenses: "AGPL-3.0-only"},
		{PURL: prefix + "/dual@1", Name: "dual", Version: "1", Licenses: "MIT,Apache-2.0"},
		{PURL: prefix + "/expr@1", Name: "expr", Version: "1", Licenses: "MIT OR AGPL-3.0-only"},
		{PURL: prefix + "/none@1", Name: "none", Version: "1"},
	}
	if err := s.SaveComponents(a.ID, components); err != nil {
		t.Fatalf("SaveComponents: %v", err)
	}

	// Round trip through components_history, so a diff's entries carry
	// licenses too rather than being silently license-less.
	snaps, err := s.ComponentSnapshots(a.ID, 1)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("ComponentSnapshots = %v, %v", snaps, err)
	}
	at, err := s.ComponentsAt(a.ID, snaps[0])
	if err != nil {
		t.Fatalf("ComponentsAt: %v", err)
	}
	var sawDual bool
	for _, c := range at {
		if c.PURL == prefix+"/dual@1" {
			sawDual = true
			if c.Licenses != "MIT,Apache-2.0" {
				t.Errorf("history licenses = %q, want MIT,Apache-2.0", c.Licenses)
			}
		}
	}
	if !sawDual {
		t.Error("the dual-licensed component is missing from the snapshot")
	}

	// Exact, per-identifier, case-insensitive.
	for _, tc := range []struct {
		license string
		want    int
		why     string
	}{
		{"AGPL-3.0-only", 1, "exact"},
		{"agpl-3.0-only", 1, "case-insensitive"},
		{"Apache-2.0", 1, "one entry of a comma-joined list"},
		{"MIT", 1, "the other entry"},
		{"GPL-3.0-only", 0, "must not match AGPL-3.0-only as a substring"},
		{"Zlib", 0, "nothing carries it"},
	} {
		got, err := s.FindByLicense(tc.license)
		if err != nil {
			t.Fatalf("FindByLicense(%s): %v", tc.license, err)
		}
		// Scoped to this test's artifact -- the database is shared.
		n := 0
		for _, x := range got {
			if x.ID == a.ID {
				n++
			}
		}
		if n != tc.want {
			t.Errorf("FindByLicense(%q) matched this artifact %d times, want %d -- %s", tc.license, n, tc.want, tc.why)
		}
	}

	// The picker carries them too.
	matches, _, err := s.SearchComponents(prefix+"/dual", 10)
	if err != nil {
		t.Fatalf("SearchComponents: %v", err)
	}
	if len(matches) != 1 || matches[0].Licenses != "MIT,Apache-2.0" {
		t.Errorf("SearchComponents = %+v, want one match carrying its licenses", matches)
	}
}

// scanSlotCount is a direct row count, bypassing the store, so the
// assertions below check the TABLE rather than what the API believes.
func scanSlotCount(t *testing.T, kind string) int {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM scan_slots WHERE scanner_kind = $1`, kind).Scan(&n); err != nil {
		t.Fatalf("count scan_slots: %v", err)
	}
	return n
}

func clearScanSlots(t *testing.T) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `DELETE FROM scan_slots`); err != nil {
		t.Fatalf("clear scan_slots: %v", err)
	}
}

// THE TEST THIS FEATURE EXISTS FOR. `INSERT ... SELECT WHERE count <
// cap` does NOT serialize under READ COMMITTED: two transactions racing
// for the last slot each count against their own snapshot, neither sees
// the other's uncommitted row, both find count = cap-1, and both
// insert. The cap is exceeded silently, under exactly the concurrent
// load it exists to bound.
//
// So this races many acquirers at a cap of ONE and asserts exactly one
// won. Two sequential acquirers would pass whether or not the advisory
// lock is there, which is why this is shaped as a race.
func TestPostgresStore_AcquireScanSlotsIsExclusiveUnderRace(t *testing.T) {
	s := newTestPostgresStore(t)
	clearScanSlots(t)
	t.Cleanup(func() { clearScanSlots(t) })

	const kind = "racetest"
	// 16 racers over several rounds. Both numbers are tuned, not
	// decorative: with the advisory lock removed this shape violates the
	// cap in 59 of 60 measured rounds, while a handful of racers in a
	// single round passes comfortably without it -- a test that cannot
	// fail is worse than no test, since it certifies the exact bug it
	// was written to catch.
	const (
		racers = 16
		rounds = 5
	)

	var acquired []string
	for round := 0; round < rounds; round++ {
		clearScanSlots(t)

		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			failures []error
		)
		acquired = nil
		start := make(chan struct{})

		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				holder := fmt.Sprintf("racer-%d-%d-%d", time.Now().UnixNano(), round, i)
				<-start // release them all at once
				res, err := s.AcquireScanSlots(artifact.ScanSlotRequest{
					HolderID:   holder,
					Kinds:      []string{kind},
					Caps:       map[string]int{kind: 1},
					StaleAfter: time.Hour,
				})
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					failures = append(failures, err)
					return
				}
				if res.Acquired {
					acquired = append(acquired, holder)
				}
			}(i)
		}
		close(start)
		wg.Wait()

		for _, err := range failures {
			t.Errorf("round %d: acquire errored: %v", round, err)
		}
		if len(acquired) != 1 {
			t.Fatalf("round %d: %d of %d racers acquired a cap-1 slot, want exactly 1 -- the count is being evaluated against a stale snapshot, so two transactions both saw a free slot",
				round, len(acquired), racers)
		}
		if n := scanSlotCount(t, kind); n != 1 {
			t.Fatalf("round %d: scan_slots holds %d rows for a cap of 1, want 1", round, n)
		}
	}

	// The winner releasing frees it for the next acquirer, and nobody
	// else's release can take it away.
	if err := s.ReleaseScanSlots("some-other-holder"); err != nil {
		t.Fatalf("releasing an unrelated holder: %v", err)
	}
	if n := scanSlotCount(t, kind); n != 1 {
		t.Fatalf("releasing an unrelated holder freed %d rows -- a holder must only free its own", 1-n)
	}
	if err := s.ReleaseScanSlots(acquired[0]); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if n := scanSlotCount(t, kind); n != 0 {
		t.Fatalf("scan_slots holds %d rows after release, want 0", n)
	}
}

// All-or-nothing across kinds: a scan blocked on ONE saturated cap must
// not leave slots held for the kinds that were free.
func TestPostgresStore_AcquireScanSlotsIsAllOrNothing(t *testing.T) {
	s := newTestPostgresStore(t)
	clearScanSlots(t)
	t.Cleanup(func() { clearScanSlots(t) })

	const heavy, light = "heavytest", "lighttest"
	caps := map[string]int{heavy: 1, light: 5}

	first, err := s.AcquireScanSlots(artifact.ScanSlotRequest{
		HolderID: "first", Kinds: []string{heavy, light}, Caps: caps, StaleAfter: time.Hour,
	})
	if err != nil || !first.Acquired {
		t.Fatalf("first acquire = %+v, %v", first, err)
	}

	// heavy is now full; light is not.
	second, err := s.AcquireScanSlots(artifact.ScanSlotRequest{
		HolderID: "second", Kinds: []string{heavy, light}, Caps: caps, StaleAfter: time.Hour,
	})
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if second.Acquired {
		t.Fatal("second acquire succeeded despite the heavy cap being full")
	}
	if second.BlockedKind != heavy {
		t.Errorf("BlockedKind = %q, want %q -- the 429 has to name the cap that refused", second.BlockedKind, heavy)
	}
	if n := scanSlotCount(t, light); n != 1 {
		t.Errorf("a rejected acquisition left %d light slots held, want only the first holder's 1", n)
	}
}

// A pod killed between acquiring and releasing leaves its rows behind.
// Reaping is what stops that from saturating a cap forever, and it runs
// inside acquisition because that is the only moment anyone cares.
func TestPostgresStore_AcquireScanSlotsReapsAbandonedSlots(t *testing.T) {
	s := newTestPostgresStore(t)
	clearScanSlots(t)
	t.Cleanup(func() { clearScanSlots(t) })

	const kind = "reaptest"
	caps := map[string]int{kind: 1}

	if res, err := s.AcquireScanSlots(artifact.ScanSlotRequest{
		HolderID: "abandoned", Kinds: []string{kind}, Caps: caps, StaleAfter: time.Hour,
	}); err != nil || !res.Acquired {
		t.Fatalf("setup acquire = %+v, %v", res, err)
	}
	// Never released -- the process "died" here.

	// Still held while it is within the staleness window.
	if res, _ := s.AcquireScanSlots(artifact.ScanSlotRequest{
		HolderID: "next", Kinds: []string{kind}, Caps: caps, StaleAfter: time.Hour,
	}); res.Acquired {
		t.Fatal("a slot inside its staleness window was reaped -- a slow but healthy scan would lose its slot")
	}

	// Past the window, it is reaped and the slot is available again.
	res, err := s.AcquireScanSlots(artifact.ScanSlotRequest{
		HolderID: "next", Kinds: []string{kind}, Caps: caps, StaleAfter: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("acquire after staleness: %v", err)
	}
	if !res.Acquired {
		t.Fatal("an abandoned slot past its staleness window was not reaped")
	}
	if n := scanSlotCount(t, kind); n != 1 {
		t.Errorf("scan_slots holds %d rows, want 1 (the abandoned one reaped, the new one held)", n)
	}
}

// A kind with no cap configured is unbounded -- the behaviour every
// scanner had before per-kind caps existed.
func TestPostgresStore_AcquireScanSlotsUncappedKindIsUnlimited(t *testing.T) {
	s := newTestPostgresStore(t)
	clearScanSlots(t)
	t.Cleanup(func() { clearScanSlots(t) })

	const kind = "uncappedtest"
	for i := 0; i < 5; i++ {
		res, err := s.AcquireScanSlots(artifact.ScanSlotRequest{
			HolderID: fmt.Sprintf("h%d", i), Kinds: []string{kind},
			Caps: map[string]int{}, StaleAfter: time.Hour,
		})
		if err != nil || !res.Acquired {
			t.Fatalf("acquire %d = %+v, %v -- an uncapped kind must never refuse", i, res, err)
		}
	}
}

// TestPostgresStore_UnsafeRoundTrips is a regression test for a field
// that existed on the model, was set at registration, and was rendered
// by the dashboard for months without ever being persisted.
//
// Artifact.Unsafe had no column and appeared in no INSERT, SELECT or
// UPDATE, so it was always false when read back -- which, with the
// Postgres store, is every read in production. MemStore keeps the whole
// struct in memory, so every test that used it passed, and the
// dashboard's "Unsafe" badge was dead code nobody could have noticed
// from the outside: the badge simply never appeared, which looks
// exactly like "no unsafe artifacts".
//
// It surfaced only when internal/policy's disallowUnsafe rule was about
// to be switched on and the artifacts table turned out to have no such
// column -- i.e. a policy gate that could never fire.
func TestPostgresStore_UnsafeRoundTrips(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.Unsafe {
		t.Fatal("a freshly created artifact is unsafe")
	}

	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.Unsafe = true
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Read back through Get -- a fresh query, not the value Update
	// happened to return, which is what made this look fine for months.
	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Unsafe {
		t.Fatal("unsafe did not survive a write/read round trip -- the dashboard badge and policy's disallowUnsafe both depend on this")
	}

	// And it must be clearable, not a one-way latch: a re-registration
	// that now resolves cleanly has to be able to take the mark off.
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.Unsafe = false
	}); err != nil {
		t.Fatalf("Update (clearing): %v", err)
	}
	cleared, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get after clearing: %v", err)
	}
	if cleared.Unsafe {
		t.Fatal("unsafe could be set but not cleared")
	}

	// It must also survive List, which uses the same column list via
	// selectArtifactColumns but a different scan path.
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) { art.Unsafe = true }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, item := range list {
		if item.ID == a.ID {
			found = true
			if !item.Unsafe {
				t.Error("unsafe is set in Get but not in List -- the list view renders this badge too")
			}
		}
	}
	if !found {
		t.Fatalf("artifact %s not in the list", a.ID)
	}
}

// TestPostgresStore_EnrichmentRoundTrips covers the two new findings
// columns and the feed tables.
//
// This file is where a forgotten column reads back as a zero value and
// nothing complains -- exactly how Artifact.Unsafe went months without
// being persisted. epss_score and known_exploited have the same shape
// of risk: their "no data" values are indistinguishable from a genuine
// negative, so a column missing from loadFindings' explicit list would
// make every finding look not-exploited forever.
func TestPostgresStore_EnrichmentRoundTrips(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = []artifact.Finding{
			{ID: "CVE-2024-1111", Severity: "high", EPSSScore: 0.97231, KnownExploited: true},
			{ID: "CVE-2024-2222", Severity: "low", EPSSScore: 0.00042},
		}
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Read back through a FRESH Get, not the value Update returned --
	// that is the distinction that made Unsafe look fine for months.
	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.CVEFindings) != 2 {
		t.Fatalf("findings = %+v", got.CVEFindings)
	}
	byID := map[string]artifact.Finding{}
	for _, f := range got.CVEFindings {
		byID[f.ID] = f
	}
	if f := byID["CVE-2024-1111"]; !f.KnownExploited || f.EPSSScore != 0.97231 {
		t.Errorf("CVE-2024-1111 = %+v, want known_exploited and its EPSS score to survive", f)
	}
	if f := byID["CVE-2024-2222"]; f.KnownExploited || f.EPSSScore != 0.00042 {
		t.Errorf("CVE-2024-2222 = %+v, want epss preserved and known_exploited false", f)
	}
}

func TestPostgresStore_ReplaceAndLookupEnrichment(t *testing.T) {
	s := newTestPostgresStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.ReplaceEnrichment(
		[]string{"CVE-2024-1111"},
		map[string]float64{"CVE-2024-1111": 0.9, "CVE-2024-2222": 0.1},
		now,
	); err != nil {
		t.Fatalf("ReplaceEnrichment: %v", err)
	}

	found, err := s.LookupEnrichment([]string{"CVE-2024-1111", "CVE-2024-2222", "CVE-1999-0001"})
	if err != nil {
		t.Fatalf("LookupEnrichment: %v", err)
	}
	if e := found["CVE-2024-1111"]; !e.KnownExploited || e.EPSSScore != 0.9 {
		t.Errorf("CVE-2024-1111 = %+v", e)
	}
	if e := found["CVE-2024-2222"]; e.KnownExploited || e.EPSSScore != 0.1 {
		t.Errorf("CVE-2024-2222 = %+v", e)
	}
	// A CVE with no row is ABSENT, not a zero entry -- the caller uses
	// that difference to leave findings unenriched rather than stamping
	// them not-exploited.
	if _, ok := found["CVE-1999-0001"]; ok {
		t.Error("an unknown CVE came back as a zero-valued entry instead of being absent")
	}

	st, err := s.EnrichmentStatus()
	if err != nil {
		t.Fatalf("EnrichmentStatus: %v", err)
	}
	if st.KEVEntries != 1 || st.EPSSEntries != 2 {
		t.Errorf("status = %+v, want 1 kev and 2 epss entries", st)
	}
	if st.KEVUpdatedAt == nil || st.EPSSUpdatedAt == nil {
		t.Fatalf("status timestamps not recorded: %+v", st)
	}
	if !st.Fresh(now, time.Hour) {
		t.Error("feeds refreshed just now report as stale")
	}
	if st.Fresh(now.Add(48*time.Hour), time.Hour) {
		t.Error("feeds two days old report as fresh")
	}

	// A CVE dropping OUT of KEV is a real state change. Replacement is
	// wholesale for exactly this: a merge would leave the old row
	// asserting known_exploited forever.
	if err := s.ReplaceEnrichment([]string{"CVE-2024-3333"}, nil, now); err != nil {
		t.Fatalf("second ReplaceEnrichment: %v", err)
	}
	found, err = s.LookupEnrichment([]string{"CVE-2024-1111", "CVE-2024-3333"})
	if err != nil {
		t.Fatalf("LookupEnrichment: %v", err)
	}
	if found["CVE-2024-1111"].KnownExploited {
		t.Error("a CVE that left the KEV catalog is still flagged known_exploited")
	}
	if !found["CVE-2024-3333"].KnownExploited {
		t.Error("a CVE newly added to KEV was not flagged")
	}
	// ...and passing nil for EPSS left the scores alone.
	if found["CVE-2024-1111"].EPSSScore != 0.9 {
		t.Errorf("a nil EPSS feed wiped the stored scores: %+v", found["CVE-2024-1111"])
	}
}

// TestPostgresStore_ListCarriesEnrichment guards the SECOND path that
// reads findings.
//
// Get uses loadFindings; List/ListPage use fillChildrenBatch. A column
// added to one and not the other is invisible -- the field reads back
// as its zero value on whichever path forgot it, and nothing errors.
// epss_score/known_exploited shipped exactly that way: the artifact
// endpoint returned them correctly while the list did not, so the
// dashboard (which renders detail pages from the list payload) showed
// no KEV badges at all.
//
// Asserts the two paths AGREE rather than checking one in isolation,
// because agreement is the actual property.
func TestPostgresStore_ListCarriesEnrichment(t *testing.T) {
	s := newTestPostgresStore(t)

	a, err := s.Create("alpine:3.19", artifact.TypeImage)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Update(a.ID, func(art *artifact.Artifact) {
		art.CVEFindings = []artifact.Finding{
			{ID: "CVE-2023-44487", Severity: "high", EPSSScore: 0.99999, KnownExploited: true},
		}
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	fromGet, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	page, _, err := s.ListPage(50, 0, "", "")
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	var fromList *artifact.Artifact
	for _, item := range page {
		if item.ID == a.ID {
			fromList = item
		}
	}
	if fromList == nil {
		t.Fatalf("artifact %s missing from the page", a.ID)
	}

	if len(fromList.CVEFindings) != 1 {
		t.Fatalf("list findings = %+v", fromList.CVEFindings)
	}
	g, l := fromGet.CVEFindings[0], fromList.CVEFindings[0]
	if g.KnownExploited != l.KnownExploited || g.EPSSScore != l.EPSSScore {
		t.Fatalf("Get and List disagree about enrichment:\n  Get : known=%v epss=%v\n  List: known=%v epss=%v",
			g.KnownExploited, g.EPSSScore, l.KnownExploited, l.EPSSScore)
	}
	if !l.KnownExploited {
		t.Error("known_exploited did not survive the list path -- the dashboard renders detail pages from this payload")
	}

	// Same for List(), which uses the same batch loader.
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, item := range all {
		if item.ID == a.ID && !item.CVEFindings[0].KnownExploited {
			t.Error("known_exploited did not survive List() either")
		}
	}
}
