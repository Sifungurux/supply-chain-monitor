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

	countRows := func(table string) int {
		t.Helper()
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE artifact_id = $1", a.ID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}

	if countRows("findings") == 0 || countRows("stage_history") == 0 || countRows("scan_errors") == 0 || countRows("artifact_documents") == 0 {
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

	for _, table := range []string{"findings", "stage_history", "scan_errors", "artifact_documents"} {
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
		}, firstScan, true)
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
		art.CVEFindings = artifact.MergeFindings(art.CVEFindings, nil, secondScan, true)
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
