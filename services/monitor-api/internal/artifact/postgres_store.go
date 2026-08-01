package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists artifacts in Postgres. It's the Store
// implementation main.go wires up in production -- see
// docs/architecture.md ("Swapping the in-memory store for Postgres")
// for why MemStore was replaced and what tradeoffs this brings.
//
// Findings and stage history live in their own tables (stage_history,
// findings, scan_errors), one row per event/finding, rather than as
// JSONB blobs on the artifacts row -- see docs/architecture.md,
// "Normalizing findings and stage history into their own tables," for
// why this changed from the original single-table JSONB design and
// what it enables (FindByFindingID, an indexed "every artifact with
// CVE X" query that a JSONB blob couldn't answer without scanning
// every row).
type PostgresStore struct {
	pool *pgxpool.Pool
}

// Bucket names used in the findings table's bucket column. Kept as
// constants rather than repeating the string literals so a typo in
// one of them is a compile error, not a silently-wrong WHERE clause.
const (
	bucketCVE              = "cve"
	bucketMalware          = "malware"
	bucketMisconfiguration = "misconfiguration"
	bucketSecret           = "secret"
	bucketOther            = "other"
)

// schemaStatements is deliberately a slice of individual single-
// statement strings, each run through its own Exec call (see
// migrate() below), rather than one semicolon-separated blob run
// through a single Exec. pgx's default query-execution mode uses
// Postgres's extended (prepared-statement) protocol, which only
// accepts one statement per Parse message -- unlike the simple
// protocol, it does NOT support multiple ;-separated statements in a
// single call. Splitting these up front avoids depending on pgx's
// query-exec-mode internals at all.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS artifacts (
		id            TEXT PRIMARY KEY,
		ref           TEXT NOT NULL,
		type          TEXT NOT NULL,
		status        TEXT NOT NULL,
		current_stage TEXT NOT NULL DEFAULT '',
		created_at    TIMESTAMPTZ NOT NULL,
		updated_at    TIMESTAMPTZ NOT NULL
	)`,
	// List() and FindByFindingID both `ORDER BY created_at DESC` over
	// the whole artifacts table -- without an index, that's a full
	// table scan plus an explicit sort on every single call, and both
	// are hit on every dashboard load. Deliberately NOT indexing
	// status or updated_at here even though they're an obvious-looking
	// next target: neither column is actually filtered or sorted on
	// anywhere in this codebase today (checked -- every WHERE clause on
	// this table is `WHERE id = $1`), so an index on either would be
	// pure write-path overhead (every INSERT/UPDATE has to maintain it)
	// for zero current benefit. Add one if/when a real query needs it,
	// e.g. a "show only failed artifacts" filter.
	`CREATE INDEX IF NOT EXISTS artifacts_created_at_idx ON artifacts (created_at DESC)`,
	// Added for digest-based duplicate-registration detection (see
	// FindByDigest below and internal/api/handlers.go). Same
	// ADD COLUMN IF NOT EXISTS idempotency as the findings.status et al.
	// migration below -- safe to run unconditionally on every startup,
	// including against a table created before this feature existed.
	// DEFAULT '' (not NULL): FindByDigest and every digest comparison in
	// this file treat "" as "no digest resolved," never a match, so
	// there's no NULL-handling special case to get wrong in a WHERE
	// clause -- see FindByDigest's own `AND digest != ''` guard.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS digest TEXT NOT NULL DEFAULT ''`,
	// Partial index (only non-empty digests): every artifact starts
	// with digest = '' until best-effort resolution succeeds (or never,
	// for local-path file/sbom/sarif refs -- see Artifact.Digest's
	// comment), so indexing '' values for every such row would be pure
	// write-path overhead for a value FindByDigest never searches for.
	`CREATE INDEX IF NOT EXISTS artifacts_digest_idx ON artifacts (digest) WHERE digest != ''`,
	// Added for the dashboard's Details modal (see Artifact.LastScanAt's
	// comment) -- same idempotent ADD COLUMN IF NOT EXISTS as digest
	// above. NULL (not a zero-value default) is deliberate: it's the
	// natural "never scanned yet" state, matching the Go field being a
	// *time.Time.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ`,
	// Added for maintainer team/contact metadata (see Artifact.MaintainerTeam's
	// comment) -- same idempotent ADD COLUMN IF NOT EXISTS pattern as
	// digest/last_scan_at above. DEFAULT '' (not NULL), matching digest:
	// every comparison/emptiness check in this codebase already treats
	// "" as "not set," so there's no separate NULL case to handle.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS maintainer_team TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS maintainer_email TEXT NOT NULL DEFAULT ''`,
	`CREATE TABLE IF NOT EXISTS stage_history (
		id          BIGSERIAL PRIMARY KEY,
		artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		stage       TEXT NOT NULL,
		note        TEXT NOT NULL DEFAULT '',
		occurred_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS stage_history_artifact_id_idx ON stage_history (artifact_id)`,
	`CREATE TABLE IF NOT EXISTS findings (
		id          BIGSERIAL PRIMARY KEY,
		artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		bucket      TEXT NOT NULL, -- 'cve' | 'malware' | 'misconfiguration' | 'secret' | 'other', see bucketCVE etc.
		finding_id  TEXT NOT NULL, -- e.g. "CVE-2024-1234" or "clamav-signature-match"
		severity    TEXT NOT NULL DEFAULT '',
		title       TEXT NOT NULL DEFAULT '',
		source      TEXT NOT NULL DEFAULT '' -- e.g. "trivy", "clamav", "sarif"
	)`,
	`CREATE INDEX IF NOT EXISTS findings_artifact_id_idx ON findings (artifact_id)`,
	// Added for finding lifecycle tracking (see merge.go's MergeFindings
	// and docs/architecture.md, "Tracking finding lifecycle: open vs
	// fixed"). `ADD COLUMN IF NOT EXISTS` is idempotent the same way the
	// `CREATE TABLE IF NOT EXISTS` statements above are, so these are
	// safe to run unconditionally on every startup, including against a
	// findings table created before this feature existed -- no separate
	// migrate-if-old-schema branch needed the way
	// migrateLegacyJSONBColumns had to for the earlier JSONB->normalized
	// migration, since ADD COLUMN IF NOT EXISTS already covers "this
	// might already exist" cleanly. DEFAULT NOW() on first_seen_at means
	// pre-existing rows (findings persisted before this migration ran)
	// get stamped with the migration time, not their real original
	// discovery date, which was never recorded -- an approximation,
	// clearly not a fabricated history, and the best available given
	// that data was never captured.
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open'`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ`,
	// Powers FindByFindingID -- "every artifact still affected by
	// CVE-2024-X" -- without scanning every artifact's findings, which
	// is exactly the query the old JSONB-blob schema couldn't answer
	// well.
	`CREATE INDEX IF NOT EXISTS findings_finding_id_idx ON findings (finding_id)`,
	`CREATE TABLE IF NOT EXISTS scan_errors (
		id          BIGSERIAL PRIMARY KEY,
		artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		error       TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS scan_errors_artifact_id_idx ON scan_errors (artifact_id)`,
}

const selectArtifactColumns = `SELECT id, ref, digest, type, status, current_stage, created_at, updated_at, last_scan_at, maintainer_team, maintainer_email FROM artifacts`

// pgxIface is satisfied by both *pgxpool.Pool and pgx.Tx, so the
// read/write helpers below can run either directly against the pool
// (Get/List, no transaction needed) or against an in-flight
// transaction (Update, which needs FOR UPDATE + multiple statements to
// commit atomically) without duplicating a single one of them.
type pgxIface interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// NewPostgresStore connects to Postgres using dsn (a standard
// "postgres://user:pass@host:port/db?sslmode=..." URL), verifies the
// connection with a ping, and ensures the schema exists (creating it
// fresh, or migrating an older single-table JSONB deployment in place
// -- see migrate() below).
//
// Deliberately fails fast rather than retrying internally -- Postgres
// and monitor-api start up concurrently in Kubernetes, so there's no
// guarantee the database is accepting connections yet the first time
// this runs. Callers should retry around this call (see main.go's
// connectStoreWithRetry) instead of this function silently blocking or
// looping.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return s, nil
}

// Close releases the underlying connection pool. Not called on every
// pod exit today (Kubernetes just kills the pod and Postgres cleans up
// server-side), but useful for tests and any future graceful-shutdown
// path.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	for _, stmt := range schemaStatements {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("create tables: %w", err)
		}
	}
	return s.migrateLegacyJSONBColumns(ctx)
}

// migrateLegacyJSONBColumns is a one-time, idempotent migration for
// clusters created before findings/stage history moved into their own
// tables. `CREATE TABLE IF NOT EXISTS` above is a no-op on an
// already-existing artifacts table, so an older deployment's
// stage_history/cve_findings/malware_findings/last_scan_errors JSONB
// columns would otherwise just sit there unused (harmless, but stale
// and confusing) while every write went to the new tables instead,
// silently orphaning old data. This checks whether those columns still
// exist, and if so, copies their contents into the new normalized
// tables before dropping them -- so upgrading an existing cluster
// (`make deploy` against one already running the old schema) preserves
// its data instead of requiring a wipe.
//
// Note: the old schema never had a column for OtherFindings (SARIF
// results) at all -- it was added to the Artifact struct after the
// original single-table design shipped, but the JSONB persistence
// layer was never updated to match, so OtherFindings silently never
// persisted past the single HTTP response that set it. That's a real
// bug this migration incidentally fixes going forward (the new
// findings table has a proper 'other' bucket); there's simply nothing
// to migrate for it from the old schema, since it was never actually
// stored.
func (s *PostgresStore) migrateLegacyJSONBColumns(ctx context.Context) error {
	// 'artifacts'::regclass resolves the unqualified table name the
	// exact same way every other unqualified "FROM artifacts"/"INSERT
	// INTO artifacts" statement in this file does -- via whatever
	// schema is first on the connection's search_path -- unlike
	// information_schema.columns, which isn't search_path-aware and
	// would happily report a match from a same-named table sitting in
	// a totally unrelated schema.
	var hasLegacyColumn bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_attribute
			WHERE attrelid = 'artifacts'::regclass
			  AND attname = 'stage_history'
			  AND NOT attisdropped
		)
	`).Scan(&hasLegacyColumn)
	if err != nil {
		return fmt.Errorf("check for legacy jsonb columns: %w", err)
	}
	if !hasLegacyColumn {
		return nil
	}

	log.Printf("postgres: found the old single-table JSONB schema -- migrating stage history and findings into normalized tables (one-time, see docs/architecture.md, %q)",
		"Normalizing findings and stage history into their own tables")

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once Commit has succeeded

	type legacyRow struct {
		id                                                         string
		stageHistory, cveFindings, malwareFindings, lastScanErrors []byte
	}
	rows, err := tx.Query(ctx, `SELECT id, stage_history, cve_findings, malware_findings, last_scan_errors FROM artifacts`)
	if err != nil {
		return fmt.Errorf("read legacy jsonb data: %w", err)
	}
	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.id, &r.stageHistory, &r.cveFindings, &r.malwareFindings, &r.lastScanErrors); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy row: %w", err)
		}
		legacy = append(legacy, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read legacy jsonb data: %w", err)
	}
	rows.Close()

	for _, r := range legacy {
		var stageHistory []StageEvent
		var cveFindings, malwareFindings []Finding
		var lastScanErrors []string
		if err := json.Unmarshal(r.stageHistory, &stageHistory); err != nil {
			return fmt.Errorf("decode legacy stage_history for %s: %w", r.id, err)
		}
		if err := json.Unmarshal(r.cveFindings, &cveFindings); err != nil {
			return fmt.Errorf("decode legacy cve_findings for %s: %w", r.id, err)
		}
		if err := json.Unmarshal(r.malwareFindings, &malwareFindings); err != nil {
			return fmt.Errorf("decode legacy malware_findings for %s: %w", r.id, err)
		}
		if err := json.Unmarshal(r.lastScanErrors, &lastScanErrors); err != nil {
			return fmt.Errorf("decode legacy last_scan_errors for %s: %w", r.id, err)
		}

		for _, e := range stageHistory {
			if _, err := tx.Exec(ctx, `INSERT INTO stage_history (artifact_id, stage, note, occurred_at) VALUES ($1, $2, $3, $4)`,
				r.id, e.Stage, e.Note, e.Timestamp); err != nil {
				return fmt.Errorf("migrate stage_history for %s: %w", r.id, err)
			}
		}
		for _, f := range cveFindings {
			if err := insertFinding(ctx, tx, r.id, bucketCVE, f); err != nil {
				return fmt.Errorf("migrate cve_findings for %s: %w", r.id, err)
			}
		}
		for _, f := range malwareFindings {
			if err := insertFinding(ctx, tx, r.id, bucketMalware, f); err != nil {
				return fmt.Errorf("migrate malware_findings for %s: %w", r.id, err)
			}
		}
		for _, msg := range lastScanErrors {
			if _, err := tx.Exec(ctx, `INSERT INTO scan_errors (artifact_id, error) VALUES ($1, $2)`, r.id, msg); err != nil {
				return fmt.Errorf("migrate last_scan_errors for %s: %w", r.id, err)
			}
		}
	}

	if _, err := tx.Exec(ctx, `
		ALTER TABLE artifacts
			DROP COLUMN stage_history,
			DROP COLUMN cve_findings,
			DROP COLUMN malware_findings,
			DROP COLUMN last_scan_errors
	`); err != nil {
		return fmt.Errorf("drop legacy jsonb columns: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	log.Printf("postgres: migration complete -- migrated %d artifacts' findings/stage history into normalized tables", len(legacy))
	return nil
}

// insertFinding defaults Status/FirstSeenAt when a caller hands it a
// Finding that doesn't have them set -- true for every finding
// migrateLegacyJSONBColumns copies in (json.Unmarshal'd from the old
// schema, which never had these fields at all), and harmless for the
// normal path (MergeFindings, in every other caller, always sets both
// explicitly before a Finding ever reaches here).
func insertFinding(ctx context.Context, q pgxIface, artifactID, bucket string, f Finding) error {
	status := f.Status
	if status == "" {
		status = FindingStatusOpen
	}
	firstSeenAt := f.FirstSeenAt
	if firstSeenAt.IsZero() {
		firstSeenAt = time.Now().UTC()
	}
	_, err := q.Exec(ctx, `INSERT INTO findings (artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		artifactID, bucket, f.ID, f.Severity, f.Title, f.Source, status, firstSeenAt, f.ResolvedAt)
	return err
}

func (s *PostgresStore) Create(ref string, t Type) (*Artifact, error) {
	ctx := context.Background()
	now := time.Now().UTC()
	a := &Artifact{
		ID:        newID(),
		Ref:       ref,
		Type:      t,
		Status:    StatusRegistered,
		CreatedAt: now,
		UpdatedAt: now,
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO artifacts (id, ref, type, status, current_stage, created_at, updated_at)
		VALUES ($1, $2, $3, $4, '', $5, $5)
	`, a.ID, a.Ref, string(a.Type), string(a.Status), now)
	if err != nil {
		return nil, fmt.Errorf("insert artifact: %w", err)
	}
	return a, nil
}

// rowScanner is satisfied by both pgx.Row (QueryRow) and pgx.Rows
// (Query, via rows.Next()+Scan), so scanArtifactRow can back both
// Get/Update (single row) and List (many rows) without duplicating the
// column list.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanArtifactRow(row rowScanner) (*Artifact, error) {
	var a Artifact
	var typ, status string

	err := row.Scan(&a.ID, &a.Ref, &a.Digest, &typ, &status, &a.CurrentStage, &a.CreatedAt, &a.UpdatedAt, &a.LastScanAt, &a.MaintainerTeam, &a.MaintainerEmail)
	if err != nil {
		return nil, err
	}
	a.Type = Type(typ)
	a.Status = Status(status)
	return &a, nil
}

// fillChildren loads stage history, all five finding buckets, and scan
// errors for a single artifact and attaches them to it. Takes a
// pgxIface rather than *pgxpool.Pool directly so Update can call this
// against its in-flight transaction (to read the pre-mutation state
// under the same FOR UPDATE lock) while Get calls it directly against
// the pool.
func (s *PostgresStore) fillChildren(ctx context.Context, q pgxIface, a *Artifact) error {
	var err error
	if a.StageHistory, err = loadStageHistory(ctx, q, a.ID); err != nil {
		return fmt.Errorf("load stage_history: %w", err)
	}
	if a.CVEFindings, err = loadFindings(ctx, q, a.ID, bucketCVE); err != nil {
		return fmt.Errorf("load cve findings: %w", err)
	}
	if a.MalwareFindings, err = loadFindings(ctx, q, a.ID, bucketMalware); err != nil {
		return fmt.Errorf("load malware findings: %w", err)
	}
	if a.MisconfigFindings, err = loadFindings(ctx, q, a.ID, bucketMisconfiguration); err != nil {
		return fmt.Errorf("load misconfiguration findings: %w", err)
	}
	if a.SecretFindings, err = loadFindings(ctx, q, a.ID, bucketSecret); err != nil {
		return fmt.Errorf("load secret findings: %w", err)
	}
	if a.OtherFindings, err = loadFindings(ctx, q, a.ID, bucketOther); err != nil {
		return fmt.Errorf("load other findings: %w", err)
	}
	if a.LastScanErrors, err = loadScanErrors(ctx, q, a.ID); err != nil {
		return fmt.Errorf("load scan_errors: %w", err)
	}
	return nil
}

func loadStageHistory(ctx context.Context, q pgxIface, artifactID string) ([]StageEvent, error) {
	rows, err := q.Query(ctx, `SELECT stage, note, occurred_at FROM stage_history WHERE artifact_id = $1 ORDER BY id`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]StageEvent, 0)
	for rows.Next() {
		var e StageEvent
		if err := rows.Scan(&e.Stage, &e.Note, &e.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func loadFindings(ctx context.Context, q pgxIface, artifactID, bucket string) ([]Finding, error) {
	rows, err := q.Query(ctx, `SELECT finding_id, severity, title, source, status, first_seen_at, resolved_at FROM findings WHERE artifact_id = $1 AND bucket = $2 ORDER BY id`, artifactID, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func loadScanErrors(ctx context.Context, q pgxIface, artifactID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT error FROM scan_errors WHERE artifact_id = $1 ORDER BY id`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Get(id string) (*Artifact, error) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, selectArtifactColumns+" WHERE id = $1", id)
	a, err := scanArtifactRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("artifact %q not found", id)
		}
		return nil, fmt.Errorf("get artifact: %w", err)
	}
	if err := s.fillChildren(ctx, s.pool, a); err != nil {
		return nil, fmt.Errorf("get artifact: %w", err)
	}
	return a, nil
}

// List loads every artifact, then fills in findings/stage
// history/errors with three batched queries total (one per child
// table, using `WHERE artifact_id = ANY($1)`) rather than three per
// artifact -- an N+1 query pattern that would otherwise scale linearly
// with the number of artifacts returned.
func (s *PostgresStore) List() ([]*Artifact, error) {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, selectArtifactColumns+" ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}

	out := make([]*Artifact, 0)
	ids := make([]string, 0)
	byID := make(map[string]*Artifact)
	for rows.Next() {
		a, err := scanArtifactRow(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan artifact row: %w", err)
		}
		out = append(out, a)
		ids = append(ids, a.ID)
		byID[a.ID] = a
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	rows.Close()

	if len(ids) == 0 {
		return out, nil
	}
	if err := s.fillChildrenBatch(ctx, ids, byID); err != nil {
		return nil, fmt.Errorf("load findings/history for listed artifacts: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) fillChildrenBatch(ctx context.Context, ids []string, byID map[string]*Artifact) error {
	stageRows, err := s.pool.Query(ctx, `SELECT artifact_id, stage, note, occurred_at FROM stage_history WHERE artifact_id = ANY($1) ORDER BY artifact_id, id`, ids)
	if err != nil {
		return fmt.Errorf("batch load stage_history: %w", err)
	}
	for stageRows.Next() {
		var artifactID string
		var e StageEvent
		if err := stageRows.Scan(&artifactID, &e.Stage, &e.Note, &e.Timestamp); err != nil {
			stageRows.Close()
			return fmt.Errorf("scan stage_history row: %w", err)
		}
		if a, ok := byID[artifactID]; ok {
			a.StageHistory = append(a.StageHistory, e)
		}
	}
	if err := stageRows.Err(); err != nil {
		stageRows.Close()
		return fmt.Errorf("batch load stage_history: %w", err)
	}
	stageRows.Close()

	findingRows, err := s.pool.Query(ctx, `SELECT artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at FROM findings WHERE artifact_id = ANY($1) ORDER BY artifact_id, id`, ids)
	if err != nil {
		return fmt.Errorf("batch load findings: %w", err)
	}
	for findingRows.Next() {
		var artifactID, bucket string
		var f Finding
		if err := findingRows.Scan(&artifactID, &bucket, &f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt); err != nil {
			findingRows.Close()
			return fmt.Errorf("scan findings row: %w", err)
		}
		a, ok := byID[artifactID]
		if !ok {
			continue
		}
		switch bucket {
		case bucketCVE:
			a.CVEFindings = append(a.CVEFindings, f)
		case bucketMalware:
			a.MalwareFindings = append(a.MalwareFindings, f)
		case bucketMisconfiguration:
			a.MisconfigFindings = append(a.MisconfigFindings, f)
		case bucketSecret:
			a.SecretFindings = append(a.SecretFindings, f)
		case bucketOther:
			a.OtherFindings = append(a.OtherFindings, f)
		}
	}
	if err := findingRows.Err(); err != nil {
		findingRows.Close()
		return fmt.Errorf("batch load findings: %w", err)
	}
	findingRows.Close()

	errRows, err := s.pool.Query(ctx, `SELECT artifact_id, error FROM scan_errors WHERE artifact_id = ANY($1) ORDER BY artifact_id, id`, ids)
	if err != nil {
		return fmt.Errorf("batch load scan_errors: %w", err)
	}
	for errRows.Next() {
		var artifactID, msg string
		if err := errRows.Scan(&artifactID, &msg); err != nil {
			errRows.Close()
			return fmt.Errorf("scan scan_errors row: %w", err)
		}
		if a, ok := byID[artifactID]; ok {
			a.LastScanErrors = append(a.LastScanErrors, msg)
		}
	}
	if err := errRows.Err(); err != nil {
		errRows.Close()
		return fmt.Errorf("batch load scan_errors: %w", err)
	}
	errRows.Close()

	return nil
}

// Update reads the row with SELECT ... FOR UPDATE inside a transaction,
// applies mutate in Go (the same callback-based shape MemStore uses, so
// internal/api's handlers don't need to know which Store they're
// talking to), then writes every mutable column/table back and
// commits.
//
// mutate always leaves the *complete* desired state of each slice
// field on the Artifact (an append for stage history, a wholesale
// replace for findings after a /scan call -- see
// internal/api/handlers.go), never a delta. The simplest way to
// persist that correctly for the normalized child tables is to delete
// every existing row for this artifact in each one and re-insert
// whatever mutate() left in the struct, in order -- not the most
// efficient possible approach for a stage history that grows over an
// artifact's whole lifetime, but obviously correct, and stage/finding
// counts per artifact are small in practice. Revisit if that ever
// stops being true.
//
// The FOR UPDATE row lock is a real improvement over MemStore's global
// mutex: two concurrent updates to the *same* artifact still serialize
// correctly, but updates to two different artifacts no longer block
// each other at all.
func (s *PostgresStore) Update(id string, mutate func(*Artifact)) (*Artifact, error) {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once Commit has succeeded

	row := tx.QueryRow(ctx, selectArtifactColumns+" WHERE id = $1 FOR UPDATE", id)
	a, err := scanArtifactRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("artifact %q not found", id)
		}
		return nil, fmt.Errorf("get artifact for update: %w", err)
	}
	if err := s.fillChildren(ctx, tx, a); err != nil {
		return nil, fmt.Errorf("load artifact children for update: %w", err)
	}

	mutate(a)
	a.UpdatedAt = time.Now().UTC()

	// digest is included here (alongside status/current_stage) even
	// though most Update callers never touch it -- it's set exactly
	// once, shortly after Create, via internal/api/handlers.go's
	// duplicate-registration check calling Update with a mutate func
	// that only sets a.Digest. Without it in this SET clause, that
	// mutation would apply to the in-memory Artifact returned to the
	// caller but silently never persist -- the same trap MemStore
	// doesn't have (its Update mutates the stored struct directly), so
	// this needed calling out explicitly rather than discovering it via
	// a test that only runs against Postgres.
	if _, err := tx.Exec(ctx, `UPDATE artifacts SET status = $1, current_stage = $2, digest = $3, updated_at = $4, last_scan_at = $5, maintainer_team = $6, maintainer_email = $7 WHERE id = $8`,
		string(a.Status), a.CurrentStage, a.Digest, a.UpdatedAt, a.LastScanAt, a.MaintainerTeam, a.MaintainerEmail, a.ID); err != nil {
		return nil, fmt.Errorf("update artifact: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM stage_history WHERE artifact_id = $1`, a.ID); err != nil {
		return nil, fmt.Errorf("clear stage_history: %w", err)
	}
	for _, e := range a.StageHistory {
		if _, err := tx.Exec(ctx, `INSERT INTO stage_history (artifact_id, stage, note, occurred_at) VALUES ($1, $2, $3, $4)`,
			a.ID, e.Stage, e.Note, e.Timestamp); err != nil {
			return nil, fmt.Errorf("insert stage_history: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE artifact_id = $1`, a.ID); err != nil {
		return nil, fmt.Errorf("clear findings: %w", err)
	}
	for _, group := range []struct {
		bucket   string
		findings []Finding
	}{
		{bucketCVE, a.CVEFindings},
		{bucketMalware, a.MalwareFindings},
		{bucketMisconfiguration, a.MisconfigFindings},
		{bucketSecret, a.SecretFindings},
		{bucketOther, a.OtherFindings},
	} {
		for _, f := range group.findings {
			if err := insertFinding(ctx, tx, a.ID, group.bucket, f); err != nil {
				return nil, fmt.Errorf("insert %s finding: %w", group.bucket, err)
			}
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM scan_errors WHERE artifact_id = $1`, a.ID); err != nil {
		return nil, fmt.Errorf("clear scan_errors: %w", err)
	}
	for _, msg := range a.LastScanErrors {
		if _, err := tx.Exec(ctx, `INSERT INTO scan_errors (artifact_id, error) VALUES ($1, $2)`, a.ID, msg); err != nil {
			return nil, fmt.Errorf("insert scan_error: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return a, nil
}

// Delete permanently removes an artifact. Unlike Update, this doesn't
// need a transaction or a FOR UPDATE row lock: a single DELETE
// statement is already atomic, and there's no read-then-write race to
// protect against the way Update has (Update loads a whole Artifact
// into Go memory, mutates it, then writes it back -- genuinely
// racy without a lock; Delete just removes a row outright). The child
// tables (stage_history, findings, scan_errors) all declare
// `artifact_id ... REFERENCES artifacts(id) ON DELETE CASCADE` (see
// schemaStatements above), so deleting the one artifacts row is
// sufficient -- Postgres removes every dependent row itself, in the
// same statement's transaction, with no separate DELETE needed here
// for each child table the way Update's re-insert dance requires.
//
// RowsAffected() (rather than a separate SELECT first) is what
// distinguishes "deleted" from "didn't exist" -- one round trip instead
// of two, and no race between a check and the delete itself.
func (s *PostgresStore) Delete(id string) error {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx, `DELETE FROM artifacts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete artifact: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("artifact %q not found", id)
	}
	return nil
}

// FindByFindingID answers "every artifact still affected by finding X"
// via the findings.finding_id index -- the query the old single-table
// JSONB schema could only answer by scanning and JSON-decoding every
// artifact row. See docs/architecture.md, "Normalizing findings and
// stage history into their own tables."
func (s *PostgresStore) FindByFindingID(findingID string) ([]*Artifact, error) {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, selectArtifactColumns+`
		WHERE id IN (SELECT DISTINCT artifact_id FROM findings WHERE finding_id = $1)
		ORDER BY created_at DESC
	`, findingID)
	if err != nil {
		return nil, fmt.Errorf("find artifacts by finding id: %w", err)
	}

	out := make([]*Artifact, 0)
	ids := make([]string, 0)
	byID := make(map[string]*Artifact)
	for rows.Next() {
		a, err := scanArtifactRow(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan artifact row: %w", err)
		}
		out = append(out, a)
		ids = append(ids, a.ID)
		byID[a.ID] = a
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("find artifacts by finding id: %w", err)
	}
	rows.Close()

	if len(ids) == 0 {
		return out, nil
	}
	if err := s.fillChildrenBatch(ctx, ids, byID); err != nil {
		return nil, fmt.Errorf("load findings/history for matched artifacts: %w", err)
	}
	return out, nil
}

// FindByDigest returns the first-registered artifact with this exact
// content digest, or (nil, nil) if none exists -- see the Store
// interface's own comment on why "not found" isn't an error here.
// `ORDER BY created_at ASC LIMIT 1` picks the original registration
// deterministically if more than one row somehow shares a digest (e.g.
// a race between two concurrent registrations that both resolved their
// digest before either committed -- rare but not impossible, since this
// check and the later Create aren't wrapped in one transaction).
func (s *PostgresStore) FindByDigest(digest string) (*Artifact, error) {
	if digest == "" {
		return nil, nil
	}
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, selectArtifactColumns+`
		WHERE digest = $1 AND digest != ''
		ORDER BY created_at ASC
		LIMIT 1
	`, digest)
	a, err := scanArtifactRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find artifact by digest: %w", err)
	}
	if err := s.fillChildren(ctx, s.pool, a); err != nil {
		return nil, fmt.Errorf("find artifact by digest: %w", err)
	}
	return a, nil
}
