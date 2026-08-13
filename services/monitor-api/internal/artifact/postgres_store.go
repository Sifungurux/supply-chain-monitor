package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
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
	// are hit on every dashboard load. ListPage's optional
	// `WHERE status = $1 / type = $1` filters are still served by this
	// index alone (created_at leads, Postgres filters the rest): both
	// columns have a handful of distinct values across the whole table,
	// so an index on either would be near-useless for selectivity while
	// costing every INSERT/UPDATE. Revisit if one status ever grows to
	// dominate the table and its filtered page reads get slow.
	`CREATE INDEX IF NOT EXISTS artifacts_created_at_idx ON artifacts (created_at DESC)`,
	// Added for digest-based duplicate-registration detection (see
	// FindByDigest below and internal/api/artifacts.go). Same
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
	// Powers FindByRef, the dedup fallback for registrations whose
	// digest wouldn't resolve (see that method). Not partial, unlike
	// the digest index above: every artifact has a ref, so there is no
	// subset worth excluding. Not UNIQUE either -- two artifacts
	// legitimately share a ref when a mutable tag's content changed and
	// both resolutions succeeded, which is exactly what digest dedup is
	// for; this index only has to make the lookup cheap.
	`CREATE INDEX IF NOT EXISTS artifacts_ref_idx ON artifacts (ref)`,
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
	// Added for classified scan-failure reasons (see
	// Artifact.LastScanFailureReason's comment and
	// internal/scanner.ClassifyScanError) -- same idempotent
	// ADD COLUMN IF NOT EXISTS pattern as maintainer_team/digest above.
	// DEFAULT '' matches "no failure reason set," the same convention
	// every other optional string column on this table already uses.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS last_scan_failure_reason TEXT NOT NULL DEFAULT ''`,
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
	// Added for VEX suppression (see merge.go's MergeFindings and
	// internal/api/vex.go) -- why a finding carries status
	// 'not_affected'. Idempotent for exactly the same reason the three
	// above are; pre-existing rows get '', which is also what every
	// finding no VEX document has spoken about carries.
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS justification TEXT NOT NULL DEFAULT ''`,
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
	// Holds generated SBOM/SARIF documents (see Document's comment) --
	// deliberately its own table, never a column on artifacts: these can
	// be multi-megabyte BYTEA blobs, and artifacts is read whole on
	// every List() call the dashboard polls every 10s (see
	// selectArtifactColumns) -- a column here would drag document bytes
	// through that path for every artifact on every poll. PRIMARY KEY
	// (artifact_id, kind) both enforces "at most one current document
	// per kind" and gives SaveDocument's ON CONFLICT upsert something to
	// target -- a re-scan simply overwrites the previous document rather
	// than accumulating history, matching Digest's "current state, not
	// an audit log" convention rather than StageHistory/findings'
	// append-only one.
	`CREATE TABLE IF NOT EXISTS artifact_documents (
		artifact_id  TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		kind         TEXT NOT NULL,
		content_type TEXT NOT NULL,
		content      BYTEA NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (artifact_id, kind)
	)`,
	// The component inventory parsed out of an ingested SBOM (see
	// scanner.ParseSBOMComponents and internal/api/documents.go) --
	// the same "normalize it into rows so it can be queried" move
	// findings already got, applied to the other thing an SBOM
	// carries. The document itself stays in artifact_documents: this
	// table is not a second copy of it, it's the two or three fields
	// per component that a query needs, with the rest of the document
	// left where it is.
	//
	// UNIQUE (artifact_id, purl) rather than a plain index: a single
	// SBOM legitimately lists the same purl more than once (the same
	// package pulled in through two paths), and without this each
	// duplicate would be its own row, so one artifact would appear
	// repeatedly for one purl query. It also makes SaveComponents'
	// insert idempotent if it's ever retried mid-flight.
	`CREATE TABLE IF NOT EXISTS components (
		id          BIGSERIAL PRIMARY KEY,
		artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		purl        TEXT NOT NULL, -- e.g. "pkg:apk/alpine/openssl@3.1.4-r5"
		name        TEXT NOT NULL DEFAULT '',
		version     TEXT NOT NULL DEFAULT '',
		UNIQUE (artifact_id, purl)
	)`,
	// Powers FindByComponentPURL -- "every artifact containing this
	// package" -- without scanning every artifact's inventory, exactly
	// what findings_finding_id_idx does for "every artifact affected by
	// this CVE".
	`CREATE INDEX IF NOT EXISTS components_purl_idx ON components (purl)`,
}

const selectArtifactColumns = `SELECT id, ref, digest, type, status, current_stage, created_at, updated_at, last_scan_at, maintainer_team, maintainer_email, last_scan_failure_reason FROM artifacts`

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
	_, err := q.Exec(ctx, `INSERT INTO findings (artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at, justification) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		artifactID, bucket, f.ID, f.Severity, f.Title, f.Source, status, firstSeenAt, f.ResolvedAt, f.Justification)
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

	err := row.Scan(&a.ID, &a.Ref, &a.Digest, &typ, &status, &a.CurrentStage, &a.CreatedAt, &a.UpdatedAt, &a.LastScanAt, &a.MaintainerTeam, &a.MaintainerEmail, &a.LastScanFailureReason)
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
	if err = loadDocumentFlags(ctx, q, a); err != nil {
		return fmt.Errorf("load document flags: %w", err)
	}
	return nil
}

// loadDocumentFlags sets HasSBOM/HasSARIF from artifact_documents.kind
// -- deliberately a `SELECT kind` (no content column touched), so
// checking whether a document exists never pulls its potentially
// multi-megabyte bytes along with it. See Document's comment.
func loadDocumentFlags(ctx context.Context, q pgxIface, a *Artifact) error {
	rows, err := q.Query(ctx, `SELECT kind FROM artifact_documents WHERE artifact_id = $1`, a.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			return err
		}
		switch kind {
		case DocumentKindSBOM:
			a.HasSBOM = true
		case DocumentKindSARIF:
			a.HasSARIF = true
		}
	}
	return rows.Err()
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
	rows, err := q.Query(ctx, `SELECT finding_id, severity, title, source, status, first_seen_at, resolved_at, justification FROM findings WHERE artifact_id = $1 AND bucket = $2 ORDER BY id`, artifactID, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt, &f.Justification); err != nil {
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

// queryArtifacts runs an artifacts query, then fills in findings/stage
// history/errors for every row it returned with four batched queries
// total (one per child table, using `WHERE artifact_id = ANY($1)`)
// rather than four per artifact -- an N+1 query pattern that would
// otherwise scale linearly with the number of artifacts returned. Every
// multi-row read (List, ListPage, FindByFindingID) goes through here so
// none of them can quietly regress into N+1.
func (s *PostgresStore) queryArtifacts(ctx context.Context, sql string, args ...any) ([]*Artifact, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	rows.Close()

	if len(ids) == 0 {
		return out, nil
	}
	if err := s.fillChildrenBatch(ctx, ids, byID); err != nil {
		return nil, fmt.Errorf("load findings/history: %w", err)
	}
	return out, nil
}

// List loads every artifact, newest first.
func (s *PostgresStore) List() ([]*Artifact, error) {
	out, err := s.queryArtifacts(context.Background(), selectArtifactColumns+" ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	return out, nil
}

// listFilterClause builds the shared WHERE clause (and its arguments)
// for ListPage's page query and its COUNT(*) query, so the two can't
// drift into filtering differently -- a count that doesn't match the
// rows is exactly the bug that makes next/prev links point at empty
// pages. Every value is a placeholder ($1, $2), never interpolated.
func listFilterClause(statusFilter, typeFilter string) (string, []any) {
	var clauses []string
	var args []any
	if statusFilter != "" {
		args = append(args, statusFilter)
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if typeFilter != "" {
		args = append(args, typeFilter)
		clauses = append(clauses, fmt.Sprintf("type = $%d", len(args)))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// ListPage is List plus filtering, LIMIT/OFFSET and a total count --
// see the Store interface's own comment. `ORDER BY created_at DESC,
// id DESC` rather than created_at alone: two artifacts registered in
// the same instant (routine for a bulk registration, which inserts a
// batch as fast as it can) are otherwise ordered arbitrarily by
// Postgres, and offset paging over an unstable order silently skips
// and repeats rows between pages. The artifacts_created_at_idx index
// still serves the created_at leg; id only breaks ties.
//
// The count query is deliberately a second round trip rather than a
// window function (`COUNT(*) OVER ()`) tacked onto the page query:
// the window variant returns the count on every row of the page, which
// means scanArtifactRow's column list would have to differ between
// List and ListPage -- and that column list is shared by Get/Update
// too.
func (s *PostgresStore) ListPage(limit, offset int, statusFilter, typeFilter string) ([]*Artifact, int, error) {
	ctx := context.Background()
	where, args := listFilterClause(statusFilter, typeFilter)

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM artifacts"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count artifacts: %w", err)
	}

	pageSQL := selectArtifactColumns + where +
		fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	out, err := s.queryArtifacts(ctx, pageSQL, append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list artifacts page: %w", err)
	}
	return out, total, nil
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

	findingRows, err := s.pool.Query(ctx, `SELECT artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at, justification FROM findings WHERE artifact_id = ANY($1) ORDER BY artifact_id, id`, ids)
	if err != nil {
		return fmt.Errorf("batch load findings: %w", err)
	}
	for findingRows.Next() {
		var artifactID, bucket string
		var f Finding
		if err := findingRows.Scan(&artifactID, &bucket, &f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt, &f.Justification); err != nil {
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

	docRows, err := s.pool.Query(ctx, `SELECT artifact_id, kind FROM artifact_documents WHERE artifact_id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("batch load document flags: %w", err)
	}
	for docRows.Next() {
		var artifactID, kind string
		if err := docRows.Scan(&artifactID, &kind); err != nil {
			docRows.Close()
			return fmt.Errorf("scan artifact_documents row: %w", err)
		}
		a, ok := byID[artifactID]
		if !ok {
			continue
		}
		switch kind {
		case DocumentKindSBOM:
			a.HasSBOM = true
		case DocumentKindSARIF:
			a.HasSARIF = true
		}
	}
	if err := docRows.Err(); err != nil {
		docRows.Close()
		return fmt.Errorf("batch load document flags: %w", err)
	}
	docRows.Close()

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
// internal/api/scan.go), never a delta. The simplest way to
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
	// once, shortly after Create, via internal/api/artifacts.go's
	// duplicate-registration check calling Update with a mutate func
	// that only sets a.Digest. Without it in this SET clause, that
	// mutation would apply to the in-memory Artifact returned to the
	// caller but silently never persist -- the same trap MemStore
	// doesn't have (its Update mutates the stored struct directly), so
	// this needed calling out explicitly rather than discovering it via
	// a test that only runs against Postgres.
	if _, err := tx.Exec(ctx, `UPDATE artifacts SET status = $1, current_stage = $2, digest = $3, updated_at = $4, last_scan_at = $5, maintainer_team = $6, maintainer_email = $7, last_scan_failure_reason = $8 WHERE id = $9`,
		string(a.Status), a.CurrentStage, a.Digest, a.UpdatedAt, a.LastScanAt, a.MaintainerTeam, a.MaintainerEmail, a.LastScanFailureReason, a.ID); err != nil {
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
	out, err := s.queryArtifacts(context.Background(), selectArtifactColumns+`
		WHERE id IN (
			SELECT DISTINCT artifact_id FROM findings
			WHERE finding_id = $1 AND `+activeFindingSQL+`
		)
		ORDER BY created_at DESC
	`, findingID)
	if err != nil {
		return nil, fmt.Errorf("find artifacts by finding id: %w", err)
	}
	return out, nil
}

// activeFindingSQL is Finding.IsActive as a predicate: not fixed, not
// VEX-suppressed. NOT IN rather than `= 'open'` for the same reason
// IsActive is written as an exclusion -- a row persisted before the
// status column existed carries whatever the migration defaulted it to,
// and anything unrecognized should count as still-a-problem.
const activeFindingSQL = `status NOT IN ('fixed', 'not_affected')`

// severityRankSQL mirrors artifact.severityRank (model.go) so "worst
// severity seen" means the same thing in the database as it does in
// MemStore and in internal/notify. Case-insensitive, and anything
// unrecognized ranks 0 -- the same treatment notify.SeverityRank gives
// a severity no scanner could rate.
const severityRankSQL = `CASE lower(severity)
	WHEN 'critical' THEN 5
	WHEN 'high' THEN 4
	WHEN 'medium' THEN 3
	WHEN 'low' THEN 2
	WHEN 'negligible' THEN 1
	ELSE 0 END`

// SearchFindings finds distinct finding ids matching a substring of the
// id or the title -- the discovery step in front of FindByFindingID's
// exact lookup, and the direct counterpart of SearchComponents.
//
// GROUP BY finding_id alone, unlike SearchComponents' (purl, name,
// version): one CVE legitimately carries different severities and
// titles across artifacts, because MergeFindings refreshes both from
// every report and upstream revises ratings. Grouping by those too
// would split one CVE into several picker rows that differ only in how
// recently each artifact was scanned. So severity is aggregated as the
// worst seen (see severityRankSQL) and the title is taken from the
// worst-rated row, which is the one a reader is most likely acting on.
//
// ponytail: ILIKE '%q%' can't use findings_finding_id_idx, so this is a
// sequential scan over the findings table -- 45k rows on a real
// deployment, single-digit milliseconds. pg_trgm is the upgrade path,
// same as for components.
func (s *PostgresStore) SearchFindings(query string, limit int) ([]FindingMatch, int, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return []FindingMatch{}, 0, nil
	}
	ctx := context.Background()
	pattern := "%" + likeEscape(query) + "%"

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT 1 FROM findings
			WHERE `+activeFindingSQL+`
			  AND (finding_id ILIKE $1 ESCAPE '\' OR title ILIKE $1 ESCAPE '\')
			GROUP BY finding_id
		) matches
	`, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count finding matches: %w", err)
	}

	// Two aggregations over the same matched rows, joined: the count
	// per id, and the worst-rated row per id (DISTINCT ON), which is
	// where both severity and title come from -- so they describe one
	// real row rather than being assembled from two different artifacts'
	// reports.
	//
	// Deliberately not one pass with a window function: Postgres has no
	// `count(DISTINCT ...) OVER (...)` ("DISTINCT is not implemented for
	// window functions"), and counting rows instead of distinct
	// artifacts would inflate every id that appears in more than one
	// bucket of the same artifact.
	rows, err := s.pool.Query(ctx, `
		WITH matched AS (
			SELECT finding_id, artifact_id, title, severity
			FROM findings
			WHERE `+activeFindingSQL+`
			  AND (finding_id ILIKE $1 ESCAPE '\' OR title ILIKE $1 ESCAPE '\')
		),
		counts AS (
			SELECT finding_id, count(DISTINCT artifact_id) AS artifacts
			FROM matched GROUP BY finding_id
		),
		worst AS (
			SELECT DISTINCT ON (finding_id) finding_id, title, severity
			FROM matched
			ORDER BY finding_id, `+severityRankSQL+` DESC, title
		)
		SELECT c.finding_id, w.title, w.severity, c.artifacts
		FROM counts c JOIN worst w USING (finding_id)
		ORDER BY c.artifacts DESC, c.finding_id ASC
		LIMIT $2
	`, pattern, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("search findings: %w", err)
	}
	defer rows.Close()

	out := make([]FindingMatch, 0)
	for rows.Next() {
		var m FindingMatch
		if err := rows.Scan(&m.ID, &m.Title, &m.Severity, &m.Artifacts); err != nil {
			return nil, 0, fmt.Errorf("scan finding match: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("search findings: %w", err)
	}
	return out, total, nil
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

// Count returns how many artifacts exist -- a bare COUNT(*), since its
// only caller (the registration quota) needs the number and nothing
// else. See the Store interface's comment.
func (s *PostgresStore) Count() (int, error) {
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM artifacts`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count artifacts: %w", err)
	}
	return n, nil
}

// FindByRef returns the first-registered artifact with this exact ref --
// the dedup fallback used only when a digest could not be resolved. See
// the Store interface's comment for why that fallback exists.
// `ORDER BY created_at ASC LIMIT 1` matches FindByDigest's oldest-wins
// tie-break, so repeated registrations converge on the original row
// instead of chaining off the most recent one.
func (s *PostgresStore) FindByRef(ref string) (*Artifact, error) {
	if ref == "" {
		return nil, nil
	}
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, selectArtifactColumns+`
		WHERE ref = $1
		ORDER BY created_at ASC
		LIMIT 1
	`, ref)
	a, err := scanArtifactRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find artifact by ref: %w", err)
	}
	if err := s.fillChildren(ctx, s.pool, a); err != nil {
		return nil, fmt.Errorf("find artifact by ref: %w", err)
	}
	return a, nil
}

// SaveDocument upserts a document, overwriting any existing one of the
// same kind for this artifact -- see artifact_documents' schema comment
// for why re-scanning replaces rather than accumulates. The artifacts
// foreign key does the "artifactID must exist" check for free; a
// missing artifact surfaces as a foreign-key-violation error here
// rather than a separate existence query first.
func (s *PostgresStore) SaveDocument(artifactID, kind, contentType string, content []byte) error {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO artifact_documents (artifact_id, kind, content_type, content, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (artifact_id, kind) DO UPDATE SET content_type = $3, content = $4, created_at = $5
	`, artifactID, kind, contentType, content, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("save %s document for %q: %w", kind, artifactID, err)
	}
	return nil
}

// SaveComponents replaces this artifact's component inventory in one
// transaction: DELETE everything on record, then insert what the
// current SBOM lists. A transaction, unlike SaveDocument's single
// upsert, because the delete and the inserts are only correct together
// -- a crash between them would otherwise leave the artifact with no
// components at all, silently dropping it out of every purl query.
//
// ON CONFLICT DO NOTHING covers the same purl appearing twice in one
// document (see the components table's own comment); the parser
// already dedupes, this is the database saying so too rather than
// trusting it.
func (s *PostgresStore) SaveComponents(artifactID string, components []Component) error {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("save components for %q: %w", artifactID, err)
	}
	defer tx.Rollback(ctx)

	// Explicit existence check: unlike SaveDocument (whose INSERT hits
	// the foreign key and fails), this function's write path for an
	// artifact with an empty component list is a DELETE that affects
	// nothing and reports no error -- so a bad ID would look like a
	// success.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM artifacts WHERE id = $1)`, artifactID).Scan(&exists); err != nil {
		return fmt.Errorf("save components for %q: %w", artifactID, err)
	}
	if !exists {
		return fmt.Errorf("artifact %q not found", artifactID)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM components WHERE artifact_id = $1`, artifactID); err != nil {
		return fmt.Errorf("save components for %q: %w", artifactID, err)
	}
	for _, c := range components {
		// ponytail: a per-row Exec, matching insertFinding. Measured
		// against a 2.4MB, 5,000-component SBOM (a large node_modules
		// tree, well past what a real image produces): 8ms to parse,
		// 476ms to insert -- against main.go's 30s httpWriteTimeout,
		// which is the deadline that matters since this runs inside the
		// upload request. pgx.CopyFrom is the upgrade path if that
		// headroom ever stops being ~60x.
		if _, err := tx.Exec(ctx, `
			INSERT INTO components (artifact_id, purl, name, version) VALUES ($1, $2, $3, $4)
			ON CONFLICT (artifact_id, purl) DO NOTHING
		`, artifactID, c.PURL, c.Name, c.Version); err != nil {
			return fmt.Errorf("save components for %q: %w", artifactID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("save components for %q: %w", artifactID, err)
	}
	return nil
}

// FindByComponentPURL answers "every artifact containing this package"
// via the components.purl index -- the component-inventory counterpart
// to FindByFindingID, and the reason an ingested SBOM is parsed into
// rows at all rather than only kept as a blob.
func (s *PostgresStore) FindByComponentPURL(purl string) ([]*Artifact, error) {
	if purl == "" {
		return []*Artifact{}, nil
	}
	out, err := s.queryArtifacts(context.Background(), selectArtifactColumns+`
		WHERE id IN (SELECT DISTINCT artifact_id FROM components WHERE purl = $1)
		ORDER BY created_at DESC
	`, purl)
	if err != nil {
		return nil, fmt.Errorf("find artifacts by component purl: %w", err)
	}
	return out, nil
}

// SearchComponents finds distinct packages matching a substring of
// their name or purl. See the Store interface for why this exists at
// all: exact purl matching is the right contract for an answer and a
// hopeless one for a human typing a search box.
//
// The count is count(DISTINCT artifact_id), not count(*): one purl has
// a row per artifact containing it, so counting rows would report
// "openssl is in 41 artifacts" as 41 separate matches of 1. Grouping by
// (purl, name, version) rather than purl alone keeps name/version in the
// result without an aggregate over them -- two rows sharing a purl but
// disagreeing on name would be a parser bug, and splitting them here
// would surface it rather than hide it behind a min().
//
// ponytail: ILIKE '%q%' cannot use the components_purl_idx B-tree, so
// this is a sequential scan -- measured at 19,497 rows on a real
// deployment, which is single-digit milliseconds. A pg_trgm GIN index
// on (name, purl) is the upgrade path if an inventory ever grows to
// where that stops being true.
func (s *PostgresStore) SearchComponents(query string, limit int) ([]ComponentMatch, int, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return []ComponentMatch{}, 0, nil
	}
	ctx := context.Background()
	// A literal substring: escape LIKE's own wildcards so a query
	// containing % or _ (a real purl qualifier can) matches those
	// characters instead of acting as a pattern.
	pattern := "%" + likeEscape(query) + "%"

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT 1 FROM components
			WHERE name ILIKE $1 ESCAPE '\' OR purl ILIKE $1 ESCAPE '\'
			GROUP BY purl, name, version
		) matches
	`, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count component matches: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT purl, name, version, count(DISTINCT artifact_id) AS artifacts
		FROM components
		WHERE name ILIKE $1 ESCAPE '\' OR purl ILIKE $1 ESCAPE '\'
		GROUP BY purl, name, version
		ORDER BY artifacts DESC, purl ASC
		LIMIT $2
	`, pattern, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("search components: %w", err)
	}
	defer rows.Close()

	out := make([]ComponentMatch, 0)
	for rows.Next() {
		var m ComponentMatch
		if err := rows.Scan(&m.PURL, &m.Name, &m.Version, &m.Artifacts); err != nil {
			return nil, 0, fmt.Errorf("scan component match: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("search components: %w", err)
	}
	return out, total, nil
}

// likeEscape neutralizes LIKE/ILIKE's wildcards in a user-supplied
// substring, so searching for "openssl_dev" or a purl qualifier
// containing % looks for those characters rather than matching any
// character / any run of characters. Paired with ESCAPE '\' at every
// call site.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// GetDocument returns (nil, nil) if no document of that kind has been
// captured yet -- see the Store interface's own comment on this
// "not found is the expected, common case" convention.
func (s *PostgresStore) GetDocument(artifactID, kind string) (*Document, error) {
	ctx := context.Background()
	var d Document
	err := s.pool.QueryRow(ctx, `
		SELECT artifact_id, kind, content_type, content, created_at
		FROM artifact_documents WHERE artifact_id = $1 AND kind = $2
	`, artifactID, kind).Scan(&d.ArtifactID, &d.Kind, &d.ContentType, &d.Content, &d.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get %s document for %q: %w", kind, artifactID, err)
	}
	return &d, nil
}
