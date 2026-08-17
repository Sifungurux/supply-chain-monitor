package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
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
	// Artifact.Unsafe existed on the model, was set at registration and
	// rendered by the dashboard for months, and was never persisted --
	// no column, absent from every INSERT, SELECT and UPDATE. So it was
	// always false when read back, which with the Postgres store is
	// every read. MemStore keeps the whole struct, which is why the
	// tests never noticed.
	//
	// That made the dashboard's "Unsafe" badge dead code in production
	// and would have made policy's disallowUnsafe a gate that could
	// never fire -- the exact silent no-op that feature exists to
	// prevent.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS unsafe BOOLEAN NOT NULL DEFAULT false`,
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
	// Search (?q=) is a case-insensitive SUBSTRING match across these
	// five columns, which a plain b-tree index cannot serve -- a
	// leading wildcard makes it useless. pg_trgm can, so it is used
	// when the extension is available.
	//
	// CREATE EXTENSION needs privileges an unprivileged application
	// role may not have, so this is deliberately best-effort: the
	// statements below are run in a way that tolerates failure (see
	// migrate), and without them the search still works -- Postgres
	// falls back to a sequential scan. At this project's scale that is
	// milliseconds, and correctness does not depend on it. What would
	// be wrong is refusing to start because an index could not be
	// created.

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
	// KEV/EPSS enrichment (see internal/scanner/enrich.go). Defaults
	// are the "no data" values, and are deliberately the same as a
	// genuine negative -- which is why EnrichmentStatus exists to tell
	// the two apart rather than trying to encode it here.
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION NOT NULL DEFAULT 0`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS known_exploited BOOLEAN NOT NULL DEFAULT false`,
	// The feeds themselves. One row per CVE, replaced wholesale on each
	// refresh (see ReplaceEnrichment) rather than merged: both feeds are
	// full snapshots, and a CVE dropping out of KEV is a real state
	// change that a merge would never apply.
	//
	// In Postgres rather than on disk, deliberately. The obvious home
	// would be the trivy cache dir the scanners already share -- but
	// monitor-api runs with a read-only root filesystem and does not
	// mount that PVC, and the PVC is ReadWriteOnce on local-path
	// storage, so attaching it to a long-lived Deployment would pin
	// every scan-worker Job to monitor-api's node. The database is
	// already here, already backed up, and already reachable from both
	// the API and the refresh CronJob.
	`CREATE TABLE IF NOT EXISTS cve_enrichment (
		cve_id          TEXT PRIMARY KEY,
		epss_score      DOUBLE PRECISION NOT NULL DEFAULT 0,
		known_exploited BOOLEAN NOT NULL DEFAULT false
	)`,
	`CREATE INDEX IF NOT EXISTS cve_enrichment_known_exploited_idx ON cve_enrichment (known_exploited) WHERE known_exploited`,
	// One row per feed, so "when did this last succeed" survives a
	// restart and can be reported without re-downloading anything.
	`CREATE TABLE IF NOT EXISTS enrichment_feeds (
		feed       TEXT PRIMARY KEY, -- 'kev' | 'epss'
		updated_at TIMESTAMPTZ NOT NULL,
		entries    INTEGER NOT NULL DEFAULT 0
	)`,
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
	// License identifiers for each component, comma-joined (see
	// artifact.Component.Licenses). Same idempotent ADD COLUMN IF NOT
	// EXISTS as every other column added after the fact; DEFAULT ''
	// matches the "empty means the document said nothing usable"
	// convention the Go field documents, so there is no NULL case for
	// the ?license= filter to get wrong.
	`ALTER TABLE components ADD COLUMN IF NOT EXISTS licenses TEXT NOT NULL DEFAULT ''`,
	// Per-scan snapshots of the above, which is what makes "what changed
	// between these two scans" answerable at all (see SaveComponents and
	// GET /api/v1/artifacts/{id}/components/diff). The `components` table
	// deliberately holds only the CURRENT inventory -- SaveComponents
	// replaces it wholesale, matching artifact_documents' latest-only
	// contract -- so before this table existed the previous inventory was
	// simply gone the moment a rescan landed.
	//
	// Append-only, unlike components: a row here is a historical fact
	// about one scan, never updated. Rows share a scan_at per snapshot,
	// which is the grouping key everything below reads by, and the
	// snapshot count per artifact is capped (MaxComponentSnapshots) in
	// the same transaction that writes one -- otherwise every scan of a
	// real image adds another few thousand rows forever.
	//
	// No UNIQUE (artifact_id, scan_at, purl): the current table has one
	// to make repeated purls in a single document idempotent, but here a
	// duplicate would have to come from the same insert loop within one
	// transaction, and ON CONFLICT DO NOTHING below covers that without
	// the index write cost on an append-only table.
	`CREATE TABLE IF NOT EXISTS components_history (
		id          BIGSERIAL PRIMARY KEY,
		artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		scan_at     TIMESTAMPTZ NOT NULL,
		purl        TEXT NOT NULL,
		name        TEXT NOT NULL DEFAULT '',
		version     TEXT NOT NULL DEFAULT ''
	)`,
	// Every read here is "this artifact's snapshots, newest first" or
	// "this artifact's rows at this scan_at" -- both served by this one
	// index, which is also what the retention DELETE scans.
	`CREATE INDEX IF NOT EXISTS components_history_artifact_scan_idx ON components_history (artifact_id, scan_at DESC)`,
	// Licenses on the history table too, so a component appearing in a
	// diff carries the same license information the picker shows for
	// it. MUST come after the CREATE TABLE above: schemaStatements runs
	// in order, and ALTER TABLE ... IF NOT EXISTS still fails outright
	// on a table that does not exist yet -- which on a fresh database
	// is every one above its own CREATE.
	`ALTER TABLE components_history ADD COLUMN IF NOT EXISTS licenses TEXT NOT NULL DEFAULT ''`,
	// Cluster-wide scan concurrency. One row per held slot; the cap is
	// enforced by counting rows inside AcquireScanSlots' transaction.
	//
	// A table rather than a session-scoped advisory lock per slot,
	// because a slot has to outlive the connection that took it: a scan
	// runs for minutes in a background goroutine while the pool
	// recycles connections underneath it, and a session-scoped lock
	// would be released the moment its connection went back to the
	// pool. Rows survive that; the trade is that a pod killed
	// mid-scan leaves its rows behind, which is what the reaping in
	// AcquireScanSlots exists to clean up.
	//
	// Deliberately NOT referencing artifacts(id): a slot is held by a
	// scan, not by an artifact, and cascading a slot away when its
	// artifact is deleted mid-scan would free a slot whose work is
	// still running -- letting one more scan start than the cap allows,
	// which is the single thing this table exists to prevent.
	`CREATE TABLE IF NOT EXISTS scan_slots (
		id          BIGSERIAL PRIMARY KEY,
		holder_id   TEXT NOT NULL,
		scanner_kind TEXT NOT NULL,
		acquired_at TIMESTAMPTZ NOT NULL
	)`,
	// Both reads are "how many of this kind are held" and "free this
	// holder"; both are served here.
	`CREATE INDEX IF NOT EXISTS scan_slots_kind_idx ON scan_slots (scanner_kind)`,
	`CREATE INDEX IF NOT EXISTS scan_slots_holder_idx ON scan_slots (holder_id)`,
	// Per-Job upload credentials for scan workers.
	//
	// A scan worker exists to process UNTRUSTED content -- that is the
	// whole reason it runs as a disposable, zero-RBAC pod. It was also
	// handed SCM_API_KEY, the master credential, purely so it could post
	// an SBOM back: a malicious image that popped trivy walked away with
	// full API authority, and the isolation bought nothing (report S3).
	//
	// A token here is scoped to ONE artifact, expires with the Job, and
	// each document kind is usable once -- so the worst a compromised
	// worker can do with it is upload one SBOM and one SARIF for the
	// artifact it was already scanning.
	//
	// Only the HASH is stored. A leaked database dump should not yield
	// usable upload credentials, the same reasoning that applies to any
	// other credential at rest.
	`CREATE TABLE IF NOT EXISTS scan_tokens (
		token_hash  TEXT PRIMARY KEY,
		artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
		expires_at  TIMESTAMPTZ NOT NULL,
		used_kinds  TEXT[] NOT NULL DEFAULT '{}'
	)`,
	// Cleanup deletes by artifact; expiry sweeps delete by time.
	`CREATE INDEX IF NOT EXISTS scan_tokens_artifact_idx ON scan_tokens (artifact_id)`,
	`CREATE INDEX IF NOT EXISTS scan_tokens_expires_idx ON scan_tokens (expires_at)`,
}

const selectArtifactColumns = `SELECT id, ref, digest, type, status, current_stage, created_at, updated_at, last_scan_at, maintainer_team, maintainer_email, last_scan_failure_reason, unsafe FROM artifacts`

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

// Ping reports whether the database is reachable right now, for the
// readiness probe (GET /readyz -- see internal/api's Config.Ready).
//
// Deliberately a method on this concrete type rather than on the Store
// interface: MemStore has nothing to check, and the interface already
// carries one context-taking method documented as a wart. main.go is
// the only caller and holds a *PostgresStore, so nothing needs the
// abstraction.
//
// NewPostgresStore already pings once at startup. This is the same call
// asked repeatedly afterwards, which is the part that was missing: a
// database that goes away after a successful start left the pod Ready
// and serving errors, because the only health signal was a handler that
// returned "ok" without consulting anything.
func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases the underlying connection pool. Not called on every
// pod exit today (Kubernetes just kills the pod and Postgres cleans up
// server-side), but useful for tests and any future graceful-shutdown
// path.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// optionalSchemaStatements are BEST EFFORT: a failure is logged and
// startup continues.
//
// They create the pg_trgm indexes that make ?q= substring search use an
// index rather than a sequential scan. `CREATE EXTENSION` needs
// privileges an unprivileged application role may not have, and the
// index statements fail if the extension is absent -- neither is a
// reason to refuse to start, because search is CORRECT either way.
// Postgres just scans instead, which at this project's scale is
// milliseconds.
//
// Kept apart from schemaStatements rather than given a "try this too"
// flag: everything in that list is required, and mixing the two would
// make the required ones look optional at a glance.
var optionalSchemaStatements = []string{
	`CREATE EXTENSION IF NOT EXISTS pg_trgm`,
	`CREATE INDEX IF NOT EXISTS artifacts_ref_trgm_idx ON artifacts USING gin (ref gin_trgm_ops)`,
	`CREATE INDEX IF NOT EXISTS artifacts_digest_trgm_idx ON artifacts USING gin (digest gin_trgm_ops)`,
	`CREATE INDEX IF NOT EXISTS artifacts_maintainer_team_trgm_idx ON artifacts USING gin (maintainer_team gin_trgm_ops)`,
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	for _, stmt := range schemaStatements {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("create tables: %w", err)
		}
	}
	for _, stmt := range optionalSchemaStatements {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			// Warn rather than fail: see optionalSchemaStatements. The
			// statement is logged so "why is search slow" has an
			// answer that does not require reading this file.
			slog.Warn("optional schema statement failed -- artifact search will use a sequential scan, which is correct but slower",
				"statement", stmt, "err", err)
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

	slog.Info("postgres: found the old single-table JSONB schema -- migrating stage history and findings into normalized tables (one-time, see docs/architecture.md)", "section",
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
	slog.Info("postgres: migration complete -- migrated findings/stage history into normalized tables", "count", len(legacy))
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
	_, err := q.Exec(ctx, `INSERT INTO findings (artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at, justification, epss_score, known_exploited) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		artifactID, bucket, f.ID, f.Severity, f.Title, f.Source, status, firstSeenAt, f.ResolvedAt, f.Justification, f.EPSSScore, f.KnownExploited)
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

	err := row.Scan(&a.ID, &a.Ref, &a.Digest, &typ, &status, &a.CurrentStage, &a.CreatedAt, &a.UpdatedAt, &a.LastScanAt, &a.MaintainerTeam, &a.MaintainerEmail, &a.LastScanFailureReason, &a.Unsafe)
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
	rows, err := q.Query(ctx, `SELECT finding_id, severity, title, source, status, first_seen_at, resolved_at, justification, epss_score, known_exploited FROM findings WHERE artifact_id = $1 AND bucket = $2 ORDER BY id`, artifactID, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt, &f.Justification, &f.EPSSScore, &f.KnownExploited); err != nil {
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
func listFilterClause(statusFilter, typeFilter, searchFilter string) (string, []any) {
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
	if q := strings.TrimSpace(searchFilter); q != "" {
		// ILIKE with a BOUND parameter, and the wildcards added to the
		// value rather than spliced into the SQL -- the query text is a
		// constant regardless of what anyone types.
		//
		// The pattern metacharacters are escaped first (see
		// likePattern): without that, a search for "100%" matches every
		// artifact rather than none, and "_" quietly becomes "any
		// character". That is a correctness bug rather than an
		// injection one, but it is the kind that makes a search box
		// feel broken for reasons nobody can explain.
		args = append(args, likePattern(q))
		n := len(args)
		clauses = append(clauses, fmt.Sprintf(
			"(ref ILIKE $%d OR digest ILIKE $%d OR maintainer_team ILIKE $%d OR maintainer_email ILIKE $%d OR current_stage ILIKE $%d)",
			n, n, n, n, n))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// likePattern turns a user's search text into a substring ILIKE
// pattern, escaping the three characters LIKE treats specially so they
// match themselves.
//
// Backslash first, or it would double-escape the escapes added after
// it.
func likePattern(q string) string {
	r := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)
	return "%" + r.Replace(q) + "%"
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
func (s *PostgresStore) ListPage(limit, offset int, statusFilter, typeFilter, searchFilter string) ([]*Artifact, int, error) {
	ctx := context.Background()
	where, args := listFilterClause(statusFilter, typeFilter, searchFilter)

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

	// Column list kept in step with loadFindings' -- there are two
	// paths that read findings (Get uses loadFindings, List/ListPage use
	// this batch query) and a column added to one and not the other is
	// invisible: the field simply reads back as its zero value on
	// whichever path forgot it. epss_score/known_exploited shipped
	// exactly that way, so the dashboard -- which renders detail pages
	// from the LIST payload -- showed no KEV badges while the artifact
	// endpoint returned them correctly.
	findingRows, err := s.pool.Query(ctx, `SELECT artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at, justification, epss_score, known_exploited FROM findings WHERE artifact_id = ANY($1) ORDER BY artifact_id, id`, ids)
	if err != nil {
		return fmt.Errorf("batch load findings: %w", err)
	}
	for findingRows.Next() {
		var artifactID, bucket string
		var f Finding
		if err := findingRows.Scan(&artifactID, &bucket, &f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt, &f.Justification, &f.EPSSScore, &f.KnownExploited); err != nil {
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
	if _, err := tx.Exec(ctx, `UPDATE artifacts SET status = $1, current_stage = $2, digest = $3, updated_at = $4, last_scan_at = $5, maintainer_team = $6, maintainer_email = $7, last_scan_failure_reason = $8, unsafe = $9 WHERE id = $10`,
		string(a.Status), a.CurrentStage, a.Digest, a.UpdatedAt, a.LastScanAt, a.MaintainerTeam, a.MaintainerEmail, a.LastScanFailureReason, a.Unsafe, a.ID); err != nil {
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

	// Aggregate over every active row of the MATCHED IDS, not over the
	// rows that matched. Those differ: one CVE is recorded with
	// whichever package title each scanner reported, so
	// CVE-2024-5535 appears as "openssl: SSL_select_next_proto buffer
	// overread" in most artifacts and as "libcrypto3 3.1.4-r5" or
	// "libssl1.0.0 ..." in others. Counting matched rows made q=openssl
	// report 21 artifacts for a CVE that 23 artifacts actually carry --
	// the picker undercounting what its own click-through returns, which
	// is the exact mismatch this feature exists to avoid. Found on live
	// data, not by a test.
	//
	// It also makes severity and title "worst across every artifact that
	// has this id", rather than "worst among the rows whose text
	// happened to contain the search term".
	//
	// Deliberately not one pass with a window function: Postgres has no
	// `count(DISTINCT ...) OVER (...)` ("DISTINCT is not implemented for
	// window functions"), and counting plain rows would inflate any id
	// appearing in two buckets of the same artifact.
	rows, err := s.pool.Query(ctx, `
		WITH matched_ids AS (
			SELECT DISTINCT finding_id
			FROM findings
			WHERE `+activeFindingSQL+`
			  AND (finding_id ILIKE $1 ESCAPE '\' OR title ILIKE $1 ESCAPE '\')
		),
		every_row AS (
			SELECT f.finding_id, f.artifact_id, f.title, f.severity
			FROM findings f
			JOIN matched_ids m ON m.finding_id = f.finding_id
			WHERE `+activeFindingSQL+`
		),
		counts AS (
			SELECT finding_id, count(DISTINCT artifact_id) AS artifacts
			FROM every_row GROUP BY finding_id
		),
		worst AS (
			SELECT DISTINCT ON (finding_id) finding_id, title, severity
			FROM every_row
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

// Stats answers the whole summary in two aggregate queries -- see
// Stats itself in model.go for what each map means.
//
// Two, not five or nine, because the numbers split cleanly along the
// two tables they come from:
//
//   - One `GROUP BY status, type, current_stage` over artifacts gives
//     the total and all three of its maps at once, folded apart in Go
//     below. That's a single sequential scan instead of four, and the
//     grouping can't blow up: status and type have four valid values
//     each and current_stage is bounded by PIPELINE_STAGES, so this
//     returns at most a couple of hundred rows regardless of how many
//     artifacts exist.
//
//   - One `GROUP BY bucket` over active findings gives the per-bucket
//     artifact counts. count(DISTINCT artifact_id), never count(*): the
//     question is "how many artifacts have a malware hit", and an
//     artifact with nine active CVEs must count once, not nine times.
//     Equivalent to an EXISTS subquery per bucket against artifacts,
//     with one scan instead of five -- a findings row can't outlive its
//     artifact (ON DELETE CASCADE), so a distinct artifact_id here is
//     always a real, still-present artifact.
//
// activeFindingSQL is reused rather than restated so this can't drift
// from FindByFindingID/SearchFindings and start reporting a population
// the click-through disagrees with. It already covers findings whose
// status is the empty string (rows predating the lifecycle columns):
// the column is NOT NULL, so an empty status is simply not one of
// ('fixed', 'not_affected') and counts as active, which is the same
// direction Finding.IsActive fails in.
func (s *PostgresStore) Stats(ctx context.Context) (Stats, error) {
	stats := Stats{
		ByStatus:     map[string]int{},
		ByType:       map[string]int{},
		WithFindings: map[string]int{},
		ByStage:      map[string]int{},
	}
	// Pre-seeded to zero, unlike the other three maps -- see Stats' own
	// comment. A GROUP BY only ever returns buckets that have rows, so
	// without this "no artifact has malware" would be an absent key
	// rather than a stated 0.
	for _, bucket := range bucketNames {
		stats.WithFindings[bucket] = 0
	}

	rows, err := s.pool.Query(ctx, `
		SELECT status, type, current_stage, count(*)
		FROM artifacts
		GROUP BY status, type, current_stage
	`)
	if err != nil {
		return Stats{}, fmt.Errorf("stats: group artifacts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status, artifactType, stage string
		var n int
		if err := rows.Scan(&status, &artifactType, &stage, &n); err != nil {
			return Stats{}, fmt.Errorf("stats: scan artifact group: %w", err)
		}
		stats.Total += n
		stats.ByStatus[status] += n
		stats.ByType[artifactType] += n
		// Unstaged artifacts land under "", which is what the column
		// already holds for them (DEFAULT '') -- see Stats.ByStage.
		stats.ByStage[stage] += n
	}
	if err := rows.Err(); err != nil {
		return Stats{}, fmt.Errorf("stats: group artifacts: %w", err)
	}

	bucketRows, err := s.pool.Query(ctx, `
		SELECT bucket, count(DISTINCT artifact_id)
		FROM findings
		WHERE `+activeFindingSQL+`
		GROUP BY bucket
	`)
	if err != nil {
		return Stats{}, fmt.Errorf("stats: group findings: %w", err)
	}
	defer bucketRows.Close()
	for bucketRows.Next() {
		var bucket string
		var n int
		if err := bucketRows.Scan(&bucket, &n); err != nil {
			return Stats{}, fmt.Errorf("stats: scan finding group: %w", err)
		}
		stats.WithFindings[bucket] = n
	}
	if err := bucketRows.Err(); err != nil {
		return Stats{}, fmt.Errorf("stats: group findings: %w", err)
	}
	return stats, nil
}

// AcquireScanSlots takes one slot per kind, all or nothing, bounded
// across every replica. See the Store interface for what it is for.
//
// THE ADVISORY LOCK IS THE CORRECTNESS CORE, not an optimisation. The
// obvious implementation -- INSERT ... SELECT WHERE (SELECT count(*)
// ...) < cap -- does NOT serialize under READ COMMITTED, which is
// Postgres's default and this pool's. Two transactions racing for the
// last slot each evaluate the count against their own snapshot, neither
// sees the other's uncommitted row, both find count = cap-1, and both
// insert. The cap is quietly exceeded, most often under exactly the
// concurrent load it exists to bound, and nothing errors.
//
// pg_advisory_xact_lock serializes acquisition per kind, so the count
// inside the lock is trustworthy. Transaction-scoped: it releases on
// commit OR rollback with nothing to remember, unlike a session lock.
// SERIALIZABLE isolation would also work and would push
// serialization-failure retries onto every caller instead.
//
// The lock is keyed by hashing the kind, so two different kinds never
// block each other -- a saturated malcontent cap must not slow trivy
// acquisition down.
func (s *PostgresStore) AcquireScanSlots(req ScanSlotRequest) (ScanSlotResult, error) {
	kinds := dedupeKinds(req.Kinds)
	if len(kinds) == 0 {
		return ScanSlotResult{Acquired: true}, nil
	}
	// Sorted so two concurrent acquirers take the per-kind locks in the
	// same order -- taking them in caller-supplied order is a deadlock
	// waiting for two scans whose kind lists overlap in opposite order.
	sorted := append([]string(nil), kinds...)
	sort.Strings(sorted)

	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ScanSlotResult{}, fmt.Errorf("acquire scan slots: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once Commit has succeeded

	for _, kind := range sorted {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, scanSlotLockKey+kind); err != nil {
			return ScanSlotResult{}, fmt.Errorf("lock scan slot kind %q: %w", kind, err)
		}
	}

	// Reap abandoned slots before counting, so a pod killed mid-scan
	// cannot hold a cap saturated forever. Inside the same transaction
	// and the same locks, so the count below sees the post-reap state.
	if req.StaleAfter > 0 {
		if _, err := tx.Exec(ctx,
			`DELETE FROM scan_slots WHERE acquired_at < $1`,
			time.Now().UTC().Add(-req.StaleAfter)); err != nil {
			return ScanSlotResult{}, fmt.Errorf("reap stale scan slots: %w", err)
		}
	}

	// Check every kind before taking any, so a rejection never leaves a
	// partial acquisition behind.
	for _, kind := range sorted {
		capacity, limited := req.Caps[kind]
		if !limited || capacity <= 0 {
			continue
		}
		var held int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM scan_slots WHERE scanner_kind = $1`, kind).Scan(&held); err != nil {
			return ScanSlotResult{}, fmt.Errorf("count scan slots for %q: %w", kind, err)
		}
		if held >= capacity {
			// Commit rather than roll back: the reap above is real work
			// worth keeping even though this acquisition failed.
			if err := tx.Commit(ctx); err != nil {
				return ScanSlotResult{}, fmt.Errorf("acquire scan slots: %w", err)
			}
			return ScanSlotResult{BlockedKind: kind, BlockedCap: capacity}, nil
		}
	}

	now := time.Now().UTC()
	for _, kind := range kinds {
		if _, err := tx.Exec(ctx,
			`INSERT INTO scan_slots (holder_id, scanner_kind, acquired_at) VALUES ($1, $2, $3)`,
			req.HolderID, kind, now); err != nil {
			return ScanSlotResult{}, fmt.Errorf("take scan slot %q: %w", kind, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ScanSlotResult{}, fmt.Errorf("acquire scan slots: %w", err)
	}
	return ScanSlotResult{Acquired: true}, nil
}

// scanSlotLockKey namespaces the advisory lock ids so they cannot
// collide with any other advisory lock this database might grow.
const scanSlotLockKey = "scm-scan-slot:"

// ReleaseScanSlots frees a holder's slots. A holder with none is not an
// error -- see the Store interface.
func (s *PostgresStore) ReleaseScanSlots(holderID string) error {
	if _, err := s.pool.Exec(context.Background(),
		`DELETE FROM scan_slots WHERE holder_id = $1`, holderID); err != nil {
		return fmt.Errorf("release scan slots for %q: %w", holderID, err)
	}
	return nil
}

// CountStaleScans counts artifacts last scanned before cutoff. The
// `last_scan_at IS NOT NULL` is the whole subtlety -- see the Store
// interface for why a never-scanned artifact is a different state
// rather than an infinitely old one.
func (s *PostgresStore) CountStaleScans(cutoff time.Time) (int, error) {
	var n int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM artifacts WHERE last_scan_at IS NOT NULL AND last_scan_at < $1`,
		cutoff).Scan(&n); err != nil {
		return 0, fmt.Errorf("count stale scans before %s: %w", cutoff.Format(time.RFC3339), err)
	}
	return n, nil
}

// CountOlderThan answers the dry run: how many artifacts have not been
// touched since cutoff. See the Store interface for why this is
// separate from deleting them.
func (s *PostgresStore) CountOlderThan(cutoff time.Time) (int, error) {
	var n int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM artifacts WHERE updated_at < $1`, cutoff).Scan(&n); err != nil {
		return 0, fmt.Errorf("count artifacts older than %s: %w", cutoff.Format(time.RFC3339), err)
	}
	return n, nil
}

// DeleteOlderThan removes up to limit artifacts, oldest first.
//
// The subselect is what bounds it: Postgres has no DELETE ... LIMIT, so
// the ids to remove are chosen first (ORDER BY updated_at, so a capped
// run takes the oldest and the next run continues) and the DELETE
// matches on those. Without the bound, a first run against a store that
// has never been pruned would delete an unbounded number of rows in one
// statement, holding locks and a growing transaction the whole time --
// on a table the API is concurrently serving from.
//
// Findings, stage history, scan errors, documents and components go
// with each artifact via ON DELETE CASCADE -- the same cascade Delete
// relies on, which is why this needs no per-child cleanup and why it is
// genuinely irreversible.
func (s *PostgresStore) DeleteOlderThan(cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(context.Background(), `
		DELETE FROM artifacts
		WHERE id IN (
			SELECT id FROM artifacts
			WHERE updated_at < $1
			ORDER BY updated_at
			LIMIT $2
		)
	`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("delete artifacts older than %s: %w", cutoff.Format(time.RFC3339), err)
	}
	return int(tag.RowsAffected()), nil
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
		// upload request. Each component is now written TWICE (here and
		// into components_history below), so read that as ~950ms and the
		// headroom as ~30x rather than ~60x. pgx.CopyFrom is the upgrade
		// path when it stops being comfortable.
		if _, err := tx.Exec(ctx, `
			INSERT INTO components (artifact_id, purl, name, version, licenses) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (artifact_id, purl) DO NOTHING
		`, artifactID, c.PURL, c.Name, c.Version, c.Licenses); err != nil {
			return fmt.Errorf("save components for %q: %w", artifactID, err)
		}
	}
	// The historical snapshot, in the SAME transaction as the replace
	// above: the current inventory and the record of what it was at this
	// scan are one fact, and a crash between them would leave a history
	// that disagrees with the components table it is supposed to explain.
	scanAt := time.Now().UTC()
	for _, c := range components {
		if _, err := tx.Exec(ctx, `
			INSERT INTO components_history (artifact_id, scan_at, purl, name, version, licenses)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, artifactID, scanAt, c.PURL, c.Name, c.Version, c.Licenses); err != nil {
			return fmt.Errorf("save component history for %q: %w", artifactID, err)
		}
	}

	// Evict everything outside the newest MaxComponentSnapshots. Runs
	// AFTER the insert above, deliberately: run before, and the snapshot
	// being written is not yet among the ones it counts, so a full
	// history would keep the oldest and drop the newest.
	//
	// Postgres has no DELETE ... LIMIT, and the unit being kept is a
	// SNAPSHOT (many rows sharing a scan_at), not a row -- hence the
	// DISTINCT subselect rather than a row count.
	if _, err := tx.Exec(ctx, `
		DELETE FROM components_history
		WHERE artifact_id = $1
		  AND scan_at NOT IN (
			SELECT scan_at FROM (
				SELECT DISTINCT scan_at
				FROM components_history
				WHERE artifact_id = $1
				ORDER BY scan_at DESC
				LIMIT $2
			) keep
		  )
	`, artifactID, MaxComponentSnapshots); err != nil {
		return fmt.Errorf("trim component history for %q: %w", artifactID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("save components for %q: %w", artifactID, err)
	}
	return nil
}

// ComponentSnapshots returns retained snapshot timestamps, newest
// first -- see the Store interface.
func (s *PostgresStore) ComponentSnapshots(artifactID string, limit int) ([]time.Time, error) {
	ctx := context.Background()
	sql := `SELECT DISTINCT scan_at FROM components_history WHERE artifact_id = $1 ORDER BY scan_at DESC`
	args := []any{artifactID}
	if limit > 0 {
		sql += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("list component snapshots for %q: %w", artifactID, err)
	}
	defer rows.Close()

	out := make([]time.Time, 0)
	for rows.Next() {
		var t time.Time
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan component snapshot timestamp: %w", err)
		}
		out = append(out, t.UTC())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list component snapshots for %q: %w", artifactID, err)
	}
	return out, nil
}

// ComponentsAt returns one snapshot's inventory. Ordered by purl so the
// two backends hand DiffComponents its input in the same order -- the
// diff sorts its own output, but keeping the input stable too means a
// future change there cannot make the two disagree.
func (s *PostgresStore) ComponentsAt(artifactID string, scanAt time.Time) ([]Component, error) {
	rows, err := s.pool.Query(context.Background(), `
		SELECT purl, name, version, licenses FROM components_history
		WHERE artifact_id = $1 AND scan_at = $2
		ORDER BY purl
	`, artifactID, scanAt)
	if err != nil {
		return nil, fmt.Errorf("load components at %s for %q: %w", scanAt.Format(time.RFC3339Nano), artifactID, err)
	}
	defer rows.Close()

	out := make([]Component, 0)
	for rows.Next() {
		var c Component
		if err := rows.Scan(&c.PURL, &c.Name, &c.Version, &c.Licenses); err != nil {
			return nil, fmt.Errorf("scan historical component: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load components at %s for %q: %w", scanAt.Format(time.RFC3339Nano), artifactID, err)
	}
	return out, nil
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

// FindByLicense returns every artifact containing at least one
// component whose license identifiers include this exact one.
//
// EXACT identifier match, case-insensitive, against one entry of the
// comma-joined list -- not a substring of the whole column. Substring
// matching would make "GPL-3.0-only" match "LGPL-3.0-only", which is a
// materially different license, and would match inside an SPDX
// expression like "MIT OR AGPL-3.0-only" where the OR is precisely the
// permissive escape that makes the package usable. Same rule
// LicenseDenylist applies, deliberately: a component the filter finds
// is a component the denylist would flag.
func (s *PostgresStore) FindByLicense(license string) ([]*Artifact, error) {
	license = strings.TrimSpace(license)
	if license == "" {
		return []*Artifact{}, nil
	}
	// string_to_array + unnest so the comparison is per-identifier
	// rather than against the joined string.
	out, err := s.queryArtifacts(context.Background(), selectArtifactColumns+`
		WHERE id IN (
			SELECT DISTINCT artifact_id FROM components
			WHERE EXISTS (
				SELECT 1 FROM unnest(string_to_array(licenses, ',')) AS one
				WHERE lower(btrim(one)) = lower(btrim($1))
			)
		)
		ORDER BY created_at DESC
	`, license)
	if err != nil {
		return nil, fmt.Errorf("find artifacts by license: %w", err)
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

	// Same shape as SearchFindings, and for the same reason: aggregate
	// over every row of the matched PURLS, not over the rows that
	// matched. A name-substring query would otherwise miss rows where
	// one artifact's SBOM spells the package differently for the same
	// purl, and undercount by exactly those artifacts. Less likely here
	// than for findings (a purl match already covers every row of that
	// purl) but it is the same bug, so it gets the same fix.
	rows, err := s.pool.Query(ctx, `
		WITH matched_purls AS (
			SELECT DISTINCT purl FROM components
			WHERE name ILIKE $1 ESCAPE '\' OR purl ILIKE $1 ESCAPE '\'
		),
		counts AS (
			SELECT c.purl, count(DISTINCT c.artifact_id) AS artifacts
			FROM components c JOIN matched_purls m ON m.purl = c.purl
			GROUP BY c.purl
		),
		display AS (
			-- One name/version per purl, chosen deterministically rather
			-- than by grouping on them: the same purl can carry different
			-- names across artifacts (one SBOM says "openssl", another
			-- "libcrypto3" for the identical package), and grouping by
			-- name would split one package into several rows of 1 instead
			-- of one row of 3. Alphabetically first is arbitrary but
			-- stable, and matches MemStore.
			SELECT DISTINCT ON (c.purl) c.purl, c.name, c.version, c.licenses
			FROM components c JOIN matched_purls m ON m.purl = c.purl
			ORDER BY c.purl, c.name, c.version
		)
		SELECT d.purl, d.name, d.version, d.licenses, c.artifacts
		FROM counts c JOIN display d USING (purl)
		ORDER BY c.artifacts DESC, d.purl ASC
		LIMIT $2
	`, pattern, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("search components: %w", err)
	}
	defer rows.Close()

	out := make([]ComponentMatch, 0)
	for rows.Next() {
		var m ComponentMatch
		if err := rows.Scan(&m.PURL, &m.Name, &m.Version, &m.Licenses, &m.Artifacts); err != nil {
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

// CreateScanToken records a per-Job upload credential. tokenHash is the
// SHA-256 of the token; the token itself is never stored.
func (s *PostgresStore) CreateScanToken(artifactID, tokenHash string, expiresAt time.Time) error {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO scan_tokens (token_hash, artifact_id, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token_hash) DO NOTHING`,
		tokenHash, artifactID, expiresAt)
	return err
}

// ConsumeScanToken validates a token for one artifact and one document
// kind, marking that kind used. Reports false for every failure mode --
// unknown token, wrong artifact, expired, or this kind already
// uploaded.
//
// ONE STATEMENT, deliberately. Check-then-update would let two
// concurrent replays of the same token both pass the check before
// either wrote, which is exactly the replay this is meant to stop. The
// UPDATE's WHERE clause is the check, so the database serialises it.
func (s *PostgresStore) ConsumeScanToken(tokenHash, artifactID, kind string) (bool, error) {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx,
		`UPDATE scan_tokens
		    SET used_kinds = array_append(used_kinds, $3)
		  WHERE token_hash = $1
		    AND artifact_id = $2
		    AND expires_at > now()
		    AND NOT ($3 = ANY(used_kinds))`,
		tokenHash, artifactID, kind)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteScanTokens revokes every token for an artifact. Called when a
// scan finishes and from the stale-scan reclamation path, so a token
// never outlives the Job it was minted for even if that Job died
// without reporting.
func (s *PostgresStore) DeleteScanTokens(artifactID string) error {
	ctx := context.Background()
	// Expired rows anywhere are swept at the same time: this runs after
	// every scan, so it is the natural place, and it needs no CronJob.
	_, err := s.pool.Exec(ctx,
		`DELETE FROM scan_tokens WHERE artifact_id = $1 OR expires_at <= now()`, artifactID)
	return err
}

// ReplaceEnrichment swaps in a whole new copy of both feeds.
//
// WHOLESALE, NOT MERGED. Both feeds publish full snapshots, and a CVE
// leaving KEV -- or an EPSS score dropping -- is a real state change
// that a merge would never apply, so the row would keep asserting
// "known exploited" forever. Done in one transaction so a reader never
// sees a half-replaced catalogue.
//
// A feed passed as nil is left completely alone, which is what lets a
// refresh where one download failed still commit the other rather than
// discarding good data. Its updated_at is not touched either, so
// EnrichmentStatus keeps reporting the older feed as stale.
func (s *PostgresStore) ReplaceEnrichment(kev []string, epss map[string]float64, at time.Time) error {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enrichment replace: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if epss != nil {
		if _, err := tx.Exec(ctx, `UPDATE cve_enrichment SET epss_score = 0`); err != nil {
			return fmt.Errorf("clear epss: %w", err)
		}
		for cve, score := range epss {
			if _, err := tx.Exec(ctx, `
				INSERT INTO cve_enrichment (cve_id, epss_score) VALUES ($1, $2)
				ON CONFLICT (cve_id) DO UPDATE SET epss_score = EXCLUDED.epss_score
			`, strings.ToUpper(cve), score); err != nil {
				return fmt.Errorf("upsert epss %s: %w", cve, err)
			}
		}
		if err := recordFeed(ctx, tx, "epss", at, len(epss)); err != nil {
			return err
		}
	}

	if kev != nil {
		if _, err := tx.Exec(ctx, `UPDATE cve_enrichment SET known_exploited = false`); err != nil {
			return fmt.Errorf("clear kev: %w", err)
		}
		for _, cve := range kev {
			if _, err := tx.Exec(ctx, `
				INSERT INTO cve_enrichment (cve_id, known_exploited) VALUES ($1, true)
				ON CONFLICT (cve_id) DO UPDATE SET known_exploited = true
			`, strings.ToUpper(cve)); err != nil {
				return fmt.Errorf("upsert kev %s: %w", cve, err)
			}
		}
		if err := recordFeed(ctx, tx, "kev", at, len(kev)); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func recordFeed(ctx context.Context, q pgxIface, feed string, at time.Time, entries int) error {
	_, err := q.Exec(ctx, `
		INSERT INTO enrichment_feeds (feed, updated_at, entries) VALUES ($1, $2, $3)
		ON CONFLICT (feed) DO UPDATE SET updated_at = EXCLUDED.updated_at, entries = EXCLUDED.entries
	`, feed, at, entries)
	if err != nil {
		return fmt.Errorf("record feed %s: %w", feed, err)
	}
	return nil
}

// LookupEnrichment returns what the feeds know about the given CVEs.
// Ids with no row are simply absent from the result -- the caller
// leaves those findings unenriched rather than writing zeroes, so a
// re-run after a refresh can fill them in.
func (s *PostgresStore) LookupEnrichment(cveIDs []string) (map[string]Enrichment, error) {
	out := make(map[string]Enrichment, len(cveIDs))
	if len(cveIDs) == 0 {
		return out, nil
	}
	upper := make([]string, 0, len(cveIDs))
	for _, id := range cveIDs {
		upper = append(upper, strings.ToUpper(id))
	}
	rows, err := s.pool.Query(context.Background(),
		`SELECT cve_id, epss_score, known_exploited FROM cve_enrichment WHERE cve_id = ANY($1)`, upper)
	if err != nil {
		return nil, fmt.Errorf("lookup enrichment: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var e Enrichment
		if err := rows.Scan(&id, &e.EPSSScore, &e.KnownExploited); err != nil {
			return nil, err
		}
		out[id] = e
	}
	return out, rows.Err()
}

// EnrichmentStatus reports how current each feed is. Never-refreshed
// feeds come back with nil timestamps, which Fresh treats as stale.
func (s *PostgresStore) EnrichmentStatus() (EnrichmentStatus, error) {
	var st EnrichmentStatus
	rows, err := s.pool.Query(context.Background(), `SELECT feed, updated_at, entries FROM enrichment_feeds`)
	if err != nil {
		return st, fmt.Errorf("enrichment status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var feed string
		var at time.Time
		var entries int
		if err := rows.Scan(&feed, &at, &entries); err != nil {
			return st, err
		}
		when := at
		switch feed {
		case "kev":
			st.KEVUpdatedAt, st.KEVEntries = &when, entries
		case "epss":
			st.EPSSUpdatedAt, st.EPSSEntries = &when, entries
		}
	}
	return st, rows.Err()
}
