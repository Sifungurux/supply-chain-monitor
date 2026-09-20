package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	// Survives a later clean scan, unlike last_scan_at -- see
	// Artifact.LastScanErrorAt. Nullable: an artifact that has never
	// failed has no error timestamp, which is different from one that
	// failed at the zero time.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS last_scan_error_at TIMESTAMPTZ`,
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
	// Signature verification outcome (report H2). Defaults to the empty
	// string, which is ProvenanceUnknown -- correct for every artifact
	// that existed before cosign, and deliberately NOT "verified".
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS provenance TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS provenance_checked_at TIMESTAMPTZ`,
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS provenance_trust_root TEXT NOT NULL DEFAULT ''`,
	// Where ref pointed before it was rewritten to the in-cluster mirror
	// -- see Artifact.SourceRef. DEFAULT '' (not NULL) for the same
	// reason digest is: FindByRef matches on it, and a NULL would need
	// its own IS NULL branch in every comparison.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS source_ref TEXT NOT NULL DEFAULT ''`,
	// The last ten full scans' wall-clock milliseconds, oldest first --
	// see Artifact.ScanDurationsMs, which explains why this is ten
	// integers in a column rather than a scan_runs table. Same
	// idempotent ADD COLUMN IF NOT EXISTS pattern as everything above,
	// NULLABLE, unlike the TEXT columns above, and deliberately: pgx
	// encodes a nil Go slice as SQL NULL, so a NOT NULL column would
	// reject the Update of every artifact that has not been scanned
	// yet -- which is every artifact, once, right after this ships.
	// NULL and '{}' both read back as a nil slice and mean the same
	// thing here ("no scan has been timed"), so nothing downstream has
	// to tell them apart.
	`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS scan_durations_ms BIGINT[]`,
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
	// Risk acceptance (see Finding.AcceptedUntil and
	// internal/api/findings.go's acceptFinding). accepted_until is
	// NULLABLE rather than defaulted, unlike the two text columns beside
	// it: NULL means "never accepted", and there is no sentinel timestamp
	// that could stand in for that without also being a real, comparable
	// date in activeFindingSQL.
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_until TIMESTAMPTZ`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS acceptance_reason TEXT NOT NULL DEFAULT ''`,
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
	// Fleet-wide OpenVEX documents (POST /api/v1/vex) -- assessments
	// that hold wherever their products appear, rather than against one
	// artifact.
	//
	// NOT artifact_documents with kind "vex", and the difference is not
	// cosmetic: that table is keyed (artifact_id, kind) and cascades
	// from artifacts, which is exactly what a document belonging to no
	// single artifact cannot have. The two coexist -- see
	// FleetVEXDocument for which wins on conflict (the per-artifact
	// one, being the more specific claim).
	//
	// id is the SHA-256 of content, so re-uploading the same document
	// from a CI pipeline replaces the row instead of adding another
	// saying the same thing.
	`CREATE TABLE IF NOT EXISTS vex_documents (
		id           TEXT PRIMARY KEY,
		content_type TEXT NOT NULL,
		content      BYTEA NOT NULL,
		uploaded_at  TIMESTAMPTZ NOT NULL
	)`,
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
