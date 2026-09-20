package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const selectArtifactColumns = `SELECT id, ref, source_ref, digest, type, status, current_stage, created_at, updated_at, last_scan_at, last_scan_error_at, maintainer_team, maintainer_email, last_scan_failure_reason, unsafe, provenance, provenance_checked_at, provenance_trust_root, scan_durations_ms FROM artifacts`

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

	err := row.Scan(&a.ID, &a.Ref, &a.SourceRef, &a.Digest, &typ, &status, &a.CurrentStage, &a.CreatedAt, &a.UpdatedAt, &a.LastScanAt, &a.LastScanErrorAt, &a.MaintainerTeam, &a.MaintainerEmail, &a.LastScanFailureReason, &a.Unsafe, &a.Provenance, &a.ProvenanceCheckedAt, &a.ProvenanceTrustRoot, &a.ScanDurationsMs)
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
		// source_ref is in the list because a mirrored artifact's ref
		// names the local copy: searching for the upstream ref it was
		// registered with has to keep finding it. The mirror path happens
		// to CONTAIN the original repo name, so a tag ref would match by
		// substring anyway -- but a digest-pinned one would not, and
		// "works for some refs" is not a searchable field.
		clauses = append(clauses, fmt.Sprintf(
			"(ref ILIKE $%d OR source_ref ILIKE $%d OR digest ILIKE $%d OR maintainer_team ILIKE $%d OR maintainer_email ILIKE $%d OR current_stage ILIKE $%d)",
			n, n, n, n, n, n))
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
	findingRows, err := s.pool.Query(ctx, `SELECT artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at, justification, epss_score, known_exploited, accepted_until, accepted_by, acceptance_reason FROM findings WHERE artifact_id = ANY($1) ORDER BY artifact_id, id`, ids)
	if err != nil {
		return fmt.Errorf("batch load findings: %w", err)
	}
	for findingRows.Next() {
		var artifactID, bucket string
		var f Finding
		if err := findingRows.Scan(&artifactID, &bucket, &f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt, &f.Justification, &f.EPSSScore, &f.KnownExploited, &f.AcceptedUntil, &f.AcceptedBy, &f.AcceptanceReason); err != nil {
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
	//
	// ref and source_ref are here for a sharper version of the same
	// reason: mirroring rewrites BOTH (internal/api/mirror.go), and they
	// have to land together or not at all -- a ref pointing at the local
	// mirror with no source_ref has lost where it came from, with no way
	// back. One statement, one transaction, so there is no window in
	// which only half of that rewrite is on disk.
	if _, err := tx.Exec(ctx, `UPDATE artifacts SET status = $1, current_stage = $2, digest = $3, updated_at = $4, last_scan_at = $5, last_scan_error_at = $6, maintainer_team = $7, maintainer_email = $8, last_scan_failure_reason = $9, unsafe = $10, provenance = $11, provenance_checked_at = $12, provenance_trust_root = $13, ref = $14, source_ref = $15, scan_durations_ms = $16 WHERE id = $17`,
		string(a.Status), a.CurrentStage, a.Digest, a.UpdatedAt, a.LastScanAt, a.LastScanErrorAt, a.MaintainerTeam, a.MaintainerEmail, a.LastScanFailureReason, a.Unsafe, a.Provenance, a.ProvenanceCheckedAt, a.ProvenanceTrustRoot, a.Ref, a.SourceRef, a.ScanDurationsMs, a.ID); err != nil {
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
	// source_ref as well as ref: once an artifact has been mirrored its
	// ref names the in-cluster copy, and a caller re-registering the
	// ORIGINAL public ref is still registering the same thing. Matching
	// only ref would let every mirrored artifact be registered a second
	// time under its upstream name -- the same duplicate accumulation
	// this fallback exists to stop.
	row := s.pool.QueryRow(ctx, selectArtifactColumns+`
		WHERE ref = $1 OR source_ref = $1
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
