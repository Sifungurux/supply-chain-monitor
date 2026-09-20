package artifact

import (
	"context"
	"fmt"
	"strings"
	"time"
)

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
	_, err := q.Exec(ctx, `INSERT INTO findings (artifact_id, bucket, finding_id, severity, title, source, status, first_seen_at, resolved_at, justification, epss_score, known_exploited, accepted_until, accepted_by, acceptance_reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		artifactID, bucket, f.ID, f.Severity, f.Title, f.Source, status, firstSeenAt, f.ResolvedAt, f.Justification, f.EPSSScore, f.KnownExploited, f.AcceptedUntil, f.AcceptedBy, f.AcceptanceReason)
	return err
}

func loadFindings(ctx context.Context, q pgxIface, artifactID, bucket string) ([]Finding, error) {
	rows, err := q.Query(ctx, `SELECT finding_id, severity, title, source, status, first_seen_at, resolved_at, justification, epss_score, known_exploited, accepted_until, accepted_by, acceptance_reason FROM findings WHERE artifact_id = $1 AND bucket = $2 ORDER BY id`, artifactID, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Severity, &f.Title, &f.Source, &f.Status, &f.FirstSeenAt, &f.ResolvedAt, &f.Justification, &f.EPSSScore, &f.KnownExploited, &f.AcceptedUntil, &f.AcceptedBy, &f.AcceptanceReason); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
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
// VEX-suppressed, not under an in-force risk acceptance. NOT IN rather
// than `= 'open'` for the same reason IsActive is written as an
// exclusion -- a row persisted before the status column existed carries
// whatever the migration defaulted it to, and anything unrecognized
// should count as still-a-problem.
//
// The acceptance half must stay in step with Finding.Accepted, which is
// the Go definition MemStore uses: a backend-dependent answer to "how
// many artifacts have active CVEs" is the kind of drift that only shows
// up in production, since the unit tests run against MemStore and only
// the integration tests reach this SQL at all.
//
// `accepted_until <= now()` (not `<`) mirrors Accepted's `t.Before` --
// an acceptance expiring exactly now has expired, and the finding is
// active again. NULL is the never-accepted case and must be spelled out
// because a NULL comparison is neither true nor false.
//
// Parenthesized as a whole: this is interpolated into WHERE clauses
// that AND further terms onto it, and an unbracketed OR inside would
// quietly swallow them.
const activeFindingSQL = `(status NOT IN ('fixed', 'not_affected') AND (accepted_until IS NULL OR accepted_until <= now()))`

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

func (s *PostgresStore) SaveFleetVEX(doc FleetVEXDocument) error {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vex_documents (id, content_type, content, uploaded_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET content_type = $2, content = $3, uploaded_at = $4
	`, doc.ID, doc.ContentType, doc.Content, doc.UploadedAt)
	if err != nil {
		return fmt.Errorf("save fleet VEX document %q: %w", doc.ID, err)
	}
	return nil
}

func (s *PostgresStore) ListFleetVEX() ([]FleetVEXDocument, error) {
	ctx := context.Background()
	// Ordered here rather than left to the scan path to sort: this is
	// read on every scan (see internal/api/scan.go's fleetVEXFor), and
	// an unstable order would make which of two documents wins for the
	// same vulnerability depend on the plan Postgres happened to pick.
	rows, err := s.pool.Query(ctx, `
		SELECT id, content_type, content, uploaded_at
		FROM vex_documents
		ORDER BY uploaded_at DESC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list fleet VEX documents: %w", err)
	}
	defer rows.Close()

	var out []FleetVEXDocument
	for rows.Next() {
		var doc FleetVEXDocument
		if err := rows.Scan(&doc.ID, &doc.ContentType, &doc.Content, &doc.UploadedAt); err != nil {
			return nil, fmt.Errorf("scan fleet VEX document: %w", err)
		}
		out = append(out, doc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list fleet VEX documents: %w", err)
	}
	return out, nil
}
