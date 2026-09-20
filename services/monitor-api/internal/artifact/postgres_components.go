package artifact

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *PostgresStore) ComponentPURLs(artifactID string) ([]string, error) {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `SELECT purl FROM components WHERE artifact_id = $1`, artifactID)
	if err != nil {
		return nil, fmt.Errorf("list component purls for %q: %w", artifactID, err)
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var purl string
		if err := rows.Scan(&purl); err != nil {
			return nil, fmt.Errorf("scan component purl: %w", err)
		}
		if purl != "" {
			out = append(out, purl)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list component purls for %q: %w", artifactID, err)
	}
	return out, nil
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
