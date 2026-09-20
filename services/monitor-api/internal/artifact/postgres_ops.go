package artifact

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

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
