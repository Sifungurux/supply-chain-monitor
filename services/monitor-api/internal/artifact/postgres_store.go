package artifact

import (
	"context"
	"fmt"
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
