module github.com/kirk-pedersen/supply-chain-monitor/monitor-api

go 1.25.0

// pgx is the one non-stdlib dependency in this module, needed to talk
// to Postgres (see internal/artifact/postgres_store.go and
// docs/architecture.md). go.sum IS committed (since f0b9c95, run via
// `make lock-deps`) -- see docs/tech-debt-audit.md for the one place
// this still isn't fully taken advantage of: the Dockerfile's build
// stage still runs `go mod tidy` on every build rather than verifying
// against the committed go.sum, which is a real, small, separate fix.
require github.com/jackc/pgx/v5 v5.10.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
