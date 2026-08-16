module github.com/kirk-pedersen/supply-chain-monitor/monitor-api

go 1.26.0

// pgx is the one non-stdlib dependency in this module, needed to talk
// to Postgres (see internal/artifact/postgres_store.go and
// docs/architecture.md). go.sum IS committed (since f0b9c95, run via
// `make lock-deps`), and the Dockerfile's build stage verifies against
// it with `go mod download && go mod verify` rather than re-resolving
// with `go mod tidy` -- tech-debt-audit.md item #5, since fixed. This
// comment used to say otherwise.
require github.com/jackc/pgx/v5 v5.10.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
