module github.com/kirk-pedersen/supply-chain-monitor/monitor-api

go 1.22

// pgx is the one non-stdlib dependency in this module, needed to talk
// to Postgres (see internal/artifact/postgres_store.go and
// docs/architecture.md). go.sum is intentionally NOT committed: it
// couldn't be generated correctly in the sandbox this was written in
// (no Go toolchain, no network access to the module proxy/checksum
// database). The Dockerfile's build stage runs `go mod tidy` before
// `go build`, which regenerates go.sum with real checksums fetched at
// build time -- see the comment there. Run `make lock-deps` once (needs
// only Docker, not a local Go install) and commit the resulting go.sum
// for reproducible, pinned builds; until then, every build re-resolves
// and re-verifies the dependency graph against sum.golang.org.
require github.com/jackc/pgx/v5 v5.7.2

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
