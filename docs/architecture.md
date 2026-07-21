# Architecture

## Goal

Track artifacts moving through a software delivery pipeline — container
images, build outputs, SBOMs, SARIF reports, or anything else that can
be packaged as an OCI artifact — and answer three questions about each
one through an API: does it have known CVEs, does it contain malware,
and what pipeline stage is it currently at.

## Components

```
                        ┌────────────────────┐
   CI/CD pipeline  ───▶ │     monitor-api     │ ◀─── operators / dashboards
   (webhooks:           │  (Go, stdlib HTTP)  │
    register artifact,  └─────────┬──────────┘
    report stage)                 │
                    ┌────────┬────┼─────┬──────────┐
                    ▼        ▼    ▼     ▼          ▼
               ┌─────────┐ ┌──────┐  ┌───────────────┐
               │ scm-    │ │clamav│  │  scm-postgres  │
               │registry │ │(3310)│  │ (Percona PG,   │
               │ (OCI,   │ │malware│  │  artifacts +  │
               │ :5000)  │ │scan  │  │  findings +   │
               └─────────┘ └──────┘  │ stage history)│
                  ▲             ▲    └───────────────┘
                  │             │
            trivy CLI     unpacker pulls + unpacks
         (CVE scan of      the image to a temp dir,
          image, in-      then streams every file
          process)        in it to clamav (malware
                           scan of image contents)
```

All five pieces run as Deployments in the `supply-chain-monitor`
namespace on a local Kubernetes cluster on macOS, created via
`cluster/create-cluster.sh`. Two runtime backends are supported:
Colima's native `--kubernetes` (k3s in the Docker VM, default and
recommended) or k3d running against Podman (experimental — k3d's own
docs flag Podman support as such, and there are open macOS-specific
bugs). See the README's "Choosing a runtime" section and
`cluster/runtimes/{colima,podman}.sh` for details; this choice is
orthogonal to everything else described below — the manifests in `k8s/`
don't care which runtime put the cluster there.

- **scm-registry** (`registry:2`) stands in for wherever the real
  pipeline pushes artifacts — a place to push test images/files during
  development so `monitor-api` has something real to point at.
- **scm-clamav** (`clamav/clamav:1.3`) is the malware-scanning backend,
  spoken to over the `clamd` INSTREAM protocol.
- **scm-postgres** (`percona/percona-distribution-postgresql:17.10`)
  persists every artifact, its findings, and its stage history —
  replacing the original in-memory store. See "Swapping the in-memory
  store for Postgres" below.
- **monitor-api** is the service being built: it owns the artifact
  model, the pipeline-stage state machine, and routes scan requests to
  the right backend(s) by artifact type. `image` artifacts route to
  *two* scanners (Trivy for CVEs, unpacker+ClamAV for malware); `file`
  artifacts route to ClamAV alone.
- CVE scanning currently shells out to the `trivy` CLI baked into the
  `monitor-api` image, rather than talking to a separate `trivy-server`
  — see "Why no trivy-server yet" below.
- Malware scanning of images shells out to `unpacker`
  (github.com/Sifungurux/unpacker, also baked into the image) to pull
  the image and reconstruct its filesystem, then streams every file in
  it to `scm-clamav` — see "Why images need unpacking" below.
- **scm-dashboard** (`nginx:1.27-alpine` serving a static page from a
  ConfigMap) is a browser UI over `monitor-api`: artifact table,
  pipeline-stage view, and scan findings detail. It's a separate
  Deployment/Service, not something `monitor-api` serves itself — see
  "Why a separate static dashboard" below.

## Design decisions and why

**Go, stdlib only, no framework.** Go 1.22's `net/http.ServeMux` got
method + wildcard path routing (`"POST /api/v1/artifacts/{id}/scan"`),
which is enough for this API surface without pulling in chi/gin/echo.
Keeps the skeleton dependency-free and easy to `go build` without a
`go.sum` to manage while the shape of the service is still moving.

**Artifact store: Postgres in production, in-memory for tests.**
`internal/artifact/store.go` now defines a `Store` interface
(`Create`/`Get`/`List`/`Update`) with two implementations: `MemStore`
(the original `sync.RWMutex`-protected map -- kept purely so this
package's and `internal/api`'s own unit tests stay fast and hermetic)
and `PostgresStore` (`postgres_store.go`), which is what `main.go`
actually wires up. See "Swapping the in-memory store for Postgres"
below for why and how.

**Swapping the in-memory store for Postgres.** The original `Store`
was deliberately in-memory ("v1 stub, no external dependencies, holds
until the schema stops changing"), with a comment saying as much and
promising a swap to a real backend later. That schema (artifact +
findings + stage history) had settled by the time this changed, and
the practical cost of the in-memory store had become real: every
`monitor-api` pod restart (a `kubectl rollout restart`, a crash, a node
reschedule) silently wiped every registered artifact and its scan
history. That's fine for a five-minute demo, not for anything meant to
actually track a pipeline.
Postgres was the obvious choice given the interface was already
designed for a drop-in swap; **Percona Distribution for PostgreSQL**
specifically (rather than the plain `postgres` image) because it's a
drop-in-compatible build of stock PostgreSQL with Percona's own
support/tooling layered on top, so nothing about the schema, the
driver, or the SQL below cares which one is running underneath — the
only real repo-visible acknowledgment is the image name in
`charts/postgres/templates/deployment.yaml` (originally
`k8s/postgres/deployment.yaml`, before the move to Helm charts -- see
"All services on Flux + Helm").
`internal/artifact/postgres_store.go` originally stored everything in a
single `artifacts` table, with `stage_history`, `cve_findings`,
`malware_findings`, and `last_scan_errors` as `JSONB` columns rather
than normalized into their own tables -- a deliberate simplicity
choice at the time, not an oversight, made on the reasoning that
nothing outside this service needed to query "every artifact with CVE
X" yet. That's since changed -- see "Normalizing findings and stage
history into their own tables" below for why and how, including the
migration path for a cluster that already has the old schema.
`Update` does a `SELECT ... FOR UPDATE` inside a transaction before
writing, which is a genuine improvement over `MemStore`'s single
global mutex: two concurrent updates to two *different* artifacts no
longer serialize against each other at all, while two concurrent
updates to the *same* artifact still can't silently drop one of them
(see `TestPostgresStore_UpdateSerializesConcurrentWritesToSameArtifact`
in the Postgres integration test, below).
Connecting to Postgres can legitimately fail on the very first attempt
in Kubernetes — `scm-postgres` and `monitor-api` start up concurrently
via the same `kubectl apply -k`, with no guarantee Postgres finishes
initializing its data directory first. `main.go`'s
`connectStoreWithRetry` retries `NewPostgresStore` with a fixed 5s
backoff (12 attempts, ~60s worst case) rather than crashing and relying
on Kubernetes' own crash-loop-backoff, which would otherwise add its
own growing delay on top. `charts/monitor-api/templates/deployment.yaml`'s
liveness/readiness probes were tuned to tolerate that ~60s window
without killing a pod that's still legitimately retrying (see the
comments there).
Credentials live in a Kubernetes Secret
(`charts/postgres/templates/secret.yaml`, `scm-postgres-credentials`) rather than
the plaintext `ConfigMap` the rest of `monitor-api`'s config lives in —
mounted into `monitor-api`'s pod via `secretKeyRef` for
`POSTGRES_PASSWORD` specifically, everything else (host, port, user,
db, sslmode) stays in the ordinary `ConfigMap` since none of it is
sensitive. The default password in that Secret
(`changeme123`) is exactly as placeholder as it looks — fine for a
local, single-user dev cluster, not for anything shared (same caveat
this project already has around `unpacker`'s hardcoded `--insecure
--public`, and around the dashboard/API's own auth Secret -- see
"Adding API authentication").
Testing this without a real database would mean either mocking the
SQL (brittle, doesn't actually prove the queries are correct) or
skipping it (leaves the riskiest new code in this change completely
unverified). Instead,
`internal/artifact/postgres_store_integration_test.go` is a real
integration test gated behind a `postgres_integration` Go build tag, so
`go test ./...` (what `make test-api` and any CI eventually wired up
against it run) never needs a database, but `make test-postgres` spins
up a throwaway Percona container, points the test suite at it via
`POSTGRES_TEST_DSN`, and tears it down afterward — the same "containers
mean no local install needed" philosophy `test-api`/`test-dashboard`
already use, just for a heavier dependency that shouldn't be part of
the default fast path.
One real limitation from writing this in a sandbox with no Go
toolchain and no network access to the module proxy: `go.sum` isn't
committed (see the comment in `go.mod`). The `Dockerfile`'s build stage
runs `go mod tidy` before `go build` to generate one at build time
instead, which works fine (the build has real internet access) but
means the dependency graph isn't pinned/reproducible until someone runs
it once with a real Go install and commits the result -- `make
lock-deps` does exactly that (via a containerized `golang:1.22-alpine`,
so it needs only Docker, not a local Go install) and is the recommended
way to do it, over running `go mod tidy` by hand, since it also runs
`go vet`/`go mod verify` as a sanity check on the result.

**Normalizing findings and stage history into their own tables.** The
original schema kept `stage_history`, `cve_findings`,
`malware_findings`, and `last_scan_errors` as `JSONB` columns directly
on the `artifacts` row -- simple, and a near-literal mirror of the
`Artifact` struct, but it meant answering "which artifacts are still
affected by CVE-2024-X" required scanning and JSON-decoding every
single row, since Postgres can't index into the middle of a JSONB
array the way it can a real column. `internal/artifact/postgres_store.go`
now splits those into three real tables -- `stage_history`, `findings`
(with a `bucket` column: `cve`/`malware`/`other`, replacing the three
separate JSONB arrays), and `scan_errors` -- each row referencing its
artifact via a foreign key, with an index on `findings.finding_id`
specifically so that query is now a single indexed lookup. `Store`
gained a new method, `FindByFindingID`, to actually expose this --
`MemStore`'s implementation is a plain linear scan (fine at in-memory
test-fixture scale), `PostgresStore`'s uses the index; a new endpoint,
`GET /api/v1/findings/{findingID}/artifacts`, exposes it over the API
(see README).
`mutate` (the callback `Update` takes) always leaves the *complete*
desired state of each slice field on the `Artifact` struct, not an
incremental delta -- appending one entry for a stage-history update,
replacing the whole set wholesale after a `/scan` call. The simplest
way to persist that correctly against three separate child tables
turned out to be the most literal one: inside `Update`'s transaction,
delete every existing row for that artifact in each child table and
re-insert whatever `mutate` left in the struct, in the same order.
Not the most efficient possible approach for a stage history that
grows across an artifact's whole lifetime, but obviously correct to
read, and stage/finding counts per artifact are small in practice --
worth revisiting only if that stops being true.
`Get`/`Update` each do one query per child table (four total, one for
the artifact row itself); `List` and `FindByFindingID` batch this into
three queries total regardless of how many artifacts come back (`WHERE
artifact_id = ANY($1)`, grouped in Go), specifically to avoid an N+1
query pattern that would otherwise scale with the size of the list.
Migrating an already-running cluster (one still on the old single-table
JSONB schema) needed real thought, since `make deploy` against an
existing cluster shouldn't mean "wipe all your data": `migrate()` first
runs `CREATE TABLE IF NOT EXISTS` for the new tables (a no-op if they
already exist), then `migrateLegacyJSONBColumns` checks whether the old
JSONB columns are still present on `artifacts` (via
`'artifacts'::regclass` + `pg_attribute`, which resolves the table the
same schema-aware way every other unqualified query in this file does
-- `information_schema.columns` was tried first and rejected, since it
isn't `search_path`-aware and would happily report a false match from
an unrelated same-named table in a different schema). If the old
columns are found, every row's JSONB data is decoded and copied into
the new tables inside one transaction, then the old columns are
dropped. This runs automatically, once, the next time `NewPostgresStore`
connects to an un-migrated database -- no separate migration step for
a human to remember to run. `postgres_store_integration_test.go`
proves this against a real database by hand-building the exact old
schema (in a disposable, uniquely-named Postgres schema/namespace, so
it doesn't collide with whatever the other integration tests in the
same run have already done against the default `public` schema),
seeding it with data, then asserting the data survived the move and the
old columns are actually gone afterward.
One real bug this incidentally fixed: the old schema never had a
column for `OtherFindings` (SARIF results) at all -- it was added to
the `Artifact` struct once SARIF scanning shipped, but the JSONB
persistence layer was never updated to match, so `OtherFindings`
silently never persisted past the single HTTP response that set it.
Nothing to migrate for it from the old schema (it was never actually
stored there), but the new `findings` table has a proper `other`
bucket, so it persists correctly going forward.

**Scanner as an interface + registry keyed by artifact type, one-to-many**
(`internal/scanner/scanner.go`). `Registry` maps a type to a *slice* of
scanners, not a single one: `image` → `[Trivy, Unpacker+ClamAV]`, `file`
→ `[ClamAV]`. The handler runs every scanner registered for a type and
sorts findings into `cve_findings`/`malware_findings` by
`Finding.Source` rather than by artifact type — that's what let malware
scanning get added to `image` artifacts without touching the CVE path
at all. `sbom` and `sarif` artifact types exist in the model already but
have no scanner wired up yet — registering one just won't have anywhere
to route a `/scan` call until that's added (see Roadmap).

**Why images need unpacking.** A container image is layers of
compressed tarballs, not a filesystem clamd can point at — `clamdscan`
or the INSTREAM protocol both expect an actual file's bytes, not an OCI
manifest plus blobs. `UnpackerScanner`
(`internal/scanner/unpacker.go`) shells out to `unpacker`
(github.com/Sifungurux/unpacker, built from source into the
`monitor-api` image — see Dockerfile) to pull the image (oras-go, with
a go-containerregistry/crane fallback for plain Docker images) and
unpack it via `umoci` into `<tmp>/image/`, a plain directory. From
there it's identical to scanning any other file: walk the tree, stream
each regular file to clamd over the same INSTREAM client
`ClamAVScanner` uses (factored out into `clamd_client.go` so both
scanners share one implementation). Files above `UNPACKER_MAX_FILE_MB`
(default 100MB) are skipped rather than streamed, and if every single
file in an image fails to reach clamd, that's surfaced as an error
instead of silently reporting a "clean" image that was never actually
scanned.
`unpacker` and `umoci` are both built from source in the Dockerfile
(rather than downloading `unpacker`'s prebuilt release or umoci's
amd64-only release binary) specifically so this also works unmodified
on an Apple Silicon Mac's arm64 Colima/Podman VM. `unpacker` has no
tagged releases yet, so its build stage pins an exact commit SHA
(`UNPACKER_COMMIT` in the Dockerfile) rather than tracking `main`.

**Why no trivy-server yet.** Trivy's client/server mode shares a
vulnerability DB across scans, which matters once you're scanning a lot
of images, but it talks a bespoke RPC protocol rather than plain REST.
For a v1 skeleton, invoking the `trivy` CLI directly per scan is far
less code and is a drop-in swap later (the `Scanner` interface doesn't
care how `TrivyScanner` gets its answer).

**SBOM and SARIF artifacts now actually get scanned.** Both types
existed in the `Artifact` model from the start but had no scanner
registered against them -- a `/scan` call just 501'd. They needed
fundamentally different treatment from each other, and from the
existing scanners:
- **`sbom`** (`internal/scanner/sbom.go`, `SBOMScanner`) shells out to
  `trivy sbom` rather than `trivy image` -- a CycloneDX/SPDX SBOM
  document lists components directly, so there's no image to pull or
  unpack first, but it's still the same vulnerability DB and the same
  `--db-repository`/`--skip-db-update` air-gapped-mirror flags as
  `TrivyScanner`. That shared behavior (DB-mirror flag assembly, JSON
  result parsing) was factored out of `trivy.go` into `dbArgs()` and
  `parseTrivyVulnerabilities()` so `SBOMScanner` doesn't duplicate
  either -- both are independently unit-tested against canned
  input/output rather than through `Scan()` itself, since `Scan()`
  still needs the real `trivy` binary.
- **`sarif`** (`internal/scanner/sarif.go`, `SARIFScanner`) doesn't
  scan anything -- a SARIF document already **is** a set of findings,
  produced by whatever tool generated it (CodeQL, Semgrep, even
  trivy's own `--format sarif` output). `SARIFScanner.Scan` just
  parses the file and normalizes its `runs[].results[]` into
  `artifact.Finding`s, matching a rule's `shortDescription` up by
  `ruleId` for a human-readable title when one exists. Severity
  prefers a rule's `properties.security-severity` (a de facto
  CVSS-like 0-10 score several tools emit, including CodeQL and
  trivy's own SARIF output, though it's not part of the core SARIF
  2.1.0 spec) when present, falling back to mapping SARIF's own
  three-level `level` (error/warning/note) onto the same
  low/medium/high vocabulary trivy findings use when it isn't. This is
  pure Go, no external binary -- unlike every other `Scan()` in this
  package, it can actually be unit-tested end to end without anything
  installed (see `sarif_test.go`).
  Since SARIF covers SAST issues, secrets, IaC misconfigurations, and
  linting -- not specifically CVEs or malware -- its findings
  (`Finding.Source == "sarif"`) land in a new third bucket,
  `Artifact.OtherFindings`, rather than being folded into
  `CVEFindings` where they'd be mislabeled. `internal/api/handlers.go`'s
  `scanArtifact` now switches on `Finding.Source` (`clamav` → malware,
  `sarif` → other, everything else → CVE) instead of the old
  two-way `clamav`-or-not check.
- Both inherited the same v1 simplification `file`-type artifacts
  already had -- `ref` assumed to already be a filesystem path
  reachable inside the `monitor-api` pod -- until "Fetching
  file/sbom/sarif artifacts from the registry" below closed that gap
  for all three at once.
- The dashboard grew a third findings column/section ("Other") to
  match, so SARIF results are actually visible rather than silently
  parsed and never shown anywhere -- the same "looks fine, shows
  nothing" bug class as the dashboard's earlier API-base bug, avoided
  proactively this time instead of shipped-then-fixed.

**Fetching file/sbom/sarif artifacts from the registry.** Every
scanner in this package used to fall into one of two categories:
`TrivyScanner`/`UnpackerScanner` fetch the `image` artifact themselves
(from an OCI registry, ref is a real image reference), while
`ClamAVScanner`/`SBOMScanner`/`SARIFScanner` assumed `ref` was *already*
a filesystem path reachable inside the `monitor-api` pod -- a
convenient v1 shortcut, but one that made `file`/`sbom`/`sarif`
artifacts hard to actually use for anything beyond a demo, since
nothing put that file on the pod's filesystem in the first place.
Given this project's own founding premise -- "an artifact is anything
that can be packed into an OCI artifact" -- the natural fix was to let
`ref` for these three types *also* be an OCI registry reference (to
`scm-registry`, the same registry `image` artifacts already use), and
fetch it the same way `oras cp` already moves the Trivy DB around in
`cluster/seed-trivy-db.sh`.
Rather than teaching `ClamAVScanner`/`SBOMScanner`/`SARIFScanner`
themselves how to fetch (which would mean repeating the same fetch
logic three times, and coupling scan logic to fetch logic), this is a
decorator: `FetchingScanner` (`internal/scanner/fetch.go`) wraps any
existing `Scanner`, resolves `ref` to a local path via a `Fetcher`
first, calls the wrapped scanner with that path exactly as before, and
cleans up. `main.go` wraps the three affected scanners in
`FetchingScanner`; `TrivyScanner`/`UnpackerScanner` (image) stay
unwrapped since they already do their own fetching. None of
`ClamAVScanner`/`SBOMScanner`/`SARIFScanner`'s own code changed at all.
`RegistryFetcher` (the one `Fetcher` implementation so far) shells out
to `oras pull` -- a new binary baked into the `monitor-api` image
alongside trivy/umoci/unpacker (see Dockerfile), using official
prebuilt release tarballs rather than building from source, since oras
(unlike umoci and unpacker) ships real arm64 release binaries. To stay
backward compatible with the original convention rather than silently
changing what `ref` means, `looksLikeLocalPath` checks whether `ref`
starts with `/`, `.`, or `~` -- if so, `Fetch` is a no-op passthrough
(still a path inside the pod, e.g. a shared volume); otherwise it's
treated as a registry reference and pulled. `oras pull` writes every
layer in the artifact to a directory; `singleFileIn` requires there be
*exactly* one file, since these three artifact types are expected to
be single-blob (one file, one SBOM document, one SARIF report) --
anything else is an error rather than a guess about which file to
scan.
`FetchingScanner`'s wrapping means every piece of this except
`RegistryFetcher.Fetch`'s actual `oras pull` call is testable without
any external binary or registry -- `fetch_test.go` covers the
local-path passthrough, the single-file selection logic, and the
decorator's fetch-then-scan-then-cleanup behavior (including that
cleanup always runs and the inner scanner never runs if the fetch
itself fails) using fakes, the same pattern `internal/api/handlers_test.go`
already uses for `Scanner`s generally.
`RegistryFetcher.PlainHTTP` defaults to `true` (`FETCH_PLAIN_HTTP` env
var), matching `scm-registry`'s own unauthenticated plain-HTTP setup --
the same assumption `UnpackerScanner`'s hardcoded `--insecure --public`
already makes for images. Pointing this at a private, authenticated,
or TLS-terminated registry isn't wired up yet (no credentials, no
`--insecure` vs `--plain-http` distinction exposed) -- same gap as
`unpacker`'s, now shared by both fetch paths (see Roadmap).

**ClamAV via raw INSTREAM protocol.** `internal/scanner/clamav.go`
implements the length-prefixed streaming protocol directly against
`clamd` rather than shelling out to `clamdscan`, since the client image
and the daemon don't share a filesystem here. Reasonable to leave as-is.

**Why a separate static dashboard.** The dashboard is one HTML file
(`dashboard/index.html`, copied verbatim into
`charts/dashboard/files/index.html` and embedded into a ConfigMap by
`charts/dashboard/templates/configmap.yaml`) served by stock
`nginx:1.27-alpine` —
no build step, no JS framework, no new language in the stack. It calls
`monitor-api`'s existing REST endpoints directly from the browser
(`fetch`, polled every 10s) rather than `monitor-api` serving its own
UI, so the API stays a plain JSON service and the two can scale/deploy
independently. The trade-off: the browser is now making cross-origin
requests (dashboard's origin → API's origin), which only works because
`monitor-api` sends `Access-Control-Allow-Origin: *` (see `withCORS` in
`internal/api/router.go`). Now that the API requires a bearer API key
on every real request (see "Adding API authentication" below), the
wide-open origin is less of a gap than it was — a browser on any
origin can *attempt* a request, but without the key it gets a 401, the
same as `curl` from anywhere else would. An origin allowlist would add
essentially nothing on top of that, since the key (not the Origin
header) is what actually gates access.
The dashboard's own color tokens are hardcoded hex (light + a
`prefers-color-scheme: dark` override) rather than referencing any
external design-system stylesheet, since this page is served standalone
from the cluster and opened in a plain browser tab — it can't assume
any host page has defined CSS custom properties for it.

**A shipped bug, and what it changed.** The first version of the
dashboard hardcoded `DEFAULT_API_BASE = 'http://localhost:30300'`. That
happened to match the podman runtime (k3d maps NodePorts straight to
host `localhost`) but silently broke the colima runtime -- the default
runtime -- since Colima's NodePorts are only reachable via the VM's own
address once `--network-address` is set; "localhost" from the Mac never
reaches them at all. The dashboard would just sit there showing no
artifacts, with the only clue being a small red status line easy to
miss. Fixed by deriving the default from `window.location` (protocol +
hostname of wherever the dashboard page itself was loaded from) instead
of a fixed string -- since the dashboard and the API are exposed on the
same host by construction, this self-corrects regardless of runtime.
`dashboard/tests/dashboard.test.js` has a standing regression test for
this (`defaults the API base to the dashboard's own host...`), plus
tests for the empty-state, error-state, and HTML-escaping paths that
would have made this class of "looks fine, shows nothing" bug much
faster to isolate.

**A second shipped bug: rebuilding the image didn't actually redeploy
it.** `make deploy` ran `docker build` then `kubectl apply -k k8s/`.
`kubectl apply` only restarts a pod when the Deployment *object*
changes; the image tag (`monitor-api:dev`) never changed across builds,
so `kubectl apply` saw an identical spec and left the already-running
pod alone -- even though the image *content* underneath that tag had
changed. In practice this meant every backend change in a given session
(the CORS headers, the multi-scanner registry, the unpacker
integration) could sit built-but-not-actually-running until something
happened to force a pod restart, which looked identical to a CORS or
connectivity failure from the dashboard's side. Fixed by adding
`kubectl rollout restart` for both `monitor-api` and `scm-dashboard`
into `make deploy`, so it's no longer possible to build new code and
have it silently not take effect. If you ever bypass `make deploy` and
apply manifests by hand, remember to `kubectl rollout restart
deployment/monitor-api` afterward.

**A third shipped bug: scans were tied to the request's lifetime.**
`scanArtifact` originally built its scan context with
`context.WithTimeout(r.Context(), 5*time.Minute)`. `net/http` cancels
`r.Context()` the instant the client connection goes away for *any*
reason -- a closed tab, a network blip, an idle timeout somewhere in
the path -- which is a real risk here since a scan can legitimately run
for a couple of minutes (trivy's first-run vulnerability DB download
alone). When that happened mid-scan, Go's `exec.CommandContext` sent
SIGKILL to whichever scanner was currently running (surfacing as
`"signal: killed"`) and every scanner still queued in the loop failed
instantly against the now-dead context (`"context canceled"`) -- two
different-looking errors from what was really one root cause. Fixed by
building the scan's context from `context.Background()` instead, so the
scan always runs to completion and updates the store regardless of what
happens to the HTTP connection that kicked it off; the dashboard's own
10s polling picks up the result either way.
`TestScanArtifact_SurvivesCanceledRequestContext` in
`internal/api/handlers_test.go` pins this down directly: it cancels the
request context *before* the handler even starts and asserts the
scanner never sees a canceled context.
`monitor-api`'s memory limit was also bumped (768Mi → 1Gi) as
defense-in-depth, since `"signal: killed"` is also exactly what an
OOM-kill produces and trivy's DB download is memory-hungry enough that
it can't be fully ruled out as a contributing factor on top of the
context bug.

**Air-gapped Trivy DB support, via an OCI mirror.** Trivy doesn't ship
its vulnerability database — on every scan it pulls two separate OCI
artifacts (`ghcr.io/aquasecurity/trivy-db:2`, and
`ghcr.io/aquasecurity/trivy-java-db:1` for Java) from the public
internet. That's invisible on a normal dev machine but a hard blocker
in an air-gapped cluster, and it's also exactly the kind of thing that
can silently degrade a "quiet" scan into an empty one if the pull ever
fails without loud logging. Rather than build a bespoke DB-caching
mechanism, this leans on the fact that trivy's own `--db-repository` /
`--java-db-repository` flags accept *any* OCI registry reference — so
the fix is to mirror both DB artifacts into `scm-registry` (already
running in-cluster for everything else) and point trivy at that mirror
instead of ghcr.io.
`TrivyDBConfig` (`internal/scanner/trivy.go`) holds the two repository
overrides plus `--skip-db-update`/`--skip-java-db-update` (skip even
trying the network once a copy is mirrored locally); empty strings mean
"trivy's own public default," so this is opt-in and changes nothing for
anyone with normal internet access. `TrivyScanner.args()` was split out
of `Scan()` specifically so this flag assembly could be unit-tested
(`internal/scanner/trivy_test.go`) without needing a real `trivy`
binary in the test run.
`cluster/seed-trivy-db.sh` does the actual mirroring, once, while still
online: `oras cp --to-plain-http` streams both artifacts straight from
ghcr.io into `scm-registry` without touching local disk. It's a
separate manual step rather than something `monitor-api` does itself on
startup, since seeding *requires* internet access — the whole point is
to do it once before going air-gapped, not to have the API silently
depend on connectivity it may not have later.
Left for later: the Java DB mirror is wired up in parallel with the
main DB but untested against a real `--java-db-repository` pull (no
Java images scanned yet in this project); and `oras cp` itself assumes
an unauthenticated source registry, so mirroring from a private ghcr.io
mirror of your own would need auth flags this script doesn't pass yet.

**Pipeline stage tracking is a labeled state machine, not a workflow
engine.** `PIPELINE_STAGES` (env/ConfigMap) defines the valid stage
names; `POST /artifacts/{id}/stage` just validates the name and appends
to history. There's no enforcement of stage *order* yet — anything can
report any valid stage at any time. That's deliberate for v1: real
pipelines don't always report events in order (retries, parallel
stages), and over-constraining this early would make the API annoying
to integrate against.

**Isolating the unpack+scan step.** `UnpackerScanner` pulls and parses
arbitrary, potentially-malicious image content (oras-go /
go-containerregistry / umoci) -- for a while, that ran in-process
inside `monitor-api` itself, the same process holding every artifact's
findings and the live Postgres connection. A parsing bug in any of
those third-party libraries had the same blast radius as a bug in
`monitor-api` itself. The fix: `IsolatedUnpackerScanner`
(`internal/scanner/isolated_unpacker.go`) creates a dedicated
Kubernetes Job per scan instead, and `main.go`'s scanner registry now
registers that in `TrivyScanner`'s place -- `TrivyScanner` itself stays
in-process deliberately (see below).
- **How it works:** `monitor-api` gained a second mode,
  `monitor-api scan-worker` (`main.go`'s `runScanWorker`) -- the exact
  same binary, but instead of starting an HTTP server it runs a single
  `UnpackerScanner.Scan` call against `SCM_SCAN_REF` and prints the
  result as JSON to stdout, then exits. `IsolatedUnpackerScanner`
  creates a Job whose one container runs `monitor-api scan-worker`,
  polls the Job's status, and once it finishes, reads the result back
  from that pod's logs. `UnpackerScanner`'s own code never changed at
  all -- it just runs in a different pod now.
- **Why a Job, and why hand-rolled REST instead of client-go:**
  a Job per scan gives each one a pod whose entire lifecycle is
  "start, do one scan, exit" -- unlike the long-running API pod, it
  can be locked down about as far as Kubernetes allows: read-only root
  filesystem (with a `/tmp` `emptyDir` carved out for unpacker's own
  scratch space), every Linux capability dropped, non-root
  (`runAsUser: 65534`, alpine's built-in `nobody` -- no Dockerfile
  change needed), and no ServiceAccount token at all (a brand new,
  zero-RBAC `scm-scan-worker` ServiceAccount --
  `charts/monitor-api/templates/serviceaccount.yaml`). None of that is
  achievable for the API server pod itself without breaking its actual
  job (serving requests, holding a Postgres connection open).
  Doing this requires `monitor-api` to call the Kubernetes API for the
  first time -- create a Job, poll it, read pod logs, delete it.
  `client-go` is the usual way to do that in Go, but it's a large
  dependency graph (`k8s.io/api`, `k8s.io/apimachinery`, and their own
  transitive deps) for four REST calls. `internal/k8sjob` hand-rolls
  just those four against the Kubernetes API server directly with
  `net/http` plus the pod's own mounted ServiceAccount token/CA cert --
  consistent with this project's very first design decision
  ("stdlib only, no framework") and much smaller than adding
  client-go for this alone.
- **What this cost:** `monitor-api`'s own ServiceAccount flipped from
  `automountServiceAccountToken: false` to `true`
  (`charts/monitor-api/templates/serviceaccount.yaml`) -- a real, deliberate
  reversal of the earlier hardening decision, since it now genuinely
  needs to call the Kubernetes API. `rbac.yaml`'s `Role` scopes that
  token down to exactly the four calls `internal/k8sjob/client.go`
  makes (`create`/`get`/`delete` on `jobs`, `get`/`list` on `pods`,
  `get` on `pods/log`), only within this one namespace -- nothing else
  the token could theoretically be used for. Net effect: the
  long-running API pod's token can now do a little more (create Jobs),
  but the code that actually parses untrusted content can now do a lot
  less (no token, no network beyond `scm-registry`/`scm-clamav`,
  read-only filesystem, no capabilities) -- a trade this project judges
  worth making.
- **Why `TrivyScanner` stayed in-process:** it only reads package
  manifests out of image metadata via the `trivy` CLI -- a
  well-established, widely-used static binary that doesn't extract or
  execute arbitrary archive contents the way `umoci`/`oras-go` do for
  `UnpackerScanner`. Smaller attack surface, and isolating it too would
  double the per-scan Job overhead for comparatively little benefit;
  revisit if that assessment ever changes.
- **Testability:** `IsolatedUnpackerScanner`'s orchestration logic
  (create → poll → find pod → read logs → parse → always clean up,
  even on every error path) is tested against a fake `jobClient` with
  no real cluster (`isolated_unpacker_test.go`); `internal/k8sjob`'s
  REST client is tested against a plain `httptest.Server` standing in
  for the Kubernetes API (`client_test.go`); `NewScanJob`'s hardening
  (read-only rootfs, dropped capabilities, non-root, no token) is
  asserted directly against the marshaled JSON (`job_test.go`). None of
  this needs a real cluster to verify the logic is right, only to
  verify it against the *real* Kubernetes API server, which is what
  actually deploying and running a scan confirms.

**Adding API authentication.** Every real endpoint used to be wide
open — anyone who could reach `monitor-api`'s port could register
artifacts, trigger scans, or read findings, with no distinction
between the dashboard, a CI pipeline, and an unrelated third party on
the same network. The fix is a single shared API key: `withAuth`
(`internal/api/router.go`) requires `Authorization: Bearer <key>` on
every request, checked with `crypto/subtle.ConstantTimeCompare` rather
than `==` to avoid a timing side-channel (a one-line difference from a
plain comparison, so there was no reason not to, even though a
single-shared-key scheme's realistic threat model probably doesn't
need it).
Two routes stay exempt, both for reasons that have nothing to do with
loosening security: `/healthz` doesn't carry credentials because
Kubernetes' own liveness/readiness probes can't be configured to send
one, and a CORS preflight `OPTIONS` request doesn't either, because
browsers never attach custom headers to preflight requests regardless
of what the real request will send. That second exemption is why
middleware ordering matters — `NewRouter` builds
`withCORS(withAuth(mux, apiKey))`, CORS outermost, so preflight gets
its 204 short-circuit before `withAuth` ever runs; the reverse order
would have every cross-origin call from the dashboard fail preflight
with a 401 before the browser even attempted the real request.
The key itself is fail-closed at startup: `main.go` reads `API_KEY`
from the environment and `log.Fatal`s if it's empty, rather than
falling back to some "insecure mode" default — the entire point of
this change is to close the no-auth gap, not to make it optional.
It's sourced from a Kubernetes Secret (`charts/monitor-api/templates/auth-secret.yaml`,
`scm-monitor-api-auth`) mounted via `secretKeyRef`, the same pattern
already used for `POSTGRES_PASSWORD` — including the same placeholder-value
caveat (`changeme-api-key`, fine for a local single-user cluster, not for
anything shared).
The dashboard gained a second input next to the existing API-base
field (persisted to `localStorage` the same way) and now attaches the
key to every `fetch` call; a 401 response is called out with a
distinguishable "Unauthorized — check the API key above" status
message rather than the generic connection-error text, since a wrong
or missing key is a very different problem from the API being
unreachable. That field started out requiring a person to paste the
key in by hand on every fresh browser -- since fixed so the dashboard
comes pre-configured with a working key automatically; see
"Configuring the dashboard via ConfigMap/Secret instead of by hand"
below.
Test coverage: `internal/api/handlers_test.go` gained a shared
`testAPIKey` constant threaded through `newTestRouter`, six dedicated
`TestAuth_*` cases (missing key, wrong key, malformed header,
correct key, `/healthz` exemption, `OPTIONS` exemption), and the
existing `doJSON` test helper now attaches the key automatically so
none of the ~10 pre-existing handler tests needed individual changes.
`dashboard/tests/dashboard.test.js` gained matching cases for the
Authorization header being sent, the 401 message, and the key
surviving a save-and-reload.

**Configuring the dashboard via ConfigMap/Secret instead of by hand.**
The dashboard originally required a person to paste the API key into
its "Key" field by hand, once per browser -- fine for whoever set it
up, but that meant anyone else who opened the same dashboard URL saw
the new "Couldn't reach ... — missing or invalid API key" status
(the correct, intended behavior of `withAuth`, just a bad first
experience) until *they* also knew to go find the key and paste it in.
That's a real usability gap for something meant to be a shared team
dashboard, not a personal tool.
The fix: `charts/dashboard/templates/deployment.yaml` gained a `render-config`
initContainer that runs before nginx starts, reading `API_KEY` from
the *same* `scm-monitor-api-auth` Secret `monitor-api` itself reads
(one source of truth -- there's no separate dashboard copy of the key
to let drift) and an optional `DASHBOARD_API_BASE` from a new
`scm-dashboard-config` ConfigMap (empty by default, meaning "let
`index.html`'s own `window.location`-based auto-detect handle it," the
same self-adapting logic from "A shipped bug, and what it changed"
below -- only set this if that self-detection is ever wrong for a
given setup). The initContainer copies `index.html` from the
ConfigMap-backed volume into a shared `emptyDir`, and writes a second
file there, `env.js` -- a single `window.SCM_CONFIG = { apiBase,
apiKey }` assignment -- which `index.html` loads via a plain `<script
src="env.js">` tag before its own inline script runs. The main nginx
container serves that `emptyDir`, not the ConfigMap directly, so nginx
itself never touches the Secret at all -- only the initContainer's
one-shot `sh` process does.
`index.html`'s own JS treats `window.SCM_CONFIG` as a *default*, not
the only source: `localStorage` (what a person types into the "API"/
"Key" fields and saves) still wins if set, which stays useful as a
deliberate escape hatch for pointing one browser tab at a different
environment temporarily without touching cluster config. Opening
`index.html` standalone, or in a test, without the initContainer ever
having run just means the `<script src="env.js">` tag 404s/fails to
load and `window.SCM_CONFIG` stays `undefined` -- handled the same way
the existing tabler-icons CDN `<link>` already degrades when its
resource can't be fetched (`dashboard/tests/dashboard.test.js` doesn't
serve `env.js` at all, and already relied on that same graceful-failure
behavior for the icon font).
The initContainer's own templating is deliberately minimal: `sed`-based
escaping of backslashes/double-quotes in the injected values (so an
unusual key or address can't break out of the JS string literal), not
a real templating engine -- adequate for this project's scope (a
single flat key and an optional URL), not something to lean on harder
without revisiting.
A genuine, unrelated bug surfaced and got fixed while wiring this up:
`k8s/dashboard/deployment.yaml`'s ConfigMap volume (this file no longer
exists -- see `charts/dashboard/templates/deployment.yaml` for its
replacement) referenced a ConfigMap named `dashboard-html`, but the
actual object (from what's now `charts/dashboard/templates/configmap.yaml`)
has always been named
`scm-dashboard-html` -- a mismatch that would leave the dashboard pod's
volume permanently unable to mount (a `FailedMount` visible only via
`kubectl describe pod`, not as any kind of application-level error, and
easy to miss since a `ConfigMap`-backed volume that never gets created
doesn't crash-loop the way a bad command or missing binary would). This
is almost certainly what the earlier "no API key field visible at all"
report was actually pointing at -- if the pod's dashboard-html volume
was never mounting, it was serving whatever `nginx:1.27-alpine` falls
back to (its own default page), not any version of this project's
`index.html`, hence no API-key field, no matter which version of the
dashboard shipped it.

**Postgres backups.** `scm-postgres-data` (the live database's PVC) had
no backup story at all -- losing that PVC (storage failure, an
accidental `kubectl delete pvc`, a botched migration) meant losing
every registered artifact and its scan history outright, the exact
problem Postgres was originally brought in to solve (see "Swapping the
in-memory store for Postgres"). `charts/postgres/templates/backup-cronjob.yaml`
adds a daily (`0 2 * * *`) `pg_dump | gzip` into a *separate* PVC,
`scm-postgres-backups` -- deliberately not the same volume the live
data lives on, since a backup that can be lost by the exact same
failure it's meant to protect against isn't much of a backup. Simple
filename-based retention (keep the newest `KEEP_BACKUPS`, default 7)
runs as part of the same Job rather than a separate cleanup process.
Uses the identical `percona/percona-distribution-postgresql` image the
database itself runs, specifically so `pg_dump`'s version always
matches the server's exactly rather than relying on cross-version
compatibility.
This CronJob's container is deliberately *not* hardened the same way
`k8s/monitor-api`'s scan-worker Job is (no forced non-root user, no
read-only root filesystem, no dropped capabilities beyond what's easy
to add safely) -- unlike the scan-worker, which exists specifically to
contain the blast radius of parsing *untrusted* image content, this
container only ever touches this cluster's own trusted database
credentials and its own dump output. Guessing the wrong non-root UID
for an image this project can't test against in every environment
risks silently breaking every backup for a much smaller real security
payoff than the scan-worker's isolation has; revisit if that trade-off
ever stops looking right.
On-demand backups, listing what's available, and restoring are all
`make` targets (`db-backup`, `db-backups-list`, `db-restore
BACKUP=...`) rather than raw `kubectl` incantations a human has to get
right every time -- see README's "Backing up and restoring Postgres"
for the exact commands. Listing and restoring both work by templating
and applying a one-off Job manifest (`cluster/postgres-list-backups-job.yaml`,
`cluster/postgres-restore-job.template.yaml` + a `sed` substitution for
the filename) rather than an inline `kubectl run --overrides=<JSON>` --
a real YAML file a human can open and read is much easier to verify
and modify than JSON embedded inside a shell one-liner, and this
project already has a precedent for the same "render a template with
sed" approach in the dashboard's `render-config` initContainer (see
"Configuring the dashboard via ConfigMap/Secret instead of by hand").
`db-restore` doesn't drop/recreate the database first -- restoring onto
a non-empty database can fail loudly on conflicting primary keys rather
than silently merging or overwriting, which is the safer failure mode
for a destructive operation; restoring into a freshly created, empty
database is the well-tested path (see README).
What this is not: point-in-time recovery. Daily dumps mean losing up to
a day of data in the worst case (right before the next scheduled
backup); WAL archiving would close that gap but is real additional
operational complexity (a place to archive WAL segments to, and a
restore procedure that replays them) that isn't justified yet for a
local dev cluster -- see Roadmap.

**Why `scm-postgres-backups` needed a pre-install hook.** The first
real `make cluster-up && make flux-install` run against a live cluster
hit exactly this: `helm upgrade` for the postgres release timed out
with `PersistentVolumeClaim/.../scm-postgres-backups status:
'InProgress'`. The cause: single-node dev clusters' default
StorageClass (k3s/k3d/colima's `local-path`) sets
`volumeBindingMode: WaitForFirstConsumer` -- correct behavior in
general, since it lets the provisioner see which node a pod actually
lands on before creating storage there, but it means a PVC only binds
once some pod is scheduled against it. `scm-postgres-data` never had
this problem because the postgres `Deployment` consumes it immediately,
in the same install batch. `scm-postgres-backups` did, because its only
real consumer is `scm-postgres-backup`, a `CronJob` that doesn't run
until its own schedule fires -- so at install time nothing ever
schedules a pod against it, it never leaves `Pending`, and Helm's
readiness wait (which treats a Pending PVC as not-yet-ready) eventually
times out waiting for a binding that was never going to happen on its
own. The fix, in `charts/postgres/templates/pvc.yaml` and the new
`backup-pvc-primer-job.yaml`: mark the PVC itself as a
`pre-install,pre-upgrade` Helm hook (so it's created before Helm's
normal apply-then-wait sequence even starts) immediately followed by a
second hook -- a trivial Job that just mounts the volume and exits.
That Job is the "first consumer" the StorageClass is waiting for, so
the PVC binds before Helm ever starts watching for readiness. This
sidesteps the whole issue without assuming anything about which
StorageClass/provisioner is actually in play, unlike hardcoding a
different `volumeBindingMode` would have required.

**Running monitor-api outside a Kubernetes pod.** Isolating the
unpack+scan step (see above) came with a real, documented regression:
`runAPIServer` started unconditionally calling
`k8sjob.NewInClusterClient`, which `log.Fatal`s without a mounted
ServiceAccount token -- meaning the binary could no longer run via a
bare `docker run` for quick local iteration, only inside a real
cluster. `DISABLE_SCAN_ISOLATION` (an env var, default `false`) restores
that ability deliberately, not by accident: when set, `runAPIServer`
skips `k8sjob.NewInClusterClient` entirely (so its fatal error on a
missing token never fires) and falls back to running `UnpackerScanner`
directly in-process for `image` malware scans, exactly like every
version of this code before the isolation work landed.
This is a real, explicit downgrade of that isolation, not a free
lunch -- turning it on means a bug in `unpacker`/`umoci`/`oras-go`
parsing a malicious image is back to sharing this process's blast
radius with the API server and its live Postgres connection. It
defaults to `false` in every real deployment
(`charts/monitor-api/values.yaml`'s `disableScanIsolation`) and is meant only for running the
plain binary standalone, never for a cluster that might see anything
beyond a throwaway local registry's own test images.
The selection logic itself (`buildImageScanners` in `main.go`) is
split out specifically so it's unit-testable
(`TestBuildImageScanners` in `main_test.go`) without needing a real
Kubernetes API client, a real `trivy` binary, or a real `unpacker` --
it never invokes either scanner it's choosing between, just picks
which one ends up in the registry.

## All services on Flux + Helm

Every service in this project -- `registry`, `clamav`, `postgres`,
`monitor-api`, `dashboard` -- deploys as a Helm chart via Flux, not
`kubectl apply -k` against raw manifests. This is a full move, not the
partial monitor-api-only migration this section used to describe. What
changed, how the pieces fit together, and the (few) manual steps this
repo genuinely can't do for itself are all below.

### Repo layout

```
charts/
  registry/       Chart.yaml, values.yaml, templates/{pvc,deployment,service}.yaml
  clamav/         Chart.yaml, values.yaml, templates/{deployment,service}.yaml
  postgres/       Chart.yaml, values.yaml, templates/{secret,pvc,deployment,service,backup-cronjob,backup-pvc-primer-job}.yaml
  monitor-api/    Chart.yaml, values.yaml, templates/{serviceaccount,rbac,auth-secret,configmap,deployment,service}.yaml
  dashboard/      Chart.yaml, values.yaml, templates/{configmap,deployment,service}.yaml, files/index.html
k8s/
  namespace.yaml
  kustomization.yaml           # root of what Flux reconciles
  flux-system/
    gotk-sync.yaml             # GitRepository + root Kustomization (path: ./k8s)
    kustomization.yaml
    values.yaml                # Helm values for installing Flux itself
    README.md
  releases/
    registry-helmrelease.yaml
    clamav-helmrelease.yaml
    postgres-helmrelease.yaml
    monitor-api-helmrelease.yaml
    dashboard-helmrelease.yaml
```

Every resource that used to be a hand-written Deployment/Service/etc.
directly under `k8s/<service>/` is now a chart template under
`charts/<service>/templates/`, parameterized by that chart's own
`values.yaml`. Resource *names* (`scm-registry`, `scm-clamav`,
`scm-postgres`, `monitor-api`, `scm-dashboard`, `scm-postgres-credentials`,
`scm-monitor-api-auth`, etc.) are deliberately hard-coded in the
templates rather than derived from the Helm release name -- every other
piece of tooling in this repo (`Makefile`, this doc, the dashboard's own
config-rendering) already refers to those exact names, and there's only
ever one release of each chart in this cluster, so templating them would
add risk for no real benefit.

### Why the root Flux Kustomization's path is `./k8s`, and reconciles itself

`k8s/flux-system/gotk-sync.yaml`'s root `Kustomization` has
`spec.path: ./k8s` -- the whole `k8s/` tree, including `flux-system/`
itself. That means Flux reconciles its own bootstrap definition (the
`GitRepository` and root `Kustomization`) as part of every sync. This is
normal and matches how real `flux bootstrap` output behaves too, not a
special case introduced here.

`k8s/kustomization.yaml` (a plain, non-Flux kustomize file) is what Flux
actually builds at that path: it lists `namespace.yaml`, the
`flux-system` directory (self-reference), and the five `HelmRelease`
custom resources under `releases/`. Each `HelmRelease`'s
`chart.spec.chart` points at `./charts/<service>` in this same repo via
`sourceRef: {kind: GitRepository, name: flux-system}` -- no separate
`HelmRepository`/OCI registry needed, since the charts live in the same
Git repo Flux already watches.

### Explicit ordering via `dependsOn`

`monitor-api`'s `HelmRelease` sets `dependsOn: [postgres, registry,
clamav]`, and `dashboard`'s sets `dependsOn: [monitor-api]` (the
dashboard's `render-config` initContainer reads the `scm-monitor-api-auth`
Secret the monitor-api chart creates). Flux won't even attempt to
reconcile a `HelmRelease` until everything in its `dependsOn` list is
itself `Ready`. This is a real ordering guarantee the old flat `kubectl
apply -k k8s/` resource list never had -- before, correctness depended
entirely on `monitor-api`'s own `connectStoreWithRetry` tolerating
Postgres not being up yet (still true and still a good belt-and-suspenders
layer, but no longer the *only* thing preventing a race).

### Installing Flux itself (automated)

`cluster/install-flux.sh` runs automatically at the end of `make
cluster-up` (set `SCM_SKIP_FLUX=1` to skip it, `make flux-install` to run
it standalone later). It installs the Flux controllers via the
`fluxcd-community/flux2` Helm chart -- not `flux bootstrap` -- then
applies `k8s/flux-system/gotk-sync.yaml` (the `GitRepository`/root
`Kustomization` pair the Helm chart itself doesn't create, hand-written
here instead). See `k8s/flux-system/README.md` for exactly what the
script does and why the Helm route needs that extra file at all.

Confirmed on a real first run: the chart's CRDs can transiently report
`InProgress` to Helm's own `--wait` readiness check and time out
(`Error: resource CustomResourceDefinition/.../...toolkit.fluxcd.io not
ready ... context deadline exceeded`) even though they finish
establishing within seconds -- a rough edge of this specific community
chart, not a real failure. Fixed by not using `helm ... --wait` for the
install itself and instead waiting on each resource type's own
well-understood condition (CRDs via `Established`, then controller
Deployments via `Available`) -- see the script and
`k8s/flux-system/README.md` for the exact sequence.

### `make deploy`: trigger a reconcile, then hand off

Since Flux now owns every resource under `k8s/`, `make deploy` no longer
runs `kubectl apply -k k8s/` itself -- doing so would just fight Flux for
ownership of the same resources. Instead it: builds the local
`monitor-api:dev` image, commits and pushes the current working tree (so
the `GitRepository` has something new to see), forces an immediate
reconcile of the source, root `Kustomization`, and all five
`HelmRelease`s (via the `flux` CLI if installed, falling back to
annotating the `GitRepository`/`Kustomization` to force an early
re-sync), then rollout-restarts `monitor-api`/`scm-dashboard`
specifically -- still necessary because the image tag (`monitor-api:dev`)
doesn't change on a rebuild, so neither Flux nor Helm can detect on their
own that a restart is warranted. The target is finite and exits when
done; it doesn't babysit the cluster afterward, since Flux keeps
reconciling continuously and independently of any particular `make
deploy` invocation.

### What this repo genuinely can't do for itself

1. **This project needs to actually be a pushed Git repository.** Flux
   polls Git, not the filesystem. `k8s/flux-system/gotk-sync.yaml`'s
   `GitRepository.spec.url` is set to
   `https://github.com/sifungurux/supply-chain-monitor.git` -- the
   install and `make deploy` both succeed regardless, but nothing
   actually reconciles until that remote exists, has this content
   pushed to it, and is reachable from the cluster.
2. **This repo is private, so the `GitRepository` also needs real
   credentials.** `gotk-sync.yaml`'s `GitRepository.spec.secretRef`
   points at a `flux-system-git-auth` Secret (username + GitHub PAT)
   that isn't and shouldn't be committed anywhere -- create it with
   `make git-auth`, then confirm it actually works with `make git-test`
   (a plain `git ls-remote` using the same credentials, which fails or
   succeeds in seconds instead of waiting on Flux's own retry loop).
   Attempting to verify this from a sandboxed assistant session
   confirmed the expected failure mode: `git ls-remote` against the
   repo URL with no credentials fails immediately (git can't prompt for
   a username non-interactively), and a plain `curl` to the repo's page
   returns `404` -- GitHub's deliberate behavior for private repos
   accessed without auth, indistinguishable from a repo that doesn't
   exist, so the same error shows up whether the token is wrong or the
   repo just isn't there. See `k8s/flux-system/README.md`'s "Private
   repo authentication" for the full setup and that reasoning.
3. **A real cluster, Docker, kubectl, and Helm on your own machine.**
   None of the automation above can be executed or verified from inside
   a sandboxed assistant session -- `make cluster-up` drives Colima (a
   local macOS VM manager) and `make deploy` drives `git`/`kubectl`/`flux`
   against a live Kubernetes API, none of which exist in a text-only
   sandbox. This repo, the charts, and the scripts are all real and
   ready to run; running them and reporting back what happens (or what
   errors out) is the one part of this loop that has to happen on your
   own machine.
4. Once all three are true, `flux get kustomizations -A` and `flux get
   helmreleases -A` should show `flux-system` and all five releases as
   `Ready` -- that's the loop closed end to end, from `git push` to
   running Deployments, with artifact registration and scanning
   (`make test-artifact`, or the dashboard) actually working against
   them.

## Roadmap / open gaps

- **Pinned dependencies**: `go.sum` still isn't committed (couldn't be
  generated correctly in the sandbox this project was built in -- no
  real Go toolchain, no network access to the module proxy -- see the
  comment in `go.mod`). Run `make lock-deps` once, from a machine with
  Docker (that's all it needs), and commit the resulting `go.sum` for
  reproducible, verified builds instead of resolving fresh in every
  Docker build.
- **No point-in-time recovery**: `charts/postgres/templates/backup-cronjob.yaml`
  now takes daily `pg_dump` backups (see "Postgres backups"), closing
  the "no backup at all" gap, but a restore can still lose up to a
  day of data (whatever changed since the last scheduled dump). WAL
  archiving would close that remaining gap but is real additional
  operational complexity not yet justified for a local dev cluster.
- **Secret management**: `charts/postgres/values.yaml`'s
  `credentials.password` ships a placeholder password in plaintext YAML
  (committed to the repo, even
  if only used locally). Fine for a throwaway dev cluster; swap for a
  generated secret or an external secret manager before this cluster
  persists anything sensitive.
- **Private/authenticated registries**: both fetch paths hardcode
  unauthenticated, plain-HTTP access to `scm-registry` --
  `UnpackerScanner` via `--insecure --public`, `RegistryFetcher` via
  `FETCH_PLAIN_HTTP`. `unpacker` supports `--config` with a
  `dockerconfig.json` and `oras pull` supports `--username`/`--password`/
  `--registry-config` for exactly this, but neither is wired up yet.
  Mount a dockerconfig/credentials secret and pass the right flags to
  both before pointing this at anything that isn't the local
  unauthenticated `scm-registry`.
- **Non-registry fetch sources**: `RegistryFetcher` only knows how to
  pull from an OCI registry. An object-store-backed `Fetcher` (S3,
  GCS, a plain HTTPS URL) would be a reasonable addition for
  `file`/`sbom`/`sarif` artifacts that don't come from a registry --
  `Fetcher` is already an interface specifically so this doesn't
  require touching `FetchingScanner` or any of the wrapped scanners.
- **OCI-native results**: attach scan results to the artifact in
  `scm-registry` as OCI referrers/attestations (cosign-style), so
  results travel with the artifact instead of living only in
  `monitor-api`'s own store.
- **trivy-server**: once scan volume matters, switch `TrivyScanner` to
  talk to a shared `trivy-server` Deployment instead of invoking the CLI
  per request.
- **`DISABLE_SCAN_ISOLATION`'s fallback is untuned**: it exists (see
  "Running monitor-api outside a Kubernetes pod") and closes the "can't
  run outside a pod at all" regression, but it's a blunt on/off switch
  -- no partial mode (e.g. isolate only when a Kubernetes API is
  actually reachable, auto-detected rather than explicitly set).
  Revisit if quick local iteration against it turns out to want
  something smarter.
- **No NetworkPolicy on the scan-worker Job pod**: it's locked down at
  the pod-security level (read-only rootfs, no capabilities, no token)
  but can still reach anything on the pod network by default, the same
  as any other pod in the cluster. A `NetworkPolicy` restricting its
  egress to just `scm-registry` and `scm-clamav` would close that.
- **Scan-worker Job scheduling latency**: each image scan now pays for
  a pod being scheduled and its image pulled (`IfNotPresent`, so
  usually a cache hit) before the actual scan starts, on top of the
  scan itself -- a few seconds typically, not something the old
  in-process approach paid at all. Not a correctness issue, just a
  slower `/scan` call than before.
- **AuthN/Z is a single shared key, not per-client identity**: every
  caller (the dashboard, any CI pipeline, an operator's `curl`) uses
  the same `API_KEY` -- there's no way to tell them apart, revoke one
  caller without rotating the key for everyone, or scope different
  callers to different permissions (e.g. read-only vs. can-trigger-scans).
  Worth per-client keys or a real identity provider (OIDC) before this
  serves more than one trusted team.
- **No key rotation story**: rotating `API_KEY` today means updating
  the Secret and restarting every caller at the same time -- both
  `monitor-api` and the dashboard's `render-config` initContainer pick
  up the new value on their next restart automatically, but there's no
  overlap window, so any caller (dashboard pod, CI pipeline) that
  hasn't restarted yet fails with 401s until it does. A two-key grace
  period (accept either the old or new key for a while) would make
  rotation safe to do without a coordinated cutover.
- **No rate limiting**: a valid key (or a leaked one) can call any
  endpoint as fast as the client can send requests -- nothing here
  throttles per-key request volume, so a single misbehaving or
  compromised caller could still overwhelm the scan pipeline or the
  database.
- **Dashboard config rendering is `sed`-based, not a real templating
  engine**: `render-config`'s escaping (backslashes/double quotes) is
  adequate for a flat API key and a plain URL, but would need
  revisiting (a real templating tool, or at least stricter input
  validation) if the injected config ever grows beyond those two
  simple string values.
- **Air-gapped DB mirroring auth**: `cluster/seed-trivy-db.sh` assumes
  an unauthenticated source registry when copying trivy's DBs via
  `oras cp`; add credential flags if the source ever needs to be a
  private mirror instead of public ghcr.io.
- **Dashboard polish**: no pagination (fine at demo scale, not at
  hundreds of artifacts), no client-side sort/filter beyond
  newest-first, and registering a `file` artifact from the form doesn't
  warn you that its `ref` needs to already be a path inside the
  `monitor-api` pod (see the `file`-artifact fetching gap above).
- **Never actually run/verified against a live cluster**: see "All
  services on Flux + Helm" above -- every chart, `HelmRelease`, and
  script here was written and statically validated (YAML parsing,
  template-balance checks, a from-scratch re-derivation of the
  dashboard ConfigMap render) but never executed against a real
  Kubernetes API, since no sandbox this project has been built in has
  had Docker, kubectl, Helm, or Colima available. Run `make cluster-up
  && make deploy` on a real machine and treat the first pass as an
  integration test of this migration, not just a routine deploy --
  report back anything that fails so it can be fixed.
