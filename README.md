# Supply Chain Monitor — cluster & API skeleton

A local Kubernetes test environment for a supply-chain security monitor:
an API-driven service that tracks artifacts (container images, files,
SBOMs, SARIF reports — anything packable into an OCI artifact), scans
them for CVEs and malware, and records what pipeline step each one is
currently at.

This is a v1 skeleton meant to run locally and grow from. See
`docs/architecture.md` for the design and known gaps.

## What's here

```
cluster/               cluster create/destroy scripts (colima by default, podman optional)
  runtimes/colima.sh    colima --kubernetes runtime path (default, recommended)
  runtimes/podman.sh    k3d-on-podman runtime path (experimental, see below)
  k3d-config.yaml       k3d config used only by the podman path
  install-flux.sh       installs Flux via Helm (`make flux-install`, or automatic via `make cluster-up`)
  postgres-restore.sh, postgres-list-backups.sh   on-demand Postgres backup restore/listing (`make db-restore`/`db-backups-list`)
charts/                 every service deploys as a Helm chart now (see "GitOps (Flux)" below)
  registry/, clamav/, postgres/, monitor-api/, dashboard/   Chart.yaml + values.yaml + templates/
k8s/                    what Flux actually reconciles (path: ./k8s) -- no raw per-service
                        manifests anymore, just the namespace, Flux's own bootstrap
                        self-reference, and a HelmRelease per service
  namespace.yaml
  flux-system/          GitRepository + root Kustomization (gotk-sync.yaml), Flux install values.yaml
  releases/             one HelmRelease per service, chart sourced from charts/ above
services/monitor-api/   the Go API service source + tests (internal/.../*_test.go)
dashboard/index.html    the dashboard itself (source of truth -- charts/dashboard/files/index.html is a copy of this)
dashboard/tests/        dashboard test suite (Node + jsdom)
docs/architecture.md    design notes, rationale, roadmap
Makefile                cluster-up/down/destroy, build, deploy, port-forward, test
```

## Prerequisites

Install on your Mac (this runs against your local machine, not a sandbox):

- kubectl
- Go 1.22+ (only if you want to build/run `monitor-api` outside a container)
- **Either** [Colima](https://github.com/abiosoft/colima) (default runtime — `brew install colima docker`)
  **or** [Podman](https://podman.io/) + [k3d](https://k3d.io/#installation) (optional alternate runtime — `brew install podman k3d`)

## Choosing a runtime

Two ways to run the cluster, selected via `SCM_RUNTIME`:

- **`colima` (default)** — `colima start --kubernetes` runs k3s directly
  inside the Colima VM, sharing its image store with `docker build`. No
  image-import step needed. This is the path to use unless you have a
  specific reason not to.
- **`podman`** — runs k3d (k3s-in-container) against Podman's socket
  instead. k3d's own docs mark Podman support **experimental**, and
  there are open macOS-specific bugs (k3d-io/k3d#1388, #1447). Only use
  this if you already have a Podman-based workflow; fall back to colima
  if cluster creation fails outright.

```bash
./cluster/create-cluster.sh                   # colima (default)
SCM_RUNTIME=podman ./cluster/create-cluster.sh  # podman, experimental
```

`make` targets default to colima; override with `SCM_RUNTIME=podman make cluster-up`, etc.

## Quickstart

```bash
make cluster-up       # colima start --kubernetes (or podman, if SCM_RUNTIME=podman); also installs Flux
make deploy            # docker build + git push + trigger Flux reconcile + rollout restart
kubectl -n supply-chain-monitor get pods -w   # wait for everything to go Ready
```

`make cluster-up` also installs Flux (see "GitOps (Flux)" below) —
`SCM_SKIP_FLUX=1 make cluster-up` if you don't want that yet. Every
service (registry, clamav, postgres, monitor-api, dashboard) deploys as
a Helm chart via Flux now — `make deploy` no longer applies manifests
directly, it pushes to Git and lets Flux do it (see "GitOps (Flux)").
That means `make deploy` needs this repo to actually be pushed to a Git
remote first — see that section for the one-time setup.

**This exact setup — full Helm-chart-per-service + Flux, path `./k8s` —
hasn't been run end-to-end on a real cluster yet.** It was built and
statically validated (every chart's YAML, template logic, and the
dashboard's embedded HTML were checked by hand and by script) but never
executed against a live Kubernetes API — treat your first `make
cluster-up && make deploy` as the real integration test of this
migration, and see "GitOps (Flux)" below for exactly what to check and
report back if something doesn't come up clean.

Note: the `clamav` pod downloads its virus definition DB on first boot,
which can take a few minutes before its readiness probe passes.
`monitor-api`'s own pod can take up to ~60s to go Ready on a fresh
`make deploy` too — it retries connecting to `scm-postgres` a dozen
times, 5s apart, since both pods start at once and there's no
guarantee Postgres finishes initializing first (see
`connectStoreWithRetry` in `main.go`, and its own logs via `make logs`
if it's taking longer than that).

Once everything is Ready:

```bash
make port-forward     # in one terminal
make test-artifact    # in another — registers a test image artifact
```

Or skip port-forwarding:

- **colima**: `create-cluster.sh` prints a VM address (from `--network-address`) —
  `curl <vm-address>:30300/healthz`, dashboard at `http://<vm-address>:30301`.
- **podman**: k3d's config maps the NodePorts straight to localhost —
  `curl localhost:30300/healthz`, dashboard at `http://localhost:30301`.

## Dashboard

`http://<vm-address-or-localhost>:30301` — a static page (nginx + a
ConfigMap, no build step, no framework) that talks to `monitor-api`
directly from the browser: an artifact table (ref, type, status,
pipeline stage, CVE/malware counts), a pipeline-stage strip showing how
many artifacts are at each stage, a form to register new artifacts, and
a per-row "Details" expando with stage history and full finding lists.
It polls the API every 10s and has a "Scan" button per row.

The API address it talks to defaults to the same host the dashboard
itself was loaded from, on port 30300 (the API's NodePort) — so it
self-adapts whether you opened the dashboard via `localhost` (podman)
or a Colima VM address, with no manual step. It's still editable (and
remembered) in the page if you need a different address, e.g. a
non-default NodePort.

*(Earlier versions of this dashboard hardcoded `http://localhost:30300`
as the default, which silently broke on the colima runtime — NodePorts
there are never reachable via `localhost` at all. If artifacts aren't
showing up and the status line at the top reads "Couldn't reach...",
that's almost certainly a stale default; the fix above self-corrects,
but double check the API field if you're on an old build.)*

This only works because `monitor-api` sends permissive CORS headers
(`Access-Control-Allow-Origin: *`) so the browser can call it from a
different origin/port. Every request still needs the API key (see
Authentication below), but you shouldn't need to paste one in
yourself — a fresh `make deploy` pre-configures the dashboard with a
working key automatically (see "Auto-configured API address/key"
below). The "API"/"Key" fields are still there and still editable (and
remembered in `localStorage`) for pointing this one browser tab
somewhere else temporarily.

To edit the dashboard: change `dashboard/index.html`, copy it into the
dashboard chart (Helm's `.Files.Get` can only read files inside the
chart directory, so this is a real second copy, not a symlink —
`make check-dashboard-configmap` catches drift between the two), then
deploy:

```bash
cp dashboard/index.html charts/dashboard/files/index.html
make deploy
```

### Auto-configured API address/key

The dashboard no longer needs anyone to open it and paste an API key
in by hand. `charts/dashboard/templates/deployment.yaml` runs a small
initContainer before nginx starts that reads `API_KEY` from the same
`scm-monitor-api-auth` Secret the monitor-api chart creates, and writes
it (plus an optional API-address override from the
`scm-dashboard-config` ConfigMap, empty/unset by default) into a
generated `env.js` the page loads automatically. Rotate the key in one
place (`charts/monitor-api/values.yaml`'s `apiKey`, or an override in
`k8s/releases/monitor-api-helmrelease.yaml`'s `spec.values`) and
redeploy — both `monitor-api` and every dashboard pod pick up the new
value, no manual re-entry anywhere. If you ever *do* want the dashboard
to point at a fixed address instead of self-detecting one from
`window.location`, set `apiBase` in `charts/dashboard/values.yaml` (or
override it in `k8s/releases/dashboard-helmrelease.yaml`) and redeploy. See
docs/architecture.md ("Configuring the dashboard via ConfigMap/Secret
instead of by hand") for the full design and a real bug that was found
and fixed while wiring this up (a ConfigMap name mismatch that left the
dashboard pod unable to mount its own HTML at all).

## Authentication

Every endpoint except `/healthz` requires `Authorization: Bearer <key>`.
The key is sourced from `API_KEY`, which `monitor-api` reads from the
`scm-monitor-api-auth` Secret (rendered from `charts/monitor-api/values.yaml`'s
`apiKey`) — override that value (never commit a real one) before this
cluster is anything but local and throwaway, the same caveat as
`scm-postgres-credentials`. A request with no key, the wrong key, or a
missing `Bearer ` prefix gets a `401`.

```bash
curl -s localhost:8080/api/v1/artifacts \
  -H 'Authorization: Bearer changeme-api-key'
```

See docs/architecture.md ("Adding API authentication") for why a
single shared key, why `/healthz` and CORS preflight `OPTIONS` are
exempt, and what's still missing (per-client keys, rotation, rate
limiting).

## API

| Method | Path                              | Purpose                                   |
|--------|-----------------------------------|--------------------------------------------|
| GET    | `/healthz`                        | liveness/readiness                         |
| GET    | `/api/v1/pipeline/stages`         | list configured pipeline stages            |
| POST   | `/api/v1/artifacts`                | register an artifact `{ref, type}`         |
| GET    | `/api/v1/artifacts`                | list all tracked artifacts                 |
| GET    | `/api/v1/artifacts/{id}`           | get one artifact (findings, current stage) |
| POST   | `/api/v1/artifacts/{id}/scan`      | run the scanner appropriate for its type   |
| POST   | `/api/v1/artifacts/{id}/stage`     | record a pipeline-stage transition         |
| GET    | `/api/v1/findings/{findingID}/artifacts` | every artifact affected by a given finding ID (e.g. a CVE) |

`type` is one of `image`, `file`, `sbom`, `sarif`.

Example flow:

```bash
AUTH='-H Authorization:Bearer\ changeme-api-key'

# register a container image artifact
curl -s -X POST localhost:8080/api/v1/artifacts $AUTH \
  -H 'Content-Type: application/json' \
  -d '{"ref":"alpine:3.19","type":"image"}'
# => {"id":"...", "ref":"alpine:3.19", "type":"image", "status":"registered", ...}

# tell the monitor it just left the "build" stage of your pipeline
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/stage $AUTH \
  -H 'Content-Type: application/json' \
  -d '{"stage":"build","note":"CI job #482"}'

# scan it: for type=image this runs Trivy (CVEs) *and* unpacker+ClamAV
# (malware) and merges both into the same artifact
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/scan $AUTH

# check results -- cve_findings from trivy, malware_findings from clamav,
# other_findings from parsed SARIF (SAST/secrets/IaC, not CVE or malware)
curl -s localhost:8080/api/v1/artifacts/<id> $AUTH

# find every artifact still affected by a given finding (e.g. after a
# fix ships, confirm nothing registered still carries this CVE)
curl -s localhost:8080/api/v1/findings/CVE-2024-1234/artifacts $AUTH
```

### SBOM and SARIF scanning

`sbom` and `sarif` artifacts are wired up now too, alongside `image`
and `file`:

- **`sbom`** — `trivy sbom` scans a CycloneDX/SPDX document for known
  CVEs in the components it lists, landing in `cve_findings` same as
  image scans (and sharing the same air-gapped DB-mirror config, see
  above).
- **`sarif`** — a SARIF file already **is** a set of findings (from
  CodeQL, Semgrep, trivy's own `--format sarif` output, etc.), so
  nothing gets re-scanned; the file is parsed directly and its results
  land in a third bucket, `other_findings` — SARIF covers SAST issues,
  secrets, and misconfigurations generally, not just CVEs, so folding
  it into `cve_findings` would mislabel it.

### Registering `file`/`sbom`/`sarif` artifacts by registry reference

`ref` for `file`, `sbom`, and `sarif` artifacts can now be an OCI
registry reference (to `scm-registry`, same as `image` artifacts) —
`monitor-api` fetches it via `oras pull` before scanning/parsing, so
these three types don't require the artifact to already be sitting on
the pod's filesystem. Push something to scan first (`brew install
oras` if you don't already have it, same as for
`cluster/seed-trivy-db.sh`):

```bash
# push a SARIF file as a single-blob OCI artifact
oras push --plain-http localhost:30500/scans/app-sarif:1 results.sarif

# register it -- ref is the registry reference, not a local path
curl -s -X POST localhost:8080/api/v1/artifacts \
  -H 'Authorization: Bearer changeme-api-key' \
  -H 'Content-Type: application/json' \
  -d '{"ref":"scm-registry.supply-chain-monitor.svc.cluster.local:5000/scans/app-sarif:1","type":"sarif"}'
```

`ref` still works as a plain filesystem path too (e.g.
`/tmp/results.sarif`) if you'd rather mount one directly — anything
starting with `/`, `.`, or `~` is treated as a path already inside the
pod and never fetched; anything else is treated as a registry
reference. Only `scm-registry`'s unauthenticated, plain-HTTP setup is
supported today (`FETCH_PLAIN_HTTP` in the ConfigMap) — see Known
limitations.

### Image scanning: CVEs and malware, not just one or the other

A container image is a real filesystem underneath, so it can carry
malware the same way a plain file can — Trivy only checks known
package-level CVEs, it doesn't look at file contents. For `image`
artifacts, `/scan` now runs both:

- **Trivy** — CVE scan against package metadata (as before).
- **[unpacker](https://github.com/Sifungurux/unpacker) + ClamAV** —
  `unpacker` pulls the image and reconstructs its filesystem into a
  plain directory (oras-go/crane + umoci), then every regular file
  under it is streamed to ClamAV over the same INSTREAM protocol used
  for standalone `file` artifacts.

Both scanners' findings land on the same artifact — `cve_findings` from
Trivy, `malware_findings` from ClamAV — told apart by `Finding.source`,
not by artifact type. Relevant env vars (see `charts/monitor-api/values.yaml`'s
`unpacker.*` keys, rendered into the ConfigMap by that chart):
`UNPACKER_INSECURE`, `UNPACKER_PUBLIC` (defaults assume our local,
unauthenticated `scm-registry`), `UNPACKER_MAX_FILE_MB` (skip huge files
when walking the unpacked image, default 100MB).

**The unpack+malware-scan step runs in its own Kubernetes Job, not
inside `monitor-api`.** `unpacker`/`umoci` parse arbitrary,
potentially-malicious image content — running that in the same
process as the API and its Postgres connection was a bigger blast
radius than it needed to be. Each image scan now spins up a dedicated,
short-lived Job (`monitor-api scan-worker` — the same binary, a
different mode) whose pod has a read-only root filesystem, every Linux
capability dropped, runs as non-root, and has no Kubernetes
ServiceAccount token at all. `monitor-api`'s own ServiceAccount gained
just enough access to create/watch that Job and read its logs — see
`charts/monitor-api/templates/rbac.yaml` and docs/architecture.md ("Isolating the
unpack+scan step") for exactly what that token can and can't do.
One practical effect: each `/scan` on an image now pays for a pod
being scheduled (usually a few seconds, since the image is normally
already cached) on top of the scan itself.

### Running monitor-api outside a Kubernetes pod

Isolating the unpack+scan step (above) means `monitor-api` now needs a
real Kubernetes API client to start at all, which normally means a
real ServiceAccount token — a bare `docker run` outside any cluster
doesn't have one, and would otherwise fail immediately. Set
`DISABLE_SCAN_ISOLATION=true` to run it anyway, for quick local
iteration:

```bash
docker run --rm -p 8080:8080 \
  -e API_KEY=dev-key \
  -e POSTGRES_DSN='postgres://monitor_api:test@host.docker.internal:5432/monitor_api?sslmode=disable' \
  -e DISABLE_SCAN_ISOLATION=true \
  monitor-api:dev
```

This is a real, deliberate downgrade, not a free convenience: image
malware scanning runs in-process again (like every version of this
code before isolation shipped), so a bug in `unpacker`/`umoci`/`oras-go`
parsing a malicious image once again shares this process's blast
radius with the API server and its Postgres connection. Leave it unset
(the default, `false`) for every real deployment — `charts/monitor-api/values.yaml`'s
`disableScanIsolation` already does. See docs/architecture.md ("Running monitor-api outside a
Kubernetes pod") for the full reasoning.

## Database

Artifacts, findings, and stage history are stored in Postgres
(`percona/percona-distribution-postgresql`, deployed as `scm-postgres`
in-cluster) instead of in-memory, so a `monitor-api` pod restart no
longer loses everything registered so far. `monitor-api` connects
using `POSTGRES_HOST`/`PORT`/`USER`/`DB`/`SSLMODE` (rendered from
`charts/monitor-api/values.yaml`'s `postgres.*` keys) plus
`POSTGRES_PASSWORD` from the `scm-postgres-credentials` Secret (from
`charts/postgres/values.yaml`'s `credentials.password`) — override
that placeholder password (via `k8s/releases/postgres-helmrelease.yaml`'s
`spec.values`, never committed directly) before this cluster is
anything but local and throwaway. `POSTGRES_DSN` is also accepted as a
full connection string override if you'd rather set one directly.

```bash
make db-shell   # opens a psql shell in the scm-postgres pod
```

Findings and stage history live in their own tables (`stage_history`,
`findings`, `scan_errors`), not as JSONB blobs on the `artifacts` row —
this is what makes the `GET /api/v1/findings/{findingID}/artifacts`
endpoint above possible (an indexed lookup, not a full-table scan). If
you're upgrading a cluster that's still on the older single-table
JSONB schema, nothing extra to do: `monitor-api` detects and migrates
it automatically the next time it connects, in place, with no data
loss (see docs/architecture.md, "Normalizing findings and stage
history into their own tables," for exactly how).

See docs/architecture.md ("Swapping the in-memory store for Postgres")
for why Postgres specifically, and how retrying the initial connection
is handled since Postgres and `monitor-api` start up concurrently.

### Backing up and restoring Postgres

A daily `pg_dump` (gzip-compressed, into its own PVC separate from the
live data) runs automatically once deployed — see
`charts/postgres/templates/backup-cronjob.yaml`. Retention keeps the
newest 7 backups by default (`backup.keepBackups` in
`charts/postgres/values.yaml`).

```bash
make db-backup          # trigger an on-demand backup right now, don't wait for the schedule
make db-backups-list    # see what's available
make db-restore BACKUP=scm-postgres-20260101T020000Z.sql.gz   # restore one (asks for confirmation first)
```

`db-restore` doesn't drop/recreate the database first — restoring onto
a database that already has conflicting data can fail loudly rather
than silently merging, which is the safer failure mode. Restoring into
a freshly created, empty `scm-postgres` (e.g. right after `make
cluster-up && make deploy` on a new cluster) is the well-tested path.

This is periodic backup, not point-in-time recovery — a restore can
still lose whatever changed since the last completed backup (up to a
day, on the default schedule). See docs/architecture.md ("Postgres
backups") for the full design and why WAL-based PITR isn't part of
this yet.

### Pinned dependencies (go.sum)

`services/monitor-api/go.sum` isn't committed yet — this project was
built in a sandbox with no Go toolchain and no network access to the
module proxy, so it couldn't be generated correctly there (see the
comment in `go.mod`). Every build currently resolves and verifies
dependencies fresh via `go mod tidy` (see the `Dockerfile` and
`make test-api`/`make test-postgres`) instead of from a pinned
lockfile. Fix this once, from your own machine:

```bash
make lock-deps   # needs only Docker, not a local Go install
git diff services/monitor-api/go.sum
git add services/monitor-api/go.sum && git commit
```

From then on, every build verifies against the committed `go.sum`
instead of resolving from scratch.

## Air-gapped operation

Trivy pulls its vulnerability DB (and a separate Java DB) from
`ghcr.io` on every scan — invisible with normal internet access, a hard
blocker in an air-gapped cluster. To run without that dependency,
mirror both DBs into the in-cluster `scm-registry` once, while still
online:

```bash
brew install oras            # if you don't already have it
./cluster/seed-trivy-db.sh   # mirrors both trivy DBs into localhost:30500
```

Then set `trivyDB.enabled: true` and fill in `trivyDB.repository`/
`trivyDB.javaRepository` in `charts/monitor-api/values.yaml` (the
script prints the values to use) and redeploy:

```bash
make deploy
```

From then on `monitor-api` points trivy at the mirrored DBs in
`scm-registry` instead of `ghcr.io`, and skips even trying the public
default (`TRIVY_SKIP_DB_UPDATE`/`TRIVY_SKIP_JAVA_DB_UPDATE`). Leave the
four lines commented out (the default) for a normal, internet-connected
setup — trivy's own defaults are used and nothing changes.

## Testing

```bash
make test            # both suites below
make test-api         # services/monitor-api's Go tests (httptest, no cluster needed)
make test-dashboard   # dashboard/index.html's Node+jsdom tests
make test-postgres    # real Postgres round-trip against a throwaway container (not part of `make test`)
```

These run in containers (`golang:1.22-alpine`, `node:22-alpine`,
`percona/percona-distribution-postgresql`) so there's nothing extra to
install beyond Docker, which you already have via Colima or Podman. No
CI workflow is wired up yet -- these `make`
targets (plus `make check-dashboard-configmap`, which checks that
`charts/dashboard/files/index.html` actually matches `dashboard/index.html`
— the exact class of bug that shipped once already, see above) are
meant to be the entry point whenever you set one up against your own
git server.

- **API tests** (`services/monitor-api/internal/.../*_test.go`): exercise
  every endpoint through `httptest`, using fake in-memory `Scanner`
  implementations instead of real trivy/clamav/unpacker, and the
  in-memory `MemStore` instead of Postgres — covers create/list/get,
  stage validation, the multi-scanner-per-type merge and
  partial-failure behavior in `/scan`, the CORS headers, the auth
  middleware, and `FindByFindingID`/`GET /api/v1/findings/{id}/artifacts`.
- **main.go tests** (`services/monitor-api/main_test.go`): `buildPostgresDSN`'s
  string logic, and `buildImageScanners`'s `DISABLE_SCAN_ISOLATION`
  selection logic (isolated vs. in-process scanner) — both pure Go, no
  real database, Kubernetes API, or trivy/unpacker binary needed.
- **Postgres integration test**
  (`internal/artifact/postgres_store_integration_test.go`): a real
  round-trip against a throwaway Percona Postgres container, run via
  `make test-postgres` (not part of `make test`/`test-api`, since it
  needs Docker networking `test-api` otherwise doesn't). Covers
  create/get/list/update, that findings and stage history survive the
  normalized-table round-trip, that concurrent updates to the *same*
  artifact don't silently drop one of them, `FindByFindingID` against
  the real index, and migrating a hand-built copy of the old
  single-table JSONB schema (seeded with data, including a
  since-fixed bug where SARIF findings never actually persisted under
  that schema) into the new tables without data loss.
- **Dashboard tests** (`dashboard/tests/dashboard.test.js`): load the
  real `dashboard/index.html` into `jsdom`, mock `fetch` with canned API
  responses, and assert on the rendered DOM — summary cards, stage
  strip, empty state, a real network-error state, HTML-escaping of
  user-supplied data, the register-form POST, SARIF/other findings
  rendering, the API key being sent as a Bearer header and persisted on
  save, a distinguishable message on a 401, `window.SCM_CONFIG`
  (simulating the render-config initContainer's `env.js`) being picked
  up automatically, `localStorage` still overriding it when a person
  has explicitly saved something, the graceful fallback when
  `window.SCM_CONFIG` is absent, and (as a standing regression test)
  that the API-base default is derived from `window.location` rather
  than hardcoded. This suite actually runs in CI-like conditions today
  (Node's own test runner, no external services) — all 13 tests pass.

## GitOps (Flux)

Every service — registry, clamav, postgres, monitor-api, dashboard —
deploys as a Helm chart via [Flux](https://fluxcd.io), not `kubectl
apply -k` against raw manifests. See `docs/architecture.md`, "All
services on Flux + Helm", for the full picture; the short version:

- `charts/<service>/` — a real Helm chart per service (`Chart.yaml`,
  `values.yaml`, `templates/`).
- `k8s/releases/<service>-helmrelease.yaml` — a Flux `HelmRelease` per
  service, sourcing its chart from `charts/<service>` in this same repo.
  `monitor-api` `dependsOn` postgres/registry/clamav; `dashboard`
  `dependsOn` monitor-api (it needs monitor-api's auth Secret to exist).
- `k8s/flux-system/gotk-sync.yaml` — the `GitRepository` (pointing at
  `https://github.com/sifungurux/supply-chain-monitor.git`, branch
  `main`) and the root `Kustomization` (`path: ./k8s` — the whole tree,
  self-referencing).
- `k8s/kustomization.yaml` — the plain kustomize file Flux actually
  builds at that path: the namespace, the `flux-system` self-reference,
  and all five `HelmRelease`s.

**Installing Flux is automated** — `make cluster-up` installs it for you
via `cluster/install-flux.sh` (the `fluxcd-community/flux2` Helm chart,
not `flux bootstrap` — see `k8s/flux-system/README.md` for why). Skip it
with `SCM_SKIP_FLUX=1 make cluster-up`, or run it standalone against an
already-running cluster with `make flux-install`.

**This repo is private, so the `GitRepository` also needs credentials**
— `gotk-sync.yaml`'s `secretRef` points at a `flux-system-git-auth`
Secret that's never committed. Set it up once per cluster:

```bash
make git-auth   # prompts for a GitHub username + personal access token
make git-test   # confirms those credentials actually work (git ls-remote),
                # in seconds — don't wait on Flux's own retry loop to tell you
```

See `k8s/flux-system/README.md`'s "Private repo authentication" for
token scope details and why a wrong token and a nonexistent repo look
identical (GitHub returns 404 for both, on purpose).

**`make deploy` no longer applies manifests directly** — it builds the
local `monitor-api:dev` image, commits and pushes the working tree,
triggers an immediate Flux reconcile (via the `flux` CLI if installed,
otherwise by annotating the `GitRepository`/`Kustomization`), then
rollout-restarts `monitor-api`/`scm-dashboard` (still needed since the
`:dev` image tag doesn't change on rebuild, so Flux/Helm can't detect a
restart is warranted on their own). It's finite and hands off once
done — Flux keeps reconciling on its own after that, independent of any
particular `make deploy` run.

What's still on you: **this project needs to actually be pushed to that
Git remote.** The Flux install and `make deploy` both succeed
regardless; nothing actually reconciles until
`https://github.com/sifungurux/supply-chain-monitor.git` exists, has
this content, and is reachable from the cluster.

Once it is, `flux get kustomizations -A` and `flux get helmreleases -A`
should show `flux-system` and all five releases `Ready`. **This exact
setup has not been run against a real cluster yet** (see the note under
Quickstart) — the first time you do, please report back exactly what
`kubectl -n supply-chain-monitor get pods`, `flux get helmreleases -A`,
and `make test-artifact` show, especially anything `NotReady`,
`CrashLoopBackOff`, or failed, so any real issue (a bad chart value, a
missed dependency, a typo an actual Kubernetes API would catch that
static YAML validation can't) gets fixed quickly rather than sitting
undiscovered.

## Tearing down

```bash
make undeploy
make cluster-down       # stops the VM/machine, keeps it around for next time
make cluster-destroy    # stops AND deletes the VM/machine + its data
```

## Known limitations (v1 stub — see docs/architecture.md for the plan)

- **This Helm-chart-per-service + Flux setup hasn't been run against a
  real cluster yet.** Every chart and CR was written and statically
  validated (YAML parsing, template-balance checks, a from-scratch
  re-derivation of the dashboard's rendered ConfigMap) but never
  executed against a live Kubernetes API — no environment this project
  has been built in has had Docker, kubectl, Helm, or Colima available.
  Treat the first `make cluster-up && make deploy` as a real
  integration test, not a routine deploy, and see "GitOps (Flux)"
  above for what to check and report back.
- **The private-repo Git credentials (`make git-auth`) haven't been
  verified against the real repo either**, for the same reason: a
  sandboxed assistant session has no GitHub PAT to test with. An
  unauthenticated `git ls-remote`/`curl` from that sandbox confirmed
  the expected failure (no creds → can't clone; GitHub 404s a private
  repo request the same way it would a nonexistent one), but the actual
  `make git-auth && make git-test` pass with a real token is still
  yours to run and report back.
- `charts/postgres/values.yaml`'s `credentials.password` ships a
  placeholder in plaintext in the repo; fine for a local, throwaway
  cluster, not for anywhere the Postgres data itself matters. Daily
  backups exist now (see "Backing up and restoring Postgres"), but not
  point-in-time recovery -- a restore can still lose up to a day of
  data in the worst case.
- `go.sum` isn't committed (couldn't be generated without a real Go
  toolchain in the sandbox this was built in) -- the Dockerfile's build
  stage runs `go mod tidy` at build time instead. Run `make lock-deps`
  once from your own machine and commit the result for pinned,
  reproducible builds (see "Pinned dependencies (go.sum)").
- CVE scanning shells out to the `trivy` CLI per-request (no shared
  `trivy-server` yet — see docs/architecture.md).
- `file`/`sbom`/`sarif` artifacts can now be fetched from
  `scm-registry` (via `oras pull`) or still assumed to be a local path
  already inside the pod — but not from anywhere else (an S3 bucket, a
  plain HTTPS URL). `Fetcher` is an interface specifically so another
  source is a small addition later, not a rewrite.
- SARIF severity falls back to a rough three-level mapping
  (error/warning/note → high/medium/low) unless a rule carries a
  `security-severity` score, which not every SARIF producer sets.
- Re-running `/scan` replaces prior findings wholesale, including with
  empty results if every scanner fails that round.
- Both registry-fetching paths hardcode unauthenticated, plain-HTTP
  access — `unpacker` via `--insecure --public`, the file/sbom/sarif
  fetcher via `FETCH_PLAIN_HTTP` — fine for the local `scm-registry`;
  scanning a private, authenticated registry isn't wired up on either
  path yet (would need mounting a `dockerconfig.json`/credentials
  secret and passing the right flags to both).
- The scan-worker Job pod is hardened at the pod-security level but has
  no `NetworkPolicy` restricting what it can reach on the pod network —
  same as any other pod in the cluster today.
- `monitor-api` requires a real Kubernetes ServiceAccount token to
  start at all by default (it creates scan-worker Jobs on boot-adjacent
  code paths) — set `DISABLE_SCAN_ISOLATION=true` to run it via a bare
  `docker run` outside a cluster instead (see "Running monitor-api
  outside a Kubernetes pod"), at the cost of moving image malware
  scanning back in-process.
- The API now requires a single shared `API_KEY` (see Authentication
  above), but it's one key for every caller — no per-client identity,
  no revocation of a single caller, no rotation window (changing the
  key means updating every caller at once), and no rate limiting per
  key. Fine for a small trusted team, not for anything wider.
- The dashboard's auto-configured key/address (see "Auto-configured
  API address/key" above) is rendered with `sed`-based string escaping
  in a shell script, not a real templating engine — fine for a flat key
  and a plain URL, would need revisiting if that config ever grows more
  complex.
