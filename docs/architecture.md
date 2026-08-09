# Architecture

## Goal

Track artifacts moving through a software delivery pipeline — container
images, build outputs, SBOMs, SARIF reports, or anything else packaged as
an OCI artifact — and answer three questions about each one through an
API: does it have known CVEs, does it contain malware, and what pipeline
stage is it at.

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
          trivy/grype    unpacker pulls + unpacks
          CLI (CVE       the image to a temp dir,
          scan of        then streams every file
          image, in a    in it to clamav (malware
          scan-worker    scan of image contents)
          Job)
```

All pieces run as Deployments in the `supply-chain-monitor` namespace on
a local Kubernetes cluster on macOS, created via `cluster/create-cluster.sh`.
Two runtime backends are supported: Colima's native `--kubernetes` (k3s
in the Docker VM, default and recommended) or k3d against Podman
(experimental). See the README's "Choosing a runtime" and
`cluster/runtimes/{colima,podman}.sh`.

- **scm-registry** (`registry:2`) — an OCI registry to push test
  images/files to during development, standing in for wherever a real
  pipeline pushes artifacts.
- **scm-clamav** (`clamav/clamav:1.3`) — the malware-scanning backend,
  spoken to over the `clamd` INSTREAM protocol.
- **scm-postgres** (`percona/percona-distribution-postgresql:17.10`) —
  persists every artifact, its findings, and its stage history.
- **monitor-api** — owns the artifact model, the pipeline-stage state
  machine, and routes scan requests to the right backend(s) by artifact
  type.
- **scm-dashboard** (`nginx:1.27-alpine` serving a static page from a
  ConfigMap) — a browser UI over `monitor-api`: artifact table,
  pipeline-stage view, and scan findings detail. A separate
  Deployment/Service, not served by `monitor-api` itself, so the API
  stays a plain JSON service and the two scale/deploy independently.
- **Traefik + Gateway API** — ingress in front of the dashboard (see
  "Ingress" below), alongside the dashboard's own NodePort.

## Data model

An `Artifact` (`internal/artifact/model.go`) has:

- `ID`, `Ref`, `Type` (`image` / `file` / `sbom` / `sarif`), `Digest`
  (resolved OCI content digest, may be empty), `Unsafe` (see "Requiring
  a verified digest" below)
- `Status` (`registered` → `scanning` → `scanned`/`failed`) and
  `StageHistory` (append-only list of pipeline-stage reports)
- Five finding buckets — `CVEFindings`, `MalwareFindings`,
  `MisconfigFindings`, `SecretFindings`, `OtherFindings` — each entry
  carrying `Status` (`open`/`fixed`), `FirstSeenAt`, `ResolvedAt`
- `HasSBOM`/`HasSARIF` flags pointing at generated documents (see
  "Generated SBOM/SARIF documents" below)

Postgres (`internal/artifact/postgres_store.go`) normalizes this into
`artifacts`, `stage_history`, `findings` (a `bucket` column instead of
five arrays, indexed on `finding_id` for `GET
/api/v1/findings/{findingID}/artifacts`), `scan_errors`, and
`artifact_documents` — all foreign-keyed to `artifacts(id)` with
`ON DELETE CASCADE`. `Store` is an interface
(`Create`/`Get`/`List`/`Update`/`Delete`/`FindByDigest`/
`FindByFindingID`); `MemStore` (a `sync.RWMutex`-protected map) backs
unit tests, `PostgresStore` is what `main.go` wires up in every real
deployment.

**Finding lifecycle.** `MergeFindings` (`internal/artifact/merge.go`)
reconciles a bucket's existing findings against a freshly reported set,
matched by ID: still-reported findings stay `open` and keep their
original `FirstSeenAt`; new IDs get `FirstSeenAt = now`; findings no
longer reported flip to `fixed` (`ResolvedAt = now`) but stay in the
bucket rather than disappearing; a finding that reappears after being
fixed flips back to `open`, clearing `ResolvedAt` but keeping its
original `FirstSeenAt`. Whether "no longer reported" is trusted to mean
"fixed" is gated per bucket by `scanner.BucketAffinity` — a scanner that
statically declares it only ever produces one bucket (Trivy, Grype,
ClamAV, the Unpacker scanners) only blocks fix-detection for that bucket
if it errors; a scanner that can't make that promise (SARIF, pluggable)
still conservatively blocks all five.

## Scanning pipeline

`internal/scanner/scanner.go`'s `Registry` maps an artifact type to a
*slice* of scanners, not a single one — `image` and `sbom` route to
whichever CVE scanner(s) `CVE_SCANNER` selects, `image` additionally to
the malware path, `file` to ClamAV alone. `scanArtifact` runs every
registered scanner for a type concurrently (one goroutine each, panics
recovered into ordinary scan errors) and sorts findings into buckets by
`Finding.Source`/`Finding.Category`, not by artifact type — this is what
lets a type gain a new finding class without touching the others.

**Built-in scanners:**

- **CVE scanning** — `TrivyScanner`/`GrypeScanner` (`image`, and
  `SBOMScanner`/`GrypeSBOMScanner` for `sbom`) shell out to the `trivy`
  / `grype` CLIs baked into the scan-worker image. `monitorApi.cveScanner`
  (`CVE_SCANNER`: `trivy` default, `grype`, or `both`) selects which
  run; under `both`, `CoalesceSameIDSources` merges a CVE reported by
  both tools into one finding with a combined `Source`
  (`"grype, trivy"`) instead of one silently overwriting the other.
- **Malware scanning** — `UnpackerScanner` pulls an `image` ref (via
  oras-go, falling back to go-containerregistry/crane) and unpacks it
  with `umoci` into a plain directory, then streams every regular file
  to `scm-clamav` over the same INSTREAM client `ClamAVScanner` uses
  for `file` artifacts. Files over `UNPACKER_MAX_FILE_MB` (default
  100MB) are skipped; if every file in an image fails to reach clamd,
  that's a hard error rather than a silently "clean" result.
- **SBOM parsing** — `SBOMScanner`/`GrypeSBOMScanner` run `trivy sbom`
  / `grype sbom:...` directly against a CycloneDX/SPDX document, no
  image to pull first.
- **SARIF parsing** — `SARIFScanner` doesn't scan anything; a SARIF
  document already *is* a set of findings (CodeQL, Semgrep, trivy's own
  `--format sarif`). It parses `runs[].results[]` and classifies each
  result into cve/misconfiguration/secret/other via
  `classifySarifCategory`, checking (in order of trust) the SARIF rule
  name against trivy's own naming convention, a CVE-ID-shaped rule ID,
  then `properties.tags` keywords, falling back to `other`.

**Pluggable scanners.** `PluggableScanner`
(`internal/scanner/pluggable.go`) shells out to an arbitrary
operator-configured command and reads its stdout as a JSON array of
findings (`[{id, severity, title, source, category}, ...]`) — the
integration point for a CVE/SBOM tool this project doesn't ship a Go
type for (Grype started here before being promoted to a built-in
scanner). `{{ref}}` in any configured arg is substituted with the real
artifact ref before running. Registered per artifact type via
`PLUGGABLE_SCANNERS` (a JSON array in `monitorApi.pluggableScanners`),
additive to the built-in scanners for that type. Command output is
capped at 10MiB (`limitedBuffer`) since this is the one place the app
runs something that could be arbitrarily buggy or compromised.

**Fetching non-image artifacts.** `file`/`sbom`/`sarif` scanners assume
`ref` is a local path already inside the pod. `FetchingScanner`
(`internal/scanner/fetch.go`) wraps any of them, resolving `ref` to a
local path first: a leading `/`, `.`, or `~` means it's already a local
path (no-op passthrough); anything else is treated as an OCI registry
reference and pulled via `oras pull` (`RegistryFetcher`) from
`scm-registry`. `image`-type scanners are left unwrapped since they
already fetch their own refs.

**Job isolation.** `UnpackerScanner` and image/sbom CVE scans run
inside a dedicated Kubernetes Job per scan (`IsolatedUnpackerScanner`,
`IsolatedTrivyScanner`, `IsolatedGrypeScanner` in
`internal/scanner/isolated_*.go`) rather than in-process inside
`monitor-api`, since they parse untrusted third-party content
(oras-go/umoci/trivy/grype). The Job runs `monitor-api scan-worker`
(a second CLI mode, `main.go`'s `runScanWorker`) with a read-only root
filesystem, every capability dropped, non-root, and no ServiceAccount
token; `monitor-api` itself talks to the Kubernetes API (create/get/
delete Job, get pod logs) via a small hand-rolled REST client
(`internal/k8sjob`) rather than pulling in `client-go`. The scan-worker
prints its result as one JSON line on stdout, marked with
`scanner.ResultMarker` so it can be found even when verbose scan
logging (`SCAN_WORKER_VERBOSE_LOGS`) tees extra output onto the same
combined stdout+stderr stream. `DISABLE_SCAN_ISOLATION` (default
`false`) falls back to running these scanners in-process, for running
the plain binary outside a cluster.

The DB each CVE scanner needs is pre-seeded rather than downloaded per
scan-worker pod: a shared, read-only `PersistentVolumeClaim` per tool
(`scm-trivy-db-cache`, `scm-grype-db-cache`), kept warm by a primer Job
at install/upgrade and a daily refresh `CronJob`, with the Job passing
`--cache-backend memory`/equivalent so the scan's own analysis cache
never touches shared disk.

**Digest resolution.** `createArtifact`/`bulkCreateArtifacts` resolve
`Ref`'s OCI content digest at registration time (`oras manifest fetch
--descriptor`, 8s timeout, best-effort) and use it to reject exact
duplicate registrations (`409 Conflict`) regardless of which tag was
used. `monitorApi.requireDigest` (`REQUIRE_DIGEST`) makes an
`expected_digest` mandatory on every registration; a mismatch or
unresolvable ref under that policy doesn't block registration, it sets
`Artifact.Unsafe = true` instead (surfaced as a badge in the dashboard).
The periodic sweep (below) opportunistically backfills a digest that
failed to resolve at registration time.

**Generated SBOM/SARIF documents.** A scan-worker Job running an image
scan converts trivy's raw report into CycloneDX and SARIF
(`trivy convert`) and POSTs both back to `monitor-api` over the
in-cluster Service, stored in `artifact_documents` and downloadable via
`GET/POST /api/v1/artifacts/{id}/documents/{kind}`. Best-effort: a
failure here never fails the scan or blocks findings from being
recorded.

## API

- `Authorization: Bearer <key>` required on every route except
  `/healthz`, `/swagger`, `/openapi.yaml`, and CORS preflight `OPTIONS`
  — checked with `crypto/subtle.ConstantTimeCompare`. `API_KEY` is
  read once at startup and `monitor-api` refuses to start without it.
- Per-key token-bucket rate limiting (`internal/api/ratelimit.go`),
  applied inside the auth check so an unauthenticated caller can't grow
  the limiter's key map. Off by default (`RATE_LIMIT_RPS <= 0`).
- CORS is wide open (`Access-Control-Allow-Origin: *`) — the dashboard
  calls the API cross-origin from the browser; the API key, not the
  origin, is what actually gates access.
- `GET /swagger` and `GET /openapi.yaml` serve a hand-written OpenAPI
  3.0 spec (`internal/api/openapi.yaml`, embedded via `go:embed`),
  covering every route the dashboard itself uses.
- Key routes beyond CRUD: `POST /api/v1/artifacts/bulk` (batch
  registration, best-effort per entry, capped at 500), `POST
  /api/v1/artifacts/{id}/scan`, `POST /api/v1/artifacts/{id}/findings`
  (record externally-produced findings into one bucket without
  triggering a scan), `POST /api/v1/artifacts/{id}/stage`, `DELETE
  /api/v1/artifacts/{id}` (hard delete, cascades to findings/history/
  documents), `GET /api/v1/findings/{findingID}/artifacts`.

## Deployment

Every service deploys as a single Helm chart, `charts/supply-chain-monitor`,
via one Flux `HelmRelease` (`k8s/releases/supply-chain-monitor-helmrelease.yaml`).
`helm install ./charts/supply-chain-monitor` works standalone, with no
Flux involved, exactly as it does through Flux.

```
charts/supply-chain-monitor/
  Chart.yaml
  values.yaml     # namespaced: registry.*, clamav.*, postgres.*, monitorApi.*, dashboard.*, gateway.*
  files/index.html
  templates/
    registry/     pvc, deployment, service
    clamav/       deployment, service
    postgres/     secret, pvc, deployment, service, backup-cronjob, backup-pvc-primer-job
    monitor-api/  serviceaccount, rbac, auth-secret, configmap, deployment, service, sweep-registered-cronjob
    dashboard/    configmap, deployment, service
    gateway/      gatewayclass, gateway, httproute
k8s/
  namespace.yaml, traefik-namespace.yaml
  kustomization.yaml           # root of what Flux reconciles
  flux-system/                 # GitRepository + root Kustomization
  sources/traefik-helmrepository.yaml
  releases/
    supply-chain-monitor-helmrelease.yaml
    traefik-helmrelease.yaml
```

Resource names (`scm-registry`, `scm-postgres`, `monitor-api`,
`scm-dashboard`, etc.) are hard-coded rather than derived from the Helm
release name — this repo's tooling already refers to those exact names,
and there's only ever one release of this chart in the cluster.

`supply-chain-monitor`'s `HelmRelease` sets `reconcileStrategy: Revision`
(not the `ChartVersion` default) since it sources from a `GitRepository`,
not a versioned `HelmRepository` — any new commit triggers a rebuild.
Traefik's `HelmRelease` stays on the `ChartVersion` default since it
pins a real chart version from an upstream `HelmRepository`.

**Ingress.** Traefik (installed via its own Flux `HelmRelease`, both
`kubernetesIngress`/`kubernetesCRD` providers disabled) routes through
the Kubernetes **Gateway API**, not classic `Ingress`. The
`GatewayClass`/`Gateway`/`HTTPRoute` objects live in this project's own
chart (`templates/gateway/`), not Traefik's — Traefik's chart disables
its own auto-created versions (`gatewayClass.enabled: false`,
`gateway.enabled: false`). The Gateway's listener port is `8000`
(Traefik's internal `web` EntryPoint port), exposed externally via
Traefik's `NodePort` Service on `30080`; the dashboard's direct
NodePort (`30301`) still works unchanged. No TLS yet — `websecure` is
disabled rather than half-wired.

**`make deploy`** builds the local `monitor-api:dev` image, commits and
pushes, forces an immediate Flux reconcile (source, root Kustomization,
both HelmReleases), then `kubectl rollout restart`s `monitor-api`/
`scm-dashboard` — still needed because the image tag never changes on
a rebuild, so nothing else notices a new image is available.

## Operational jobs

- **Postgres backups** — a daily (`0 2 * * *`) `CronJob` runs
  `pg_dump | gzip` into a separate PVC (`scm-postgres-backups`),
  keeping the newest `KEEP_BACKUPS` (default 7). On-demand backup,
  listing, and restore are `make db-backup`/`db-backups-list`/
  `db-restore BACKUP=...` targets. Point-in-time recovery isn't
  supported — worst case is losing up to a day of data.
- **Registered-artifact sweep** — `monitor-api sweep-registered`
  (a third CLI mode, run as a `CronJob` every 15 minutes by default,
  `monitorApi.sweep.*`) lists artifacts still at `registered` status,
  oldest first up to `batchSize` (default 5), and scans each through
  the normal `/scan` endpoint. Also opportunistically backfills any
  artifact still missing a digest.
- **DB cache refresh** — daily `CronJob`s per active CVE scanner keep
  the shared Trivy/Grype vulnerability-DB PVCs current, staggered an
  hour apart so they don't compete for disk/CPU on a small node.

## Known limitations

- Auth is a single shared API key — no per-client identity, no
  revocation of one caller without rotating for everyone, no rotation
  grace period.
- `charts/supply-chain-monitor/values.yaml`'s `postgres.credentials.password`
  and `monitorApi.apiKey` are empty by default — no plaintext credential
  ships in this repo. A real value comes from one of three places: Flux's
  `HelmRelease.spec.valuesFrom` (this project's own deployment, sourced
  from a `scm-chart-secrets` Secret — `make chart-secrets` creates it),
  `--set`/`-f` for a bare `helm install`, or `postgres.credentials.existingSecret` /
  `monitorApi.apiKeyExistingSecret` (both `false` by default) for fully
  externally-managed Secrets (sealed-secrets, external-secrets, SOPS,
  plain `kubectl create secret`). Left genuinely unset, Postgres's own
  entrypoint and `monitor-api`'s own startup check both refuse to run
  rather than come up with an empty password/key — see README's
  "Bringing your own secrets". `dockerAuth.accounts.*.password`
  (registry auth) has no such escape hatch yet, still plaintext-only.
- Both fetch paths (`RegistryFetcher`, `UnpackerScanner`) assume
  unauthenticated, plain-HTTP access to the registry — no credentials
  wired up for a private or TLS-terminated registry.
- No `NetworkPolicy` on scan-worker Job pods — locked down at the
  pod-security level, but not restricted at the network level.
- No TLS on the Gateway.
- Dashboard has no pagination or filtering beyond newest-first.
- SARIF and pluggable scanners can't declare a single finding bucket,
  so a failure in either still conservatively blocks fix-detection for
  all five buckets that scan round.
- `modelscan`-based scanning of Pickle/H5/SavedModel AI-model
  artifacts exists as an untested prototype
  (`cluster/modelscan-to-findings.sh`) but isn't wired into any chart
  values.

See `docs/tech-debt-audit.md` for a fuller, actively-maintained list.
