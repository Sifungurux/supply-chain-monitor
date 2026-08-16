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
  carrying `Status` (`open`/`fixed`/`not_affected`), `FirstSeenAt`,
  `ResolvedAt`, and `Justification` (see "Suppressing findings with
  VEX" below)
- `HasSBOM`/`HasSARIF` flags pointing at generated documents (see
  "Generated SBOM/SARIF documents" below)

Postgres (`internal/artifact/postgres_store.go`) normalizes this into
`artifacts`, `stage_history`, `findings` (a `bucket` column instead of
five arrays, indexed on `finding_id` for `GET
/api/v1/findings/{findingID}/artifacts`), `scan_errors`,
`artifact_documents`, and `components` (see "Indexing SBOM components"
below) — all foreign-keyed to `artifacts(id)` with
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

**Suppressing findings with VEX.** A scanner reports what a component
*contains*; whether a vulnerability is actually exploitable in this
artifact is a judgement it can't make. VEX is how that judgement gets
recorded: `POST /api/v1/artifacts/{id}/vex` (`internal/api/vex.go`)
takes an OpenVEX or CycloneDX-VEX document, parses it
(`internal/scanner/vex.go` — both formats, told apart by whether the
document has a `statements` or a `vulnerabilities` array), and applies
every `not_affected`/`fixed` statement to the artifact's findings
immediately. `under_investigation` changes nothing, and neither does any
status string the parser doesn't recognize — the failure direction is
showing a real vulnerability, never hiding one. `affected` is the one
non-suppressing status that still does something: it revokes an earlier
`not_affected` on the same vulnerability, so a wrong assessment can be
retracted by re-uploading a corrected document rather than by editing
the database.

Three properties are worth spelling out, because each one is a way this
could have been built wrong:

- **Suppression is stored on the finding, not derived from the
  document.** A finding already carrying `not_affected` keeps that
  status and its `Justification` when a scanner reports it again — which
  it always will, since VEX asserts something about reachability, not
  about the image's contents. Nothing has to re-read the document for
  suppression to hold, so a scan that can't load it doesn't reopen work
  somebody already assessed.
- **The document is still re-read on every scan and findings
  submission** (`handler.vexFor`), so a vulnerability *discovered after*
  the document was uploaded lands suppressed instead of being open until
  something else merges it.
- **Suppressed is not deleted.** `not_affected` findings stay in their
  bucket with the justification attached, out of every count on the
  dashboard (`openFindings`) but visible on the detail page with a
  "VEX: not affected" badge — the same "keep history, don't overwrite
  it" treatment `fixed` gets.

`Justification` is lifecycle metadata like `Status`/`FirstSeenAt`:
`MergeFindings` always recomputes it, so a `POST .../findings` caller
can't invent a justification for a finding nobody assessed. VEX
documents are stored through the same `artifact_documents` table as
SBOM/SARIF (kind `vex`) but deliberately aren't accepted by the generic
`POST .../documents/{kind}` endpoint — that one stores bytes, and a VEX
document that stored but suppressed nothing would be worse than a
rejection. OpenVEX `products[]` is ignored: the document was uploaded to
one artifact, so the operator has already scoped it (matching purls
would be the change needed if VEX ever arrives fleet-wide rather than
per-artifact).

**Indexing SBOM components.** An SBOM's whole point is the inventory it
carries, but as a stored blob that inventory can only be read one
downloaded document at a time. So `uploadDocument`
(`internal/api/documents.go`) parses each uploaded SBOM
(`scanner.ParseSBOMComponents` — CycloneDX or SPDX JSON, told apart by
whether the document has a `components` or a `packages` array) into a
`components` table indexed on purl, and `GET /api/v1/components?purl=…`
answers "every artifact containing this package" through that index —
the component-level counterpart to `FindByFindingID`'s "every artifact
affected by this CVE", and the same normalize-so-it's-queryable move
findings already got.

Three things this gets right that are easy to get wrong:

- **Parse after storing, best-effort.** The document is saved first and
  a parse failure is only logged. `scanner.UploadDocument` treats any
  non-200 as a scan error that lands in `LastScanErrors`, so rejecting
  an unfamiliar SBOM would turn a good scan into a failed one *and*
  discard a document that is itself fine and downloadable. (Deliberately
  the opposite ordering from `uploadVEX`, which parses first — there the
  parse *is* the point.)
- **`SaveComponents` replaces, in a transaction.** `SaveDocument`
  overwrites the previous SBOM rather than keeping history, so appending
  here would leave every package the artifact ever contained on record
  and keep answering queries for one a rebuild removed. DELETE + INSERT
  in one transaction, with `UNIQUE (artifact_id, purl)` making a
  duplicate inside one document a no-op.
- **The document's own subject isn't a component of itself.** CycloneDX
  keeps it in `metadata.component` (outside the array), SPDX puts it in
  `packages[]` with `primaryPackagePurpose: CONTAINER` — skipped
  explicitly, or the two formats disagree by exactly one row for the
  same image.

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

**Fetching non-image artifacts.** `file`/`sbom`/`sarif` scanners take a
local path to scan. `FetchingScanner` (`internal/scanner/fetch.go`)
wraps any of them, resolving `ref` to one first: a leading `/`, `.`, or
`~` means the ref names a path on this pod's own filesystem, which is
refused unless an operator opted in via `ALLOW_LOCAL_ARTIFACT_PATHS` +
`LOCAL_ARTIFACT_ROOT` and the path survives `filepath.Clean`,
`EvalSymlinks`, and a regular-file check against that root
(`internal/scanner/localpath.go`) — that convention predates registry
fetching and, ungated, was an arbitrary-file-read primitive, since
`file`/`sarif` artifacts scan in-process rather than in an isolated
Job. Anything else is treated as an OCI registry
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

**Ref validation.** An artifact `ref` is caller-supplied input that
`monitor-api` then makes outbound requests with (`oras`, trivy, grype,
unpacker), which makes it an SSRF primitive unless something bounds
where it may point. `scanner.ValidateRef`
(`internal/scanner/refvalidate.go`) refuses a ref carrying a URL scheme,
and refuses one whose registry host is `*.svc.cluster.local` (by name)
or resolves to a loopback, link-local (`169.254.0.0/16`, including the
cloud instance-metadata address), private (RFC1918, IPv6 ULA), or
unspecified address. It runs at registration in both endpoints *before*
digest resolution -- the first thing to make an outbound request -- and
again at every point the ref becomes an outbound request:
`RegistryFetcher.Fetch` and `OrasDigestResolver.Resolve` for the
fetch/digest paths, and `TrivyScanner.ScanRaw`, `GrypeScanner.ScanRaw`,
`UnpackerScanner.Scan` and `PluggableScanner.Scan` for `image` artifacts,
which are pulled by those tools themselves and so never touch Fetch or
Resolve at all. `scanArtifact` also re-checks before dispatching
anything, which is what catches a row registered before this existed --
refused with a 400 *before* the status flips, so the artifact keeps its
findings (failing inside `runScan` would hand `MergeFindings` an empty
result set and mark every existing finding "fixed"). The per-scanner
checks are what cover the scan-worker Job, a process no handler check
reaches; note trivy is validated in `ScanRaw` rather than `Scan`,
because the worker's image mode arrives via `ScanWithRaw`.
`REF_HOST_ALLOWLIST` (`monitorApi.refHostAllowlist`) exempts named
hosts; the chart populates it with this deployment's own `scm-registry`,
which would otherwise be refused twice over -- it is both a cluster-DNS
name and a `ClusterIP` in RFC1918 space. A host that doesn't resolve at
all is allowed through (there is no address to reach, and an unreachable
registry at registration time is routine here); the fetch fails on its
own later.

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
- Every write endpoint caps its request body with
  `http.MaxBytesReader` and answers `413` rather than `400` when the cap
  is hit (`internal/api/bodylimit.go`): 64KiB for the small JSON writes,
  4MiB for bulk registration and for a VEX document, 16MiB for findings
  submission, 64MiB for a document upload. The pre-existing per-entry caps (`maxBulkArtifacts`,
  the findings validation) don't cover this — they run *after*
  `json.Decode` has already read the whole body into memory, so they
  bound a request's logical size, not the bytes spent getting there.
  `ReadTimeout` bounds how long a body may take to arrive, not how large
  it may be.
- Per-key token-bucket rate limiting (`internal/api/ratelimit.go`),
  applied inside the auth check so an unauthenticated caller can't grow
  the limiter's key map. Off by default (`RATE_LIMIT_RPS <= 0`).
- CORS is wide open (`Access-Control-Allow-Origin: *`) — the dashboard
  calls the API cross-origin from the browser; the API key, not the
  origin, is what actually gates access.
- `GET /swagger` and `GET /openapi.yaml` serve a hand-written OpenAPI
  3.0 spec (`internal/api/openapi.yaml`, embedded via `go:embed`),
  covering every route the dashboard itself uses.
- `GET /api/v1/artifacts` is paginated server-side:
  `?limit=50&offset=0` (max 200, over that is a `400` rather than a
  silent clamp) with optional `?status=`/`?type=` filters, answering
  `{"total": N, "artifacts": [...]}` plus `X-Total-Count` and RFC 5988
  `Link` next/prev headers. `Store.ListPage` backs it — one page plus a
  total, ordered by `(created_at DESC, id DESC)` so paging over an
  unstable tie order can't skip or repeat rows. The unpaginated
  `Store.List` is kept for callers that genuinely want everything.
  Filters are applied in the database (a `WHERE` clause shared by the
  page query and its `COUNT(*)`), not in Go after loading every row.
- **Outbound notifications** (`internal/notify`, off by default): when a
  scan introduces new findings at or above `NOTIFY_MIN_SEVERITY`, a
  generic webhook (optionally HMAC-SHA256 signed) and/or a Slack
  incoming webhook receive the event. "New" reuses `MergeFindings`'
  `FirstSeenAt` stamp rather than recomputing it, so a re-scan reporting
  the same findings is silent, and an artifact's first ever scan is
  suppressed by default (everything is new on a first look -- that's a
  backlog pager, not a change signal), overridable with
  `suppressFirstScan: false` for pipelines where each artifact is only
  ever scanned once. Delivery is fire-and-forget on its own
  goroutine: a destination that errors, hangs, or panics is logged and
  dropped, and cannot fail a scan — the one-way counterpart to the
  inbound webhooks CI/CD already uses to register artifacts.
- `POST /api/v1/artifacts/{id}/scan` is **asynchronous**: it answers
  `202` with a `Location` pointing at the artifact, runs every scanner
  for that type concurrently in a background goroutine, and callers poll
  `GET /api/v1/artifacts/{id}` until `status` leaves `scanning`. It used
  to block until every scanner finished, which the 30s `http.Server`
  `WriteTimeout` made unworkable — a 30–330s scan had its connection torn
  down before the response could be written, so callers saw a dropped
  connection while the work completed server-side. A scan interrupted by
  a pod restart leaves its artifact at `scanning`; the `sweep-registered`
  CronJob reclaims those by re-scanning anything stuck over 20 minutes
  (`staleScanningAfter`), which is why "re-scan" is the reclaim rather
  than a status-rewriting endpoint that doesn't exist.
- **Registration is bounded** by `MAX_ARTIFACTS` /
  `monitorApi.maxArtifacts` (0 = unlimited, the default). `Store.Count`
  backs it, checked once per request -- a bulk registration asks once
  and decrements locally rather than counting per entry. Over the cap,
  single registration answers `403` (a quota is not a rate limit:
  retrying cannot help, deleting can) and bulk reports it per entry so a
  partially-fitting batch still registers what fits. Duplicates create
  nothing and never consume quota -- in both endpoints the quota gate
  sits *after* the dedup check, so re-registering an existing artifact
  stays an idempotent 409 even at the cap. `Count` + `Create` is not one
  transaction, so the bound is approximate under concurrent registration
  (overshoot bounded by in-flight requests). The API key is shared, so this bounds
  the deployment rather than any individual caller.
- Concurrent scans are capped server-side (`SCAN_CONCURRENCY` /
  `monitorApi.scanConcurrency`, 4 in the chart, 0 = unlimited in the
  binary). A saturated cap answers `429` + `Retry-After` immediately —
  no queue, since scanning is asynchronous and no caller is blocked on
  the response; the slot is taken *after* the 404/501 checks and
  *before* the status flips to `scanning`, so a rejected scan leaves the
  artifact untouched. The cap counts scans, but the resource is Jobs:
  one image scan spawns one scan-worker Job per registered scanner,
  concurrently — three at the chart's default `cveScanner: "both"`
  (trivy, grype, unpacker) — each extracting a whole image to disk. The
  per-Job ephemeral limit only ever contained one Job at a time; this is
  what bounds them collectively.
- **Duplicate registration** keys on the resolved content digest, and
  falls back to the exact ref when no digest could be resolved
  (`Store.FindByRef`). The fallback exists because an empty digest is
  routine — dead ref, rate-limited registry, or a local path that never
  had one — and skipping the check there meant every re-registration
  created a new artifact: a live deployment accumulated 43 duplicate
  rows from 5 unresolvable refs. A resolved digest always wins, since
  only a digest separates "same image twice" from "mutable tag whose
  content changed"; the ref is used only where no such evidence exists.
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
NodePort (`30301`) still works unchanged. `websecure` is exposed (NodePort
`30443`) and the Gateway terminates TLS there; see "Known limitations"
for what a private CA does and does not buy.

**Network policy.** Three `NetworkPolicy` objects
(`templates/networkpolicy/`, gated on `networkPolicy.enabled`, default
true) put an L3 floor under the application-layer ref validation above.

The important one is a **default-deny egress** policy on scan-worker Job
pods (`app: scm-scan-worker`, set by `k8sjob.NewScanJob`). Those pods run
trivy/grype/unpacker against a caller-supplied ref, so they are where a
confused-deputy request would originate. They may reach exactly: DNS,
clamd, the in-cluster registry, that registry's token-auth service, and
monitor-api — plus the public internet on 80/443 with RFC1918 and
`169.254.0.0/16` carved out. That last exception is the security
content: it denies the cloud metadata service and the kube-apiserver
(ClusterIP and node addresses alike) while still allowing the public
registry pulls every `image` scan depends on. Note `NetworkPolicy` has
no deny primitive — an `except` narrows the rule it appears in, and
rules are OR'd, so the in-cluster `podSelector` allows still work.

Postgres gets ingress from monitor-api and backup Jobs only (its probes
are `exec`, so no kubelet allowance is needed). monitor-api gets ingress
from the ingress controller, in-namespace pods, and the node CIDRs —
that last one is required, since its probes are `httpGet` and kubelet
traffic comes from the node, not a pod. Its egress is deliberately left
open except the metadata range: it legitimately talks to the apiserver
(it creates the scan Jobs), Postgres, registries, and arbitrary
notification webhooks, so a default-deny there would be a long allow-list
that breaks the first time someone configures a new webhook.

**These enforce nothing on a CNI that ignores NetworkPolicy** — the
objects are accepted and enforce zero, which is worse than absent
because it looks like protection. k3s/k3d enforce them via an embedded
kube-router; see `networkPolicy` in values.yaml for a probe that
verifies enforcement on your own cluster.

**Image supply chain.** `services/monitor-api/Dockerfile` bundles five
third-party binaries (trivy, grype, oras, unpacker, umoci) plus the
service itself, so how they get in is part of this project's own threat
model rather than a build detail. Every base image is pinned by digest
as well as tag; every downloaded tarball is checked against a per-arch
sha256 pinned in the Dockerfile before it is unpacked; umoci is pinned
to a commit, with a `rev-parse` assertion so the pin is verified rather
than merely stated. Downloads happen in a dedicated `tools` stage, which
keeps `curl` and GNU `tar` out of the shipped image entirely. The
runtime stage ends with `USER 65534` — the same uid every workload in
this chart already pins — so a bare `docker run` gets the same non-root
posture the cluster enforces. (Note for derived images: switch to `USER
root` for install steps and back afterwards, see README's pluggable-
scanner example.)

Alpine rather than distroless is a checked decision, not an omission:
four of this chart's own workloads run `sh -c` from this image (the
trivy/grype DB primer Jobs and refresh CronJobs), so a shell-less base
would break the vulnerability-DB pipeline every scan depends on. The
`monitor-api` binary itself is static (`CGO_ENABLED=0`) and would move
to `distroless/static` unchanged the day those four stop needing a
shell. `make test-image` asserts all of this and runs in CI, on an
amd64 runner — the only place the amd64 half of the checksum table
actually executes, since qemu can't emulate the Go toolchain well
enough to build that image on an arm64 dev machine.

**`make deploy`** builds the local `monitor-api:dev` image, commits and
pushes, forces an immediate Flux reconcile (source, root Kustomization,
both HelmReleases), then `kubectl rollout restart`s `monitor-api`/
`scm-dashboard` — still needed because the image tag never changes on
a rebuild, so nothing else notices a new image is available.

## Operational jobs

- **Postgres TLS** — the database serves TLS with a certificate from
  the same private CA as the Gateway and registry
  (`postgres.tls.enabled`, on by default). The key cannot come
  straight from a Secret mount: postgres refuses a group-readable key
  file, and the usual fix — a pod-level `fsGroup` — is the one thing
  this pod cannot have, because it applies recursively and turns
  PGDATA's `0700` into `0770`, which postgres also refuses. An
  initContainer running as the same uid copies the pair to an
  `emptyDir` and chmods the key to `0600`. monitor-api's `sslmode` is
  *derived* from this setting rather than configured separately, so
  the server and client cannot disagree — a server serving TLS while
  clients connect in cleartext is a failure with no runtime symptom.
  Default `require` (encrypted, certificate unchecked);
  `postgres.tls.verify` gives `verify-full`, which additionally needs
  the CA mounted and is a hard startup failure if the SAN or mount is
  wrong, which is why it is not the default.
- **Postgres backups** — a daily (`0 2 * * *`) `CronJob` runs
  `pg_dump | gzip` into a separate PVC (`scm-postgres-backups`),
  keeping the newest `KEEP_BACKUPS` (default 7). On-demand backup,
  listing, and restore are `make db-backup`/`db-backups-list`/
  `db-restore BACKUP=...` targets. Point-in-time recovery isn't
  supported — worst case is losing up to a day of data.
  Optionally encrypted (`postgres.backup.encryption.publicKeySecret`)
  to a GPG **public** key, so the cluster holds only the half that
  encrypts and cannot read its own backups; the private half is lent
  to a restore Job by `cluster/postgres-restore.sh` and deleted
  afterwards. Each dump carries a `.sha256` sidecar, and validity is
  asserted *mid-stream* — verifying after the write stopped being
  possible once the writer can no longer decrypt what it wrote. The
  gate is byte-oriented (`dd` reads the first 512 bytes, checks the
  header there, and passes the rest of the stream through untouched)
  rather than line-oriented: a line-oriented gate has to hold one
  whole `pg_dump` COPY row in memory, and rows holding SBOM/SARIF
  documents are tens of MB, which OOM-killed the job. Dumps are
  written to `*.partial` and renamed, so the final name only exists
  once every byte is there — SIGKILL, node loss and power failure all
  run no cleanup, and an interrupted write that looked like a finished
  backup would be kept by the rule below. Retention sorts by the ISO
  timestamp in the filename rather than by mtime, which doesn't
  survive a PVC restore or a file copy.
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

- Auth keys are **named per client** (`monitorApi.apiKeys`), so a
  request is attributed in the audit log and one consumer can be revoked
  without re-keying the others. A legacy shared `monitorApi.apiKey`
  still authenticates, as the client `default`, so upgrading cannot lock
  a deployment out. What is still missing is **scopes**: every key is
  full-privilege, so a key that only needs to register artifacts can
  also delete them and upload VEX (which suppresses findings).
- **The dashboard hands its API key to any browser that loads it.** An
  initContainer renders `env.js` from the same Secret
  (`templates/dashboard/deployment.yaml`), so whoever can reach the
  dashboard holds a full-privilege key. That is the trade-off for
  needing no manual key entry; treat dashboard access as equivalent to
  key access.
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
  "Bringing your own secrets". The three `dockerAuth.accounts.*.password`
  values (registry auth) now work the same way -- empty by default,
  sourced from `make chart-secrets`/`--set`/`dockerAuth.existingSecret`,
  and an account left unset is omitted from docker_auth's config
  entirely rather than rendered as a hash of the empty string (which
  would accept an empty password).
- `scm-registry` and `scm-docker-auth`'s token endpoint serve **TLS**
  from the in-cluster private CA (`registry.tls.enabled`, on by
  default), and both fetch paths authenticate with the registry
  credentials the chart provisions. In-cluster clients get the CA
  mounted with `SSL_CERT_DIR` — deliberately not `SSL_CERT_FILE`, which
  in Go *replaces* the system trust store and would stop `oras`,
  `trivy` and `grype` trusting public registries.
  What is still not wired up is an **external** private registry: there
  is no per-registry credential or CA configuration for pulling from,
  say, a private GHCR or Harbor.
- Scan concurrency is now cluster-wide: slots are rows in a `scan_slots`
  table rather than a buffered channel per process, so two monitor-api
  replicas share one budget instead of each allowing a full
  `SCAN_CONCURRENCY`. Acquisition takes a transaction-scoped advisory
  lock per scanner kind before counting -- `INSERT ... SELECT WHERE
  count < cap` does not serialize under READ COMMITTED, so without it
  two racers both see a free slot and the cap is quietly exceeded under
  exactly the load it exists to bound.

  The new failure mode to know about: a pod killed mid-scan leaves its
  slot rows behind. They are reaped by the next acquisition once they
  are older than the scan timeout plus a margin -- above the timeout so
  a slow-but-healthy scan never loses its slot, and below the sweep
  CronJob's own 20-minute artifact reclamation so the reclaim's re-scan
  can actually get a slot. Slots are not tied to artifacts by foreign
  key for the same reason: deleting an artifact mid-scan must not free a
  slot whose work is still running.
- The Gateway terminates **TLS** with a cert-manager-issued certificate
  from a private CA, and redirects plain HTTP to HTTPS (308). It is a
  *private* CA: browsers warn until it is trusted, and it is no
  substitute for a real certificate on anything public.
- The dashboard's search box only searches the page currently loaded
  (server-side `status`/`type` filters narrow the whole set instead).
  The summary cards and pipeline strip no longer have this problem —
  they read `GET /api/v1/stats`, which aggregates over the whole store
  in the backend.
- `/healthz` reports the process, not its dependencies: it returns
  `{"status":"ok"}` without touching Postgres, and backs both the
  readiness and the liveness probe. Startup is covered (main.go blocks
  on `connectStoreWithRetry` before listening), but a database that
  goes away *after* startup leaves the pod Ready and serving 500s.
- SARIF and pluggable scanners can't declare a single finding bucket,
  so a failure in either still conservatively blocks fix-detection for
  all five buckets that scan round.
- `modelscan`-based scanning of Pickle/H5/SavedModel AI-model
  artifacts exists as an untested prototype
  (`cluster/modelscan-to-findings.sh`) but isn't wired into any chart
  values.

See `docs/tech-debt-audit.md` for a fuller, actively-maintained list.
