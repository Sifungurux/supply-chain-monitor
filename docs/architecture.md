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
rejection. OpenVEX `products[]` is ignored *on this endpoint*: the
document was uploaded to one artifact, so the operator has already
scoped it.

**Fleet-wide VEX.** `POST /api/v1/vex` (`internal/api/vexfleet.go`)
takes one OpenVEX document that applies wherever its products appear,
rather than to a named artifact — "CVE-2021-44228 does not apply to
log4j-core 2.14.1 the way we build it, wherever it ships." With no
artifact in the URL, `products[]` becomes the addressing, and
`scanner.ParseVEXProducts` reads it (0.0.1 bare purl strings, 0.2.0's
`@id`/`identifiers`/`hashes`, the last normalized into `sha256:<hex>`
so it compares directly against `Artifact.Digest`).

Each identifier is matched two ways, and they differ enormously in
blast radius. **By digest** the product *is* the artifact: one match,
narrow by construction. **By component purl** the product is something
artifacts *contain*, resolved through `FindByComponentPURL`, so one
line can cover the entire estate. That breadth is the point, and it is
also why the endpoint returns `artifacts_updated` and the ids (capped
at 200, with `artifacts_truncated` saying so) rather than a bare
"applied" — a fleet suppression that silently covered 400
artifacts is exactly the kind of thing this codebase keeps having to
learn to make visible. A statement naming **no** product matches
nothing and is counted in `statements_naming_no_product`; the other
reading, "applies to everything", would let one malformed document
suppress the fleet.

Documents live in their own `vex_documents` table keyed by content hash
(so re-running a `vexctl` pipeline in CI is idempotent), *not* in
`artifact_documents` — that table is keyed `(artifact_id, kind)` and
cascades from `artifacts`, which is precisely what a document belonging
to no single artifact cannot have. The two kinds coexist.

On conflict **the per-artifact statement wins**, being the more
specific claim: an operator who assessed *this* image is not overridden
by a statement about a package it happens to contain. That precedence
is applied by layering the per-artifact map over the fleet one, both at
upload time and on every scan (`runScan`), which is also what makes
revocation work across the two for free — `MergeFindings` already
revokes a suppression when it sees `affected`, so a per-artifact
`affected` over a fleet `not_affected` un-suppresses through the
existing path, with no separate retraction mechanism to keep in step.

`ParseVEXProducts` is OpenVEX-only. CycloneDX expresses the same idea
through `affects[].ref`, which points into the document's own component
tree rather than naming an identifier — resolving those means resolving
a whole BOM. A CycloneDX document posted here is rejected with a 400
saying so, rather than accepted as one that silently matches nothing.

Fleet documents are read and parsed on **every scan**, uncached, and
the ceiling to watch is *bytes* rather than document count —
`ListFleetVEX` selects the full content column, so the cost is total
stored bytes × scans in flight, and at `maxVEXBytes` each a handful of
documents is already tens of MB per scan. That is still a deliberate
call at this scale: against a scan that spends seconds to minutes in
trivy/grype it is noise, and a
process-local cache would go stale on the other replica the moment
somebody uploaded a document. If the count ever makes it measurable,
the upgrade is a short-TTL cache keyed on row count plus newest
`uploaded_at` — not a lifetime one.

**Accepting the risk of a finding.** VEX answers "this doesn't apply
here." The far more common situation has no VEX statement that is
honest: the vulnerability is real, it does apply, and there is no fix
yet — or the fix is a major-version upgrade that isn't happening this
quarter. Before this, the only options were to leave the policy gate red
forever (which teaches a team to stop reading it) or to assert a
`not_affected` nobody believes.
`POST /api/v1/artifacts/{id}/findings/{findingID}/acceptance`
(`internal/api/findings.go`) is the honest third option: a time-boxed
risk acceptance carrying `AcceptedUntil`, `AcceptedBy` and
`AcceptanceReason`.

The expiry is the whole design. An acceptance with no end date is a
deletion with extra steps, so `until` is required, must be in the
future, and is capped at 365 days — every accepted risk is re-examined
within a year, and it comes back on its own with nothing scheduled to
run and nobody to remember. An expired `accepted_until` is kept on the
finding rather than cleared, so "never accepted" and "accepted and
lapsed" stay distinguishable.

Three things follow from where the rule lives:

- **It is one predicate, honoured everywhere.** `Finding.IsActive`
  excludes an in-force acceptance alongside `fixed` and `not_affected`,
  so `internal/policy`, `GET /api/v1/stats`, the finding search and
  every dashboard count respect acceptances with no code of their own.
  `IsActive` reads the wall clock for this — `Finding.Accepted(t)` is
  the clock-injectable half the tests and the SQL are checked against.
  The Postgres backend computes the same population in SQL
  (`activeFindingSQL`), which has to be kept in step by hand: a
  backend-dependent answer to "how many artifacts have active CVEs"
  would only show up in production.
- **It survives rescans, and never blocks fix-detection.**
  `MergeFindings` carries the three fields across every merge, like
  `Justification` — a scanner re-reporting the finding is not news about
  the decision. But an accepted finding that stops being reported still
  flips to `fixed`: an accepted problem actually getting fixed is good
  news, and swallowing it would leave a resolved finding looking like
  one somebody chose to tolerate.
- **Admin scope, and `AcceptedBy` is never from the body.** Submitting
  findings and uploading VEX are `scan`-scoped, because reporting a
  result is what a CI scanner does. Deciding what the organization will
  tolerate is not, and a scanner able to make that call could silence
  whatever it found. The accepter is taken from the authenticated client
  (`ClientFromContext`) — an accountability record a caller can write is
  not one — and `MergeFindings` clears these fields on anything reported,
  so a `POST .../findings` caller can't accept its own findings' risk.

`DELETE` on the same path revokes early, and is idempotent: the caller
asked for a state ("not accepted"), and that state holds either way. A
404 is reserved for an artifact or finding id that doesn't exist.

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

### Mirroring artifacts into the local registry

With `monitorApi.mirrorArtifacts.enabled` (`MIRROR_ARTIFACTS`) on,
registration copies the artifact into `scm-registry` and rewrites
`Artifact.Ref` to the copy, keeping the ref it was registered with in
`Artifact.SourceRef`. Because every scanner reads `Ref`, that one
rewrite is what takes the public registry out of the scanning path:

    registered:  ghcr.io/acme/checkout:2.4.1
    stored ref:  scm-registry:5000/mirror/ghcr.io/acme/checkout:2.4.1
    source_ref:  ghcr.io/acme/checkout:2.4.1

The public registry is the least reliable participant in a scan.
Anonymous Docker Hub pull limits are the most common single cause of a
scan failing here; an upstream tag can move or vanish under an artifact
that has already been assessed; and every re-scan re-downloads the same
gigabytes. Mirrored, an artifact is pulled from upstream once and every
scan after that is a same-cluster pull of the exact bytes registered.

**Mechanics** (`internal/scanner/mirror.go`, `internal/api/mirror.go`):

- `oras copy --recursive` does the copy — the same binary already used
  for `oras pull`/`oras manifest fetch`, authenticating to both ends from
  the one merged docker config (`--from-registry-config` /
  `--to-registry-config`). Only the destination may be downgraded to
  plain HTTP, and only when `InsecureTransportAllowed` agrees it is this
  deployment's own registry.
- **A zero exit is not proof.** The destination ref is then resolved and
  required to equal the source digest before anything is rewritten. OCI
  refs are content-addressed, so a mismatch — or a destination that will
  not resolve — means a partial push or a wrong destination name, both of
  which otherwise produce a ref that looks fine and scans as nothing.
- `ref` and `source_ref` are written in **one** `Update`. A half-applied
  rewrite would leave a local ref with no record of where it came from,
  and there is no way back from that.
- **Best-effort throughout.** A registry that is unreachable, refusing
  the push, or out of disk leaves the artifact on its original ref; the
  next scan retries. Nothing fails a registration or a scan over it.

**Who mirrors what.** `POST /api/v1/artifacts` copies inline and answers
with the rewritten ref. `POST /api/v1/artifacts/bulk` deliberately does
not — 500 refs in one request cannot each wait for a full pull-and-push
— so bulk-registered artifacts keep their original ref until their first
scan. `runScan` calls the same `mirrorArtifact`, which makes the existing
`sweep-registered` CronJob the backfill for everything registration
skipped: bulk batches, artifacts registered before this feature existed,
and copies that failed the first time.

**Signature verification still runs against `source_ref`.** cosign's
classic signatures live at a sibling `sha256-<digest>.sig` *tag*, which
is not an OCI referrer and so is not something `oras copy --recursive`
brings along; verifying the copy would report every signed image in the
fleet as unsigned. It is also the more correct answer on its own terms —
the signer signed that identity, not a path in this cluster's registry.

**Cost:** registry disk. Every distinct artifact is stored in full and
`registry.persistence.size` defaults to 5Gi, which holds only a handful
of real images. Size it for the fleet being registered before turning
this on.

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
  artifact still missing a digest. It additionally retries every
  *failed* artifact on every run, and — with
  `scanFreshness.autoRescan` (on by default) — rescans artifacts whose
  last successful scan is older than `scanFreshness.rescanAfterDays`
  (1 day). That threshold is deliberately **not** the same value as
  the staleness badge (`warnAfterDays`, 7 days): a scanning cadence
  and an alerting threshold are different questions, and sharing one
  value leaves the badge permanently lit, since rescans are paced at
  `batchSize` per run and a full pass takes hours.
- **DB cache refresh** — daily `CronJob`s per active CVE scanner keep
  the shared Trivy/Grype vulnerability-DB PVCs current, staggered an
  hour apart so they don't compete for disk/CPU on a small node. Note
  these only refresh the *databases*: nothing re-derives findings for
  an already-scanned artifact, so the refresh is only worth anything
  in combination with the auto-rescan above.

## Known limitations

- Auth keys are **named per client** (`monitorApi.apiKeys`), so a
  request is attributed in the audit log and one consumer can be revoked
  without re-keying the others. A legacy shared `monitorApi.apiKey`
  still authenticates, as the client `default`, so upgrading cannot lock
  a deployment out. Keys also carry **scopes**
  (`monitorApi.apiKeyScopes`): `read`, `register`, `scan`,
  `documents:write` and `admin`, enforced per route in `NewRouter` so
  the whole permission model is one readable block. A denial is 403,
  not 401 — the credential is valid, it simply may not do this.


  What remains, deliberately: scopes are configured in the chart rather
  than managed through an API, so granting one means a redeploy. The
  report's H1 sketched a database-backed `api_keys` table with
  CRUD endpoints; the Secret-based form was chosen instead because it
  keeps credentials in the same place as every other secret this chart
  manages, with no new admin surface to protect. And enforcement is
  **opt-in**: with `apiKeyScopes` empty nothing is enforced, and once
  set, a key with no entry still runs unrestricted (named in a startup
  warning) so that scoping one consumer cannot break the others.
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
  **External** private registries are now configurable too, via
  `monitorApi.registryCredentials`: each entry names a host and one of
  three credential sources — inline `username`/`password`, a
  `usernameSecretRef` naming an operator-managed Secret that holds a
  bare username and password (with the key names configurable, since
  an existing Secret rarely calls them `username`/`password`), or an
  existing `kubernetes.io/dockerconfigjson` Secret — plus an optional
  CA. Prefer `usernameSecretRef`: the inline form puts a registry
  password in `values.yaml`, which is checked into git in most
  deployments including this one.

  A `usernameSecretRef` pair carries no host of its own the way a
  dockerconfigjson does, so **the host is the mount path**: the chart
  mounts each pair at `/etc/scm/registry-auth/<host>` and
  `mergeRegistryAuths` reads it back from the directory name. The
  volume name could not carry it — that must be a DNS-1123 label, and
  `registry.internal:5000` is not one. A colon in a `mountPath` was
  verified against a real kubelet, not assumed. Everything lands in ONE merged
  `config.json` that every tool authenticates from — `oras` via
  `--registry-config`, trivy/grype/cosign via `DOCKER_CONFIG`, unpacker
  via `--config` — so a credential is scoped to its own host instead of
  being offered to whatever registry a scan happens to touch. The merge
  happens in the pod at startup rather than in the chart, because an
  operator-managed Secret's contents are not readable at template time.
  The same Secrets and CAs are mounted into every scan-worker Job, so
  the isolated path authenticates identically.

  Three things this does NOT do. It does not open network egress: a
  registry on a private address or a non-standard port is still refused
  by the scan-worker egress policy, which allows 80/443 to public
  addresses only (see `templates/networkpolicy/scan-worker-egress.yaml`).
  It does not map host names to docker's auth keys: `host` is used
  verbatim, so Docker Hub must be written as
  `https://index.docker.io/v1/`. And it does not verify that a
  configured credential works — a wrong one degrades to an anonymous
  pull, which against a public registry succeeds with fewer results
  rather than failing.

  One implementation detail worth knowing before touching
  `mergeRegistryAuths`: a mounted Secret is not a flat directory. The
  kubelet's atomic writer keeps the real files in a timestamped
  `..2026_08_22_15_44_23.381250005` directory and symlinks `..data` at
  it, so every key is visible twice. That is harmless for a docker
  config (the same hosts merged twice) and wrong for a
  `usernameSecretRef` pair, whose host is its directory name — the
  second copy would register credentials for a registry called
  `..2026_08_22_15_44_23.381250005`. Hence the dot-directory skip in
  the walk, and the test that reproduces the real mount layout rather
  than two plain files.
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
