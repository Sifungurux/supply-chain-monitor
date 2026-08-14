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
  install-gateway-api.sh   installs the Gateway API CRDs (`make gateway-api-install`, or automatic via `make cluster-up`)
  postgres-restore.sh, postgres-list-backups.sh   on-demand Postgres backup restore/listing (`make db-restore`/`db-backups-list`)
charts/supply-chain-monitor/   the whole application as ONE Helm chart (see "GitOps (Flux)" below)
  Chart.yaml, values.yaml (namespaced per service: registry.*, clamav.*, postgres.*,
    monitorApi.*, dashboard.*, gateway.*), templates/{registry,clamav,postgres,
    monitor-api,dashboard,gateway}/, files/index.html
k8s/                    what Flux actually reconciles (path: ./k8s) -- no raw per-service
                        manifests anymore, just the namespaces, Flux's own bootstrap
                        self-reference, and two HelmReleases (the app, and Traefik)
  namespace.yaml, traefik-namespace.yaml
  flux-system/          GitRepository + root Kustomization (gotk-sync.yaml), Flux install values.yaml
  sources/              upstream HelmRepository for Traefik's chart (not vendored into charts/)
  releases/             supply-chain-monitor-helmrelease.yaml (the app) + traefik-helmrelease.yaml
services/monitor-api/   the Go API service source + tests (internal/.../*_test.go)
dashboard/index.html    the dashboard itself (source of truth -- charts/supply-chain-monitor/files/index.html is a copy of this)
dashboard/tests/        dashboard test suite (Node + jsdom)
docs/architecture.md    design notes, rationale, roadmap
Makefile                cluster-up/down/destroy, build, deploy, port-forward, test
```

## Prerequisites

Install on your Mac (this runs against your local machine, not a sandbox):

- kubectl
- Go 1.25+ (only if you want to build/run `monitor-api` outside a container)
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

`make` targets detect the runtime: a running podman machine with no
running colima picks podman, and anything else (both running, neither
running, colima only) falls back to colima. Override whenever the guess
is wrong — `make cluster-up SCM_RUNTIME=podman`, or export it — since a
running VM doesn't prove the k3d cluster was created on it. The scripts
above are unchanged: run directly, they still default to colima.

Getting this wrong used to fail badly rather than loudly. On podman
without the flag, `DOCKER_HOST` was never resolved, so `make build` went
looking for `/var/run/docker.sock` and reported what reads like a broken
Docker install — and the k3d image import was skipped silently, so a
`make deploy` that appeared to succeed would roll out the previous
image.

## Quickstart

```bash
make cluster-up       # colima start --kubernetes (or podman, if SCM_RUNTIME=podman); also installs Flux
make chart-secrets     # generates the Postgres password + API key the chart needs (see "Bringing your own secrets" below)
make deploy            # docker build + git push + trigger Flux reconcile + rollout restart
kubectl -n supply-chain-monitor get pods -w   # wait for everything to go Ready
```

`postgres.credentials.password` and `monitorApi.apiKey` are empty by
default in the chart's `values.yaml` — Postgres and monitor-api both
fail to start without `make chart-secrets` run first.

`make cluster-up` also installs Flux (see "GitOps (Flux)" below) —
`SCM_SKIP_FLUX=1 make cluster-up` if you don't want that yet. The whole
application (registry, clamav, postgres, monitor-api, dashboard) is one
Helm chart deployed via Flux now — `make deploy` no longer applies
manifests directly, it pushes to Git and lets Flux do it (see "GitOps
(Flux)"). That means `make deploy` needs this repo to actually be pushed
to a Git remote first — see that section for the one-time setup.

**This setup — a single Helm chart + Flux, path `./k8s` — has been run
end-to-end on a real, multi-node podman/k3d cluster**, repeatedly,
including `make deploy` and `make load-test-clamav` — see
`docs/tech-debt-audit.md`'s Status section for what that testing found
and fixed (a Flux `reconcileStrategy` bug that silently stopped chart
updates from ever reaching the cluster, a Gateway API listener-port
mismatch, an ephemeral-storage eviction under load, among others), all
against the real cluster, not simulated. Colima (the default,
recommended runtime — see "Choosing a runtime" below) hasn't been
separately re-confirmed against this exact chart in the same round of
testing; if you hit something there that doesn't match this doc,
that's the more likely place to look first.

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
cp dashboard/index.html charts/supply-chain-monitor/files/index.html
make deploy
```

### Auto-configured API address/key

The dashboard no longer needs anyone to open it and paste an API key
in by hand. `charts/supply-chain-monitor/templates/dashboard/deployment.yaml` runs a small
initContainer before nginx starts that reads `API_KEY` from the same
`scm-monitor-api-auth` Secret the monitor-api chart creates, and writes
it (plus an optional API-address override from the
`scm-dashboard-config` ConfigMap, empty/unset by default) into a
generated `env.js` the page loads automatically. Rotate the key in one
place (`charts/supply-chain-monitor/values.yaml`'s `monitorApi.apiKey`,
or an override in
`k8s/releases/supply-chain-monitor-helmrelease.yaml`'s `spec.values`) and
redeploy — both `monitor-api` and every dashboard pod pick up the new
value, no manual re-entry anywhere. If you ever *do* want the dashboard
to point at a fixed address instead of self-detecting one from
`window.location`, set `dashboard.apiBase` in
`charts/supply-chain-monitor/values.yaml` (or override it in
`k8s/releases/supply-chain-monitor-helmrelease.yaml`) and redeploy. See
docs/architecture.md ("Configuring the dashboard via ConfigMap/Secret
instead of by hand") for the full design and a real bug that was found
and fixed while wiring this up (a ConfigMap name mismatch that left the
dashboard pod unable to mount its own HTML at all).

## Authentication

Every endpoint except `/healthz`, `/readyz` and `/metrics` requires
`Authorization: Bearer <key>` (a kubelet probe can't present one).
The key is sourced from `API_KEY`, which `monitor-api` reads from the
`scm-monitor-api-auth` Secret (rendered from
`charts/supply-chain-monitor/values.yaml`'s `monitorApi.apiKey` by
default) — see "Bringing your own secrets" below before this cluster
is anything but local and throwaway, the same caveat as
`scm-postgres-credentials`. A request with no key, the wrong key, or a
missing `Bearer ` prefix gets a `401`.

```bash
curl -s localhost:8080/api/v1/artifacts \
  -H "Authorization: Bearer $API_KEY"
```

That endpoint is paginated: it answers with
`{"total": N, "artifacts": [...]}` where `total` counts everything
matching the filters (not the page), plus `X-Total-Count` and RFC 5988
`Link` headers carrying next/prev. Default page size is 50, the maximum
is 200 (a larger `limit` is a `400`, not a silent clamp), and
`?status=` / `?type=` narrow the set server-side:

```bash
curl -s "localhost:8080/api/v1/artifacts?limit=100&offset=100&status=scanned&type=image" \
  -H "Authorization: Bearer $API_KEY"
```

See docs/architecture.md ("Adding API authentication") for why a
single shared key, why the probe endpoints and CORS preflight `OPTIONS` are
exempt, and what's still missing (per-client keys, rotation, rate
limiting).

### Bringing your own secrets

`postgres.credentials.password` and `monitorApi.apiKey` are **empty**
in the chart's own `values.yaml` — deliberately, so a real value never
sits in plaintext in a committed file. Left empty, Postgres's own
entrypoint refuses to start (it requires a non-empty
`POSTGRES_PASSWORD`) and `monitor-api` refuses to start (`API_KEY must
be set`) — a fresh `helm install` with truly default values fails
loudly rather than coming up with a known, checked-in password. You
need to supply real values one of two ways:

**Through Flux (this project's actual deployment path):**
`k8s/releases/supply-chain-monitor-helmrelease.yaml`'s `spec.valuesFrom`
sources both from a Secret, `scm-chart-secrets`, in the `flux-system`
namespace (not `supply-chain-monitor` — Flux requires a `valuesFrom`
Secret to live alongside the `HelmRelease` object itself). Create/update
it with:

```bash
make chart-secrets   # first run: generates a strong random value for
                      # anything you don't pass in
                      # POSTGRES_PASSWORD=... API_KEY=... make chart-secrets
                      # rotates just the one(s) you pass — the other is
                      # carried over unchanged from the existing Secret
```

Nothing in this repo ever sees either value — see
`cluster/chart-secrets.sh`, which also prints the extra step Postgres
needs on rotation (an `ALTER ROLE`, since it only reads
`POSTGRES_PASSWORD` on first init against an empty volume — a plain
pod restart against the existing PVC won't pick up a new one).
`monitor-api` and `scm-dashboard` just need a restart, since a
Secret's *content* changing doesn't trigger a rollout on its own, the
same as any other running pod's env vars.

**Without Flux** (a bare `helm install`/`helm upgrade`, or testing
locally): pass real values directly —
`--set postgres.credentials.password=... --set monitorApi.apiKey=...`,
or a gitignored `-f my-secrets.yaml`.

**Fully external management** (sealed-secrets, an external-secrets
operator, SOPS, or you'd just rather `kubectl create secret` the exact
Secret objects yourself): set `postgres.credentials.existingSecret: true`
and/or `monitorApi.apiKeyExistingSecret: true` instead of either path
above. The chart then skips rendering its own copy of that Secret
entirely — you're expected to have already created one yourself under
the exact name the rest of the chart already expects
(`scm-postgres-credentials` with `POSTGRES_USER`/`POSTGRES_PASSWORD`/
`POSTGRES_DB` keys, `scm-monitor-api-auth` with an `API_KEY` key, both
in the `supply-chain-monitor` namespace this time, not `flux-system` —
this is a different mechanism from `valuesFrom` above, matching
whatever namespace the chart itself deploys into). If the named Secret
doesn't actually exist when a pod that needs it starts, that pod fails
to start (`CreateContainerConfigError`, missing key/Secret) — the
normal, expected Kubernetes failure mode for this pattern, not
something this chart adds extra validation on top of.

The `dockerAuth.accounts.*.password` values (registry auth) are a
separate, still-plaintext-only set of credentials — none of the above
covers them yet; see docs/architecture.md's "Known limitations".

## API

Interactive docs (every route below, plus request/response schemas) are
served by `monitor-api` itself at `/swagger` — no auth required to read
them, same as `/healthz` (the spec is `/openapi.yaml`). This table stays
as a quick-reference summary; `/swagger` is the source of truth for exact
request/response shapes.

| Method | Path                              | Purpose                                   |
|--------|-----------------------------------|--------------------------------------------|
| GET    | `/healthz`                        | liveness — the process only, never the database (a liveness failure kills the pod) |
| GET    | `/readyz`                         | readiness — pings Postgres; 503 when it is unreachable, so the pod leaves the Service instead of serving 500s |
| GET    | `/metrics`                        | Prometheus metrics — process and scan counters only, never fleet data (which is why it needs no key) |
| GET    | `/api/v1/pipeline/stages`         | list configured pipeline stages            |
| GET    | `/api/v1/stats`                   | fleet-wide counts: artifacts by status/type/stage, plus how many carry active findings per bucket — what the dashboard's summary cards read, since `/api/v1/artifacts` is paginated |
| POST   | `/api/v1/artifacts`                | register an artifact `{ref, type}`         |
| POST   | `/api/v1/artifacts/bulk`           | register many artifacts in one request `{artifacts: [{ref, type}, ...]}`, max 500 |
| GET    | `/api/v1/artifacts`                | list tracked artifacts, newest first — paginated (`?limit=50&offset=0`, max 200) with optional `?status=`/`?type=` filters |
| GET    | `/api/v1/artifacts/{id}`           | get one artifact (findings, current stage) |
| DELETE | `/api/v1/artifacts/{id}`           | permanently delete an artifact and everything recorded against it (no undo) |
| POST   | `/api/v1/artifacts/{id}/scan`      | run the scanner appropriate for its type   |
| POST   | `/api/v1/artifacts/{id}/findings`  | record findings an external system already computed `{bucket, findings}` |
| POST   | `/api/v1/artifacts/{id}/vex`       | upload an OpenVEX/CycloneDX-VEX document and suppress the findings it clears |
| POST   | `/api/v1/artifacts/{id}/stage`     | record a pipeline-stage transition         |
| GET    | `/api/v1/findings?q=...`           | search finding ids/titles ("log4j") — returns matching ids with artifact counts |
| GET    | `/api/v1/findings/{findingID}/artifacts` | every artifact still affected by a given finding ID (e.g. a CVE) |
| GET    | `/api/v1/components?purl=...`      | every artifact whose ingested SBOM lists that component |

`type` is one of `image`, `file`, `sbom`, `sarif`.

Example flow:

```bash
# a bash array, not a plain string -- keeps "Authorization: Bearer <key>"
# as one argument through expansion instead of being word-split on the
# space (a plain `AUTH='-H Authorization:Bearer\ <key>'` string looks
# like it should work but silently truncates the header at the space
# when $AUTH is expanded unquoted below; use "${AUTH[@]}", quoted, with
# an array instead)
AUTH=(-H "Authorization: Bearer $API_KEY")

# register a container image artifact
curl -s -X POST localhost:8080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"alpine:3.19","type":"image"}'
# => {"id":"...", "ref":"alpine:3.19", "type":"image", "status":"registered", ...}

# tell the monitor it just left the "build" stage of your pipeline
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/stage "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"stage":"build","note":"CI job #482"}'

# scan it: for type=image this runs Trivy (CVEs) *and* unpacker+ClamAV
# (malware) and merges both into the same artifact
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/scan "${AUTH[@]}"

# check results -- cve_findings from trivy, malware_findings from clamav,
# misconfiguration_findings/secret_findings/other_findings from parsed
# SARIF, classified per-result (see "SBOM and SARIF scanning" below)
curl -s localhost:8080/api/v1/artifacts/<id> "${AUTH[@]}"

# search findings by id or title when you don't have the exact id
curl -s "${AUTH[@]}" --get --data-urlencode 'q=log4j' localhost:8080/api/v1/findings

# find every artifact still affected by a given finding (e.g. after a
# fix ships, confirm nothing registered still carries this CVE)
curl -s localhost:8080/api/v1/findings/CVE-2024-1234/artifacts "${AUTH[@]}"
```

### Registering many artifacts at once

`POST /api/v1/artifacts/bulk` takes `{"artifacts": [{"ref":..., "type":...}, ...]}`
and registers every entry in one request, instead of one round trip per
artifact via plain `POST /api/v1/artifacts`. It's best-effort, not
all-or-nothing: one bad entry (missing `ref`, invalid `type`) doesn't
stop the rest of the batch from registering, and the response reports
success/failure per entry. `testdata/bulk-test-images.json` is a ready-
made batch of 95 real image refs spread across six public registries
(public.ecr.aws, quay.io, ghcr.io, registry.k8s.io, mcr.microsoft.com,
gcr.io) for exercising this in one call:

It deliberately contains **no Docker Hub references**: a 100-image burst
exhausts Docker Hub's anonymous pull limit part-way through, and the
resulting 401/429 is classified as `registry_auth_failed` — so a load
test reports failures for perfectly healthy images and two runs are
never comparable. Official images are mirrored at
`public.ecr.aws/docker/library/<name>`; keep new entries off Docker Hub
for the same reason.

```bash
curl -s -X POST localhost:8080/api/v1/artifacts/bulk "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d @testdata/bulk-test-images.json
# => {"created":100,"failed":0,"duplicates":0,"results":[{"ref":"alpine:3.19","type":"image","artifact":{...}}, ...]}
```

### Duplicate registration is caught by content, not by ref string

Both `POST /api/v1/artifacts` and the bulk endpoint above resolve each
`image`/`sbom`/`sarif` ref's real OCI content digest (via `oras manifest
fetch --descriptor`, best-effort -- an unreachable/rate-limited registry
never fails a registration) and check it against every digest already on
record. This catches the same
underlying image registered twice even under two different tags
(`alpine:3.19` and `alpine:latest` resolving to the same digest), not
just an exact repeated ref string.

`POST /api/v1/artifacts` returns `409 Conflict` for a genuine duplicate:

```bash
curl -s -X POST localhost:8080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"alpine:latest","type":"image"}'
# => {"error":"an artifact with this digest is already registered", "digest":"sha256:...",
#     "existing_artifact_id":"...", "existing_artifact_ref":"alpine:3.19"}
```

**When a digest can't be resolved, the ref is the fallback key.** An
unresolvable digest is routine, not exceptional — a dead or moved ref, a
rate-limited registry, or a `file`-type path that never had one. Dedup
used to be skipped entirely in that case, so every re-registration
created a *new* artifact: this deployment accumulated 43 duplicate rows
from 5 unresolvable refs across ~9 runs, all with an empty digest. Now a
registration with no resolved digest matches on the exact ref instead.

A resolved digest always wins — it's strictly better evidence, and only
a digest distinguishes "the same image twice" from "a mutable tag whose
content changed". The ref fallback applies *only* when there's no digest
to compare, where there is no evidence of a change either way and
creating an unscannable second row is the worse outcome.

The bulk endpoint treats a duplicate as its own outcome, not a failure --
`duplicates` is a separate counter from `failed`, and a duplicate
entry's `artifact` field still points at the *existing* artifact rather
than being empty, so re-submitting `testdata/bulk-test-images.json` a
second time (e.g. re-running `make load-test-clamav`) still returns a
usable artifact id per ref instead of erroring the whole batch. `file`-
type artifacts using the opt-in local-path convention (see
`looksLikeLocalPath` and "Local filesystem paths as refs") never
attempt digest resolution at all -- there's no registry to check a
filesystem path against.

A bare Docker Hub ref (`nginx:alpine`, `bitnami/redis:7.2.5` -- no
explicit registry host) is qualified with `docker.io/` (and `library/`
for a single-segment official-image name) before being handed to `oras`:
unlike `docker pull`, `oras` never applies that default itself, so
`oras manifest fetch nginx:alpine` parses `nginx` as the registry host
and fails a DNS lookup for it -- every unqualified Docker Hub ref,
deterministically, every time (confirmed live: `oras manifest fetch
bitnami/redis:7.2.5` tried to resolve a registry literally named
`bitnami`). `qualifyDockerHubRef` (`internal/scanner/digest.go`) is the
fix, applied only to digest resolution -- image *scanning* (trivy, via
go-containerregistry) already applies this same default on its own, so
it was never affected.

Registration-time resolution above is one-shot -- a registry that's
rate-limited or briefly unreachable at that moment leaves the digest
empty forever, with no automatic retry. `monitor-api sweep-registered`
(a `CronJob`, `monitorApi.sweep.schedule` -- every 15 minutes by
default) periodically scans up to `monitorApi.sweep.batchSize` (default
5) artifacts still sitting at status `registered`, oldest first; every
scan it triggers also backfills a missing digest if the registry
resolves cleanly this time. Set `monitorApi.sweep.enabled: false` to
turn it off. See docs/architecture.md ("Sweeping registered-but-
unscanned artifacts, and backfilling missing digests") for the full
reasoning.

### Notifications

When a scan introduces **new** findings at or above a severity
threshold, monitor-api can POST an event outbound. Off by default — with
no URL configured nothing is sent, and nothing can fail.

```yaml
monitorApi:
  notifications:
    webhookURL: "https://example.internal/scm-hook"   # generic receiver
    webhookSecret: "..."                              # optional HMAC-SHA256
    slackURL: "https://hooks.slack.com/services/..."  # optional Slack
    minSeverity: "high"                               # critical|high|medium|low
    suppressFirstScan: true                           # default; see below
```

Env equivalents: `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET`,
`NOTIFY_SLACK_URL`, `NOTIFY_MIN_SEVERITY`,
`NOTIFY_SUPPRESS_FIRST_SCAN`.

The generic webhook payload:

```json
{
  "artifact_id": "8f14e45fceea167a",
  "artifact_ref": "ghcr.io/acme/checkout:2.4.1",
  "severity": "CRITICAL",
  "new_findings": [
    { "id": "CVE-2024-1234", "severity": "CRITICAL", "title": "openssl", "source": "trivy", "status": "open", "first_seen_at": "..." }
  ]
}
```

**"New" means new to this artifact in this scan round.** A re-scan
reporting the same findings is silent, so a nightly sweep doesn't page
about a CVE that has been known for weeks; a finding that was fixed and
came back counts as new again.

**An artifact's first ever scan does not notify** —
`suppressFirstScan: true`, the default. Every finding is "new" there
only because nobody had looked before; that's not a change in the
artifact, which is what this signal is for. Without it, switching
notifications on in an existing deployment pages once per
already-registered artifact as the sweep works through the backlog, and
re-registering anything re-pages it.

Set `suppressFirstScan: false` (`NOTIFY_SUPPRESS_FIRST_SCAN=false`)
where the first scan *is* the interesting event — a pipeline that
registers and scans each artifact once at import never gets a second
scan to compare against, so the default would mean it never notifies at
all.

A first scan that *failed* still counts as having looked, so the next
successful scan notifies under either setting. That decision isn't recomputed here — it
reuses the `FirstSeenAt` stamp `MergeFindings` already assigns (see
docs/architecture.md, "Tracking finding lifecycle").

**Severity is compared case-insensitively**, because scanners disagree:
trivy emits `HIGH`, grype emits `High`, ClamAV findings are written
`critical`, and all three land in the same table. A finding a scanner
couldn't rate (`UNKNOWN`, `Negligible`) never satisfies a real threshold
on its own.

**Signing.** With `webhookSecret` set, each request carries
`X-Signature-256: sha256=<hex>` — HMAC-SHA256 over the exact request
body, the same shape GitHub uses, so a receiver written against that
convention verifies it unchanged. Compare with a constant-time helper
(`hmac.Equal`, `crypto.timingSafeEqual`), not `==`.

**Delivery is fire-and-forget.** Each destination gets its own
goroutine with a 30s budget; the generic webhook retries once on a 5xx
or transport error (never on a 4xx — the request itself is wrong).
Failures are logged and dropped. A destination that is down, slow, or
panicking can never fail a scan, change its result, or delay it —
there's a test for each of those.

`webhookSecret` and `slackURL` are templated into their own Secret
(`scm-monitor-api-notify`), not the ConfigMap: the Slack incoming
webhook URL *is* the credential.

### Scanning is asynchronous

`POST /api/v1/artifacts/{id}/scan` returns **202** as soon as the scan
starts and does not wait for it to finish. Poll
`GET /api/v1/artifacts/{id}` (the `Location` header points there) until
`status` leaves `scanning` — it settles on `scanned`, or `failed` if
every scanner failed:

```bash
curl -s -o /dev/null -w '%{http_code} %header{Location}\n' \
  -X POST localhost:8080/api/v1/artifacts/$ID/scan \
  -H "Authorization: Bearer $API_KEY"
# 202 /api/v1/artifacts/8f14e45fceea167a

curl -s localhost:8080/api/v1/artifacts/$ID \
  -H "Authorization: Bearer $API_KEY" | jq -r .status
# scanning  ... then: scanned
```

The 202 body is the artifact as the scan *started*, so its findings are
the previous scan's — read results from the poll, not from the 202.

This used to block until every scanner finished, which never worked end
to end: the API's `http.Server` sets a 30s write timeout, the deadline
starts when the request headers are read, and a real scan runs
30–330s — so the server tore the connection down before it could answer
and callers saw a dropped connection (`curl` reports `000`) for anything
but the fastest scans. The work always completed server-side; only the
answer was lost.

A scan interrupted by a pod restart leaves its artifact at `scanning`
with nothing left to finish it; the `sweep-registered` CronJob reclaims
those by re-scanning anything stuck there for over 20 minutes.

### Logs and metrics

Logs are **structured JSON on stderr**, one object per line
(`log/slog`). `monitorApi.logLevel` (`LOG_LEVEL`, **info**) sets the
floor — `debug`, `info`, `warn`, `error`; anything unrecognized means
`info` rather than refusing to start.

Fields are named consistently across packages so one identifier finds
everything about it: `artifact_id`, `ref`, `err`, `scanner`, `status`,
`job`, `host`, `count`.

```bash
kubectl logs deploy/monitor-api | jq 'select(.artifact_id == "b4e826f58da2884c")'
kubectl logs deploy/monitor-api | jq 'select(.level == "ERROR")'
```

stderr specifically, because `monitor-api scan-worker` prints its
result JSON to stdout and the parent reads it back out of the Job pod's
logs.

`GET /metrics` serves Prometheus text-format metrics — responses by
status class, scans started/succeeded/failed, uptime, goroutines, heap.
It needs no API key: it reports *process* state only, never fleet data
(that's `/api/v1/stats`, which does need the key), and it never queries
the database — a scrape endpoint that did would fail exactly when the
database is down.

Set `monitorApi.serviceMonitor.enabled=true` to have a Prometheus
Operator scrape it. Off by default because `ServiceMonitor` is a CRD:
enabling it without prometheus-operator installed makes the install
fail on an unknown kind.

### Capping how many artifacts can exist

`monitorApi.maxArtifacts` (`MAX_ARTIFACTS`, **0 = unlimited** by
default) bounds the total number of artifacts.

Nothing else does: the bulk endpoint caps *one request* at 500 entries
and the body limits cap bytes per request, but a caller can repeat
either indefinitely — and every artifact costs a row, its findings, its
stage history, and a share of every list the dashboard polls every 10s.

```bash
curl -s -X POST localhost:8080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"alpine:3.19","type":"image"}'
# => 403 {"error":"artifact limit reached (500) -- delete artifacts to free
#          capacity, or raise monitorApi.maxArtifacts", "max_artifacts":500}
```

**403, not 429** — a quota is not a rate limit. Retrying doesn't help;
deleting artifacts does, and it frees the quota again. This matches
Kubernetes' own `ResourceQuota` behaviour.

The check is a `COUNT(*)` followed by an insert, not one transaction, so
the bound is **approximate under concurrent registration**: N requests
arriving at once with one slot left can all pass the gate. Overshoot is
bounded by the number of in-flight registrations, which is what a
deployment guardrail needs — but don't read `count > maxArtifacts` after
a burst as a bug.

A **bulk** request fills to the cap and reports the rest per entry, so a
batch that half fits still registers the half that does — the same
best-effort shape that endpoint already uses for bad refs. Duplicates
create nothing and so never consume quota, which keeps re-submitting the
same batch a safe no-op — and for the same reason **single registration
of an existing artifact still answers 409 at the cap**, not 403.

Note the API key is a single shared one, so this bounds the
*deployment*, not a caller: there is no per-client identity to meter.

### Capping concurrent scans

One scan fans out to a scan-worker Job **per registered scanner**, all
running at once — with `cveScanner: "both"` that's three (trivy, grype,
unpacker) — and each extracts the whole image under scan into its own
`/tmp` (512Mi request, 3Gi limit, measured peaks 1.8–2.6Gi). That
per-Job limit stops one Job from filling a node; it does nothing about
fifty scans' worth of Jobs at once, which an unbounded
`POST /api/v1/artifacts/{id}/scan` allowed.

`monitorApi.scanConcurrency` (`SCAN_CONCURRENCY`, **8** in the chart —
so up to ~24 concurrent Jobs at the default `cveScanner`; multiply
before changing it) caps how many scans run at once across the process.
It is bounded by node scratch disk, nothing else — `values.yaml`
documents the measurements and what would let you raise it (bigger
nodes, or moving per-Job `/tmp` onto a networked StorageClass such as
Ceph RBD).
Scanning is asynchronous, so nobody is blocked on the response: a
request arriving with every slot busy is rejected immediately with a
`429` and `Retry-After`, rather than queueing:

```bash
curl -s -o /dev/null -w '%{http_code} %header{Retry-After}\n' \
  -X POST localhost:8080/api/v1/artifacts/$ID/scan \
  -H "Authorization: Bearer $API_KEY"
# 429 10
```

A rejected request leaves the artifact untouched — it is never marked
`scanning`. `0` disables the cap entirely (the binary's own default when
the chart isn't in play). Note that per-key rate limiting
(`RATE_LIMIT_RPS`) also answers `429`; the two are distinguishable by
the error message. `cluster/load-test-clamav.sh` honors `Retry-After`
and reports retries separately, so a load test at `PARALLELISM` above
the cap still measures the scan pipeline rather than the cap.

### Requiring a verified digest at registration

`expected_digest` above is normally optional, and a mismatch refuses the
whole registration (409). `monitorApi.requireDigest` (`REQUIRE_DIGEST`)
is a deployment-wide policy that changes both of those: `expected_digest`
becomes a **required** field on every `POST /api/v1/artifacts` (and every
entry in a bulk request) -- missing it is a 400, before any registry call
happens -- and a mismatch (or an unresolvable ref) no longer refuses
registration. The artifact is still created, just with `"unsafe": true`:

```bash
curl -s -X POST localhost:8080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"alpine:3.19","type":"image","expected_digest":"sha256:claimed..."}'
# resolved digest doesn't match "sha256:claimed..." ->
# {"id":"...", "ref":"alpine:3.19", "digest":"sha256:actual...", "unsafe":true, ...}
```

This is deliberately a mark, not a block: refusing every unverifiable
registration outright would be too disruptive to turn on for an existing
pipeline that doesn't yet know about it. The dashboard shows a red
"Unsafe" badge next to the status badge, both in the artifact table and
on the detail page, for anything registered this way. Off by default --
turning it on is a real policy change, not something a deployment should
pick up silently.

### Where an artifact ref may point

A `ref` is caller-supplied, and monitor-api makes outbound requests with
it (digest resolution, `oras pull`, trivy/grype/unpacker) -- so it is
validated before any of that happens, on both `POST /api/v1/artifacts`
and `/artifacts/bulk`, and again in the fetch/resolve code itself so the
scan-worker Jobs are covered too. Refused with a `400`:

- anything carrying a URL scheme (`https://...`, `file://...`) -- an OCI
  ref is `host/repo:tag`, never a URL;
- a host ending in `.svc.cluster.local`;
- a host resolving to a loopback, link-local, RFC1918/IPv6-ULA, or
  unspecified address.

```bash
curl -s -X POST localhost:8080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"169.254.169.254/latest/meta-data:1","type":"image"}'
# {"error":"ref host \"169.254.169.254\" resolves to a link-local address -- refused (set REF_HOST_ALLOWLIST to permit it)"}
```

That link-local range is where every major cloud serves instance
credentials, which is the whole point: without this, an artifact ref is
a way to make monitor-api fetch from anything its pod can reach.

`monitorApi.refHostAllowlist` (`REF_HOST_ALLOWLIST`, comma-separated
`host` or `host:port`) exempts hosts you actually do run a registry on.
This chart's own `scm-registry` is already exempt automatically -- it is
both a cluster-DNS name and a `ClusterIP`, so it would otherwise be
refused twice over. A ref whose host doesn't resolve at all is allowed
through, unchanged from before: there is nothing to reach, and
registering an artifact whose registry is temporarily unreachable is
normal here. A ref that is already a filesystem path inside the pod
(the `/path/to/file` convention) makes no outbound request and is left
alone.

### Submitting findings from an external scanner

`/scan` always has monitor-api run one of its own registered scanners
(Trivy, unpacker+ClamAV, ...) against `ref` itself. If a scan already
happened somewhere else -- an external pipeline's own malware scanner,
a SAST tool run in CI -- and you just want to record the result,
`/api/v1/artifacts/{id}/findings` takes the findings directly instead,
with no fetch or re-scan of `ref` involved at all:

```bash
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/findings "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{
    "bucket": "malware",
    "findings": [
      {"id": "eicar-test-signature", "severity": "critical", "title": "EICAR test file detected", "source": "external-clamav"}
    ]
  }'
```

`bucket` is one of `cve`, `malware`, `misconfiguration`, `secret`,
`other` -- matching `cve_findings`/`malware_findings`/
`misconfiguration_findings`/`secret_findings`/`other_findings` on the
artifact. This call only ever touches the one bucket named, unlike
`/scan` (which re-runs every scanner for the type and touches all
five), so submitting external malware results here won't disturb CVE
findings a real Trivy scan already produced against the same artifact.
An artifact still in `registered` status moves to `scanned` after its
first `/findings` call; an artifact that's already
`scanning`/`scanned`/`failed` keeps its existing status.

An external SAST/IaC/secrets-scanning tool that already produces its
own SARIF report doesn't need to pre-sort its results into these
buckets by hand -- registering the report as a `sarif`-type artifact
and calling `/scan` gets the same classification `/findings` requires
manually, done automatically (see "SBOM and SARIF scanning" below).
`/findings` exists for tools that report in some other format
entirely, or that already know which single bucket their result
belongs in.

### Finding lifecycle: open, new, and fixed

Both `/scan` and `/findings` **merge** each round's report into the
bucket's existing findings rather than replacing it wholesale. Every
finding carries a `status` (`"open"` or `"fixed"`), a `first_seen_at`,
and a `resolved_at` (set once it's fixed):

- A finding reported again keeps its original `first_seen_at` -- it
  doesn't look newly discovered just because a scan re-ran.
- A finding that stops being reported becomes `"fixed"`, with
  `resolved_at` set -- it stays visible (so "what got fixed, and when"
  is answerable), it just isn't currently open anymore.
- A finding reported once, then absent, then reported again (a
  regression) goes back to `"open"` and `resolved_at` clears -- but
  `first_seen_at` still reflects the original discovery date.
- `/scan` only marks anything fixed on a fully clean run -- if any
  registered scanner for the type errored, existing findings are left
  exactly as they were rather than risk a scanner failure looking like
  "everything got fixed." `/findings` always trusts the caller's report
  as complete for the bucket named.

`GET /api/v1/artifacts/{id}` and the dashboard both reflect this: the
count columns and summary cards only count `open` findings (a fixed CVE
doesn't inflate "With CVEs"), and the detail view shows a `Fixed`
badge with how long ago, or a `New` badge for anything discovered on
the most recent update.

### Suppressing findings with VEX

A scanner can tell you a vulnerable component is *present*. It cannot
tell you whether the vulnerable code is reachable in your image, whether
the affected feature is even compiled in, or whether the CVE applies to
your platform at all. Those are human judgements, and without somewhere
to record them the list of findings only grows — until nobody reads it,
which costs more than the CVEs did.

VEX (Vulnerability EXploitability eXchange) is the format for recording
them, and `POST /api/v1/artifacts/{id}/vex` is where it goes. A
suppressed finding is not deleted: it stays on the artifact with its
justification and a badge, out of every count.

**Writing a document.** Both formats are accepted — OpenVEX
(`{"statements": […]}`) and CycloneDX VEX
(`{"vulnerabilities": [{"id": …, "analysis": {"state": …}}]}`) — told
apart by shape rather than by a version string, so a document whose
`@context`/`bomFormat` is missing or misspelled still parses. OpenVEX's
`vulnerability` may be the 0.0.1 bare string or the 0.2.0 object form.

The smallest document this service will act on is two fields:

```json
{ "statements": [ { "vulnerability": "CVE-2024-1234", "status": "not_affected" } ] }
```

A realistic one adds the reason, which is what makes the record worth
keeping. `@context`, `author`, `timestamp` and `version` are all
accepted and ignored here — keep them if you want the document to be
valid OpenVEX for other tools:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "security@example.com",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-1234" },
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
```

**Uploading it.** From a file, which is what a document checked in next
to a Dockerfile or produced by `vexctl create` looks like:

```bash
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/vex "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  --data-binary @vex.json
```

A file isn't required — the endpoint takes the document as the request
body, so a one-off assessment can go inline, and a generator can pipe
straight in:

```bash
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/vex "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"statements":[{"vulnerability":{"name":"CVE-2024-1234"},
       "status":"not_affected","justification":"component_not_present"}]}'

# anything that writes an OpenVEX document to stdout (vexctl, a build
# step, jq) can pipe straight in -- see vexctl's own docs for its flags
vexctl create <args> \
  | curl -s -X POST localhost:8080/api/v1/artifacts/<id>/vex "${AUTH[@]}" \
      -H 'Content-Type: application/json' --data-binary @-
```

The response reports how many statements were understood — the one
number that tells you the document said something this service could
read — plus the updated artifact:

```json
{ "status": "applied", "statements": 1, "artifact": { ... } }
```

`"statements": 0` means a document that parsed but asserted nothing
matchable: usually a `vulnerability` field this parser couldn't find an
id in. It's a successful upload that changed nothing, which is worth
being able to see without diffing the artifact.

An artifact holds **one** VEX document: re-uploading replaces the
previous one, so upload the complete current set of statements rather
than a delta. A document that fails to parse is a `400` and leaves
whatever was already applied in place — deliberately unlike an SBOM
upload, which stores the document and only skips the indexing, because
there the parse is a bonus and here it *is* the point.

What each status does:

| VEX status | effect on a matching finding |
|------------|------------------------------|
| `not_affected` (CycloneDX `not_affected`, `false_positive`) | `status` becomes `"not_affected"`, `justification` attached, dropped from every count |
| `fixed` (CycloneDX `resolved`, `resolved_with_pedigree`) | `status` becomes `"fixed"` with `resolved_at` set, same as a scan-detected fix |
| `affected` (CycloneDX `exploitable`) | revokes an earlier `not_affected` on that vulnerability — this is how a wrong assessment is retracted. Nothing otherwise: a reported finding already means "affected" |
| `under_investigation` (`in_triage`) | nothing — "nobody's decided yet" is not a reason to hide a finding, or to un-hide one somebody already assessed |
| anything unrecognized | nothing — a status this parser doesn't know shows the vulnerability rather than hiding it |

**What happens to the finding.** It gains `"status": "not_affected"` and
the `justification` from the statement, and drops out of every count:
the dashboard's summary cards, the per-artifact CVE/malware columns, the
risk spectrum, the tab counts, and search. It stays visible on the
artifact's detail page with a `VEX: not affected` badge (justification in
the tooltip), dimmed the way a fixed finding is — the record of an
assessment is worth as much as the assessment.

Notifications follow the same line: a suppressed finding is not "new and
at or above the threshold", so it never pages anyone.

**You upload once, not per scan.** The suppression is written onto the
finding, so the next scan — which *will* report that CVE again, because
VEX asserts reachability and doesn't change the image — leaves it
suppressed. That matters more than it sounds: if suppression were
re-derived from the document each time, a scan that couldn't read it
would silently reopen work somebody had already assessed.

The document is *also* re-read on every scan and every `/findings`
submission, but only to catch what wasn't there before: a vulnerability
first reported next month lands already suppressed rather than being
open until something merges it.

**Checking it worked**, without trusting a `200`:

```bash
# the finding itself
curl -s "${AUTH[@]}" localhost:8080/api/v1/artifacts/<id> \
  | jq '.cve_findings[] | select(.status == "not_affected")
        | {id, status, justification}'
```
```sql
-- or across the fleet, via `make db-shell`
SELECT a.ref, f.finding_id, f.justification
FROM findings f JOIN artifacts a ON a.id = f.artifact_id
WHERE f.status = 'not_affected';
```

**Retracting.** Upload a document that states `affected` for that
vulnerability and it reopens immediately, on the same upload path that
applies one:

```bash
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/vex "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"statements":[{"vulnerability":{"name":"CVE-2024-1234"},"status":"affected"}]}'
```

The status goes back to `open` and the justification is cleared with the
suppression it explained. A document that merely *stops mentioning* a
vulnerability retracts nothing — silence isn't an assertion, so removing
a statement leaves the earlier one standing.

Some details worth knowing:

- **`justification` is server-managed.** Only a VEX document can set it;
  `MergeFindings` recomputes it on every write, so a `/findings` caller
  can't attach a reason to a finding nobody assessed. The same is true of
  `status` — `not_affected` cannot be submitted, only asserted.
- **A statement applies to the artifact you uploaded it to, and only
  that one.** OpenVEX `products[]`/`subcomponents` are ignored: the
  document arrived at `/artifacts/{id}/vex`, so the scoping is already
  done. There is no fleet-wide VEX ingestion — the same document has to
  be uploaded per artifact (a loop over
  `/api/v1/findings/{cve}/artifacts` is the practical way to do that).
- **Unrecognized statuses suppress nothing.** A typo or an unfamiliar
  vocabulary leaves the finding exactly as the scan found it. The
  failure direction is showing a real vulnerability, never hiding one.
- **It suppresses findings, not artifacts.** An image whose only CVE is
  suppressed shows 0 CVEs and stays exactly where it was in every other
  view.
- **The document is kept** (document kind `vex`) so a later scan can
  re-read it — but it is deliberately *not* reachable through
  `POST /documents/{kind}`, which stores bytes and would let a document
  land without ever being applied.

### Searching findings: which images still have this CVE?

Exact ids are the right thing to *answer* with and a poor thing to
*search* with — you remember "log4j" or "that Spring RCE", not
`CVE-2021-44228`. So finding lookup works in the same two steps
component search does:

```bash
# 1. which ids exist, and where's the weight?
curl -s "${AUTH[@]}" --get --data-urlencode 'q=log4j' \
  localhost:8080/api/v1/findings
```
```json
{ "total": 2, "findings": [
  { "id": "CVE-2021-44228", "title": "log4j: RCE via JNDI lookup",
    "severity": "critical", "artifacts": 12 },
  { "id": "CVE-2021-45046", "title": "log4j: incomplete fix for CVE-2021-44228",
    "severity": "high", "artifacts": 9 } ] }
```
```bash
# 2. exactly which artifacts are still affected by the one you meant
curl -s "${AUTH[@]}" localhost:8080/api/v1/findings/CVE-2021-44228/artifacts
```

`q` matches a substring of the finding id *or* its title,
case-insensitively, so `log4j`, `CVE-2021`, and `jndi` all get there.
Results are distinct ids (not one row per artifact), most widespread
first, capped at 200 with the true total reported alongside. `severity`
is the **worst** recorded for that id across artifacts — a scanner
revising a rating between scans shouldn't let a search rank a critical
as medium.

**Both steps count the same population: findings that are neither fixed
nor VEX-suppressed.** A search promising "12 artifacts" that opens onto
15 would be worse than no count at all, so the exact lookup applies the
same filter — it has always described itself as "still affected", and an
artifact that patched the CVE or formally assessed it as not applying is
not still affected. If you need the historical view ("who *ever* had
this"), query the `findings` table via `make db-shell`; the API answers
the operational question.

The dashboard's second search box is this endpoint: type `log4j`, get
the matching ids with severity and artifact counts, click one to see the
artifacts, with a link back to the other matches. An exact `CVE-…` id
skips the picker.

### SBOM and SARIF scanning

`sbom` and `sarif` artifacts are wired up now too, alongside `image`
and `file`:

- **`sbom`** — `trivy sbom` scans a CycloneDX/SPDX document for known
  CVEs in the components it lists, landing in `cve_findings` same as
  image scans (and sharing the same air-gapped DB-mirror config, see
  above).
- **`sarif`** — a SARIF file already **is** a set of findings (from
  CodeQL, Semgrep, Checkov, Gitleaks, trivy's own `--format sarif`
  output, etc.), so nothing gets re-scanned; the file is parsed
  directly. A single SARIF document can legitimately mix several kinds
  of result at once — trivy's own SARIF output alone can carry both
  CVEs and misconfigurations in the same file — so each result is
  classified individually into `cve_findings`,
  `misconfiguration_findings`, `secret_findings`, or `other_findings`
  (the catch-all for SAST/code-quality/license findings and anything
  else that doesn't fit the more specific buckets), rather than
  lumping every SARIF result into one bucket regardless of what it
  actually is. Classification checks, in order:
  1. The rule's SARIF `name` field against trivy's own convention
     (`OsPackageVulnerability`/`LanguageSpecificPackageVulnerability` →
     cve, `Misconfiguration` → misconfiguration, `Secret` → secret,
     `License` → other) — trusted first since it's the producing tool
     telling us directly what a result is.
  2. A CVE-ID-shaped rule ID (`CVE-YYYY-NNNN`, with or without a
     prefix like `go/`) → cve — tool-agnostic, for scanners besides
     trivy that use CVE numbers as rule IDs.
  3. Keyword matching against the rule's `tags` (e.g. `secret`/
     `credential` → secret, `misconfig`/`iac`/`compliance` →
     misconfiguration, `cve`/`vulnerab` → cve) — SARIF's own spec says
     tags shouldn't be used this way, but in practice most tools don't
     follow that, and tags remain the most common cross-tool signal.
  4. Anything matching none of the above lands in `other_findings`,
     the same place every SARIF result used to land before this
     classification existed — this only ever adds precision, it never
     drops a finding.

### Searching by component: which images ship this package?

An SBOM answers "what is in this artifact". Stored as a document, that
answer can only be read one download at a time — which is the wrong
shape for the question people actually turn up with, which is the
inverse: *"we just heard about log4j / that base image / this
transitive Go module — where is it?"*

So every SBOM ingested through
`POST /api/v1/artifacts/{id}/documents/sbom` is also parsed into a
normalized `components` table (purl, name, version, artifact id) indexed
on purl, and `GET /api/v1/components?purl=…` answers across the whole
fleet at once. It's the package-level counterpart to
`GET /api/v1/findings/{findingID}/artifacts`, which answers the same
shape of question about a CVE, and it shares that endpoint's
conventions: the full artifacts rather than bare IDs, newest first, and
an empty array (not a `404`) when nothing ships it.

**Getting SBOMs in.** For `image` artifacts this is already happening:
a scan-worker Job converts the trivy report it just produced into a
CycloneDX SBOM and uploads it (see "Image scanning" above), and that
upload is what triggers indexing. **Scan an image and its components
index themselves** — there is no second tool to run and no extra step.

To index an SBOM produced somewhere else (syft, a build system, a
vendor-supplied document), upload it yourself:

```bash
curl -s -X POST "${AUTH[@]}" \
  -H 'Content-Type: application/vnd.cyclonedx+json' \
  --data-binary @sbom.json \
  localhost:8080/api/v1/artifacts/<id>/documents/sbom
```

CycloneDX and SPDX are both read, and in JSON only. They're told apart
by shape (a `components` array vs a `packages` one) rather than by
`bomFormat`/`spdxVersion`, so a hand-assembled document that omits or
misspells those still parses. Nested `components[].components[]` are
walked, which matters for producers like syft that express transitive
dependencies as nesting rather than a flat list.

**Querying it, in two steps.** Nobody knows they want
`pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64&distro=3.19.1`. They know
`openssl`. So the endpoint answers two questions — search, then answer:

```bash
# 1. which openssl packages actually exist, and where's the weight?
curl -s "${AUTH[@]}" --get --data-urlencode 'q=openssl' \
  localhost:8080/api/v1/components
```
```json
{ "total": 3, "packages": [
  { "purl": "pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64&distro=3.19.1",
    "name": "openssl", "version": "3.1.4-r6", "artifacts": 12 },
  { "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.5",
    "name": "openssl", "version": "3.0.11-1~deb12u2", "artifacts": 4 } ] }
```
```bash
# 2. exactly which artifacts contain the one you meant
curl -s "${AUTH[@]}" \
  --get --data-urlencode 'purl=pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64&distro=3.19.1' \
  localhost:8080/api/v1/components
```

`q` matches a substring of either the package name or the purl,
case-insensitively, so `q=openssl`, `q=OpenSSL` and `q=pkg:apk/alpine/`
all work — and it returns *distinct packages* (one entry per purl, with
the number of artifacts containing it), most widespread first, capped at
200 with the true total always reported. `purl` stays exact, qualifiers
included: the search is forgiving so a person can find the thing, and
the answer is precise so it can be trusted. If both are supplied, `purl`
wins.

`--get --data-urlencode`, not a hand-built query string: a purl contains
`/`, `@`, and frequently a query string of its own
(`?arch=x86_64&distro=3.19.9`), all of which have to arrive
percent-encoded. That's also why these are query parameters rather than
path segments.

The dashboard's component box (above the artifact table) is exactly this
flow: type `openssl`, press Enter, and you get the matching packages
with their artifact counts; click one and the table narrows to the
artifacts containing precisely that purl, with a link back to the other
matches. Pasting a full `pkg:…` purl skips the picker and goes straight
to the artifacts. The status and type filters grey out while a component
search is active — this endpoint takes no filters — and clearing the box
returns to the normal paginated list.

For fleet-wide aggregates the endpoint deliberately doesn't try to
answer ("what is most widespread", "which packages appear in more than
N artifacts"), query the table directly via `make db-shell`:

```sql
-- the packages that would hurt most to have a CVE published against
SELECT purl, count(DISTINCT artifact_id) AS artifacts
FROM components GROUP BY purl ORDER BY artifacts DESC LIMIT 20;

-- everything one artifact contains
SELECT purl FROM components WHERE artifact_id = '<id>' ORDER BY purl;
```

**Finding the exact purl.** `?q=` above is the answer for this most of
the time. The SQL equivalent, if you're already in `make db-shell`:

```sql
SELECT DISTINCT purl FROM components WHERE name = 'openssl' ORDER BY purl;
```

Some details worth knowing:

- **`purl` is matched exactly, qualifiers included.**
  `pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64` and the same purl
  without `?arch=` are different keys — which is the point: an answer
  that quietly included packages you didn't ask about would be worth
  less than no answer. Use `?q=` (or `q=openssl@3.1` for a
  version-family) when you want the forgiving side; it's the step that
  hands you the exact purl to ask with.
- **Indexing happens on upload.** SBOMs that were already stored before
  this feature existed have no inventory until their next scan re-uploads
  one. To backfill without rescanning anything, replay the documents the
  API already holds — download each stored SBOM and POST it straight
  back, which is idempotent:

  ```bash
  for id in $(curl -s "${AUTH[@]}" 'localhost:8080/api/v1/artifacts?limit=200' \
                | jq -r '.artifacts[] | select(.has_sbom) | .id'); do
    curl -s "${AUTH[@]}" "localhost:8080/api/v1/artifacts/$id/documents/sbom" -o /tmp/sbom.json
    curl -s -o /dev/null -X POST "${AUTH[@]}" -H 'Content-Type: application/vnd.cyclonedx+json' \
      --data-binary @/tmp/sbom.json "localhost:8080/api/v1/artifacts/$id/documents/sbom"
  done
  ```

- **A re-uploaded SBOM replaces the inventory**, exactly as it replaces
  the document itself — so an artifact stops matching a package a
  rebuild removed, rather than matching forever. Upload the complete
  current document, never a delta.
- **A component with no purl is skipped**, since a purl is what this
  query keys on (in practice: the CycloneDX `operating-system` entry).
  A minimal image can legitimately index to zero components — `pause`
  and `busybox` SBOMs list no packages at all, so an empty inventory
  there is the correct answer, not a failure.
- **The artifact an SBOM describes is not a component of itself.**
  CycloneDX keeps it in `metadata.component`, SPDX in `packages[]` with
  `primaryPackagePurpose: CONTAINER` — both are skipped, so searching an
  image's own `pkg:oci/…` purl returns nothing.
- **An SBOM that can't be parsed doesn't fail the upload.** The document
  is stored and downloadable either way; only the inventory is skipped,
  and the reason is logged (`kubectl -n supply-chain-monitor logs
  deployment/monitor-api | grep -i sbom`). A scan worker uploading a
  document treats any non-200 as a scan error, and a component inventory
  is not worth turning a good scan into a failed one.
- **`sbom`-*type artifacts* don't get an inventory** — those are scanned
  from a ref (`trivy sbom`, see above) and never pass through the
  document-upload path. Upload the document itself to index it.
- **Deleting an artifact takes its inventory with it** (`ON DELETE
  CASCADE`), so a deleted image never lingers in a component search.

### Registering `file`/`sbom`/`sarif` artifacts by registry reference

`ref` for `file`, `sbom`, and `sarif` artifacts can now be an OCI
registry reference (to `scm-registry`, same as `image` artifacts) —
`monitor-api` fetches it via `oras pull` before scanning/parsing, so
these three types don't require the artifact to already be sitting on
the pod's filesystem. Push something to scan first (`brew install
oras` if you don't already have it, same as for
`cluster/seed-trivy-db.sh`):

```bash
# push a SARIF file as a single-blob OCI artifact -- scm-registry now
# requires auth (see "Registry authentication" below); scm-writer can
# push, scm-reader can only pull. Credentials are the plaintext
# dev-placeholder values.yaml sets under dockerAuth.accounts.*.
oras push --plain-http -u scm-writer -p changeme-writer localhost:30500/scans/app-sarif:1 results.sarif

# register it -- ref is the registry reference, not a local path
curl -s -X POST localhost:8080/api/v1/artifacts \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"scm-registry.supply-chain-monitor.svc.cluster.local:5000/scans/app-sarif:1","type":"sarif"}'
```

Anything starting with `/`, `.`, or `~` is treated as a filesystem path
rather than a registry reference — and **is refused by default**, see
"Local filesystem paths as refs" below. Anything else is a registry
reference, fetched plain-HTTP (`FETCH_PLAIN_HTTP` in the ConfigMap) and
authenticated with the credentials in `REGISTRY_USERNAME`/
`REGISTRY_PASSWORD` — see "Registry authentication" below.

#### Local filesystem paths as refs

`ref` used to accept any path the `monitor-api` pod could read, and
`file`/`sarif` artifacts are scanned **in-process** (they have no
isolated scan-worker Job), so that path was opened inside the API pod
itself — the one holding `POSTGRES_PASSWORD` and `API_KEY` in its
environment. `ref: "/proc/self/environ"`, the ServiceAccount token, or
`/dev/zero` streamed to clamd until something gave out were all valid
registrations. They are refused now, at registration and again at open
time.

Two environment variables bring the convention back, and both are
required — either one alone is refused rather than guessed at:

| Variable | Meaning |
| --- | --- |
| `ALLOW_LOCAL_ARTIFACT_PATHS` | `true` opts in. Default `false`: every ref is fetched from a registry. |
| `LOCAL_ARTIFACT_ROOT` | Absolute path to the **one** directory such refs may live under. |

A path must be absolute, must stay inside that root after
`filepath.Clean` **and** after symlink resolution (a symlink inside the
root pointing at `/etc/shadow` is refused), and must be a regular file.
`SARIFScanner` and `ClamAVScanner` re-check this themselves before
opening anything, rather than trusting their caller.

Both are chart values — `monitorApi.localArtifacts.enabled` and
`.root` — alongside `monitorApi.extraVolumes`/`extraVolumeMounts`,
which is how you give the pod the directory to read in the first place:

```yaml
monitorApi:
  localArtifacts:
    enabled: "true"
    root: /artifacts
  extraVolumes:
    - name: artifacts
      persistentVolumeClaim:
        claimName: scm-artifacts
  extraVolumeMounts:
    - name: artifacts
      mountPath: /artifacts
      readOnly: true
```

One caveat: a local path is only reachable by a scanner running
**in-process**. That is always the case for `file` and `sarif`, and for
`sbom`/`image` only under `DISABLE_SCAN_ISOLATION` — an isolated
scan-worker Job runs in its own pod with its own filesystem, which is
why registry refs exist. Nothing new in this release; it has always been
true of the path convention.

### Registry authentication

`scm-registry` requires a Bearer token from `scm-docker-auth`
([cesanta/docker_auth](https://github.com/cesanta/docker_auth)) for
every `/v2/` request — the registry used to be fully open (plain HTTP,
no auth at all), so anyone with network access could push. Three static
accounts, one flat role each (not scoped per-repository — this is a
single shared registry):

| account | role | can |
|---|---|---|
| `scm-reader` | read | pull only |
| `scm-writer` | read-write | pull, push |
| `scm-admin` | admin | pull, push, delete — no restrictions |

Credentials are the plaintext dev placeholders `values.yaml`'s
`dockerAuth.accounts.*.password` sets — change before this points at
anything shared. `docker`/`oras` pick up a token automatically once
you've logged in or passed `-u`/`-p`:

```bash
docker login localhost:30500 -u scm-writer -p changeme-writer
# or, per-command, no login needed:
oras push --plain-http -u scm-writer -p changeme-writer localhost:30500/myapp:1 ./myapp.tar
```

`monitor-api` itself only ever pulls (never pushes) — it authenticates
as `scm-reader` via the `REGISTRY_USERNAME`/`REGISTRY_PASSWORD` env vars
(`registry-credentials-secret.yaml`), forwarded into every isolated
scan-worker Job it creates the same way `SCM_API_KEY` already is.

### Image scanning: CVEs and malware, not just one or the other

A container image is a real filesystem underneath, so it can carry
malware the same way a plain file can — Trivy only checks known
package-level CVEs, it doesn't look at file contents. For `image`
artifacts, `/scan` now runs both:

- **Trivy** — CVE scan against package metadata (as before, but now
  isolated the same way ClamAV's malware scan is — see below).
- **[unpacker](https://github.com/Sifungurux/unpacker) + ClamAV** —
  `unpacker` pulls the image and reconstructs its filesystem into a
  plain directory (oras-go/crane + umoci), then every regular file
  under it is streamed to ClamAV over the same INSTREAM protocol used
  for standalone `file` artifacts.

Both scanners' findings land on the same artifact — `cve_findings` from
Trivy, `malware_findings` from ClamAV — told apart by `Finding.source`,
not by artifact type. Relevant env vars (see
`charts/supply-chain-monitor/values.yaml`'s `monitorApi.unpacker.*`
keys, rendered into the ConfigMap by that chart):
`UNPACKER_INSECURE`, `UNPACKER_PUBLIC` (defaults assume our local,
plain-HTTP `scm-registry`), `UNPACKER_MAX_FILE_MB` (skip huge files
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
`charts/supply-chain-monitor/templates/monitor-api/rbac.yaml` and docs/architecture.md ("Isolating the
unpack+scan step") for exactly what that token can and can't do.
One practical effect: each `/scan` on an image now pays for a pod
being scheduled (usually a few seconds, since the image is normally
already cached) on top of the scan itself.

**Trivy's CVE scan for `image` artifacts runs in its own Job too, the
same way.** `IsolatedTrivyScanner` mirrors the unpack+malware-scan
isolation above almost exactly (same `monitor-api scan-worker` binary,
same hardened pod spec), governed by the same
`DISABLE_SCAN_ISOLATION` flag — there's one on/off switch for
isolation, not two. The one real difference: trivy needs its
vulnerability DB to actually scan anything, and downloading that fresh
inside every scan-worker Job would make every scan slow and
network-dependent. Instead, a shared `PersistentVolumeClaim`
(`scm-trivy-db-cache`) holds a copy of the DB that a dedicated primer
Job downloads at install/upgrade time and a daily `CronJob`
(`scm-trivy-db-refresh`, `charts/supply-chain-monitor/values.yaml`'s
`monitorApi.trivyCache.refreshSchedule`, `0 3 * * *` UTC by default)
keeps current — every scan-worker Job mounts this PVC **read-only** and
never tries to update it itself. This is safe to share across many
concurrent scans because trivy opens its vulnerability DB read-only
internally; see docs/architecture.md ("Isolating Trivy scanning") for
the fuller reasoning, including why trivy's *separate* scan-cache
(a different thing from the DB, and NOT safe to share the same way)
is kept in-memory per Job instead (`--cache-backend memory`) rather
than on that same PVC.

**`sbom` artifacts are scanned in an isolated Job too, the same way.**
`IsolatedTrivyScanner` (`SubCommand: "sbom"`) covers this now, governed
by the same `DISABLE_SCAN_ISOLATION` flag as `image` above — no
separate switch. The one thing this Job has to do that `image`'s
doesn't: an `sbom` artifact's ref may be an OCI registry reference
rather than a path already on disk, and a scan-worker Job's pod can't
see whatever monitor-api's own pod might have already fetched, so it
fetches its own copy first (the same `oras pull`-backed fetch
`FetchingScanner` already does in-process). See docs/architecture.md's
"Scanning pipeline" section for the full reasoning.

### Scan scratch space: node disk or a StorageClass

Every scan Job extracts the image it is scanning to `/tmp`, and that
`/tmp` is an `emptyDir` — which means the **node's own disk**. Measured
extractions reach 2395Mi, so a handful of concurrent scans compete for
the same filesystem as the kubelet, the container images and every other
pod on that node. On this project's own cluster that has already gone
wrong once: a load test filled the disk and evicted `monitor-api` itself.

`monitorApi.scanScratch.storageClass` moves that traffic onto storage:

```yaml
monitorApi:
  scanScratch:
    storageClass: "ceph-rbd"   # or "-" for the cluster default
    size: "3Gi"                # per Job; defaults to 3Gi
```

Each Job then gets a **generic ephemeral volume** — a PVC created from
an inline template when the pod starts and deleted with it. That is an
`emptyDir`'s lifecycle (per-pod, nothing shared between concurrent
scans, nothing to clean up) with a StorageClass's capacity behind it.
Empty (the default) keeps today's `emptyDir`, so nothing changes until
you set it.

**`sbom`-mode Jobs opt out automatically.** They fetch a single JSON
document and scan it — that's why they already carry the much smaller
128Mi/256Mi ephemeral sizing — so giving them a PVC would add
provisioning latency and a volume attach to buy storage they never write
to. Image-mode Jobs, which extract gigabytes, take whatever you
configured. The rule lives next to the sizing rationale it mirrors
(`scratchClassFor` in `internal/scanner/isolated.go`), so the two can't
drift into disagreeing about which modes touch disk.

The mechanism behind that is `"none"`, which any Job can use to opt back
into an `emptyDir` even where a StorageClass is configured
process-wide.

So the setting has three non-default values, and they mean three
different things: a class name, `"-"` for the cluster default, and
`"none"` for an explicit `emptyDir`.

Two more things to know:

- **The chart grants extra RBAC only when you set it.** A pod requesting
  a generic ephemeral volume creates a PVC indirectly, so monitor-api
  needs `create`/`delete` on `persistentvolumeclaims`. That rule is
  rendered only when a `storageClass` is configured — an unused
  permission is one worth not having.
- **The class has to be backed by something other than the node.**
  k3s/k3d ship `local-path`, which provisions from
  `/var/lib/rancher/k3s/storage` *on the node* — setting that moves the
  bytes into a PVC without moving them off the disk they were already
  competing for. Verified end to end against `local-path` (PVC created
  per Job, bound, scan ran, PVC deleted with the pod), which proves the
  plumbing but not the relief. For relief, point it at network or
  attached storage.

This applies to every scan Job — trivy, grype, unpacker+ClamAV and
malcontent alike — not just to one scanner.

### A second malware scanner: malcontent (prototype)

ClamAV answers "is this a *known* threat". It cannot answer "does this
image behave like a compromised package" — and that second question is
the one a supply-chain attack actually trips. `monitorApi.malwareScanner`
adds [malcontent](https://github.com/chainguard-dev/malcontent) alongside
it, the same way `cveScanner` adds Grype alongside Trivy:

```yaml
monitorApi:
  malwareScanner: "both"   # "clamav" (default) | "malcontent" | "both"
  malcontent:
    minRisk: "critical"
```

Both land in `malware_findings`, each finding sourced to the tool that
produced it. malcontent matches YARA rules describing *capabilities*, so
a finding reads "runs atypical busybox programs" or "userland rootkit
designed to hide files" rather than a signature name, keyed on the rule
id (`exec/shell/busybox_exec`) so it stays stable across scans.

**Why `minRisk` defaults to `critical`.** Measured, not guessed: a stock
`alpine:3.19` reports **four HIGH behaviours** — busybox exec patterns, a
`/dev/shm` reference, a route lookup. Nothing about that image is
compromised. At `high` most of a normal fleet grows malware findings and
notifications page on them, so the default sits one notch above and you
lower it deliberately.

**The threshold is applied by monitor-api, not by malcontent.** Its
`--min-risk` flag is still passed, but on a live scan it filters nothing
in `scan` mode: `--min-risk critical`, `high` and `any` all returned
byte-identical output for the same image. `scan` is documented as
returning "findings of the highest severity" and means it literally. So
the floor is enforced on the parsed findings (`scanner.FilterBySeverity`)
— which is the difference between a default that reads like a filter and
one that is one.

Two things worth knowing before enabling it:

- **The scan Job runs Chainguard's image, not monitor-api's.** malcontent
  publishes no release binaries, and the binary in its container is
  glibc-linked — copying it into this project's musl/alpine image builds
  fine and then fails with `missing dynamic library`. So the Job runs
  `cgr.dev/chainguard/malcontent` directly, pinned by digest
  (`monitorApi.malcontent.image`). Nodes need to pull that image once.
- **`DISABLE_SCAN_ISOLATION` can't use it** for the same reason — there
  is no `mal` in the API image. monitor-api says so loudly at startup;
  provide one on `PATH` in a derived image if you need that path.

Nothing to mirror or refresh: malcontent embeds its rules, so there is no
DB cache PVC and no refresh CronJob, and the air-gapped story is simpler
than Trivy's or Grype's. Private-registry pulls are not wired up yet —
public images work today; see `IsolatedMalcontentConfig`'s note.

**What a trial actually measured**, one Job per image on a four-node k3d
cluster, before enabling this anywhere:

| image | limit | result |
|---|---|---|
| `alpine:3.19` | 2Gi | 15s · 4 rules · 0 critical |
| `node-exporter:v1.8.1` | 2Gi | 27s · 1 rule · **1 CRITICAL** |
| `python:3.11-slim` | 2Gi | 25s · 16 rules · 34 HIGH |
| `lambda/python:3.12` | 2Gi | **OOMKilled** |
| `rust:1.79` | 2Gi / 4Gi / 6Gi | **OOMKilled** |
| `rust:1.79` | 8Gi | 119s · peak 6351Mi · 28 rules |
| `playwright:v1.44.0-jammy` | 8Gi | **OOMKilled** |

Two things follow, and both are why `malwareScanner` still defaults to
`clamav`:

- **Memory.** A rust-sized image needs ~6.4GiB — over three times the
  2Gi this shipped with, now raised to 8Gi — and the largest image in
  this fleet needs more than 8GiB. One scan is most of a 15GiB node, and
  `SCAN_CONCURRENCY` applies to every scanner equally, so enabling this
  fleet-wide wants a per-scanner concurrency cap that doesn't exist yet.
- **False positives at the default threshold.** A stock
  `node-exporter:v1.8.1` reports CRITICAL `malware/family/mirai` on
  `/bin/getconf`. At `notify`'s default that pages someone. malcontent's
  `--ignore-rules` is the lever for this, unwired here.

What did hold up: runtime is a non-issue when a scan completes (25–120s),
and five consecutive OOMKills had no effect on anything else in the
cluster — no evictions, no disk growth, other workloads untouched. The
Job isolation does exactly what it exists for, which is what made
measuring this against a live cluster safe in the first place.

### Choosing a CVE scanner: Trivy, Grype, or both

Trivy is the default CVE scanner for `image`/`sbom` artifacts, but
[Grype](https://github.com/anchore/grype) is available as a drop-in
alternative or a second opinion, via `monitorApi.cveScanner` (env
`CVE_SCANNER`):

```yaml
monitorApi:
  cveScanner: "trivy"   # default — exactly today's behavior
  # cveScanner: "grype"  # Grype only
  # cveScanner: "both"   # both, findings merged (see below)
```

Grype gets full parity with Trivy, not a stripped-down add-on: it
scans both `image` and `sbom` artifacts, runs in its own isolated
Kubernetes Job the same way Trivy does (`IsolatedGrypeScanner`
mirrors `IsolatedTrivyScanner`), and keeps its vulnerability DB warm
via its own read-only PVC (`scm-grype-db-cache`) with a primer Job at
install/upgrade time and a daily refresh `CronJob`
(`monitorApi.grypeCache.refreshSchedule`, `0 4 * * *` UTC by
default — staggered an hour after Trivy's own 03:00 refresh so they
don't compete for disk/CPU on a small cluster). None of this
Grype-specific infrastructure runs unless `cveScanner` is `"grype"`
or `"both"`.

**`cveScanner: "both"` doesn't duplicate findings.** When Trivy and
Grype both report the same CVE ID for one scan round, they're merged
into a single finding whose `source` lists every tool that found it
(e.g. `"grype, trivy"`, alphabetically sorted) instead of one
silently overwriting the other — see `CoalesceSameIDSources` in
`internal/artifact/merge.go`.

```bash
curl -s -X POST localhost:8080/api/v1/artifacts/<id>/scan -H 'Authorization: Bearer <key>'
curl -s localhost:8080/api/v1/artifacts/<id> -H 'Authorization: Bearer <key>' | \
  jq '.cve_findings[] | {id, source}'
# under cveScanner: both, a CVE both tools found: {"id":"CVE-2024-1234","source":"grype, trivy"}
```

**Registry credentials work differently for Grype than for Trivy —
this is already wired up, but worth knowing if you're debugging a
pull failure.** Trivy takes `TRIVY_USERNAME`/`TRIVY_PASSWORD` env vars
directly; Grype's documented `SYFT_REGISTRY_AUTH_*` env vars looked
like the equivalent but turned out not to work at all (confirmed by
inspecting the actual requests it sends — no `Authorization` header
went out no matter how they were set). Grype instead needs a real
`~/.docker/config.json`-shaped file, pointed at via `DOCKER_CONFIG`;
`main.go`'s `writeDockerConfig` already generates one from
`REGISTRY_USERNAME`/`REGISTRY_PASSWORD` for both the malware-scan
unpacker step and Grype, so no extra setup is needed here — see
docs/architecture.md ("Adding Grype as a second CVE scanner") for the
full story, including why `scm-registry`'s plain-HTTP setup also
needs `GRYPE_REGISTRY_INSECURE_USE_HTTP=true`.

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
malware scanning *and* image CVE scanning both run in-process again
(like every version of this code before isolation shipped), so a bug
in `unpacker`/`umoci`/`oras-go`/`trivy` parsing a malicious image once
again shares this process's blast radius with the API server and its
Postgres connection. Leave it unset
(the default, `false`) for every real deployment —
`charts/supply-chain-monitor/values.yaml`'s
`monitorApi.disableScanIsolation` already does. See
docs/architecture.md ("Running monitor-api outside a Kubernetes pod")
for the full reasoning.

### Pluggable scanners

Trivy, ClamAV, and the built-in SBOM/SARIF scanners aren't the only
option — `monitorApi.pluggableScanners` in
`charts/supply-chain-monitor/values.yaml` lets you register an
arbitrary command as an *additional* scanner for any artifact type,
alongside (not instead of) the built-in ones.

**This is not the same thing as "a scanner running somewhere else."**
A pluggable scanner is a command *monitor-api itself* execs, in this
cluster, every time `/scan` runs — the "external" in its old name
meant "external to this project's Go code," not "external to this
infrastructure." If what you actually want is to record results a
scanner produced somewhere else entirely — a CI pipeline, a different
cluster, a vendor's SaaS scanner — skip this section and use
`POST /api/v1/artifacts/{id}/findings` instead (see "Submitting
findings from an external scanner" above), which takes a JSON body
over HTTP and never runs anything itself.

```yaml
monitorApi:
  pluggableScanners:
    - name: grype
      artifactTypes: ["image"]
      command: grype-to-findings.sh
      args: ["{{ref}}"]
      category: cve
      timeoutSeconds: 300
```

The command is run as `<command> <args...>`, with every arg containing
the literal substring `{{ref}}` replaced by the actual artifact
ref/local path being scanned. It must print a JSON array of findings
on stdout:

```json
[
  {"id": "CVE-2024-1234", "severity": "high", "title": "...", "source": "grype", "category": "cve"}
]
```

`source` and `category` are both optional per finding — a finding that
omits either falls back to that entry's own `name`/`category`. `source`
becomes `Finding.Source`; `category` picks which bucket the finding
lands in (`cve`, `misconfiguration`, `secret`, or `other` — never
`malware`, since this isn't a signature scanner). This is deliberately
the same low-level contract `POST /api/v1/artifacts/{id}/findings`
findings already use, just delivered by running a command instead of
an HTTP call.

**monitor-api never needs to understand your scanner's own output
format** — it understands exactly one JSON shape, and the `command`
you point it at is responsible for producing that shape, however it
gets there. In practice `command` is almost always a small wrapper
script, not the third-party scanner binary directly, since tools like
Grype/OSV-Scanner/Syft don't natively emit this exact schema. A
minimal Grype example (`grype-to-findings.sh`, needs `jq`):

```bash
#!/bin/sh
set -eu
grype "$1" -o json | jq '[.matches[] | {
  id: .vulnerability.id,
  severity: (.vulnerability.severity | ascii_downcase),
  title: .vulnerability.description,
  source: "grype",
  category: "cve"
}]'
```

**The scanner binary itself has to actually be in the image.** This
project's own `Dockerfile` can't bake in every possible third-party
scanner on the chance someone configures one — build a derived image
instead:

```dockerfile
FROM monitor-api:dev
# The base image ends with USER 65534, so any build step that writes
# outside /tmp needs root back for the duration -- and must hand it
# back, or the derived image runs as root in a cluster whose manifests
# all expect 65534. Without this you get "Unable to lock database:
# Permission denied" from apk, or a permission error from COPY targets.
USER root
# curl is installed here because the base image deliberately ships
# without it (it lives in the Dockerfile's `tools` stage only). busybox
# wget is present and looks like it would do, but it fails on GitHub
# release URLs specifically -- those redirect to
# objects.githubusercontent.com, and it gives up with "error getting
# response: Resource temporarily unavailable".
RUN apk add --no-cache curl jq

# Pin the version AND verify a checksum, the way this project's own
# Dockerfile installs its tools. `curl ... | sh` from a project's main
# branch runs whatever that file says on the day you happen to build,
# which is precisely the class of thing a supply-chain scanner exists to
# catch. SCANNER_SHA256 comes from the release's own checksums.txt.
ARG SCANNER_VERSION=1.2.3
ARG SCANNER_SHA256=""
RUN curl -fsSL -o /tmp/scanner.tar.gz \
      "https://example.com/scanner/releases/download/v${SCANNER_VERSION}/scanner_linux_amd64.tar.gz" \
    && echo "${SCANNER_SHA256}  /tmp/scanner.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/scanner.tar.gz -C /usr/local/bin scanner \
    && rm -f /tmp/scanner.tar.gz

COPY grype-to-findings.sh /usr/local/bin/grype-to-findings.sh
RUN chmod +x /usr/local/bin/grype-to-findings.sh
USER 65534:65534
```

...then point `monitorApi.image.repository`/`tag` (and, if scanning
runs isolated in scan-worker Jobs, the same image is used automatically
since `SCAN_WORKER_IMAGE` defaults to it — see `monitorApi.scanWorkerImage`)
at your derived image.

Registration is additive per artifact type — adding a pluggable
scanner against `image` doesn't remove trivy or the malware scan, the
same way `image` already runs both today. `file`/`sbom`/`sarif`
registrations automatically get the same registry-fetch treatment
(`ref` may be an OCI reference, not a local path) the built-in
scanners for those types already get; `image` registrations receive
the raw ref, since an image/CVE scanner is expected to resolve it
itself, same as trivy. See docs/architecture.md ("Pluggable scanners")
for the full design.

### Rate limiting

`monitorApi.rateLimit` in `charts/supply-chain-monitor/values.yaml`
throttles requests per API key, so one misbehaving or compromised
caller can't overwhelm the scan pipeline or database:

```yaml
monitorApi:
  rateLimit:
    requestsPerSecond: 20
    burst: 40
```

`requestsPerSecond: 0` (the default) disables it entirely. `/healthz`
is always exempt, so liveness/readiness probes are never affected.
Since every caller currently shares one `API_KEY` (see "Authentication"
below), this is effectively one global limit rather than per-client
until per-client keys exist — see docs/architecture.md ("Fixed: nothing
throttled request volume per API key").

### Scaling ClamAV

`clamav.autoscaling` in `charts/supply-chain-monitor/values.yaml`
(enabled by default) puts a `HorizontalPodAutoscaler` in front of
`scm-clamav` — it scales the Deployment between `minReplicas` (2) and
`maxReplicas` (10) on CPU utilization (target `70%`), since clamd
scanning is CPU-bound and each pod freshclams its own DB independently
(no shared storage), so adding pods scales cleanly with no other
change needed. A `topologySpreadConstraint` on the Deployment
(`preferred`, not `required`, so it's a no-op on a single-node cluster)
spreads replicas across nodes rather than letting the scheduler stack
them all on one, so scaling up on a multi-node cluster actually buys
you separate nodes' worth of CPU, not just separate pods competing for
the same node.

**This needs a `metrics-server`** (the `metrics.k8s.io` API) in the
target cluster to actually act on — without one the HPA object still
creates fine, it just can't read CPU metrics and never scales. If the
target cluster doesn't have one, or its node pool can't itself grow to
give the HPA somewhere to schedule new pods, set
`clamav.autoscaling.enabled: false` to fall back to a fixed
`clamav.replicas` (default `2`, matching `minReplicas` so turning
autoscaling off holds the count steady rather than jumping) instead —
raise that manually if scans
start queuing behind clamd connections faster than one instance keeps
up.

**Scaling up is bounded by node disk, not just CPU.** Every replica
freshclams its own virus DB into its own writable layer — measured
168Mi steady-state, ~260Mi mid-update — so `clamav.resources` declares
`ephemeral-storage` at `512Mi`, request *and* limit.

That declaration is what keeps autoscaling from evicting itself, and the
mechanism is eviction ranking rather than scheduler placement: under node
`DiskPressure` the kubelet kills pods by how far their disk usage exceeds
their **request**, worst first. Undeclared, ClamAV's whole 168Mi counted
as over-request and it went to the front of that queue — so the first
scale-up to `maxReplicas` evicted most of the new pods *and* some
already-healthy ones, while the actual disk hogs (concurrent scan-worker
Jobs, `2048Mi` limit each) survived. Setting request to cover real peak
keeps these pods under their request and out of the queue; keeping limit
equal to request stops a pod growing back over it.

**Every long-lived component declares `ephemeral-storage` for this
reason**, not just ClamAV — `postgres`, `registry`, `dashboard`,
`docker-auth`, `monitor-api`. Protecting only one component doesn't fix
the problem, it just moves the target: the first run after ClamAV was
given a request evicted **Postgres** instead, and losing the database
took down 99 of 100 scans in that run. A pod with a PVC is not exempt —
eviction ranking looks at the pod's ephemeral usage, not where its real
data lives. If you add a component to this chart, give it an
`ephemeral-storage` request or it becomes the new easiest victim.

**Verify your cluster's disk accounting is real before trusting
`maxReplicas`.** On the local k3d path the four "nodes" are containers
sharing one filesystem, so each reports ~37GiB allocatable
ephemeral-storage while the cluster physically has ~40GiB total — a 4×
overcommit the scheduler cannot see. Autoscaling to 10 replicas is fine
against ClamAV's own footprint (10 × 512Mi = 5GiB), but it shares that
one real disk with every concurrent scan-worker Job, which is what
tipped it into `DiskPressure` under a `PARALLELISM=30` load test. If
ClamAV pods evict or sit `Pending` at high load, the cluster is out of
real room: give the nodes more disk, or lower `maxReplicas` to what it
can actually host.

**Testing this for real, at scale**, needs two things the default local
setup doesn't give you on its own:

1. **A multi-node cluster.** The default runtime, Colima
   (`cluster/create-cluster.sh`), runs k3s inside a single VM — one
   node, no matter how many replicas the HPA asks for. For an actual
   multi-node cluster, use the podman/k3d path with `SCM_K3D_AGENTS` set
   (see `cluster/k3d-config.yaml`):
   ```bash
   SCM_RUNTIME=podman SCM_K3D_AGENTS=3 ./cluster/create-cluster.sh
   ```
2. **Real concurrent scan load.** `cluster/load-test-clamav.sh` (`make
   load-test-clamav`) bulk-registers `testdata/bulk-test-images.json`
   (100 artifacts) and fires `PARALLELISM` (default 10) concurrent
   `POST /scan` requests, reporting success/failure counts and latency
   (min/p50/p95/max). Watch the HPA react while it runs, then again
   once it's done (scale-down lags behind by the HPA's default
   stabilization window):
   ```bash
   make port-forward   # separate terminal
   kubectl -n supply-chain-monitor get hpa scm-clamav -w   # separate terminal
   PARALLELISM=30 ./cluster/load-test-clamav.sh   # heavier concurrency
   ```

### Verbose scan-worker logging

By default, `kubectl logs` on a scan-worker Job's pod (the short-lived
Job each `image`/`sbom` scan runs in — see "Image scanning" above)
shows almost nothing: trivy and unpacker's own progress output is
captured for parsing/error messages but never printed to the pod's own
log stream. That's fine once things are working, but not much help
diagnosing a scan that's slow, silently stuck, or failing in a way the
final error alone doesn't explain.

`monitorApi.scanWorker.verboseLogs` in
`charts/supply-chain-monitor/values.yaml` (default `false`) turns this
on:

```yaml
monitorApi:
  scanWorker:
    verboseLogs: true
```

With it set, every scan-worker Job's pod logs also show trivy's own
scan-step output (it runs with `--debug` instead of `--quiet`) and
unpacker's own pull messages (the `pulling <ref> with oras`,
oras-failed-falling-back-to-crane lines) as they happen, alongside the
final findings/error every scan already reports. Applies to both the
isolated (default) and in-process (`DISABLE_SCAN_ISOLATION=true`) scan
paths.

### Tuning scan timeouts for heavier images

A scan can fail with something like:

```
scan job for "mysql:8.0": timed out waiting for trivy scan job to complete: context deadline exceeded
```

even though nothing is actually stuck -- it's a budget problem, not a
hang. Two timeouts are involved: how long Kubernetes lets each
scan-worker Job's pod run (`monitorApi.scanWorker.activeDeadlineSeconds`,
default 600s), and how long the API handler itself waits for one to
finish before giving up on the whole scan
(`monitorApi.scanTimeoutSeconds`, default 660s, deliberately 60s above
the first). Both are sized for alpine/busybox-sized images; a heavier
one (more OS packages for trivy to walk/query -- `mysql`, `postgres`, and
similar images are common examples) plus real scheduling delay and CPU
contention from several scans running concurrently (see "Scaling
ClamAV"/`make load-test-clamav` above) can push actual runtime past
that. Raise both together, keeping `scanTimeoutSeconds` above
`activeDeadlineSeconds`:

```yaml
monitorApi:
  scanWorker:
    activeDeadlineSeconds: 900
  scanTimeoutSeconds: 960
```

`runAPIServer` refuses to start if `scanTimeoutSeconds` isn't strictly
greater than `scanWorker.activeDeadlineSeconds` -- that ordering is what
keeps this handler from ever giving up on a scan before Kubernetes' own
deadline would have killed a genuinely stuck Job, so a config that gets
it backwards is rejected at startup instead of surfacing later as
confusing, intermittent timeouts under load.

### Debugging a specific scan-worker Job

Every scan-worker Job prints a start line naming which tool it's
running (`trivy`, `grype`, or `unpacker + clamav`) and a completion
line with the finding count or error, regardless of `verboseLogs` — so
`kubectl logs` on a `scm-scan-*` pod always shows *something* while a
scan is in flight, not just silence until a final JSON result line.
The malware path (`unpacker + clamav`) also logs the handoff between
its two tools: "image unpacked, scanning files with clamav" once
`unpacker` finishes pulling the image, then a scanned/failed/finding
count once ClamAV's done. `verboseLogs` is a separate, much noisier
knob on top of this — it tees the underlying CLI tool's own
step-by-step output (trivy's own progress lines, unpacker's oras/crane
pull attempts) into the same log stream, for the rarer case where the
tool-level summary above isn't enough to tell what's actually stuck.

Scan-worker Job pods are deleted right after each scan finishes (see
`docs/architecture.md`, "Isolating the unpack+scan step"), so to
actually watch one's logs live, trigger a scan and immediately tail
Jobs in the namespace:

```bash
kubectl get jobs -n supply-chain-monitor -w
# once a scm-scan-* Job appears:
kubectl logs -n supply-chain-monitor -l job-name=<job-name> -f
```

## Database

Artifacts, findings, and stage history are stored in Postgres
(`percona/percona-distribution-postgresql`, deployed as `scm-postgres`
in-cluster) instead of in-memory, so a `monitor-api` pod restart no
longer loses everything registered so far. `monitor-api` connects
using `POSTGRES_HOST`/`PORT`/`USER`/`DB`/`SSLMODE` (rendered from
`charts/supply-chain-monitor/values.yaml`'s `monitorApi.postgres.*`
keys) plus `POSTGRES_PASSWORD` from the `scm-postgres-credentials`
Secret (from `charts/supply-chain-monitor/values.yaml`'s
`postgres.credentials.password`) — see "Bringing your own secrets"
above before this cluster is anything but local and throwaway.
`POSTGRES_DSN` is also accepted as a full connection string override
if you'd rather set one directly.

```bash
make db-shell   # opens a psql shell in the scm-postgres pod
```

Connection pool size is set via `monitorApi.postgres.pool.maxConns`/
`.minConns` in values.yaml (defaults `10`/`2`) rather than left at
pgxpool's own CPU-count-derived default, which has no relationship to
Postgres's own `max_connections` limit. Raise `maxConns` if this chart
is ever scaled to more than one `monitor-api` replica.

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
`charts/supply-chain-monitor/templates/postgres/backup-cronjob.yaml`. Retention keeps the
newest 7 backups by default (`postgres.backup.keepBackups` in
`charts/supply-chain-monitor/values.yaml`).

The backups PVC binds via a small pre-install Helm hook
(`backup-pvc-primer-job.yaml`) rather than waiting for its first real
consumer — needed because that consumer is the daily CronJob, and on
most single-node dev clusters' default StorageClass, a PVC only binds
once some pod is actually scheduled against it. Without this, the
first `helm upgrade`/`flux reconcile` for postgres would time out with
`PersistentVolumeClaim/.../scm-postgres-backups status: 'InProgress'`
— see docs/architecture.md ("Why scm-postgres-backups needed a
pre-install hook") if you hit that.

**If `scm-postgres-backups` shows up stuck in `Terminating` after a
`make deploy`:** this was a real bug (fixed in `pvc.yaml` — see
docs/architecture.md, "Fixed: `scm-postgres-backups` was getting
deleted and recreated on every single `make deploy`") where the PVC
had no explicit `helm.sh/hook-delete-policy`, so it silently inherited
Helm's destructive `before-hook-creation` default and got
deleted-then-recreated on every upgrade — losing every backup on it,
and hanging in `Terminating` if a pod (a recent backup CronJob run, or
the primer Job) was still mounting it at that exact moment. **The live
database itself (`scm-postgres-data`) is never touched by this — only
the separate backup-copy PVC is at risk.** If you're on a chart version
from before the fix, or you're currently looking at a stuck PVC:

```bash
# 1. Find whatever pod is still mounting it -- that's what's holding
#    the kubernetes.io/pvc-protection finalizer open.
kubectl get pods -n supply-chain-monitor -o json \
  | jq -r '.items[] | select(.spec.volumes[]?.persistentVolumeClaim.claimName=="scm-postgres-backups") | .metadata.name'

# 2. Delete that pod (a completed backup-CronJob pod or the primer
#    Job's pod, almost always) so the finalizer can clear.
kubectl delete pod -n supply-chain-monitor <pod-name>

# 3. Before the PVC actually finishes disappearing, if you want a
#    chance at recovering whatever backups were on it: find its
#    PersistentVolume and flip its reclaim policy to Retain. Once the
#    PVC (and then the PV) are gone with the default Delete policy, the
#    underlying storage -- and the backup files on it -- are gone too;
#    Retain keeps the PV (and its data) around in a Released state
#    instead, for manual recovery later.
PV=$(kubectl get pvc scm-postgres-backups -n supply-chain-monitor -o jsonpath='{.spec.volumeName}')
kubectl patch pv "$PV" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'
```

Then pull the chart fix (`pvc.yaml`'s explicit `hook-delete-policy`) and
redeploy — the next upgrade creates a fresh `scm-postgres-backups` PVC
and leaves it alone from then on.

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

Then set `monitorApi.trivyDB.enabled: true` and fill in
`monitorApi.trivyDB.repository`/`monitorApi.trivyDB.javaRepository` in
`charts/supply-chain-monitor/values.yaml` (the script prints the values
to use) and redeploy:

```bash
make deploy
```

From then on `monitor-api` points trivy at the mirrored DBs in
`scm-registry` instead of `ghcr.io`, and skips even trying the public
default (`TRIVY_SKIP_DB_UPDATE`/`TRIVY_SKIP_JAVA_DB_UPDATE`). Leave the
four lines commented out (the default) for a normal, internet-connected
setup — trivy's own defaults are used and nothing changes.

One wrinkle since image-type CVE scans moved into their own Job (see
"Trivy's CVE scan for `image` artifacts runs in its own Job too"
above): a scan-worker Job never fetches or updates the DB itself
anymore, only `scm-trivy-db-cache-primer`/`scm-trivy-db-refresh` do, on
your behalf, into the shared `scm-trivy-db-cache` PVC. So in an
air-gapped cluster, it's specifically *those* two — not each individual
scan — that need to reach `monitorApi.trivyDB.repository`/
`javaRepository` (`scm-registry` by default); `monitorApi.trivyDB.*`
still configures where they pull from either way, this just moves
*which* thing in the cluster actually does the pulling.

## Testing

```bash
make test            # both suites below
make test-api         # services/monitor-api's Go tests (httptest, no cluster needed)
make test-dashboard   # dashboard/index.html's Node+jsdom tests
make test-postgres    # real Postgres round-trip against a throwaway container (not part of `make test`)
```

These run in containers (`golang:1.26-alpine`, `node:22-alpine`,
`percona/percona-distribution-postgresql`) so there's nothing extra to
install beyond Docker, which you already have via Colima or Podman. No
CI workflow is wired up yet -- these `make`
targets (plus `make check-dashboard-configmap`, which checks that
`charts/supply-chain-monitor/files/index.html` actually matches `dashboard/index.html`
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

The whole application — registry, clamav, postgres, monitor-api,
dashboard, plus the Gateway API resources routing to the dashboard —
deploys as **one Helm chart** via [Flux](https://fluxcd.io), not
`kubectl apply -k` against raw manifests, and not 5 separate per-service
charts either (an earlier iteration of this project's design — see
docs/architecture.md, "A single chart for the whole application", for
why it was consolidated). See `docs/architecture.md` for the full
picture; the short version:

- `charts/supply-chain-monitor/` — one real Helm chart for the entire
  application (`Chart.yaml`, one `values.yaml` namespaced per service,
  `templates/{registry,clamav,postgres,monitor-api,dashboard,gateway}/`).
  A completely normal Helm chart — `helm install supply-chain-monitor
  ./charts/supply-chain-monitor` works standalone too, with or without
  Flux.
- `k8s/releases/supply-chain-monitor-helmrelease.yaml` — the one Flux
  `HelmRelease` for that chart, sourcing it from this same repo, with
  `chart.spec.reconcileStrategy: Revision` set explicitly — **this
  matters**. Left at Flux's default (`ChartVersion`), a chart sourced
  from a `GitRepository` (ours) only gets rebuilt when
  `Chart.yaml`'s `version:` field itself changes, which is very easy to
  forget on routine template edits. Confirmed this the hard way: chart
  changes sat committed and pushed, `make deploy` reported success
  every time, `flux get helmreleases -A` showed `Ready: True`, and yet
  the actual release never moved past its very first install (`.v1`)
  — see docs/architecture.md, "Fixed: chart template changes never
  actually reaching the cluster." `Revision` makes any new commit
  enough on its own to trigger a real rebuild+upgrade, matching what
  this repo's whole "every push deploys" workflow already assumes is
  happening.
  No `dependsOn` needed between the former 5 services anymore — they're
  one Helm release now, so Helm's own resource-kind apply ordering
  (Secrets/ConfigMaps/PVCs before Deployments/Jobs/CronJobs) covers what
  `dependsOn` used to guarantee between separate `HelmRelease`s (e.g.
  the dashboard's `render-config` initContainer reading monitor-api's
  auth Secret still works, since Secrets apply before any Deployment).
  `monitor-api`'s own `connectStoreWithRetry` remains the
  belt-and-suspenders layer for Postgres specifically.
- `k8s/releases/traefik-helmrelease.yaml` — a second, separate
  `HelmRelease` for Traefik (the ingress controller), sourced from an
  upstream `HelmRepository` rather than this repo's own charts/ — it's
  third-party infrastructure, not part of the application, so it stays
  its own release. See "Ingress: Traefik + Gateway API" below.
- `k8s/flux-system/gotk-sync.yaml` — the `GitRepository` (pointing at
  `https://github.com/sifungurux/supply-chain-monitor.git`, branch
  `main`) and the root `Kustomization` (`path: ./k8s` — the whole tree,
  self-referencing).
- `k8s/kustomization.yaml` — the plain kustomize file Flux actually
  builds at that path: the namespaces, the `flux-system` self-reference,
  and the two `HelmRelease`s above.

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
should show `flux-system` and both releases (`supply-chain-monitor` and
`traefik`) `Ready` — confirmed on a real podman/k3d cluster (see the
note under Quickstart). If `kubectl -n supply-chain-monitor get pods`,
`flux get helmreleases -A`, or `make test-artifact` ever show anything
`NotReady`, `CrashLoopBackOff`, or failed on a fresh install, that's a
real regression worth reporting, not an expected first-run rough edge.

### Ingress: Traefik + Gateway API

The dashboard is also reachable through an ingress path now — Traefik,
configured for the Kubernetes **Gateway API** specifically (not classic
`Ingress`, not Traefik's own `IngressRoute` CRDs — both disabled). Its
direct NodePort (`30301`) still works unchanged; this is an additional
path in.

Same per-runtime address split as every other NodePort in this project
(see Quickstart):

- **colima**: `http://<vm-address>:30080` — the VM address `create-cluster.sh`
  prints (`--network-address` gives the VM its own routable IP; `localhost`
  does *not* reach it, since colima doesn't forward NodePorts to the host's
  loopback the way k3d's port mapping does).
- **podman/k3d**: `http://localhost:30080` — forwarded via the `30080:30080`
  mapping in `cluster/k3d-config.yaml`.

Both runtimes already disable k3s's *bundled* Traefik
(`--k3s-arg="--disable=traefik"` / `--disable=traefik`) — this project
installs its own version-pinned Traefik instead via a Flux `HelmRelease`
(`k8s/releases/traefik-helmrelease.yaml`, chart from the upstream
`https://traefik.github.io/charts` repo), same reproducibility reasoning
as pinning Flux's own chart version. The Gateway API CRDs themselves are
installed by `cluster/install-gateway-api.sh`, automatically at the end
of `make cluster-up` (`SCM_SKIP_GATEWAY_API=1` to skip, `make
gateway-api-install` to run standalone) — Traefik's chart doesn't
install these for you, same shape of problem Flux's own CRDs have. See
`docs/architecture.md`'s "Ingress: Traefik + Gateway API" for the full
design, including the exact `GatewayClass`/`Gateway`/`HTTPRoute` wiring
and the version pins used (checked against the real upstream sources at
write time, not assumed). No TLS/HTTPS yet — see Known limitations.

## Tearing down

```bash
make undeploy
make cluster-down       # stops the VM/machine, keeps it around for next time
make cluster-destroy    # stops AND deletes the VM/machine + its data
```

## Known limitations

See `docs/architecture.md`'s "Known limitations" for the
actively-maintained list of what's genuinely still open today (single
shared API key with no rotation window, plaintext default secrets in
`values.yaml`, no TLS on the Gateway, no `NetworkPolicy` on scan-worker
pods, coarser fix-detection for SARIF/pluggable scanners, the untested
`modelscan` prototype) — kept in one place rather than duplicated here,
where a previous version of this list drifted out of sync with reality
(see `docs/tech-debt-audit.md`, #11).

A few more specific to running this repo day to day, not covered there:

- `file`/`sbom`/`sarif` artifacts can only be fetched from
  `scm-registry` (via `oras pull`), or from a mounted directory an
  operator has explicitly opted into (see "Local filesystem paths as
  refs") — no S3/HTTPS fetcher yet. `Fetcher` is an interface
  specifically so another source is a small addition later, not a
  rewrite.
- SARIF severity falls back to a rough three-level mapping
  (error/warning/note → high/medium/low) unless a rule carries a
  `security-severity` score, which not every SARIF producer sets.
- CVE scanning shells out to the `trivy`/`grype` CLI per scan rather
  than talking to a shared server process — fine at today's scan
  volume.
- Both registry-fetching paths (`UnpackerScanner`, the file/sbom/sarif
  `Fetcher`) hardcode unauthenticated, plain-HTTP access — fine for the
  local `scm-registry`; a private or authenticated registry isn't
  wired up on either path yet (would need mounting a
  `dockerconfig.json`/credentials secret and passing the right flags
  to both).
- `monitor-api` needs a real Kubernetes ServiceAccount token to start
  by default, since it creates scan-worker Jobs on the hot path — set
  `DISABLE_SCAN_ISOLATION=true` to run it via a bare `docker run`
  outside a cluster instead (see "Running monitor-api outside a
  Kubernetes pod"), at the cost of moving image scanning back
  in-process.
- The dashboard's auto-configured key/address (see "Auto-configured
  API address/key" above) is rendered with `sed`-based string escaping
  in a shell script, not a real templating engine — fine for a flat
  key and a plain URL, would need revisiting if that config ever grows
  more complex.
