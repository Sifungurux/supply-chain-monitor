# Supply Chain Monitor

[![CI](https://github.com/Sifungurux/supply-chain-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Sifungurux/supply-chain-monitor/actions/workflows/ci.yml)

[![CVE: Trivy + Grype](https://img.shields.io/badge/CVE-Trivy%20%2B%20Grype-2f6feb?style=flat-square)](docs/operations.md#choosing-a-cve-scanner-trivy-grype-or-both)
[![Malware: ClamAV + malcontent](https://img.shields.io/badge/Malware-ClamAV%20%2B%20malcontent-c2410c?style=flat-square)](docs/operations.md#image-scanning-cves-and-malware-not-just-one-or-the-other)
[![Triage: KEV + EPSS](https://img.shields.io/badge/Triage-KEV%20%2B%20EPSS-7c3aed?style=flat-square)](docs/operations.md#which-cves-are-actually-being-exploited)
[![VEX: OpenVEX](https://img.shields.io/badge/VEX-OpenVEX-0f766e?style=flat-square)](docs/operations.md#suppressing-findings-with-vex)
[![Policy gate: pass / fail](https://img.shields.io/badge/Policy%20gate-pass%20%2F%20fail-15803d?style=flat-square)](docs/operations.md#gating-a-pipeline-on-policy)
[![Provenance: cosign + SLSA](https://img.shields.io/badge/Provenance-cosign%20%2B%20SLSA-334155?style=flat-square)](docs/operations.md#provenance-was-this-image-signed-and-by-whom)

**Know what is in every image you ship, what is wrong with it, whether it
came from you — and keep knowing after the day you built it.**

Supply Chain Monitor is a self-hosted service that tracks the artifacts your
pipeline produces (container images, files, SBOMs, SARIF reports), scans them
for vulnerabilities and malware, records where each one is in your pipeline,
and answers one question your CI job cannot: *is this still true today?*

> ### ⚠️ Rotate every credential before any real deployment
>
> This repository and its git history are public, and two placeholder
> credentials were committed until `aebf6fe` (2026-08-09):
> `POSTGRES_PASSWORD: changeme123` and
> `monitorApi.apiKey: qwe4r56789009876543223456789`. Both are permanently
> readable by anyone who clones this repo — grep your own cluster for them.
> Both now ship **empty** and the
> chart fails closed — but a database initialised before that date still
> has the old password, because Postgres only reads `POSTGRES_PASSWORD` on
> first init. Rotating it needs the `ALTER ROLE` step in
> [`cluster/chart-secrets.sh`](cluster/chart-secrets.sh), not just a new
> Secret. Details: [docs/operations.md § Bringing your own
> secrets](docs/operations.md#bringing-your-own-secrets).

---

## The problem

A CI scan is a photograph. It tells you an image was clean at 14:03 on a
Tuesday, and then it is thrown away.

But CVEs are published after your build, not before it. The image you shipped
last month is still running, and nothing rescans it. Severity scores tell you
how bad exploitation *would* be, not whether anyone is doing it, so your
"critical" list is thousands of rows long and nobody reads it. Your scanner
tells you a package is vulnerable but not whether your code even reaches it.
And nothing at all tells you a dependency showed up in the build that nobody
added.

This service is the thing that keeps looking after CI has moved on.

## What it does

| | |
|---|---|
| **Finds what's wrong** | Trivy **and** Grype for CVEs (findings merged, not duplicated), ClamAV for malware, [malcontent](https://github.com/chainguard-dev/malcontent) for suspicious binary behaviour, Trivy's secret scanner, license policy |
| **Tells you what matters** | CISA **KEV** (exploitation observed) and **EPSS** (predicted, daily) on every CVE, so a medium under active attack outranks a critical nobody has touched |
| **Lets you say "not affected"** | **VEX** documents suppress findings with a reason, fleet-wide or per artifact, plus time-boxed risk acceptance that expires instead of being forgotten |
| **Proves where it came from** | **cosign** signature and **SLSA** provenance verification against your own identity — the one question a CVE scanner cannot ask |
| **Watches the inventory** | SBOM per artifact, component search across the fleet, and a diff that alerts when a package appears that nobody added |
| **Keeps it true over time** | A sweep rescans continuously, vulnerability DBs refresh nightly, and SBOMs are re-evaluated against fresh data without re-pulling every image |
| **Gates your pipeline** | One `GET .../policy` call returns pass/fail with the violated rules named — call it from CI, or from Kyverno/Gatekeeper at admission |
| **Answers fleet questions** | "Which images still ship this CVE?" · "Which contain this package?" · "What changed between these two builds?" |

Everything is behind a plain JSON API with an OpenAPI spec and a Swagger UI,
plus a small dashboard. Scans run in isolated, unprivileged Kubernetes Jobs —
the code that parses untrusted image content never runs in the API pod.

## How it works

```
  register ──▶ stage ──▶ scan ──▶ findings ──▶ policy verdict
     │                     │                        │
   digest is           trivy/grype + unpacker    pass / fail, with
   resolved and        + clamav, each in its      the violated rules
   pinned here         own isolated Job           named
```

Four things shape every integration:

- **Identity is the digest, not the tag.** Two registrations of the same bytes
  under different tags are one artifact — which is what makes "which images
  still ship this CVE" answerable at all.
- **Scanning is asynchronous.** `POST /scan` returns `202`. A pipeline that
  reads findings immediately reads an empty set, which looks exactly like a
  clean image.
- **Findings have a lifecycle.** open → fixed → open again, each with a
  `first_seen_at`. A rescan reporting the same CVE is not news and does not
  notify.
- **A scan that fails is not a scan that passed.** Failures are recorded per
  artifact and block fix-detection for the buckets they cover, so a broken
  scanner can never quietly mark everything resolved.

Full design and rationale: [docs/architecture.md](docs/architecture.md).

## Deploy it

### Locally, from scratch

Needs [Colima](https://github.com/abiosoft/colima) (recommended) or
Podman + [k3d](https://k3d.io), plus `kubectl` and Docker.

```bash
make cluster-up        # starts the VM + k3s, installs Flux and the Gateway API CRDs
make chart-secrets     # generates the Postgres password, API keys and registry accounts
make deploy            # builds the image, pushes to git, lets Flux reconcile
kubectl -n supply-chain-monitor get pods -w
```

`make chart-secrets` is not optional — Postgres and monitor-api both refuse to
start without it rather than coming up with an empty password.

Give it a few minutes on first boot: ClamAV downloads its virus definitions,
and monitor-api retries Postgres for up to ~60s while both start at once.

```bash
make port-forward      # one terminal
make test-artifact     # another — registers alpine:3.19 and scans it
```

The dashboard is on NodePort `30301`, the API on `30300`. On Colima
`create-cluster.sh` prints the VM address; on podman/k3d it is `localhost`.

### On a cluster you already have

It is an ordinary Helm chart — Flux is how *this* repo deploys it, not a
requirement:

```bash
helm install supply-chain-monitor ./charts/supply-chain-monitor \
  --namespace supply-chain-monitor --create-namespace \
  -f my-values.yaml
```

You need a `StorageClass` (Postgres, the registry, and the scanner DB caches
all want PVCs), and cert-manager if you want the TLS the chart can issue. For
the GitOps path, see [docs/operations.md § GitOps
(Flux)](docs/operations.md#gitops-flux).

Tear down with `make undeploy`, `make cluster-down`, or `make cluster-destroy`.

## Configure it

**The chart exposes ~200 values; these ~30 need a decision.** The rest are
sized already and safe to leave alone —
`helm show values ./charts/supply-chain-monitor` lists every one of them with
the reasoning for its default inline.

### 1. Set these before first boot

| Value | Default | Recommended | Why |
|---|---|---|---|
| `postgres.credentials.password` | `""` | from `make chart-secrets` | Empty by design; Postgres refuses to init without it |
| `monitorApi.apiKey` | `""` | from `make chart-secrets` | The master key. Every route but `/healthz` needs a key |
| `monitorApi.apiKeys` | `""` | one named key per consumer | Named keys are attributable in the audit log and revocable one at a time |
| `dockerAuth.accounts.*.password` | `""` | from `make chart-secrets` | Three registry accounts: reader (scan Jobs), writer (mirroring), admin |
| `monitorApi.image.repository` / `.digest` | `monitor-api:dev` | your registry, pinned by digest | A floating tag means a node keeps whatever it has, forever |

### 2. Turn these on — they ship off, and a real deployment wants them

| Value | Default | Recommended | Why |
|---|---|---|---|
| `monitorApi.apiKeyScopes` | `""` (unenforced) | `dashboard=read\|scan;sweep=read\|scan` | Without scopes every in-cluster consumer holds full authority. Dashboard reach == dashboard key |
| `monitorApi.tls.enabled` | `false` | `true` | In-cluster TLS for the API, including the scan-worker's document upload |
| `monitorApi.requireDigest` | `false` | `true` for pipelines you control | Makes an unverifiable ref land as `unsafe: true` instead of silently trusted |
| `monitorApi.cosign.enabled` | `false` | `true`, **scoped** | Needs `certIdentityRegexp` + `certOIDCIssuer` or it refuses to start. Note: unsigned is a `high` finding, so enabling it against a fleet of upstream images lights up every one of them |
| `monitorApi.sweepSbom.enabled` | `false` | `true` | Re-derives CVEs from stored SBOMs nightly — a CVE published today surfaces fleet-wide tomorrow, at a fraction of the IO of a full rescan |
| `monitorApi.rateLimit.requestsPerSecond` / `.burst` | `0` (off) / `20` | `20` / `50` | Off means one client can saturate the API |
| `postgres.backup.encryption.publicKeySecret` | `""` | a Secret you hold the private half of | Backups are written unencrypted otherwise |
| `monitorApi.retention.enabled` | `false` | `true` with `days: 90` | Nothing ages out on its own |
| `monitorApi.prometheusRule.enabled` / `serviceMonitor.enabled` | `false` | `true` if you run Prometheus | Ships real alert rules, including "backups have gone stale" |

`monitorApi.enrichment.enabled` (KEV/EPSS) and `monitorApi.sweep.enabled`
are **on** by default. Leave them on — without the sweep nothing is ever
rescanned, and without enrichment every finding has `epss_score: 0` and no
triage signal.

### 3. Capacity — the numbers that came from measurement

Defaults are sized for a small single-node cluster. The right-hand column is
what this project runs on its own fleet (~97 images), and every number has a
report behind it in `docs/`.

| Value | Default | Fleet | Why |
|---|---|---|---|
| `monitorApi.scanConcurrency` | `8` | `12` | Cluster-wide scan slot budget, shared across API replicas |
| `monitorApi.sweep.schedule` / `.batchSize` / `.concurrency` | `*/15` / `5` / `1` | `*/5` / `10` / `4` | How fast the fleet is re-covered. **Raise this last** — 4 sweep slots fan out to ~10 scan pods, and that is what exhausts a small node, not the cap itself |
| `monitorApi.mirrorArtifacts.enabled` | `false` | `true` | Mirrors every scanned artifact into the local registry, so a deleted upstream tag stays scannable. Costs real disk: mirroring copies **all platforms**, ~5.3 per image |
| `registry.persistence.size` | `150Gi` | `150Gi`+ | Only meaningful with mirroring on. 97 images cost ~80GB |
| `registry.resources.limits.memory` | `2Gi` | `2Gi` | **Do not lower.** At 512Mi the registry OOMs under a mirrored fleet before disk or node memory binds — [docs/scan-concurrency-2026-08-24.md](docs/scan-concurrency-2026-08-24.md) |
| `monitorApi.scanJobResources.perKind.grype.memoryLimit` | `1536Mi` | `1536Mi` | **Do not lower.** Grype peaks at ~1.04GiB on heavy images; at 1Gi it is OOM-killed and the artifact still reports "scanned" with half its CVE coverage |
| `monitorApi.maxArtifacts` | `0` (unlimited) | `500` | A registration limit is a capacity guardrail, not a licence check |
| `clamav.autoscaling.maxReplicas` | `16` | `16` | ClamAV is the first thing to saturate under a burst; `make load-test-clamav` measures it |

### 4. Scanner choice

| Value | Default | Notes |
|---|---|---|
| `monitorApi.cveScanner` | `both` | `trivy`, `grype`, or `both`. Under `both`, a CVE found by both tools merges into one finding with `source: "grype, trivy"` |
| `monitorApi.grypeDB.byCVE` | `false` | Recommended `true`. Grype otherwise names findings after the advisory (`GHSA-`, `GO-`, `ELSA-`), which never dedupes against Trivy's CVE ids, never matches a VEX statement, and never carries KEV/EPSS |
| `monitorApi.malwareScanner` | `clamav` | `malcontent` adds behavioural analysis; its `minRisk` defaults to `critical` because a stock `alpine` reports four HIGHs |
| `monitorApi.pluggableScanners` | `[]` | Shell out to any tool that emits a JSON findings array — OSV-Scanner, your own. No Go changes |

Full per-value reference with the reasoning behind each default:
[`charts/supply-chain-monitor/values.yaml`](charts/supply-chain-monitor/values.yaml)
and [docs/operations.md](docs/operations.md).

## Use it

```bash
AUTH=(-H "Authorization: Bearer $SCM_API_KEY")

# register something your pipeline just built
curl -s "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"ref":"ghcr.io/acme/checkout:2.4.1","type":"image"}' \
  localhost:8080/api/v1/artifacts

# scan it (202 — it runs in a Job)
curl -s -X POST "${AUTH[@]}" localhost:8080/api/v1/artifacts/$ID/scan

# ask whether it may ship
curl -s "${AUTH[@]}" localhost:8080/api/v1/artifacts/$ID/policy
# => {"pass":false,"configured":true,
#     "violations":[{"rule":"maxSeverity","detail":"...","finding_id":"CVE-2024-1234"}]}

# which images still ship this CVE?
curl -s "${AUTH[@]}" "localhost:8080/api/v1/findings/CVE-2024-1234/artifacts"
```

Swagger UI is at `/swagger`, the spec at `/openapi.yaml`.

**[docs/user-guide.md](docs/user-guide.md) is the place to start** — it is
task-oriented ("turn this into a gate", "living with findings", Tekton
integration) and every example in it was run against a live cluster.

## Contributing

```bash
git checkout -b feat/my-change     # never commit to main directly
# ... edit ...
make test                          # everything CI runs, locally
git push -u origin feat/my-change  # then open a PR against main
```

CI runs on every PR targeting `main` and on every push to it. Dependencies
are kept current by Dependabot ([`.github/dependabot.yml`](.github/dependabot.yml)).

`make test` needs Docker and nothing else — no local Go, no local Node. It
runs the Go suite (with `gofmt` and `go vet` enforced), the dashboard's
jsdom tests, and the chart/manifest/OpenAPI checks. CI runs the same `make`
targets on every PR, so "passes locally" and "passes in CI" mean the same
thing.

Targets worth knowing:

| Command | What it covers |
|---|---|
| `make test-api` | Go tests, `gofmt`, `go vet` (MemStore only — no database needed) |
| `make test-postgres` | The real Postgres store, against a throwaway container |
| `make test-swagger-docs` | Boots a real API and runs the documented `curl` examples against it |
| `make test-dashboard` | `dashboard/index.html`, Node + jsdom |
| `make helm-lint` / `helm-template` | The chart renders and lints |
| `make check-openapi-spec` | Every route is described and every `$ref` resolves |

Conventions the code holds itself to, and reviews will ask about:

- **Explain the non-obvious in a comment**, especially where the simple thing
  is wrong. This codebase is unusually heavily commented on purpose — the
  comments carry the reasoning that would otherwise be re-derived (or
  re-broken) by the next person.
- **A bugfix fixes the root cause**, not the one caller in the report.
- **New logic leaves a runnable check behind.** If you cannot write a test that
  fails without your change, say so in the PR.
- **Editing `dashboard/index.html`?** Copy it to
  `charts/supply-chain-monitor/files/index.html` — Helm cannot read outside
  the chart directory, so it is a real second copy. `make
  check-dashboard-configmap` catches the drift.

## Where things live

```
charts/supply-chain-monitor/   the whole application as one Helm chart
cluster/                       cluster create/destroy, secrets, backup/restore scripts
dashboard/                     the dashboard (source of truth)
docs/                          see below
k8s/                           what Flux reconciles: namespaces + two HelmReleases
services/monitor-api/          the Go service and its tests
```

| Document | What it is |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Task-oriented: wiring it into a pipeline. **Start here.** |
| [docs/operations.md](docs/operations.md) | The full manual — every feature, flag and failure mode, with the reasoning |
| [docs/architecture.md](docs/architecture.md) | Design, data model, and known limitations |
| [docs/tech-debt-audit.md](docs/tech-debt-audit.md) | What is knowingly unfinished, scored |
| [docs/load-test-2026-08-13.md](docs/load-test-2026-08-13.md), `docs/scan-concurrency-*.md` | The measurements behind the capacity numbers above |
