# Supply Chain Monitor — user guide

This guide is task-oriented: what each feature is *for*, and how to wire it into a pipeline. For per-feature configuration reference — every chart value, every flag — see [README.md](../README.md) and [docs/architecture.md](architecture.md). This guide links into those rather than restating them.

**Every example below was run.** Against the live development cluster, on 2026-08-21, at commit `fbf4918`. Outputs are pasted from the run, not composed. Where something could not be executed here, it says so inline — and says why.

---

## Contents

1. [The mental model](#1-the-mental-model)
2. [Before you start](#2-before-you-start)
3. [The core loop: register, stage, scan, read](#3-the-core-loop)
4. [Turning it into a gate](#4-turning-it-into-a-gate)
5. [Living with findings](#5-living-with-findings)
6. [Fleet questions](#6-fleet-questions)
7. [Tekton integration](#7-tekton-integration)
8. [Chart configuration: turning features on and off](#8-chart-configuration)
9. [Connecting your own registries](#9-connecting-your-own-registries)
10. [When a result looks too clean](#10-when-a-result-looks-too-clean)
11. [Endpoint reference](#11-endpoint-reference)

---

## 1. The mental model

An **artifact** is a thing your pipeline produced: a container image, a file, an SBOM, or a SARIF report. You register it once; the monitor tracks it from then on.

```
  register ──▶ stage ──▶ scan ──▶ findings ──▶ policy verdict
     │                     │                        │
   digest is           runs Trivy/Grype +      pass / fail, with
   resolved and        unpacker+ClamAV in       the violated rules
   pinned here         isolated Jobs            named
```

Four things are worth internalising because they shape every integration:

- **Identity is the digest, not the ref string.** Two registrations of the same bytes under different tags are one artifact. This is what makes "which images still ship this CVE" answerable.
- **Scanning is asynchronous.** `POST /scan` returns `202` and the work happens in separate Kubernetes Jobs. A pipeline that reads findings immediately reads an empty set — which is indistinguishable from a clean image.
- **Findings have a lifecycle.** They are `open`, or suppressed via VEX (`not_affected`), or resolved when a rescan stops seeing them. They are not deleted.
- **The policy verdict is the product.** Registration and scanning exist so that something can answer "may this be promoted?" — [`/policy`](#4-turning-it-into-a-gate) is that answer.

---

## 2. Before you start

**Address.** In-cluster, monitor-api is at `http://monitor-api.<namespace>.svc.cluster.local:8080`. From a laptop, port-forward:

```bash
kubectl port-forward -n supply-chain-monitor deploy/monitor-api 18080:8080
```

**Key.** Every `/api/v1` route needs a bearer token:

```bash
KEY=$(kubectl get secret -n supply-chain-monitor scm-monitor-api-auth \
        -o jsonpath='{.data.API_KEY}' | base64 -d)
```

Keep the header as a bash *array*, not a string — a plain string silently truncates at the space when expanded unquoted:

```bash
AUTH=(-H "Authorization: Bearer $KEY")
curl -s "${AUTH[@]}" localhost:18080/api/v1/stats
```

**Scopes.** Keys can be named per client and scoped to `read`, `register`, `scan`, `documents:write` or `admin`. A denial is **403, not 401** — the credential is valid, it just may not do this. See [README § Per-client API keys](../README.md#per-client-api-keys).

**Health.** `/healthz` and `/metrics` need no key. `/healthz` reports the process only; `/readyz` actually pings Postgres.

---

## 3. The core loop

### Register what you built

**Solves:** the pipeline knows what it produced; nothing else does. Registration is the handoff.

```bash
curl -s -X POST localhost:18080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"public.ecr.aws/docker/library/nginx:1.27-alpine","type":"image"}'
```

```json
{
  "id": "b260643ae4e79edc",
  "ref": "public.ecr.aws/docker/library/nginx:1.27-alpine",
  "digest": "sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10",
  "type": "image",
  "status": "registered",
  "created_at": "2026-08-21T12:18:53.698923Z"
}
```

The digest was resolved for you at registration — you did not supply it. That resolution is what makes duplicates detectable.

**Registering many at once** (`/artifacts/bulk`) reports each outcome separately rather than failing the batch:

```json
{"created": 1, "failed": 0, "duplicates": 1}
```

That run registered `redis:7-alpine` and re-submitted the `nginx` above. The duplicate is **not** an error — it is the same bytes, already known.

### Say where it is

**Solves:** "this image is in production" is a question people ask at 3am. Stage history answers it without archaeology.

The configured stages come from the deployment:

```bash
curl -s "${AUTH[@]}" localhost:18080/api/v1/pipeline/stages
```

```json
{"stages": ["source","build","test","scan","sign","publish","deploy"]}
```

```bash
curl -s -X POST "localhost:18080/api/v1/artifacts/$ID/stage" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"stage":"build"}'
```

```json
{
  "id": "b260643ae4e79edc",
  "current_stage": "build",
  "stage_history": [{"stage": "build", "timestamp": "2026-08-21T12:19:01.630553156Z"}]
}
```

### Scan it

**Solves:** CVEs *and* malware in one pass. For `type: image` this runs Trivy and/or Grype for CVEs **and** unpacker + ClamAV for malware, merging both into one artifact.

```bash
curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
  -X POST "localhost:18080/api/v1/artifacts/$ID/scan" "${AUTH[@]}"
# HTTP 202
```

`202`, not `200`. The artifact goes to `status: "scanning"` and separate Jobs do the work. **Poll for the result — do not sleep and assume:**

```bash
while [ "$(curl -s "${AUTH[@]}" "localhost:18080/api/v1/artifacts/$ID" | jq -r .status)" = scanning ]; do
  sleep 10
done
```

Observed on this run: `scanning scanning scanned` — about 25 seconds for a small Alpine-based image.

### Read the results

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/artifacts/$ID"
```

```
status: scanned | stage: build | last_scan_at: 2026-08-21T12:19:23.781439Z
cve_findings: 129
malware_findings: 0
secret_findings: 0
misconfiguration_findings: 0
other_findings: 0
```

One finding, in full:

```json
{
  "id": "CVE-2024-58251",
  "severity": "MEDIUM",
  "title": "In netstat in BusyBox through 1.37.0, local users can launch of networ ...",
  "source": "grype, trivy",
  "status": "open",
  "first_seen_at": "2026-08-21T12:19:23.781439Z",
  "epss_score": 0.0017
}
```

`source: "grype, trivy"` means both scanners found it — this deployment runs `CVE_SCANNER=both`. `epss_score` comes from enrichment, covered [below](#prioritise-by-what-is-actually-exploited).

---

## 4. Turning it into a gate

### The policy verdict

**Solves:** every team writes the same brittle shell that greps a scanner's JSON for "HIGH". Put the rule in one place and ask a yes/no question instead.

The policy on this deployment:

```json
{"disallowUnsafe": true, "maxSeverity": {"malware": "none"}, "requireScanWithinDays": 2}
```

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/artifacts/$ID/policy"
```

```json
{"pass": true, "violations": [], "configured": true}
```

And a real failure, from an artifact registered but never scanned:

```json
{
  "pass": false,
  "violations": [{"rule": "requireScanWithinDays", "detail": "artifact has never been scanned"}],
  "configured": true
}
```

> **Check `configured`, not just `pass`.** With no policy set, the endpoint answers honestly that nothing was checked. A gate that ignores this field reports a green light on a deployment that has no policy at all. The [Tekton gate Task](#7-tekton-integration) fails closed on it.

### Pin the digest your build produced

**Solves:** the tag moved between build and deploy. Classic, silent, and a supply-chain attack when it isn't an accident.

Send `expected_digest` and registration is refused if the registry disagrees:

```bash
curl -s -X POST localhost:18080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"public.ecr.aws/docker/library/alpine:3.20","type":"image",
       "expected_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}'
```

```json
{
  "error": "resolved digest does not match the expected digest -- registration refused",
  "expected_digest": "sha256:0000...0000",
  "resolved_digest": "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
  "ref": "public.ecr.aws/docker/library/alpine:3.20"
}
```
→ `HTTP 409`

To make this mandatory fleet-wide, set `REQUIRE_DIGEST` (see [README § Requiring a verified digest](../README.md#requiring-a-verified-digest-at-registration)). Note the different behaviour: with `REQUIRE_DIGEST` on, a mismatch registers the artifact with `unsafe: true` rather than refusing it, so an existing pipeline doesn't start hard-failing the day you flip it — and `disallowUnsafe` in the policy is what then blocks promotion.

### A ref cannot point at your own network

**Solves:** an artifact ref is caller-supplied, and the scanner pulls it. Without a check that is a confused deputy pointed at your metadata service.

```bash
curl -s -X POST localhost:18080/api/v1/artifacts "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"ref":"169.254.169.254/latest/meta-data:v1","type":"image"}'
```

```json
{"error": "ref host \"169.254.169.254\" resolves to a link-local address -- refused (set REF_HOST_ALLOWLIST to permit it)"}
```
→ `HTTP 400`

There is a NetworkPolicy floor under this too — the application check bounds the string, the policy refuses the packet regardless of what any binary decided to do with it. If you genuinely have an internal registry, `REF_HOST_ALLOWLIST` is the deliberate opt-in, and it needs a matching egress change (see [§9](#9-connecting-your-own-registries)).

---

## 5. Living with findings

### Suppress a false positive with VEX

**Solves:** the finding that is real, understood, and not applicable — and that otherwise gets re-triaged by a different person every sprint.

Post an [OpenVEX](https://openvex.dev) document. Anything that writes OpenVEX to stdout (`vexctl`, a build step, `jq`) can pipe straight in:

```bash
curl -s -X POST "localhost:18080/api/v1/artifacts/$ID/vex" "${AUTH[@]}" \
  -H 'Content-Type: application/json' --data-binary @vex.json
```

with

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/nginx-busybox-netstat",
  "author": "platform-team",
  "timestamp": "2026-08-21T12:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {"name": "CVE-2024-58251"},
    "products": [{"@id": "pkg:oci/nginx"}],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path"
  }]
}
```

The response reports what it applied:

```json
{"statements": 1, "status": "applied"}
```

and the finding is now:

```json
{
  "id": "CVE-2024-58251",
  "severity": "MEDIUM",
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "epss_score": 0.0017
}
```

**The finding is still there.** Suppression is not deletion — the justification travels with it, and an auditor can see what was decided and why. What changes is that it stops counting as active. Measured: before the VEX, `CVE-2024-58251` reported **24** affected artifacts; after, **23**.

### Prioritise by what is actually exploited

**Solves:** 129 findings on one image. Severity alone does not tell you which one matters tonight.

Findings are enriched with CISA KEV and FIRST EPSS:

```json
{
  "id": "CVE-2023-44487",
  "severity": "High",
  "title": "nginx 1.27.5-1~bookworm",
  "source": "grype",
  "status": "open",
  "epss_score": 0.99999,
  "known_exploited": true
}
```

`known_exploited: true` means it is on CISA's Known Exploited Vulnerabilities list. `epss_score: 0.99999` is a 99.999% modelled probability of exploitation in the next 30 days. That is a different question from CVSS severity, and a better one for "what do I fix first".

### Which images still have this?

**Solves:** the fix shipped — did it actually land everywhere?

Search when you don't have the exact id:

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/findings?q=CVE-2024-58251&limit=3"
```

```json
{
  "total": 1,
  "findings": [{
    "id": "CVE-2024-58251",
    "title": "In netstat in BusyBox through 1.37.0, local users can launch of networ ...",
    "severity": "MEDIUM",
    "artifacts": 24
  }]
}
```

Then get the actual artifacts:

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/findings/CVE-2024-58251/artifacts?limit=3"
```

Returns full artifact objects — ref, digest, stage, and their findings — so you can see *where* each affected image sits in the pipeline, not just that it exists.

### Feed in another scanner

**Solves:** you already run something the monitor doesn't. SARIF from any tool can be submitted against an artifact and lands in the same buckets, classified per result (misconfiguration / secret / other). See [README § Submitting findings from an external scanner](../README.md#submitting-findings-from-an-external-scanner).

---

## 6. Fleet questions

### Which images ship this package?

**Solves:** a CVE lands in a library before any scanner has a rule for it. You need the blast radius *now*.

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/components?q=openssl&limit=3"
```

```json
{
  "total": 50,
  "packages": [
    {"purl": "pkg:deb/debian/openssl-provider-legacy@3.5.6-1~deb13u2?arch=amd64&distro=debian-13.6",
     "name": "openssl-provider-legacy", "version": "3.5.6-1~deb13u2",
     "licenses": "Apache-2.0,Artistic-2.0,GPL-1.0-or-later,GPL-1.0-only", "artifacts": 8},
    {"purl": "pkg:deb/debian/openssl@3.5.6-1~deb13u2?arch=amd64&distro=debian-13.6",
     "name": "openssl", "version": "3.5.6-1~deb13u2", "artifacts": 7},
    {"purl": "pkg:deb/debian/openssl@3.0.20-1~deb12u2?arch=amd64&distro=debian-12.15",
     "name": "openssl", "version": "3.0.20-1~deb12u2", "artifacts": 3}
  ]
}
```

Note the versions are separate rows. "How many images have openssl" is rarely the question; "how many have the *vulnerable* one" is, and that is a different number — here 7 versus 3 versus 8.

Licenses come along for free, which is what the license denylist gates on ([README § Component licenses](../README.md#component-licenses-and-the-denylist)).

### What changed between builds?

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/artifacts/$ID/components/diff"
```

```json
{"from": null, "to": null, "added": [], "removed": [], "version_changed": []}
```

That empty result is honest and worth showing: this artifact has been scanned **once**, so there is no earlier snapshot to compare against. A diff appears after a rescan sees different components — a base-image bump shows up as `version_changed` entries, which is the review you actually want on a dependency PR.

### Fleet summary

```bash
curl -s "${AUTH[@]}" localhost:18080/api/v1/stats
```

```json
{
  "total": 98,
  "by_status": {"registered": 1, "scanned": 97},
  "by_type": {"image": 98},
  "with_findings": {"cve": 92, "malware": 0, "misconfiguration": 0, "other": 0, "secret": 4},
  "by_stage": {"": 96, "build": 2},
  "stale_after_days": 7,
  "stale": 0
}
```

These are **fleet-wide** counts computed in the database, not counts of whatever page you happen to be looking at. `with_findings` counts artifacts carrying at least one *active* finding per bucket — VEX-suppressed ones drop out, which is the point of suppressing them.

`stale` is how many artifacts have not been scanned within `stale_after_days`. It is the number to alert on: an image nobody has looked at in three weeks is a worse risk than one with a known MEDIUM.

### The generated documents

Every image scan captures a CycloneDX SBOM and a SARIF report:

```bash
curl -s "${AUTH[@]}" "localhost:18080/api/v1/artifacts/$ID/documents/sbom"
```

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:e41df598-a320-47ba-8966-82d1824c5e1f",
  "metadata": {"timestamp": "2026-08-21T12:19:12+00:00", ...}
}
```

`documents/sarif` likewise. Both returned `200` for a freshly scanned image.

### Metrics

`/metrics` is Prometheus text, no key required:

```
scm_scans_started_total 5
scm_scans_succeeded_total 5
scm_scans_failed_total 0
scm_http_responses_total{class="2xx"} 147
scm_http_responses_total{class="4xx"} 4
scm_http_responses_total{class="5xx"} 0
```

---

## 7. Tekton integration

Everything in this section **was executed in the development cluster.** The manifests live in [`examples/tekton/`](../examples/tekton/) and are applied and run below, with the real output.

### The shape

Four Tasks that mirror what a build pipeline already does:

| Task | What it does | Fails when |
| --- | --- | --- |
| `scm-register` | registers the built image, emits `artifact-id` | digest mismatch |
| `scm-stage` | records the stage reached | the stage isn't configured |
| `scm-scan` | triggers a scan **and polls** until it finishes | timeout |
| `scm-gate` | asks `/policy` | policy fails, or no policy is configured |

They authenticate from the Secret the chart already creates — no key of their own:

```yaml
env:
  - name: API_KEY
    valueFrom:
      secretKeyRef:
        name: scm-monitor-api-auth
        key: API_KEY
```

Run the PipelineRun in a namespace the monitor-api ingress NetworkPolicy admits. In-namespace pods are admitted, which is why these run in `supply-chain-monitor` itself.

### Install and run

```bash
kubectl apply -n supply-chain-monitor \
  -f examples/tekton/scm-tasks.yaml \
  -f examples/tekton/scm-pipeline.yaml
```

```
task.tekton.dev/scm-register created
task.tekton.dev/scm-stage created
task.tekton.dev/scm-scan created
task.tekton.dev/scm-gate created
pipeline.tekton.dev/scm-scan-and-gate created
```

```yaml
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: scm-guide-run-
spec:
  pipelineRef:
    name: scm-scan-and-gate
  params:
    - name: image
      value: public.ecr.aws/docker/library/busybox:1.36
    - name: stage
      value: build
  timeouts:
    pipeline: 20m
```

Result:

```
Succeeded: Tasks Completed: 4 (Failed: 0, Cancelled 0), Skipped: 0
```

Task by task:

```
=== register ===
already registered as b9a4f0d569256d63 -- reusing it
=== stage ===
b9a4f0d569256d63 is now at stage build
=== scan ===
scan requested for b9a4f0d569256d63
scan finished with status: scanned
=== gate ===
policy passed
```

Pipeline results, available to whatever runs next:

```
artifact-id=b9a4f0d569256d63
digest=sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
```

### The bug the first run found

The first version of `scm-register` treated **every** `409` as a digest mismatch. Running it produced:

```
REFUSED: {"digest":"sha256:73aaf0...","error":"an artifact with this digest is already registered",
          "existing_artifact_id":"b9a4f0d569256d63", ...}
The registry resolved this ref to a different digest than the build produced.
```

That message is wrong, and the pipeline failed on a completely normal event — rebuilding an unchanged image. Two different things return `409` and a pipeline must distinguish them by the response body:

| Response carries | Meaning | What CI should do |
| --- | --- | --- |
| `existing_artifact_id` | same bytes already registered | **adopt that id and continue** |
| `resolved_digest` | the ref resolves to different bytes | **stop the pipeline** |

The fixed Task does exactly that:

```sh
409)
  existing=$(printf '%s' "$json" | jq -r '.existing_artifact_id // empty')
  if [ -n "$existing" ]; then
    echo "already registered as $existing -- reusing it"
    printf '%s' "$existing" > "$(results.artifact-id.path)"
    exit 0
  fi
  echo "REFUSED: $json" >&2
  exit 1 ;;
```

This is the whole argument for running your examples: the broken version reads perfectly well.

### Proving the gate blocks

A gate nobody has watched fail is not a gate. Run `scm-gate` alone against an artifact that was registered but never scanned:

```yaml
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  generateName: scm-gate-blocks-
spec:
  taskRef:
    name: scm-gate
  params:
    - name: artifact-id
      value: a0f5bf07f48eca61
```

```
reason=Failed
policy FAILED:
  - requireScanWithinDays: artifact has never been scanned
```

The TaskRun fails, so the Pipeline stops, so nothing is promoted.

### Two things to get right

**Use `runAfter`.** Staging and scanning both only depend on the artifact id, so Tekton would happily run them concurrently. Without `runAfter` the stage history can record `test` before the scan that justified it:

```yaml
- name: scan
  taskRef: {name: scm-scan}
  runAfter: [stage]
```

**Poll, don't sleep.** `scm-scan` polls `/artifacts/{id}` until `status` leaves `scanning`. A fixed `sleep 30` reads an empty finding set on a slow scan — which looks exactly like a clean image.

### Adapting to other CI

Nothing here is Tekton-specific beyond the YAML. The same four steps are four `curl` calls in GitHub Actions, GitLab CI or Jenkins; the only real requirements are network reach to monitor-api and the API key in the environment.

---

## 8. Chart configuration

Everything is a value in `charts/supply-chain-monitor/values.yaml`. This section is the map: what each switch turns on, **what actually disappears when you turn it off**, and which ones cost you more than they look like they do.

The "removes" column below is measured, not read off the templates — each row was produced by rendering the chart twice and diffing the objects:

```bash
helm template scm charts/supply-chain-monitor --set networkPolicy.enabled=false
```

### How to apply values

Two shapes, depending on how the release is managed.

**Flux (how this cluster runs):** the HelmRelease carries `values:` inline and `valuesFrom:` for anything secret. Edit `k8s/releases/supply-chain-monitor-helmrelease.yaml`, commit, push — Flux reconciles. A secret never goes in that file; it goes in the Secret that `valuesFrom` points at.

**Direct Helm:**

```bash
helm upgrade --install scm charts/supply-chain-monitor -n supply-chain-monitor -f my-values.yaml
```

> **One caveat that has bitten this repo.** A comma inside a value reaches Flux through Helm's `strvals` parser, where a comma is a delimiter — a comma-separated value set through `valuesFrom` with a `targetPath` is torn apart before Helm sees it. `monitorApi.apiKeys` uses semicolons for exactly this reason.

### Feature switches

Defaults are the chart's, not this cluster's — a HelmRelease can and does override them.

| Value | Default | On/off turns this on or off | What actually appears or disappears |
| --- | --- | --- | --- |
| `networkPolicy.enabled` | `true` | the L3 floor under everything | 3 NetworkPolicies: `scm-monitor-api`, `scm-postgres-ingress`, `scm-scan-worker-egress` |
| `registry.tls.enabled` | `true` | HTTPS on the in-cluster registry and its token endpoint | Certificates `scm-registry-tls`, `scm-docker-auth-tls` |
| `postgres.tls.enabled` | `true` | TLS to the database | Certificate `scm-postgres-tls` |
| `postgres.backup.enabled` | `true` | nightly `pg_dump` | CronJob `scm-postgres-backup`, its primer Job, and the backups PVC |
| `clamav.autoscaling.enabled` | `true` | scaling malware scanning with load | HPA `scm-clamav` |
| `monitorApi.enrichment.enabled` | `true` | CISA KEV + FIRST EPSS on findings | CronJob `scm-enrich-refresh` |
| `monitorApi.sweep.enabled` | `true` | picking up artifacts that need a rescan | CronJob `scm-sweep-registered` |
| `monitorApi.retention.enabled` | `false` | deleting artifacts older than `retention.days` | CronJob `scm-prune` |
| `monitorApi.serviceMonitor.enabled` | `false` | Prometheus Operator scraping | ServiceMonitor `monitor-api` |
| `monitorApi.prometheusRule.enabled` | `false` | the shipped alert rules | PrometheusRule `monitor-api` |
| `monitorApi.cosign.enabled` | `false` | signature + SLSA provenance verification | nothing — env only (see the trap below) |
| `gateway.api.enabled` | `true` | routing the API through the Gateway | HTTPRoute `scm-api` |
| `gateway.tls.enabled` | `true` | TLS at the Gateway + HTTP→HTTPS redirect | Certificate `scm-gateway-tls`, HTTPRoute `scm-https-redirect` |
| `dockerAuth.existingSecret` | `false` | *bring your own* registry credentials | removes Secrets `scm-docker-auth-config` **and** `scm-registry-credentials` — the chart stops rendering both halves together, deliberately |
| `monitorApi.requireDigest` | `false` | `expected_digest` mandatory at registration | env only |
| `monitorApi.disableScanIsolation` | `false` | running scans **in the API pod** instead of isolated Jobs | env only — a documented hardening downgrade for local dev |
| `monitorApi.scanFreshness.autoRescan` | `true` | the sweep actually rescanning, rather than only reporting staleness | env only |
| `monitorApi.localArtifacts.enabled` | `"false"` | accepting filesystem paths as refs | env only (`ALLOW_LOCAL_ARTIFACT_PATHS`) |
| `dashboard.allowManualRegistration` | `false` | the dashboard's register form | env only |

### Switches that are off by being empty

Not every toggle is a boolean. These are disabled by their zero value, which is easy to miss when scanning a values file for `enabled:`:

| Value | Off when | Turns on |
| --- | --- | --- |
| `monitorApi.maxArtifacts` | `0` | a cap on how many artifacts can exist (403 at the cap) |
| `monitorApi.rateLimit.requestsPerSecond` | `0` | request rate limiting |
| `monitorApi.licenseDenylist` | `""` | license findings from SBOM components |
| `monitorApi.refHostAllowlist` | `""` | permitting refs that the private-IP checks would otherwise refuse |
| `monitorApi.notifications.webhookURL` / `.slackURL` | `""` | outbound notifications |
| `monitorApi.registryCredentials` | `[]` | credentials for registries beyond the in-cluster one ([§9](#9-connecting-your-own-registries)) |
| `monitorApi.pluggableScanners` | `[]` | additional scanners |
| `monitorApi.scanScratch.storageClass` | `""` | per-Job PVCs instead of node-disk `emptyDir` |
| `monitorApi.cosign.trustedRootSecret` | `""` | verifying against a **private** Sigstore rather than the public one |

### Choosing scanners

```yaml
monitorApi:
  cveScanner: both        # trivy | grype | both
  malwareScanner: clamav  # clamav | malcontent | both
```

`cveScanner: trivy` removes the grype DB primer Job and refresh CronJob. `cveScanner: grype` removes **nothing** — the trivy DB cache keeps refreshing, and that asymmetry is deliberate rather than an oversight:

> ⚠️ **Turning trivy off costs more than CVEs.** The CycloneDX SBOM and SARIF documents are derived from *trivy's* raw image report (`captureImageDocuments` in `main.go`, `captureDocuments` in `internal/api/scan.go` — both take a trivy report; the grype branch calls `Scan`, not `ScanWithRaw`). Component indexing is triggered **by that document arriving**. So `cveScanner: grype` also costs you the SBOM, the component inventory, the component-diff endpoint, and license findings — and every scan still looks completely healthy while those features quietly do nothing.
>
> This is not hypothetical: the same gap already shipped once on the `disableScanIsolation` path, where image scans produced no SBOM at all.

If you want grype's findings without losing all that, use `both`.

### Secrets: three "bring your own" switches

The chart generates credentials by default and hands them to the things that need them. Each can be replaced with one you manage:

| Value | Chart stops rendering | You must provide |
| --- | --- | --- |
| `dockerAuth.existingSecret: true` | `scm-docker-auth-config` **and** `scm-registry-credentials` | both halves — the bcrypt hashes docker_auth checks, and the cleartext monitor-api presents |
| `postgres.credentials.existingSecret: true` | the Postgres credentials Secret | `scm-postgres-credentials` |
| `monitorApi.apiKeyExistingSecret: true` | `scm-monitor-api-auth` | a Secret with an `API_KEY` key |

The docker-auth pair is one switch on purpose. Managing one externally while the chart renders the other from values it no longer has produces two objects that look fine and disagree — the symptom is 401s from the registry with nothing obviously wrong.

### Two traps worth knowing

**A feature that is off and a feature that is broken render identically.** `cosign.enabled: true` adds no Kubernetes object — it is environment only. If the identity and issuer are missing, monitor-api **refuses to start**, which is the intended behaviour: an artifact list with no provenance findings would otherwise look like "everything is signed". Check the pod, not the dashboard.

**String-typed defaults accept real booleans.** Some values are quoted strings in `values.yaml` (`fetchPlainHTTP: "false"`, `unpacker.insecure: "false"`, `localArtifacts.enabled: "false"`) because they become env vars. Setting a genuine YAML `true` works — verified:

```
--set monitorApi.fetchPlainHTTP=true       -> FETCH_PLAIN_HTTP: "true"
--set monitorApi.unpacker.insecure=true    -> UNPACKER_INSECURE: "true"
--set monitorApi.localArtifacts.enabled=true -> ALLOW_LOCAL_ARTIFACT_PATHS: "true"
```

**But `registry.tls.enabled` and `unpacker.insecure` are not linked**, and that pair is a real footgun: `--insecure` is unpacker's own switch and the chart cannot know what a differently-configured registry needs. Turn registry TLS off and you must set `unpacker.insecure: "true"` yourself, or image pulls fail.

### Check your values before you apply them

The technique used to build the table above works for any change — render, and diff the objects:

```bash
helm template scm charts/supply-chain-monitor > /tmp/before.yaml
helm template scm charts/supply-chain-monitor -f my-values.yaml > /tmp/after.yaml
diff /tmp/before.yaml /tmp/after.yaml
```

`make helm-template` goes further: it renders the chart and fails on documents missing `apiVersion`, on any Postgres client not admitted by the NetworkPolicy in front of it, and on a two-registry credential file that renders an unusable docker config. `make helm-lint` is the structural check.

### A worked override

Turning on the things that are off by default, for a deployment that has somewhere to send alerts:

```yaml
monitorApi:
  # cap the fleet and shed load rather than falling over
  maxArtifacts: 500
  rateLimit:
    requestsPerSecond: 20
    burst: 40
  # delete artifacts nobody has touched in a quarter, dry-run first
  retention:
    enabled: true
    days: 90
    dryRun: true
  # scrape and alert
  serviceMonitor:
    enabled: true
  prometheusRule:
    enabled: true
  # refuse anything whose digest the build did not pin
  requireDigest: true
  policy:
    disallowUnsafe: true
    maxSeverity:
      malware: none
    requireScanWithinDays: 2
  notifications:
    slackURL: ""   # set via valuesFrom, not here
    minSeverity: high
```

Note `retention.dryRun: true`. Retention deletes; run it in dry-run for a cycle and read the logs before letting it act.

---

## 9. Connecting your own registries

**Solves:** the monitor scans public images out of the box, but yours are in a private GHCR, Harbor or ECR that needs credentials — and possibly a private CA.

Configure a list in the chart:

```yaml
monitorApi:
  registryCredentials:
    - host: ghcr.io
      username: my-bot
      password: ghp_xxx
    - existingDockerConfigSecret: harbor-pull-secret
      caSecret:
        name: harbor-ca
        key: ca.crt
```

Each entry is either inline credentials or a Secret you manage yourself in the standard `kubernetes.io/dockerconfigjson` shape — the one `kubectl create secret docker-registry` produces. Entries carrying both are treated as inline.

Everything is merged into one `config.json` in the pod, which every tool authenticates from: `oras` via `--registry-config`, Trivy/Grype/cosign via `DOCKER_CONFIG`, unpacker via `--config`. The same Secrets are mounted into every scan-worker Job, so isolated scans authenticate identically. Credentials are scoped **per host** — a scan of a ghcr.io image offers ghcr.io's entry and nothing else.

Three things to know before you rely on it:

- **`host` is used verbatim** as the docker `auths` key. Docker Hub is the one host whose key is not its hostname: write it as `https://index.docker.io/v1/`.
- **This does not open network egress.** A registry on a private address, or on a non-standard port, is still refused by the scan-worker egress policy, which allows 80/443 to public addresses only. It fails as a connection timeout that reads like the registry being down. Reaching one means deliberately narrowing `networkPolicy.blockedEgressCIDRs`.
- **A wrong credential degrades to an anonymous pull**, and against a public registry an anonymous pull *succeeds* with fewer results rather than failing. Verify by scanning a known-private image and confirming you get findings.

> ⚠️ **Not executed here.** The credential mechanism was verified against a registry with htpasswd auth — all four tools authenticate from a merged config, with anonymous controls that fail. But this development cluster has no second private registry configured, so `registryCredentials` has never authenticated a real second registry end-to-end. Treat the first configuration as something to verify, not assume.

For the in-cluster registry's own auth, see [README § Registry authentication](../README.md#registry-authentication).

---

## 10. When a result looks too clean

A short list of results that look like good news and aren't. Each has a concrete thing to check.

### "Zero malware findings"

`malware_findings: 0` means ClamAV found nothing **in the files it opened**. It does not tell you how many files that was — and if the unpack produced nothing, zero files were opened and the artifact is still recorded clean.

**Check the count.** In a scan-worker Job's log:

```
{"msg":"unpacker: clamav scan complete","scanner":"clamav","files_scanned":15530,"files_failed":2,"count":0}
```

`files_scanned: 15530` is what makes `count: 0` mean something. A `files_scanned: 0` line with zero findings is not a clean image, it is an image nobody looked at.

```bash
kubectl logs -n supply-chain-monitor <scm-scan-pod> | grep files_scanned
```

### "No provenance findings, so everything is signed"

Signature and SLSA-provenance verification is off unless `COSIGN_ENABLED=true` **and** a certificate identity and OIDC issuer are configured. On this deployment `COSIGN_ENABLED = false`, so no artifact carries provenance and the dashboard shows nothing — which is exactly what a broken verification setup would also look like.

**Check the config, not the UI.** monitor-api refuses to start if `COSIGN_ENABLED` is set without an identity, precisely so that "enabled but unusable" cannot masquerade as "everything is signed". See [README § Provenance](../README.md#provenance-was-this-image-signed-and-by-whom).

### "Policy passed"

`{"pass": true}` with `{"configured": false}` means no policy exists and nothing was checked. Always read `configured`.

### "The scan finished instantly"

Check `last_scan_at` actually moved. A rescan of an artifact that is already fresh may be a no-op depending on your rescan cadence settings ([README § Scan freshness](../README.md#scan-freshness)).

---

## 11. Endpoint reference

Full schemas: [`services/monitor-api/internal/api/openapi.yaml`](../services/monitor-api/internal/api/openapi.yaml), served live at `/openapi.yaml` with Swagger UI at **`/swagger`** — both without a key, deliberately, for the same reason `/healthz` needs none: they describe the API's shape, not its contents. (`/docs` is **not** a route; it 404s.)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` · `/readyz` · `/metrics` | liveness · readiness (pings Postgres) · Prometheus metrics |
| `GET` | `/api/v1/stats` | fleet counts: totals, per status/type/stage, artifacts with active findings |
| `GET` | `/api/v1/pipeline/stages` | the configured stage names |
| `POST` | `/api/v1/artifacts` | register one artifact |
| `GET` | `/api/v1/artifacts` | list, with `?q=`, `?status=`, `?type=`, paging — searching is **server-side**, so `total` is the fleet count, not the page |
| `POST` | `/api/v1/artifacts/bulk` | register many, per-item outcomes |
| `GET` `DELETE` | `/api/v1/artifacts/{id}` | fetch · delete |
| `POST` | `/api/v1/artifacts/{id}/scan` | trigger a scan (`202`, asynchronous) |
| `POST` | `/api/v1/artifacts/{id}/stage` | record a stage transition |
| `POST` | `/api/v1/artifacts/{id}/maintainer` | set the owning team — `{"team":..., "email":...}`, **both required** |
| `GET` `POST` | `/api/v1/artifacts/{id}/findings` | read · submit findings (e.g. SARIF from another scanner) |
| `GET` | `/api/v1/artifacts/{id}/policy` | the promotion verdict |
| `POST` | `/api/v1/artifacts/{id}/vex` | apply an OpenVEX document |
| `GET` | `/api/v1/artifacts/{id}/documents/{kind}` | the captured `sbom` / `sarif` |
| `GET` | `/api/v1/artifacts/{id}/components/diff` | component changes since the previous scan |
| `GET` | `/api/v1/findings` | search findings by id or title |
| `GET` | `/api/v1/findings/{findingID}/artifacts` | every artifact still affected |
| `GET` | `/api/v1/components` | search packages across the fleet, with licenses |

### Configuration seen in this guide

Values as deployed on the cluster these examples ran against:

| Setting | Value | Meaning |
| --- | --- | --- |
| `CVE_SCANNER` | `both` | Trivy **and** Grype; findings merge, `source` names them |
| `SCAN_CONCURRENCY` | `8` | cluster-wide, not per replica |
| `SCAN_STALE_AFTER_DAYS` | `7` | drives `stale` in `/stats` |
| `MAX_ARTIFACTS` | `500` | registration returns 403 at the cap |
| `REQUIRE_DIGEST` | `false` | `expected_digest` is optional |
| `COSIGN_ENABLED` | `false` | provenance verification off |
| `LICENSE_DENYLIST` | *(empty)* | no license gating |

---

## Appendix: what was and wasn't run

| Section | How it was verified |
| --- | --- |
| §3 core loop, §4 gate, §5 findings, §6 fleet | Executed against the live cluster; every output pasted from the run |
| §7 Tekton | Tekton Pipelines installed in the dev cluster; Tasks and Pipeline applied; PipelineRun and a failing TaskRun both executed |
| §8 chart configuration | Every "what disappears" measured by rendering the chart twice and diffing the objects; the string-vs-bool renderings taken from `helm template --set` output. **The trivy/SBOM coupling was read from the code, not executed** — the claim is that `cveScanner: grype` produces no SBOM, and this cluster runs `both` |
| §8 registry credentials | Mechanism verified against an htpasswd registry with anonymous controls; **the chart values have not authenticated a real second registry in a cluster** |
| §9 malware `files_scanned` | Observed in a live scan-worker Job log (`files_scanned: 15530`) |
| §9 provenance | Read from the live ConfigMap (`COSIGN_ENABLED = false`); the enabled path was not exercised |
