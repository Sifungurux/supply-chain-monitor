# Scan concurrency ramp, 2026-08-24 — where a mirrored fleet breaks

The 2026-08-23 ramp raised `scanConcurrencyPerKind.unpacker` from 2 to 8 and
found **no clean capacity ceiling** on a 100 GB VM: every rung from 2 to 8
completed with zero failures, and disk — the constraint the cap was invented to
enforce — had stopped binding. The cap was chosen on blast radius, not because
anything was shown to fail.

Two things have changed since, and both change the answer:

1. The VM was rebuilt at **300 GB**, so disk is even further from binding.
2. **Artifact mirroring is on.** 91 of 92 artifacts now resolve to
   `scm-registry`, so every scan pulls from a single in-cluster pod instead of
   from Docker Hub / ghcr.io / public.ecr.aws.

**Outcome: the cluster broke at cap 16, and it broke somewhere new.** Not disk,
not scan-worker memory, not the node. `scm-registry` was **OOMKilled** at its
512Mi limit, and the scans it was serving failed with it.

## What counts as "breaks"

Defined before the first run and applied identically to every rung — the same
definition the 2026-08-23 ramp used, so the two are comparable:

- any pod `Evicted`, **or**
- any artifact whose scan outcome is not `scanned`, **or**
- any node reporting `DiskPressure=True`

A **retried 429 is not a break.** That is the cap doing its job — a refused scan
is a 429 with `Retry-After`, never a queue — and the harness counts retries
separately from failures for exactly that reason.

Two things are recorded but are explicitly *not* breaks:

- `ImagePullBackOff` on `monitor-api:dev` — a **harness** failure. That image
  exists only because `k3d image import` put it in each node's containerd, and
  kubelet's image GC deletes it under the very pressure this test induces. The
  2026-08-13 load test lost a run to this.
- `OOMKilled` **scan-worker** containers — a per-scan property independent of
  the cap (see the 1Gi grype limit, which the previous ramp documented).

## Method

`SCAN_CONCURRENCY` and `SCAN_CONCURRENCY_UNPACKER` are raised together at each
rung. Raising only the global cap would have pinned the whole ramp at the
unpacker cap of 2, since image scans take an unpacker slot.

Flux was suspended for the duration (it owns the ConfigMap and would revert
each rung), `monitor-api` restarted per rung, and the same **40 mirrored
artifacts** driven through a scan in the same order at every rung.

Rungs: **8 → 12 → 16** (planned 24, 32, 48, 64; stopped at the first break).

Harness: `docs/data/scan-concurrency-2026-08-24/ramp.py`.

## Results

| cap | wall | 429 retries | not scanned | evicted | scan-worker OOM | DiskPressure | peak disk | verdict |
|-----|------|-------------|-------------|---------|------------------|--------------|-----------|---------|
| 8   | 599.4s | 285 | 0 | 0 | 0 | False | 92.5 GB | clean |
| 12  | 521.9s | 174 | 0 | 0 | 0 | False | 95.8 GB | clean |
| 16  | 505.3s | 126 | **5** | 0 | 0 | False | 92.9 GB | **BROKE** |

`peak disk` is the whole node filesystem (299.4 GB), not the registry alone. It
never moved outside a 92–96 GB band and was never within 200 GB of full.

## The break: scm-registry runs out of memory

All five failures are `status=failed`, meaning *every* scanner failed, not one
of several:

```
3 x  not_found
2 x  registry_auth_failed
```

All five are mirrored refs. The cause is in the registry pod's own status:

```json
"lastState": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}}
"restartCount": 4
```

`scm-registry` is **1 replica, 512Mi memory, 500m CPU**. It idles at **26Mi** —
so the limit is 20x its resting size, which is why nobody noticed. What blows it
up is concurrent blob serving. From its own log, immediately before the kill:

```
http.response.duration=37.5291363s  http.response.written=16435389
  vars.name=mirror/mirror.gcr.io/portainer/portainer-ce
```

**37.5 seconds to serve a 16 MB blob.** The registry was already badly degraded
before it died. When it did, kubelet reported both probes failing
(`connection reset by peer`, then `connection refused`), and every scan holding
a pull against it failed — a manifest lookup mid-restart reads as `not_found`,
and a token exchange mid-restart reads as `registry_auth_failed`. Those two
reason codes are the *symptom* of the restart, not two separate faults.

### Why this is new

This constraint did not exist before mirroring, and could not have. Every image
scan used to pull from Docker Hub / ghcr.io / public.ecr.aws — highly available
services with no memory limit this project sets. Mirroring moved 91 of 92
artifacts onto **one pod with a 512Mi limit and no replicas**, and then pointed
every scanner at it: at cap 16 that is 16 concurrent scans, each running trivy,
grype and unpacker, each pulling independently.

Mirroring traded a rate limit we did not control for a capacity limit we do.
That is the right trade — but the capacity has to actually be provisioned, and
it currently is not.

## Throughput

Raising the cap barely helps, and that is consistent with 2026-08-23 (where
cap 12 was 39% *slower* than cap 8):

| cap | wall | vs cap 8 |
|-----|------|----------|
| 8   | 599.4s | — |
| 12  | 521.9s | −13% |
| 16  | 505.3s | −16%, but 5 scans failed |

Between 12 and 16 the gain is 3% — and it is bought by killing the registry.
The work is bounded by what one registry pod and the scanner tools can do, not
by how many scans are permitted to start. The falling 429 counts (285 → 174 →
126) confirm the cap was the binding constraint at 8 and had stopped being one
by 16.

## Recommendation

**Keep the cap at 12.** It is the highest rung that completed clean, it is 13%
faster than 8, and the next rung up breaks the registry for a further 3%.

**Raise `registry.resources.limits.memory` before raising the cap again.** 512Mi
is sized for a registry that served a handful of SBOM blobs. It now serves every
image scan in the fleet. Until that is fixed, cap 16+ is not a capacity question
about scanning at all — it is a question about one under-provisioned pod.

Worth considering alongside it:

- **`registry.replicas: 1`** is a single point of failure for *all* scanning now
  that refs point at it. It was merely a convenience before.
- **Both DB cache PVCs are `ReadWriteOnce` on `local-path`**
  (`scm-trivy-db-cache`, `scm-grype-db-cache`), which pins every trivy and grype
  Job to one node. Not implicated in this break — nothing was ever `Pending` —
  but it caps how wide scanning can ever spread.

## Limitations

- **One corpus, one run per rung.** No repeats, so the wall-clock figures carry
  no error bars. The break at 16 is not a timing artefact — a registry OOMKill
  is unambiguous — but "12 is 13% faster than 8" is a single measurement.
- **40 of 92 artifacts**, selected by id order rather than by size. The
  heaviest images in the fleet (`golang:1.23`, `python:3.13`, ~8 GB across all
  platforms) are not guaranteed to be in it, so this understates peak load.
- **Rungs above 16 were never run.** The ramp stops at the first break by
  design, so the ceiling once the registry is properly sized is unknown.
- **The scan cap is not the only limit in play.** `SCAN_CONCURRENCY_MALCONTENT`
  is 2 and clamav autoscaled to its `maxReplicas: 10` during the cap-16 rung;
  neither was isolated here.

## Instrumentation defects found while running this

Recorded because each one silently corrupted a rung before it was fixed, and
each would do so again:

1. **The sweep CronJob competes with the load test.** It scans on its own
   schedule, consuming slots and adding artifacts outside the corpus. Throughput
   read as 1 scan per 10 minutes until it was suspended; the same workload then
   did 26 in 8 minutes. Suspend `scm-sweep-registered` for any load test.
2. **`kubectl port-forward` binds to one pod.** Changing the cap restarts
   `monitor-api`, which kills the forward — a whole rung recorded 40 connection
   failures that looked like the API refusing scans.
3. **Restarting monitor-api mid-scan orphans artifacts at `status=scanning`**
   with no pod behind them. The in-flight goroutine is simply lost. The sweep's
   stale-scanning reclaim exists for this, but a load test that has suspended
   the sweep has to clear them itself or count them as failures it did not cause.

## Prerequisite fixed before this ran

The ramp was blocked by a real defect and would have measured nothing useful
without fixing it first. `IsolatedTrivyConfig` forwarded
`REGISTRY_USERNAME`/`PASSWORD` to the scan Job but **not `REGISTRY_ADDR`**, and
`runScanWorker` keys its generated docker config *by host* — so trivy's
credentials were filed under `""` and it 401'd on **every** mirrored artifact
(13 of 13 measured). grype, clamav and unpacker succeeded, so artifacts still
reported `scanned` with their CVE coverage quietly halved.

Fixed in `fix/trivy-job-registry-addr`. Left unfixed, every rung here would have
measured trivy failing fast instead of trivy working, and the cluster would have
appeared to tolerate far more concurrency than it can.
