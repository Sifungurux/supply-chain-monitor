# Plan: make cap 24 and 32 runnable

Target: `SCAN_CONCURRENCY` / `SCAN_CONCURRENCY_UNPACKER` at **24** and **32**
completing a 40-artifact batch clean, against the same break criteria the
2026-08-24 ramp used (no `Evicted` pod, no scan outcome other than `scanned`,
no node `DiskPressure=True`).

## Read this first: the honest expectation

**Cap 24/32 will almost certainly not be faster.** The measured curve is already
flat and the mechanism is understood:

| cap | wall | vs previous |
|-----|------|-------------|
| 8   | 599.4s | — |
| 12  | 521.9s | −13% |
| 16  | 505.3s | −3%, and it broke |

Throughput is bounded by what the scanner tools and one registry pod can do, not
by how many scans are permitted to start. The falling 429 counts (285 → 174 →
126) say the cap had already stopped being the binding constraint by 16.

So this is a **stability and headroom exercise**, not a performance one. Worth
doing — the cluster should not fall over at 24, and finding out *what* fails
next is real information — but nobody should expect a speedup. If the actual
goal is throughput, the levers are elsewhere (see "What would actually make
scanning faster" at the end).

## The blockers, with evidence

### B1 — trivy and grype Jobs are pinned to one node (hard blocker)

`scm-trivy-db-cache` and `scm-grype-db-cache` are `ReadWriteOnce` on
`local-path`, and both PVs carry node affinity for **`agent-0`**. Every trivy
and grype Job must therefore schedule there.

Confirmed by observation, not just from the PV spec: during a 4-artifact scan,
all 4 trivy Jobs and all 4 grype Jobs landed on `agent-0`, while the unpacker
Jobs — which mount no cache PVC — spread across `server-0` and `agent-2`. Two of
the three Jobs per scan are pinned.

Each of those Jobs **requests** 200m CPU / 512Mi, and Kubernetes schedules on
requests.

**Measured at cap 12** (sampling every 3s through a 20-artifact batch, rather
than modelling it):

| metric | at cap 12 |
|--------|-----------|
| peak concurrent scan-worker pods | **48** |
| peak concurrently on `agent-0` | **26** |
| **peak `Pending`** | **21** |

Two things follow, and the second one matters more.

**Scheduling pressure already exists at cap 12.** 21 pods were `Pending` at
once — the current, supposedly-clean production cap is already queueing on the
scheduler. An earlier single-instant check during the cap-16 rung showed zero
Pending and was simply mis-sampled; `Pending` is transient and continuous
sampling is required to see it at all.

**26 concurrent Jobs on `agent-0` at cap 12** is ~13 GiB of requests against a
node advertising 16 GiB. Scaling that ratio, cap 24 lands around 52 Jobs / 26
GiB and cap 32 around 69 Jobs / 35 GiB on a single node — both far beyond what
`agent-0` can accept, and beyond what the VM behind it physically has.

A `Pending` pod is not a visible failure. It waits until
`activeDeadlineSeconds` (600s) kills it, which surfaces as a scan timeout — see
B7, which is why that outcome must be classified separately.

This is the blocker. Nothing else matters until it is gone.

### B2 — the VM is 6 CPU / 16 GiB, and the host caps how far that can grow

The four k3d "nodes" are containers **sharing one podman VM**. Each advertises
the whole VM (6 CPU / 16 GiB), so Kubernetes believes the cluster has 24 CPU /
64 GiB. It has 6 and 16. Same overcommit fiction as the ephemeral-storage one
this project already documented.

Host: **32 GiB RAM, 10 CPUs.** A realistic ceiling is **8 CPU / 24 GiB**,
leaving macOS ~8 GiB. So even a maximally grown VM cannot satisfy cap 32's
32 GiB of requests on one node, and cap 24 would consume the entire VM with
nothing left for postgres, the registry, clamav or the unpacker Jobs.

**Growing the VM alone does not get there.** Per-scan footprint has to come down
as well.

### B3 — registry capacity is unvalidated above cap 12

Raised to 1 CPU / 2Gi after it was OOMKilled at 512Mi during cap 16. That number
was chosen to be comfortably clear of the observed failure, **not measured**.
Nothing has yet run at 24 to confirm it.

`registry.replicas: 1` also cannot be raised: the backing PVC is `ReadWriteOnce`
on `local-path`, and `local-path` is the only StorageClass. Horizontal scaling
needs shared storage that does not exist here.

### B4 — grype Jobs OOM on heavy images (pre-existing, independent of the cap)

1Gi limit; RSS measured at ~1.043 GiB on heavy images, producing
`CONSTRAINT_MEMCG` kills. Higher concurrency means more heavy images running at
once, so this gets more likely, not less. Already known; not caused by this work.

### B5 — clamav is capped at 10 replicas

It autoscaled to `maxReplicas: 10` during the cap-16 rung. At 24/32 it is a
candidate next bottleneck, and unlike the others it fails as *slow scans* rather
than as anything obvious.

### B7 — the 600s Job deadline will manufacture a break at 24

`scanWorker.activeDeadlineSeconds` is 600 and `monitorApi.scanTimeoutSeconds` is
660 (main.go refuses to start unless the second exceeds the first). Neither
scales with the cap.

At 24, per-scan latency stretches from contention even when everything schedules
and nothing OOMs — and a scan killed at 600s is recorded as `not scanned`, which
is a **break** by the criteria above. That is a timeout artefact, not a capacity
finding, and in the results table it is indistinguishable from a real one.

This would have made the cap-24 rung "fail" no matter what else was fixed.

### B6 — the ramp harness produces false results

Three defects, each of which silently corrupted a rung before being caught:

1. The sweep CronJob competes for scan slots (throughput read as 1 scan per
   10 min until suspended; then 26 in 8 min).
2. `kubectl port-forward` binds to one pod; changing the cap restarts
   monitor-api and kills it. One rung logged 40 connection failures that looked
   like the API refusing scans.
3. Restarting monitor-api mid-scan orphans artifacts at `status=scanning` with
   no pod behind them.

## The plan

Ordered so that each phase is verifiable on its own, and so the thing that makes
results trustworthy comes first.

### Phase 0 — make the ramp trustworthy (do this first)

Without it, every later phase is unfalsifiable.

- Fold the three B6 workarounds into a committed harness under
  `cluster/`, rather than a scratch script: suspend/restore the sweep, rebuild
  the port-forward after every rollout and treat HTTP 0 as a harness fault,
  clear orphaned `scanning` rows between rungs, scope the drain to the rung's
  own corpus.
- Add a **pre-flight assertion** to each rung: fail loudly if any Job is
  `Pending` for more than 60s. That converts B1 from "mysterious timeouts" into
  "the scheduler refused, here is what it wanted".
- Raise scan-worker `ttlSecondsAfterFinished` **for the duration of a ramp only**
  so failing Jobs can be read. Diagnosis of the trivy 401 was blocked for an
  hour by pods vanishing in seconds.
- **Sample continuously, not at instants.** Peak concurrent Jobs, peak per node,
  and peak `Pending` every ~3s for the whole rung. A single-instant check is what
  hid B1 during the cap-16 rung.
- **Classify "killed by deadline" as its own outcome**, distinct from a scan
  failure (B7). Raise `activeDeadlineSeconds`/`scanTimeoutSeconds` together for
  the ramp, preserving the 60s ordering main.go validates, so a slow scan is
  recorded as slow rather than as a break.
- **Sample registry memory during peak blob transfer** (B3). A reading taken
  after a batch drains is worthless — measured 42Mi that way, against the 512Mi
  that was OOMKilled under load.
- **Raise clamav `maxReplicas` above 10** (B5), or accept that it stays
  unresolved: it was already saturated at its ceiling during cap 16, so at 24
  "clamav is the bottleneck" and "everything is slow" are indistinguishable.

*Verify:* establish a **fresh cap-12 baseline** and use that as the reference.

**Pre-#150 numbers are not comparable and must not be used as a gate.** The
521.9s figure was measured while trivy 401'd instantly on every mirrored
artifact; now that trivy does real work, cap 12 *should* be slower. Treating the
old number as the target would fail Phase 0 against a bug that no longer exists
and send someone hunting a harness fault that is not there.

### Phase 1 — un-pin trivy and grype from agent-0

Still the blocker after measurement — the "maybe the Jobs run sequentially, so
this is not really binding" hypothesis was tested and **disproven**: 26
concurrent Jobs on `agent-0` and 21 `Pending` cluster-wide, at cap 12.

Three options, in preference order:

**1a. Per-node cache PVCs (recommended).** One 2Gi PVC per node with node
affinity, primed by a DaemonSet instead of the current single primer Job. Jobs
then schedule anywhere. Costs ~6Gi extra disk (irrelevant at 300 GB) and turns
two primer Jobs into two DaemonSets.

**1b. emptyDir cache + DB from the in-cluster registry.** `TRIVY_DB_REPOSITORY`
already exists and `cluster/seed-trivy-db.sh` already seeds a mirror. Simplest
change, but it re-pulls the DB per Job — adding load to the registry, which is
the component that already broke. **Rejected for that reason** unless 1a proves
impractical.

**1c. Bake the DBs into the worker image.** No PVC, no pin, fastest start. But
the DB goes stale with the image and the refresh CronJobs lose their purpose.
Rejected.

*Verify:* at cap 24, confirm trivy/grype Jobs are distributed across all four
nodes and none is `Pending`. This is a scheduling assertion and does not require
a full clean rung.

### Phase 2 — grow the VM to the host's practical limit

6 CPU / 16 GiB → **8 CPU / 24 GiB**, disk unchanged at 300 GB.

Requires a rebuild (podman machine memory/CPU can be `set`, but the cluster's
`--agents 3` topology and the whole DB come with it — and the DB must be dumped
**to the host** first, since the backup PVC dies with the VM).

*Verify:* `kubectl get nodes` shows the new allocatable, and a cap-12 rung still
reproduces its baseline.

### Phase 3 — reduce per-scan footprint (the decisive lever)

Even after Phases 1–2, cap 32 wants 32 GiB of Job requests against a 24 GiB VM.
Something has to give. In preference order:

**3a. `CVE_SCANNER=both` — MEASURED, AND THE ANSWER IS KEEP IT.** Running trivy
*and* grype doubles the CVE Job count per scan and is the single biggest
multiplier: at cap 24, `both` means 48 CVE Jobs where `trivy` alone means 24.
Dropping grype would make cap 24 schedulable on today's hardware without any
other change, which makes it a tempting knob.

Measured on the current 92-artifact fleet before deciding:

| source | findings |
|--------|----------|
| trivy only | 33,653 |
| both (coalesced) | 6,393 |
| **grype only** | **4,831** |
| total | 44,877 |

**Grype alone contributes 10.8% of all findings.** That is real coverage, not
redundancy. Trading away one in nine findings to raise a concurrency number that
does not improve throughput is a bad trade, and this option is therefore
**rejected**. Recorded here so it is not rediscovered as a good idea later.

The consequence is important: with `both` retained, the per-scan Job count
cannot come down, so Phase 3 has to deliver its headroom through 3b alone — and
if 3b is not enough, **cap 32 is not reachable on this host.**

**3b. Right-size Job requests from measurement.** Requests are 512Mi (trivy,
grype) and 256Mi (unpacker) against 1Gi limits. If real RSS is well under
512Mi for most scans, lowering the *request* raises schedulable density without
touching the limit. Risk: requests are also the eviction-ranking input, so
lowering them makes scan Jobs the first thing killed under node pressure. Needs
real RSS data per scanner across the corpus before touching.

**3c. Raise the grype Job limit past 1Gi** (B4). Independent of the cap, but it
will show up more often at 24/32, and an OOMKilled grype is a scan that reports
`scanned` with half its coverage.

### Phase 4 — re-ramp

Same corpus, same break criteria, rungs **16 → 24 → 32**, one clean baseline at
12 first. Size the registry from measurement at 24 rather than from the guess
that got it to 2Gi.

## What could invalidate this plan

Stated up front so they are checks, not surprises:

- **Phase 1 may not be sufficient.** Un-pinning fixes *scheduling*; the VM's
  real 16–24 GiB is still shared across all four fake nodes. Spreading Jobs
  across nodes that are all the same VM changes what the scheduler permits, not
  what the hardware can run. Phase 1 without Phase 3 may simply move the failure
  from "Pending" to "OOMKilled".
- **The registry may break again before the cap does.** It is 1 replica by
  necessity (RWO, single StorageClass) and it is on the path of every scan now.
  If it OOMs again at 24 even at 2Gi, the honest answer may be that
  cap 24 is not reachable while every scan pulls from one pod.
- **Cap 32 is now likely infeasible on this host.** With 3a rejected on coverage
  grounds, the Job count per scan is fixed at 3, so 32 concurrent scans means 96
  containers and 32 GiB of CVE-Job requests against a VM that tops out at 24 GiB.
  Phase 3b would have to roughly halve the requests to close that, and there is
  no reason yet to think real RSS supports it.
- **Cap 32 may be infeasible on this host, full stop.** 32 concurrent scans × 3
  Jobs = 96 containers on 8 CPUs. Even scheduled and un-OOMed, per-scan latency
  would stretch until `activeDeadlineSeconds` (600s) starts killing scans — which
  registers as a break, correctly. If Phase 4 shows that, the finding is "32 needs
  different hardware", and that is a legitimate outcome to report rather than
  something to tune around.
- **Throughput may get worse.** Already observed between 12 and 16. If 24 is
  slower than 12 while merely not breaking, "runnable" and "advisable" are
  different answers and the recommendation should stay at 12.

## Verdict on feasibility

Stated plainly, because the plan is worth little if it implies a promise it
cannot keep:

- **Cap 24: plausible**, but only after Phases 0–2 *and* 3b, and only if 3b's
  measurement supports lowering requests. It is not reachable by configuration
  alone.
- **Cap 32: probably not on this host.** 3a is rejected on coverage, so the
  per-scan Job count is fixed at 3. Cap 32 implies roughly 69 Jobs and ~35 GiB
  of requests on a single node, against a VM that tops out at 24 GiB. Closing
  that needs either a bigger machine or a structural change to how scanning
  works — not a larger number in a ConfigMap.
- **Neither will be faster than 12.** The curve was already flat by 16.

If the answer that matters is "can this cluster scan more per hour", the plan to
run is the one at the end of this document, not this one.

## Rollback

Every phase is independently revertible:

- Phases 0, 1, 3 are chart/code changes behind PRs — revert the PR.
- Phase 2 is a VM rebuild; the DB dump to the host is the rollback, and it must
  be **verified non-empty before destroying anything** (a previous dump reported
  success and protected nothing).
- The live cap is a ConfigMap value; Flux restores it from `main` on resume.

## What would actually make scanning faster

Out of scope here, but worth recording, since "raise the cap" is unlikely to be
the answer to the question people are really asking:

- **Mirror a single platform.** Images average 5.3 platforms and only one is
  ever scanned; the corpus is 79.5 GB all-platform vs 7.8 GB for linux/arm64.
  Less to pull per scan, and far less registry pressure — which is the component
  that broke first.
- **Stop re-scanning unchanged digests.** A mirrored artifact is content-
  addressed and immutable; a re-scan of the same digest with the same DB version
  can only produce the same answer.
- **Give the registry room, or take it off the hot path** (image-level caching
  on the nodes).


---

# Execution outcome, 2026-08-24

**Cap 24 and 32 were not reached. The attempt made the cluster worse before it
was reverted, and the reason is the most useful thing it produced.**

## What shipped and stayed

| PR | change | verdict |
|----|--------|---------|
| #153 | Job deadline 600s→1200s, scanTimeout→1320s | kept — B7 was real |
| #153 | clamav maxReplicas 10→16 | kept |
| #153 | grype Job memory limit → 1536Mi | kept — B4 was real |
| #153 | scan Job resources made configurable | kept — right lever |
| #154 | duplicate key broke the Flux Kustomization | **fixed** |
| #155 | registry logging an OTel span per blob read | **fixed** |
| #156 | request 512Mi→256Mi | **reverted** |

## The finding that matters

Phase 3b — lowering the memory request from 512Mi to 256Mi to match measured
RSS — **took the cluster down**. The VM reached **load average 174 on 6 CPUs**
with 251MB of 16GB free, one node went `NotReady`, and the Kubernetes API
server became unreachable with TLS handshake timeouts.

The measurement behind it was correct: across 38 scan-worker Jobs, RSS was
median 31Mi, p90 264Mi, max 754Mi. A 512Mi request really is ~16x the median.

**The inference was wrong, and this plan contained the reason without drawing
the conclusion.** B2 records that all four k3d "nodes" are containers sharing
one VM, each advertising the whole thing, so the scheduler believes it has
24 CPU / 64GiB against a real 6 and 16. What follows — and what the plan failed
to state — is that **the request is not a reservation on this topology, it is
the only admission control there is.** Nothing else bounds how much work reaches
the hardware. Halving it doubled what the scheduler admitted onto a machine that
had not grown.

B1's table was therefore directionally right and mechanically wrong. The pinning
is real (measured: 26 concurrent Jobs on `agent-0`, 21 `Pending` at cap 12), but
"raise the ceiling by lowering requests" removes the brake rather than widening
the road.

## Two real defects found on the way

Neither was in the plan, and both were doing damage before this started.

**The Flux Kustomization had been broken for hours.** A duplicate
`scanConcurrencyPerKind` key introduced in PR #151 failed `kustomize build`,
freezing everything under `k8s/` at its last good revision. It was invisible
because HelmRelease *chart* upgrades kept flowing normally — they read the chart
directly — so only the HelmRelease's own values were stale. The live cluster
reported `scanConcurrency 8 / unpacker 2` while the committed file said 12.
`check-duplicate-keys` renders the chart and never looks at `k8s/`;
`check-k8s-manifests` now does, and fails on this exact defect.

**The registry was logging at debug.** `registry:3` ships a config defaulting to
`level: debug`, which emits a full OpenTelemetry span as JSON for every storage
operation on every blob of every pull — on the path every scan now takes.
Observed alongside 50-64MB blob reads taking ~236s each. Nothing collects them.

## Revised view of what cap 24 needs

The plan's ordering was wrong. Requests cannot be lowered to buy scheduling
headroom on this topology, so Phase 3b as written is off the table — and with 3a
already rejected on coverage grounds, **the per-scan footprint cannot come down
at all**. That leaves:

1. **Grow the VM** (Phase 2) — 6→8 CPU, 16→24GiB, the host's practical limit.
   Requests then admit proportionally more work onto proportionally more
   hardware, which is the only safe version of this.
2. **Un-pin trivy/grype** (Phase 1) — still needed, but clearly *after* Phase 2
   rather than before. Un-pinning without more hardware only spreads the same
   overload across four fake nodes on one real machine.
3. **Re-measure the registry** at whatever cap results, with debug logging off
   for the first time.

Cap 32 remains out of reach on a 32GiB host, for the reasons already stated.

## Honest status

The cluster is back to a known-good state: all nodes `Ready`, load 9.8, cap
12/12, requests 512Mi, sweep re-enabled, Flux resumed and reconciling. Nothing
from this attempt is left running.
