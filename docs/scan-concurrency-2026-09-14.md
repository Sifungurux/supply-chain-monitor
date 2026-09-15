# Scan concurrency on the rack, 2026-09-14 — the cap was never the limit

The [2026-08-24 ramp](scan-concurrency-2026-08-24.md) ran on a single-node
k3d-on-podman VM and broke at cap 16, when `scm-registry` was OOMKilled at its
512Mi limit. That limit is now 2Gi, and the cluster is six real machines
(3 control planes, 3 workers at 8 CPU / 32GiB each) on Longhorn storage.

The expectation going in was a higher ceiling. What the ramp found instead is
that **this cluster was slower than the laptop VM**, and that the scan
concurrency cap had not been the binding constraint at any rung measured.

The cause was a `ReadWriteOnce` PersistentVolumeClaim. Switching the scanner DB
caches to `ReadWriteMany` cut wall-clock 30–42% and per-scan median 46–63% at
every rung — see [After](#after-the-same-ramp-against-readwritemany) below.

## The headline

At every cap from 8 to 24, the limit was a `ReadWriteOnce` PersistentVolumeClaim.

Every isolated scan-worker Job mounts a shared vulnerability-DB cache
(`scm-grype-db-cache`). RWO does not mean "one pod" — it means **one node**.
Jobs scheduled onto the node the volume happens to be attached to run; every
Job scheduled anywhere else sits `Pending`:

```
Multi-Attach error for volume "pvc-f152a1b3-51f2-456b-bb81-94f41c01da57"
Volume is already used by pod(s) scm-scan-1ea3590e1115-9t8k4, ...
```

Observed directly, mid-rung at cap 12:

| Node | grype-db-cache attached | Scan Jobs |
| --- | --- | --- |
| w1 | yes | all **Running** |
| w2 | no | all **Pending** |
| w3 | no | all **Pending** |

84 `FailedAttachVolume` events in that rung alone.

**This is not only a throughput problem.** Scan Jobs carry
`activeDeadlineSeconds: 1200`. A Job that waits 20 minutes for a volume it will
never get is killed by its own deadline and recorded as a **scan failure against
an artifact that was never the problem** — a `scan_timeout` with nothing wrong
upstream. At cap 12 the slowest scan took 1035s, 86% of the way to that.

## Why it was invisible until now

`local-path`, the k3d and dev default, is `hostPath` underneath. There is no
attach/detach controller and no real attachment, so RWO never binds there. Every
measurement this project has taken until today was taken on storage that could
not exhibit the bug. It is the third thing local-path has hidden here, after
cache sizing and Postgres volume ownership.

The consequence was even written down. `docs/operations.md`, explaining why
enrichment data does *not* live on the trivy cache, says attaching that RWO PVC
to a Deployment "would pin every scan-worker Job to monitor-api's node". The
reasoning was correct and was never carried across to the Jobs themselves.

## Method

Identical to the [2026-08-24 ramp](scan-concurrency-2026-08-24.md) wherever it
could be, so caps 8/12/16 compare directly across hardware: the same break
criteria, the same corpus selection (`order by a.id limit 40` over mirrored
artifacts), the same artifacts in the same order at every rung, and
`SCAN_CONCURRENCY` raised together with `SCAN_CONCURRENCY_UNPACKER`.

Break criteria, fixed before the first run:

- any pod `Evicted`, **or**
- any artifact whose scan outcome is not `scanned`, **or**
- any node reporting `DiskPressure=True` **or `MemoryPressure=True`**

`MemoryPressure` is new here. `internal/k8sjob` has no nodeSelector support and
this cluster's three control planes are untainted with 16GiB each, so a large
cap can schedule multi-GB extractions next to etcd. Without this criterion, a
starved control plane would surface later as some unrelated symptom.

A retried `429` is not a break — that is the cap doing its job.

Harness: [`docs/data/scan-concurrency-2026-09-14/ramp.py`](data/scan-concurrency-2026-09-14/ramp.py).
Rungs **8 → 12 → 16 → 24 → 32**.

## Results

| cap | wall | 429 retries | not scanned | peak Pending | scan median | scan p95 | scan max | verdict |
|-----|------|-------------|-------------|--------------|-------------|----------|----------|---------|
| 8  | 1355.7s | 883 | 0 | 18 | 204.2s | 674.4s | 674.5s | clean |
| 12 | 1077.9s | 555 | 0 | 24 | 174.2s | 1014.7s | 1034.7s | clean |
| 16 | 1013.5s | 323 | 0 | 27 | 274.2s | 674.5s | 874.7s | clean |
| 24 | 692.9s | 167 | 0 | 40 | 254.2s | 574.5s | 594.4s | clean |
| 32 | 672.5s | 69 | 0 | 50 | 359.3s | 654.5s | 664.5s | clean |

**No break through cap 32.** No evictions, no failed scans, no node pressure of
either kind, no `scm-registry` restarts, and disk sat flat at 101.4 GB the whole
way — nowhere near the ~786GiB per worker available.

### The numbers do not say "raise the cap"

Wall-clock halves from cap 8 to cap 32 (1356s → 673s), which looks like a clean
win until you ask *why*.

Pods on the node holding the volume share it happily; pods anywhere else block.
So a larger cap does not create more capacity — it creates **more lottery
tickets**. More Jobs are launched, so more of them happen to land on the one
node that can run them. `peak Pending` rising 18 → 50 across the ramp is the
cost of that: at cap 32 every artifact in the corpus was queued simultaneously.

Per-scan latency shows the same thing from the other side. Median *rises* with
the cap (204s → 359s) even as wall-clock falls, because each individual scan
spends longer waiting behind others for the same volume. The ramp is not
measuring scanner throughput at any rung. It is measuring how often the
scheduler guesses right.

### Control planes take a growing share

`scan_jobs_by_node`, counting Job pods observed per node per rung:

| cap | on workers | on control planes |
|-----|-----------|-------------------|
| 12 | 28 | 8 |
| 16 | 34 | 13 |
| 24 | 47 | 25 |
| 32 | 60 | 35 |

By cap 32, **37% of scan Jobs ran on control-plane nodes** — 16GiB machines also
running etcd and the API server. Nothing broke, and the
[2026-09-13 decision](https://github.com/Sifungurux/supply-chain-monitor) to
leave the control planes untainted is what made that spare capacity usable. But
it is now measured rather than assumed, and it is the reason `MemoryPressure`
belongs in the break criteria.

(Cap 8's row is blank: the first run of the harness selected Job pods by a
`scan-` name prefix, and the pods are named `scm-scan-...`, so it recorded an
empty map at every rung. Fixed to select on the `app=scm-scan-worker` label
before rung 12. The rest of cap 8's numbers are unaffected.)

## The fix

`monitorApi.grypeCache.persistence.accessMode` and its trivy counterpart are now
values keys (scm `68ffba2`), defaulting to `ReadWriteOnce` because `local-path`
cannot do `ReadWriteMany` at all and that is what a fresh clone installs onto.

On this cluster they must be `ReadWriteMany`. Longhorn serves RWX through a
share-manager; provisioning was verified here with a throwaway PVC before the
change was written. The DB is read-only to every scan Job — only the primer Job
and the refresh CronJob write it — so concurrent cross-node mounts are safe.

**Applying it is not a values edit alone.** `accessModes` is immutable on a
bound PVC: Helm's pre-upgrade hook fails applying the change, and Flux then
rolls back every other change in the same commit. The order that works is

1. suspend the flux-system Kustomization, then the HelmRelease
2. land the values change
3. delete the PVC, with no scan running
4. resume Flux — the pre-upgrade hook recreates it as RWX, and the primer Job
   repopulates the DB

## After: the same ramp against ReadWriteMany

Applied 2026-09-15 and re-ran every rung. Same cluster, same 40-artifact corpus,
same order, same break criteria. The only intended difference is the access mode.

| cap | wall RWO | wall RWX | | median RWO | median RWX | | p95 RWO | p95 RWX | |
|-----|---------|---------|------|-----------|-----------|------|--------|--------|------|
| 8  | 1356s | **889s** | −34% | 204s | **84s** | −59% | 674s | **314s** | −53% |
| 12 | 1078s | **692s** | −36% | 174s | **94s** | −46% | 1015s | **314s** | −69% |
| 16 | 1014s | **590s** | −42% | 274s | **114s** | −58% | 675s | **314s** | −53% |
| 24 | 693s | **486s** | −30% | 254s | **124s** | −51% | 575s | **314s** | −45% |
| 32 | 672s | **466s** | −31% | 359s | **134s** | −63% | 654s | **314s** | −52% |

Wall-clock fell 30–42% at every rung and per-scan median fell 46–63%. No break
at any rung in either run, and **zero failed scans across all ten**.

### The p95 is the proof

```
p95 across the five RWX rungs, in milliseconds:
  314296  314264  314302  314309  314280
```

**Flat to within 45ms across a 4× range of concurrency caps.** That is the real
scan time of the heaviest artifact in the corpus, and it is the number the
before-run could never see: under RWO the same metric wandered 674 → 1015 → 675
→ 575 → 654s, because it was measuring how long a Job waited for a volume rather
than how long a scan took.

A metric that does not move when you change the cap is measuring work. A metric
that jumps around is measuring queueing. That is the whole difference.

### The deadline is no longer in reach

The worst single scan went from **1035s** — 86% of the 1200s
`activeDeadlineSeconds`, close enough that one slower artifact would have
produced a false `scan_timeout` failure — to **314s**, 26% of it. The failure
mode this fix exists to remove is now nowhere near triggering.

### Queueing stopped growing with the cap

`peak Pending` under RWO climbed with every rung: 18 → 24 → 27 → 40 → 50. Under
RWX it is 18 → 25 → 28 → 24 → 29 — flat, and it *falls* at cap 24 where the old
run was climbing fastest. 429 retries roughly halved at every rung too (883 →
440 at cap 8), because slots free up instead of being held by Jobs that are not
doing anything.

### What the cap means now

It is still not a throughput ceiling — nothing broke at 32, and no node reported
pressure of either kind at any point. But it is now bounded by real work rather
than by scheduling luck, and per-scan latency degrades gently with concurrency
(84 → 134s median across a 4× cap increase) instead of erratically.

Raising the production cap above 12 is now a defensible change rather than a
gamble. It has deliberately been left at 12 pending a decision.

### One new thing to watch

The grype DB primer **OOMKilled twice before succeeding** on the first upgrade
after the switch. The Job completed (Helm saw 1/1) and nothing downstream
noticed, but it had not done that before. RWX on Longhorn is NFS-backed through
a share-manager, which is a different IO path than a local block device, and the
primer downloads and migrates a multi-hundred-MB database. Worth watching on the
next few refreshes; `monitorApi.grypeCache.resources` is the knob if it recurs.

## Harness notes for next time

Two traps beyond the [three already recorded](scan-concurrency-2026-08-24.md),
both of which produce plausible wrong numbers rather than errors:

1. **Suspending the HelmRelease is not enough on this cluster.** The HelmRelease
   is applied by the flux-system Kustomization from the homelab repo, where
   `spec.suspend` is absent — so patching only the HelmRelease works for up to
   one Kustomization interval and is then silently reverted. The first run
   printed `suspend=True` and left Flux fully live. Suspend the Kustomization
   first, and **verify** afterwards: `kubectl patch` exits 0 for a patch that is
   about to be undone by something else.
2. **Select Job pods by label, not name prefix.** An empty result reads exactly
   like "no Jobs ran".
3. **Resume in the same order you suspend: Kustomization first.** The
   Kustomization is what carries new values onto the HelmRelease, so resuming
   the HelmRelease first makes it reconcile against whatever values were in the
   cluster *before* the change. Doing exactly that during the RWX switch
   recreated both PVCs as ReadWriteOnce from a correct RWX commit, and left the
   HelmRelease holding RWX values against RWO volumes — one reconcile away from
   the immutable-field failure the whole procedure exists to avoid. Verify the
   values are present on the HelmRelease *before* resuming it.

Also: deleting these PVCs blocks on the `pvc-protection` finalizer held by
**completed** DB-refresh CronJob pods from previous days. A finished pod still
counts as a consumer; delete those pods and the PVCs release immediately.
