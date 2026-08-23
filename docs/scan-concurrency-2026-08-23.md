# Scan concurrency ramp, 2026-08-23 — re-deriving the unpacker cap on a 100GB VM

`monitorApi.scanConcurrencyPerKind.unpacker` was **2**, chosen because three
concurrent image scans produced ephemeral-storage evictions on a 42.3GB
filesystem that was already 82% full. That VM was rebuilt at 100GB earlier the
same day, so the number was inherited rather than derived. This ramps it up
until something breaks and settles on the last value that holds.

**Outcome: raised 2 → 8.**

**The ramp found no clean capacity ceiling.** Every value from 2 to 8 completed
its batch with zero failures, zero evictions and `DiskPressure=False`
throughout, and peak disk never left a +8.4…+12.5GB band against ~76GB free.
Disk — the constraint the cap was invented to enforce — stopped binding when
the VM grew. 8 is chosen on blast radius and a throughput measurement, not
because 12 was shown to fail.

What does fail on heavy images is **per-scan memory**, and it is independent of
this cap. That is the more consequential finding and has its own section.

## What this tests

The knob is `monitorApi.scanConcurrencyPerKind.unpacker` — how many whole
image scans may extract at once. It bounds image scans rather than just the
malware leg: scan slots are acquired all-or-nothing across scanner kinds
(`tryAcquireScanSlots`), and trivy's image-mode Jobs extract the whole image
too, so bounding image scans bounds both extractors. `file`/`sbom`/`sarif`
artifacts never take an unpacker slot and are unaffected.

It was set to **2** on the previous cluster, and the reason is on the record
in `k8s/releases/supply-chain-monitor-helmrelease.yaml`: **3 concurrent image
scans is what produced ephemeral-storage evictions** there. That measurement
was taken on a **42.3 GB** filesystem that was already **82% full**.

The cluster was rebuilt on 2026-08-23 at **100 GB**, ~21 GB used. That is not
"a bit more headroom" — it is a different regime, so 2 is no longer a derived
number, it is an inherited one. This re-derives it.

## What counts as "breaks"

Defined before the first run and held to for every rung:

- any pod `Evicted` for ephemeral-storage, **or**
- any scan outcome that is not `scanned`, **or**
- any node `DiskPressure=True`

A **retried 429 is not a break**. That is the cap doing its job — a refused
scan is a 429 with `Retry-After`, never a queue — and the harness reports
retries separately from failures for exactly this reason.

One failure mode is explicitly classified as a *harness* failure and not a
break: `ImagePullBackOff` on `monitor-api:dev`. That image exists only because
`k3d image import` put it in each node's containerd; it has no registry to be
pulled from. Under disk pressure kubelet's image GC deletes it as unused — and
pushing the cap until it breaks is precisely what induces that pressure. The
prior load test (`docs/load-test-2026-08-13.md`) lost a run to this. Recording
it as "concurrency N broke" would corrupt the ramp, so each rung checks for it
separately.

## Method

Sequential ramp, not a bisect: **2 → 3 → 4 → 6 → 8 → 12 → 16**, stopping at the
first rung that breaks. A bisect would attribute a break at 12 to 12 when it
may be cumulative disk from the rungs before it.

Per rung:

1. Set the cap and **verify the value the process actually booted with** by
   reading it back out of the running pod — not merely that the patch was
   accepted. The Flux HelmRelease is **suspended** for the duration; without
   that it reconciles the cap back and every rung silently measures the same
   value.
2. Corpus = the **3×cap heaviest images** of the 95-image corpus, in fixed
   heaviest-first order, with `PARALLELISM=3×cap`. Every rung is therefore
   ~3 waves and the first wave is always the heaviest images available. This
   keeps rung runtime bounded instead of growing with the cap, and puts peak
   concurrent extraction — the thing that actually breaks — early in the run.
3. Record baseline disk, sample disk every 15s, record peak.
4. Reclaim between rungs (delete completed Jobs and Evicted pods) so a break
   is attributable to that rung rather than to leftover scratch.

`SCAN_CONCURRENCY` (global) is **8**. Because slots are all-or-nothing across
kinds, the global becomes the binding cap at unpacker ≥ 8, so it is raised in
step from that rung on. Without that the ramp plateaus on the global and the
plateau reads as a false disk ceiling.

### What this method does not measure

The subset grows with the cap, so a high rung includes lighter images the low
rungs never saw. The first wave is always the heaviest N, so peak extraction
is still heavy-loaded, but per-rung wall clock is **not** comparable across
rungs and is not used as a signal. Only the break criteria and peak disk are.

All four k3d "nodes" share one filesystem, so node count does not multiply the
available disk — `kubectl` reports ~101 GB allocatable ephemeral-storage *per
node* on a 100 GB disk, which is roughly 4× fiction. Requests buy eviction
ranking; they do not buy space.

## Environment

Cluster rebuilt 2026-08-23 immediately before this test (see the TL;DR note
for that rebuild). Every number below is from the new VM.

| | previous cluster | this test |
| --- | --- | --- |
| runtime | podman + k3d | podman + k3d |
| VM | 6 CPU / 16 GiB / **40 GB** | 6 CPU / 16 GiB / **100 GB** |
| disk at rest | 32 GB used, **82% full** | 23G used, 23% full |
| nodes | 1 server + 3 agents | 1 server + 3 agents |
| k3s | v1.35.5+k3s1 | v1.35.5+k3s1 |
| `SCAN_CONCURRENCY` | 8 | 8 (raised in step at unpacker ≥ 8) |
| `SCAN_CONCURRENCY_UNPACKER` | 2 | **under test** |
| `CVE_SCANNER` | both | both |
| `SCAN_TIMEOUT_SECONDS` | 660 | 660 |

Harness: `cluster/load-test-clamav.sh` (unmodified), driven by
`run-step.sh` / `ramp.sh`, against NodePort 30300 rather than a
port-forward. Corpus: `testdata/bulk-test-images.json`, heaviest-first
subset per rung.

The database started **empty** (the rebuild did not restore the previous
dump), so every rung registers into a store well under the 500-artifact
`maxArtifacts` cap and duplicate refusals on re-registration are expected,
not failures.

## Results

Each rung: the 3×cap heaviest images of the corpus, `PARALLELISM` = 3×cap.

| cap | images | scanned | not scanned | OOM kills | evicted | DiskPressure | baseline | peak | delta | 429 retries | wall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **12** | 36 | 34 | 2 | 1 | 0 | no | 29.6 GB | 36.8 GB | **+7.2 GB** | 1248 | 1475s |
| **2** | 6 | 6 | 0 | n/a | 0 | no | 21.4 GB | 29.9 GB | **+8.4 GB** | 180 | 909s |
| **3** | 9 | 9 | 0 | n/a | 0 | no | 23.5 GB | 32.5 GB | **+9.1 GB** | 287 | 891s |
| **4** | 12 | 12 | 0 | 1 | 0 | no | 23.6 GB | 32.1 GB | **+8.5 GB** | 420 | 981s |
| **6** | 18 | 18 | 0 | 2 | 0 | no | 23.8 GB | 35.7 GB | **+11.9 GB** | 398 | 775s |
| **8** | 24 | 24 | 0 | 0 | 0 | no | 23.9 GB | 36.4 GB | **+12.5 GB** | 696 | 855s |
| **8** | 36 | 35 | 1 | -1 | 0 | no | 26.8 GB | 33.5 GB | **+6.8 GB** | 651 | 1066s |

Rows with 36 images are the controlled A/B below, not ramp rungs. OOM columns
marked `n/a` predate the instrumentation; negative values are a `dmesg`
ring-buffer wrap (see "Instrumentation defects").

### The controlled A/B

The rungs above are not directly comparable: corpus size grows with the cap, so
cap=8 met 24 images and cap=12 met 36. This is the one comparison where the cap
is the only variable — **same 36 images, same 16 client connections**:

| cap | scanned | failed | which failed | wall clock |
| --- | --- | --- | --- | --- |
| **8** | 35 | 1 | `mssql/server:2022-latest` | **1066s** |
| **12** | 34 | 2 | `mssql/server`, `dotnet/sdk:8.0` | 1475s |

12 is **39% slower** than 8 on identical work. More concurrency bought
contention, not throughput. That, plus the fact that any value above 8 also
requires raising the global `SCAN_CONCURRENCY` (slots are all-or-nothing across
kinds, so the global otherwise binds first) — which changes behaviour for every
scanner kind, not just image scans — is why 8 is the recommendation.

**The one-failure-versus-two difference is not evidence.** `mssql/server` failed
at cap=8 *and* cap=12, and succeeded at cap=8 in the 24-image rung. It is a
marginal image that flakes, not a threshold being crossed. Single runs cannot
separate 1 from 2 failures here.

## The real constraint: per-scan memory, not concurrency

`isolated_grype.go` hardcodes the grype scan-worker Job's memory limit to
**1Gi**, with no chart or environment override. grype's measured RSS on heavy
images:

```
anon-rss:1043372kB   anon-rss:1043396kB   anon-rss:1043764kB   anon-rss:1043988kB
```

Four independent kills within 600KB of each other — that is one process meeting
one wall, not variable demand. The kernel is unambiguous about which wall:

```
oom-kill:constraint=CONSTRAINT_MEMCG ... task=grype
```

`CONSTRAINT_MEMCG` is the container's own cgroup limit. The VM had 16GiB and was
never close to exhausting it. **This fires regardless of the concurrency cap** —
it happened at cap=2, 3, 4, 6 and 12 alike, and the rate tracks how many heavy
images a rung meets, not how many run at once.

### Why this is worse than it looks

`scan.go:286` sets an artifact `failed` only if **every** scanner failed:

> a partial failure is a successful scan that recorded scan errors

So when grype is OOM-killed and trivy survives, the artifact is reported
`scanned`, with no failure reason. With `CVE_SCANNER=both`, that image silently
got half its CVE coverage and nothing surfaces it. The load-test harness — which
reads terminal status — cannot see it either; only `dmesg` and pod status can.

`mcr.microsoft.com/playwright:v1.44.0` is the case where all three legs died,
which is the only reason it showed up as a failure at all. It is excluded from
the ramp corpus for that reason.

**Recommended fix, not applied here:** raise grype's Job memory limit (~1.5Gi
would clear the observed 1.043GiB with headroom) and make it configurable from
the chart. Changing a hardcoded production default mid-experiment would have
invalidated the ramp, so it is left as a decision to take deliberately.

### Secondary failure mode: registry stream cancellation

`dotnet/sdk:8.0`'s trivy leg failed with:

```
stream error: stream ID 19; CANCEL; received from peer
```

The registry cancelled the pull. Raising concurrency means more simultaneous
pulls from one registry, so this gets worse with the cap — but it is a
registry-side behaviour, not a cluster capacity limit, and it is not something
the cap can be tuned to avoid.

## Instrumentation defects found mid-test

Both of my own, both the same shape — enumerating expected failure names instead
of matching "anything that is not `scanned`". Recorded because they would each
have produced a confidently wrong number.

1. **The OOM blind spot.** Break criteria read the artifact's terminal status,
   which `scan.go:286` leaves as `scanned` on partial scanner failure. Rungs 2
   and 3 were scored clean while grype was being OOM-killed inside them (2 kills
   each, confirmed against `dmesg` afterwards). Fixed by sampling `dmesg` OOM
   counts per rung.

2. **The HTTP-000 miss.** cap=12's first run had **all 36 scans** return
   `http-000`, and the driver scored it `broke=0` and continued to cap=16,
   because the detector matched `failed|timeout|error` and the outcome is named
   `http-000`.

Neither corrupted the conclusion, because each break was diagnosed for cause
rather than accepted at face value — which is the practice that mattered more
than the criteria themselves.

### The HTTP-000 result was the harness, not the cluster

All 36 clients died at the same instant (min = p50 = p95 = max = 199000ms).
Meanwhile monitor-api had **0 restarts**, served 112 requests in that window
(105 of them 429 — the cap working), and answered `healthz` in 0.1ms. Re-running
cap=12 at **16** client connections instead of 36 produced **zero** HTTP 000.

The ceiling is host-side: podman's port forwarding saturates somewhere between
24 and 36 concurrent connections from macOS.

| cap | client conns | result |
| --- | --- | --- |
| 8 | 24 | 24/24 scanned |
| 12 | 36 | 36/36 HTTP 000 |
| 12 | 16 | 34/36 scanned |

**This harness tops out before the cluster does.** Anything above ~24 concurrent
client connections must be driven from inside the cluster, or the transport is
what gets measured. cap=16 was aborted for this reason and is untested.

## What was and was not established

**Established:**
- 2, 3, 4, 6 and 8 all complete cleanly; no evictions or DiskPressure at any value
- disk is no longer the binding constraint at 100GB (+8.4…+12.5GB peak vs ~76GB free)
- cap=3 — the exact value that evicted the old 40GB cluster — is clean here
- 12 is measurably slower than 8 on identical work (1475s vs 1066s)
- grype OOMs at a hardcoded 1Gi limit, independent of concurrency, and is reported as a successful scan

**Not established:**
- any value above 8 being unsafe — 12 was not shown to fail, only to be slower
- cap=16 — untested, aborted on the harness transport limit
- whether 1 vs 2 failures in the A/B means anything — single runs, marginal image
- per-rung wall clock as a throughput curve — corpus size varies by rung, so only the A/B is comparable

**If this needs to go further:** drive the load from inside the cluster to get
past the ~24-connection host ceiling, repeat each rung to separate signal from
flake, and fix the grype memory limit first so heavy images stop failing for a
reason that has nothing to do with concurrency.
