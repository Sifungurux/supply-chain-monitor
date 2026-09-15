#!/usr/bin/env python3
"""Scan-concurrency ramp on the RACK cluster, AFTER the RWX fix.

Identical to docs/data/scan-concurrency-2026-09-14/ramp.py except that it
starts from an empty results file and re-runs every rung. Pair it with
that run's numbers: same corpus, same selection, same break criteria,
same cluster -- the only intended difference is that the scanner DB
cache PVCs are now ReadWriteMany, so scan Jobs are no longer serialized
onto whichever single node the volume happens to be attached to.

Adapted from docs/data/scan-concurrency-2026-08-24/ramp.py. The break
criteria and the corpus selection are deliberately UNCHANGED so rungs are
comparable with the VM runs at caps 8/12/16 -- that comparison is half
the point of running this again on hardware.

Break criteria (fixed before the first run):

  * any pod Evicted, or
  * any artifact whose scan outcome is not "scanned", or
  * any node reporting DiskPressure=True or MemoryPressure=True

MemoryPressure is NEW, and it is here because the rack has no node
pinning for scan Jobs (internal/k8sjob has no nodeSelector support) while
its three control planes are untainted and hold 16GiB each next to etcd.
A cap-32 burst can schedule Jobs there. Without this criterion, etcd
being starved by scan Jobs would show up as some unrelated symptom
minutes later.

A retried 429 is NOT a break -- that is the cap doing its job.

Dropped from the VM harness because they were k3d artefacts:
  * ImagePullBackOff on monitor-api:dev -- the image now comes from ghcr
    by digest, so kubelet image GC cannot delete it out from under a run.

Recorded but not a break (per-scan property, independent of the cap):
  * OOMKilled scan-worker containers (see the 1Gi grype limit).
"""
import json
import os
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

NS = "supply-chain-monitor"
CTX = "rack"
API = "https://localhost:18080"
S = "/private/tmp/claude-501/-Users-kirk-Development-supply-chain-monitor/4951a4b4-4af7-497b-a69d-78bd55c27131/scratchpad/"
OUT = os.path.dirname(os.path.abspath(__file__))
RUNGS = [8, 12, 16, 24, 32]
PROD_CAP = 12          # what the cluster runs, restored on exit
CORPUS_N = 40

# The API serves HTTPS with its own CA. Verification is off because this
# is a port-forward to a pod we already have kubectl credentials for --
# the trust decision was made by kubeconfig, not by this certificate.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def sh(a, t=180):
    """kubectl calls are pinned to the rack context rather than relying
    on whatever the ambient current-context happens to be -- this script
    changes production settings, and picking the wrong cluster because
    someone ran `kubectl config use-context` is not a recoverable
    mistake."""
    if a and a[0] == "kubectl":
        a = [a[0], "--context", CTX] + list(a[1:])
    return subprocess.run(a, capture_output=True, text=True, timeout=t)


def psql(q, retries=4):
    """A transient `kubectl exec` failure returns no rows. That is a
    harness hiccup, not a measurement -- retry rather than crashing a
    multi-hour ramp on it."""
    for attempt in range(retries):
        r = sh(["kubectl", "exec", "-n", NS, "deploy/scm-postgres", "-c", "postgres",
                "--", "psql", "-U", "monitor_api", "-d", "monitor_api", "-tAc", q])
        out = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if out or r.returncode == 0:
            return out
        time.sleep(5 * (attempt + 1))
    return []


def psql1(q, default="0"):
    out = psql(q)
    return out[0] if out else default


def key():
    import base64
    return base64.b64decode(sh(["kubectl", "get", "secret", "scm-monitor-api-auth",
                                "-n", NS, "-o", "jsonpath={.data.API_KEY}"]).stdout).decode()


_PF = {"proc": None}


def port_forward():
    """(Re)establish the port-forward. It binds to ONE pod, and set_cap
    replaces that pod on every rung -- leaving the old one up produced a
    whole rung of connection failures on the VM that looked like the API
    refusing scans."""
    if _PF["proc"]:
        _PF["proc"].terminate()
        time.sleep(1)
    for attempt in range(6):
        _PF["proc"] = subprocess.Popen(
            ["kubectl", "--context", CTX, "port-forward", "-n", NS,
             "svc/monitor-api", "18080:8080"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            time.sleep(2)
            try:
                urllib.request.urlopen(f"{API}/healthz", timeout=5, context=SSL_CTX).read()
                return
            except urllib.error.HTTPError:
                return  # answering at all is enough
            except Exception:
                continue
        _PF["proc"].terminate()
        time.sleep(5)
    raise RuntimeError("port-forward never came up")


def suspend(on):
    """Flux owns monitor-api-config and would revert every rung's cap
    within its interval. The sweep CronJob scans on its own schedule --
    on the VM it made throughput read as 1 scan per 10 minutes until it
    was suspended, then 26 in 8 minutes.

    TWO Flux objects, in this order, and the order is the whole point.
    On this cluster the HelmRelease is not hand-applied: it is applied by
    the flux-system KUSTOMIZATION from the homelab repo, where
    spec.suspend is absent. So patching only the HelmRelease works for
    up to one Kustomization interval and is then silently reverted --
    the first run of this harness printed "suspend=True" and left Flux
    fully live, because the patch landed and was undone minutes later.
    Suspend the Kustomization FIRST so it cannot revert what comes next.

    Verified after patching rather than trusted: `kubectl patch` exits 0
    for a patch that is about to be reverted by something else, so the
    exit code says nothing about whether Flux is actually stopped."""
    order = ["kustomization", "helmrelease"] if on else ["helmrelease", "kustomization"]
    for kind in order:
        name = "flux-system" if kind == "kustomization" else "supply-chain-monitor"
        sh(["kubectl", "patch", kind, name, "-n", "flux-system",
            "--type", "merge", "-p", json.dumps({"spec": {"suspend": bool(on)}})])
    sh(["kubectl", "patch", "cronjob", "scm-sweep-registered", "-n", NS,
        "--type", "merge", "-p", json.dumps({"spec": {"suspend": bool(on)}})])

    if on:
        for kind, name in (("kustomization", "flux-system"),
                           ("helmrelease", "supply-chain-monitor")):
            got = sh(["kubectl", "get", kind, name, "-n", "flux-system",
                      "-o", "jsonpath={.spec.suspend}"]).stdout.strip()
            if got != "true":
                raise RuntimeError(
                    f"{kind}/{name} did not suspend (spec.suspend={got!r}) -- "
                    "refusing to ramp with Flux live, it would revert the cap mid-rung")
    print(f"  flux(kustomization+helmrelease)+sweep suspend={on}", flush=True)


def set_cap(n):
    """Global and unpacker caps together -- the unpacker cap bounds image
    scans specifically, so leaving it low would pin the whole ramp there
    no matter what the global cap said."""
    sh(["kubectl", "patch", "cm", "monitor-api-config", "-n", NS, "--type", "merge",
        "-p", json.dumps({"data": {"SCAN_CONCURRENCY": str(n),
                                   "SCAN_CONCURRENCY_UNPACKER": str(n)}})])
    sh(["kubectl", "rollout", "restart", "deploy/monitor-api", "-n", NS])
    sh(["kubectl", "rollout", "status", "deploy/monitor-api", "-n", NS,
        "--timeout=240s"], t=300)
    time.sleep(10)
    port_forward()


def disk_used_gb():
    r = sh(["kubectl", "exec", "-n", NS, "deploy/scm-registry", "--",
            "df", "-B1", "/var/lib/registry"])
    for line in r.stdout.splitlines()[1:]:
        p = line.split()
        if len(p) >= 3:
            return int(p[2]) / 1e9
    return 0.0


def registry_restarts():
    """The VM ramp broke here: scm-registry OOMKilled at 512Mi serving
    concurrent blobs. It is 2Gi on the rack, which is a guess until it
    is loaded -- so this is measured, not assumed."""
    r = sh(["kubectl", "get", "pods", "-n", NS, "-l", "app=scm-registry", "-o", "json"])
    try:
        pods = json.loads(r.stdout)["items"]
    except Exception:
        return 0
    return sum((cs.get("restartCount") or 0)
               for p in pods for cs in (p["status"].get("containerStatuses") or []))


def pod_stats():
    r = sh(["kubectl", "get", "pods", "-n", NS, "-o", "json"])
    try:
        pods = json.loads(r.stdout)["items"]
    except Exception:
        return 0, 0, 0, {}
    ev = sum(1 for p in pods if p["status"].get("reason") == "Evicted")
    oom = pending = 0
    by_node = {}
    for p in pods:
        if p["status"].get("phase") == "Pending":
            pending += 1
        # Where scan Jobs actually land. No nodeSelector exists for them,
        # so a cap-32 burst can put multi-GB extractions on a 16GiB
        # control plane next to etcd -- this is what makes a break
        # diagnosable rather than just "it broke".
        #
        # Selected by LABEL, not by a name prefix. The first run of this
        # harness matched "scan-" and the pods are named "scm-scan-...",
        # so every rung reported an empty map -- which reads exactly like
        # "no Jobs ran" instead of "the filter is wrong". The label is
        # set in internal/k8sjob/job.go and is not derived from the name.
        if (p["metadata"].get("labels") or {}).get("app") == "scm-scan-worker":
            n = p["spec"].get("nodeName") or "unscheduled"
            by_node[n] = by_node.get(n, 0) + 1
        for cs in p["status"].get("containerStatuses") or []:
            t = cs.get("state", {}).get("terminated") or {}
            if t.get("reason") == "OOMKilled":
                oom += 1
    return ev, oom, pending, by_node


def node_pressure():
    """Returns (disk, memory). MemoryPressure is new for the rack -- see
    the module docstring."""
    r = sh(["kubectl", "get", "nodes", "-o", "json"])
    dp = mp = False
    try:
        for n in json.loads(r.stdout)["items"]:
            for c in n["status"]["conditions"]:
                if c["status"] != "True":
                    continue
                if c["type"] == "DiskPressure":
                    dp = True
                elif c["type"] == "MemoryPressure":
                    mp = True
    except Exception:
        pass
    return dp, mp


def post(aid, k):
    req = urllib.request.Request(f"{API}/api/v1/artifacts/{aid}/scan", method="POST",
                                 headers={"Authorization": "Bearer " + k})
    try:
        with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def durations(corpus):
    """This rung's per-scan durations, from the field the scan itself
    wrote. The TAIL of scan_durations_ms is the most recent scan, which
    is this rung's.

    Deliberately NOT /metrics scm_scan_duration_mean10_seconds: that is
    the pod's last ten scans regardless of artifact, and set_cap
    restarts the pod every rung anyway."""
    ids = "','".join(corpus)
    rows = psql(f"select scan_durations_ms[array_length(scan_durations_ms,1)] "
                f"from artifacts where id in ('{ids}') "
                "and scan_durations_ms is not null")
    out = []
    for r in rows:
        try:
            out.append(int(r))
        except ValueError:
            pass
    return out


def run_rung(cap, corpus, k):
    print(f"\n=== rung cap={cap} ({len(corpus)} artifacts) ===", flush=True)
    set_cap(cap)
    # Clear rows orphaned at "scanning" by the rollout restart above.
    # They are an artefact of changing the cap, not a scan outcome, and
    # the sweep's stale-scanning reclaim is suspended for this run, so
    # nothing else will do it.
    ids_q0 = "','".join(corpus)
    psql(f"update artifacts set status='registered' where id in ('{ids_q0}') "
         "and status='scanning'")
    base_ev, base_oom, _, _ = pod_stats()
    base_reg = registry_restarts()
    peak_disk = disk_used_gb()
    peak_pending = 0
    nodes_seen = {}
    t0 = time.time()

    pending_ids, retries, accepted = list(corpus), 0, 0
    while pending_ids:
        still = []
        for aid in pending_ids:
            c = post(aid, k)
            if c == 202:
                accepted += 1
            elif c == 429:
                retries += 1
                still.append(aid)
            elif c == 0:
                # Connection failure = harness fault (a dropped
                # port-forward), never a statement about the cap.
                print("  connection lost -- re-establishing port-forward", flush=True)
                port_forward()
                still.append(aid)
            else:
                print(f"  unexpected HTTP {c} for {aid}", flush=True)
        pending_ids = still
        peak_disk = max(peak_disk, disk_used_gb())
        _, _, pend, by_node = pod_stats()
        peak_pending = max(peak_pending, pend)
        for n, v in by_node.items():
            nodes_seen[n] = max(nodes_seen.get(n, 0), v)
        if pending_ids:
            time.sleep(20)

    # Drain, scoped to THIS corpus. Watching the global "scanning" count
    # lets anything outside it hold the rung open forever.
    ids_q = "','".join(corpus)
    stall = 0
    while True:
        n = int(psql1(f"select count(*) from artifacts where id in ('{ids_q}') "
                      "and status='scanning'"))
        peak_disk = max(peak_disk, disk_used_gb())
        _, _, pend, by_node = pod_stats()
        peak_pending = max(peak_pending, pend)
        for nd, v in by_node.items():
            nodes_seen[nd] = max(nodes_seen.get(nd, 0), v)
        if n == 0:
            break
        stall += 1
        if stall > 90:  # 30 min: past SCAN_TIMEOUT_SECONDS, so genuinely stuck
            print(f"  WARNING: {n} artifact(s) still 'scanning' after 30m -- "
                  "recording rung as stalled", flush=True)
            break
        time.sleep(20)
    wall = time.time() - t0

    ev, oom, _, _ = pod_stats()
    bad = int(psql1(f"select count(*) from artifacts where id in ('{ids_q}') "
                    "and status <> 'scanned'"))
    dp, mp = node_pressure()
    ds = durations(corpus)
    reg_delta = registry_restarts() - base_reg

    broke = (ev > base_ev) or (bad > 0) or dp or mp
    res = {"cap": cap, "artifacts": len(corpus), "wall_s": round(wall, 1),
           "accepted": accepted, "retries_429": retries,
           "not_scanned": bad,
           "evicted_new": ev - base_ev, "oomkilled_new": oom - base_oom,
           "registry_restarts_new": reg_delta,
           "disk_pressure": dp, "memory_pressure": mp,
           "peak_pending_pods": peak_pending,
           "scan_jobs_by_node": nodes_seen,
           "peak_disk_used_gb": round(peak_disk, 1),
           "scan_ms_n": len(ds),
           "scan_ms_median": int(statistics.median(ds)) if ds else None,
           "scan_ms_p95": int(sorted(ds)[int(len(ds) * 0.95) - 1]) if len(ds) >= 2 else None,
           "scan_ms_max": max(ds) if ds else None,
           "BROKE": broke}
    print(json.dumps(res), flush=True)
    return res


def restore(corpus):
    """Caps FIRST, so a crash part-way through still leaves production
    settings behind rather than a ramp's cap frozen in the ConfigMap."""
    print("\n=== restoring ===", flush=True)
    sh(["kubectl", "patch", "cm", "monitor-api-config", "-n", NS, "--type", "merge",
        "-p", json.dumps({"data": {"SCAN_CONCURRENCY": str(PROD_CAP),
                                   "SCAN_CONCURRENCY_UNPACKER": str(PROD_CAP)}})])
    sh(["kubectl", "rollout", "restart", "deploy/monitor-api", "-n", NS])
    sh(["kubectl", "rollout", "status", "deploy/monitor-api", "-n", NS,
        "--timeout=240s"], t=300)
    if corpus:
        ids = "','".join(corpus)
        psql(f"update artifacts set status='registered' where id in ('{ids}') "
             "and status='scanning'")
    suspend(False)
    print(f"  cap restored to {PROD_CAP}, flux+sweep resumed", flush=True)


def main():
    corpus = []
    # NO resume here, unlike the 2026-09-14 run. This is the AFTER half of
    # an A/B: loading an existing file would concatenate RWO rungs onto
    # RWX ones under the same cap numbers, and the comparison table would
    # be quietly wrong rather than obviously broken.
    results = []
    try:
        port_forward()
        k = key()
        # Fixed corpus, same artifacts and same order at every rung, so
        # rungs are comparable -- and the SAME selection the 2026-08-24
        # VM ramp used, so caps 8/12/16 compare across hardware.
        # (The VM harness's comment claimed "heaviest first"; the SQL
        # has always been `order by a.id`. Kept as-is: changing the
        # order now would break the comparison it exists for.)
        corpus = psql("select a.id from artifacts a where a.source_ref<>'' "
                      f"and a.source_ref<>a.ref order by a.id limit {CORPUS_N}")
        print(f"corpus: {len(corpus)} mirrored artifacts", flush=True)
        if len(corpus) < CORPUS_N:
            print(f"WARNING: wanted {CORPUS_N}, got {len(corpus)}", flush=True)
        suspend(True)
        for cap in RUNGS:
            r = run_rung(cap, corpus, k)
            results.append(r)
            json.dump(results, open(os.path.join(OUT, "ramp-results.json"), "w"), indent=1)
            if r["BROKE"]:
                print(f"\n*** BROKE at cap={cap} ***", flush=True)
                break
        else:
            print("\nno break through the top rung", flush=True)
    finally:
        json.dump(results, open(os.path.join(OUT, "ramp-results.json"), "w"), indent=1)
        try:
            restore(corpus)
        finally:
            if _PF["proc"]:
                _PF["proc"].terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
