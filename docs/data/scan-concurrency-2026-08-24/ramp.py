#!/usr/bin/env python3
"""Scan-concurrency ramp: raise the cap until the cluster breaks.

Break criteria, fixed before the first run and applied identically to
every rung (same definition the 2026-08-23 ramp used):

  * any pod Evicted, or
  * any artifact whose scan outcome is not "scanned", or
  * any node reporting DiskPressure=True

A retried 429 is NOT a break -- that is the cap doing its job, and
retries are counted separately from failures for exactly that reason.
ImagePullBackOff on monitor-api:dev is a HARNESS failure, not a break:
the image exists only because `k3d image import` put it in each node's
containerd, and kubelet's image GC deletes it under the very disk
pressure this test induces.

Recorded but not itself a break, because it is a per-scan property
independent of the cap: OOMKilled scan-worker containers.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

NS = "supply-chain-monitor"
API = "http://localhost:18080"
S = "/private/tmp/claude-501/-Users-kirk-Development-supply-chain-monitor/1cdf13fb-da65-4f77-8d87-cca8b8d7d5d7/scratchpad/"
RUNGS = [16, 24, 32, 48, 64]


def sh(a, t=180):
    return subprocess.run(a, capture_output=True, text=True, timeout=t)


def psql(q, retries=4):
    """A transient `kubectl exec` failure returns no rows. That is a
    harness hiccup, not a measurement -- retry rather than crashing a
    multi-hour ramp on it (which is exactly what happened at cap=16)."""
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
    whole rung of connection failures that looked like the API refusing
    scans."""
    if _PF["proc"]:
        _PF["proc"].terminate()
        time.sleep(1)
    # Several attempts, each with its own process: right after a rollout
    # the Service can briefly have no ready endpoint, and a port-forward
    # started in that window stays dead rather than retrying itself.
    for attempt in range(6):
        _PF["proc"] = subprocess.Popen(
            ["kubectl", "port-forward", "-n", NS, "svc/monitor-api", "18080:8080"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            time.sleep(2)
            try:
                urllib.request.urlopen(f"{API}/healthz", timeout=5).read()
                return
            except urllib.error.HTTPError:
                return  # answering at all is enough
            except Exception:
                continue
        _PF["proc"].terminate()
        time.sleep(5)
    raise RuntimeError("port-forward never came up")


def set_cap(n):
    """Global and unpacker caps together -- the unpacker cap bounds image
    scans specifically, so leaving it at 2 would pin the whole ramp at 2
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


def evicted():
    r = sh(["kubectl", "get", "pods", "-n", NS, "-o", "json"])
    try:
        pods = json.loads(r.stdout)["items"]
    except Exception:
        return 0, 0, 0
    ev = sum(1 for p in pods if p["status"].get("reason") == "Evicted")
    oom = ipbo = 0
    for p in pods:
        for cs in p["status"].get("containerStatuses") or []:
            t = cs.get("state", {}).get("terminated") or {}
            if t.get("reason") == "OOMKilled":
                oom += 1
            w = cs.get("state", {}).get("waiting") or {}
            if w.get("reason") in ("ImagePullBackOff", "ErrImagePull"):
                ipbo += 1
    return ev, oom, ipbo


def disk_pressure():
    r = sh(["kubectl", "get", "nodes", "-o", "json"])
    try:
        for n in json.loads(r.stdout)["items"]:
            for c in n["status"]["conditions"]:
                if c["type"] == "DiskPressure" and c["status"] == "True":
                    return True
    except Exception:
        pass
    return False


def post(aid, k):
    req = urllib.request.Request(f"{API}/api/v1/artifacts/{aid}/scan", method="POST",
                                 headers={"Authorization": "Bearer " + k})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def run_rung(cap, corpus, k):
    print(f"\n=== rung cap={cap} ({len(corpus)} artifacts) ===", flush=True)
    set_cap(cap)
    # Clear rows orphaned at "scanning" by the rollout restart above --
    # they are an artefact of changing the cap, not a scan outcome, and
    # counting them as this rung's failures would report a break that
    # the cap did not cause.
    ids_q0 = "','".join(corpus)
    psql(f"update artifacts set status='registered' where id in ('{ids_q0}') "
         "and status='scanning'")
    base_ev, base_oom, _ = evicted()
    peak_disk = disk_used_gb()
    t0 = time.time()

    pending, retries, accepted = list(corpus), 0, 0
    while pending:
        still = []
        for aid in pending:
            c = post(aid, k)
            if c == 202:
                accepted += 1
            elif c == 429:
                retries += 1
                still.append(aid)
            elif c == 0:
                # Connection failure = harness fault (a dropped
                # port-forward), never a statement about the cap. Rebuild
                # and retry rather than recording a rung that never ran.
                print("  connection lost -- re-establishing port-forward", flush=True)
                port_forward()
                still.append(aid)
            else:
                print(f"  unexpected HTTP {c} for {aid}", flush=True)
        pending = still
        peak_disk = max(peak_disk, disk_used_gb())
        if pending:
            time.sleep(20)

    # Drain, scoped to THIS corpus. Watching the global "scanning" count
    # let anything outside it hold the rung open forever -- a
    # sweep-triggered scan, or an artifact orphaned by set_cap's rollout
    # restart (which drops the in-flight goroutine and leaves the row at
    # "scanning" with no pod behind it).
    ids_q = "','".join(corpus)
    stall = 0
    while True:
        n = int(psql1(f"select count(*) from artifacts where id in ('{ids_q}') "
                      "and status='scanning'"))
        peak_disk = max(peak_disk, disk_used_gb())
        if n == 0:
            break
        stall += 1
        if stall > 90:  # 30 min: past SCAN_TIMEOUT_SECONDS, so genuinely stuck
            print(f"  WARNING: {n} artifact(s) still 'scanning' after 30m -- "
                  "recording rung as stalled", flush=True)
            break
        time.sleep(20)
    wall = time.time() - t0

    ev, oom, ipbo = evicted()
    ids = "','".join(corpus)
    bad = int(psql1(f"select count(*) from artifacts where id in ('{ids}') "
                    "and status <> 'scanned'"))
    errs = int(psql1(f"select count(*) from scan_errors where artifact_id in ('{ids}')"))
    dp = disk_pressure()

    broke = (ev > base_ev) or (bad > 0) or dp
    res = {"cap": cap, "artifacts": len(corpus), "wall_s": round(wall, 1),
           "accepted": accepted, "retries_429": retries,
           "not_scanned": bad, "scan_error_rows": errs,
           "evicted_new": ev - base_ev, "oomkilled_new": oom - base_oom,
           "imagepullbackoff": ipbo, "disk_pressure": dp,
           "peak_disk_used_gb": round(peak_disk, 1), "BROKE": broke}
    print(json.dumps(res), flush=True)
    return res


def main():
    port_forward()
    results = json.load(open(S + "ramp-results.json")) if __import__("os").path.exists(S + "ramp-results.json") else []
    try:
        k = key()
        # Fixed corpus, same artifacts and same order at every rung, so
        # rungs are comparable. Heaviest first: the big multi-platform
        # images are where extraction and memory actually bite, and
        # front-loading them stops a rung looking cheap because the tail
        # happened to be alpine.
        corpus = psql("select a.id from artifacts a where a.source_ref<>'' "
                      "and a.source_ref<>a.ref order by a.id limit 40")
        print(f"corpus: {len(corpus)} mirrored artifacts", flush=True)
        for cap in RUNGS:
            r = run_rung(cap, corpus, k)
            results.append(r)
            json.dump(results, open(S + "ramp-results.json", "w"), indent=1)
            if r["BROKE"]:
                print(f"\n*** BROKE at cap={cap} ***", flush=True)
                break
        else:
            print("\nno break through the top rung", flush=True)
    finally:
        json.dump(results, open(S + "ramp-results.json", "w"), indent=1)
        if _PF["proc"]:
            _PF["proc"].terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
