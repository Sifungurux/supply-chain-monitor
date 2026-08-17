#!/usr/bin/env python3
"""Every workload that connects to Postgres must be admitted by the
NetworkPolicy that fronts it.

WHY THIS EXISTS

scm-postgres-ingress admits pods by label. A workload that talks to
Postgres without a matching entry is denied at the network layer, and
the symptom is "connection refused" -- which reads like a dead database,
not a policy decision. It is invisible until somebody exercises that
workload, and CronJobs that are off by default can sit broken for
months.

This repo has hit it three times:

  - the restore Job carried no labels at all, so every restore was
    denied from the day the policies were created until one was finally
    run;
  - `monitor-api prune` was never admitted, and retention is off by
    default so it has never run;
  - `monitor-api enrich-refresh` was never admitted, found by running it.

Rather than a fourth comment explaining the same trap, this fails the
build. A workload is treated as a Postgres client if its pod spec pulls
POSTGRES_PASSWORD from the credentials Secret -- the one thing every
direct client needs and nothing else does.
"""
import subprocess
import sys

CHART = "charts/supply-chain-monitor"
CREDENTIALS_SECRET = "scm-postgres-credentials"


def render():
    out = subprocess.run(
        ["helm", "template", "scm-ci", CHART, "-n", "supply-chain-monitor",
         # Render workloads that are off by default too: a CronJob
         # nobody has enabled is exactly where this hides.
         "--set", "monitorApi.retention.enabled=true",
         "--set", "monitorApi.enrichment.enabled=true",
         "--set", "postgres.backup.enabled=true"],
        capture_output=True, text=True, check=True,
    )
    import yaml
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def pod_spec(doc):
    kind = doc.get("kind")
    if kind in ("Deployment", "Job"):
        return doc["spec"]["template"]
    if kind == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]
    return None


def uses_postgres(tmpl):
    for c in tmpl["spec"].get("containers", []) + tmpl["spec"].get("initContainers", []):
        for env in c.get("env", []) or []:
            ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}
            if ref.get("name") == CREDENTIALS_SECRET:
                return True
        for src in c.get("envFrom", []) or []:
            if (src.get("secretRef") or {}).get("name") == CREDENTIALS_SECRET:
                return True
    return False


def main():
    docs = render()

    admitted = set()
    # The policy's own subject is Postgres itself, which holds the
    # credentials Secret because it IS the database, not because it
    # connects to one. Excluded by reading the policy's podSelector
    # rather than hardcoding a name, so renaming the service does not
    # silently turn this back into a false positive.
    subject = None
    for d in docs:
        if d.get("kind") != "NetworkPolicy" or d["metadata"]["name"] != "scm-postgres-ingress":
            continue
        subject = (d["spec"].get("podSelector") or {}).get("matchLabels", {}).get("app")
        for rule in d["spec"].get("ingress", []) or []:
            for src in rule.get("from", []) or []:
                labels = (src.get("podSelector") or {}).get("matchLabels") or {}
                if "app" in labels:
                    admitted.add(labels["app"])

    if not admitted:
        print("ERROR: scm-postgres-ingress rendered no pod selectors -- this check is not looking at anything.",
              file=sys.stderr)
        return 1

    failures = []
    for d in docs:
        tmpl = pod_spec(d)
        if tmpl is None or not uses_postgres(tmpl):
            continue
        label = (tmpl.get("metadata", {}).get("labels") or {}).get("app")
        name = d["metadata"]["name"]
        if label is not None and label == subject:
            continue
        if label is None:
            failures.append(f"{d['kind']} {name} connects to Postgres but its pod template sets no 'app' label, "
                            f"so no NetworkPolicy rule can ever match it")
        elif label not in admitted:
            failures.append(f"{d['kind']} {name} connects to Postgres with app={label!r}, which "
                            f"scm-postgres-ingress does not admit (it admits: {', '.join(sorted(admitted))})")

    if failures:
        print("ERROR: workloads that would be denied at the network layer:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print("       The symptom is 'connection refused', which reads like a dead database rather", file=sys.stderr)
        print("       than a policy decision -- see templates/networkpolicy/postgres.yaml.", file=sys.stderr)
        return 1

    print(f"ok:   every Postgres client is admitted by scm-postgres-ingress ({len(admitted)} selectors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
