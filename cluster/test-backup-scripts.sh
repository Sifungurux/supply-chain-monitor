#!/usr/bin/env bash
# Executes the Postgres backup and restore SHELL LOGIC -- see `make
# test-backup-scripts`.
#
# WHY THIS EXISTS
#
# Everything else in CI checks these two files as text. `helm lint`,
# `helm template` and cluster/check-helm-manifests.sh all confirm the
# manifests render and that encryption is wired up, and none of them
# run a single line of the scripts inside them. That gap is not
# academic: this repo has already shipped a backup job that reported
# success for three days while writing empty files and deleting good
# ones to make room, and every check in CI was green throughout.
#
# The retention change that came with encryption had the same shape.
# Moving the prune from `ls -1t` (mtime, newest first) to sorting by
# the timestamp in the filename is correct only in REVERSE: plain
# ascending order is oldest-first, so the same `tail` that used to drop
# the oldest backups drops the newest ones instead -- silently, nightly,
# while printing the same "pruning to the newest 7" message. It renders
# identically. It lints identically. T3 below is the only thing in this
# repo that can tell the difference.
#
# So this runs the REAL scripts, extracted from the rendered chart and
# the restore template rather than retyped here (a copy would drift and
# then pass while the shipped code broke), in the REAL image, against a
# stub pg_dump/psql. No cluster, no database.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
CHART="charts/supply-chain-monitor"
HELM_IMAGE="alpine/helm:4.2.0"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The image under test is whatever the chart actually deploys, read
# from values.yaml -- pinning it here would let the test drift onto a
# different image than the CronJob uses, which is the one thing it
# must not do.
PG_IMAGE="$(python3 - "$ROOT/$CHART/values.yaml" <<'PY'
import sys, yaml
v = yaml.safe_load(open(sys.argv[1]))["postgres"]["image"]
print(f'{v["repository"]}:{v["tag"]}')
PY
)"
echo "== extracting the shipped scripts (image under test: ${PG_IMAGE}) =="

cd "$ROOT"
printf 'postgres:\n  backup:\n    encryption:\n      publicKeySecret: scm-backup-encryption\n' > "$WORK/enc-values.yaml"
cp "$WORK/enc-values.yaml" "$CHART/.test-backup-enc.yaml"
trap 'rm -rf "$WORK" "$ROOT/$CHART/.test-backup-enc.yaml"' EXIT

docker run --rm -v "$ROOT":/src -w /src "$HELM_IMAGE" template scm "$CHART" \
	--show-only templates/postgres/backup-cronjob.yaml > "$WORK/render-plain.yaml"
docker run --rm -v "$ROOT":/src -w /src "$HELM_IMAGE" template scm "$CHART" \
	-f "$CHART/.test-backup-enc.yaml" \
	--show-only templates/postgres/backup-cronjob.yaml > "$WORK/render-enc.yaml"

python3 - "$WORK" "$ROOT" <<'PY'
import sys, yaml, os, stat
work, root = sys.argv[1], sys.argv[2]

for variant in ("plain", "enc"):
    doc = yaml.safe_load(open(f"{work}/render-{variant}.yaml"))
    args = doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    open(f"{work}/script-{variant}.sh", "w").write(args)

# The restore template is not a chart template -- it is sed'd at
# restore time. Substitute the same placeholder with a shell variable
# so one extracted script can be pointed at either backup.
raw = open(f"{root}/cluster/postgres-restore-job.template.yaml").read()
for variant, var in (("enc", "BKUP_ENC"), ("plain", "BKUP_PLAIN")):
    doc = yaml.safe_load(raw.replace("__BACKUP_FILE__", "${%s}" % var))
    args = doc["spec"]["template"]["spec"]["containers"][0]["args"][0]
    open(f"{work}/restore-{variant}.sh", "w").write(args)

os.makedirs(f"{work}/stubs", exist_ok=True)
stubs = {
    "pg_isready": "#!/bin/sh\nexit 0\n",
    # Emits a real dump header and enough rows that truncation shows up.
    "pg_dump": (
        "#!/bin/sh\n"
        "echo '--'\necho '-- PostgreSQL database dump'\necho '--'\n"
        "echo 'CREATE TABLE t (id int, payload text);'\n"
        "i=0; while [ $i -lt 2000 ]; do echo \"INSERT INTO t VALUES ($i, 'row-$i-payload');\"; i=$((i+1)); done\n"
        "echo '-- PostgreSQL database dump complete'\n"
    ),
    # Connects fine, produces nothing -- the exact failure that ran for
    # three days reporting success.
    "pg_dump_empty": "#!/bin/sh\nexit 0\n",
    "psql": "#!/bin/sh\ncat > /tmp/psql.in\nexit 0\n",
}
for name, body in stubs.items():
    p = f"{work}/stubs/{name}"
    open(p, "w").write(body)
    os.chmod(p, 0o755)
print(f"  extracted {len(stubs)} stubs and 4 scripts")
PY

cp "$DIR/test-backup-scripts-cases.sh" "$WORK/cases.sh"

echo "== running them =="
docker run --rm \
	-v "$WORK":/h \
	--tmpfs /backups:rw,mode=1777 \
	--tmpfs /etc/scm-backup-decryption:rw,mode=1777 \
	-e KEEP_BACKUPS=7 \
	--entrypoint sh "$PG_IMAGE" /h/cases.sh
