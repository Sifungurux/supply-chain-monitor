#!/usr/bin/env bash
# Restores a backup from the scm-postgres-backups PVC into the live
# scm-postgres database -- see `make db-restore BACKUP=...` and
# README's "Backing up and restoring Postgres". DESTRUCTIVE: this
# overwrites whatever is currently in the database with the backup's
# contents (it doesn't drop/recreate anything first -- a restore onto
# a non-empty database can fail on conflicting rows/constraints rather
# than silently merging; restoring onto a freshly created, empty
# database is the well-tested path).
set -euo pipefail

NAMESPACE="supply-chain-monitor"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP="${1:-}"

if [ -z "$BACKUP" ]; then
	echo "Usage: $0 <backup-filename>" >&2
	echo "  (see 'make db-backups-list' for what's available)" >&2
	exit 1
fi

echo "This will restore '${BACKUP}' into the live scm-postgres database, in namespace ${NAMESPACE}."
echo "Existing data is NOT dropped first -- see this script's own comment for what that means."
read -r -p "Type 'yes' to continue: " confirm
if [ "$confirm" != "yes" ]; then
	echo "Aborted."
	exit 1
fi

kubectl -n "$NAMESPACE" delete job scm-postgres-restore --ignore-not-found >/dev/null
sed "s|__BACKUP_FILE__|${BACKUP}|g" "$DIR/postgres-restore-job.template.yaml" | kubectl -n "$NAMESPACE" apply -f -
kubectl -n "$NAMESPACE" wait --for=condition=complete --timeout=120s job/scm-postgres-restore || {
	echo "restore job did not complete -- logs:" >&2
	kubectl -n "$NAMESPACE" logs job/scm-postgres-restore || true
	exit 1
}
kubectl -n "$NAMESPACE" logs job/scm-postgres-restore
kubectl -n "$NAMESPACE" delete job scm-postgres-restore --ignore-not-found >/dev/null
echo "restore complete."
