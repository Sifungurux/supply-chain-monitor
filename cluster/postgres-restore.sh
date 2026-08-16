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
	echo "  For an encrypted backup (.sql.gz.gpg), also set:" >&2
	echo "    GPG_PRIVATE_KEY_FILE=/path/to/privatekey.asc" >&2
	echo "    GPG_PASSPHRASE_FILE=/path/to/passphrase   (only if the key has one)" >&2
	exit 1
fi

# THE PRIVATE KEY IS LENT TO THE CLUSTER, NOT GIVEN TO IT.
#
# Backups are encrypted to a public key precisely so that nothing in
# the cluster can read them -- not the backup job, not anyone who
# walks off with the PVC. Parking the private half in a permanent
# Secret would hand that ability straight back and reduce the whole
# scheme to a shared passphrase with extra steps.
#
# So the key is created as a Secret here, immediately before the
# restore Job, and deleted on the way out -- including on Ctrl-C and
# on failure, which is what the trap is for. It exists in etcd for
# roughly the length of one restore.
KEYFILE="${GPG_PRIVATE_KEY_FILE:-}"
PASSFILE="${GPG_PASSPHRASE_FILE:-}"
cleanup_key() {
	kubectl -n "$NAMESPACE" delete secret scm-backup-decryption --ignore-not-found >/dev/null 2>&1 || true
}

case "$BACKUP" in
*.gpg)
	if [ -z "$KEYFILE" ]; then
		echo "ERROR: ${BACKUP} is encrypted, but GPG_PRIVATE_KEY_FILE is not set." >&2
		echo "  make db-restore BACKUP=${BACKUP} GPG_PRIVATE_KEY_FILE=/path/to/privatekey.asc" >&2
		exit 1
	fi
	if [ ! -r "$KEYFILE" ]; then
		echo "ERROR: cannot read private key file: ${KEYFILE}" >&2
		exit 1
	fi
	;;
*)
	if [ -n "$KEYFILE" ]; then
		echo "Note: ${BACKUP} is not encrypted -- ignoring GPG_PRIVATE_KEY_FILE."
		KEYFILE=""
	fi
	;;
esac

echo "This will restore '${BACKUP}' into the live scm-postgres database, in namespace ${NAMESPACE}."
echo "Existing data is NOT dropped first -- see this script's own comment for what that means."
read -r -p "Type 'yes' to continue: " confirm
if [ "$confirm" != "yes" ]; then
	echo "Aborted."
	exit 1
fi

kubectl -n "$NAMESPACE" delete job scm-postgres-restore --ignore-not-found >/dev/null

if [ -n "$KEYFILE" ]; then
	# Registered before the Secret is created, so an interrupt between
	# the two still tears down cleanly.
	trap cleanup_key EXIT INT TERM
	cleanup_key
	if [ -n "$PASSFILE" ]; then
		kubectl -n "$NAMESPACE" create secret generic scm-backup-decryption \
			--from-file=privatekey.asc="$KEYFILE" \
			--from-file=passphrase="$PASSFILE" >/dev/null
	else
		kubectl -n "$NAMESPACE" create secret generic scm-backup-decryption \
			--from-file=privatekey.asc="$KEYFILE" >/dev/null
	fi
	echo "private key lent to the cluster for this restore -- it is deleted when this script exits."
fi

sed -e "s|__BACKUP_FILE__|${BACKUP}|g" \
	-e "s|__PGSSLMODE__|${PGSSLMODE:-require}|g" \
	"$DIR/postgres-restore-job.template.yaml" | kubectl -n "$NAMESPACE" apply -f -
kubectl -n "$NAMESPACE" wait --for=condition=complete --timeout=120s job/scm-postgres-restore || {
	echo "restore job did not complete -- logs:" >&2
	kubectl -n "$NAMESPACE" logs job/scm-postgres-restore || true
	exit 1
}
kubectl -n "$NAMESPACE" logs job/scm-postgres-restore
kubectl -n "$NAMESPACE" delete job scm-postgres-restore --ignore-not-found >/dev/null
if [ -n "$KEYFILE" ]; then
	cleanup_key
	echo "private key removed from the cluster."
fi
echo "restore complete."
