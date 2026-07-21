#!/usr/bin/env bash
# Lists what's in the scm-postgres-backups PVC by running a tiny,
# throwaway Job that mounts it read-only -- there's no long-running
# pod with that PVC mounted to `kubectl exec` into otherwise (only the
# backup CronJob's own short-lived Jobs touch it). See `make
# db-backups-list`.
set -euo pipefail

NAMESPACE="supply-chain-monitor"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

kubectl -n "$NAMESPACE" delete job scm-postgres-list-backups --ignore-not-found >/dev/null
kubectl -n "$NAMESPACE" apply -f "$DIR/postgres-list-backups-job.yaml"
kubectl -n "$NAMESPACE" wait --for=condition=complete --timeout=60s job/scm-postgres-list-backups
kubectl -n "$NAMESPACE" logs job/scm-postgres-list-backups
kubectl -n "$NAMESPACE" delete job scm-postgres-list-backups --ignore-not-found >/dev/null
