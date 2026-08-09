#!/usr/bin/env bash
# Creates/updates the scm-chart-secrets Secret that
# k8s/releases/supply-chain-monitor-helmrelease.yaml's spec.valuesFrom
# reads postgres.credentials.password and monitorApi.apiKey from -- the
# chart's own values.yaml deliberately leaves both empty, since a real
# value there would sit in plaintext in this repo's git history.
#
# Lives in the flux-system namespace, not supply-chain-monitor -- Flux
# requires a valuesFrom Secret to be in the same namespace as the
# HelmRelease object itself (flux-system), not the release's own
# targetNamespace. Same pattern as flux-system-git-auth
# (git-auth-secret.sh) for exactly that reason.
#
# This script never writes either value to disk anywhere in this repo,
# and the Secret it creates is cluster state, not a committed file --
# re-run it any time you rotate either value. A value you don't provide
# is left as-is (carried over from the existing Secret) so that rotating
# one credential never silently regenerates the other; on first run,
# with no existing Secret, unprovided values are generated for you
# (openssl rand) rather than left to a weak hand-typed default.
#
# Usage:
#   ./cluster/chart-secrets.sh                 # first run: generates both values
#   POSTGRES_PASSWORD=... ./cluster/chart-secrets.sh   # rotate one, keep the other
#   POSTGRES_PASSWORD=... API_KEY=... ./cluster/chart-secrets.sh   # pin both (e.g. CI)
set -euo pipefail

NAMESPACE="flux-system"
SECRET_NAME="scm-chart-secrets"

if ! command -v kubectl >/dev/null 2>&1; then
	echo "kubectl is not installed. Install it: brew install kubectl" >&2
	exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl is not installed -- needed to generate a password/key if you don't supply your own." >&2
	exit 1
fi

existing_postgres_password="$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.postgres-password}' 2>/dev/null | base64 --decode 2>/dev/null || true)"
existing_api_key="$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.api-key}' 2>/dev/null | base64 --decode 2>/dev/null || true)"

POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-${existing_postgres_password:-$(openssl rand -hex 24)}}"
API_KEY="${API_KEY:-${existing_api_key:-$(openssl rand -hex 32)}}"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl create secret generic "$SECRET_NAME" \
	--namespace "$NAMESPACE" \
	--from-literal=postgres-password="$POSTGRES_PASSWORD" \
	--from-literal=api-key="$API_KEY" \
	--dry-run=client -o yaml | kubectl apply -f - >/dev/null

unset POSTGRES_PASSWORD API_KEY

echo "Secret '${SECRET_NAME}' created/updated in namespace '${NAMESPACE}'."
echo "Next: 'flux reconcile helmrelease supply-chain-monitor -n flux-system --with-source'"
echo "(or just push -- the next reconcile picks this up) to roll it out."
echo
echo "Rotating API_KEY: re-run this script with API_KEY=..., then restart"
echo "monitor-api and scm-dashboard -- Flux/Helm won't restart pods on its own"
echo "for a Secret-content-only change."
echo
echo "Rotating POSTGRES_PASSWORD: re-run this script with POSTGRES_PASSWORD=...,"
echo "then also run this against scm-postgres before restarting anything --"
echo "Postgres only reads POSTGRES_PASSWORD on initdb against an empty volume,"
echo "so a plain restart against the existing PVC leaves the old password active:"
echo "  kubectl exec -n supply-chain-monitor deploy/scm-postgres -- \\"
echo "    psql -U ${POSTGRES_USER:-monitor_api} -d ${POSTGRES_DB:-monitor_api} -c \\"
echo "    \"ALTER ROLE ${POSTGRES_USER:-monitor_api} WITH PASSWORD '<new password>';\""
echo "Then restart monitor-api so it picks up the new value from the Secret."
