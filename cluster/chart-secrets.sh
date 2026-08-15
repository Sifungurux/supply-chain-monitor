#!/usr/bin/env bash
# Creates/updates the scm-chart-secrets Secret that
# k8s/releases/supply-chain-monitor-helmrelease.yaml's spec.valuesFrom
# reads postgres.credentials.password, monitorApi.apiKey and the three
# dockerAuth.accounts.*.password values from -- the chart's own
# values.yaml deliberately leaves them all empty, since a real value
# there would sit in plaintext in this repo's git history.
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
#   ./cluster/chart-secrets.sh                 # first run: generates every value
#   POSTGRES_PASSWORD=... ./cluster/chart-secrets.sh   # rotate one, keep the rest
#   REGISTRY_READER_PASSWORD=... ./cluster/chart-secrets.sh   # rotate a registry account
#   POSTGRES_PASSWORD=... API_KEY=... ./cluster/chart-secrets.sh   # pin several (e.g. CI)
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

# read_existing KEY -- the current value of one key, empty if the Secret
# or the key doesn't exist yet. Carrying values over is what makes
# rotating one credential leave the others alone.
read_existing() {
	kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath="{.data.$1}" 2>/dev/null | base64 --decode 2>/dev/null || true
}

# is_placeholder -- true for values that are obviously not credentials.
#
# Carrying values over is the whole point of read_existing, but it means
# the generate-a-random-one branch below only ever fires on a FIRST run,
# against no Secret at all. So a placeholder that got in once is
# preserved by every subsequent run, and re-running this script to
# "rotate credentials" faithfully re-applies it.
#
# Not theoretical: postgres-password sat at "changeme123" in a live
# cluster across several runs of this script. The CI guard could not see
# it either -- that guard greps charts/, where the value correctly is
# not, while the placeholder lived in cluster state.
is_placeholder() {
	case "$1" in
	changeme* | CHANGEME* | ChangeMe* | password | secret | admin | test) return 0 ;;
	esac
	return 1
}

# Recorded here in the PARENT shell, deliberately. Doing this inside
# read_existing would not work: it is called as "$(read_existing ...)",
# which runs in a subshell, so any array append is discarded with it and
# the warning below would never fire.
placeholders_replaced=()

existing_api_keys="$(read_existing api-keys)"
existing_postgres_password="$(read_existing postgres-password)"
existing_api_key="$(read_existing api-key)"
existing_registry_reader="$(read_existing registry-reader-password)"
existing_registry_writer="$(read_existing registry-writer-password)"
existing_registry_admin="$(read_existing registry-admin-password)"

# Blanking it is what makes the generate branch below fire.
if is_placeholder "$existing_postgres_password"; then
	placeholders_replaced+=("postgres-password")
	existing_postgres_password=""
fi
if is_placeholder "$existing_api_key"; then
	placeholders_replaced+=("api-key")
	existing_api_key=""
fi
if is_placeholder "$existing_registry_reader"; then
	placeholders_replaced+=("registry-reader-password")
	existing_registry_reader=""
fi
if is_placeholder "$existing_registry_writer"; then
	placeholders_replaced+=("registry-writer-password")
	existing_registry_writer=""
fi
if is_placeholder "$existing_registry_admin"; then
	placeholders_replaced+=("registry-admin-password")
	existing_registry_admin=""
fi

POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-${existing_postgres_password:-$(openssl rand -hex 24)}}"
API_KEY="${API_KEY:-${existing_api_key:-$(openssl rand -hex 32)}}"
# The three registry accounts (docker_auth). Generated rather than left
# empty on a first run: an empty password means the chart omits that
# account entirely, so monitor-api could not pull from scm-registry at
# all -- which is the correct failure for an unconfigured credential and
# a pointless one for a cluster this script is setting up.
# API_KEY_NAMES is the DESIRED SET of named clients, not an addition to
# it: a name present here keeps its existing key (or gets a fresh one),
# and a name absent from it is dropped. Dropping is how a consumer is
# revoked, so it has to be expressible.
#
# Unset leaves the existing named keys exactly as they are. Without that
# rule, running this script to rotate an unrelated credential would
# silently revoke every named client -- the same carry-over trap that
# left postgres-password on a placeholder for weeks, in the opposite
# direction.
if [ -n "${API_KEY_NAMES:-}" ]; then
	API_KEYS=""
	for name in $(printf '%s' "$API_KEY_NAMES" | tr ',' ' '); do
		[ -n "$name" ] || continue
		# Reuse this client's current key if it already has one, so
		# adding a second consumer does not re-key the first.
		current="$(printf '%s' "$existing_api_keys" | tr ',;' '\n' | while IFS=: read -r n k; do
			[ "$n" = "$name" ] && printf '%s' "$k"
		done)"
		[ -n "$current" ] || current="$(openssl rand -hex 32)"
		# Semicolon, not comma: Flux parses a targetPath valuesFrom
		# value through Helm's strvals, where a comma is a delimiter --
		# a comma-separated value breaks the HelmRelease reconcile
		# outright ("key ... has no value").
		[ -n "$API_KEYS" ] && API_KEYS="${API_KEYS};"
		API_KEYS="${API_KEYS}${name}:${current}"
	done
else
	API_KEYS="$existing_api_keys"
fi

REGISTRY_READER_PASSWORD="${REGISTRY_READER_PASSWORD:-${existing_registry_reader:-$(openssl rand -hex 24)}}"
REGISTRY_WRITER_PASSWORD="${REGISTRY_WRITER_PASSWORD:-${existing_registry_writer:-$(openssl rand -hex 24)}}"
REGISTRY_ADMIN_PASSWORD="${REGISTRY_ADMIN_PASSWORD:-${existing_registry_admin:-$(openssl rand -hex 24)}}"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl create secret generic "$SECRET_NAME" \
	--namespace "$NAMESPACE" \
	--from-literal=postgres-password="$POSTGRES_PASSWORD" \
	--from-literal=api-key="$API_KEY" \
	--from-literal=api-keys="$API_KEYS" \
	--from-literal=registry-reader-password="$REGISTRY_READER_PASSWORD" \
	--from-literal=registry-writer-password="$REGISTRY_WRITER_PASSWORD" \
	--from-literal=registry-admin-password="$REGISTRY_ADMIN_PASSWORD" \
	--dry-run=client -o yaml | kubectl apply -f - >/dev/null

unset POSTGRES_PASSWORD API_KEY API_KEYS
unset REGISTRY_READER_PASSWORD REGISTRY_WRITER_PASSWORD REGISTRY_ADMIN_PASSWORD

if [ ${#placeholders_replaced[@]} -gt 0 ]; then
	echo
	echo "!! Replaced placeholder credential(s): ${placeholders_replaced[*]}"
	echo "!! A placeholder is not a credential, so it was regenerated rather than"
	echo "!! carried over. If postgres-password is in that list the database role"
	echo "!! still has the OLD password -- follow the ALTER ROLE step below, or"
	echo "!! monitor-api will fail to connect on its next restart."
	echo
fi

echo "Secret '${SECRET_NAME}' created/updated in namespace '${NAMESPACE}'."
echo "Next: 'flux reconcile helmrelease supply-chain-monitor -n flux-system --with-source'"
echo "(or just push -- the next reconcile picks this up) to roll it out."
echo
echo "Rotating API_KEY: re-run this script with API_KEY=... -- monitor-api and"
echo "scm-dashboard roll themselves on the next reconcile (both carry a"
echo "checksum/api-key annotation), so no manual restart is needed."
echo
echo "Rotating POSTGRES_PASSWORD: re-run this script with POSTGRES_PASSWORD=...,"
echo "then also run this against scm-postgres before restarting anything --"
echo "Postgres only reads POSTGRES_PASSWORD on initdb against an empty volume,"
echo "so a plain restart against the existing PVC leaves the old password active:"
echo "  kubectl exec -n supply-chain-monitor deploy/scm-postgres -- \\"
echo "    psql -U ${POSTGRES_USER:-monitor_api} -d ${POSTGRES_DB:-monitor_api} -c \\"
echo "    \"ALTER ROLE ${POSTGRES_USER:-monitor_api} WITH PASSWORD '<new password>';\""
echo "Then restart monitor-api so it picks up the new value from the Secret."
echo
echo "Rotating a registry account: re-run with REGISTRY_READER_PASSWORD=... (or"
echo "WRITER/ADMIN). monitor-api and scm-docker-auth both roll themselves on the"
echo "next reconcile. Anyone holding the old password -- including a 'docker"
echo "login' session -- has to log in again."
echo "To retrieve one:"
echo "  kubectl get secret ${SECRET_NAME} -n ${NAMESPACE} \\"
echo "    -o jsonpath='{.data.registry-writer-password}' | base64 --decode"
