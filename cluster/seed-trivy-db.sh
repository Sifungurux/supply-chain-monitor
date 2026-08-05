#!/usr/bin/env bash
set -euo pipefail

# Mirrors trivy's vulnerability databases into scm-registry, so
# monitor-api can scan images without reaching ghcr.io -- required for
# air-gapped operation. Run this ONCE, from a machine that still has
# internet access, against a running cluster (cluster/create-cluster.sh
# + make deploy already done). It does not need to run again unless you
# want to refresh the mirrored DB.
#
# Requires the oras CLI: brew install oras
# (https://oras.land/docs/installation)
#
# Usage:
#   ./cluster/seed-trivy-db.sh                        # scm-registry via NodePort (localhost:30500, podman runtime)
#   ./cluster/seed-trivy-db.sh <vm-address>:30500      # colima runtime -- use the VM address create-cluster.sh printed
#   ./cluster/seed-trivy-db.sh myregistry.example.com   # any other reachable registry
#
# scm-registry now requires push auth (see README's "Registry
# authentication") -- SCM_WRITER_USERNAME/PASSWORD default to the
# dev-placeholder scm-writer account values.yaml ships
# (dockerAuth.accounts.writer), override both if you've changed them.

REGISTRY="${1:-localhost:30500}"
DB_REF="aquasecurity/trivy-db:2"
JAVA_DB_REF="aquasecurity/trivy-java-db:1"
SCM_WRITER_USERNAME="${SCM_WRITER_USERNAME:-scm-writer}"
SCM_WRITER_PASSWORD="${SCM_WRITER_PASSWORD:-changeme-writer}"

if ! command -v oras >/dev/null 2>&1; then
  echo "oras is not installed. Install it: brew install oras" >&2
  exit 1
fi

echo "Copying ghcr.io/${DB_REF} -> ${REGISTRY}/${DB_REF} ..."
oras cp --to-plain-http --to-username "${SCM_WRITER_USERNAME}" --to-password "${SCM_WRITER_PASSWORD}" "ghcr.io/${DB_REF}" "${REGISTRY}/${DB_REF}"

echo "Copying ghcr.io/${JAVA_DB_REF} -> ${REGISTRY}/${JAVA_DB_REF} ..."
oras cp --to-plain-http --to-username "${SCM_WRITER_USERNAME}" --to-password "${SCM_WRITER_PASSWORD}" "ghcr.io/${JAVA_DB_REF}" "${REGISTRY}/${JAVA_DB_REF}"

echo
echo "Done. scm-registry now has its own copy of both trivy databases."
echo "To make monitor-api use it, set monitorApi.trivyDB.enabled: true and"
echo "fill in these values in charts/supply-chain-monitor/values.yaml's"
echo "monitorApi.trivyDB section (or override them in"
echo "k8s/releases/supply-chain-monitor-helmrelease.yaml's spec.values):"
echo
echo "  TRIVY_DB_REPOSITORY: \"scm-registry.supply-chain-monitor.svc.cluster.local:5000/${DB_REF}\""
echo "  TRIVY_JAVA_DB_REPOSITORY: \"scm-registry.supply-chain-monitor.svc.cluster.local:5000/${JAVA_DB_REF}\""
echo "  TRIVY_SKIP_DB_UPDATE: \"true\""
echo "  TRIVY_SKIP_JAVA_DB_UPDATE: \"true\""
echo
echo "Then: make deploy"
