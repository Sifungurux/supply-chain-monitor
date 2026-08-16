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
# authentication"). SCM_WRITER_PASSWORD is REQUIRED: values.yaml ships
# no password for this account any more, so there is no default left to
# fall back to -- and a wrong one would fail as an opaque 401 from the
# registry rather than as the missing-configuration it is. With
# `make chart-secrets`, read it back with:
#
#   kubectl get secret scm-chart-secrets -n flux-system \
#     -o jsonpath='{.data.registry-writer-password}' | base64 --decode

REGISTRY="${1:-localhost:30500}"
DB_REF="aquasecurity/trivy-db:2"
JAVA_DB_REF="aquasecurity/trivy-java-db:1"
SCM_WRITER_USERNAME="${SCM_WRITER_USERNAME:-scm-writer}"
SCM_WRITER_PASSWORD="${SCM_WRITER_PASSWORD:?SCM_WRITER_PASSWORD is required -- values.yaml ships no registry password; see the header of this script for how to read yours back}"

if ! command -v oras >/dev/null 2>&1; then
  echo "oras is not installed. Install it: brew install oras" >&2
  exit 1
fi

echo "Copying ghcr.io/${DB_REF} -> ${REGISTRY}/${DB_REF} ..."
# scm-registry serves TLS by default (registry.tls.enabled), and this
# script runs from the HOST, which does not trust the in-cluster private
# CA. Two ways through:
#
#   SCM_REGISTRY_PLAIN_HTTP=true   the registry is running plain HTTP
#                                  (registry.tls.enabled=false)
#   SCM_REGISTRY_CA=/path/ca.crt   trust the cluster CA, exported with:
#     kubectl -n supply-chain-monitor get secret scm-ca-tls \
#       -o jsonpath='{.data.ca\.crt}' | base64 -d > scm-ca.crt
#
# Neither set means a TLS registry and no CA, which fails with an opaque
# x509 error -- so say so plainly instead.
ORAS_TO_PLAIN_HTTP=""
if [ "${SCM_REGISTRY_PLAIN_HTTP:-false}" = "true" ]; then
	ORAS_TO_PLAIN_HTTP="--to-plain-http"
elif [ -n "${SCM_REGISTRY_CA:-}" ]; then
	SSL_CERT_DIR="/etc/ssl/certs:$(dirname "${SCM_REGISTRY_CA}")"
	export SSL_CERT_DIR
else
	echo "scm-registry serves TLS. Set SCM_REGISTRY_CA=/path/to/ca.crt (see this script's header)," >&2
	echo "or SCM_REGISTRY_PLAIN_HTTP=true if you deployed with registry.tls.enabled=false." >&2
	exit 1
fi

oras cp ${ORAS_TO_PLAIN_HTTP} --to-username "${SCM_WRITER_USERNAME}" --to-password "${SCM_WRITER_PASSWORD}" "ghcr.io/${DB_REF}" "${REGISTRY}/${DB_REF}"

echo "Copying ghcr.io/${JAVA_DB_REF} -> ${REGISTRY}/${JAVA_DB_REF} ..."
oras cp ${ORAS_TO_PLAIN_HTTP} --to-username "${SCM_WRITER_USERNAME}" --to-password "${SCM_WRITER_PASSWORD}" "ghcr.io/${JAVA_DB_REF}" "${REGISTRY}/${JAVA_DB_REF}"

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
