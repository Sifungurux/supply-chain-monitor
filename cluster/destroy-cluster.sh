#!/usr/bin/env bash
set -euo pipefail

# Tear down the local dev cluster. Mirrors create-cluster.sh's runtime
# selection: SCM_RUNTIME=colima|podman (default colima).
#
# Pass --delete to also wipe the underlying VM/machine and its data
# (not just stop it):
#   ./cluster/destroy-cluster.sh --delete
#   SCM_RUNTIME=podman ./cluster/destroy-cluster.sh --delete

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${SCM_RUNTIME:-colima}"

case "${RUNTIME}" in
  colima)
    source "${SCRIPT_DIR}/runtimes/colima.sh"
    colima_down "${1:-}"
    ;;
  podman)
    source "${SCRIPT_DIR}/runtimes/podman.sh"
    podman_down "${1:-}"
    ;;
  *)
    echo "Unknown SCM_RUNTIME '${RUNTIME}' (expected 'colima' or 'podman')" >&2
    exit 1
    ;;
esac
