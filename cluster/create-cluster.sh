#!/usr/bin/env bash
set -euo pipefail

# Local dev cluster for the supply chain monitor. Two runtime backends
# are supported on macOS -- pick with SCM_RUNTIME=colima|podman
# (defaults to colima):
#
#   colima (default, recommended) -- cluster/runtimes/colima.sh
#     Colima's native --kubernetes flag runs k3s inside the Docker VM
#     and shares its image store with `docker build`.
#
#   podman -- cluster/runtimes/podman.sh
#     Runs k3d against Podman's socket. k3d marks Podman support
#     "experimental" and there are open macOS-specific bugs. Use only
#     if you have a reason to avoid Colima; fall back to colima if
#     cluster creation fails outright.
#
# Examples:
#   ./cluster/create-cluster.sh                   # colima
#   SCM_RUNTIME=podman ./cluster/create-cluster.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${SCM_RUNTIME:-colima}"

case "${RUNTIME}" in
  colima)
    source "${SCRIPT_DIR}/runtimes/colima.sh"
    colima_up
    ;;
  podman)
    source "${SCRIPT_DIR}/runtimes/podman.sh"
    podman_up
    ;;
  *)
    echo "Unknown SCM_RUNTIME '${RUNTIME}' (expected 'colima' or 'podman')" >&2
    exit 1
    ;;
esac
