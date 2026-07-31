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
    # shellcheck source=cluster/runtimes/colima.sh
    source "${SCRIPT_DIR}/runtimes/colima.sh"
    colima_up
    ;;
  podman)
    # shellcheck source=cluster/runtimes/podman.sh
    source "${SCRIPT_DIR}/runtimes/podman.sh"
    podman_up
    ;;
  *)
    echo "Unknown SCM_RUNTIME '${RUNTIME}' (expected 'colima' or 'podman')" >&2
    exit 1
    ;;
esac

# Flux install piggybacks on cluster-up rather than being a separate
# manual step (see cluster/install-flux.sh and
# k8s/flux-system/README.md) -- set SCM_SKIP_FLUX=1 to skip it
# (e.g. if you're standing the cluster up before helm/kubectl are ready,
# or don't want Flux on this cluster at all) and run `make flux-install`
# yourself whenever you do want it.
if [[ "${SCM_SKIP_FLUX:-0}" != "1" ]]; then
  echo
  echo "Installing Flux (set SCM_SKIP_FLUX=1 to skip this step)..."
  "${SCRIPT_DIR}/install-flux.sh"
else
  echo
  echo "SCM_SKIP_FLUX=1 -- skipping Flux install. Run 'make flux-install' later if you want it."
fi

# Same shape of bootstrap problem as Flux's own CRDs: Traefik's Gateway
# API provider (k8s/releases/traefik-helmrelease.yaml) needs these CRDs
# to exist before it can watch GatewayClass/Gateway/HTTPRoute objects,
# and no Helm chart installs them for you. Set SCM_SKIP_GATEWAY_API=1 to
# skip (e.g. if you don't want Traefik/Gateway API on this cluster at
# all) and run `make gateway-api-install` yourself whenever you do want
# it -- see cluster/install-gateway-api.sh and docs/architecture.md.
if [[ "${SCM_SKIP_GATEWAY_API:-0}" != "1" ]]; then
  echo
  echo "Installing Gateway API CRDs (set SCM_SKIP_GATEWAY_API=1 to skip this step)..."
  "${SCRIPT_DIR}/install-gateway-api.sh"
else
  echo
  echo "SCM_SKIP_GATEWAY_API=1 -- skipping Gateway API CRD install. Run 'make gateway-api-install' later if you want it."
fi
