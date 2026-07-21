#!/usr/bin/env bash
# Podman-backed cluster path.
#
# Podman has no bundled Kubernetes control plane, so this runs k3d
# (k3s-in-container) against Podman's Docker-API-compatible socket.
#
# IMPORTANT: k3d's own docs mark Podman support "experimental"
# (https://k3d.io/v5.8.1/usage/advanced/podman/), and there are open
# macOS-specific bugs -- k3d-io/k3d#1388 (cluster creation fails on
# macOS but works with Docker) and #1447 (host.k3d.internal gateway
# error on recent macOS/podman/k3d combos). Prefer the colima runtime
# (the default) unless you have a specific reason to use Podman; if
# cluster creation fails outright here, that's likely one of the above,
# not a mistake in this script.
#
# Sourced by cluster/create-cluster.sh and cluster/destroy-cluster.sh;
# not meant to be run directly.

PROFILE="${SCM_PODMAN_MACHINE:-podman-machine-default}"
CLUSTER_NAME="${SCM_CLUSTER_NAME:-supply-chain-monitor}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

podman_require_tools() {
  local bin
  for bin in podman k3d kubectl jq; do
    if ! command -v "${bin}" >/dev/null 2>&1; then
      echo "${bin} is not installed. It's required for the podman runtime path (brew install ${bin})." >&2
      exit 1
    fi
  done
}

podman_up() {
  podman_require_tools

  if ! podman machine inspect "${PROFILE}" >/dev/null 2>&1; then
    echo "Initializing podman machine '${PROFILE}'..."
    podman machine init "${PROFILE}" \
      --cpus "${SCM_PODMAN_CPU:-4}" \
      --memory "${SCM_PODMAN_MEMORY:-8192}" \
      --disk-size "${SCM_PODMAN_DISK:-40}"
  fi

  local state
  state="$(podman machine inspect "${PROFILE}" 2>/dev/null | jq -r '.[0].State' 2>/dev/null || echo "")"
  if [[ "${state}" != "running" ]]; then
    podman machine start "${PROFILE}"
  fi

  # k3d needs a network with DNS enabled; Podman's default network
  # doesn't provide it (documented k3d+podman requirement).
  podman network inspect k3d >/dev/null 2>&1 || podman network create k3d >/dev/null

  # Point the docker-compatible client at the podman machine's socket
  # (an ssh:// URI on macOS), and load its SSH identity so that works
  # without a passphrase prompt.
  local uri identity
  uri="$(podman system connection ls --format json | jq -r --arg p "${PROFILE}" '.[] | select(.Name==$p) | .URI')"
  identity="$(podman system connection ls --format json | jq -r --arg p "${PROFILE}" '.[] | select(.Name==$p) | .Identity')"
  if [[ -z "${uri}" || "${uri}" == "null" ]]; then
    echo "Could not resolve a podman connection URI for '${PROFILE}'. Run 'podman system connection ls' to inspect." >&2
    exit 1
  fi
  export DOCKER_HOST="${uri}"
  if [[ -n "${identity}" && "${identity}" != "null" ]]; then
    ssh-add "${identity}" >/dev/null 2>&1 || true
  fi

  if k3d cluster list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "${CLUSTER_NAME}"; then
    echo "k3d cluster '${CLUSTER_NAME}' already exists on podman."
  else
    k3d cluster create --config "${SCRIPT_DIR}/../k3d-config.yaml"
  fi

  kubectl config use-context "k3d-${CLUSTER_NAME}"

  echo
  echo "Cluster '${CLUSTER_NAME}' is up on podman machine '${PROFILE}'."
  echo "(This path is experimental -- see the warning at the top of cluster/runtimes/podman.sh.)"
  kubectl cluster-info

  echo
  echo "DOCKER_HOST is set for this script's process only. To 'docker build'"
  echo "against podman in your own shell too, run:"
  echo "  export DOCKER_HOST=${DOCKER_HOST}"
}

podman_down() {
  podman_require_tools
  k3d cluster delete "${CLUSTER_NAME}" 2>/dev/null || true
  if [[ "${1:-}" == "--delete" ]]; then
    podman machine stop "${PROFILE}" 2>/dev/null || true
    podman machine rm -f "${PROFILE}" 2>/dev/null || true
  fi
}
