#!/usr/bin/env bash
# Colima-backed cluster path (recommended default).
#
# `colima start --kubernetes` runs k3s inside the same VM as Docker.
# With the default docker runtime, that VM shares one image store with
# `docker build`, so `make build` alone is enough to make images
# visible to the cluster -- no image-import step needed.
#
# Sourced by cluster/create-cluster.sh and cluster/destroy-cluster.sh;
# not meant to be run directly.

PROFILE="${SCM_COLIMA_PROFILE:-supply-chain-monitor}"
CPU="${SCM_COLIMA_CPU:-4}"
MEMORY="${SCM_COLIMA_MEMORY:-8}"
DISK="${SCM_COLIMA_DISK:-40}"
K8S_VERSION="${SCM_K3S_VERSION:-}"   # optional pin, e.g. v1.29.4+k3s1

colima_require_tools() {
  local bin
  for bin in colima kubectl; do
    if ! command -v "${bin}" >/dev/null 2>&1; then
      echo "${bin} is not installed. Install it: brew install ${bin}" >&2
      exit 1
    fi
  done
}

colima_up() {
  colima_require_tools

  if colima status -p "${PROFILE}" >/dev/null 2>&1; then
    echo "Colima profile '${PROFILE}' is already running."
  else
    echo "Starting Colima profile '${PROFILE}' (cpu=${CPU} memory=${MEMORY}GiB disk=${DISK}GiB)..."
    local args=(start -p "${PROFILE}" --kubernetes
          --cpu "${CPU}" --memory "${MEMORY}" --disk "${DISK}"
          --k3s-arg="--disable=traefik"
          --network-address)
    if [[ -n "${K8S_VERSION}" ]]; then
      args+=(--kubernetes-version "${K8S_VERSION}")
    fi
    colima "${args[@]}"
  fi

  # Colima registers a kubectl context named "colima-<profile>" for named
  # profiles (or plain "colima" for the default profile).
  local context="colima-${PROFILE}"
  if ! kubectl config get-contexts "${context}" >/dev/null 2>&1; then
    context="colima"
  fi
  kubectl config use-context "${context}"

  echo
  echo "Cluster is up on Colima profile '${PROFILE}' (kubectl context: ${context})."
  kubectl cluster-info

  if command -v jq >/dev/null 2>&1; then
    local vm_ip
    vm_ip="$(colima ls --json 2>/dev/null | jq -r "select(.name==\"${PROFILE}\") | .address" 2>/dev/null || true)"
    if [[ -n "${vm_ip}" && "${vm_ip}" != "null" ]]; then
      echo "VM address: ${vm_ip}"
      echo "  API:       curl ${vm_ip}:30300/healthz"
      echo "  Dashboard: http://${vm_ip}:30301"
    fi
  fi
}

colima_down() {
  colima_require_tools
  colima stop -p "${PROFILE}"
  if [[ "${1:-}" == "--delete" ]]; then
    colima delete -p "${PROFILE}" --data --force
  fi
}
