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
# Also handled below (k3d-io/k3d#1082): a non-root user's systemd slice
# only gets memory/pids cgroup delegation by default, not cpu/cpuset/io,
# and k3s hard-requires the cpuset controller -- without the fix in
# podman_cgroup_fixup below, server-0 crashes almost immediately after
# generating its certs with `level=fatal msg="Error: failed to find
# cpuset cgroup (v2)"`, but podman still reports the container as "Up"
# (it's k3s exiting inside a still-running container, not the container
# itself crashing), so this can look like a silent hang rather than a
# clear failure -- if you're debugging one, `podman --connection
# <profile> logs k3d-supply-chain-monitor-server-0` is the first place
# to look, filtering out the repeating "connection refused" noise that
# follows once the apiserver is down.
#
# Sourced by cluster/create-cluster.sh and cluster/destroy-cluster.sh;
# not meant to be run directly.

PROFILE="${SCM_PODMAN_MACHINE:-podman-machine-default}"
CLUSTER_NAME="${SCM_CLUSTER_NAME:-supply-chain-monitor}"
# Deliberately NOT named SCRIPT_DIR: this file is `source`d (not run as
# its own process) into create-cluster.sh's shell, which sets its own
# SCRIPT_DIR for its own later use (e.g. "${SCRIPT_DIR}/install-flux.sh")
# -- reusing that name here would silently clobber it with this file's
# own directory (cluster/runtimes, not cluster/) for the rest of
# create-cluster.sh's run, once this function returns.
PODMAN_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
  local machine_just_started=0
  if [[ "${state}" != "running" ]]; then
    podman machine start "${PROFILE}"
    machine_just_started=1
  fi

  # Delegate the cpuset cgroup controller to the machine's user systemd
  # slice -- see the k3d-io/k3d#1082 note at the top of this file. Only
  # needed once per machine (the delegate.conf drop-in persists across
  # start/stop, though not across `podman machine rm`+`init`), but
  # cheap and idempotent to redo on every fresh start in case an older
  # machine predates this fix or the drop-in was lost some other way.
  # Uses `<<'EOF'` (quoted) so $UID is expanded by the *remote* shell
  # (the podman machine's own UID for its "core" user), not evaluated
  # locally before sending -- those happen to often match on macOS but
  # that's a coincidence this shouldn't rely on.
  if [[ "${machine_just_started}" -eq 1 ]]; then
    echo "Delegating the cpuset cgroup controller inside podman machine '${PROFILE}' (k3d-io/k3d#1082)..."
    podman machine ssh "${PROFILE}" bash -e <<'EOF' || echo "  (cgroup delegation step failed -- if cluster creation later hangs with 'failed to find cpuset cgroup (v2)' in server-0's logs, see k3d-io/k3d#1082 and retry this manually)"
      printf '[Service]\nDelegate=cpuset\n' | sudo tee /etc/systemd/system/user@.service.d/k3d.conf >/dev/null
      sudo systemctl daemon-reload
      sudo systemctl restart "user@$UID"
EOF
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

  # k3d/docker tunnel their API calls over SSH to this port
  # (ssh://user@host:port/...). Podman re-negotiates that forwarded port
  # on every `podman machine start`, so a *different* podman machine (or
  # a previous incarnation of this one) can leave a stale known_hosts
  # entry pointing a different key at the same port number -- OpenSSH
  # then refuses outright ("Host key verification failed"), even though
  # it's a loopback connection to a VM we ourselves just booted (no real
  # MITM risk here to trust it automatically). Purge any stale entry for
  # this exact host:port and let the next connection (k3d's own, right
  # below) record the current key via accept-new instead of failing.
  if [[ "${uri}" =~ ^ssh://([^@]+)@([^:/]+):([0-9]+) ]]; then
    local ssh_user="${BASH_REMATCH[1]}" ssh_host="${BASH_REMATCH[2]}" ssh_port="${BASH_REMATCH[3]}"
    ssh-keygen -R "[${ssh_host}]:${ssh_port}" >/dev/null 2>&1 || true
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
        -p "${ssh_port}" -l "${ssh_user}" "${ssh_host}" true >/dev/null 2>&1 || true
  fi

  if k3d cluster list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "${CLUSTER_NAME}"; then
    echo "k3d cluster '${CLUSTER_NAME}' already exists on podman."
  else
    # SCM_K3D_AGENTS overrides k3d-config.yaml's agent count (k3d CLI
    # flags take precedence over --config) -- set it to grow this into a
    # real multi-node cluster, e.g. for testing whether scm-clamav's
    # replicas (charts/supply-chain-monitor/values.yaml's clamav.replicas)
    # actually spread across nodes and keep up under concurrent scan load
    # (see README's "Scaling ClamAV" and `make load-test-clamav`):
    #   SCM_RUNTIME=podman SCM_K3D_AGENTS=3 ./cluster/create-cluster.sh
    local create_args=(cluster create --config "${PODMAN_SCRIPT_DIR}/../k3d-config.yaml")
    if [[ -n "${SCM_K3D_AGENTS:-}" ]]; then
      create_args+=(--agents "${SCM_K3D_AGENTS}")
    fi
    k3d "${create_args[@]}"
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
