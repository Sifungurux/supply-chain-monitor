#!/usr/bin/env bash
set -euo pipefail

# Installs Flux into whatever cluster the current kubectl context points
# at, via the community fluxcd-community/flux2 Helm chart -- not `flux
# bootstrap` (see k8s/flux-system/README.md for why this project chose
# the Helm route). Called automatically from create-cluster.sh so `make
# cluster-up` leaves you with Flux already installed; also runnable
# standalone (`make flux-install`) any time you just want to
# install/upgrade Flux itself against an already-running cluster.
#
# Idempotent: `helm upgrade --install` and `kubectl apply` are both safe
# to re-run.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FLUX_SYSTEM_DIR="${REPO_ROOT}/k8s/flux-system"
NAMESPACE="flux-system"
RELEASE="flux2"
CHART_REPO_URL="https://fluxcd-community.github.io/helm-charts"

flux_require_tools() {
  local bin
  for bin in helm kubectl; do
    if ! command -v "${bin}" >/dev/null 2>&1; then
      echo "${bin} is not installed. Install it: brew install ${bin}" >&2
      exit 1
    fi
  done
  # flux (the CLI) is only used here for a friendlier status check at the
  # end -- everything that actually installs/deploys anything uses helm
  # and kubectl, which are already required above.
}

flux_install() {
  flux_require_tools

  echo "Adding/updating the fluxcd-community Helm repo..."
  helm repo add fluxcd-community "${CHART_REPO_URL}" >/dev/null 2>&1 || true
  helm repo update fluxcd-community >/dev/null

  echo "Creating '${NAMESPACE}' namespace if it doesn't exist..."
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  echo "Installing/upgrading Flux controllers via Helm (release '${RELEASE}')..."
  # Deliberately NOT --wait here: this chart applies its CRDs as regular
  # templates (not Helm's special pre-install crds/ directory), and on a
  # truly fresh install Helm's own readiness check (kstatus) can get
  # stuck reporting a CRD as "InProgress" and time out
  # (`context deadline exceeded`) even though the CRD itself finishes
  # establishing within seconds -- a known rough edge of this specific
  # community chart, not a sign anything is actually wrong. Waiting for
  # each resource type on our own terms below (CRDs via
  # condition=Established, then controller Deployments via
  # condition=Available) sidesteps that flakiness entirely instead of
  # fighting it.
  helm upgrade --install "${RELEASE}" fluxcd-community/flux2 \
    --namespace "${NAMESPACE}" \
    --values "${FLUX_SYSTEM_DIR}/values.yaml" \
    --timeout 5m

  echo "Waiting for Flux's CRDs to be Established..."
  # CRD names are stable across chart versions/releases (unlike Helm
  # release-scoped labels, which this chart doesn't consistently apply
  # to CRDs anyway) -- filter by the toolkit.fluxcd.io group instead of
  # relying on a label selector.
  flux_crds="$(kubectl get crd -o name 2>/dev/null | grep 'toolkit\.fluxcd\.io' || true)"
  if [[ -n "${flux_crds}" ]]; then
    # shellcheck disable=SC2086
    kubectl wait --for=condition=Established --timeout=120s ${flux_crds}
  else
    echo "  (no toolkit.fluxcd.io CRDs found yet -- check 'kubectl get crds' if this looks wrong)"
  fi

  echo "Waiting for Flux controller Deployments to be available..."
  kubectl -n "${NAMESPACE}" wait --for=condition=Available \
    deployment -l app.kubernetes.io/part-of=flux --timeout=180s 2>/dev/null || \
    echo "  (some controller labels may differ across chart versions -- check 'kubectl -n ${NAMESPACE} get pods' if this looked like it skipped anything)"

  echo "Applying the Git sync (GitRepository + root Kustomization, path: ./k8s)..."
  kubectl apply -k "${FLUX_SYSTEM_DIR}/"

  echo
  echo "Checking Git connectivity (informational -- sifungurux/supply-chain-monitor"
  echo "is a private repo, so this needs the flux-system-git-auth Secret to exist)..."
  if kubectl get secret flux-system-git-auth -n "${NAMESPACE}" >/dev/null 2>&1; then
    "${SCRIPT_DIR}/test-git-connection.sh" || \
      echo "  (see above -- fix and re-run 'make git-test' once resolved; this doesn't block install)"
  else
    echo "  Skipped: no flux-system-git-auth Secret yet. Run 'make git-auth' (then"
    echo "  'make git-test' to confirm) -- until then the GitRepository below won't"
    echo "  go Ready against a private repo."
  fi

  echo
  echo "Flux is installed. Current state:"
  kubectl -n "${NAMESPACE}" get pods
  echo
  if command -v flux >/dev/null 2>&1; then
    flux get kustomizations -A || true
    flux get helmreleases -A || true
  else
    echo "(install the 'flux' CLI -- brew install fluxcd/tap/flux -- for a friendlier"
    echo " status view; kubectl works fine without it too:)"
    kubectl -n "${NAMESPACE}" get gitrepositories,kustomizations
    kubectl -n "${NAMESPACE}" get helmreleases
  fi
  echo
  echo "Note: the flux-system GitRepository won't go Ready, and none of the"
  echo "five HelmReleases under k8s/releases/ will reconcile, until:"
  echo "  1. ${FLUX_SYSTEM_DIR}/gotk-sync.yaml's url actually points at a pushed,"
  echo "     reachable remote -- expected if you haven't pushed this repo yet."
  echo "  2. the flux-system-git-auth Secret exists with working credentials --"
  echo "     the repo is private, see 'make git-auth' / 'make git-test' above."
}

flux_install
