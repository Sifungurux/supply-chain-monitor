#!/usr/bin/env bash
# Installs the Kubernetes Gateway API CRDs -- required before Traefik's
# kubernetesGateway provider (see k8s/releases/traefik-helmrelease.yaml)
# can watch GatewayClass/Gateway/HTTPRoute objects at all. These are
# upstream, community-maintained CRDs (kubernetes-sigs/gateway-api), not
# something Traefik's own Helm chart installs for you -- same shape of
# problem as Flux's own CRDs, and solved the same way: a small script
# called automatically from create-cluster.sh, standalone via `make
# gateway-api-install`.
#
# "standard" channel, not "experimental" -- this project only uses
# HTTPRoute (see k8s/gateway/), which is standard-channel; the
# experimental channel adds TCPRoute/TLSRoute and other things this repo
# doesn't need yet. Pinned to v1.5.1 (the latest release as of this
# writing) rather than tracking `main`, for the same reproducibility
# reasons every other version pin in this project exists -- bump the
# version below when you deliberately want a newer one.
#
# Idempotent: `kubectl apply` is always safe to re-run.
set -euo pipefail

GATEWAY_API_VERSION="${SCM_GATEWAY_API_VERSION:-v1.5.1}"
MANIFEST_URL="https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

gateway_api_require_tools() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl is not installed. Install it: brew install kubectl" >&2
    exit 1
  fi
}

gateway_api_install() {
  gateway_api_require_tools

  echo "Applying Gateway API CRDs (${GATEWAY_API_VERSION}, standard channel)..."
  # --server-side: the CRD bundle's annotations exceed kubectl's default
  # client-side apply size limit on some versions -- server-side apply
  # is also just the officially recommended way to install these
  # upstream (see the Gateway API project's own install docs).
  kubectl apply --server-side --force-conflicts -f "${MANIFEST_URL}"

  echo "Waiting for the Gateway API CRDs to be Established..."
  gw_crds="$(kubectl get crd -o name 2>/dev/null | grep 'gateway\.networking\.k8s\.io' || true)"
  if [[ -n "${gw_crds}" ]]; then
    # shellcheck disable=SC2086
    kubectl wait --for=condition=Established --timeout=120s ${gw_crds}
  else
    echo "  (no gateway.networking.k8s.io CRDs found yet -- check 'kubectl get crds' if this looks wrong)"
  fi

  echo "Gateway API CRDs installed:"
  kubectl get crd -o name | grep 'gateway\.networking\.k8s\.io' || true
  echo
  echo "Note: Traefik itself (the GatewayClass it registers, and the"
  echo "Gateway/HTTPRoute routing to the dashboard) is Flux-managed --"
  echo "see k8s/releases/traefik-helmrelease.yaml and k8s/gateway/ -- so"
  echo "it only actually appears once this repo is pushed and Flux has"
  echo "reconciled, same as every other service."
}

gateway_api_install
