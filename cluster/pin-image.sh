#!/usr/bin/env bash
# Pins a locally-imported image against kubelet's image garbage
# collection, on every node of a k3d cluster.
#
# WHY THIS EXISTS
#
# `k3d image import` is the only way monitor-api:dev reaches this
# cluster -- it is built locally and pushed to no registry, so
# containerd has nowhere to re-pull it from. Kubelet's image GC does
# not know that. It frees images when the node filesystem crosses
# --image-gc-high-threshold (85% by default) and, crucially, it only
# considers an image "in use" if a container ON THAT NODE is using it.
#
# So the image survives on whichever node happens to be running
# monitor-api and is collected everywhere else. Nothing notices until a
# Job -- the grype/trivy DB primers, the sweep, a scan worker -- is
# scheduled onto one of those nodes, and then it fails with
#
#   Failed to pull image "monitor-api:dev": ... pull access denied,
#   repository does not exist or may require authorization
#
# which reads like a registry credentials problem and is nothing of the
# kind. If that Job is a Helm hook (the DB primers are), the Helm
# upgrade blocks behind it for its full 15-minute timeout and the
# deploy appears to hang. That happened twice on 2026-08-16.
#
# containerd's CRI plugin honours a `pinned` label and skips those
# images during GC entirely, which is exactly the statement we want to
# make: this image cannot be re-fetched, so never collect it.
#
# The in-cluster registry is NOT an alternative here, though it looks
# like one. scm-registry authenticates through a token realm at
# https://scm-docker-auth...svc.cluster.local:5001/auth -- a cluster-DNS
# name that node-level containerd cannot resolve, and behind a private
# CA it does not trust. Making node pulls work would mean a
# registries.yaml on every node plus a node-reachable auth realm, and
# k3d only writes registries.yaml at cluster CREATION -- i.e. destroy
# and recreate a cluster holding the live database. See README,
# "Why the image is pinned rather than pushed to scm-registry".
set -euo pipefail

IMAGE="${1:-docker.io/library/monitor-api:dev}"
CLUSTER="${2:-supply-chain-monitor}"

if ! command -v k3d >/dev/null 2>&1; then
	echo "pin-image: k3d not found -- nothing to pin (not a k3d cluster?)" >&2
	exit 0
fi

# The loadbalancer node is a proxy container with no containerd, so it
# is excluded rather than allowed to fail.
nodes="$(k3d node list --no-headers 2>/dev/null \
	| awk -v c="$CLUSTER" '$3 == c && $2 != "loadbalancer" { print $1 }')"

if [ -z "$nodes" ]; then
	echo "pin-image: no nodes found for cluster '${CLUSTER}' -- nothing to pin." >&2
	exit 0
fi

failed=0
for node in $nodes; do
	# Not fatal per node: a node that does not have the image yet is a
	# normal state right after it joins, and failing the whole build
	# over it would be worse than the GC problem this prevents.
	if docker exec "$node" ctr -n k8s.io images label \
		"$IMAGE" io.cri-containerd.pinned=pinned >/dev/null 2>&1; then
		echo "pin-image: pinned ${IMAGE} on ${node}"
	else
		echo "pin-image: could not pin ${IMAGE} on ${node} (not present there yet?)" >&2
		failed=$((failed + 1))
	fi
done

if [ "$failed" -gt 0 ]; then
	echo "pin-image: ${failed} node(s) not pinned -- a Job scheduled there can still hit ImagePullBackOff." >&2
fi
