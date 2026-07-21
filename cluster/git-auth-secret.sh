#!/usr/bin/env bash
# Creates/updates the flux-system-git-auth Secret that
# k8s/flux-system/gotk-sync.yaml's GitRepository references via
# spec.secretRef -- required because sifungurux/supply-chain-monitor is
# a private repo, so Flux's source-controller needs real credentials to
# clone it over HTTPS.
#
# This script never writes your credentials to disk anywhere in this
# repo, and the Secret it creates is cluster state, not a committed
# file -- re-run it any time you rotate the token.
#
# What you need: a GitHub Personal Access Token with read access to
# this repo (a fine-grained PAT scoped to just this repo, "Contents:
# Read-only", is enough -- a classic PAT with the "repo" scope also
# works if you'd rather not fuss with fine-grained scoping). Create one
# at https://github.com/settings/tokens.
#
# Usage:
#   ./cluster/git-auth-secret.sh                 # prompts for username + token
#   GIT_USERNAME=you GIT_PASSWORD=ghp_xxx ./cluster/git-auth-secret.sh   # non-interactive (e.g. CI)
#
# GIT_USERNAME can be your actual GitHub username or literally anything
# non-empty -- GitHub's HTTPS auth only checks the token itself, but
# source-controller's Secret schema requires both keys to be present.
set -euo pipefail

NAMESPACE="flux-system"
SECRET_NAME="flux-system-git-auth"

if ! command -v kubectl >/dev/null 2>&1; then
	echo "kubectl is not installed. Install it: brew install kubectl" >&2
	exit 1
fi

GIT_USERNAME="${GIT_USERNAME:-}"
GIT_PASSWORD="${GIT_PASSWORD:-}"

if [ -z "$GIT_USERNAME" ]; then
	read -r -p "GitHub username (any non-empty value works): " GIT_USERNAME
fi
if [ -z "$GIT_USERNAME" ]; then
	echo "Username can't be empty." >&2
	exit 1
fi

if [ -z "$GIT_PASSWORD" ]; then
	read -r -s -p "GitHub personal access token (input hidden): " GIT_PASSWORD
	echo
fi
if [ -z "$GIT_PASSWORD" ]; then
	echo "Token can't be empty." >&2
	exit 1
fi

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl create secret generic "$SECRET_NAME" \
	--namespace "$NAMESPACE" \
	--type kubernetes.io/basic-auth \
	--from-literal=username="$GIT_USERNAME" \
	--from-literal=password="$GIT_PASSWORD" \
	--dry-run=client -o yaml | kubectl apply -f - >/dev/null

unset GIT_PASSWORD

echo "Secret '${SECRET_NAME}' created/updated in namespace '${NAMESPACE}'."
echo "Next: run 'make git-test' to verify these credentials actually work"
echo "before waiting on Flux to reconcile."
