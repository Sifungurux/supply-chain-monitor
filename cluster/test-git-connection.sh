#!/usr/bin/env bash
# Verifies that Flux can actually authenticate to the private GitHub
# repo configured in k8s/flux-system/gotk-sync.yaml, *before* you wait
# on Flux's own (much slower) reconcile/retry loop to tell you the same
# thing. Does a plain `git ls-remote` using the exact same credentials
# Flux itself will use (read from the flux-system-git-auth Secret, the
# one `make git-auth` creates), so a pass here means the GitRepository
# should go Ready, and a fail here tells you concretely why before you
# ever touch the cluster.
#
# Usage: ./cluster/test-git-connection.sh [repo-url]
#   repo-url defaults to whatever's in gotk-sync.yaml's GitRepository.spec.url.
#
# Credentials are read, in order:
#   1. GIT_USERNAME / GIT_PASSWORD env vars, if both are set
#   2. the flux-system-git-auth Secret in-cluster (kubectl get secret),
#      if a kubeconfig context is available
#   3. an interactive prompt, same as cluster/git-auth-secret.sh
#
# The token is never printed, logged, or written to a file -- it's
# passed to git via an inline credential helper that only exists for
# the lifetime of this one command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GOTK_SYNC="${REPO_ROOT}/k8s/flux-system/gotk-sync.yaml"
NAMESPACE="flux-system"
SECRET_NAME="flux-system-git-auth"

REPO_URL="${1:-}"
if [ -z "$REPO_URL" ]; then
	# [[:space:]] (POSIX bracket class), not \s -- \s is a GNU-only sed/grep
	# extension and silently fails to match on BSD sed (stock on macOS),
	# which left the whole "  url: https://..." line un-stripped here and
	# made git choke on "protocol '  url: https' is not supported".
	REPO_URL="$(sed -n 's/^[[:space:]]*url:[[:space:]]*//p' "$GOTK_SYNC" | head -n1)"
fi
if [ -z "$REPO_URL" ]; then
	echo "Couldn't determine the repo URL -- pass it explicitly:" >&2
	echo "  $0 https://github.com/<owner>/<repo>.git" >&2
	exit 1
fi

GIT_USERNAME="${GIT_USERNAME:-}"
GIT_PASSWORD="${GIT_PASSWORD:-}"

if [ -z "$GIT_USERNAME" ] || [ -z "$GIT_PASSWORD" ]; then
	if command -v kubectl >/dev/null 2>&1 && kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
		echo "Reading credentials from the in-cluster '${SECRET_NAME}' Secret..."
		GIT_USERNAME="$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.username}' | base64 -d)"
		GIT_PASSWORD="$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.password}' | base64 -d)"
	fi
fi

if [ -z "$GIT_USERNAME" ]; then
	read -r -p "GitHub username (any non-empty value works): " GIT_USERNAME
fi
if [ -z "$GIT_PASSWORD" ]; then
	read -r -s -p "GitHub personal access token (input hidden): " GIT_PASSWORD
	echo
fi

if [ -z "$GIT_USERNAME" ] || [ -z "$GIT_PASSWORD" ]; then
	echo "Missing username/token -- can't test the connection without both." >&2
	exit 1
fi

echo "Testing access to ${REPO_URL} ..."

# Inline credential helper: prints the credentials git asks for on
# stdin/stdout only, for this one process -- nothing touches disk, and
# `set +x` (never set here) plus the fact this whole thing is one
# subshell means the token never appears in shell history either.
helper_script="$(mktemp)"
trap 'rm -f "$helper_script"' EXIT
cat >"$helper_script" <<EOF
#!/usr/bin/env bash
echo "username=${GIT_USERNAME}"
echo "password=${GIT_PASSWORD}"
EOF
chmod +x "$helper_script"

set +e
GIT_TERMINAL_PROMPT=0 git -c credential.helper="$helper_script" ls-remote "$REPO_URL" >/tmp/scm-git-test-refs.txt 2>/tmp/scm-git-test-err.txt
status=$?
set -e

if [ "$status" -eq 0 ]; then
	echo "OK -- connection and authentication succeeded."
	echo "  $(wc -l </tmp/scm-git-test-refs.txt | tr -d ' ') ref(s) found, e.g.:"
	head -3 /tmp/scm-git-test-refs.txt | sed 's/^/    /'
	echo
	echo "Flux's GitRepository should go Ready with these same credentials"
	echo "(run 'make git-auth' first if you haven't already, so Flux uses them too)."
else
	echo "FAILED -- git could not reach or authenticate to the repo." >&2
	echo "--- git's error output ---" >&2
	cat /tmp/scm-git-test-err.txt >&2
	echo "---------------------------" >&2
	echo >&2
	echo "Common causes:" >&2
	echo "  - the token is wrong, expired, or lacks read access to this repo" >&2
	echo "  - the repo doesn't exist at this URL, or the URL/owner/name has a typo" >&2
	echo "    (GitHub returns the same 'repository not found' for both a wrong" >&2
	echo "    token AND a private repo you genuinely can't see, on purpose --" >&2
	echo "    it doesn't reveal whether the repo exists to someone unauthorized)" >&2
	echo "  - this machine's network can't reach github.com at all" >&2
	exit 1
fi
