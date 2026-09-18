#!/usr/bin/env bash
# Proves the credentials that leaked in this repo's git history are dead
# on a live cluster. See `make check-live-secrets`.
#
# Run this against EVERY cluster that has ever had this chart installed,
# not just the current one -- a credential is only rotated where it was
# actually rotated.
#
# A PASS HERE IS A MEASUREMENT, NOT A REASSURANCE. The point is that
# rotation was already done and documented, and nothing ever confirmed
# it took. Postgres in particular reads POSTGRES_PASSWORD only on initdb
# against an empty volume, so rotating the Secret without the ALTER ROLE
# step leaves the old password working while everything looks healthy.
set -euo pipefail

NAMESPACE="supply-chain-monitor"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# THE LEAKED CREDENTIALS, ON PURPOSE, IN PLAINTEXT.
#
# These are the values commit aebf6fe ("remove plaintext default secrets
# from the chart", 2026-08-09) took out of charts/supply-chain-monitor/
# values.yaml. This repository has been PUBLIC since 2026-09-02, so both
# are readable by anyone with `git log -p`. Keeping them here discloses
# nothing that is not already disclosed, and it is the only way to test
# the thing that actually matters: that they no longer work.
#
# They are historical, so this is a list -- a future rotation appends a
# line rather than restructuring anything.
#
# On CI's placeholder grep: cluster/check-helm-manifests.sh greps for
# "changeme" under charts/supply-chain-monitor/ ONLY, so these constants
# living in cluster/ do not trip it. Checked, not assumed -- and worth
# knowing before anyone "fixes" this file by obfuscating the values,
# which would only make the check unreadable.
LEAKED_PG_PASSWORD="changeme123"
LEAKED_API_KEY="qwe4r56789009876543223456789"

KUBECTL=(kubectl)
if [ "${1:-}" = "--context" ]; then
	[ -n "${2:-}" ] || { echo "--context needs a value" >&2; exit 2; }
	KUBECTL=(kubectl --context "$2")
fi

# Printed BEFORE anything runs. A pass read against the wrong cluster is
# worse than no check at all, and the context is the one thing a person
# cannot infer from the output.
echo "Checking cluster context: $("${KUBECTL[@]}" config current-context)"
echo "Namespace:               ${NAMESPACE}"
echo

# await prints the Job's logs and returns its container exit code:
# 0 refused (pass), 1 accepted (fail), 2 inconclusive.
await() {
	local job="$1" waited=0 succeeded="" failed="" code=""
	# Waits for EITHER outcome. `kubectl wait --for=condition=complete`
	# is one-sided and would sit here for the full timeout on exactly
	# the runs that matter -- the ones where the credential still works.
	while [ "$waited" -lt 120 ]; do
		succeeded=$("${KUBECTL[@]}" -n "$NAMESPACE" get job "$job" \
			-o jsonpath='{.status.succeeded}' 2>/dev/null || true)
		failed=$("${KUBECTL[@]}" -n "$NAMESPACE" get job "$job" \
			-o jsonpath='{.status.failed}' 2>/dev/null || true)
		if [ -n "$succeeded" ] || [ -n "$failed" ]; then
			break
		fi
		sleep 3
		waited=$((waited + 3))
	done

	"${KUBECTL[@]}" -n "$NAMESPACE" logs "job/${job}" 2>/dev/null | sed 's/^/    /' || true

	code=$("${KUBECTL[@]}" -n "$NAMESPACE" get pods -l "job-name=${job}" \
		-o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
	# An empty code means the pod never terminated -- still pending, or
	# evicted. That is inconclusive, never a pass.
	[ -n "$code" ] || code=2
	return "$code"
}

cleanup() {
	for job in scm-check-leaked-postgres scm-check-leaked-apikey; do
		"${KUBECTL[@]}" -n "$NAMESPACE" delete job "$job" --ignore-not-found >/dev/null 2>&1 || true
	done
}
trap cleanup EXIT

cleanup
# The manifest ships placeholders so the leaked values live in exactly
# one place (above) rather than in two files that can drift apart.
sed -e "s|PLACEHOLDER_PG_PASSWORD|${LEAKED_PG_PASSWORD}|" \
    -e "s|PLACEHOLDER_API_KEY|${LEAKED_API_KEY}|" \
    "$DIR/check-live-secrets-job.yaml" \
	| "${KUBECTL[@]}" -n "$NAMESPACE" apply -f - >/dev/null

rc=0
for job in scm-check-leaked-postgres scm-check-leaked-apikey; do
	echo "== ${job}"
	if await "$job"; then
		:
	else
		case "$?" in
			1) rc=1 ;;
			# Inconclusive does not downgrade an already-failing run, but
			# it must never leave rc at 0.
			*) [ "$rc" -eq 1 ] || rc=2 ;;
		esac
	fi
	echo
done

case "$rc" in
	0) echo "PASS: every leaked credential is refused by this cluster." ;;
	1) echo "FAIL: a leaked credential still works. Rotate it -- see cluster/chart-secrets.sh." >&2 ;;
	*) echo "INCONCLUSIVE: at least one check could not reach its target. This is NOT a pass." >&2 ;;
esac
exit "$rc"
