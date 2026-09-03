#!/usr/bin/env bash
# Re-populates the in-cluster registry from each artifact's source_ref.
#
# WHY THIS EXISTS
#
# The database and the registry are two pieces of state with no
# relationship in backup, and they are coupled: once an artifact has
# been mirrored its `ref` points at scm-registry, so restoring a dump
# into a cluster whose registry PVC is empty leaves every mirrored
# artifact pointing at a 404. That happened on 2026-09-03 -- 91 of 93
# artifacts went to `failed` with MANIFEST_UNKNOWN, and stayed there.
#
# NOTHING SELF-HEALS IT. Mirroring happens at REGISTRATION;
# internal/api/mirror.go's mirrorArtifact returns early when SourceRef
# is already set:
#
#     if h.mirror == nil || a == nil || a.SourceRef != "" { return a }
#
# That guard means "already mirrored", and it cannot tell that case
# apart from "was mirrored, and the mirror is gone" -- so the sweep's
# backfill skips exactly the artifacts that need repairing. This script
# is the repair, and `make db-restore` is incomplete without it.
#
# Idempotent and resumable: an artifact already in the registry is
# skipped after one HEAD, so re-running after a stop is cheap.
#
# DISK-AWARE, because it has to be. A mirror copies EVERY platform
# (measured: 5.3 per image, ~79.5GB for 97 images) while this cluster's
# node has ~81GB free and each scan Job wants up to 2.6GB of it. Filling
# the disk evicts pods; stopping short leaves a smaller registry and a
# clear report. It stops.
#
# Usage:
#   ./cluster/remirror-registry.sh              # copy what is missing
#   ./cluster/remirror-registry.sh --dry-run    # list what it would copy
#
#   SCM_REMIRROR_MIN_FREE_GB=15  stop below this much free (default 15)
#   NAMESPACE=supply-chain-monitor
set -euo pipefail

NAMESPACE="${NAMESPACE:-supply-chain-monitor}"
MIN_FREE_GB="${SCM_REMIRROR_MIN_FREE_GB:-15}"
DRY_RUN=no
case "${1:-}" in
	--dry-run) DRY_RUN=yes ;;
	-h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	"") ;;
	*) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
esac

command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found." >&2; exit 1; }

# Free GB on the registry's own volume. Read from the registry pod
# rather than the node: the PVC is what fills up, and on local-path it
# is the node's disk anyway, so this is the number that matters and the
# one that is true if the storage class ever changes.
free_gb() {
	kubectl exec -n "$NAMESPACE" deploy/scm-registry -- df -P /var/lib/registry 2>/dev/null \
		| awk 'NR==2 {printf "%d", $4/1024/1024}'
}

# id|source_ref|ref for every artifact whose ref points into the mirror.
# source_ref is the upstream the copy comes FROM; ref is where it has to
# land, taken from the row rather than recomputed so this can never
# disagree with what the artifact says it is.
rows="$(kubectl exec -n "$NAMESPACE" deploy/scm-postgres -c postgres -- \
	psql -U monitor_api -d monitor_api -t -A -F'|' -c \
	"select id, source_ref, ref from artifacts
	 where source_ref is not null and source_ref <> '' and ref like '%/mirror/%'
	 order by id;" 2>/dev/null | sed '/^$/d')"

total="$(printf '%s\n' "$rows" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "$total" = "0" ]; then
	echo "Nothing to do: no artifact has both a source_ref and a mirrored ref."
	exit 0
fi

echo "== $total mirrored artifact(s); $(free_gb)GB free, floor ${MIN_FREE_GB}GB =="
echo

# NO CREDENTIALS ON A COMMAND LINE. The obvious spelling passes
# --to-username/--to-password, which puts the registry password in the
# POD's process list -- readable by anything that can exec into it or
# read /proc, in a pod that runs scan tooling against untrusted images.
# Keeping it off the caller's machine is not enough; the first version of
# this script got that half right and shipped the other half wrong.
#
# internal/scanner/mirror.go has the same problem and solves it the same
# way: a docker config file passed as --to-registry-config. This builds
# one inside the pod from the pod's OWN environment, 0600, in a
# trap-cleaned temp dir, so the secret never leaves the process that
# already had it and never reaches an argv.
#
# shellcheck disable=SC2016
AUTH_PREAMBLE='
	set -e
	d="$(mktemp -d)"
	trap '"'"'rm -rf "$d"'"'"' EXIT
	cfg="$d/config.json"
	umask 077
	printf "{\"auths\":{\"%s\":{\"auth\":\"%s\"}}}" \
		"$REGISTRY_ADDR" \
		"$(printf "%s:%s" "$MIRROR_REGISTRY_USERNAME" "$MIRROR_REGISTRY_PASSWORD" | base64 | tr -d "\n")" \
		> "$cfg"
'

copied=0; skipped=0; failed=0; stopped=no
while IFS='|' read -r id src dst; do
	[ -n "$id" ] || continue

	avail="$(free_gb)"
	if [ -z "$avail" ]; then
		echo "ERROR: could not read free space from the registry pod; stopping." >&2
		stopped=yes
		break
	fi
	if [ "$avail" -lt "$MIN_FREE_GB" ]; then
		echo
		echo "STOPPING: ${avail}GB free is below the ${MIN_FREE_GB}GB floor."
		echo "Re-run after making room; everything already copied is kept."
		stopped=yes
		break
	fi

	# Already there? One manifest HEAD, which is also the only honest
	# test -- the registry either serves this ref or it does not.
	# shellcheck disable=SC2016
	if kubectl exec -n "$NAMESPACE" deploy/monitor-api -- sh -c "$AUTH_PREAMBLE"'
			oras manifest fetch --descriptor --registry-config "$cfg" -- "$0"' \
			"$dst" >/dev/null 2>&1; then
		skipped=$((skipped+1))
		printf '  skip  %s\n' "$src"
		continue
	fi

	if [ "$DRY_RUN" = yes ]; then
		printf '  COPY  %s\n' "$src"
		copied=$((copied+1))
		continue
	fi

	# --recursive to bring the artifact's OCI referrers (SBOMs,
	# attestations) with it, matching internal/scanner/mirror.go's
	# copyArgs -- a re-mirror that dropped them would silently reduce
	# what a later scan can see.
	# shellcheck disable=SC2016
	if kubectl exec -n "$NAMESPACE" deploy/monitor-api -- sh -c "$AUTH_PREAMBLE"'
			oras copy --recursive --to-registry-config "$cfg" -- "$0" "$1"' \
			"$src" "$dst" >/dev/null 2>&1; then
		copied=$((copied+1))
		printf '  ok    %s  (%sGB free)\n' "$src" "$avail"
	else
		failed=$((failed+1))
		printf '  FAIL  %s\n' "$src"
	fi
done <<EOF
$rows
EOF

echo
echo "copied=$copied skipped=$skipped failed=$failed of $total  ($(free_gb)GB free)"
if [ "$stopped" = yes ]; then
	echo
	echo "Stopped before finishing. The artifacts not reached are still pointing at"
	echo "a ref this registry does not serve, and will keep scanning as failed."
	exit 1
fi
if [ "$failed" -gt 0 ]; then
	echo
	echo "Some copies failed. Those artifacts keep failing to scan until they land."
	exit 1
fi
