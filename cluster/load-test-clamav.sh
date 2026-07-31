#!/usr/bin/env bash
# Load-tests the register->scan pipeline against a real, concurrent batch
# of artifacts, specifically to answer "does scm-clamav (see README's
# "Scaling ClamAV") become a bottleneck once many scans land at once, and
# does raising clamav.replicas actually help" -- rather than guessing
# from clamav.replicas alone. Needs `make port-forward` running in
# another terminal first (or PORT_FORWARD=0 if you already have some
# other route to monitor-api, e.g. NodePort 30300).
#
# What it does:
#   1. Bulk-registers testdata/bulk-test-images.json (100 image refs,
#      see README's "Registering many artifacts at once") via
#      POST /api/v1/artifacts/bulk.
#   2. Fires POST /api/v1/artifacts/{id}/scan for every artifact that
#      registered, PARALLELISM at a time (there's no batch-scan endpoint
#      -- see docs/architecture.md, scan is one-artifact-per-request by
#      design), timing each request.
#   3. Reports success/failure counts and latency (min/avg/max/total
#      wall clock) so a before/after comparison across different
#      clamav.replicas values (and, on the podman/k3d runtime, different
#      SCM_K3D_AGENTS node counts -- see cluster/k3d-config.yaml) is
#      actually a comparison of numbers, not vibes.
#
# Examples:
#   make load-test-clamav
#   PARALLELISM=20 ./cluster/load-test-clamav.sh
#   # compare against a scaled-up clamav:
#   helm upgrade supply-chain-monitor charts/supply-chain-monitor \
#     -n supply-chain-monitor --reuse-values --set clamav.replicas=4
#   ./cluster/load-test-clamav.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

API_BASE="${API_BASE:-http://localhost:8080}"
# Matches Makefile's test-artifact default (the dev-only key baked into
# charts/supply-chain-monitor/values.yaml's monitorApi.apiKey) -- override
# if you've rotated it.
SCM_API_KEY="${SCM_API_KEY:-qwe4r56789009876543223456789}"
BATCH_FILE="${BATCH_FILE:-${REPO_ROOT}/testdata/bulk-test-images.json}"
# How many /scan requests to have in flight at once -- this is the knob
# that actually puts concurrent load on clamd; raise it toward (or past)
# clamav.replicas to see queuing show up as rising latency/timeouts.
PARALLELISM="${PARALLELISM:-10}"

for bin in curl jq xargs; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    echo "${bin} is required but not installed." >&2
    exit 1
  fi
done

# Portable millisecond timestamp. `date +%s%3N` is a GNU-date-ism -- on
# macOS's stock BSD date, %N isn't recognized and prints a literal "N"
# (e.g. "1784996920N"), which then blows up as soon as it hits arithmetic
# ("value too great for base"). Prefer gdate (brew's coreutils) if
# present, else use GNU date's %N only after confirming it actually
# produced digits, else fall back to whole-second precision -- coarser,
# but always a valid integer everywhere.
now_ms() {
  if command -v gdate >/dev/null 2>&1; then
    gdate +%s%3N
    return
  fi
  local candidate
  candidate="$(date +%s%3N 2>/dev/null)"
  if [[ "${candidate}" =~ ^[0-9]+$ ]]; then
    echo "${candidate}"
  else
    echo "$(( $(date +%s) * 1000 ))"
  fi
}
export -f now_ms

if [[ ! -f "${BATCH_FILE}" ]]; then
  echo "Batch file not found: ${BATCH_FILE}" >&2
  exit 1
fi

echo "Bulk-registering $(jq '.artifacts | length' "${BATCH_FILE}") artifacts from ${BATCH_FILE}..."
# Captured with an explicit -w/http_code split and an explicit `||`
# guard (rather than a bare `bulk_response="$(curl ...)"` that `set -e`
# would kill with zero output on failure) so an unreachable API
# (`make port-forward` not running -- the documented prerequisite) or an
# auth/server error fails loud, with a message explaining why, instead of
# the script just silently stopping.
bulk_http="$(curl -s -w '\n%{http_code}' -X POST "${API_BASE}/api/v1/artifacts/bulk" \
  -H "Authorization: Bearer ${SCM_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d @"${BATCH_FILE}")" || {
  echo "Could not reach ${API_BASE} -- is 'make port-forward' running in another terminal (or API_BASE set correctly)?" >&2
  exit 1
}
bulk_status="${bulk_http##*$'\n'}"
bulk_response="${bulk_http%$'\n'*}"
if [[ "${bulk_status}" != "200" && "${bulk_status}" != "201" ]]; then
  echo "Bulk registration failed: HTTP ${bulk_status}" >&2
  echo "${bulk_response}" >&2
  exit 1
fi

created="$(echo "${bulk_response}" | jq -r '.created // 0')"
# Duplicates (see docs/architecture.md, "Digest-based duplicate-
# registration detection") are neither created nor failed -- an artifact
# that already exists by digest is a perfectly normal, expected outcome
# of rerunning this exact fixed batch file a second time, not a problem.
# Reporting only created/failed here used to print "0 created, 0 failed"
# on every rerun after the first, which reads exactly like the script
# silently did nothing -- even though it goes on to scan all the
# (pre-existing) ids just fine.
duplicates="$(echo "${bulk_response}" | jq -r '.duplicates // 0')"
failed="$(echo "${bulk_response}" | jq -r '.failed // 0')"
echo "Registered: ${created} created, ${duplicates} already registered (matched by digest), ${failed} failed to register."

ids_file="$(mktemp)"
results_file="$(mktemp)"
trap 'rm -f "${ids_file}" "${results_file}"' EXIT

# `.results[]?` (not `.results[]`) so a response shape this script didn't
# expect (e.g. an auth error body with no `.results` key at all) yields
# no lines instead of a jq parse error -- which, combined with
# pipefail+set -e above, used to kill the script silently right here too.
# The id_count==0 check right below is what actually explains that case
# to the user now, instead of the pipeline dying before ever reaching it.
echo "${bulk_response}" | jq -r '.results[]?.artifact.id // empty' > "${ids_file}"

id_count="$(wc -l < "${ids_file}" | tr -d ' ')"
if [[ "${id_count}" -eq 0 ]]; then
  echo "No artifacts registered -- nothing to scan. Bulk response was:" >&2
  echo "${bulk_response}" >&2
  exit 1
fi

echo
echo "Scanning ${id_count} artifacts, ${PARALLELISM} concurrent requests (this exercises clamd -- expect it to take a while)..."
start_ts="$(date +%s)"

export API_BASE SCM_API_KEY results_file
scan_one() {
  local id="$1"
  local t0 t1 elapsed_ms status
  t0="$(now_ms)"
  status="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    "${API_BASE}/api/v1/artifacts/${id}/scan" \
    -H "Authorization: Bearer ${SCM_API_KEY}")"
  t1="$(now_ms)"
  elapsed_ms=$((t1 - t0))
  echo "${status} ${elapsed_ms} ${id}" >> "${results_file}"
}
export -f scan_one

xargs -P "${PARALLELISM}" -I{} bash -c 'scan_one "$@"' _ {} < "${ids_file}"

end_ts="$(date +%s)"
total_wall_s=$((end_ts - start_ts))

echo
echo "=== Results ==="
echo "Total wall clock: ${total_wall_s}s for ${id_count} scans (parallelism=${PARALLELISM})"

awk '{print $1}' "${results_file}" | sort | uniq -c | sort -rn | while read -r count code; do
  echo "  HTTP ${code}: ${count}"
done

echo
awk '{print $2}' "${results_file}" | sort -n | awk '
  { a[NR]=$1; sum+=$1 }
  END {
    if (NR==0) { print "no completed requests"; exit }
    printf "Per-scan latency (ms) -- min: %d  p50: %d  p95: %d  max: %d  avg: %.0f\n",
      a[1], a[int(NR*0.5)+1<=NR?int(NR*0.5)+1:NR], a[int(NR*0.95)+1<=NR?int(NR*0.95)+1:NR], a[NR], sum/NR
  }'

fail_count="$(awk '$1 != "200" {c++} END{print c+0}' "${results_file}")"
if [[ "${fail_count}" -gt 0 ]]; then
  echo
  echo "${fail_count} scan(s) did not return 200 -- non-200 status codes and their artifact ids:"
  awk '$1 != "200" {print "  " $1, $3}' "${results_file}"
fi
