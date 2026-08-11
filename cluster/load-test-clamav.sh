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
#   NOTE ON THE IMAGE CORPUS: testdata/bulk-test-images.json deliberately
#   contains NO Docker Hub references. A 100-image burst exhausts Docker
#   Hub's anonymous pull limit part-way through, and the resulting
#   401/429 is classified as `registry_auth_failed` -- so a run reports a
#   pile of "failures" for images that are perfectly healthy, and two
#   runs are never comparable. Every entry is on a registry without that
#   limit (public.ecr.aws, quay.io, ghcr.io, registry.k8s.io,
#   mcr.microsoft.com, gcr.io). Keep it that way when adding images:
#   official Docker images are mirrored at
#   public.ecr.aws/docker/library/<name>.
#
#   1. Bulk-registers testdata/bulk-test-images.json (95 image refs,
#      see README's "Registering many artifacts at once") via
#      POST /api/v1/artifacts/bulk.
#   2. Fires POST /api/v1/artifacts/{id}/scan for every artifact that
#      registered, PARALLELISM at a time (there's no batch-scan endpoint
#      -- see docs/architecture.md, scan is one-artifact-per-request by
#      design), timing each request.
#   3. Reports per-artifact outcomes (scanned/failed/timeout), 429-retry
#      counts (see scan_one --
#      the server caps concurrent scans and this honors Retry-After
#      rather than counting the cap as a failure), and latency
#      (min/avg/max/total wall clock) so a before/after comparison
#      across different
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
# No chart default to fall back to -- values.yaml's monitorApi.apiKey
# is deliberately empty (see README's "Bringing your own secrets"), so
# this must match whatever real value your cluster is actually running
# with. Required, not defaulted: guessing wrong here would just be a
# confusing wall of 401s partway through a 100-artifact batch.
SCM_API_KEY="${SCM_API_KEY:?SCM_API_KEY is required, e.g.: SCM_API_KEY=... ./cluster/load-test-clamav.sh}"
BATCH_FILE="${BATCH_FILE:-${REPO_ROOT}/testdata/bulk-test-images.json}"
# How many /scan requests to have in flight at once -- this is the knob
# that actually puts concurrent load on clamd; raise it toward (or past)
# clamav.replicas to see queuing show up as rising latency/timeouts.
PARALLELISM="${PARALLELISM:-10}"
# How many times one scan retries a 429 from the server-side scan
# concurrency cap before giving up and recording the 429 (see scan_one).
# Bounded on purpose: an unbounded retry would turn a saturated server
# into a script that never finishes, which is a worse outcome for a
# measurement tool than a run that completes and reports the rejections.
MAX_429_RETRIES="${MAX_429_RETRIES:-500}"
# Total seconds one artifact will keep re-trying a 429 before giving up.
# This is the bound that actually matters: with SCAN_CONCURRENCY=4 and
# ~100s per scan, 100 artifacts take ~25 waves, so the last one in line
# waits over half an hour by design. A retry *count* alone (the previous
# bound of 10, ~100s) reported that expected queueing as 74 failures.
MAX_429_WAIT_S="${MAX_429_WAIT_S:-2700}"
# Scans are asynchronous (POST returns 202), so each worker polls the
# artifact until it leaves "scanning" -- these bound that poll. The
# timeout is above the API's own SCAN_TIMEOUT_SECONDS default (660s) so
# a legitimately slow scan is reported as its real outcome rather than
# as a timeout of this script's own making.
SCAN_POLL_INTERVAL_S="${SCAN_POLL_INTERVAL_S:-5}"
SCAN_POLL_TIMEOUT_S="${SCAN_POLL_TIMEOUT_S:-900}"

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
# tmp_dir holds one response-header file per concurrent scan_one worker
# (keyed by BASHPID) -- scan_one needs Retry-After off a 429, and a
# single shared file would be raced by PARALLELISM workers at once.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${ids_file}" "${results_file}" "${tmp_dir}"' EXIT

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

export API_BASE SCM_API_KEY results_file tmp_dir MAX_429_RETRIES MAX_429_WAIT_S SCAN_POLL_INTERVAL_S SCAN_POLL_TIMEOUT_S
# Scanning is asynchronous: POST /scan answers 202 the moment a scan
# starts, so this fires the POST and then polls GET /artifacts/{id}
# until the artifact leaves "scanning". Without the poll every timing
# below would measure how long it takes to *enqueue* a scan (a few ms),
# not how long the pipeline takes to run one -- which is the entire
# point of this script.
#
# A 429 is monitor-api's server-side scan concurrency cap
# (SCAN_CONCURRENCY / monitorApi.scanConcurrency), not a failure: with
# scans asynchronous the cap sheds immediately rather than queueing, so
# a PARALLELISM wider than the cap is *expected* to see them. Retrying
# (honoring Retry-After) keeps this measuring the scan pipeline rather
# than the cap. Retries are counted and reported separately.
scan_one() {
  local id="$1"
  local t0 t1 elapsed_ms status retry_after retries=0 waited_429=0 outcome
  # $$ (not BASHPID): each xargs worker is its own `bash -c` process, so
  # $$ is already unique per worker -- and it works on the bash 3.2 that
  # ships as /bin/bash on macOS, where BASHPID is unset and every worker
  # would race one shared header file.
  local hdr="${tmp_dir}/hdr.$$"
  t0="$(now_ms)"
  while :; do
    status="$(curl -s -o /dev/null -D "${hdr}" -w '%{http_code}' -X POST \
      "${API_BASE}/api/v1/artifacts/${id}/scan" \
      -H "Authorization: Bearer ${SCM_API_KEY}")"
    [ "${status}" = "429" ] || break
    # Bounded: a server that stays saturated must still let this script
    # finish and report, rather than retrying forever.
    if [ "${retries}" -ge "${MAX_429_RETRIES}" ] || [ "${waited_429}" -ge "${MAX_429_WAIT_S}" ]; then
      break
    fi
    retry_after="$(awk 'tolower($1) == "retry-after:" {gsub(/\r/, "", $2); print $2}' "${hdr}")"
    retries=$((retries + 1))
    sleep "${retry_after:-5}"
    waited_429=$((waited_429 + ${retry_after:-5}))
  done
  rm -f "${hdr}"

  if [ "${status}" != "202" ]; then
    # Never started -- record the HTTP code itself as the outcome.
    t1="$(now_ms)"
    echo "http-${status} $((t1 - t0)) ${id} ${retries}" >> "${results_file}"
    return
  fi

  # Poll until the scan lands. SCAN_POLL_TIMEOUT_S bounds it so one
  # wedged artifact can't hang the whole run (see MAX_429_RETRIES for
  # the same reasoning on the other loop).
  local waited=0
  outcome="timeout"
  while [ "${waited}" -lt "${SCAN_POLL_TIMEOUT_S}" ]; do
    status="$(curl -s -o "${tmp_dir}/art.$$" -w '%{http_code}' \
      "${API_BASE}/api/v1/artifacts/${id}" \
      -H "Authorization: Bearer ${SCM_API_KEY}")"
    if [ "${status}" != "200" ]; then
      outcome="poll-http-${status}"
      break
    fi
    # grep -o (not sed): an artifact carries a "status" field per
    # finding as well as its own, and sed's greedy .* matched the LAST
    # one -- reporting every completed scan as "open", a finding status,
    # instead of "scanned". Taking the first match is the artifact's own.
    outcome="$(grep -o '"status":"[a-z]*"' "${tmp_dir}/art.$$" | head -1 | cut -d'"' -f4)"
    [ "${outcome}" = "scanning" ] || break
    sleep "${SCAN_POLL_INTERVAL_S}"
    waited=$((waited + SCAN_POLL_INTERVAL_S))
  done
  rm -f "${tmp_dir}/art.$$"

  t1="$(now_ms)"
  elapsed_ms=$((t1 - t0))
  echo "${outcome} ${elapsed_ms} ${id} ${retries}" >> "${results_file}"
}
export -f scan_one

xargs -P "${PARALLELISM}" -I{} bash -c 'scan_one "$@"' _ {} < "${ids_file}"

end_ts="$(date +%s)"
total_wall_s=$((end_ts - start_ts))

echo
echo "=== Results ==="
echo "Total wall clock: ${total_wall_s}s for ${id_count} scans (parallelism=${PARALLELISM})"

awk '{print $1}' "${results_file}" | sort | uniq -c | sort -rn | while read -r count outcome; do
  echo "  ${outcome}: ${count}"
done

echo
awk '{print $2}' "${results_file}" | sort -n | awk '
  { a[NR]=$1; sum+=$1 }
  END {
    if (NR==0) { print "no completed requests"; exit }
    printf "Per-scan latency (ms) -- min: %d  p50: %d  p95: %d  max: %d  avg: %.0f\n",
      a[1], a[int(NR*0.5)+1<=NR?int(NR*0.5)+1:NR], a[int(NR*0.95)+1<=NR?int(NR*0.95)+1:NR], a[NR], sum/NR
  }'

# Queueing behind the server-side scan cap shows up here rather than in
# the status-code tally above (a retried 429 eventually reports its real
# status) -- so a run against a capped server stays comparable to one
# against an uncapped one, with the waiting made explicit instead of
# vanishing into latency.
retry_total="$(awk '{r+=$4} END{print r+0}' "${results_file}")"
if [[ "${retry_total}" -gt 0 ]]; then
  retried_scans="$(awk '$4 > 0 {c++} END{print c+0}' "${results_file}")"
  echo
  echo "Queued behind the scan concurrency cap: ${retried_scans} scan(s) retried after a 429, ${retry_total} retries total."
  echo "  (server-side SCAN_CONCURRENCY / monitorApi.scanConcurrency -- raise it, or lower PARALLELISM, to reduce this)"
fi

fail_count="$(awk '$1 != "scanned" {c++} END{print c+0}' "${results_file}")"
if [[ "${fail_count}" -gt 0 ]]; then
  echo
  echo "${fail_count} scan(s) did not end up \"scanned\" -- outcome and artifact id:"
  awk '$1 != "scanned" {print "  " $1, $3}' "${results_file}"
fi
