#!/usr/bin/env bash
# Proves /swagger and /openapi.yaml actually work against a real, running
# monitor-api process -- not just internal/api's httptest-based Go tests
# (TestAuth_SwaggerRoutesExempt, TestSwaggerUI_ReferencesOpenAPISpec,
# TestOpenAPISpec_DescribesEveryRegisteredRoute), which exercise the exact
# same handler code but never open a real TCP listener or make a real HTTP
# round trip. Also runs the literal curl examples from README.md's
# "Authentication" and "API" sections against that live server, so a
# documented command that's since drifted from what the API actually
# returns fails here instead of just misleading the next person who
# copy-pastes it.
#
# Needs nothing but Docker: starts a throwaway Postgres (same image
# test-postgres in the Makefile uses) plus monitor-api itself via `go run`
# in a golang:1.22-alpine container, both on --network host so monitor-api
# can reach Postgres via localhost -- see the Makefile's test-postgres
# target for why that means this doesn't work on Docker Desktop for macOS
# (only a real Linux host, e.g. Colima or a GitHub Actions runner).
#
# Usage: ./cluster/test-swagger-docs.sh  (or `make test-swagger-docs`)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PG_CONTAINER=scm-test-postgres-swagger
API_CONTAINER=scm-test-monitor-api-swagger
PG_PORT=55433
API_PORT=8099
API_KEY=test-swagger-docs-key
BASE="http://localhost:${API_PORT}"

cleanup() {
	docker stop "$API_CONTAINER" >/dev/null 2>&1 || true
	docker stop "$PG_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> starting throwaway Postgres on :${PG_PORT}"
docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --rm --name "$PG_CONTAINER" \
	-e POSTGRES_PASSWORD=test -p "${PG_PORT}:5432" \
	percona/percona-distribution-postgresql:17.10 >/dev/null

echo "==> starting monitor-api on :${API_PORT} (DISABLE_SCAN_ISOLATION=true -- see README, \"Running monitor-api outside a Kubernetes pod\")"
docker rm -f "$API_CONTAINER" >/dev/null 2>&1 || true
docker run -d --rm --network host --name "$API_CONTAINER" \
	-v "$(pwd)/services/monitor-api":/src -w /src \
	-e API_KEY="$API_KEY" \
	-e LISTEN_ADDR=":${API_PORT}" \
	-e POSTGRES_HOST=localhost -e POSTGRES_PORT="${PG_PORT}" \
	-e POSTGRES_USER=postgres -e POSTGRES_DB=postgres -e POSTGRES_PASSWORD=test \
	-e DISABLE_SCAN_ISOLATION=true \
	golang:1.22-alpine sh -c "go mod download && go run ." >/dev/null

echo "==> waiting for /healthz (Postgres startup + Go build can take a while on a cold cache)"
ready=false
for _ in $(seq 1 60); do
	if curl -sf "${BASE}/healthz" >/dev/null 2>&1; then
		ready=true
		break
	fi
	sleep 2
done
if [ "$ready" != true ]; then
	echo "monitor-api never became ready -- container logs:" >&2
	docker logs "$API_CONTAINER" >&2 || true
	echo "If the log above actually shows 'monitor-api listening on :${API_PORT}', this is" >&2
	echo "the same --network host limitation test-postgres's own Makefile comment" >&2
	echo "describes: on podman machine/Colima (macOS), --network host binds inside the" >&2
	echo "Linux VM, not reachable from the Mac host's own localhost. Re-run this" >&2
	echo "check from inside the VM instead (e.g. 'podman machine ssh'); a real Linux" >&2
	echo "CI runner (no VM layer) doesn't hit this at all." >&2
	exit 1
fi
echo "    ready"

fail=0
check() {
	# check DESCRIPTION ACTUAL_STATUS WANT_STATUS
	if [ "$2" != "$3" ]; then
		echo "FAIL: $1 -- got status $2, want $3" >&2
		fail=1
	else
		echo "ok:   $1"
	fi
}

echo "==> /swagger and /openapi.yaml: unauthenticated, correct content"
swagger_status=$(curl -s -o /tmp/swagger.html -w '%{http_code}' "${BASE}/swagger")
check "GET /swagger (no auth)" "$swagger_status" "200"
grep -q 'swagger-ui' /tmp/swagger.html || { echo "FAIL: /swagger response doesn't look like Swagger UI" >&2; fail=1; }
grep -q '/openapi.yaml' /tmp/swagger.html || { echo "FAIL: /swagger doesn't reference /openapi.yaml" >&2; fail=1; }

spec_status=$(curl -s -o /tmp/openapi.yaml -w '%{http_code}' "${BASE}/openapi.yaml")
check "GET /openapi.yaml (no auth)" "$spec_status" "200"
grep -q '^openapi: 3.0' /tmp/openapi.yaml || { echo "FAIL: /openapi.yaml doesn't look like an OpenAPI 3.0 document" >&2; fail=1; }
grep -q '/api/v1/artifacts:' /tmp/openapi.yaml || { echo "FAIL: /openapi.yaml doesn't document /api/v1/artifacts" >&2; fail=1; }

echo "==> auth is actually enforced on real data endpoints (the thing /swagger documents but doesn't bypass)"
noauth_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/v1/artifacts")
check "GET /api/v1/artifacts (no auth)" "$noauth_status" "401"

echo "==> README's documented curl examples, run for real"
AUTH=(-H "Authorization: Bearer ${API_KEY}")

stages_status=$(curl -s -o /tmp/stages.json -w '%{http_code}' "${AUTH[@]}" "${BASE}/api/v1/pipeline/stages")
check "GET /api/v1/pipeline/stages" "$stages_status" "200"
grep -q '"stages"' /tmp/stages.json || { echo "FAIL: pipeline stages response missing \"stages\" key: $(cat /tmp/stages.json)" >&2; fail=1; }

create_status=$(curl -s -o /tmp/create.json -w '%{http_code}' -X POST "${AUTH[@]}" \
	-H 'Content-Type: application/json' \
	-d '{"ref":"alpine:3.19","type":"image"}' \
	"${BASE}/api/v1/artifacts")
check "POST /api/v1/artifacts (README's example)" "$create_status" "201"
artifact_id=$(grep -o '"id":"[^"]*"' /tmp/create.json | head -1 | cut -d'"' -f4)
if [ -z "$artifact_id" ]; then
	echo "FAIL: could not extract artifact id from create response: $(cat /tmp/create.json)" >&2
	fail=1
else
	get_status=$(curl -s -o /tmp/get.json -w '%{http_code}' "${AUTH[@]}" "${BASE}/api/v1/artifacts/${artifact_id}")
	check "GET /api/v1/artifacts/{id}" "$get_status" "200"
	grep -q '"ref":"alpine:3.19"' /tmp/get.json || { echo "FAIL: fetched artifact doesn't have the ref it was registered with: $(cat /tmp/get.json)" >&2; fail=1; }

	delete_status=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${AUTH[@]}" "${BASE}/api/v1/artifacts/${artifact_id}")
	check "DELETE /api/v1/artifacts/{id}" "$delete_status" "200"
fi

if [ "$fail" -ne 0 ]; then
	echo "FAILED -- see above" >&2
	exit 1
fi
echo "PASSED"
