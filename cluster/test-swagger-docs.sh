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
# in a golang:1.26-alpine container, both on --network host so monitor-api
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
	golang:1.26-alpine sh -c "go mod download && go run ." >/dev/null

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

	# README's "Suppressing findings with VEX" example, end to end:
	# record a finding, upload the document from that section verbatim,
	# and check the finding actually comes back suppressed. The Go tests
	# cover the same path, but only this one proves the documented
	# --data-binary curl (raw body, not a JSON wrapper) is the shape the
	# endpoint really accepts.
	findings_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${AUTH[@]}" \
		-H 'Content-Type: application/json' \
		-d '{"bucket":"cve","findings":[{"id":"CVE-2024-1234","severity":"critical","source":"external"}]}' \
		"${BASE}/api/v1/artifacts/${artifact_id}/findings")
	check "POST /api/v1/artifacts/{id}/findings (README's example)" "$findings_status" "200"

	cat >/tmp/vex.json <<-'VEXDOC'
		{
		  "@context": "https://openvex.dev/ns/v0.2.0",
		  "statements": [
		    {
		      "vulnerability": { "name": "CVE-2024-1234" },
		      "status": "not_affected",
		      "justification": "vulnerable_code_not_in_execute_path"
		    }
		  ]
		}
	VEXDOC
	vex_status=$(curl -s -o /tmp/vex-response.json -w '%{http_code}' -X POST "${AUTH[@]}" \
		-H 'Content-Type: application/json' \
		--data-binary @/tmp/vex.json \
		"${BASE}/api/v1/artifacts/${artifact_id}/vex")
	check "POST /api/v1/artifacts/{id}/vex (README's example)" "$vex_status" "200"
	grep -q '"statements":1' /tmp/vex-response.json || { echo "FAIL: VEX upload didn't report 1 understood statement: $(cat /tmp/vex-response.json)" >&2; fail=1; }

	curl -s -o /tmp/get-vex.json "${AUTH[@]}" "${BASE}/api/v1/artifacts/${artifact_id}"
	grep -q '"status":"not_affected"' /tmp/get-vex.json || { echo "FAIL: finding not suppressed after the documented VEX upload: $(cat /tmp/get-vex.json)" >&2; fail=1; }
	grep -q '"justification":"vulnerable_code_not_in_execute_path"' /tmp/get-vex.json || { echo "FAIL: VEX justification didn't persist: $(cat /tmp/get-vex.json)" >&2; fail=1; }

	# README's "Searching by component" example, end to end: upload an
	# SBOM, then run the documented --get/--data-urlencode curl and check
	# the artifact comes back. The purl carries "/", "@" and a query
	# string of its own, which is exactly what a live round trip through
	# real URL parsing tests and an httptest handler call cannot.
	cat >/tmp/sbom.json <<-'SBOMDOC'
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.5",
		  "metadata": { "component": { "type": "container", "name": "alpine:3.19", "purl": "pkg:oci/alpine@sha256:abc" } },
		  "components": [
		    { "type": "library", "name": "openssl", "version": "3.1.4-r5", "purl": "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64" }
		  ]
		}
	SBOMDOC
	sbom_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${AUTH[@]}" \
		-H 'Content-Type: application/vnd.cyclonedx+json' \
		--data-binary @/tmp/sbom.json \
		"${BASE}/api/v1/artifacts/${artifact_id}/documents/sbom")
	check "POST /api/v1/artifacts/{id}/documents/sbom" "$sbom_status" "200"

	component_status=$(curl -s -o /tmp/components.json -w '%{http_code}' "${AUTH[@]}" \
		--get --data-urlencode 'purl=pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64' \
		"${BASE}/api/v1/components")
	check "GET /api/v1/components?purl=... (README's example)" "$component_status" "200"
	grep -q "\"id\":\"${artifact_id}\"" /tmp/components.json || { echo "FAIL: component search didn't return the artifact whose SBOM lists it: $(cat /tmp/components.json)" >&2; fail=1; }

	# The document's own subject is not a component of it.
	subject_json=$(curl -s "${AUTH[@]}" --get --data-urlencode 'purl=pkg:oci/alpine@sha256:abc' "${BASE}/api/v1/components")
	[ "$subject_json" = "[]" ] || { echo "FAIL: the SBOM's own subject was indexed as a component of itself: $subject_json" >&2; fail=1; }

	# The discovery half of the same endpoint: a substring somebody
	# types, answered with packages rather than artifacts. Worth running
	# for real -- `q` is free text that arrives through the same URL
	# parsing as the purl, and the response is a different shape.
	search_status=$(curl -s -o /tmp/component-search.json -w '%{http_code}' "${AUTH[@]}" \
		--get --data-urlencode 'q=openssl' "${BASE}/api/v1/components")
	check "GET /api/v1/components?q=... (README's example)" "$search_status" "200"
	grep -q '"packages"' /tmp/component-search.json || { echo "FAIL: package search response has no \"packages\" key: $(cat /tmp/component-search.json)" >&2; fail=1; }
	grep -q '"artifacts":1' /tmp/component-search.json || { echo "FAIL: package search didn't report an artifact count: $(cat /tmp/component-search.json)" >&2; fail=1; }
	grep -q 'pkg:apk/alpine/openssl@3.1.4-r5' /tmp/component-search.json || { echo "FAIL: package search didn't find the uploaded component by name: $(cat /tmp/component-search.json)" >&2; fail=1; }

	# A term matching nothing is an empty answer, not an error.
	empty_search=$(curl -s "${AUTH[@]}" --get --data-urlencode 'q=nothing-like-this' "${BASE}/api/v1/components")
	echo "$empty_search" | grep -q '"total":0' || { echo "FAIL: no-match search should report total 0: $empty_search" >&2; fail=1; }

	missing_purl_status=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "${BASE}/api/v1/components")
	check "GET /api/v1/components (neither purl nor q)" "$missing_purl_status" "400"

	delete_status=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${AUTH[@]}" "${BASE}/api/v1/artifacts/${artifact_id}")
	check "DELETE /api/v1/artifacts/{id}" "$delete_status" "200"
fi

if [ "$fail" -ne 0 ]; then
	echo "FAILED -- see above" >&2
	exit 1
fi
echo "PASSED"
