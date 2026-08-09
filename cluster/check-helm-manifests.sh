#!/bin/sh
# Renders charts/supply-chain-monitor for real and fails if any emitted
# document is missing apiVersion. `helm lint` and a bare `helm
# template` both exit 0 on a document that's missing one -- this chart
# shipped exactly that once (two {{- ... -}} trims in
# docker-auth/signing-cert-secret.yaml glued "apiVersion: v1" onto the
# end of a comment line), and only `helm upgrade`'s server-side
# validation against a real cluster caught it. This is the offline
# equivalent of that validation, run per value-combination that gates
# a distinct set of templates on, so a newly-added conditional block
# gets exercised too.
set -eu

check_render() {
	label="$1"
	shift
	echo "== helm template ($label) =="
	helm template scm-ci charts/supply-chain-monitor "$@" | awk '
		/^---$/ { if (body && !has) { print "ERROR: document missing apiVersion:"; exit 1 } body=0; has=0; next }
		/^#/ || /^[ \t]*$/ { next }
		{ body=1; if ($0 ~ /^apiVersion:/) has=1 }
		END { if (body && !has) { print "ERROR: document missing apiVersion:"; exit 1 } }
	'
}

check_render "default values"
check_render "cveScanner=both, dockerAuth.enabled=true" --set monitorApi.cveScanner=both --set dockerAuth.enabled=true
check_render "postgres/apiKey existingSecret=true" --set postgres.credentials.existingSecret=true --set monitorApi.apiKeyExistingSecret=true
