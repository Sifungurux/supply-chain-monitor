#!/bin/sh
# modelscan-to-findings.sh -- PluggableScanner shim wiring ProtectAI's
# modelscan (https://github.com/protectai/modelscan) into monitor-api's
# pluggable scanner mechanism (internal/scanner/pluggable.go),
# for AI model artifacts registered as artifact type "image" (e.g.
# Docker Model Runner's "ai/<model>:<tag>" refs, packaged as OCI
# artifacts with artifactType application/vnd.cncf.model.manifest.v1+json
# -- a media type trivy's own image scanner doesn't understand, hence
# the "unsupported artifact type" failure this was written to address).
#
# See README.md's "Scanning AI model artifacts" section and
# docs/architecture.md for the full reasoning, including an important
# caveat: modelscan (as of this writing) only understands Pickle/H5/
# SavedModel/Keras-V3-formatted model files. Many modern LLM weight
# formats (safetensors, GGUF) are NOT pickle-based and are considered
# inherently safer against deserialization attacks by design -- for
# those, this shim will legitimately find "no supported files" and
# report zero findings, which is expected, not a bug. This is still
# worth wiring up: it protects any Pickle/H5/SavedModel-based models
# elsewhere in your registry, and costs nothing extra to also run
# against refs where it happens to find nothing.
#
# Usage: monitor-api invokes this as `modelscan-to-findings.sh <ref>`
# (see the {{ref}} substitution in PluggableScannerConfig.Args).
#
# Requires (see the Dockerfile snippet in README.md for a derived
# image): oras (already baked into monitor-api's own Dockerfile),
# python3/pip with modelscan installed, and jq.
set -eu

if [ "$#" -lt 1 ]; then
	echo "usage: modelscan-to-findings.sh <ref>" >&2
	exit 4
fi
REF="$1"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# oras pull works against any OCI 1.1 artifact regardless of its
# artifactType -- it just needs a valid manifest and blobs, the same
# way monitor-api's own RegistryFetcher (internal/scanner/fetch.go)
# already pulls sbom/file/sarif artifacts. Whether this needs
# --plain-http depends entirely on where ref actually points: unlike
# monitor-api's own FETCH_PLAIN_HTTP (which is specifically about its
# internal, plain-HTTP scm-registry), an "ai/*" ref is often a public,
# HTTPS registry (e.g. Docker Hub) -- so this defaults to NOT using
# --plain-http, and only opts in via MODELSCAN_PLAIN_HTTP for anyone
# pointing this at their own on-prem, plain-HTTP registry instead.
ORAS_ARGS="pull --output $WORKDIR"
if [ "${MODELSCAN_PLAIN_HTTP:-false}" = "true" ]; then
	ORAS_ARGS="$ORAS_ARGS --plain-http"
fi
# ORAS_ARGS is intentionally an unquoted, word-split string, not a
# quoted variable: this is #!/bin/sh (POSIX), which has no arrays, and
# the whole point of building it above is a variable-length arg list
# (plain "pull --output $WORKDIR", or that plus "--plain-http") --
# quoting it as shellcheck's default suggestion would do turns it into
# one single argument instead of several, breaking oras's own argv
# parsing. Safe in practice since $WORKDIR comes from `mktemp -d`, never
# user input.
# shellcheck disable=SC2086
oras $ORAS_ARGS "$REF" 1>&2

RESULT_FILE="$WORKDIR/modelscan-result.json"

# modelscan's CLI exit codes (see its README): 0 = clean, 1 = issues
# found, 2 = scan error, 3 = no supported files in the scanned path,
# 4 = usage error. 0/1/3 are all a *successful run* from this shim's
# point of view -- "no supported files" just means every file in this
# artifact is a format modelscan doesn't parse (safetensors/GGUF, most
# likely -- see the caveat above), not a failure. Only 2/4 are real
# errors, and those are left to propagate as a nonzero exit so
# PluggableScanner surfaces them as an actual scan error instead of
# silently reporting "no findings."
set +e
modelscan -p "$WORKDIR" -r json -o "$RESULT_FILE" 1>&2
MODELSCAN_EXIT=$?
set -e

case "$MODELSCAN_EXIT" in
0 | 1 | 3) ;;
*)
	echo "modelscan exited $MODELSCAN_EXIT (a real scan/usage error, not just \"no findings\")" >&2
	exit "$MODELSCAN_EXIT"
	;;
esac

if [ ! -s "$RESULT_FILE" ]; then
	echo '[]'
	exit 0
fi

# NOTE: modelscan does not publish a formal JSON schema as of this
# writing. This filter assumes an "issues" array with description/
# severity/module/operator fields, matching modelscan's own reporting
# terminology (see its docs/severity_levels.md) -- but has not been
# confirmed byte-for-byte against a live scan. Before relying on this
# in production, run `modelscan -p <model> -r json -o out.json` once
# against a real model and compare `cat out.json | jq .` against what
# this filter expects, adjusting field names below if they've drifted.
jq '[ (.issues // [])[] | {
	id: ("modelscan-" + (.module // "unknown") + "-" + (.operator // "issue")),
	severity: ((.severity // "unknown") | ascii_downcase),
	title: (.description // "unsafe operator detected in model file"),
	source: "modelscan",
	category: "other"
} ]' "$RESULT_FILE"
