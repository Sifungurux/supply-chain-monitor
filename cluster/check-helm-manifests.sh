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
check_render "clamav.autoscaling.enabled=false" --set clamav.autoscaling.enabled=false
# The local-artifacts combination: two ConfigMap keys plus the
# extraVolumes/extraVolumeMounts passthrough they need to be usable at
# all. Worth its own case because those two are hand-written `nindent`
# blocks appended to lists that already have entries -- the one shape
# in this chart where a wrong indent still produces valid-looking YAML.
check_render "localArtifacts + extraVolumes/Mounts" \
	--set monitorApi.localArtifacts.enabled=true \
	--set monitorApi.localArtifacts.root=/artifacts \
	--set 'monitorApi.extraVolumes[0].name=artifacts' \
	--set 'monitorApi.extraVolumes[0].persistentVolumeClaim.claimName=scm-artifacts' \
	--set 'monitorApi.extraVolumeMounts[0].name=artifacts' \
	--set 'monitorApi.extraVolumeMounts[0].mountPath=/artifacts' \
	--set 'monitorApi.extraVolumeMounts[0].readOnly=true'
check_render "postgres.dsnExistingSecret" --set monitorApi.postgres.dsnExistingSecret=scm-external-db
