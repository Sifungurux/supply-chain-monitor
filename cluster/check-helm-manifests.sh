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
# The ServiceMonitor is off by default (it needs prometheus-operator's
# CRD), so the default render above never touches this template at all
# -- exactly the shape of conditional block that ships broken.
check_render "serviceMonitor.enabled=true" \
	--set monitorApi.serviceMonitor.enabled=true \
	--set monitorApi.serviceMonitor.labels.release=kube-prometheus-stack
# Retention is off by default, so the default render never touches the
# prune CronJob template -- the same conditional-block blind spot the
# ServiceMonitor case above covers.
check_render "retention.enabled=true" --set monitorApi.retention.enabled=true
check_render "dockerAuth.existingSecret=true" --set dockerAuth.existingSecret=true

# NetworkPolicies, asserted by NAME in both directions.
#
# check_render above only proves every emitted document has an
# apiVersion -- which a chart emitting ZERO NetworkPolicies passes
# trivially. That is exactly the failure worth catching here: a typo in
# the `if .Values.networkPolicy.enabled` guard, or a values key renamed
# out from under it, silently produces a cluster with no policies and a
# chart that still renders green. So this checks the policies are
# actually there when enabled, and actually gone when not.
expect_policies() {
	label="$1"
	shift
	expected="$1"
	shift
	echo "== networkpolicy ($label) =="
	got=$(helm template scm-ci charts/supply-chain-monitor "$@" | grep -c '^kind: NetworkPolicy' || true)
	if [ "$got" != "$expected" ]; then
		echo "ERROR: expected $expected NetworkPolicy documents, got $got" >&2
		exit 1
	fi
	if [ "$expected" != "0" ]; then
		for name in scm-scan-worker-egress scm-postgres-ingress scm-monitor-api; do
			helm template scm-ci charts/supply-chain-monitor "$@" | grep -q "name: $name" || {
				echo "ERROR: NetworkPolicy $name did not render" >&2
				exit 1
			}
		done
	fi
}

# The ServiceMonitor's selector has to match the LABELS ON THE SERVICE,
# which are a different field from the Service's own pod selector. Get
# that wrong and nothing errors: the scrape config just matches no
# Service and silently collects nothing, which is indistinguishable
# from an exporter that is down. check_render above cannot see this --
# both documents render perfectly well while disagreeing.
echo "== prune cronjob is absent unless retention is enabled =="
if helm template scm-ci charts/supply-chain-monitor | grep -q "name: scm-prune"; then
	echo "ERROR: the prune CronJob renders with DEFAULT values -- retention deletes" >&2
	echo "       artifacts irreversibly and must never be on unless asked for." >&2
	exit 1
fi
helm template scm-ci charts/supply-chain-monitor --set monitorApi.retention.enabled=true \
	| grep -q "name: scm-prune" || {
	echo "ERROR: retention.enabled=true did not render the prune CronJob" >&2
	exit 1
}

# docker_auth accounts: an account with NO password must be omitted from
# the rendered config entirely. Sprig's `bcrypt` hashes an empty string
# into a perfectly valid hash that authenticates an EMPTY PASSWORD, so
# the difference between "omitted" and "rendered" here is the difference
# between a locked registry and an open one -- and both render, both
# lint, and only this check tells them apart.
echo "== docker_auth omits accounts that have no password =="
default_render=$(helm template scm-ci charts/supply-chain-monitor)
echo "$default_render" | grep -q "users: {}" || {
	echo "ERROR: values.yaml ships no docker_auth passwords, so the rendered config" >&2
	echo "       must have an empty user map. It does not -- which means an account" >&2
	echo "       was rendered with a bcrypt hash of the empty string, i.e. an account" >&2
	echo "       anyone can log into." >&2
	exit 1
}

# The opposite direction, so the check above cannot pass merely because
# the template stopped rendering users at all.
echo "== docker_auth renders an account that HAS a password =="
helm template scm-ci charts/supply-chain-monitor \
	--set dockerAuth.accounts.writer.password=some-real-password \
	| grep -q '"scm-writer"' || {
	echo "ERROR: a configured account did not render into docker_auth's config" >&2
	exit 1
}

# No dev-placeholder credential may survive anywhere in the chart.
echo "== no placeholder credentials ship in the chart =="
if grep -rn "changeme" charts/supply-chain-monitor/ >/dev/null 2>&1; then
	echo "ERROR: a 'changeme' placeholder credential is still present:" >&2
	grep -rn "changeme" charts/supply-chain-monitor/ >&2
	exit 1
fi

# Credentials reach these pods through secretKeyRef, and env vars are
# captured once at container start -- so a rotated credential is
# invisible to a running pod unless something changes its spec. These
# checksum annotations ARE that something. A rotation with them missing
# looks entirely healthy: both Secrets correct, pod Running and Ready,
# and every registry pull failing 401 against a password it no longer
# has. That happened.
echo "== credential rotation changes the pods that consume it =="
annots() {
	helm template scm-ci charts/supply-chain-monitor "$@" \
		| awk -v want="$DEPLOY" '
			/^kind: Deployment$/ { d=1; name="" }
			d && /^  name: / { name=$2 }
			d && name==want && /checksum\// { print $1 $2 }
		'
}

for pair in "monitor-api:dockerAuth.accounts.reader.password" "monitor-api:monitorApi.apiKey" "scm-dashboard:monitorApi.apiKey"; do
	DEPLOY="${pair%%:*}"
	key="${pair##*:}"
	before=$(annots)
	after=$(annots --set "${key}=rotated-to-something-else")
	if [ "$before" = "$after" ]; then
		echo "ERROR: rotating ${key} does not change any checksum annotation on ${DEPLOY}." >&2
		echo "       That pod would keep serving the old credential after a rotation," >&2
		echo "       with everything reporting healthy." >&2
		exit 1
	fi
done

echo "== servicemonitor selector matches the service =="
# Renders ONLY the Service template (-s), so "before spec:" is an
# unambiguous test for "in the metadata block" -- matching against the
# whole multi-document render instead would happily find
# `app: monitor-api` in the Deployment's labels or the Service's own pod
# selector and pass while the metadata label was missing.
helm template scm-ci charts/supply-chain-monitor \
	-s templates/monitor-api/service.yaml | awk '
	/^spec:/ { in_metadata=0 }
	/^metadata:/ { in_metadata=1 }
	in_metadata && /^[ \t]+app: monitor-api$/ { found=1 }
	END { exit(found ? 0 : 1) }
' || {
	echo "ERROR: the monitor-api Service has no 'app: monitor-api' METADATA label." >&2
	echo "       spec.selector is a different field -- a ServiceMonitor selects Services by" >&2
	echo "       their metadata labels, so without it the scrape matches nothing and" >&2
	echo "       reports no error. See templates/monitor-api/servicemonitor.yaml." >&2
	exit 1
}

expect_policies "enabled by default" 3
expect_policies "networkPolicy.enabled=false" 0 --set networkPolicy.enabled=false

# == a named API key with no value never reaches API_KEYS ==
#
# An empty key would be compared against the empty string a caller
# presents with a bare "Bearer ", match, and authenticate every
# anonymous request as that client -- so removing a consumer would
# silently open the API to the world. The binary drops these too
# (internal/api.ParseAPIKeys); this asserts the chart never emits one in
# the first place, because a credential-shaped blank in a rendered
# Secret is worth catching at template time.
echo "== a named API key with no value is dropped =="
rendered_keys="$(helm template scm-ci charts/supply-chain-monitor \
	--set monitorApi.apiKey=shared \
	--set monitorApi.apiKeys.retired= \
	--set monitorApi.apiKeys.live=realkey \
	-s templates/monitor-api/auth-secret.yaml | awk -F': ' '/API_KEYS:/ { print $2 }')"
case "$rendered_keys" in
*retired*)
	echo "ERROR: a named API key with an EMPTY value was rendered into API_KEYS:" >&2
	echo "       ${rendered_keys}" >&2
	echo "       An empty key matches a bare 'Bearer ' and would authenticate every" >&2
	echo "       anonymous request as that client. See templates/_helpers.tpl's" >&2
	echo "       supply-chain-monitor.apiKeys." >&2
	exit 1
	;;
esac
case "$rendered_keys" in
*live:realkey*) ;;
*)
	echo "ERROR: a VALID named API key did not reach API_KEYS (got: ${rendered_keys})." >&2
	echo "       The blank-key filter must drop blanks without dropping real keys." >&2
	exit 1
	;;
esac

# == API_KEYS is safe to carry through Flux valuesFrom ==
#
# Flux resolves a valuesFrom entry with a targetPath through Helm's
# strvals parser, where "," and "=" are DELIMITERS. A value containing
# either is torn apart before Helm sees it, and the HelmRelease stops
# reconciling entirely ("key ... has no value") -- which happened on a
# live cluster, took the whole application release down to
# not-reconciling, and was invisible to every existing test because they
# all exercised the chart or the binary but never the layer between.
echo "== API_KEYS survives Flux's strvals parsing =="
strvals_value="$(helm template scm-ci charts/supply-chain-monitor \
	--set monitorApi.apiKey=shared \
	--set monitorApi.apiKeys.ci=k1 \
	--set monitorApi.apiKeys.dashboard=k2 \
	-s templates/monitor-api/auth-secret.yaml | awk -F': ' '/API_KEYS:/ { print $2 }')"
case "$strvals_value" in
*,* | *=*)
	echo "ERROR: rendered API_KEYS contains a strvals delimiter (',' or '='):" >&2
	echo "       ${strvals_value}" >&2
	echo "       Flux would tear this apart resolving valuesFrom, and the whole" >&2
	echo "       HelmRelease would stop reconciling. Join with ';' -- see" >&2
	echo "       templates/_helpers.tpl's supply-chain-monitor.apiKeys." >&2
	exit 1
	;;
esac
case "$strvals_value" in
*"ci:k1"*) ;;
*)
	echo "ERROR: rendered API_KEYS lost a configured key (got: ${strvals_value})." >&2
	exit 1
	;;
esac
