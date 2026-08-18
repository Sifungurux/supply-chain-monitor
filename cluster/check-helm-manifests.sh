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
# == the Gateway's TLS listener uses an EntryPoint port, not a NodePort ==
#
# A Gateway listener's port must match one of Traefik's actual internal
# EntryPoint ports (websecure = 8443), NOT the externally-exposed
# NodePort. This project has already been bitten by exactly this once:
# the http listener used 80 (the external port) instead of 8000, Traefik
# silently programmed no route at all, and every request landed on its
# default "404 page not found" handler. Nothing errored -- see
# templates/gateway/gateway.yaml's comment for the full story.
#
# A NodePort-range value here is that same mistake, so it fails the build
# rather than being discovered through a 404 later.
echo "== gateway TLS listener uses an EntryPoint port, not a NodePort =="
tls_port="$(helm template scm-ci charts/supply-chain-monitor \
	-s templates/gateway/gateway.yaml | awk '/name: https/ { found=1 } found && /port:/ { print $2; exit }')"
if [ -z "$tls_port" ]; then
	echo "ERROR: gateway.tls is enabled by default but no https listener rendered." >&2
	exit 1
fi
if [ "$tls_port" -ge 30000 ] && [ "$tls_port" -le 32767 ]; then
	echo "ERROR: the https listener port ${tls_port} is in the NodePort range." >&2
	echo "       A Gateway listener must name Traefik's INTERNAL EntryPoint port" >&2
	echo "       (websecure = 8443), not the externally-exposed NodePort. Using the" >&2
	echo "       external port programs no route at all and fails as a silent 404." >&2
	exit 1
fi

# ... and disabling TLS must remove the listener AND the certificates,
# so a cluster without cert-manager can still render this chart.
echo "== with every TLS feature off, no cert-manager objects render =="
# The point is that a cluster with no cert-manager CRDs can still render
# this chart. ALL THREE gates have to be off for that: the CA chain is
# SHARED between the Gateway, the registry and Postgres, so any one of
# them alone legitimately pulls it in.
#
# postgres.tls was added to this list when it was added to the chart --
# and this check is what noticed, by failing. Anything that starts
# issuing certificates has to be named here, or "every TLS feature off"
# quietly stops meaning every.
disabled_tls="$(helm template scm-ci charts/supply-chain-monitor \
	--set gateway.tls.enabled=false --set registry.tls.enabled=false \
	--set postgres.tls.enabled=false \
	2>/dev/null | grep -cE "kind: Certificate|kind: Issuer" || true)"
if [ "$disabled_tls" != "0" ]; then
	echo "ERROR: with gateway.tls, registry.tls and postgres.tls all off, ${disabled_tls} cert-manager object(s) still rendered." >&2
	echo "       A cluster without cert-manager CRDs must be able to render this chart." >&2
	exit 1
fi

# ...and the sharing itself: registry TLS alone must still produce the CA
# it signs against, or the Certificate references an Issuer that does not
# exist and never becomes Ready -- a failure that is silent from the
# chart's point of view.
echo "== registry TLS alone still renders the shared CA issuer =="
registry_only="$(helm template scm-ci charts/supply-chain-monitor \
	--set gateway.tls.enabled=false --set registry.tls.enabled=true 2>/dev/null)"
case "$registry_only" in
*"name: scm-ca-issuer"*) ;;
*)
	echo "ERROR: registry.tls.enabled=true rendered no scm-ca-issuer." >&2
	echo "       The registry Certificate would reference an Issuer that does not exist." >&2
	exit 1
	;;
esac

# == the HTTPRoute attaches to the https listener, not just http ==
#
# sectionName pins a route to ONE named listener. A route attached only
# to "http" leaves the https listener with no routes at all: the TLS
# handshake completes, Traefik finds nothing to route to, and every
# HTTPS request returns 404 from its default handler.
#
# Nothing errors in that state -- the Gateway reports both listeners
# Programmed, both Certificates report Ready, and the chart looks
# entirely healthy. It shipped that way and was caught only by
# completing a real request over HTTPS.
echo "== the HTTPRoute attaches to the https listener =="
helm template scm-ci charts/supply-chain-monitor \
	-s templates/gateway/httproute.yaml | grep -q "sectionName: https" || {
	echo "ERROR: the HTTPRoute does not attach to the 'https' listener." >&2
	echo "       TLS would terminate and then every request would 404, with" >&2
	echo "       nothing reporting an error anywhere. See" >&2
	echo "       templates/gateway/httproute.yaml." >&2
	exit 1
}

# == the HTTPS redirect targets a CLIENT-reachable port, not the EntryPoint ==
#
# The redirect port and the listener port mean opposite things and are
# easy to swap. A listener port names Traefik's INTERNAL EntryPoint
# (8443) because Traefik is wiring its own plumbing. The redirect port
# goes into a Location header that a BROWSER follows, so it must name an
# address a client can actually reach (the NodePort, 30443).
#
# Swapping them fails silently in both directions: 8443 in the redirect
# sends every visitor to a port nothing listens on, and 30443 on the
# listener programs no route at all.
echo "== the HTTPS redirect port is not the internal EntryPoint port =="
redirect_port="$(helm template scm-ci charts/supply-chain-monitor \
	-s templates/gateway/httproute.yaml | awk '/requestRedirect:/ { f=1 } f && /port:/ { print $2; exit }')"
listener_port="$(helm template scm-ci charts/supply-chain-monitor \
	-s templates/gateway/gateway.yaml | awk '/name: https/ { f=1 } f && /port:/ { print $2; exit }')"
if [ -z "$redirect_port" ]; then
	echo "ERROR: redirectHTTP is enabled by default but no redirect route rendered." >&2
	exit 1
fi
if [ "$redirect_port" = "$listener_port" ]; then
	echo "ERROR: the redirect port (${redirect_port}) is the internal EntryPoint port." >&2
	echo "       A browser follows this Location header, so it must name a port the" >&2
	echo "       CLIENT can reach (the NodePort), not the one Traefik listens on" >&2
	echo "       internally. See values.yaml's gateway.tls.redirectPort." >&2
	exit 1
fi

# With the redirect on, the dashboard route must NOT also claim the http
# listener -- two routes matching the same path on one listener leaves
# which wins to tie-breaking rules rather than to intent.
echo "== the dashboard route does not fight the redirect for the http listener =="
http_claims="$(helm template scm-ci charts/supply-chain-monitor \
	-s templates/gateway/httproute.yaml | awk '/name: scm-dashboard/ { d=1 } /name: scm-https-redirect/ { d=0 } d && /sectionName: http$/ { n++ } END { print n+0 }')"
if [ "$http_claims" != "0" ]; then
	echo "ERROR: with the redirect enabled, scm-dashboard still attaches to the" >&2
	echo "       http listener -- two routes match the same path there." >&2
	exit 1
fi

# == the API is routed through the Gateway, on the TLS listener ==
#
# Without this route the Gateway fronts only the dashboard's HTML, and
# monitor-api stays a bare plain-HTTP NodePort -- so the bearer token
# every request carries still crosses the network in cleartext, which is
# the entire reason TLS was added. It also breaks the dashboard over
# HTTPS, which derives its API address from its own protocol.
echo "== the API is routed through the Gateway on the https listener =="
api_route="$(helm template scm-ci charts/supply-chain-monitor -s templates/gateway/httproute-api.yaml)"
case "$api_route" in
*"name: monitor-api"*) ;;
*)
	echo "ERROR: no Gateway route to monitor-api rendered." >&2
	echo "       The API would be reachable only as a plain-HTTP NodePort." >&2
	exit 1
	;;
esac
case "$api_route" in
*"sectionName: https"*) ;;
*)
	echo "ERROR: the API route does not attach to the 'https' listener." >&2
	echo "       TLS would terminate and API calls would 404 -- see the same" >&2
	echo "       failure documented for the dashboard route." >&2
	exit 1
	;;
esac

# == the dashboard never ships the API key to browsers ==
#
# The render-config initContainer writes env.js, which nginx serves to
# ANY browser that can reach the dashboard. Writing API_KEY into it
# published the only credential this API had -- full
# register/scan/delete authority, retrievable with a plain
# `curl .../env.js` (report S1, CRITICAL).
#
# The key now lives only in the nginx proxy config inside the pod. This
# asserts the env.js line never regains it: the two are written by the
# same script, a few lines apart, so a future edit could easily put it
# back.
echo "== the dashboard's env.js carries no API key =="
# Only the line that WRITES the file -- comments mentioning apiKey (and
# there are several, explaining why it is absent) are not the thing
# under test.
init_script="$(helm template scm-ci charts/supply-chain-monitor \
	-s templates/dashboard/deployment.yaml \
	| grep -E "printf .*SCM_CONFIG" || true)"
if [ -z "$init_script" ]; then
	echo "ERROR: could not find the line that writes env.js -- this check is not looking at anything." >&2
	exit 1
fi
case "$init_script" in
*apiKey*)
	echo "ERROR: the generated env.js includes an apiKey field." >&2
	echo "       env.js is served unauthenticated to every browser that can reach" >&2
	echo "       the dashboard. The key belongs only in the nginx proxy config." >&2
	echo "       Offending line: ${init_script}" >&2
	exit 1
	;;
esac

# == backup encryption is wired end to end when it is switched on ==
#
# The failure this exists to catch is a backup job that LOOKS
# configured for encryption and quietly writes plaintext anyway.
# encrypt() in the CronJob branches on GPG_RECIPIENT_FILE being set,
# so if the value is honoured in one place (the volume) but not the
# other (the env var), every nightly dump lands unencrypted on the
# PVC while values.yaml says otherwise -- and nothing fails, which is
# the worst possible way for this to break.
#
# Rendered with the value ON, since with it off there is nothing to
# assert; the default-off path is covered by the plaintext branch of
# the CronJob's own script.
echo "== backup encryption is wired end to end when enabled =="
enc_cronjob="$(helm template scm-ci charts/supply-chain-monitor \
	--set postgres.backup.encryption.publicKeySecret=scm-backup-encryption \
	-s templates/postgres/backup-cronjob.yaml)"
#
# Matched on the env DECLARATION, not the bare name. The script body
# reads ${GPG_RECIPIENT_FILE:-} in three places, so a substring test
# for the name alone passes even with the env var deleted -- it would
# be asserting that the script mentions the variable, which is not the
# question. Verified by deleting the env entry and watching this fail.
case "$enc_cronjob" in
*"- name: GPG_RECIPIENT_FILE"*) ;;
*)
	echo "ERROR: postgres.backup.encryption.publicKeySecret is set but the backup" >&2
	echo "       CronJob has no GPG_RECIPIENT_FILE env var. Its encrypt() falls back" >&2
	echo "       to cat, so every backup would be written in PLAINTEXT while the" >&2
	echo "       configuration claims otherwise -- and the job would exit 0." >&2
	exit 1
	;;
esac
case "$enc_cronjob" in
*"secretName: \"scm-backup-encryption\""*) ;;
*)
	echo "ERROR: the backup CronJob does not mount the configured public-key Secret." >&2
	echo "       The pod would fail to start, or worse, run without the key." >&2
	exit 1
	;;
esac
# The private half must never appear in anything the chart deploys.
# A restore mounts it from a Secret this repo's restore script creates
# and deletes; a chart template referencing it would make it permanent
# and hand the cluster the ability to read every backup it ever wrote.
echo "== no chart template mounts the backup PRIVATE key =="
all_templates="$(helm template scm-ci charts/supply-chain-monitor \
	--set postgres.backup.encryption.publicKeySecret=scm-backup-encryption)"
case "$all_templates" in
*scm-backup-decryption* | *privatekey.asc*)
	echo "ERROR: a deployed template references the backup private key." >&2
	echo "       Encrypting to a public key is pointless if the cluster permanently" >&2
	echo "       holds the half that decrypts -- see cluster/postgres-restore.sh," >&2
	echo "       which lends it for the duration of a restore instead." >&2
	exit 1
	;;
esac

# == postgres TLS is not half-configured ==
#
# The failure this catches reports NOTHING at runtime: the server
# serves TLS with a perfectly valid certificate, the client connects
# with sslmode=disable, and every row crosses the pod network in
# cleartext exactly as before. Both sides come up healthy, the
# certificate renews on schedule, and the only symptom is that the
# security property everyone believes is on is off.
#
# So the two halves are asserted against the SAME render.
echo "== postgres TLS is wired on both sides =="
pg_deploy="$(helm template scm-ci charts/supply-chain-monitor -s templates/postgres/deployment.yaml)"
pg_cm="$(helm template scm-ci charts/supply-chain-monitor -s templates/monitor-api/configmap.yaml)"
case "$pg_deploy" in
*"ssl=on"*) ;;
*)
	echo "ERROR: postgres.tls.enabled is on but the postgres container is not started with ssl=on." >&2
	echo "       The server would accept only cleartext connections." >&2
	exit 1
	;;
esac
case "$pg_deploy" in
*"ssl_key_file=/tls/tls.key"*) ;;
*)
	echo "ERROR: postgres is started with ssl=on but no ssl_key_file -- it will not start." >&2
	exit 1
	;;
esac
# The initContainer is what makes the key readable at all: a Secret
# mount is 0644 and postgres refuses a group-readable key, and this
# pod cannot use fsGroup to fix that (it would break PGDATA's 0700).
case "$pg_deploy" in
*"name: copy-tls"*) ;;
*)
	echo "ERROR: no copy-tls initContainer, so /tls/tls.key comes straight from a Secret mount." >&2
	echo "       postgres refuses a key file that group or world can read and will not start." >&2
	exit 1
	;;
esac
case "$pg_cm" in
*'POSTGRES_SSLMODE: "disable"'*)
	echo "ERROR: postgres.tls.enabled is on but monitor-api is configured with sslmode=disable." >&2
	echo "       The server would serve TLS while every connection stayed in cleartext," >&2
	echo "       and nothing at runtime would report it. See report S4." >&2
	exit 1
	;;
esac
# ...and with TLS off, the client must NOT demand it, or monitor-api
# cannot reach a database that is running perfectly well.
echo "== with postgres TLS off, the client does not demand TLS =="
pg_cm_off="$(helm template scm-ci charts/supply-chain-monitor --set postgres.tls.enabled=false -s templates/monitor-api/configmap.yaml)"
case "$pg_cm_off" in
*'POSTGRES_SSLMODE: "disable"'*) ;;
*)
	echo "ERROR: with postgres.tls.enabled=false, monitor-api still asks for TLS." >&2
	echo "       It would fail to open its connection pool at startup." >&2
	exit 1
	;;
esac

# == the rescan cadence is separate from the staleness badge ==
#
# Two silent failures, one guard.
#
# If autoRescan is on but SWEEP_RESCAN_STALE_AFTER_DAYS renders 0, the
# sweep never rescans anything on age and NOTHING says so -- the
# CronJob runs every 15 minutes, exits 0, and reports how many
# registered artifacts it found. The vulnerability DBs keep refreshing
# daily against artifacts that are never re-evaluated.
#
# And if the two values are wired to the same source again, an
# aggressive rescan cadence drags the dashboard badge down with it,
# which is the coupling this split exists to remove.
echo "== rescan cadence and staleness badge are wired separately =="
sweep_cj="$(helm template scm-ci charts/supply-chain-monitor -s templates/monitor-api/sweep-registered-cronjob.yaml)"
api_cm="$(helm template scm-ci charts/supply-chain-monitor -s templates/monitor-api/configmap.yaml)"
rescan_days="$(printf '%s' "$sweep_cj" | grep -A1 "name: SWEEP_RESCAN_STALE_AFTER_DAYS" | grep "value:" | tr -dc '0-9')"
warn_days="$(printf '%s' "$api_cm" | grep "SCAN_STALE_AFTER_DAYS:" | tr -dc '0-9')"
if [ -z "$rescan_days" ] || [ -z "$warn_days" ]; then
	echo "ERROR: could not read the rescan/staleness values -- this check is not looking at anything." >&2
	echo "       (rescan='${rescan_days}' warn='${warn_days}')" >&2
	exit 1
fi
# Defaults ship autoRescan on, so a 0 here means the feature is off
# while values.yaml says it is on.
if [ "$rescan_days" = "0" ]; then
	echo "ERROR: monitorApi.scanFreshness.autoRescan is on, but the sweep CronJob renders" >&2
	echo "       SWEEP_RESCAN_STALE_AFTER_DAYS=0 -- it will never rescan anything on age," >&2
	echo "       silently, while the trivy/grype DB refreshes keep running against" >&2
	echo "       artifacts that are never re-evaluated." >&2
	exit 1
fi
if [ "$rescan_days" = "$warn_days" ]; then
	echo "ERROR: the rescan cadence (${rescan_days}d) equals the staleness badge (${warn_days}d)." >&2
	echo "       These were deliberately split: rescans are paced at sweep.batchSize per" >&2
	echo "       run, so artifacts legitimately sit past an aggressive threshold most of" >&2
	echo "       the time and the badge stops meaning anything. If they genuinely should" >&2
	echo "       match, change this check with the reason." >&2
	exit 1
fi

# == cosign verification is configured meaningfully, or not at all ==
#
# `cosign verify` with no --certificate-identity-regexp and no
# --certificate-oidc-issuer checks only that SOMEBODY signed the image
# and that it chains to the trust root. Anybody can arrange that for any
# image, so it proves close to nothing -- and it reports a PASS, which
# is worse than not verifying: an artifact list with no provenance
# findings reads as "everything is signed".
#
# monitor-api refuses to start in that state; this catches it at render
# time instead, where the fix is obvious.
echo "== cosign, when enabled, verifies against a real identity =="
# Reads the CONFIGURED values rather than forcing enabled=true, which
# would be this check constructing the bad state and then reporting it.
cosign_cm="$(helm template scm-ci charts/supply-chain-monitor -s templates/monitor-api/configmap.yaml)"
cosign_on=$(printf '%s' "$cosign_cm" | grep -c 'COSIGN_ENABLED: "true"' || true)
if [ "$cosign_on" != "0" ]; then
	case "$cosign_cm" in
	*'COSIGN_CERT_IDENTITY_REGEXP: ""'* | *'COSIGN_CERT_OIDC_ISSUER: ""'*)
		echo "ERROR: monitorApi.cosign.enabled is true without certIdentityRegexp/certOIDCIssuer." >&2
		echo "       Verification would only prove SOMEBODY signed the image -- which anybody" >&2
		echo "       can arrange -- and would report that as a pass. An artifact list with no" >&2
		echo "       provenance findings then reads as \"everything is signed\"." >&2
		exit 1
		;;
	esac
	echo "      (cosign enabled, verifying against a configured identity)"
fi
