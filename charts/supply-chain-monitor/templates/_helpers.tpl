
{{/*
supply-chain-monitor.apiKeys renders monitorApi.apiKeys as the flat
"name:key,name:key" string the binary parses, accepting either a map or
that string already.

Sorted, so the rendered Secret is byte-identical run to run -- Helm's
map iteration has no inherent order, and an unstable value here would
change the Secret's checksum on every reconcile and roll monitor-api
for no reason (the deployment carries a checksum/api-key annotation).

Joined with SEMICOLONS, not commas. Flux resolves a valuesFrom entry
with a targetPath through Helm's strvals parser, where a comma is a
delimiter -- a comma-separated value arriving that way is torn apart
before Helm sees it and the HelmRelease fails to reconcile with
"key ... has no value". That happened on a live cluster; the binary
accepts both separators so a hand-set API_KEYS still works.

Entries with an empty key are dropped here as well as in the binary.
Doing it in both places is deliberate: the chart should not emit a
credential-shaped blank, and the binary must not trust that it didn't.
*/}}
{{- define "supply-chain-monitor.apiKeys" -}}
{{- $value := .Values.monitorApi.apiKeys -}}
{{- if kindIs "map" $value -}}
{{- $pairs := list -}}
{{- range $name, $key := $value -}}
{{- if and $name $key -}}
{{- $pairs = append $pairs (printf "%s:%s" $name $key) -}}
{{- end -}}
{{- end -}}
{{- join ";" (sortAlpha $pairs) -}}
{{- else -}}
{{- $value -}}
{{- end -}}
{{- end -}}

{{/*
supply-chain-monitor.apiKeyScopes renders monitorApi.apiKeyScopes as the
flat "name=scope|scope;name=scope" string the binary parses, accepting
either a map of lists or that string already.

Sorted for the same reason apiKeys is: an unstable value changes the
ConfigMap's checksum on every reconcile and rolls monitor-api for no
reason.

Semicolons between clients and pipes between scopes, NOT commas -- Flux
resolves a valuesFrom entry with a targetPath through Helm's strvals
parser, where a comma is a delimiter that tears the value apart before
Helm sees it. Same hazard already documented for apiKeys above.

Deliberately NOT in the auth Secret: scopes are not credentials, and the
Secret carries a checksum/api-key annotation, so putting them there
would roll the pod as though a key had rotated every time a permission
changed.
*/}}
{{- define "supply-chain-monitor.apiKeyScopes" -}}
{{- $value := .Values.monitorApi.apiKeyScopes -}}
{{- if kindIs "map" $value -}}
{{- $pairs := list -}}
{{- range $name, $scopes := $value -}}
{{- if and $name $scopes -}}
{{- $pairs = append $pairs (printf "%s=%s" $name (join "|" $scopes)) -}}
{{- end -}}
{{- end -}}
{{- join ";" (sortAlpha $pairs) -}}
{{- else -}}
{{- $value -}}
{{- end -}}
{{- end -}}

{{/*
supply-chain-monitor.registryAuthSecrets renders the names of every
Secret holding a docker config for a non-scm registry, comma-separated
and sorted.

Two sources, one list: the Secret this chart renders from inline
credentials, and every Secret an operator manages themselves. The
consumers cannot tell them apart and should not -- both are mounted into
the same directory and merged in the pod (main.go's mergeRegistryAuths).

Sorted so the value is stable run to run; an unstable env var would roll
monitor-api on every reconcile for no reason.
*/}}
{{- define "supply-chain-monitor.registryAuthSecrets" -}}
{{- $names := list -}}
{{- range .Values.monitorApi.registryCredentials -}}
{{- if .username -}}
{{- $names = append $names "scm-registry-credentials-inline" -}}
{{- else if and .usernameSecretRef .host -}}
{{- /* handled by registryUserSecrets below -- listed here so an entry
       carrying BOTH does not also mount its dockerconfigjson and end
       up with two entries racing for the same host. */ -}}
{{- else if .existingDockerConfigSecret -}}
{{- $names = append $names .existingDockerConfigSecret -}}
{{- end -}}
{{- end -}}
{{- join "," ($names | uniq | sortAlpha) -}}
{{- end -}}

{{/*
supply-chain-monitor.extraCASecrets renders the names of every Secret
holding an additional registry CA, comma-separated and sorted. Same
shape and same reasoning as registryAuthSecrets above.
*/}}
{{- define "supply-chain-monitor.extraCASecrets" -}}
{{- $names := list -}}
{{- range .Values.monitorApi.registryCredentials -}}
{{- if .ca -}}
{{- $names = append $names "scm-registry-extra-cas" -}}
{{- else if .caSecret -}}
{{- $names = append $names .caSecret.name -}}
{{- end -}}
{{- end -}}
{{- join "," ($names | uniq | sortAlpha) -}}
{{- end -}}

{{/*
supply-chain-monitor.registryUserSecrets renders every
registryCredentials entry that names a usernameSecretRef -- an
operator-managed Secret holding a bare username and password -- as a
JSON array.

JSON rather than the comma-separated shape the two helpers above use,
because this one carries FOUR fields per entry and one of them is a
registry host. A host legitimately contains a colon
("registry.internal:5000"), which rules out the obvious inner
separator, and every other candidate is a character that eventually
turns up in a Secret name or key. See internal/k8sjob/job.go's
registryUserSecret.

Precedence, matching values.yaml: an inline `username` wins outright,
then usernameSecretRef, then existingDockerConfigSecret. They are
alternatives, not layers.

Sorted by host for the same reason the others are sorted: an unstable
value would roll monitor-api on every reconcile for no reason.
*/}}
{{- define "supply-chain-monitor.registryUserSecrets" -}}
{{- $byHost := dict -}}
{{- range .Values.monitorApi.registryCredentials -}}
{{- /* `.host` is REQUIRED here, not merely expected. Without it the
       mount path collapses to the auth directory's own root, and that
       mount shadows every other credential underneath it -- the one
       failure in this file that hides working credentials rather than
       failing closed to an anonymous pull. Dropped silently for the
       same reason the rest of this helper is forgiving: one malformed
       entry must not take out the registries that are fine. */ -}}
{{- if and .usernameSecretRef .host (not .username) -}}
{{- $_ := set $byHost .host (dict
    "host" .host
    "secret" .usernameSecretRef.name
    "usernameKey" (default "username" .usernameSecretRef.usernameKey)
    "passwordKey" (default "password" .usernameSecretRef.passwordKey)) -}}
{{- end -}}
{{- end -}}
{{- if $byHost -}}
{{- $out := list -}}
{{- /* `range` over a dict visits keys in sorted order, which is what
       makes this value stable -- sprig has no sortBy for a list of
       dicts, so the dict IS the sort. */ -}}
{{- range $host, $entry := $byHost -}}
{{- $out = append $out $entry -}}
{{- end -}}
{{- $out | toJson -}}
{{- end -}}
{{- end -}}
