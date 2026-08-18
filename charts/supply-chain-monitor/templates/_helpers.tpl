
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
