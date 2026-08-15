
{{/*
supply-chain-monitor.apiKeys renders monitorApi.apiKeys as the flat
"name:key,name:key" string the binary parses, accepting either a map or
that string already.

Sorted, so the rendered Secret is byte-identical run to run -- Helm's
map iteration has no inherent order, and an unstable value here would
change the Secret's checksum on every reconcile and roll monitor-api
for no reason (the deployment carries a checksum/api-key annotation).

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
{{- join "," (sortAlpha $pairs) -}}
{{- else -}}
{{- $value -}}
{{- end -}}
{{- end -}}
