{{- define "sentinel.name" -}}
sentinel
{{- end -}}

{{- define "sentinel.fullname" -}}
sentinel
{{- end -}}

{{- define "sentinel.labels" -}}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
