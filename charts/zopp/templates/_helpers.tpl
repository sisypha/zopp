{{/*
Expand the name of the chart.
*/}}
{{- define "zopp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zopp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "zopp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zopp.labels" -}}
helm.sh/chart: {{ include "zopp.chart" . }}
{{ include "zopp.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zopp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zopp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Server labels
*/}}
{{- define "zopp.server.labels" -}}
{{ include "zopp.labels" . }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Server selector labels
*/}}
{{- define "zopp.server.selectorLabels" -}}
{{ include "zopp.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Operator labels
*/}}
{{- define "zopp.operator.labels" -}}
{{ include "zopp.labels" . }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Operator selector labels
*/}}
{{- define "zopp.operator.selectorLabels" -}}
{{ include "zopp.selectorLabels" . }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "zopp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "zopp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Server address for operator
*/}}
{{- define "zopp.operator.serverAddress" -}}
{{- if .Values.operator.server.address }}
{{- .Values.operator.server.address }}
{{- else if .Values.server.enabled }}
{{- printf "%s-server:%d" (include "zopp.fullname" .) (.Values.server.service.grpcPort | int) }}
{{- else }}
{{- fail "operator.server.address is required when server.enabled=false" }}
{{- end }}
{{- end }}
