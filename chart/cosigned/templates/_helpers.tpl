{{/*
Expand the name of the chart.
*/}}
{{- define "cosigned.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cosigned.fullname" -}}
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
{{- define "cosigned.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cosigned.labels" -}}
helm.sh/chart: {{ include "cosigned.chart" . }}
{{ include "cosigned.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cosigned.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cosigned.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "cosigned.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cosigned.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Self-signed certificate authority issuer name
*/}}
{{- define "cosigned.CAIssuerName" -}}
{{- if .Values.certificates.ca.issuer.name -}}
{{ .Values.certificates.ca.issuer.name }}
{{- else -}}
{{ template "cosigned.fullname" . }}-ca-issuer
{{- end -}}
{{- end -}}

{{/*
CA Certificate issuer name
*/}}
{{- define "cosigned.CAissuerName" -}}
{{- if .Values.certificates.selfSigned -}}
{{ template "cosigned.CAIssuerName" . }}
{{- else -}}
{{ required "A valid .Values.certificates.ca.issuer.name is required!" .Values.certificates.issuer.name }}
{{- end -}}
{{- end -}}

{{/*
CA signed certificate issuer name
*/}}
{{- define "cosigned.IssuerName" -}}
{{- if .Values.certificates.issuer.name -}}
{{ .Values.certificates.issuer.name }}
{{- else -}}
{{ template "cosigned.fullname" . }}-issuer
{{- end -}}
{{- end -}}

{{/*
Certificate issuer name
*/}}
{{- define "cosigned.issuerName" -}}
{{- if .Values.certificates.selfSigned -}}
{{ template "cosigned.IssuerName" . }}
{{- else -}}
{{ required "A valid .Values.certificates.issuer.name is required!" .Values.certificates.issuer.name }}
{{- end -}}
{{- end -}}
