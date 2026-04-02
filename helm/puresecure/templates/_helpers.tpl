{{/*
Common labels for all resources
*/}}
{{- define "puresecure.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: puresecure
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
App selector labels
*/}}
{{- define "puresecure.app.selectorLabels" -}}
app: {{ .Values.app.name }}
{{- end }}

{{/*
App labels
*/}}
{{- define "puresecure.app.labels" -}}
{{ include "puresecure.app.selectorLabels" . }}
tier: backend
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Prometheus selector labels
*/}}
{{- define "puresecure.prometheus.selectorLabels" -}}
app: prometheus
{{- end }}

{{/*
Prometheus labels
*/}}
{{- define "puresecure.prometheus.labels" -}}
{{ include "puresecure.prometheus.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Grafana selector labels
*/}}
{{- define "puresecure.grafana.selectorLabels" -}}
app: grafana
{{- end }}

{{/*
Grafana labels
*/}}
{{- define "puresecure.grafana.labels" -}}
{{ include "puresecure.grafana.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Locust selector labels
*/}}
{{- define "puresecure.locust.selectorLabels" -}}
app: locust
{{- end }}

{{/*
Locust labels
*/}}
{{- define "puresecure.locust.labels" -}}
{{ include "puresecure.locust.selectorLabels" . }}
tier: testing
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Alertmanager selector labels
*/}}
{{- define "puresecure.alertmanager.selectorLabels" -}}
app: alertmanager
{{- end }}

{{/*
Alertmanager labels
*/}}
{{- define "puresecure.alertmanager.labels" -}}
{{ include "puresecure.alertmanager.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Redis selector labels
*/}}
{{- define "puresecure.redis.selectorLabels" -}}
app: redis
{{- end }}

{{/*
Redis labels
*/}}
{{- define "puresecure.redis.labels" -}}
{{ include "puresecure.redis.selectorLabels" . }}
tier: cache
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Redis Exporter selector labels
*/}}
{{- define "puresecure.redisExporter.selectorLabels" -}}
app: redis-exporter
{{- end }}

{{/*
Redis Exporter labels
*/}}
{{- define "puresecure.redisExporter.labels" -}}
{{ include "puresecure.redisExporter.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Node Exporter selector labels
*/}}
{{- define "puresecure.nodeExporter.selectorLabels" -}}
app: node-exporter
{{- end }}

{{/*
Node Exporter labels
*/}}
{{- define "puresecure.nodeExporter.labels" -}}
{{ include "puresecure.nodeExporter.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Kube State Metrics selector labels
*/}}
{{- define "puresecure.kubeStateMetrics.selectorLabels" -}}
app: kube-state-metrics
{{- end }}

{{/*
Kube State Metrics labels
*/}}
{{- define "puresecure.kubeStateMetrics.labels" -}}
{{ include "puresecure.kubeStateMetrics.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Loki selector labels
*/}}
{{- define "puresecure.loki.selectorLabels" -}}
app: loki
{{- end }}

{{/*
Loki labels
*/}}
{{- define "puresecure.loki.labels" -}}
{{ include "puresecure.loki.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Promtail selector labels
*/}}
{{- define "puresecure.promtail.selectorLabels" -}}
app: promtail
{{- end }}

{{/*
Promtail labels
*/}}
{{- define "puresecure.promtail.labels" -}}
{{ include "puresecure.promtail.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}
