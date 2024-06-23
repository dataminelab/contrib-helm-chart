{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "datareporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "datareporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 43 chars because some Kubernetes name fields are limited to 64 (by the DNS naming spec),
and we use this as a base for component names (which can add up to 20 chars).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "datareporter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 43 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 43 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 43 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create a default fully qualified adhocWorker name.
*/}}
{{- define "datareporter.adhocWorker.fullname" -}}
{{- template "datareporter.fullname" . -}}-adhocworker
{{- end -}}

{{/*
Create a default fully qualified scheduledworker name.
*/}}
{{- define "datareporter.scheduledWorker.fullname" -}}
{{- template "datareporter.fullname" . -}}-scheduledworker
{{- end -}}

{{/*
Create a default fully qualified genericWorker name.
*/}}
{{- define "datareporter.genericWorker.fullname" -}}
{{- template "datareporter.fullname" . -}}-genericworker
{{- end -}}

{{/*
Create a default fully qualified scheduler name.
*/}}
{{- define "datareporter.scheduler.fullname" -}}
{{- template "datareporter.fullname" . -}}-scheduler
{{- end -}}

{{/*
Create a default fully qualified postgresql name.
*/}}
{{- define "datareporter.postgresql.fullname" -}}
{{- printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified redis name.
*/}}
{{- define "datareporter.redis.fullname" -}}
{{- printf "%s-%s" .Release.Name "redis-master" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Get the secret name.
*/}}
{{- define "datareporter.secretName" -}}
{{- if .Values.datareporter.existingSecret }}
    {{- printf "%s" .Values.datareporter.existingSecret -}}
{{- else -}}
    {{- printf "%s" (include "datareporter.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Shared environment block used across each component.
*/}}
{{- define "datareporter.env" -}}
{{- if not .Values.postgresql.enabled }}
  {{- if .Values.externalPostgreSQLSecret }}
- name: REDASH_DATABASE_URL
  valueFrom:
    secretKeyRef:
      {{- .Values.externalPostgreSQLSecret | toYaml | nindent 6 }}
  {{- else if .Values.externalPostgreSQLConfig }}
- name: REDASH_DATABASE_USER
  {{- .Values.externalPostgreSQLConfig.user  | toYaml | nindent 2}}"
- name: REDASH_DATABASE_PASSWORD
  {{- .Values.externalPostgreSQLConfig.password  | toYaml | nindent 2}}"
- name: REDASH_DATABASE_HOSTNAME
  {{- .Values.externalPostgreSQLConfig.host  | toYaml | nindent 2}}"
- name: REDASH_DATABASE_PORT
  {{- .Values.externalPostgreSQLConfig.port  | toYaml | nindent 2}}"
- name: REDASH_DATABASE_DB
  {{- .Values.externalPostgreSQLConfig.port  | toYaml | nindent 2}}"
  {{ else }}
- name: REDASH_DATABASE_URL
  value: {{ default "" .Values.externalPostgreSQL | quote }}
  {{- end }}
{{- else }}
- name: REDASH_DATABASE_USER
  value: "{{ .Values.postgresql.postgresqlUsername }}"
- name: REDASH_DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Release.Name }}-postgresql
      key: postgresql-password
- name: REDASH_DATABASE_HOSTNAME
  value: {{ include "datareporter.postgresql.fullname" . }}
- name: REDASH_DATABASE_PORT
  value: "{{ .Values.postgresql.service.port }}"
- name: REDASH_DATABASE_DB
  value: "{{ .Values.postgresql.postgresqlDatabase }}"
{{- end }}
{{- if not .Values.redis.enabled }}
  {{- if .Values.externalRedisSecret }}
- name: REDASH_REDIS_URL
  valueFrom:
    secretKeyRef:
      {{- .Values.externalRedisSecret | toYaml | nindent 6 }}
  {{- else if .Values.externalRedisConfig}}
  - name: REDASH_REDIS_PASSWORD
  {{- .Values.externalRedisConfig.password  | toYaml | nindent 2}}"
- name: REDASH_REDIS_HOSTNAME
  {{- .Values.externalRedisConfig.host  | toYaml | nindent 2}}"
- name: REDASH_REDIS_PORT
  {{- .Values.externalRedisConfig.port  | toYaml | nindent 2}}"
- name: REDASH_REDIS_DB
  {{- .Values.externalRedisConfig.db  | toYaml | nindent 2}}"

  {{- else }}
- name: REDASH_REDIS_URL
  value: {{ default "" .Values.externalRedis | quote }}
  {{- end }}
{{- else }}
- name: REDASH_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
    {{- if .Values.redis.existingSecret }}
      name: {{ .Values.redis.existingSecret }}
    {{- else }}
      name: {{ .Release.Name }}-redis
    {{- end }}
      key: redis-password
- name: REDASH_REDIS_HOSTNAME
  value: {{ include "datareporter.redis.fullname" . }}
- name: REDASH_REDIS_PORT
  value: "{{ .Values.redis.master.port }}"
- name: REDASH_REDIS_DB
  value: "{{ .Values.redis.databaseNumber }}"
{{- end }}
- name: PLYWOOD_SERVER_URL
  value: http://{{ include "datareporter.plywood.fullname" . }}:{{ .Values.plywood.service.port}}
{{- range $key, $value := .Values.env }}
- name: "{{ $key }}"
  value: "{{ $value }}"
{{- end }}
## Start primary Redash configuration
{{- if or .Values.datareporter.secretKey .Values.datareporter.existingSecret }}
- name: REDASH_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "datareporter.secretName" . }}
      key: secretKey
{{- end }}
{{- if .Values.datareporter.samlSchemeOverride }}
- name: REDASH_SAML_SCHEME_OVERRIDE
  value: {{ default  .Values.datareporter.samlSchemeOverride | quote }}
{{- end }}
{{- if .Values.datareporter.proxiesCount }}
- name: REDASH_PROXIES_COUNT
  value: {{ default  .Values.datareporter.proxiesCount | quote }}
{{- end }}
{{- if .Values.datareporter.statsdHost }}
- name: REDASH_STATSD_HOST
  value: {{ default  .Values.datareporter.statsdHost | quote }}
{{- end }}
{{- if .Values.datareporter.statsdPort }}
- name: REDASH_STATSD_PORT
  value: {{ default  .Values.datareporter.statsdPort | quote }}
{{- end }}
{{- if .Values.datareporter.statsdPrefix }}
- name: REDASH_STATSD_PREFIX
  value: {{ default  .Values.datareporter.statsdPrefix | quote }}
{{- end }}
{{- if .Values.datareporter.statsdUseTags }}
- name: REDASH_STATSD_USE_TAGS
  value: {{ default  .Values.datareporter.statsdUseTags | quote }}
{{- end }}
{{- if .Values.datareporter.celeryBroker }}
- name: REDASH_CELERY_BROKER
  value: {{ default  .Values.datareporter.celeryBroker | quote }}
{{- end }}
{{- if .Values.datareporter.celeryBackend }}
- name: REDASH_CELERY_BACKEND
  value: {{ default  .Values.datareporter.celeryBackend | quote }}
{{- end }}
{{- if .Values.datareporter.celeryTaskResultExpires }}
- name: REDASH_CELERY_TASK_RESULT_EXPIRES
  value: {{ default  .Values.datareporter.celeryTaskResultExpires | quote }}
{{- end }}
{{- if .Values.datareporter.queryResultsCleanupEnabled }}
- name: REDASH_QUERY_RESULTS_CLEANUP_ENABLED
  value: {{ default  .Values.datareporter.queryResultsCleanupEnabled | quote }}
{{- end }}
{{- if .Values.datareporter.queryResultsCleanupCount }}
- name: REDASH_QUERY_RESULTS_CLEANUP_COUNT
  value: {{ default  .Values.datareporter.queryResultsCleanupCount | quote }}
{{- end }}
{{- if .Values.datareporter.queryResultsCleanupMaxAge }}
- name: REDASH_QUERY_RESULTS_CLEANUP_MAX_AGE
  value: {{ default  .Values.datareporter.queryResultsCleanupMaxAge | quote }}
{{- end }}
{{- if .Values.datareporter.schemasRefreshQueue }}
- name: REDASH_SCHEMAS_REFRESH_QUEUE
  value: {{ default  .Values.datareporter.schemasRefreshQueue | quote }}
{{- end }}
{{- if .Values.datareporter.schemasRefreshSchedule }}
- name: REDASH_SCHEMAS_REFRESH_SCHEDULE
  value: {{ default  .Values.datareporter.schemasRefreshSchedule | quote }}
{{- end }}
{{- if .Values.datareporter.authType }}
- name: REDASH_AUTH_TYPE
  value: {{ default  .Values.datareporter.authType | quote }}
{{- end }}
{{- if .Values.datareporter.enforceHttps }}
- name: REDASH_ENFORCE_HTTPS
  value: {{ default  .Values.datareporter.enforceHttps | quote }}
{{- end }}
{{- if .Values.datareporter.invitationTokenMaxAge }}
- name: REDASH_INVITATION_TOKEN_MAX_AGE
  value: {{ default  .Values.datareporter.invitationTokenMaxAge | quote }}
{{- end }}
{{- if .Values.datareporter.multiOrg }}
- name: REDASH_MULTI_ORG
  value: {{ default  .Values.datareporter.multiOrg | quote }}
{{- end }}
{{- if .Values.datareporter.googleClientId }}
- name: REDASH_GOOGLE_CLIENT_ID
  value: {{ default  .Values.datareporter.googleClientId | quote }}
{{- end }}
{{- if or .Values.datareporter.googleClientSecret .Values.datareporter.existingSecret }}
- name: REDASH_GOOGLE_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "datareporter.secretName" . }}
      key: googleClientSecret
{{- end }}
{{- if .Values.datareporter.remoteUserLoginEnabled }}
- name: REDASH_REMOTE_USER_LOGIN_ENABLED
  value: {{ default  .Values.datareporter.remoteUserLoginEnabled | quote }}
{{- end }}
{{- if .Values.datareporter.remoteUserHeader }}
- name: REDASH_REMOTE_USER_HEADER
  value: {{ default  .Values.datareporter.remoteUserHeader | quote }}
{{- end }}
{{- if .Values.datareporter.ldapLoginEnabled }}
- name: REDASH_LDAP_LOGIN_ENABLED
  value: {{ default  .Values.datareporter.ldapLoginEnabled | quote }}
{{- end }}
{{- if .Values.datareporter.ldapUrl }}
- name: REDASH_LDAP_URL
  value: {{ default  .Values.datareporter.ldapUrl | quote }}
{{- end }}
{{- if .Values.datareporter.ldapBindDn }}
- name: REDASH_LDAP_BIND_DN
  value: {{ default  .Values.datareporter.ldapBindDn | quote }}
{{- end }}
{{- if or .Values.datareporter.ldapBindDnPassword .Values.datareporter.existingSecret }}
- name: REDASH_LDAP_BIND_DN_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "datareporter.secretName" . }}
      key: ldapBindDnPassword
{{- end }}
{{- if .Values.datareporter.ldapDisplayNameKey }}
- name: REDASH_LDAP_DISPLAY_NAME_KEY
  value: {{ default  .Values.datareporter.ldapDisplayNameKey | quote }}
{{- end }}
{{- if .Values.datareporter.ldapEmailKey }}
- name: REDASH_LDAP_EMAIL_KEY
  value: {{ default  .Values.datareporter.ldapEmailKey | quote }}
{{- end }}
{{- if .Values.datareporter.ldapCustomUsernamePrompt }}
- name: REDASH_LDAP_CUSTOM_USERNAME_PROMPT
  value: {{ default  .Values.datareporter.ldapCustomUsernamePrompt | quote }}
{{- end }}
{{- if .Values.datareporter.ldapSearchTemplate }}
- name: REDASH_LDAP_SEARCH_TEMPLATE
  value: {{ default  .Values.datareporter.ldapSearchTemplate | quote }}
{{- end }}
{{- if .Values.datareporter.ldapSearchDn }}
- name: REDASH_LDAP_SEARCH_DN
  value: {{ default  .Values.datareporter.ldapSearchDn | quote }}
{{- end }}
{{- if .Values.datareporter.staticAssetsPath }}
- name: REDASH_STATIC_ASSETS_PATH
  value: {{ default  .Values.datareporter.staticAssetsPath | quote }}
{{- end }}
{{- if .Values.datareporter.jobExpiryTime }}
- name: REDASH_JOB_EXPIRY_TIME
  value: {{ default  .Values.datareporter.jobExpiryTime | quote }}
{{- end }}
{{- if or .Values.datareporter.cookieSecret .Values.datareporter.existingSecret }}
- name: REDASH_COOKIE_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "datareporter.secretName" . }}
      key: cookieSecret
{{- end }}
{{- if .Values.datareporter.logLevel }}
- name: REDASH_LOG_LEVEL
  value: {{ default  .Values.datareporter.logLevel | quote }}
{{- end }}
{{- if .Values.datareporter.mailServer }}
- name: REDASH_MAIL_SERVER
  value: {{ default  .Values.datareporter.mailServer | quote }}
{{- end }}
{{- if .Values.datareporter.mailPort }}
- name: REDASH_MAIL_PORT
  value: {{ default  .Values.datareporter.mailPort | quote }}
{{- end }}
{{- if .Values.datareporter.mailUseTls }}
- name: REDASH_MAIL_USE_TLS
  value: {{ default  .Values.datareporter.mailUseTls | quote }}
{{- end }}
{{- if .Values.datareporter.mailUseSsl }}
- name: REDASH_MAIL_USE_SSL
  value: {{ default  .Values.datareporter.mailUseSsl | quote }}
{{- end }}
{{- if .Values.datareporter.mailUsername }}
- name: REDASH_MAIL_USERNAME
  value: {{ default  .Values.datareporter.mailUsername | quote }}
{{- end }}
{{- if or .Values.datareporter.mailPassword .Values.datareporter.existingSecret }}
- name: REDASH_MAIL_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "datareporter.secretName" . }}
      key: mailPassword
{{- end }}
{{- if .Values.datareporter.mailDefaultSender }}
- name: REDASH_MAIL_DEFAULT_SENDER
  value: {{ default  .Values.datareporter.mailDefaultSender | quote }}
{{- end }}
{{- if .Values.datareporter.mailMaxEmails }}
- name: REDASH_MAIL_MAX_EMAILS
  value: {{ default  .Values.datareporter.mailMaxEmails | quote }}
{{- end }}
{{- if .Values.datareporter.mailAsciiAttachments }}
- name: REDASH_MAIL_ASCII_ATTACHMENTS
  value: {{ default  .Values.datareporter.mailAsciiAttachments | quote }}
{{- end }}
{{- if .Values.datareporter.host }}
- name: REDASH_HOST
  value: {{ default  .Values.datareporter.host | quote }}
{{- end }}
{{- if .Values.datareporter.alertsDefaultMailSubjectTemplate }}
- name: REDASH_ALERTS_DEFAULT_MAIL_SUBJECT_TEMPLATE
  value: {{ default  .Values.datareporter.alertsDefaultMailSubjectTemplate | quote }}
{{- end }}
{{- if .Values.datareporter.throttleLoginPattern }}
- name: REDASH_THROTTLE_LOGIN_PATTERN
  value: {{ default  .Values.datareporter.throttleLoginPattern | quote }}
{{- end }}
{{- if .Values.datareporter.limiterStorage }}
- name: REDASH_LIMITER_STORAGE
  value: {{ default  .Values.datareporter.limiterStorage | quote }}
{{- end }}
{{- if .Values.datareporter.corsAccessControlAllowOrigin }}
- name: REDASH_CORS_ACCESS_CONTROL_ALLOW_ORIGIN
  value: {{ default  .Values.datareporter.corsAccessControlAllowOrigin | quote }}
{{- end }}
{{- if .Values.datareporter.corsAccessControlAllowCredentials }}
- name: REDASH_CORS_ACCESS_CONTROL_ALLOW_CREDENTIALS
  value: {{ default  .Values.datareporter.corsAccessControlAllowCredentials | quote }}
{{- end }}
{{- if .Values.datareporter.corsAccessControlRequestMethod }}
- name: REDASH_CORS_ACCESS_CONTROL_REQUEST_METHOD
  value: {{ default  .Values.datareporter.corsAccessControlRequestMethod | quote }}
{{- end }}
{{- if .Values.datareporter.corsAccessControlAllowHeaders }}
- name: REDASH_CORS_ACCESS_CONTROL_ALLOW_HEADERS
  value: {{ default  .Values.datareporter.corsAccessControlAllowHeaders | quote }}
{{- end }}
{{- if .Values.datareporter.enabledQueryRunners }}
- name: REDASH_ENABLED_QUERY_RUNNERS
  value: {{ default  .Values.datareporter.enabledQueryRunners | quote }}
{{- end }}
{{- if .Values.datareporter.additionalQueryRunners }}
- name: REDASH_ADDITIONAL_QUERY_RUNNERS
  value: {{ default  .Values.datareporter.additionalQueryRunners | quote }}
{{- end }}
{{- if .Values.datareporter.disabledQueryRunners }}
- name: REDASH_DISABLED_QUERY_RUNNERS
  value: {{ default  .Values.datareporter.disabledQueryRunners | quote }}
{{- end }}
{{- if .Values.datareporter.scheduledQueryTimeLimit }}
- name: REDASH_SCHEDULED_QUERY_TIME_LIMIT
  value: {{ default  .Values.datareporter.scheduledQueryTimeLimit | quote }}
{{- end }}
{{- if .Values.datareporter.adhocQueryTimeLimit }}
- name: REDASH_ADHOC_QUERY_TIME_LIMIT
  value: {{ default  .Values.datareporter.adhocQueryTimeLimit | quote }}
{{- end }}
{{- if .Values.datareporter.enabledDestinations }}
- name: REDASH_ENABLED_DESTINATIONS
  value: {{ default  .Values.datareporter.enabledDestinations | quote }}
{{- end }}
{{- if .Values.datareporter.additionalDestinations }}
- name: REDASH_ADDITIONAL_DESTINATIONS
  value: {{ default  .Values.datareporter.additionalDestinations | quote }}
{{- end }}
{{- if .Values.datareporter.eventReportingWebhooks }}
- name: REDASH_EVENT_REPORTING_WEBHOOKS
  value: {{ default  .Values.datareporter.eventReportingWebhooks | quote }}
{{- end }}
{{- if .Values.datareporter.sentryDsn }}
- name: REDASH_SENTRY_DSN
  value: {{ default  .Values.datareporter.sentryDsn | quote }}
{{- end }}
{{- if .Values.datareporter.allowScriptsInUserInput }}
- name: REDASH_ALLOW_SCRIPTS_IN_USER_INPUT
  value: {{ default  .Values.datareporter.allowScriptsInUserInput | quote }}
{{- end }}
{{- if .Values.datareporter.dashboardRefreshIntervals }}
- name: REDASH_DASHBOARD_REFRESH_INTERVALS
  value: {{ default  .Values.datareporter.dashboardRefreshIntervals | quote }}
{{- end }}
{{- if .Values.datareporter.queryRefreshIntervals }}
- name: REDASH_QUERY_REFRESH_INTERVALS
  value: {{ default  .Values.datareporter.queryRefreshIntervals | quote }}
{{- end }}
{{- if .Values.datareporter.passwordLoginEnabled }}
- name: REDASH_PASSWORD_LOGIN_ENABLED
  value: {{ default  .Values.datareporter.passwordLoginEnabled | quote }}
{{- end }}
{{- if .Values.datareporter.samlMetadataUrl }}
- name: REDASH_SAML_METADATA_URL
  value: {{ default  .Values.datareporter.samlMetadataUrl | quote }}
{{- end }}
{{- if .Values.datareporter.samlEntityId }}
- name: REDASH_SAML_ENTITY_ID
  value: {{ default  .Values.datareporter.samlEntityId | quote }}
{{- end }}
{{- if .Values.datareporter.samlNameidFormat }}
- name: REDASH_SAML_NAMEID_FORMAT
  value: {{ default  .Values.datareporter.samlNameidFormat | quote }}
{{- end }}
{{- if .Values.datareporter.dateFormat }}
- name: REDASH_DATE_FORMAT
  value: {{ default  .Values.datareporter.dateFormat | quote }}
{{- end }}
{{- if .Values.datareporter.jwtLoginEnabled }}
- name: REDASH_JWT_LOGIN_ENABLED
  value: {{ default  .Values.datareporter.jwtLoginEnabled | quote }}
{{- end }}
{{- if .Values.datareporter.jwtAuthIssuer }}
- name: REDASH_JWT_AUTH_ISSUER
  value: {{ default  .Values.datareporter.jwtAuthIssuer | quote }}
{{- end }}
{{- if .Values.datareporter.jwtAuthPublicCertsUrl }}
- name: REDASH_JWT_AUTH_PUBLIC_CERTS_URL
  value: {{ default  .Values.datareporter.jwtAuthPublicCertsUrl | quote }}
{{- end }}
{{- if .Values.datareporter.jwtAuthAudience }}
- name: REDASH_JWT_AUTH_AUDIENCE
  value: {{ default  .Values.datareporter.jwtAuthAudience | quote }}
{{- end }}
{{- if .Values.datareporter.jwtAuthAlgorithms }}
- name: REDASH_JWT_AUTH_ALGORITHMS
  value: {{ default  .Values.datareporter.jwtAuthAlgorithms | quote }}
{{- end }}
{{- if .Values.datareporter.jwtAuthCookieName }}
- name: REDASH_JWT_AUTH_COOKIE_NAME
  value: {{ default  .Values.datareporter.jwtAuthCookieName | quote }}
{{- end }}
{{- if .Values.datareporter.jwtAuthHeaderName }}
- name: REDASH_JWT_AUTH_HEADER_NAME
  value: {{ default  .Values.datareporter.jwtAuthHeaderName | quote }}
{{- end }}
{{- if .Values.datareporter.featureShowQueryResultsCount }}
- name: REDASH_FEATURE_SHOW_QUERY_RESULTS_COUNT
  value: {{ default  .Values.datareporter.featureShowQueryResultsCount | quote }}
{{- end }}
{{- if .Values.datareporter.versionCheck }}
- name: REDASH_VERSION_CHECK
  value: {{ default  .Values.datareporter.versionCheck | quote }}
{{- end }}
{{- if .Values.datareporter.featureDisableRefreshQueries }}
- name: REDASH_FEATURE_DISABLE_REFRESH_QUERIES
  value: {{ default  .Values.datareporter.featureDisableRefreshQueries | quote }}
{{- end }}
{{- if .Values.datareporter.featureShowPermissionsControl }}
- name: REDASH_FEATURE_SHOW_PERMISSIONS_CONTROL
  value: {{ default  .Values.datareporter.featureShowPermissionsControl | quote }}
{{- end }}
{{- if .Values.datareporter.featureAllowCustomJsVisualizations }}
- name: REDASH_FEATURE_ALLOW_CUSTOM_JS_VISUALIZATIONS
  value: {{ default  .Values.datareporter.featureAllowCustomJsVisualizations | quote }}
{{- end }}
{{- if .Values.datareporter.featureDumbRecents }}
- name: REDASH_FEATURE_DUMB_RECENTS
  value: {{ default  .Values.datareporter.featureDumbRecents | quote }}
{{- end }}
{{- if .Values.datareporter.featureAutoPublishNamedQueries }}
- name: REDASH_FEATURE_AUTO_PUBLISH_NAMED_QUERIES
  value: {{ default  .Values.datareporter.featureAutoPublishNamedQueries | quote }}
{{- end }}
{{- if .Values.datareporter.featureExtendedAlertOptions }}
- name: REDASH_FEATURE_EXTENDED_ALERT_OPTIONS
  value: {{ default  .Values.datareporter.featureExtendedAlertOptions | quote }}
{{- end }}
{{- if .Values.datareporter.bigqueryHttpTimeout }}
- name: REDASH_BIGQUERY_HTTP_TIMEOUT
  value: {{ default  .Values.datareporter.bigqueryHttpTimeout | quote }}
{{- end }}
{{- if .Values.datareporter.schemaRunTableSizeCalculations }}
- name: REDASH_SCHEMA_RUN_TABLE_SIZE_CALCULATIONS
  value: {{ default  .Values.datareporter.schemaRunTableSizeCalculations | quote }}
{{- end }}
{{- if .Values.datareporter.webWorkers }}
- name: REDASH_WEB_WORKERS
  value: {{ default  .Values.datareporter.webWorkers | quote }}
{{- end }}
{{- if .Values.datareporter.sqlAlchemyEnablePoolPrePing }}
- name: SQLALCHEMY_ENABLE_POOL_PRE_PING
  value: {{ default .Values.datareporter.sqlAlchemyEnablePoolPrePing | quote }}
{{- end }}
## End primary Redash configuration
{{- end -}}

{{/*
Environment variables initialized from secret used across each component.
*/}}
{{- define "datareporter.envFrom" -}}
{{- if .Values.envSecretName -}}
- secretRef:
    name: {{ .Values.envSecretName }}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "datareporter.labels" -}}
helm.sh/chart: {{ include "datareporter.chart" . }}
{{ include "datareporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "datareporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "datareporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "datareporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "datareporter.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

# This ensures a random value is provided for postgresqlPassword:
required "A secure random value for .postgresql.postgresqlPassword is required" .Values.postgresql.postgresqlPassword

{{- define "datareporter.plywood.fullname" -}}
{{- printf "%s-%s" (include "datareporter.fullname" .) "plywood" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{ include "base.images.image" ( dict "imageRoot" .Values.path.to.the.image "global" $) }}
*/}}
{{- define "base.images.image" -}}
{{- $registryName := .imageRoot.registry -}}
{{- $repositoryName := .imageRoot.repository -}}
{{- $tag := "" -}}
{{- if  .imageRoot.tag -}}
{{- $tag = .imageRoot.tag | toString -}}
{{- else -}}
{{  $tag = .Chart.AppVersion }}
{{- end -}}
{{- if .global }}
    {{- if .global.imageRegistry }}
     {{- $registryName = .global.imageRegistry -}}
    {{- end -}}
{{- end -}}
{{- if not $registryName }}
    {{- if .Values.image.registry }}
        {{- $registryName = .Values.image.registry -}}
    {{- end -}}
{{- end -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else -}}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end -}}
{{- end -}}
{{- define "base.images.pullPolicy" -}}
{{- $pullPolicy := .imageRoot.pullPolicy -}}
{{- if not $pullPolicy }}
    {{- if .Values.image.pullPolicy }}
        {{- $pullPolicy = .Values.image.pullPolicy -}}
    {{- end -}}
{{- end -}}
{{- if .global }}
    {{- if .global.pullPolicy }}
     {{- $pullPolicy = .global.pullPolicy -}}
    {{- end -}}
{{- end -}}
{{- $pullPolicy  -}}
{{- end -}}