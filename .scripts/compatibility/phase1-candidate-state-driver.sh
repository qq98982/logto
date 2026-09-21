#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() {
  printf '%s\n' 'Phase 1 candidate state projection failed.' >&2
  exit 1
}

trusted_binary() {
  local name=$1 candidate resolved owner mode
  candidate="$(command -v "$name" 2>/dev/null || true)"
  resolved="$(realpath -e -- "$candidate" 2>/dev/null || true)"
  [[ -n "$resolved" && -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || fail
  owner="$(stat -c %u -- "$resolved" 2>/dev/null || true)"
  mode="$(stat -c %a -- "$resolved" 2>/dev/null || true)"
  [[ "$owner" == 0 || "$owner" == "$(id -u)" ]] || fail
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#$mode & 8#022)) && fail
  printf '%s' "$resolved"
}

container_id=''
project_name=''
expected_service=''
scenario_id=''
step_id=''
while (($# > 0)); do
  case "$1" in
    --container-id) [[ -z "$container_id" && $# -ge 2 ]] || fail; container_id=$2; shift 2 ;;
    --project-name) [[ -z "$project_name" && $# -ge 2 ]] || fail; project_name=$2; shift 2 ;;
    --expected-service) [[ -z "$expected_service" && $# -ge 2 ]] || fail; expected_service=$2; shift 2 ;;
    --scenario-id) [[ -z "$scenario_id" && $# -ge 2 ]] || fail; scenario_id=$2; shift 2 ;;
    --step-id) [[ -z "$step_id" && $# -ge 2 ]] || fail; step_id=$2; shift 2 ;;
    *) fail ;;
  esac
done

[[ "$container_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
[[ "$project_name" =~ ^aster-phase1-[0-9a-f]{16}$ ]] || fail
case "$expected_service" in
  candidate-primary-postgres) database=aster_phase1_candidate_primary ;;
  candidate-foreign-postgres) database=aster_phase1_candidate_foreign ;;
  *) fail ;;
esac

case "$scenario_id" in
  discovery.config) [[ "$step_id" =~ ^(oidc-discovery|oauth-discovery|jwks)$ ]] || fail ;;
  authorization.password-pkce-consent) [[ "$step_id" =~ ^(authorize|experience-bootstrap|password|identify|submit|consent-get|consent-post|resume|callback|state)$ ]] || fail ;;
  token.authorization-code) [[ "$step_id" =~ ^(token|state)$ ]] || fail ;;
  token.refresh-rotation) [[ "$step_id" =~ ^(code-token|refresh-token|family-state)$ ]] || fail ;;
  userinfo.openid) [[ "$step_id" =~ ^(userinfo|state)$ ]] || fail ;;
  management.application-read) [[ "$step_id" =~ ^(first-party|third-party|saml|state)$ ]] || fail ;;
  management.user-read) [[ "$step_id" =~ ^(users|state)$ ]] || fail ;;
  console.admin-auth-resource-refresh) [[ "$step_id" =~ ^(authorize|code-token|management-refresh|state)$ ]] || fail ;;
  console.admin-organization-token-refresh) [[ "$step_id" =~ ^(organization-refresh|state)$ ]] || fail ;;
  account.admin-operator-read) [[ "$step_id" =~ ^(account|state)$ ]] || fail ;;
  cors.management-list) [[ "$step_id" =~ ^(applications-preflight|users-preflight|applications-get|users-get)$ ]] || fail ;;
  cookie.localhost-port-interleaving) [[ "$step_id" =~ ^(admin-start|data-start|admin-finish|data-finish|data-start-reverse|admin-start-reverse|data-finish-reverse|admin-finish-reverse|state)$ ]] || fail ;;
  authorization.redirect-uri-rejected|authorization.pkce-method-rejected) [[ "$step_id" =~ ^(authorize|state)$ ]] || fail ;;
  token.pkce-verifier-rejected) [[ "$step_id" =~ ^(bad-verifier|valid-verifier-probe|state)$ ]] || fail ;;
  token.code-reuse-rejected) [[ "$step_id" =~ ^(first-exchange|replay|state)$ ]] || fail ;;
  interaction.password-rejected) [[ "$step_id" =~ ^(experience-bootstrap|password|state)$ ]] || fail ;;
  interaction.consent-session-boundary) [[ "$step_id" =~ ^(get-absent|get-partial|get-tampered|get-spliced|get-replayed|get-foreign|post-absent|post-partial|post-tampered|post-spliced|post-replayed|post-foreign|get-valid-b|post-valid-b|state)$ ]] || fail ;;
  token.refresh-reuse-rejected) [[ "$step_id" =~ ^(code-token|rotate|replay-old|probe-descendant|state)$ ]] || fail ;;
  token.issuer-audience-scope-rejected) [[ "$step_id" =~ ^(wrong-issuer|wrong-audience|missing-scope|state)$ ]] || fail ;;
  token.concurrent-code-single-winner|token.concurrent-refresh-single-winner) [[ "$step_id" =~ ^(attempt-a|attempt-b|race|state)$ ]] || fail ;;
  *) fail ;;
esac

engine_socket="${ASTER_PHASE1_ENGINE_SOCKET-}"
if [[ -n "${ASTER_PHASE1_ENGINE_SOCKET+x}" ]]; then
  [[ "${engine_socket}" == /* && "${#engine_socket}" -le 100 && \
    "${engine_socket}" != *'//'* && "${engine_socket}" != *'/./'* && \
    "${engine_socket}" != *'/../'* && ! "${engine_socket}" =~ [[:cntrl:]] && \
    -S "${engine_socket}" && ! -L "${engine_socket}" ]] || fail
  [[ "$(/usr/bin/realpath -e -- "${engine_socket}" 2>/dev/null || true)" == "${engine_socket}" ]] || fail
  [[ "$(/usr/bin/stat -c '%u|%F' -- "${engine_socket}" 2>/dev/null || true)" == "$(/usr/bin/id -u)|socket" ]] || fail
  socket_parent="$(/usr/bin/dirname -- "${engine_socket}")"
  [[ "$(/usr/bin/realpath -e -- "${socket_parent}" 2>/dev/null || true)" == "${socket_parent}" ]] || fail
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "${socket_parent}" 2>/dev/null || true)" == "$(/usr/bin/id -u)|700|directory" ]] || fail
  DOCKER_BIN="$(trusted_binary /usr/bin/docker)"
  [[ "$(/usr/bin/stat -c %u -- "${DOCKER_BIN}")" == 0 ]] || fail
  export DOCKER_HOST="unix://${engine_socket}"
else
  DOCKER_BIN="$(trusted_binary docker)"
fi
readonly DOCKER_BIN
labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$container_id" 2>/dev/null || true)"
[[ "$labels" == "${expected_service}|${project_name}" ]] || fail

projection="$($DOCKER_BIN exec --interactive --user postgres "$container_id" \
  psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
  --set=ON_ERROR_STOP=1 \
  --set="scenario_id=$scenario_id" --set="step_id=$step_id" \
  --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '5s';
SET LOCAL idle_in_transaction_session_timeout = '20s';
SET LOCAL search_path = pg_catalog;
with model_rows as (
  select 'interaction'::text as kind, tenant_id,
    nullif(payload #>> '{params,client_id}', '') as client_id,
    coalesce(nullif(payload #>> '{session,accountId}', ''), nullif(payload #>> '{lastSubmission,login,accountId}', '')) as account_id,
    null::text as family_fingerprint, encode(handle_digest, 'hex') as artifact_fingerprint,
    false as consumed, expires_at > extract(epoch from clock_timestamp())::bigint as active,
    null::bigint as rotation,
    case when jsonb_typeof(payload #> '{result,verificationRecords}')='array' then jsonb_array_length(payload #> '{result,verificationRecords}') else 0 end as verification_count,
    coalesce(payload #>> '{lastSubmission,login,accountId}', payload #>> '{session,accountId}') is not null as identified,
    '[]'::jsonb as oidc_scopes, '[]'::jsonb as resources
  from aster_tenant.interactions
  union all
  select 'session', session_row.tenant_id, authorization_entry.key, session_row.account_id,
    case when nullif(authorization_entry.value->>'grant_id','') is null then null else encode(sha256(convert_to('phase1-family:'||(authorization_entry.value->>'grant_id'),'UTF8')),'hex') end,
    encode(session_row.handle_digest,'hex'), false,
    session_row.expires_at > extract(epoch from clock_timestamp())::bigint, null, 0, false, '[]'::jsonb, '[]'::jsonb
  from aster_tenant.sessions as session_row
  cross join lateral jsonb_each(case when jsonb_typeof(session_row.session_context->'authorizations')='object' then session_row.session_context->'authorizations' else '{}'::jsonb end) as authorization_entry
  union all
  select 'grant', grant_row.tenant_id, grant_row.client_id, grant_row.account_id,
    encode(sha256(convert_to('phase1-family:'||grant_row.grant_id,'UTF8')),'hex'),
    encode(sha256(convert_to('phase1-artifact:'||grant_row.grant_id,'UTF8')),'hex'), false,
    grant_row.expires_at > extract(epoch from clock_timestamp())::bigint, null, 0, false,
    to_jsonb(array_remove(array_remove(regexp_split_to_array(trim(grant_row.permission_data #>> '{approved,scope}'),'\s+'),'openid'),'offline_access')),
    coalesce((select jsonb_agg(jsonb_build_object('indicator',resource.key,'scopes',to_jsonb(regexp_split_to_array(trim(resource.value),'\s+'))) order by resource.key) from jsonb_each_text(coalesce(grant_row.permission_data #> '{approved,resources}','{}'::jsonb)) as resource),'[]'::jsonb)
  from aster_tenant.grants as grant_row
  union all
  select 'one-time', tenant_id, client_id, account_id,
    encode(sha256(convert_to('phase1-family:'||grant_id,'UTF8')),'hex'), encode(code_digest,'hex'), consumed,
    expires_at > extract(epoch from clock_timestamp())::bigint, null, 0, false, '[]'::jsonb, '[]'::jsonb
  from aster_tenant.authorization_codes
  union all
  select 'rotation', family.tenant_id, family.client_id, family.account_id,
    encode(sha256(convert_to('phase1-family:'||family.grant_id,'UTF8')),'hex'), encode(token.refresh_digest,'hex'),
    token.consumed_at is not null, token.expires_at > extract(epoch from clock_timestamp())::bigint,
    token.rotation_ordinal, 0, false, '[]'::jsonb, '[]'::jsonb
  from aster_tenant.refresh_tokens as token join aster_tenant.token_families as family using (tenant_id,family_id)
), model_json as (
  select coalesce(jsonb_agg(jsonb_build_object('kind',kind,'tenantId',tenant_id,'clientId',client_id,'accountId',account_id,'familyFingerprint',family_fingerprint,'artifactFingerprint',artifact_fingerprint,'consumed',consumed,'active',active,'rotation',rotation,'verificationCount',verification_count,'identified',identified,'oidcScopes',oidc_scopes,'resources',resources) order by kind,tenant_id,client_id nulls first,account_id nulls first,artifact_fingerprint),'[]'::jsonb) value from model_rows
), extension_json as (
  select coalesce(jsonb_agg(jsonb_build_object('tenantId',session_row.tenant_id,'accountId',session_row.account_id,'clientId',authorization_entry.key,'loginAccountId',session_row.account_id,'updatedAt',session_row.issued_at*1000) order by session_row.tenant_id,session_row.account_id,authorization_entry.key),'[]'::jsonb) value
  from aster_tenant.sessions as session_row cross join lateral jsonb_each(case when jsonb_typeof(session_row.session_context->'authorizations')='object' then session_row.session_context->'authorizations' else '{}'::jsonb end) authorization_entry where session_row.account_id is not null and nullif(authorization_entry.value->>'grant_id','') is not null
), user_json as (
  select coalesce(jsonb_agg(jsonb_build_object('tenantId',tenant_id,'id',user_id,'applicationId',first_consent_client_id) order by tenant_id,user_id),'[]'::jsonb) value from aster_tenant.users
), verification_json as (
  select coalesce(jsonb_agg(jsonb_build_object('tenantId',tenant_id,'userId',user_id,'count',record_count) order by tenant_id,user_id),'[]'::jsonb) value from (
    select interaction.tenant_id, record->>'accountId' as user_id, count(*)::integer record_count
    from aster_tenant.interactions interaction cross join lateral jsonb_array_elements(case when jsonb_typeof(interaction.payload #> '{result,verificationRecords}')='array' then interaction.payload #> '{result,verificationRecords}' else '[]'::jsonb end) record
    group by interaction.tenant_id, record->>'accountId'
  ) grouped
)
select jsonb_build_object('schemaVersion',1,'scenarioId',:'scenario_id','stepId',:'step_id','models',model_json.value,'extensions',extension_json.value,'users',user_json.value,'verificationRecords',verification_json.value) from model_json,extension_json,user_json,verification_json;
SQL
)" || fail

[[ -n "$projection" ]] || fail
byte_count="$(printf '%s' "$projection" | wc -c | tr -d '[:space:]')"
[[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 524288 ]] || fail
printf '%s\n' "$projection"
