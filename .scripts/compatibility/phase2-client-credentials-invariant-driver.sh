#!/usr/bin/env bash
# jq programs are intentionally single-quoted so shell expansion cannot alter them.
# shellcheck disable=SC2016
set -euo pipefail
umask 077
export LC_ALL=C

readonly FAILURE='Phase 2 client credentials invariant driver failed.'
readonly MAX_INPUT_BYTES=65536
readonly MAX_OUTPUT_BYTES=65536
readonly DOCKER_BIN=/usr/bin/docker
readonly JQ_BIN=/usr/bin/jq
readonly PYTHON_BIN=/usr/bin/python3.12
readonly CURL_BIN=/usr/bin/curl

signing_corrupted=false
primary_postgres_id=''

early_cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ "$status" -ne 0 ]]; then
    printf '%s\n' "$FAILURE" >&2
  fi
  exit "$status"
}
trap early_cleanup EXIT HUP INT TERM

die() {
  return 1
}

trusted_root_binary() {
  local binary=$1 identity mode
  [[ "$binary" == /* && -f "$binary" && -x "$binary" && ! -L "$binary" ]] || die
  [[ "$(/usr/bin/realpath -e -- "$binary" 2>/dev/null || true)" == "$binary" ]] || die
  identity="$(/usr/bin/stat -c '%u|%a|%F' -- "$binary" 2>/dev/null || true)"
  [[ "$identity" =~ ^0\|[0-7]{3,4}\|regular\ file$ ]] || die
  mode=${identity#*|}; mode=${mode%%|*}
  if ((8#$mode & 8#022)); then
    die
  fi
}

for binary in \
  "$DOCKER_BIN" "$JQ_BIN" "$PYTHON_BIN" "$CURL_BIN" /usr/bin/realpath /usr/bin/stat \
  /usr/bin/id /usr/bin/dirname /usr/bin/head /usr/bin/wc /usr/bin/tr /usr/bin/mktemp \
  /usr/bin/chmod /usr/bin/rm /usr/bin/grep; do
  trusted_root_binary "$binary"
done

[[ -n "${ASTER_PHASE2_CONTROL_SOCKET+x}" && -n "${ASTER_CORE_URL+x}" && -n "${ASTER_ADMIN_URL+x}" && \
   -n "${ASTER_FOREIGN_CORE_URL+x}" && -n "${ASTER_FOREIGN_ADMIN_URL+x}" ]] || die
[[ "$ASTER_PHASE2_CONTROL_SOCKET" == /* && ${#ASTER_PHASE2_CONTROL_SOCKET} -le 4096 ]] || die
[[ "$ASTER_PHASE2_CONTROL_SOCKET" != *'//'* && "$ASTER_PHASE2_CONTROL_SOCKET" != *'/./'* && "$ASTER_PHASE2_CONTROL_SOCKET" != *'/../'* ]] || die
[[ ! "$ASTER_PHASE2_CONTROL_SOCKET" =~ [[:cntrl:]] && -S "$ASTER_PHASE2_CONTROL_SOCKET" && ! -L "$ASTER_PHASE2_CONTROL_SOCKET" ]] || die
[[ "$(/usr/bin/realpath -e -- "$ASTER_PHASE2_CONTROL_SOCKET" 2>/dev/null || true)" == "$ASTER_PHASE2_CONTROL_SOCKET" ]] || die
CURRENT_UID="$(/usr/bin/id -u)"
readonly CURRENT_UID
[[ "$(/usr/bin/stat -c '%u|%F' -- "$ASTER_PHASE2_CONTROL_SOCKET" 2>/dev/null || true)" == "$CURRENT_UID|socket" ]] || die
SOCKET_PARENT="$(/usr/bin/dirname -- "$ASTER_PHASE2_CONTROL_SOCKET")"
readonly SOCKET_PARENT
[[ "$(/usr/bin/realpath -e -- "$SOCKET_PARENT" 2>/dev/null || true)" == "$SOCKET_PARENT" ]] || die
[[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$SOCKET_PARENT" 2>/dev/null || true)" == "$CURRENT_UID|700|directory" ]] || die
export DOCKER_HOST="unix://${ASTER_PHASE2_CONTROL_SOCKET}"

restore_signing_material() {
  [[ "$signing_corrupted" == true && -n "$primary_postgres_id" ]] || return 0
  if ! run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres >/dev/null <<'SQL'
SET LOCAL session_replication_role=replica;
UPDATE aster_tenant.signing_key_material
SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0) # 1)
FROM aster_tenant.signing_key_metadata AS metadata
WHERE signing_key_material.tenant_id=metadata.tenant_id
  AND signing_key_material.material_id=metadata.material_id
  AND signing_key_material.key_version_id=metadata.key_version_id
  AND signing_key_material.tenant_id='default'
  AND metadata.lifecycle_state='active';
SQL
  then
    return 1
  fi
  signing_corrupted=false
}

cleanup() {
  local status=$? restore_status=0
  trap - EXIT HUP INT TERM
  if [[ "$signing_corrupted" == true ]] && ! restore_signing_material; then
    restore_status=1
  fi
  if [[ "$status" -ne 0 || "$restore_status" -ne 0 ]]; then
    printf '%s\n' "$FAILURE" >&2
    exit 1
  fi
  exit 0
}
trap cleanup EXIT HUP INT TERM

raw_request="$(/usr/bin/head -c $((MAX_INPUT_BYTES + 1)))"
request_bytes="$(printf '%s' "$raw_request" | /usr/bin/wc -c | /usr/bin/tr -d '[:space:]')"
[[ "$request_bytes" =~ ^[0-9]+$ && "$request_bytes" -gt 0 && "$request_bytes" -le "$MAX_INPUT_BYTES" ]] || die

request="$(printf '%s' "$raw_request" | "$PYTHON_BIN" -c '
import json, re, sys
class DuplicateKey(ValueError): pass
def pairs(items):
    out={}
    for key,value in items:
        if key in out: raise DuplicateKey()
        out[key]=value
    return out
def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys): raise ValueError()
def text(value, pattern=r"^[^\x00-\x1f\x7f]{1,4096}$"):
    if type(value) is not str or re.fullmatch(pattern,value) is None: raise ValueError()
def endpoint(value, core, admin):
    exact(value,["label","coreUrl","adminUrl"])
    if value != {"label":"candidate","coreUrl":core,"adminUrl":admin}: raise ValueError()
def fixture(value):
    exact(value,["allocationId","clients","resources","organization","scopes","boundary"])
    text(value["allocationId"],r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    exact(value["clients"],["basic","post"])
    for name,method in (("basic","client_secret_basic"),("post","client_secret_post")):
        exact(value["clients"][name],["id","method"]); text(value["clients"][name]["id"],r"^[A-Za-z0-9._~-]{1,128}$")
        if value["clients"][name]["method"] != method: raise ValueError()
    exact(value["resources"],["primary","default"])
    for name,indicator in (("primary","https://phase2.example.invalid/api-primary"),("default","https://phase2.example.invalid/api-default")):
        exact(value["resources"][name],["id","indicator"]); text(value["resources"][name]["id"],r"^[A-Za-z0-9._~-]{1,128}$")
        if value["resources"][name]["indicator"] != indicator: raise ValueError()
    exact(value["organization"],["id","scopeName"]); text(value["organization"]["id"],r"^[A-Za-z0-9._~-]{1,128}$")
    if value["organization"]["scopeName"] != "organization:read": raise ValueError()
    exact(value["scopes"],["read","write","unassigned"])
    for name in ("read","write","unassigned"):
        exact(value["scopes"][name],["id","name"]); text(value["scopes"][name]["id"],r"^[A-Za-z0-9._~-]{1,128}$")
        if value["scopes"][name]["name"] != name: raise ValueError()
    exact(value["boundary"],["primary","foreign"])
    if value["boundary"] != {"primary":"provisioned","foreign":"unchanged"}: raise ValueError()
try:
    value=json.load(sys.stdin,object_pairs_hook=pairs)
    exact(value,["schemaVersion","kind","invariantId","target","fixture","credentials"])
    if value["schemaVersion"] != 1 or value["kind"] != "phase2-client-credentials-candidate-invariant-request": raise ValueError()
    if value["invariantId"] not in {
      "client-credentials.cross-tenant-authority-rejected","client-credentials.request-role-write-rejected",
      "client-credentials.signing-failure-rolls-back","client-credentials.user-authority-unchanged",
      "logout-session.verification-storage-closed"}: raise ValueError()
    exact(value["target"],["primary","foreign"])
    endpoint(value["target"]["primary"],"http://localhost:3321/","http://localhost:3421/")
    endpoint(value["target"]["foreign"],"http://localhost:3322/","http://localhost:3422/")
    fixture(value["fixture"])
    exact(value["credentials"],["basic","post"])
    text(value["credentials"]["basic"],r"^[^\x00-\x20\x7f]{1,256}$"); text(value["credentials"]["post"],r"^[^\x00-\x20\x7f]{1,256}$")
    if value["credentials"]["basic"] == value["credentials"]["post"]: raise ValueError()
    sys.stdout.write(json.dumps(value,separators=(",",":"),ensure_ascii=True))
except Exception:
    sys.exit(1)
' 2>/dev/null)" || die
[[ -n "$request" && ${#request} -le $MAX_INPUT_BYTES ]] || die

value() {
  printf '%s' "$request" | "$JQ_BIN" -er "$1" 2>/dev/null
}

invariant_id="$(value '.invariantId')" || die
[[ "$ASTER_CORE_URL" == 'http://localhost:3321/' && "$ASTER_ADMIN_URL" == 'http://localhost:3421/' && \
   "$ASTER_FOREIGN_CORE_URL" == 'http://localhost:3322/' && "$ASTER_FOREIGN_ADMIN_URL" == 'http://localhost:3422/' ]] || die
[[ "$(value '.target.primary.coreUrl')" == "$ASTER_CORE_URL" && "$(value '.target.primary.adminUrl')" == "$ASTER_ADMIN_URL" && \
   "$(value '.target.foreign.coreUrl')" == "$ASTER_FOREIGN_CORE_URL" && "$(value '.target.foreign.adminUrl')" == "$ASTER_FOREIGN_ADMIN_URL" ]] || die

bounded_engine() {
  local output
  output="$($DOCKER_BIN "$@" 2>/dev/null)" || die
  [[ ${#output} -le $MAX_OUTPUT_BYTES ]] || die
  printf '%s' "$output"
}

normalize_image_id() {
  local value=$1
  if [[ "$value" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'sha256:%s' "$value"
  elif [[ "$value" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '%s' "$value"
  else
    return 1
  fi
}

discover_core() {
  local service=$1 ids identity
  ids="$(bounded_engine ps --no-trunc -q --filter "label=com.docker.compose.service=$service")" || die
  [[ "$ids" =~ ^[0-9a-f]{64}$ ]] || die
  identity="$(bounded_engine inspect --format '{{.Id}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project"}}|{{.Config.Image}}|{{.State.Status}}' "$ids")" || die
  printf '%s' "$identity"
}

primary_identity="$(discover_core candidate-primary-core)" || die
foreign_identity="$(discover_core candidate-foreign-core)" || die
IFS='|' read -r primary_core_id primary_service project_name primary_image primary_status <<<"$primary_identity"
IFS='|' read -r foreign_core_id foreign_service foreign_project foreign_image foreign_status <<<"$foreign_identity"
primary_image="$(normalize_image_id "$primary_image")" || die
foreign_image="$(normalize_image_id "$foreign_image")" || die
[[ "$primary_core_id" =~ ^[0-9a-f]{64}$ && "$foreign_core_id" =~ ^[0-9a-f]{64}$ && "$primary_core_id" != "$foreign_core_id" ]] || die
[[ "$primary_service" == candidate-primary-core && "$foreign_service" == candidate-foreign-core ]] || die
[[ "$project_name" =~ ^aster-phase2-client-credentials-[0-9a-f]{16}$ && "$foreign_project" == "$project_name" ]] || die
[[ "$foreign_image" == "$primary_image" ]] || die
[[ "$primary_status" == running && "$foreign_status" == running ]] || die

readiness() {
  local base_url=$1 issuer=$2 body
  body="$($CURL_BIN --fail --silent --show-error --max-time 10 --max-filesize "$MAX_OUTPUT_BYTES" \
    "${base_url}oidc/.well-known/openid-configuration" 2>/dev/null)" || die
  [[ ${#body} -le $MAX_OUTPUT_BYTES ]] || die
  printf '%s' "$body" | "$JQ_BIN" -e --arg issuer "$issuer" 'type=="object" and .issuer==$issuer' >/dev/null 2>&1 || die
}
readiness "$ASTER_CORE_URL" "${ASTER_CORE_URL%/}/oidc"
readiness "$ASTER_ADMIN_URL" "${ASTER_ADMIN_URL%/}/oidc"
readiness "$ASTER_FOREIGN_CORE_URL" "${ASTER_FOREIGN_CORE_URL%/}/oidc"
readiness "$ASTER_FOREIGN_ADMIN_URL" "${ASTER_FOREIGN_ADMIN_URL%/}/oidc"

discover_postgres() {
  local service=$1 ids identity
  ids="$(bounded_engine ps --no-trunc -q --filter "label=com.docker.compose.service=$service" --filter "label=com.docker.compose.project=$project_name")" || die
  [[ "$ids" =~ ^[0-9a-f]{64}$ ]] || die
  identity="$(bounded_engine inspect --format '{{.Id}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project"}}|{{.State.Status}}' "$ids")" || die
  [[ "$identity" == "$ids|$service|$project_name|running" ]] || die
  printf '%s' "$ids"
}
primary_postgres_id="$(discover_postgres candidate-primary-postgres)" || die
foreign_postgres_id="$(discover_postgres candidate-foreign-postgres)" || die
[[ "$primary_postgres_id" != "$foreign_postgres_id" ]] || die

attestation="$($JQ_BIN -cn --arg projectName "$project_name" \
  --arg primaryId "$primary_core_id" --arg primaryService "$primary_service" --arg primaryImage "$primary_image" \
  --arg foreignId "$foreign_core_id" --arg foreignService "$foreign_service" --arg foreignImage "$foreign_image" \
  '{projectName:$projectName,primary:{containerId:$primaryId,service:$primaryService,imageDigest:$primaryImage},foreign:{containerId:$foreignId,service:$foreignService,imageDigest:$foreignImage}}')" || die

run_sql() {
  local container=$1 database=$2 username=$3 output stderr_file stderr_fd stderr_size
  shift 3
  stderr_file="$(/usr/bin/mktemp "$SOCKET_PARENT/phase2-invariant-psql.XXXXXXXX")" || die
  /usr/bin/chmod 0600 -- "$stderr_file"
  exec {stderr_fd}<>"$stderr_file" || {
    /usr/bin/rm -f -- "$stderr_file"
    return 1
  }
  /usr/bin/rm -f -- "$stderr_file" || {
    exec {stderr_fd}>&-
    return 1
  }
  if ! output="$($DOCKER_BIN exec --interactive --user postgres "$container" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username "$username" --dbname "$database" "$@" 2>&$stderr_fd)"; then
    exec {stderr_fd}>&-
    return 1
  fi
  stderr_size="$(/usr/bin/stat -Lc %s -- "/proc/$BASHPID/fd/$stderr_fd" 2>/dev/null || true)"
  exec {stderr_fd}>&-
  if [[ "$stderr_size" != 0 ]]; then
    return 1
  fi
  [[ ${#output} -le $MAX_OUTPUT_BYTES ]] || return 1
  printf '%s' "$output"
}

snapshot() {
  local container=$1 database=$2 output
  output="$(run_sql "$container" "$database" postgres <<'SQL'
SET LOCAL statement_timeout='20s';
SET LOCAL lock_timeout='5s';
SET LOCAL idle_in_transaction_session_timeout='20s';
WITH browser AS (
  SELECT jsonb_build_object(
    'users',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.users row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'sessions',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.sessions row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'grants',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.grants row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'authorizationCodes',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.authorization_codes row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'interactions',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.interactions row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'tokenFamilies',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.token_families row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'refreshTokens',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM aster_tenant.refresh_tokens row WHERE tenant_id='default'),'[]'),'UTF8')),'hex')
  ) value
), machine AS (
  SELECT encode(sha256(convert_to(jsonb_build_object(
    'oidc_client_grants',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY client_id,grant_type) FROM aster_tenant.oidc_client_grants row WHERE tenant_id='default'),'[]'::jsonb),
    'm2m_client_resource_scopes',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY client_id,scope_id) FROM aster_tenant.m2m_client_resource_scopes row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_m2m_clients',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_id,client_id) FROM aster_tenant.organization_m2m_clients row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_m2m_scopes',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_id,client_id,scope_name) FROM aster_tenant.organization_m2m_scopes row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_m2m_resource_scopes',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_id,client_id,scope_id) FROM aster_tenant.organization_m2m_resource_scopes row WHERE tenant_id='default'),'[]'::jsonb)
  )::text,'UTF8')),'hex') value
), signing AS (
  SELECT jsonb_build_object(
    'static',encode(sha256(convert_to(jsonb_build_object(
      'general',COALESCE((SELECT jsonb_agg(jsonb_build_object('metadata',to_jsonb(metadata)-'last_signed_at','material',to_jsonb(material)) ORDER BY metadata.key_version_id) FROM aster_tenant.signing_key_metadata metadata JOIN aster_tenant.signing_key_material material USING(tenant_id,material_id,key_version_id,public_metadata_fingerprint) WHERE metadata.tenant_id='default'),'[]'::jsonb),
      'oidc',COALESCE((SELECT jsonb_agg(jsonb_build_object('metadata',to_jsonb(metadata)-'last_signed_at','material',to_jsonb(material)) ORDER BY metadata.key_version_id) FROM aster_tenant.oidc_id_token_signing_key_metadata metadata JOIN aster_tenant.oidc_id_token_signing_key_material material USING(tenant_id,material_id,key_version_id,public_metadata_fingerprint) WHERE metadata.tenant_id='default'),'[]'::jsonb)
    )::text,'UTF8')),'hex'),
    'generalKeyId',COALESCE((SELECT key_version_id FROM aster_tenant.signing_key_metadata WHERE tenant_id='default' AND lifecycle_state='active'),''),
    'generalLastSignedAt',COALESCE((SELECT (date_part('epoch',last_signed_at)*1000000)::bigint FROM aster_tenant.signing_key_metadata WHERE tenant_id='default' AND lifecycle_state='active'),0),
    'oidcIdTokenKeyId',COALESCE((SELECT key_version_id FROM aster_tenant.oidc_id_token_signing_key_metadata WHERE tenant_id='default' AND lifecycle_state='active'),''),
    'oidcIdTokenLastSignedAt',COALESCE((SELECT (date_part('epoch',last_signed_at)*1000000)::bigint FROM aster_tenant.oidc_id_token_signing_key_metadata WHERE tenant_id='default' AND lifecycle_state='active'),0)
  ) value
)
SELECT jsonb_build_object('browser',browser.value,'machine',machine.value,'signing',signing.value) FROM browser,machine,signing;
SQL
  )" || die
  printf '%s' "$output" | "$JQ_BIN" -ce '
    if (keys|sort)==["browser","machine","signing"] and
       (.browser|keys|sort)==["authorizationCodes","grants","interactions","refreshTokens","sessions","tokenFamilies","users"] and
       (.signing|keys|sort)==["generalKeyId","generalLastSignedAt","oidcIdTokenKeyId","oidcIdTokenLastSignedAt","static"]
    then . else error("closed") end' 2>/dev/null
}

expect_rejected_sql() {
  local error
  if error="$($DOCKER_BIN exec --interactive --user postgres "$primary_postgres_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --username postgres --dbname aster_phase1_candidate_primary 2>&1 >/dev/null)"; then
    return 1
  fi
  [[ -n "$error" && ${#error} -le $MAX_OUTPUT_BYTES ]] || die
  printf '%s' "$error" | /usr/bin/tr '\n' ' ' | /usr/bin/grep -Eq 'ERROR:[[:space:]]+42501:' || die
}

urlencode() {
  printf '%s' "$1" | "$JQ_BIN" -sRr @uri
}

http_token_request() {
  local base_url=$1 client_id=$2 secret=$3 resource=$4 config response body status
  config="$(printf 'request = "POST"\nurl = "%soidc/token"\nheader = "Content-Type: application/x-www-form-urlencoded"\ndata = "grant_type=client_credentials&client_id=%s&client_secret=%s&resource=%s"\n' \
    "$base_url" "$(urlencode "$client_id")" "$(urlencode "$secret")" "$(urlencode "$resource")")" || die
  response="$(printf '%s' "$config" | $CURL_BIN --silent --show-error --max-time 15 \
    --max-filesize "$MAX_OUTPUT_BYTES" --config - --write-out $'\n%{http_code}' 2>/dev/null)" || die
  status="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [[ "$status" =~ ^[0-9]{3}$ && ${#body} -le $MAX_OUTPUT_BYTES ]] || die
  HTTP_STATUS=$status
  HTTP_BODY=$body
}

assert_unchanged() {
  local before=$1 after=$2
  [[ "$(printf '%s\n%s' "$before" "$after" | "$JQ_BIN" -s '.[0]==.[1]')" == true ]] || die
}

terminal() {
  local projection=$1
  "$JQ_BIN" -cn --arg invariantId "$invariant_id" --argjson projection "$projection" --argjson attestation "$attestation" \
    '{schemaVersion:1,kind:"phase2-client-credentials-candidate-invariant",invariantId:$invariantId,projection:$projection,attestation:$attestation}' | /usr/bin/tr -d '\n'
}

basic_client_id="$(value '.fixture.clients.basic.id')" || die
primary_resource="$(value '.fixture.resources.primary.indicator')" || die
basic_secret="$(value '.credentials.basic')" || die

case "$invariant_id" in
  client-credentials.cross-tenant-authority-rejected)
    primary_before="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    foreign_before="$(snapshot "$foreign_postgres_id" aster_phase1_candidate_foreign)" || die
    http_token_request "$ASTER_FOREIGN_CORE_URL" "$basic_client_id" "$basic_secret" "$primary_resource"
    [[ "$HTTP_STATUS" == 400 ]] || die
    printf '%s' "$HTTP_BODY" | "$JQ_BIN" -e 'type=="object" and .error=="invalid_client" and (has("access_token")|not)' >/dev/null 2>&1 || die
    primary_after="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    foreign_after="$(snapshot "$foreign_postgres_id" aster_phase1_candidate_foreign)" || die
    assert_unchanged "$primary_before" "$primary_after"
    assert_unchanged "$foreign_before" "$foreign_after"
    projection='{"invariant":"cross-tenant-authority-rejected","foreignCredential":"rejected","response":{"status":400,"error":"invalid_client"},"primaryAuthority":"unchanged","foreignSigningUse":"unchanged"}'
    terminal "$projection"
    ;;
  client-credentials.request-role-write-rejected)
    before="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    expect_rejected_sql <<'SQL'
SET ROLE aster_request;
INSERT INTO aster_tenant.oidc_client_grants (tenant_id,client_id,grant_type)
VALUES ('default','phase2-write-probe','client_credentials');
SQL
    expect_rejected_sql <<'SQL'
SET ROLE aster_request;
UPDATE aster_tenant.oidc_client_grants
SET grant_type=grant_type
WHERE false;
SQL
    expect_rejected_sql <<'SQL'
SET ROLE aster_request;
DELETE FROM aster_tenant.oidc_client_grants
WHERE false;
SQL
    after="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    assert_unchanged "$before" "$after"
    projection='{"invariant":"request-role-write-rejected","role":"aster_request","insert":"rejected","update":"rejected","delete":"rejected","authority":"unchanged"}'
    terminal "$projection"
    ;;
  client-credentials.signing-failure-rolls-back)
    before="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres >/dev/null <<'SQL'
SET LOCAL session_replication_role=replica;
UPDATE aster_tenant.signing_key_material
SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0) # 1)
FROM aster_tenant.signing_key_metadata AS metadata
WHERE signing_key_material.tenant_id=metadata.tenant_id
  AND signing_key_material.material_id=metadata.material_id
  AND signing_key_material.key_version_id=metadata.key_version_id
  AND signing_key_material.tenant_id='default'
  AND metadata.lifecycle_state='active';
SQL
    signing_corrupted=true
    http_token_request "$ASTER_CORE_URL" "$basic_client_id" "$basic_secret" "$primary_resource"
    [[ "$HTTP_STATUS" == 503 ]] || die
    printf '%s' "$HTTP_BODY" | "$JQ_BIN" -e 'type=="object" and .error=="temporarily_unavailable" and (has("access_token")|not)' >/dev/null 2>&1 || die
    restore_signing_material || die
    after="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    assert_unchanged "$before" "$after"
    projection='{"invariant":"signing-failure-rolls-back","response":{"status":503,"error":"temporarily_unavailable"},"credentialAccepted":true,"tokenPublished":false,"signingUse":"unchanged","authority":"unchanged"}'
    terminal "$projection"
    ;;
  client-credentials.user-authority-unchanged)
    before="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    http_token_request "$ASTER_CORE_URL" "$basic_client_id" "$basic_secret" "$primary_resource"
    [[ "$HTTP_STATUS" == 200 ]] || die
    printf '%s' "$HTTP_BODY" | "$JQ_BIN" -e 'type=="object" and (.access_token|type)=="string" and (.access_token|length)>0 and (has("id_token")|not) and (has("refresh_token")|not)' >/dev/null 2>&1 || die
    after="$(snapshot "$primary_postgres_id" aster_phase1_candidate_primary)" || die
    [[ "$(printf '%s\n%s' "$before" "$after" | "$JQ_BIN" -s '
      .[0].browser==.[1].browser and .[0].machine==.[1].machine and
      .[0].signing.static==.[1].signing.static and
      .[0].signing.oidcIdTokenKeyId==.[1].signing.oidcIdTokenKeyId and
      .[0].signing.oidcIdTokenLastSignedAt==.[1].signing.oidcIdTokenLastSignedAt and
      .[1].signing.generalLastSignedAt > .[0].signing.generalLastSignedAt')" == true ]] || die
    projection='{"invariant":"user-authority-unchanged","successfulMachineGrant":true,"users":"unchanged","sessions":"unchanged","grants":"unchanged","authorizationCodes":"unchanged","interactions":"unchanged"}'
    terminal "$projection"
    ;;
  logout-session.verification-storage-closed)
    verification_catalog="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres <<'SQL'
SET LOCAL statement_timeout='20s';
SELECT jsonb_build_object(
  'forcedRls',(
    SELECT relation.relforcerowsecurity
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname='aster_tenant'
      AND relation.relname='account_verification_records'
  ),
  'columns',(
    SELECT jsonb_agg(attribute.attname ORDER BY attribute.attnum)
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation ON relation.oid=attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname='aster_tenant'
      AND relation.relname='account_verification_records'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  ),
  'privileges',(
    SELECT jsonb_agg(grant_row.privilege_type ORDER BY grant_row.privilege_type)
    FROM information_schema.role_table_grants AS grant_row
    WHERE grant_row.table_schema='aster_tenant'
      AND grant_row.table_name='account_verification_records'
      AND grant_row.grantee='aster_request'
  ),
  'recordCount',(
    SELECT count(*) FROM aster_tenant.account_verification_records
    WHERE tenant_id='default'
  )
);
SQL
    )" || die
    printf '%s' "$verification_catalog" | "$JQ_BIN" -e '
      . == {
        forcedRls:true,
        columns:["tenant_id","verification_digest","account_id","verification_method","issued_at","expires_at"],
        privileges:["INSERT","SELECT"],
        recordCount:0
      }' >/dev/null 2>&1 || die
    projection='{"invariant":"verification-storage-closed","forcedRls":true,"clearMaterial":"absent","requestPrivileges":"insert-select","records":"empty"}'
    terminal "$projection"
    ;;
  *) die ;;
esac

trap - EXIT HUP INT TERM
