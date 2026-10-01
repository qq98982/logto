#!/usr/bin/env bash
# jq programs are intentionally single-quoted so shell expansion cannot alter them.
# shellcheck disable=SC2016
set -euo pipefail
umask 077
export LC_ALL=C

readonly FAILURE='Phase 2 client credentials state driver failed.'
readonly MAX_INPUT_BYTES=65536
readonly MAX_ENGINE_BYTES=65536
readonly MAX_DB_BYTES=65536
readonly DOCKER_BIN=/usr/bin/docker
readonly JQ_BIN=/usr/bin/jq
readonly PYTHON_BIN=/usr/bin/python3.12
readonly CURL_BIN=/usr/bin/curl
readonly FLOCK_BIN=/usr/bin/flock

handle_path=''
handle_fd=''
handle_identity=''
remove_handle_on_failure=false

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ "$status" -ne 0 && "$remove_handle_on_failure" == true && -n "${handle_fd:-}" ]]; then
    unlink_locked_handle >/dev/null 2>&1 || true
  fi
  if [[ -n "${handle_fd:-}" ]]; then
    exec {handle_fd}>&- || true
    handle_fd=''
  fi
  if [[ "$status" -ne 0 ]]; then
    printf '%s\n' "$FAILURE" >&2
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

die() {
  return 1
}

trusted_root_binary() {
  local binary=$1 identity
  [[ "$binary" == /* && -f "$binary" && -x "$binary" && ! -L "$binary" ]] || die
  [[ "$(/usr/bin/realpath -e -- "$binary" 2>/dev/null || true)" == "$binary" ]] || die
  identity="$(/usr/bin/stat -c '%u|%a|%F' -- "$binary" 2>/dev/null || true)"
  [[ "$identity" =~ ^0\|[0-7]{3,4}\|regular\ file$ ]] || die
  local mode=${identity#*|}
  mode=${mode%%|*}
  if ((8#$mode & 8#022)); then
    die
  fi
}

for binary in \
  "$DOCKER_BIN" "$JQ_BIN" "$PYTHON_BIN" "$CURL_BIN" "$FLOCK_BIN" /usr/bin/realpath /usr/bin/stat /usr/bin/id \
  /usr/bin/dirname /usr/bin/head /usr/bin/wc /usr/bin/tr /usr/bin/od /usr/bin/mkdir \
  /usr/bin/chmod /usr/bin/rm /usr/bin/mktemp; do
  trusted_root_binary "$binary"
done

[[ -n "${ASTER_PHASE2_CONTROL_SOCKET+x}" ]] || die
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

readonly HANDLE_ROOT="$SOCKET_PARENT/phase2-client-credentials-state"
if ! /usr/bin/mkdir --mode=0700 -- "$HANDLE_ROOT" 2>/dev/null; then
  [[ -d "$HANDLE_ROOT" && ! -L "$HANDLE_ROOT" ]] || die
fi
[[ "$(/usr/bin/realpath -e -- "$HANDLE_ROOT" 2>/dev/null || true)" == "$HANDLE_ROOT" ]] || die
[[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$HANDLE_ROOT" 2>/dev/null || true)" == "$CURRENT_UID|700|directory" ]] || die

raw_request="$(/usr/bin/head -c $((MAX_INPUT_BYTES + 1)))"
request_bytes="$(printf '%s' "$raw_request" | /usr/bin/wc -c | /usr/bin/tr -d '[:space:]')"
[[ "$request_bytes" =~ ^[0-9]+$ && "$request_bytes" -gt 0 && "$request_bytes" -le "$MAX_INPUT_BYTES" ]] || die

request="$(printf '%s' "$raw_request" | "$PYTHON_BIN" -c '
import hashlib, json, re, sys

class DuplicateKey(ValueError): pass
def pairs(items):
    out = {}
    for key, value in items:
        if key in out: raise DuplicateKey()
        out[key] = value
    return out
def exact(obj, keys):
    if type(obj) is not dict or set(obj) != set(keys): raise ValueError()
def text(value, pattern=r"^[^\x00-\x1f\x7f]{1,4096}$"):
    if type(value) is not str or re.fullmatch(pattern, value) is None: raise ValueError()
    return value
def target(value, label, core, admin):
    exact(value, ["label", "coreUrl", "adminUrl"])
    if value != {"label": label, "coreUrl": core, "adminUrl": admin}: raise ValueError()
def fixture(value, label):
    exact(value, ["allocationId", "clients", "deviceClients", "resources", "organization", "scopes", "boundary"] + (["admin"] if label == "candidate" else []))
    text(value["allocationId"], r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    if label == "candidate":
        exact(value["admin"], ["allocationId"])
        expected_admin = "phase2-admin-" + hashlib.sha256(value["allocationId"].encode("utf8")).hexdigest()
        if value["admin"]["allocationId"] != expected_admin: raise ValueError()
    exact(value["clients"], ["basic", "post"])
    exact(value["clients"]["basic"], ["id", "method"]); exact(value["clients"]["post"], ["id", "method"])
    if value["clients"]["basic"]["method"] != "client_secret_basic" or value["clients"]["post"]["method"] != "client_secret_post": raise ValueError()
    text(value["clients"]["basic"]["id"], r"^[A-Za-z0-9._~-]{1,128}$"); text(value["clients"]["post"]["id"], r"^[A-Za-z0-9._~-]{1,128}$")
    exact(value["deviceClients"], ["firstParty", "thirdParty", "missingGrant", "ineligibleWeb"])
    for name, application_type, third_party, grant in (("firstParty", "Native", False, True), ("thirdParty", "Native", True, True), ("missingGrant", "Native", False, False), ("ineligibleWeb", "SPA", False, False)):
        client = value["deviceClients"][name]
        exact(client, ["id", "applicationType", "authenticationMethod", "isThirdParty", "deviceGrantEnabled"])
        text(client["id"], r"^[A-Za-z0-9._~-]{1,128}$")
        if client["applicationType"] != application_type or client["authenticationMethod"] != "none" or client["isThirdParty"] is not third_party or client["deviceGrantEnabled"] is not grant: raise ValueError()
    exact(value["resources"], ["primary", "default"])
    for name, indicator in (("primary", "https://phase2.example.invalid/api-primary"), ("default", "https://phase2.example.invalid/api-default")):
        exact(value["resources"][name], ["id", "indicator"]); text(value["resources"][name]["id"], r"^[A-Za-z0-9._~-]{1,128}$")
        if value["resources"][name]["indicator"] != indicator: raise ValueError()
    exact(value["organization"], ["id", "scopeName"]); text(value["organization"]["id"], r"^[A-Za-z0-9._~-]{1,128}$")
    if value["organization"]["scopeName"] != "organization:read": raise ValueError()
    exact(value["scopes"], ["read", "write", "unassigned"])
    for name in ("read", "write", "unassigned"):
        exact(value["scopes"][name], ["id", "name"]); text(value["scopes"][name]["id"], r"^[A-Za-z0-9._~-]{1,128}$")
        if value["scopes"][name]["name"] != name: raise ValueError()
    exact(value["boundary"], ["primary", "foreign"])
    if value["boundary"] != {"primary":"provisioned", "foreign":"unchanged"}: raise ValueError()

try:
    value = json.load(sys.stdin, object_pairs_hook=pairs)
    extras = {
        "finish":["handle","responseStatus","tokenIssued","responseError","signingKeyId"],
        "abort":["handle"], "set-default-resource":["enabled"],
        "device-capture":["handle"], "device-transition":["handle","action"],
        "device-abort":["handle"]
    }
    exact(value, ["schemaVersion", "kind", "operation", "scenarioId", "target", "foreignTarget", "fixture"] + extras.get(value.get("operation"), []))
    if value["schemaVersion"] != 1 or value["kind"] != "phase2-client-credentials-state-request": raise ValueError()
    legacy_scenarios = {"client-credentials." + name for name in ["basic-explicit-resource","post-explicit-resource","default-resource","resource-no-scope","resource-partial-scope","organization-empty-scope","organization-scope","organization-resource-scope","unknown-client-basic","unknown-client-post","wrong-secret-basic","wrong-secret-post","mixed-authentication","missing-target","unknown-resource","unassociated-organization","duplicate-resource","duplicate-scope-name","malformed-scope-whitespace","unsupported-parameter"]}
    device_actions = {
        "device-verification.expired-code":"expire",
        "device-verification.already-used-code":"consume",
        "device-token.expired-code":"expire",
        "device-token.session-bound-expiry":"expire-session"
    }
    scenarios = legacy_scenarios | set(device_actions)
    if value["scenarioId"] not in scenarios: raise ValueError()
    operation = value["operation"]
    if operation not in ("begin","finish","abort","set-default-resource","device-begin","device-capture","device-transition","device-abort"): raise ValueError()
    scenario = value["scenarioId"]
    if operation in ("begin", "finish", "abort") and scenario not in legacy_scenarios: raise ValueError()
    if operation == "set-default-resource" and scenario != "client-credentials.missing-target": raise ValueError()
    if operation in ("device-begin", "device-capture", "device-transition", "device-abort") and scenario not in device_actions: raise ValueError()
    label = value["target"].get("label") if type(value["target"]) is dict else None
    if label == "oracle":
        target(value["target"], label, "http://localhost:3311/", "http://localhost:3411/")
        target(value["foreignTarget"], label, "http://localhost:3312/", "http://localhost:3412/")
    elif label == "candidate":
        target(value["target"], label, "http://localhost:3321/", "http://localhost:3421/")
        target(value["foreignTarget"], label, "http://localhost:3322/", "http://localhost:3422/")
    else: raise ValueError()
    fixture(value["fixture"], label)
    if operation == "finish":
        text(value["handle"], r"^[0-9a-f]{32}$")
        if type(value["responseStatus"]) is not int or not 100 <= value["responseStatus"] <= 599 or type(value["tokenIssued"]) is not bool: raise ValueError()
        if value["responseError"] is not None and value["responseError"] not in ("invalid_client", "invalid_target", "access_denied", "invalid_request"): raise ValueError()
        if value["signingKeyId"] is not None: text(value["signingKeyId"], r"^[A-Za-z0-9._~-]{1,256}$")
    elif operation in ("abort", "device-abort"):
        if value["handle"] is not None: text(value["handle"], r"^[0-9a-f]{32}$")
    elif operation == "device-capture":
        text(value["handle"], r"^[0-9a-f]{32}$")
    elif operation == "device-transition":
        text(value["handle"], r"^[0-9a-f]{32}$")
        if value["action"] not in ("expire", "consume", "expire-session"): raise ValueError()
        if value["action"] != device_actions[value["scenarioId"]]: raise ValueError()
    elif operation == "set-default-resource":
        if type(value["enabled"]) is not bool: raise ValueError()
    sys.stdout.write(json.dumps(value, separators=(",",":"), ensure_ascii=True))
except Exception:
    sys.exit(1)
' 2>/dev/null)" || die
[[ -n "$request" && ${#request} -le $MAX_INPUT_BYTES ]] || die

operation="$(printf '%s' "$request" | "$JQ_BIN" -er '.operation' 2>/dev/null)" || die
scenario_id="$(printf '%s' "$request" | "$JQ_BIN" -er '.scenarioId' 2>/dev/null)" || die
target_kind="$(printf '%s' "$request" | "$JQ_BIN" -er '.target.label' 2>/dev/null)" || die

fixture_value() {
  printf '%s' "$request" | "$JQ_BIN" -er "$1" 2>/dev/null
}

fixture_boolean() {
  printf '%s' "$request" | "$JQ_BIN" -r "$1" 2>/dev/null
}

case "$target_kind" in
  oracle)
    primary_core_service='oracle-primary-core'
    foreign_core_service='oracle-foreign-core'
    primary_postgres_service='oracle-primary-postgres'
    foreign_postgres_service='oracle-foreign-postgres'
    primary_database=aster
    database_user=aster
    ;;
  candidate)
    primary_core_service='candidate-primary-core'
    foreign_core_service='candidate-foreign-core'
    primary_postgres_service='candidate-primary-postgres'
    foreign_postgres_service='candidate-foreign-postgres'
    primary_database=aster_phase1_candidate_primary
    database_user=postgres
    ;;
  *) die ;;
esac

bounded_engine() {
  local output
  output="$($DOCKER_BIN "$@" 2>/dev/null)" || die
  [[ ${#output} -le $MAX_ENGINE_BYTES ]] || die
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

primary_identity="$(discover_core "$primary_core_service")" || die
foreign_identity="$(discover_core "$foreign_core_service")" || die
IFS='|' read -r primary_core_id primary_service project_name primary_image primary_status <<<"$primary_identity"
IFS='|' read -r foreign_core_id foreign_service foreign_project foreign_image foreign_status <<<"$foreign_identity"
primary_image="$(normalize_image_id "$primary_image")" || die
foreign_image="$(normalize_image_id "$foreign_image")" || die
[[ "$primary_core_id" =~ ^[0-9a-f]{64}$ && "$foreign_core_id" =~ ^[0-9a-f]{64}$ && "$primary_core_id" != "$foreign_core_id" ]] || die
[[ "$primary_service" == "$primary_core_service" && "$foreign_service" == "$foreign_core_service" ]] || die
[[ "$project_name" =~ ^aster-phase2-client-credentials-[0-9a-f]{16}$ && "$foreign_project" == "$project_name" ]] || die
[[ "$foreign_image" == "$primary_image" ]] || die
[[ "$primary_status" == running && "$foreign_status" == running ]] || die

readiness() {
  local base_url=$1 expected_issuer=$2 body
  body="$($CURL_BIN --fail --silent --show-error --max-time 10 --max-filesize "$MAX_ENGINE_BYTES" \
    "${base_url}oidc/.well-known/openid-configuration" 2>/dev/null)" || die
  [[ ${#body} -le $MAX_ENGINE_BYTES ]] || die
  printf '%s' "$body" | "$JQ_BIN" -e --arg issuer "$expected_issuer" \
    'type=="object" and .issuer==$issuer' >/dev/null 2>&1 || die
}

oracle_signing_key_id() {
  local base_url=$1 body
  body="$($CURL_BIN --fail --silent --show-error --max-time 10 --max-filesize "$MAX_ENGINE_BYTES" \
    "${base_url}oidc/jwks" 2>/dev/null)" || die
  [[ ${#body} -le $MAX_ENGINE_BYTES ]] || die
  printf '%s' "$body" | "$JQ_BIN" -er '
    if type=="object" and (.keys|type)=="array" and (.keys|length)>0 and
       (.keys[0]|type)=="object" and (.keys[0].kid|type)=="string" and
       (.keys[0].kid|length)==43 and (.keys[0].kid|test("^[A-Za-z0-9_-]+$"))
    then .keys[0].kid else error("closed") end' 2>/dev/null
}

primary_core_url="$(fixture_value '.target.coreUrl')" || die
primary_admin_url="$(fixture_value '.target.adminUrl')" || die
foreign_core_url="$(fixture_value '.foreignTarget.coreUrl')" || die
foreign_admin_url="$(fixture_value '.foreignTarget.adminUrl')" || die
readiness "$primary_core_url" "${primary_core_url%/}/oidc"
readiness "$primary_admin_url" "${primary_admin_url%/}/oidc"
readiness "$foreign_core_url" "${foreign_core_url%/}/oidc"
readiness "$foreign_admin_url" "${foreign_admin_url%/}/oidc"

discover_postgres() {
  local service=$1 ids identity
  ids="$(bounded_engine ps --no-trunc -q --filter "label=com.docker.compose.service=$service" --filter "label=com.docker.compose.project=$project_name")" || die
  [[ "$ids" =~ ^[0-9a-f]{64}$ ]] || die
  identity="$(bounded_engine inspect --format '{{.Id}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project"}}|{{.State.Status}}' "$ids")" || die
  [[ "$identity" == "$ids|$service|$project_name|running" ]] || die
  printf '%s' "$ids"
}

primary_postgres_id="$(discover_postgres "$primary_postgres_service")" || die
foreign_postgres_id="$(discover_postgres "$foreign_postgres_service")" || die
[[ "$primary_postgres_id" != "$foreign_postgres_id" ]] || die

attestation="$($JQ_BIN -cn \
  --arg projectName "$project_name" \
  --arg primaryId "$primary_core_id" --arg primaryService "$primary_service" --arg primaryImage "$primary_image" \
  --arg foreignId "$foreign_core_id" --arg foreignService "$foreign_service" --arg foreignImage "$foreign_image" \
  '{projectName:$projectName,primary:{containerId:$primaryId,service:$primaryService,imageDigest:$primaryImage},foreign:{containerId:$foreignId,service:$foreignService,imageDigest:$foreignImage}}')" || die

allocation_id="$(fixture_value '.fixture.allocationId')" || die
basic_client_id="$(fixture_value '.fixture.clients.basic.id')" || die
post_client_id="$(fixture_value '.fixture.clients.post.id')" || die
device_client_id="$(fixture_value '.fixture.deviceClients.firstParty.id')" || die
primary_resource="$(fixture_value '.fixture.resources.primary.indicator')" || die
default_resource_id="$(fixture_value '.fixture.resources.default.id')" || die
organization_id="$(fixture_value '.fixture.organization.id')" || die

case "$scenario_id" in
  client-credentials.post-explicit-resource|client-credentials.wrong-secret-post|client-credentials.unassociated-organization)
    client_id=$post_client_id
    ;;
  client-credentials.unknown-client-basic)
    client_id='phase2-unknown-client-basic'
    ;;
  client-credentials.unknown-client-post)
    client_id='phase2-unknown-client-post'
    ;;
  *)
    client_id=$basic_client_id
    ;;
esac
resource=$primary_resource
organization=''
requested_scope=''
request_target=resource
case "$scenario_id" in
  client-credentials.default-resource) resource=''; request_target=default ;;
  client-credentials.missing-target) resource=''; request_target=none ;;
  client-credentials.unknown-resource) resource='https://phase2.example.invalid/unknown' ;;
  client-credentials.organization-empty-scope|client-credentials.organization-scope|client-credentials.unassociated-organization)
    resource=''; organization=$organization_id; request_target=organization ;;
  client-credentials.organization-resource-scope)
    organization=$organization_id; request_target='resource-organization' ;;
  client-credentials.duplicate-resource) request_target='duplicate-resource' ;;
esac
case "$scenario_id" in
  client-credentials.resource-partial-scope) requested_scope='read unavailable' ;;
  client-credentials.organization-scope) requested_scope='organization:read unavailable' ;;
  client-credentials.organization-resource-scope) requested_scope='read write unassigned' ;;
  client-credentials.duplicate-scope-name) requested_scope='read read write' ;;
  client-credentials.malformed-scope-whitespace) requested_scope=' read  write ' ;;
esac

run_primary_sql() {
  local output stderr_file stderr_fd stderr_size
  stderr_file="$(/usr/bin/mktemp "$HANDLE_ROOT/psql-stderr.XXXXXXXX")" || die
  /usr/bin/chmod 0600 -- "$stderr_file"
  exec {stderr_fd}<>"$stderr_file" || {
    /usr/bin/rm -f -- "$stderr_file"
    return 1
  }
  /usr/bin/rm -f -- "$stderr_file" || {
    exec {stderr_fd}>&-
    return 1
  }
  if ! output="$($DOCKER_BIN exec --interactive --user postgres "$primary_postgres_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username "$database_user" --dbname "$primary_database" "$@" \
    2>&$stderr_fd)"; then
    exec {stderr_fd}>&-
    return 1
  fi
  stderr_size="$(/usr/bin/stat -Lc %s -- "/proc/$BASHPID/fd/$stderr_fd" 2>/dev/null || true)"
  exec {stderr_fd}>&-
  if [[ "$stderr_size" != 0 ]]; then
    return 1
  fi
  [[ ${#output} -le $MAX_DB_BYTES ]] || die
  printf '%s' "$output"
}

snapshot_oracle() {
  run_primary_sql \
    --set="client_id=$client_id" --set="resource=$resource" --set="organization_id=$organization" \
    --set="requested_scope=$requested_scope" --set="request_target=$request_target" <<'SQL'
SET LOCAL statement_timeout='20s';
SET LOCAL lock_timeout='5s';
SET LOCAL idle_in_transaction_session_timeout='20s';
WITH client_row AS (
  SELECT id FROM applications WHERE tenant_id='default' AND id=:'client_id'
    AND type='MachineToMachine' LIMIT 2
), selected_resource AS (
  SELECT id,indicator FROM resources WHERE tenant_id='default' AND (
    (:'request_target'='default' AND is_default) OR
    (:'request_target' IN ('resource','resource-organization','duplicate-resource') AND indicator=:'resource')
  ) LIMIT 2
), resource_authority AS (
  SELECT DISTINCT scope.name
  FROM applications_roles ar
  JOIN roles r ON r.tenant_id=ar.tenant_id AND r.id=ar.role_id AND r.type='MachineToMachine'
  JOIN roles_scopes rs ON rs.tenant_id=r.tenant_id AND rs.role_id=r.id
  JOIN scopes scope ON scope.tenant_id=rs.tenant_id AND scope.id=rs.scope_id
  JOIN selected_resource resource ON resource.id=scope.resource_id
  WHERE ar.tenant_id='default' AND ar.application_id=:'client_id'
), organization_association AS (
  SELECT 1 AS present FROM organization_application_relations
  WHERE tenant_id='default' AND organization_id=:'organization_id' AND application_id=:'client_id'
), organization_scope_authority AS (
  SELECT DISTINCT scope.name
  FROM organization_role_application_relations relation
  JOIN organization_roles role ON role.tenant_id=relation.tenant_id AND role.id=relation.organization_role_id AND role.type='MachineToMachine'
  JOIN organization_role_scope_relations role_scope ON role_scope.tenant_id=role.tenant_id AND role_scope.organization_role_id=role.id
  JOIN organization_scopes scope ON scope.tenant_id=role_scope.tenant_id AND scope.id=role_scope.organization_scope_id
  WHERE relation.tenant_id='default' AND relation.organization_id=:'organization_id' AND relation.application_id=:'client_id'
), organization_resource_authority AS (
  SELECT DISTINCT scope.name
  FROM organization_role_application_relations relation
  JOIN organization_roles role ON role.tenant_id=relation.tenant_id AND role.id=relation.organization_role_id AND role.type='MachineToMachine'
  JOIN organization_role_resource_scope_relations role_scope ON role_scope.tenant_id=role.tenant_id AND role_scope.organization_role_id=role.id
  JOIN scopes scope ON scope.tenant_id=role_scope.tenant_id AND scope.id=role_scope.scope_id
  JOIN selected_resource resource ON resource.id=scope.resource_id
  WHERE relation.tenant_id='default' AND relation.organization_id=:'organization_id' AND relation.application_id=:'client_id'
), available AS (
  SELECT name FROM resource_authority WHERE :'request_target' IN ('resource','default','duplicate-resource')
  UNION SELECT name FROM organization_scope_authority WHERE :'request_target'='organization'
  UNION SELECT name FROM organization_resource_authority WHERE :'request_target'='resource-organization'
), requested AS (
  SELECT DISTINCT value AS name FROM regexp_split_to_table(trim(:'requested_scope'), ' +') WITH ORDINALITY AS item(value,position)
  WHERE value<>''
), authority AS (
  SELECT CASE
    WHEN (SELECT count(*) FROM client_row)<>1 THEN 'unauthorized-client'
    WHEN :'request_target'='none' THEN 'invalid-target'
    WHEN :'request_target' IN ('resource','default','resource-organization','duplicate-resource') AND (SELECT count(*) FROM selected_resource)<>1 THEN 'invalid-target'
    WHEN :'request_target' IN ('organization','resource-organization') AND (SELECT count(*) FROM organization_association)<>1 THEN 'access-denied'
    ELSE 'authorized' END AS decision
), facts AS (
  SELECT jsonb_build_object(
    'decision',(SELECT decision FROM authority),
    'targetKind',CASE WHEN (SELECT decision FROM authority)<>'authorized' THEN 'none' WHEN :'request_target'='organization' THEN 'organization' ELSE 'resource' END,
    'target',CASE WHEN (SELECT decision FROM authority)<>'authorized' THEN NULL WHEN :'request_target'='organization' THEN :'organization_id' ELSE (SELECT indicator FROM selected_resource) END,
    'availableScopes',COALESCE((SELECT jsonb_agg(name ORDER BY name) FROM available),'[]'::jsonb),
    'effectiveScopes',CASE WHEN :'requested_scope'='' THEN '[]'::jsonb ELSE COALESCE((SELECT jsonb_agg(name ORDER BY name) FROM requested JOIN available USING(name)),'[]'::jsonb) END
  ) value
), browser AS (
  SELECT jsonb_build_object(
    'users',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM users row WHERE tenant_id='default'),'[]'),'UTF8')),'hex'),
    'sessions',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM oidc_model_instances row WHERE tenant_id='default' AND model_name='Session'),'[]'),'UTF8')),'hex'),
    'grants',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM oidc_model_instances row WHERE tenant_id='default' AND model_name='Grant'),'[]'),'UTF8')),'hex'),
    'authorizationCodes',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM oidc_model_instances row WHERE tenant_id='default' AND model_name='AuthorizationCode'),'[]'),'UTF8')),'hex'),
    'interactions',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM oidc_model_instances row WHERE tenant_id='default' AND model_name='Interaction'),'[]'),'UTF8')),'hex'),
    'tokenFamilies',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM oidc_model_instances row WHERE tenant_id='default' AND model_name='RefreshToken'),'[]'),'UTF8')),'hex'),
    'refreshTokens',encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text)::text FROM oidc_model_instances row WHERE tenant_id='default' AND model_name='RefreshToken'),'[]'),'UTF8')),'hex')
  ) value
), machine AS (
  SELECT encode(sha256(convert_to(jsonb_build_object(
    'applications',COALESCE((SELECT jsonb_agg(to_jsonb(row)-'secret' ORDER BY id) FROM applications row WHERE tenant_id='default'),'[]'::jsonb),
    'resources',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM resources row WHERE tenant_id='default'),'[]'::jsonb),
    'scopes',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM scopes row WHERE tenant_id='default'),'[]'::jsonb),
    'roles',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM roles row WHERE tenant_id='default'),'[]'::jsonb),
    'applications_roles',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM applications_roles row WHERE tenant_id='default'),'[]'::jsonb),
    'roles_scopes',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM roles_scopes row WHERE tenant_id='default'),'[]'::jsonb),
    'organizations',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM organizations row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_roles',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM organization_roles row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_scopes',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY id) FROM organization_scopes row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_application_relations',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_id,application_id) FROM organization_application_relations row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_role_application_relations',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_id,organization_role_id,application_id) FROM organization_role_application_relations row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_role_scope_relations',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_role_id,organization_scope_id) FROM organization_role_scope_relations row WHERE tenant_id='default'),'[]'::jsonb),
    'organization_role_resource_scope_relations',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY organization_role_id,scope_id) FROM organization_role_resource_scope_relations row WHERE tenant_id='default'),'[]'::jsonb)
  )::text,'UTF8')),'hex') value
), signing AS (
  SELECT jsonb_build_object(
    'static',encode(sha256(convert_to(value::text,'UTF8')),'hex'),
    'generalKeyId',COALESCE((SELECT element->>'id' FROM jsonb_array_elements(value) WITH ORDINALITY item(element,position) ORDER BY CASE element->>'status' WHEN 'Current' THEN 0 ELSE 1 END,position LIMIT 1),''),
    'generalLastSignedAt',0,
    'oidcIdTokenKeyId',COALESCE((SELECT element->>'id' FROM jsonb_array_elements(value) WITH ORDINALITY item(element,position) ORDER BY CASE element->>'status' WHEN 'Current' THEN 0 ELSE 1 END,position LIMIT 1),''),
    'oidcIdTokenLastSignedAt',0
  ) value FROM logto_configs WHERE tenant_id='default' AND key='oidc.privateKeys'
)
SELECT jsonb_build_object('authority',facts.value,'browser',browser.value,'machine',machine.value,'signing',signing.value)
FROM facts,browser,machine,signing;
SQL
}

snapshot_candidate() {
  run_primary_sql \
    --set="client_id=$client_id" --set="resource=$resource" --set="organization_id=$organization" \
    --set="requested_scope=$requested_scope" --set="request_target=$request_target" <<'SQL'
SET LOCAL statement_timeout='20s';
SET LOCAL lock_timeout='5s';
SET LOCAL idle_in_transaction_session_timeout='20s';
WITH client_row AS (
  SELECT client_id FROM aster_tenant.oidc_clients WHERE tenant_id='default' AND client_id=:'client_id' LIMIT 2
), grant_row AS (
  SELECT grant_type FROM aster_tenant.oidc_client_grants WHERE tenant_id='default' AND client_id=:'client_id' AND grant_type='client_credentials' LIMIT 2
), selected_resource AS (
  SELECT resource_id,indicator FROM aster_tenant.api_resources WHERE tenant_id='default' AND (
    (:'request_target'='default' AND is_default) OR
    (:'request_target' IN ('resource','resource-organization','duplicate-resource') AND indicator=:'resource')
  ) LIMIT 2
), association AS (
  SELECT 1 present FROM aster_tenant.organization_m2m_clients WHERE tenant_id='default' AND organization_id=:'organization_id' AND client_id=:'client_id'
), available AS (
  SELECT scope.name FROM aster_tenant.m2m_client_resource_scopes authority
  JOIN aster_tenant.api_scopes scope ON scope.tenant_id=authority.tenant_id AND scope.scope_id=authority.scope_id
  JOIN selected_resource resource ON resource.resource_id=scope.resource_id
  WHERE authority.tenant_id='default' AND authority.client_id=:'client_id' AND :'request_target' IN ('resource','default','duplicate-resource')
  UNION SELECT authority.scope_name FROM aster_tenant.organization_m2m_scopes authority
  WHERE authority.tenant_id='default' AND authority.client_id=:'client_id' AND authority.organization_id=:'organization_id' AND :'request_target'='organization'
  UNION SELECT scope.name FROM aster_tenant.organization_m2m_resource_scopes authority
  JOIN aster_tenant.api_scopes scope ON scope.tenant_id=authority.tenant_id AND scope.scope_id=authority.scope_id
  JOIN selected_resource resource ON resource.resource_id=scope.resource_id
  WHERE authority.tenant_id='default' AND authority.client_id=:'client_id' AND authority.organization_id=:'organization_id' AND :'request_target'='resource-organization'
), requested AS (
  SELECT DISTINCT value AS name FROM regexp_split_to_table(trim(:'requested_scope'), ' +') WITH ORDINALITY AS item(value,position) WHERE value<>''
), authority AS (
  SELECT CASE
    WHEN (SELECT count(*) FROM client_row)<>1 OR (SELECT count(*) FROM grant_row)<>1 THEN 'unauthorized-client'
    WHEN :'request_target'='none' THEN 'invalid-target'
    WHEN :'request_target' IN ('resource','default','resource-organization','duplicate-resource') AND (SELECT count(*) FROM selected_resource)<>1 THEN 'invalid-target'
    WHEN :'request_target' IN ('organization','resource-organization') AND (SELECT count(*) FROM association)<>1 THEN 'access-denied'
    ELSE 'authorized' END decision
), facts AS (
  SELECT jsonb_build_object(
    'decision',(SELECT decision FROM authority),
    'targetKind',CASE WHEN (SELECT decision FROM authority)<>'authorized' THEN 'none' WHEN :'request_target'='organization' THEN 'organization' ELSE 'resource' END,
    'target',CASE WHEN (SELECT decision FROM authority)<>'authorized' THEN NULL WHEN :'request_target'='organization' THEN :'organization_id' ELSE (SELECT indicator FROM selected_resource) END,
    'availableScopes',COALESCE((SELECT jsonb_agg(name ORDER BY name) FROM available),'[]'::jsonb),
    'effectiveScopes',CASE WHEN :'requested_scope'='' THEN '[]'::jsonb ELSE COALESCE((SELECT jsonb_agg(name ORDER BY name) FROM requested JOIN available USING(name)),'[]'::jsonb) END
  ) value
), browser AS (
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
SELECT jsonb_build_object('authority',facts.value,'browser',browser.value,'machine',machine.value,'signing',signing.value)
FROM facts,browser,machine,signing;
SQL
}

snapshot() {
  local value
  if [[ "$target_kind" == oracle ]]; then value="$(snapshot_oracle)"; else value="$(snapshot_candidate)"; fi
  printf '%s' "$value" | "$JQ_BIN" -ce '
    if (keys|sort)==["authority","browser","machine","signing"] and
       (.authority|keys|sort)==["availableScopes","decision","effectiveScopes","target","targetKind"] and
       (.browser|keys|sort)==["authorizationCodes","grants","interactions","refreshTokens","sessions","tokenFamilies","users"] and
       (.signing|keys|sort)==["generalKeyId","generalLastSignedAt","oidcIdTokenKeyId","oidcIdTokenLastSignedAt","static"]
    then . else error("closed") end' 2>/dev/null
}

new_handle() {
  local handle candidate create_fd rw_fd descriptor_identity path_identity
  for _ in {1..16}; do
    handle="$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
    [[ "$handle" =~ ^[0-9a-f]{32}$ ]] || die
    candidate="$HANDLE_ROOT/$handle.json"
    set -o noclobber
    if exec {create_fd}>"$candidate" 2>/dev/null; then
      set +o noclobber
      descriptor_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h' -- "/proc/$BASHPID/fd/$create_fd" 2>/dev/null || true)"
      path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$candidate" 2>/dev/null || true)"
      if [[ ! -f "$candidate" || -L "$candidate" || ! "$descriptor_identity" =~ ^[0-9]+\|[0-9]+\|${CURRENT_UID}\|600\|1$ || "$path_identity" != "$descriptor_identity" ]]; then
        exec {create_fd}>&-
        return 1
      fi
      handle_fd=$create_fd
      handle_path=$candidate
      handle_identity=$descriptor_identity
      if ! exec {rw_fd}<>"/proc/$BASHPID/fd/$create_fd"; then
        unlink_locked_handle || true
        close_handle_file
        return 1
      fi
      exec {create_fd}>&-
      handle_fd=$rw_fd
      "$FLOCK_BIN" --exclusive --timeout 30 "$handle_fd" || {
        unlink_locked_handle || true
        close_handle_file
        return 1
      }
      descriptor_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
      path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$candidate" 2>/dev/null || true)"
      if [[ ! -f "$candidate" || -L "$candidate" || ! "$descriptor_identity" =~ ^[0-9]+\|[0-9]+\|${CURRENT_UID}\|600\|1$ || "$path_identity" != "$descriptor_identity" ]]; then
        unlink_locked_handle || true
        close_handle_file
        return 1
      fi
      handle_identity=$descriptor_identity
      new_handle_value=$handle
      return 0
    fi
    set +o noclobber
  done
  die
}

validate_handle_file() {
  local handle=$1
  [[ "$handle" =~ ^[0-9a-f]{32}$ ]] || die
  handle_path="$HANDLE_ROOT/$handle.json"
  [[ -f "$handle_path" && ! -L "$handle_path" ]] || die
  [[ "$(/usr/bin/realpath -e -- "$handle_path" 2>/dev/null || true)" == "$handle_path" ]] || die
  [[ "$(/usr/bin/stat -c '%u|%a|%h' -- "$handle_path" 2>/dev/null || true)" == "$CURRENT_UID|600|1" ]] || die
}

close_handle_file() {
  if [[ -n "${handle_fd:-}" ]]; then
    exec {handle_fd}>&-
    handle_fd=''
  fi
  handle_identity=''
}

lock_handle_file() {
  local handle=$1 source_path source_identity descriptor_identity path_identity
  [[ "$handle" =~ ^[0-9a-f]{32}$ ]] || die
  source_path="$HANDLE_ROOT/$handle.json"
  if [[ ! -e "$source_path" && ! -L "$source_path" ]]; then
    return 2
  fi
  validate_handle_file "$handle"
  source_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$handle_path" 2>/dev/null || true)"
  [[ "$source_identity" =~ ^[0-9]+\|[0-9]+\|${CURRENT_UID}\|600\|1$ ]] || die
  if ! exec {handle_fd}<>"$source_path"; then
    handle_fd=''
    [[ ! -e "$source_path" && ! -L "$source_path" ]] && return 2
    return 1
  fi
  if ! "$FLOCK_BIN" --exclusive --timeout 30 "$handle_fd"; then
    close_handle_file
    return 1
  fi
  descriptor_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  if [[ ! -e "$source_path" && ! -L "$source_path" ]]; then
    close_handle_file
    return 2
  fi
  path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$source_path" 2>/dev/null || true)"
  if [[ "$descriptor_identity" != "$source_identity" || "$path_identity" != "$source_identity" ]]; then
    close_handle_file
    return 1
  fi
  handle_path=$source_path
  handle_identity=$source_identity
}

write_locked_handle() {
  local document=$1 after_identity path_identity
  [[ -n "${handle_fd:-}" && -n "$handle_identity" ]] || die
  printf '%s' "$document" | "$PYTHON_BIN" -c '
import os, stat, sys
fd_path, maximum_text, uid_text = sys.argv[1:]
maximum, uid = int(maximum_text), int(uid_text)
fd = os.open(fd_path, os.O_RDWR)
data = sys.stdin.buffer.read(maximum + 1)
if not data or len(data) > maximum: raise SystemExit(1)
before = os.fstat(fd)
if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1: raise SystemExit(1)
os.ftruncate(fd, 0); os.lseek(fd, 0, os.SEEK_SET)
view = memoryview(data)
while view:
    written = os.write(fd, view)
    if written <= 0: raise SystemExit(1)
    view = view[written:]
os.fsync(fd)
after = os.fstat(fd)
if (after.st_dev,after.st_ino,after.st_uid,stat.S_IMODE(after.st_mode),after.st_nlink,after.st_size) != (before.st_dev,before.st_ino,uid,0o600,1,len(data)): raise SystemExit(1)
os.close(fd)
' "/proc/$BASHPID/fd/$handle_fd" "$MAX_DB_BYTES" "$CURRENT_UID" 2>/dev/null || die
  after_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$handle_path" 2>/dev/null || true)"
  [[ "$after_identity" == "$handle_identity" && "$path_identity" == "$handle_identity" ]] || die
}

read_locked_handle() {
  local after_identity path_identity
  [[ -n "${handle_fd:-}" && -n "$handle_identity" ]] || die
  "$PYTHON_BIN" -c '
import os, stat, sys
fd_path, maximum_text, uid_text = sys.argv[1:]
maximum, uid = int(maximum_text), int(uid_text)
fd = os.open(fd_path, os.O_RDONLY)
before = os.fstat(fd)
if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size <= 0 or before.st_size > maximum: raise SystemExit(1)
os.lseek(fd, 0, os.SEEK_SET)
data = bytearray()
while len(data) <= maximum:
    chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
    if not chunk: break
    data.extend(chunk)
after = os.fstat(fd)
if len(data) != before.st_size or (after.st_dev,after.st_ino,after.st_uid,after.st_mode,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns) != (before.st_dev,before.st_ino,before.st_uid,before.st_mode,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns): raise SystemExit(1)
sys.stdout.buffer.write(data)
os.close(fd)
' "/proc/$BASHPID/fd/$handle_fd" "$MAX_DB_BYTES" "$CURRENT_UID" 2>/dev/null || die
  after_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$handle_path" 2>/dev/null || true)"
  [[ "$after_identity" == "$handle_identity" && "$path_identity" == "$handle_identity" ]] || die
}

unlink_locked_handle() {
  local descriptor_identity path_identity quarantine quarantine_identity renamed=false
  [[ -n "${handle_fd:-}" && -n "$handle_identity" && -n "$handle_path" ]] || die
  remove_handle_on_failure=false
  descriptor_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$handle_path" 2>/dev/null || true)"
  [[ "$descriptor_identity" == "$handle_identity" && "$path_identity" == "$handle_identity" ]] || die
  for _ in {1..16}; do
    quarantine="$HANDLE_ROOT/.quarantine.$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
    [[ "$quarantine" =~ ^${HANDLE_ROOT}/\.quarantine\.[0-9a-f]{32}$ ]] || die
    [[ ! -e "$quarantine" && ! -L "$quarantine" ]] || continue
    if "$PYTHON_BIN" -c '
import ctypes, os, sys
source, quarantine = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None: raise SystemExit(1)
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
if renameat2(-100, os.fsencode(source), -100, os.fsencode(quarantine), 1) != 0: raise SystemExit(1)
' "$handle_path" "$quarantine" 2>/dev/null; then
      renamed=true
      break
    fi
    die
  done
  [[ "$renamed" == true && ! -e "$handle_path" && ! -L "$handle_path" ]] || die
  quarantine_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$quarantine" 2>/dev/null || true)"
  [[ "$quarantine_identity" == "$handle_identity" ]] || die
  handle_path=$quarantine
  write_locked_handle '{"schemaVersion":1,"retired":true}'
  quarantine_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h' -- "$quarantine" 2>/dev/null || true)"
  [[ "$quarantine_identity" == "$handle_identity" ]] || die
}

terminal_base() {
  local extra=$1
  "$JQ_BIN" -cn --arg operation "$operation" --arg scenarioId "$scenario_id" --argjson attestation "$attestation" --argjson extra "$extra" \
    '$extra + {schemaVersion:1,kind:"phase2-client-credentials-state",operation:$operation,scenarioId:$scenarioId,attestation:$attestation}'
}

device_ids() {
  if [[ "$target_kind" == oracle ]]; then
    run_primary_sql --set="client_id=$device_client_id" <<'SQL'
SELECT COALESCE(jsonb_agg(id ORDER BY id),'[]'::jsonb)
FROM oidc_model_instances
WHERE tenant_id='default' AND model_name='DeviceCode'
  AND COALESCE(payload->>'clientId',payload->'params'->>'client_id')=:'client_id'
  AND expires_at>now();
SQL
  else
    run_primary_sql --set="client_id=$device_client_id" <<'SQL'
SELECT COALESCE(jsonb_agg(device_uid ORDER BY device_uid),'[]'::jsonb)
FROM aster_tenant.device_authorizations
WHERE tenant_id='default' AND client_id=:'client_id'
  AND expires_at>floor(extract(epoch from now()))::bigint;
SQL
  fi
}

load_device_handle() {
  local handle=$1 saved
  lock_handle_file "$handle" || die
  saved="$(read_locked_handle)" || die
  printf '%s' "$saved" | "$JQ_BIN" -e \
    --arg kind "$target_kind" --arg scenarioId "$scenario_id" \
    --arg allocationId "$allocation_id" --arg projectName "$project_name" --arg handle "$handle" '
      (keys==["allocationId","handle","kind","projectName","scenarioId","schemaVersion","selectedId","snapshot"] or
       keys==["allocationId","handle","kind","projectName","scenarioId","schemaVersion","snapshot"]) and
      .schemaVersion==1 and .kind==$kind and .scenarioId==$scenarioId and
      .handle==$handle and
      .allocationId==$allocationId and .projectName==$projectName and
      (.snapshot|type)=="array" and (.snapshot|all(type=="string" and test("^[A-Za-z0-9._~-]{1,128}$"))) and
      (.selectedId == null or (.selectedId|type)=="string" and (.selectedId|test("^[A-Za-z0-9._~-]{1,128}$")))
    ' >/dev/null 2>&1 || die
  remove_handle_on_failure=true
  device_handle_document=$saved
}

case "$operation" in
  begin)
    baseline="$(snapshot)" || die
    new_handle_value=''
    new_handle || die
    handle=$new_handle_value
    remove_handle_on_failure=true
    handle_document="$($JQ_BIN -cn --arg schemaVersion '1' --arg kind "$target_kind" --arg scenarioId "$scenario_id" \
      --arg allocationId "$allocation_id" --arg projectName "$project_name" --arg handle "$handle" --argjson baseline "$baseline" \
      '{schemaVersion:($schemaVersion|tonumber),kind:$kind,scenarioId:$scenarioId,allocationId:$allocationId,projectName:$projectName,handle:$handle,baseline:$baseline}')" || die
    write_locked_handle "$handle_document"
    remove_handle_on_failure=false
    terminal_base "$($JQ_BIN -cn --arg handle "$handle" '{handle:$handle}')" | /usr/bin/tr -d '\n'
    ;;
  finish)
    handle="$(fixture_value '.handle')" || die
    lock_handle_file "$handle" || die
    saved="$(read_locked_handle)" || die
    printf '%s' "$saved" | "$JQ_BIN" -e --arg kind "$target_kind" --arg scenarioId "$scenario_id" --arg allocationId "$allocation_id" --arg projectName "$project_name" --arg handle "$handle" \
      'keys==["allocationId","baseline","handle","kind","projectName","scenarioId","schemaVersion"] and .schemaVersion==1 and .kind==$kind and .scenarioId==$scenarioId and .allocationId==$allocationId and .projectName==$projectName and .handle==$handle' >/dev/null 2>&1 || die
    remove_handle_on_failure=true
    baseline="$(printf '%s' "$saved" | "$JQ_BIN" -ce '.baseline')" || die
    token_issued="$(fixture_boolean '.tokenIssued')" || die
    response_status="$(fixture_value '.responseStatus')" || die
    response_error="$(printf '%s' "$request" | "$JQ_BIN" -r 'if .responseError == null then "null" else .responseError end' 2>/dev/null)" || die
    signing_key_id="$(printf '%s' "$request" | "$JQ_BIN" -r 'if .signingKeyId == null then "null" else .signingKeyId end' 2>/dev/null)" || die
    current="$(snapshot)" || die
    [[ "$(printf '%s\n%s' "$baseline" "$current" | "$JQ_BIN" -s '.[0].browser==.[1].browser and .[0].machine==.[1].machine and .[0].signing.static==.[1].signing.static and .[0].signing.generalKeyId==.[1].signing.generalKeyId and .[0].signing.oidcIdTokenKeyId==.[1].signing.oidcIdTokenKeyId and .[0].signing.oidcIdTokenLastSignedAt==.[1].signing.oidcIdTokenLastSignedAt')" == true ]] || die
    db_decision="$(printf '%s' "$current" | "$JQ_BIN" -er '.authority.decision')" || die
    if [[ "$token_issued" == true ]]; then
      [[ "$response_status" == 200 && "$response_error" == null && "$db_decision" == authorized ]] || die
      [[ "$signing_key_id" =~ ^[A-Za-z0-9._~-]{1,256}$ ]] || die
      if [[ "$target_kind" == candidate ]]; then
        current_general_key_id="$(printf '%s' "$current" | "$JQ_BIN" -er '.signing.generalKeyId')" || die
        [[ "$signing_key_id" == "$current_general_key_id" ]] || die
        before_general_key_id="$(printf '%s' "$baseline" | "$JQ_BIN" -er '.signing.generalKeyId')" || die
        before_general="$(printf '%s' "$baseline" | "$JQ_BIN" -er '.signing.generalLastSignedAt')" || die
        after_general="$(printf '%s' "$current" | "$JQ_BIN" -er '.signing.generalLastSignedAt')" || die
        [[ "$before_general_key_id" == "$current_general_key_id" ]] || die
        [[ "$after_general" =~ ^[0-9]+$ && "$before_general" =~ ^[0-9]+$ && "$after_general" -gt "$before_general" ]] || die
      else
        current_general_key_id="$(oracle_signing_key_id "$primary_core_url")" || die
        [[ "$signing_key_id" == "$current_general_key_id" ]] || die
      fi
      authority="$(printf '%s' "$current" | "$JQ_BIN" -ce '.authority')"
      general_use=verified
    else
      [[ "$signing_key_id" == null ]] || die
      if [[ "$target_kind" == candidate ]]; then
        [[ "$(printf '%s\n%s' "$baseline" "$current" | "$JQ_BIN" -s '.[0].signing.generalLastSignedAt==.[1].signing.generalLastSignedAt')" == true ]] || die
      fi
      general_use=unchanged
      case "$response_error" in
        invalid_client)
          [[ "$response_status" == 400 || "$response_status" == 401 ]] || die
          [[ "$db_decision" == unauthorized-client || "$db_decision" == authorized ]] || die
          published_decision=unauthorized-client
          ;;
        invalid_target)
          [[ "$response_status" == 400 ]] || die
          [[ "$db_decision" == invalid-target || "$db_decision" == authorized ]] || die
          published_decision=invalid-target
          ;;
        access_denied)
          [[ "$response_status" == 403 && "$db_decision" == access-denied ]] || die
          published_decision=access-denied
          ;;
        invalid_request)
          [[ "$response_status" == 400 && "$db_decision" == authorized ]] || die
          published_decision=invalid-request
          ;;
        *) die ;;
      esac
      authority="$($JQ_BIN -cn --arg decision "$published_decision" '{decision:$decision,targetKind:"none",target:null,availableScopes:[],effectiveScopes:[]}')"
    fi
    unlink_locked_handle
    close_handle_file
    remove_handle_on_failure=false
    finish_extra="$($JQ_BIN -cn --arg handle "$handle" --argjson authority "$authority" --arg general "$general_use" \
      '{handle:$handle,authority:$authority,signingUse:{generalKeyUse:$general,oidcIdTokenKeyUse:"unchanged"},sideEffects:{users:0,sessions:0,grants:0,authorizationCodes:0,interactions:0,refreshTokens:0,tokenFamilies:0}}')" || die
    terminal_base "$finish_extra" | /usr/bin/tr -d '\n'
    ;;
  abort)
    handle="$(printf '%s' "$request" | "$JQ_BIN" -er '.handle // empty' 2>/dev/null || true)"
    if [[ -n "$handle" ]]; then
      if lock_handle_file "$handle"; then
        saved="$(read_locked_handle)" || die
        printf '%s' "$saved" | "$JQ_BIN" -e --arg kind "$target_kind" --arg scenarioId "$scenario_id" --arg allocationId "$allocation_id" --arg projectName "$project_name" --arg handle "$handle" \
          'keys==["allocationId","baseline","handle","kind","projectName","scenarioId","schemaVersion"] and .schemaVersion==1 and .kind==$kind and .scenarioId==$scenarioId and .allocationId==$allocationId and .projectName==$projectName and .handle==$handle' >/dev/null 2>&1 || die
        remove_handle_on_failure=true
        unlink_locked_handle
        close_handle_file
        remove_handle_on_failure=false
      else
        lock_status=$?
        [[ "$lock_status" == 2 ]] || die
      fi
    fi
    terminal_base '{"ok":true}' | /usr/bin/tr -d '\n'
    ;;
  set-default-resource)
    enabled="$(fixture_boolean '.enabled')" || die
    if [[ "$target_kind" == oracle ]]; then
      default_result="$(run_primary_sql --set="resource_id=$default_resource_id" --set="enabled=$enabled" <<'SQL'
UPDATE resources SET is_default=false WHERE tenant_id='default' AND is_default;
UPDATE resources SET is_default=:'enabled'::boolean WHERE tenant_id='default' AND id=:'resource_id';
SELECT CASE WHEN
  (SELECT count(*) FROM resources WHERE tenant_id='default' AND id=:'resource_id')=1
  AND (SELECT count(*) FROM resources WHERE tenant_id='default' AND is_default)=CASE WHEN :'enabled'::boolean THEN 1 ELSE 0 END
  AND (NOT :'enabled'::boolean OR EXISTS (SELECT 1 FROM resources WHERE tenant_id='default' AND id=:'resource_id' AND is_default))
THEN 'ok' ELSE 'invalid' END;
SQL
      )" || die
    else
      default_result="$(run_primary_sql --set="resource_id=$default_resource_id" --set="enabled=$enabled" <<'SQL'
UPDATE aster_tenant.api_resources SET is_default=false WHERE tenant_id='default' AND is_default;
UPDATE aster_tenant.api_resources SET is_default=:'enabled'::boolean WHERE tenant_id='default' AND resource_id=:'resource_id';
SELECT CASE WHEN
  (SELECT count(*) FROM aster_tenant.api_resources WHERE tenant_id='default' AND resource_id=:'resource_id')=1
  AND (SELECT count(*) FROM aster_tenant.api_resources WHERE tenant_id='default' AND is_default)=CASE WHEN :'enabled'::boolean THEN 1 ELSE 0 END
  AND (NOT :'enabled'::boolean OR EXISTS (SELECT 1 FROM aster_tenant.api_resources WHERE tenant_id='default' AND resource_id=:'resource_id' AND is_default))
THEN 'ok' ELSE 'invalid' END;
SQL
      )" || die
    fi
    [[ "$default_result" == ok ]] || die
    terminal_base '{"ok":true}' | /usr/bin/tr -d '\n'
    ;;
  device-begin)
    device_snapshot="$(device_ids)" || die
    device_snapshot="$(printf '%s' "$device_snapshot" | "$JQ_BIN" -ce 'if type=="array" and all(type=="string" and test("^[A-Za-z0-9._~-]{1,128}$")) then . else error("closed") end')" || die
    new_handle_value=''
    new_handle || die
    handle=$new_handle_value
    remove_handle_on_failure=true
    handle_document="$($JQ_BIN -cn --arg kind "$target_kind" --arg scenarioId "$scenario_id" \
      --arg allocationId "$allocation_id" --arg projectName "$project_name" --arg handle "$handle" --argjson snapshot "$device_snapshot" \
      '{schemaVersion:1,kind:$kind,scenarioId:$scenarioId,allocationId:$allocationId,projectName:$projectName,handle:$handle,snapshot:$snapshot}')" || die
    write_locked_handle "$handle_document"
    remove_handle_on_failure=false
    terminal_base "$($JQ_BIN -cn --arg handle "$handle" '{handle:$handle}')" | /usr/bin/tr -d '\n'
    ;;
  device-capture)
    handle="$(fixture_value '.handle')" || die
    load_device_handle "$handle"
    printf '%s' "$device_handle_document" | "$JQ_BIN" -e 'has("selectedId")|not' >/dev/null 2>&1 || die
    current_ids="$(device_ids)" || die
    current_ids="$(printf '%s' "$current_ids" | "$JQ_BIN" -ce 'if type=="array" and all(type=="string" and length>0) then . else error("closed") end')" || die
    selected_id="$(printf '%s\n%s' "$device_handle_document" "$current_ids" | "$JQ_BIN" -ser '
      .[0].snapshot as $before | .[1] as $after |
      if (($before-$after)|length)==0 and (($after-$before)|length)==1
      then ($after-$before)[0] else error("not-one-new-device") end' 2>/dev/null)" || die
    captured_document="$(printf '%s' "$device_handle_document" | "$JQ_BIN" -ce --arg selectedId "$selected_id" '. + {selectedId:$selectedId}')" || die
    write_locked_handle "$captured_document"
    close_handle_file
    remove_handle_on_failure=false
    terminal_base '{"ok":true}' | /usr/bin/tr -d '\n'
    ;;
  device-transition)
    handle="$(fixture_value '.handle')" || die
    action="$(fixture_value '.action')" || die
    load_device_handle "$handle"
    selected_id="$(printf '%s' "$device_handle_document" | "$JQ_BIN" -er '.selectedId')" || die
    if [[ "$action" == expire && "$target_kind" == oracle ]]; then
      transition_result="$(run_primary_sql --set="selected_id=$selected_id" <<'SQL'
WITH changed AS (
  UPDATE oidc_model_instances
  SET expires_at=to_timestamp(0),
      payload=pg_catalog.jsonb_set(payload,'{exp}','0'::jsonb,false)
  WHERE tenant_id='default' AND model_name='DeviceCode' AND id=:'selected_id'
    AND pg_catalog.jsonb_typeof(payload->'exp')='number'
  RETURNING expires_at,payload->>'exp' AS payload_exp
)
SELECT CASE WHEN count(*)=1 AND bool_and(expires_at<now() AND payload_exp='0') THEN 'ok' ELSE 'invalid' END FROM changed;
SQL
      )" || die
    elif [[ "$action" == expire ]]; then
      transition_result="$(run_primary_sql --set="selected_id=$selected_id" <<'SQL'
WITH changed AS (
  UPDATE aster_tenant.device_authorizations
  SET issued_at=GREATEST(0,extract(epoch from now())::bigint-601),
      expires_at=GREATEST(0,extract(epoch from now())::bigint-601)+600
  WHERE tenant_id='default' AND device_uid=:'selected_id'
  RETURNING expires_at
)
SELECT CASE WHEN count(*)=1 AND bool_and(expires_at<extract(epoch from now())::bigint) THEN 'ok' ELSE 'invalid' END FROM changed;
SQL
      )" || die
    elif [[ "$action" == consume && "$target_kind" == oracle ]]; then
      transition_result="$(run_primary_sql --set="selected_id=$selected_id" <<'SQL'
WITH changed AS (
  UPDATE oidc_model_instances SET consumed_at=now()
  WHERE tenant_id='default' AND model_name='DeviceCode' AND id=:'selected_id' AND consumed_at IS NULL
  RETURNING consumed_at
)
SELECT CASE WHEN count(*)=1 AND bool_and(consumed_at IS NOT NULL) THEN 'ok' ELSE 'invalid' END FROM changed;
SQL
      )" || die
    elif [[ "$action" == consume ]]; then
      transition_result="$(run_primary_sql --set="selected_id=$selected_id" <<'SQL'
WITH changed AS (
  UPDATE aster_tenant.device_authorizations
  SET status='consumed',consumed_at=extract(epoch from now())::bigint
  WHERE tenant_id='default' AND device_uid=:'selected_id' AND status='approved' AND consumed_at IS NULL
  RETURNING status,consumed_at
)
SELECT CASE WHEN count(*)=1 AND bool_and(status='consumed' AND consumed_at IS NOT NULL) THEN 'ok' ELSE 'invalid' END FROM changed;
SQL
      )" || die
    elif [[ "$action" == expire-session && "$target_kind" == oracle ]]; then
      transition_result="$(run_primary_sql --set="selected_id=$selected_id" <<'SQL'
WITH device AS (
  SELECT payload->>'sessionUid' session_uid FROM oidc_model_instances
  WHERE tenant_id='default' AND model_name='DeviceCode' AND id=:'selected_id'
), session_candidates AS (
  SELECT id FROM oidc_model_instances
  WHERE tenant_id='default' AND model_name='Session'
    AND payload->>'uid'=(SELECT session_uid FROM device)
), unique_session AS (
  SELECT min(id) AS id FROM session_candidates HAVING count(*)=1
), changed AS (
  UPDATE oidc_model_instances
  SET expires_at=to_timestamp(0),
      payload=pg_catalog.jsonb_set(payload,'{exp}','0'::jsonb,false)
  WHERE tenant_id='default' AND model_name='Session'
    AND id=(SELECT id FROM unique_session)
    AND pg_catalog.jsonb_typeof(payload->'exp')='number'
  RETURNING expires_at,payload->>'exp' AS payload_exp
)
SELECT CASE WHEN count(*)=1 AND bool_and(expires_at<now() AND payload_exp='0') THEN 'ok' ELSE 'invalid' END FROM changed;
SQL
      )" || die
    elif [[ "$action" == expire-session ]]; then
      transition_result="$(run_primary_sql --set="selected_id=$selected_id" <<'SQL'
WITH device AS (
  SELECT session_uid FROM aster_tenant.device_authorizations
  WHERE tenant_id='default' AND device_uid=:'selected_id' AND status='consumed'
), changed AS (
  UPDATE aster_tenant.sessions SET expires_at=0
  WHERE tenant_id='default' AND session_uid=(SELECT session_uid FROM device)
  RETURNING expires_at
)
SELECT CASE WHEN count(*)=1 AND bool_and(expires_at=0) THEN 'ok' ELSE 'invalid' END FROM changed;
SQL
      )" || die
    else
      die
    fi
    [[ "$transition_result" == ok ]] || die
    close_handle_file
    remove_handle_on_failure=false
    terminal_base '{"ok":true}' | /usr/bin/tr -d '\n'
    ;;
  device-abort)
    handle="$(printf '%s' "$request" | "$JQ_BIN" -er '.handle // empty' 2>/dev/null || true)"
    if [[ -n "$handle" ]]; then
      if lock_handle_file "$handle"; then
        saved="$(read_locked_handle)" || die
        printf '%s' "$saved" | "$JQ_BIN" -e --arg kind "$target_kind" --arg scenarioId "$scenario_id" --arg allocationId "$allocation_id" --arg projectName "$project_name" --arg handle "$handle" '
          (keys==["allocationId","handle","kind","projectName","scenarioId","schemaVersion","selectedId","snapshot"] or keys==["allocationId","handle","kind","projectName","scenarioId","schemaVersion","snapshot"]) and
          .schemaVersion==1 and .kind==$kind and .scenarioId==$scenarioId and .allocationId==$allocationId and .projectName==$projectName and .handle==$handle' >/dev/null 2>&1 || die
        remove_handle_on_failure=true
        unlink_locked_handle
        close_handle_file
        remove_handle_on_failure=false
      else
        lock_status=$?
        [[ "$lock_status" == 2 ]] || die
      fi
    fi
    terminal_base '{"ok":true}' | /usr/bin/tr -d '\n'
    ;;
  *) die ;;
esac

trap - EXIT HUP INT TERM
