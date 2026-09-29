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
readonly FLOCK_BIN=/usr/bin/flock

signing_corrupted=false
primary_postgres_id=''
device_failure_armed=false
device_digest_failure_substage=''
device_secret_failure_substage=''
handle_fd=''
handle_path=''
handle_identity=''

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

device_digest_fail() {
  device_digest_failure_substage=$1
  return 41
}

device_secret_fail() {
  device_secret_failure_substage=$1
  return 42
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
  "$DOCKER_BIN" "$JQ_BIN" "$PYTHON_BIN" "$CURL_BIN" "$FLOCK_BIN" /usr/bin/realpath /usr/bin/stat \
  /usr/bin/id /usr/bin/dirname /usr/bin/head /usr/bin/wc /usr/bin/tr /usr/bin/mktemp \
  /usr/bin/chmod /usr/bin/rm /usr/bin/grep /usr/bin/mkdir /usr/bin/od; do
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

readonly HANDLE_ROOT="$SOCKET_PARENT/phase2-device-invariants"
if ! /usr/bin/mkdir --mode=0700 -- "$HANDLE_ROOT" 2>/dev/null; then
  [[ -d "$HANDLE_ROOT" && ! -L "$HANDLE_ROOT" ]] || die
fi
[[ "$(/usr/bin/realpath -e -- "$HANDLE_ROOT" 2>/dev/null || true)" == "$HANDLE_ROOT" ]] || die
[[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$HANDLE_ROOT" 2>/dev/null || true)" == "$CURRENT_UID|700|directory" ]] || die

create_handle() {
  local document=$1 candidate create_status
  for _ in {1..32}; do
    candidate="$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
    [[ "$candidate" =~ ^[0-9a-f]{32}$ ]] || die
    handle_path="$HANDLE_ROOT/$candidate"
    if printf '%s' "$document" | "$PYTHON_BIN" -c '
import os, stat, sys
path=sys.argv[1]
data=sys.stdin.buffer.read(65537)
if not data or len(data)>65536: raise SystemExit(1)
try: fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
except FileExistsError: raise SystemExit(2)
os.write(fd,data); os.fsync(fd)
state=os.fstat(fd)
if not stat.S_ISREG(state.st_mode) or stat.S_IMODE(state.st_mode)!=0o600 or state.st_nlink!=1: raise SystemExit(1)
os.close(fd)
' "$handle_path" 2>/dev/null; then
      printf '%s' "$candidate"
      return 0
    else
      create_status=$?
      [[ "$create_status" == 2 ]] || return 1
    fi
  done
  return 1
}

lock_handle() {
  local handle=$1 fd_identity path_identity
  [[ "$handle" =~ ^[0-9a-f]{32}$ ]] || die
  handle_path="$HANDLE_ROOT/$handle"
  [[ -f "$handle_path" && ! -L "$handle_path" ]] || die
  exec {handle_fd}<>"$handle_path" || die
  "$FLOCK_BIN" --exclusive --nonblock "$handle_fd" || die
  fd_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h|%F' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%F' -- "$handle_path" 2>/dev/null || true)"
  [[ "$fd_identity" == "$path_identity" && "$fd_identity" =~ \|${CURRENT_UID}\|600\|1\|regular\ file$ ]] || die
  handle_identity=$fd_identity
}

read_handle() {
  local document after
  document="$(/usr/bin/head -c $((MAX_OUTPUT_BYTES + 1)) "/proc/$BASHPID/fd/$handle_fd")" || die
  [[ -n "$document" && ${#document} -le $MAX_OUTPUT_BYTES ]] || die
  after="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h|%F' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  [[ "$after" == "$handle_identity" ]] || die
  printf '%s' "$document"
}

rewrite_handle() {
  local document=$1
  printf '%s' "$document" | "$PYTHON_BIN" -c '
import os, sys
path, expected=sys.argv[1:]
data=sys.stdin.buffer.read(65537)
if not data or len(data)>65536: raise SystemExit(1)
fd=os.open(path,os.O_WRONLY)
state=os.fstat(fd)
identity=f"{state.st_dev}|{state.st_ino}|{state.st_uid}|{state.st_mode & 0o777:o}|{state.st_nlink}|regular file"
if identity != expected: raise SystemExit(1)
os.ftruncate(fd,0); os.write(fd,data); os.fsync(fd); os.close(fd)
' "/proc/$BASHPID/fd/$handle_fd" "$handle_identity" 2>/dev/null || die
}

retire_handle() {
  local descriptor_identity path_identity quarantine quarantine_identity renamed=false
  descriptor_identity="$(/usr/bin/stat -Lc '%d|%i|%u|%a|%h|%F' -- "/proc/$BASHPID/fd/$handle_fd" 2>/dev/null || true)"
  path_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%F' -- "$handle_path" 2>/dev/null || true)"
  [[ "$descriptor_identity" == "$handle_identity" && "$path_identity" == "$handle_identity" ]] || die
  for _ in {1..32}; do
    quarantine="$HANDLE_ROOT/.quarantine.$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
    [[ "$quarantine" =~ ^${HANDLE_ROOT}/\.quarantine\.[0-9a-f]{32}$ ]] || die
    [[ ! -e "$quarantine" && ! -L "$quarantine" ]] || continue
    if "$PYTHON_BIN" -c '
import ctypes, os, sys
source, target=sys.argv[1:]
libc=ctypes.CDLL(None,use_errno=True)
renameat2=getattr(libc,"renameat2",None)
if renameat2 is None: raise SystemExit(1)
renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
renameat2.restype=ctypes.c_int
if renameat2(-100,os.fsencode(source),-100,os.fsencode(target),1)!=0: raise SystemExit(1)
' "$handle_path" "$quarantine" 2>/dev/null; then
      renamed=true
      break
    fi
    die
  done
  [[ "$renamed" == true && ! -e "$handle_path" && ! -L "$handle_path" ]] || die
  quarantine_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%F' -- "$quarantine" 2>/dev/null || true)"
  [[ "$quarantine_identity" == "$handle_identity" ]] || die
  handle_path=$quarantine
  rewrite_handle '{"schemaVersion":1,"retired":true}'
  quarantine_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%F' -- "$quarantine" 2>/dev/null || true)"
  [[ "$quarantine_identity" == "$handle_identity" ]] || die
  exec {handle_fd}>&-
  handle_fd=''
}

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
  if [[ "$status" -ne 0 && "$device_failure_armed" == true && -n "$primary_postgres_id" ]]; then
    if ! run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres >/dev/null <<'SQL'
DROP TRIGGER IF EXISTS phase2_device_transition_failure ON aster_tenant.device_authorizations;
DROP FUNCTION IF EXISTS aster_runtime.phase2_device_transition_failure();
SQL
    then
      restore_status=1
    fi
  fi
  if [[ -n "$handle_fd" ]]; then
    exec {handle_fd}>&- || true
  fi
  if [[ "$restore_status" -ne 0 ]]; then
    printf '%s\n' "$FAILURE" >&2
    exit 1
  fi
  if [[ "$status" == 41 && "$device_digest_failure_substage" =~ ^(private-code-extraction|row-sql|row-missing|row-facts|schema-query|schema-clear-columns)$ ]]; then
    printf 'Phase 2 client credentials invariant driver failed (device-1-%s).\n' "$device_digest_failure_substage" >&2
    exit 41
  fi
  if [[ "$status" == 42 && "$device_secret_failure_substage" =~ ^(private-extraction|row-sql|row-facts|schema-query|schema-clear-columns|scan-input|scan-query|scan-match|normalized-input|normalized-query|normalized-match)$ ]]; then
    printf 'Phase 2 client credentials invariant driver failed (device-7-%s).\n' "$device_secret_failure_substage" >&2
    exit 42
  fi
  if [[ "$status" -ne 0 ]]; then
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
    exact(value,["allocationId","clients","deviceClients","resources","organization","scopes","boundary"])
    text(value["allocationId"],r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    exact(value["clients"],["basic","post"])
    for name,method in (("basic","client_secret_basic"),("post","client_secret_post")):
        exact(value["clients"][name],["id","method"]); text(value["clients"][name]["id"],r"^[A-Za-z0-9._~-]{1,128}$")
        if value["clients"][name]["method"] != method: raise ValueError()
    exact(value["deviceClients"],["firstParty","thirdParty","missingGrant","ineligibleWeb"])
    for name,application_type,third_party,grant in (("firstParty","Native",False,True),("thirdParty","Native",True,True),("missingGrant","Native",False,False),("ineligibleWeb","SPA",False,False)):
        client=value["deviceClients"][name]
        exact(client,["id","applicationType","authenticationMethod","isThirdParty","deviceGrantEnabled"])
        text(client["id"],r"^[A-Za-z0-9._~-]{1,128}$")
        if client["applicationType"] != application_type or client["authenticationMethod"] != "none" or client["isThirdParty"] is not third_party or client["deviceGrantEnabled"] is not grant: raise ValueError()
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
    if value["schemaVersion"] != 1 or value["kind"] != "phase2-client-credentials-candidate-invariant-request": raise ValueError()
    legacy={
      "client-credentials.cross-tenant-authority-rejected","client-credentials.request-role-write-rejected",
      "client-credentials.signing-failure-rolls-back","client-credentials.user-authority-unchanged",
      "logout-session.verification-storage-closed"}
    device={
      "device-authorization.forced-rls-isolation","device-authorization.credentials-digest-only",
      "device-authorization.cross-tenant-lookup-rejected","device-authorization.transition-failure-rolls-back",
      "device-token.consumed-replay-revokes-grant","device-authorization.expired-cleanup-bounded",
      "device-evidence.secret-material-absent"}
    invariant=value["invariantId"]
    if invariant in legacy:
      exact(value,["schemaVersion","kind","invariantId","target","fixture","credentials"])
      exact(value["credentials"],["basic","post"])
      text(value["credentials"]["basic"],r"^[^\x00-\x20\x7f]{1,256}$"); text(value["credentials"]["post"],r"^[^\x00-\x20\x7f]{1,256}$")
      if value["credentials"]["basic"] == value["credentials"]["post"]: raise ValueError()
    elif invariant in device:
      operation=value.get("operation")
      base=["schemaVersion","kind","invariantId","operation","target","fixture","private","observation"]
      exact(value,base+(["handle"] if "handle" in value else []))
      if operation not in {"probe","arm","restore","finish","abort"}: raise ValueError()
      if operation in {"restore","finish","abort"}:
        text(value.get("handle"),r"^[0-9a-f]{32}$")
      elif "handle" in value: raise ValueError()
      if type(value["private"]) is not dict or type(value["observation"]) is not dict: raise ValueError()
      private_keys=set(value["private"]); observation_keys=set(value["observation"])
      code_keys={"deviceCode","userCode","xsrf"}
      device_only={"deviceCode"}
      if private_keys == code_keys:
        for item in value["private"].values(): text(item,r"^[^\x00-\x1f\x7f]{1,4096}$")
      elif private_keys == device_only:
        text(value["private"]["deviceCode"],r"^[^\x00-\x1f\x7f]{1,4096}$")
      elif invariant == "device-evidence.secret-material-absent" and private_keys == {"password","clientSecrets","tokens"}:
        text(value["private"]["password"],r"^[^\x00-\x1f\x7f]{1,4096}$")
        for name in ("clientSecrets","tokens"):
          if type(value["private"][name]) is not list or not 1 <= len(value["private"][name]) <= 4: raise ValueError()
          for item in value["private"][name]: text(item,r"^[^\x00-\x1f\x7f]{1,16384}$")
      elif invariant == "device-evidence.secret-material-absent" and private_keys == code_keys|{"password","clientSecrets","tokens"}:
        for name in code_keys|{"password"}: text(value["private"][name],r"^[^\x00-\x1f\x7f]{1,4096}$")
        for name in ("clientSecrets","tokens"):
          if type(value["private"][name]) is not list or not 1 <= len(value["private"][name]) <= 4: raise ValueError()
          for item in value["private"][name]: text(item,r"^[^\x00-\x1f\x7f]{1,16384}$")
      elif private_keys: raise ValueError()
      allowed={
        "device-authorization.forced-rls-isolation":{"probe":(set(),set())},
        "device-authorization.credentials-digest-only":{"probe":(code_keys,set())},
        "device-authorization.cross-tenant-lookup-rejected":{
          "arm":(code_keys,set()),"finish":(set(),{"foreignStatus","foreignError"}),
          "abort":(set(),set())},
        "device-authorization.transition-failure-rolls-back":{
          "arm":(device_only,set()),"restore":(set(),{"failureStatus","tokenPublished"}),
          "finish":(set(),{"retryStatus"}),"abort":(set(),set())},
        "device-token.consumed-replay-revokes-grant":{
          "arm":(device_only,{"issuedStatus"}),
          "finish":(set(),{"replayStatus","replayError","accessActive","refreshActive","refreshStatus","refreshError"}),
          "abort":(set(),set())},
        "device-authorization.expired-cleanup-bounded":{
          "arm":(set(),set()),"finish":(code_keys,{"authorizationStatus"}),"abort":(set(),set())},
        "device-evidence.secret-material-absent":{
          "probe":(code_keys|{"password","clientSecrets","tokens"},{"issuedStatus"})},
      }
      expected=allowed.get(invariant,{}).get(operation)
      if expected is None or private_keys != expected[0] or observation_keys != expected[1]: raise ValueError()
      for observed in value["observation"].values():
        if type(observed) not in (str,int,bool) or (type(observed) is str and re.fullmatch(r"^[^\x00-\x1f\x7f]{1,128}$",observed) is None): raise ValueError()
    else: raise ValueError()
    exact(value["target"],["primary","foreign"])
    endpoint(value["target"]["primary"],"http://localhost:3321/","http://localhost:3421/")
    endpoint(value["target"]["foreign"],"http://localhost:3322/","http://localhost:3422/")
    fixture(value["fixture"])
    sys.stdout.write(json.dumps(value,separators=(",",":"),ensure_ascii=True))
except Exception:
    sys.exit(1)
' 2>/dev/null)" || die
[[ -n "$request" && ${#request} -le $MAX_INPUT_BYTES ]] || die

value() {
  printf '%s' "$request" | "$JQ_BIN" -er "$1" 2>/dev/null
}

invariant_id="$(value '.invariantId')" || die
operation="$(printf '%s' "$request" | "$JQ_BIN" -r '.operation // "legacy"' 2>/dev/null)" || die
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

control_terminal() {
  local extra=$1
  "$JQ_BIN" -cn --arg invariantId "$invariant_id" --arg operation "$operation" \
    --argjson extra "$extra" --argjson attestation "$attestation" \
    '{schemaVersion:1,kind:"phase2-device-candidate-invariant-control",invariantId:$invariantId,operation:$operation} + $extra + {attestation:$attestation}' | /usr/bin/tr -d '\n'
}

device_handle_document() {
  local handle=$1 document
  lock_handle "$handle"
  document="$(read_handle)" || die
  printf '%s' "$document" | "$JQ_BIN" -e --arg invariantId "$invariant_id" \
    --arg allocationId "$(value '.fixture.allocationId')" --arg projectName "$project_name" '
      .schemaVersion==1 and .invariantId==$invariantId and .allocationId==$allocationId and
      .projectName==$projectName and (.stage|type)=="string" and (.data|type)=="object" and
      (keys|sort)==["allocationId","data","invariantId","projectName","schemaVersion","stage"]' \
    >/dev/null 2>&1 || die
  device_handle_value=$document
}

new_device_handle() {
  local stage=$1 data=$2 document
  document="$(printf '%s' "$data" | $JQ_BIN -c --arg invariantId "$invariant_id" \
    --arg allocationId "$(value '.fixture.allocationId')" --arg projectName "$project_name" \
    --arg stage "$stage" \
    'if type=="object" then {schemaVersion:1,invariantId:$invariantId,allocationId:$allocationId,projectName:$projectName,stage:$stage,data:.} else error("closed") end')" || die
  create_handle "$document"
}

device_row() {
  local device_code=$1 user_code=$2 client_id
  client_id="$(value '.fixture.deviceClients.firstParty.id')" || die
  printf '%s\t%s\t%s\n' "$device_code" "$user_code" "$client_id" | run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres \
    --command='CREATE TEMP TABLE phase2_private_codes(device_code text,user_code text,client_id text) ON COMMIT DROP;' \
    --command='COPY phase2_private_codes FROM STDIN;' \
    --command=$'SELECT jsonb_build_object(\n  \'uid\',device_uid,\'status\',status,\'grantId\',grant_id,\n  \'deviceBytes\',octet_length(device_digest),\'userBytes\',octet_length(user_digest),\n  \'clearAbsent\',position(codes.device_code in to_jsonb(device_authorizations)::text)=0\n    AND position(codes.user_code in to_jsonb(device_authorizations)::text)=0\n    AND position(upper(replace(codes.user_code,\'-\',\'\')) in to_jsonb(device_authorizations)::text)=0,\n  \'row\',to_jsonb(device_authorizations)\n)\nFROM aster_tenant.device_authorizations CROSS JOIN phase2_private_codes codes\nWHERE tenant_id=\'default\' AND device_authorizations.client_id=codes.client_id\n  AND device_digest=sha256(convert_to(codes.device_code,\'UTF8\'))\n  AND user_digest=sha256(convert_to(upper(replace(codes.user_code,\'-\',\'\')),\'UTF8\'));'
}

device_row_by_device_code() {
  local device_code=$1 client_id
  client_id="$(value '.fixture.deviceClients.firstParty.id')" || die
  printf '%s\t%s\n' "$device_code" "$client_id" | run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres \
    --command='CREATE TEMP TABLE phase2_private_device_code(device_code text,client_id text) ON COMMIT DROP;' \
    --command='COPY phase2_private_device_code FROM STDIN;' \
    --command=$'SELECT jsonb_build_object(\n  \'uid\',device_uid,\'status\',status,\'grantId\',grant_id,\n  \'deviceBytes\',octet_length(device_digest),\'userBytes\',octet_length(user_digest),\n  \'clearAbsent\',position(codes.device_code in to_jsonb(device_authorizations)::text)=0,\n  \'row\',to_jsonb(device_authorizations)\n)\nFROM aster_tenant.device_authorizations CROSS JOIN phase2_private_device_code codes\nWHERE tenant_id=\'default\' AND device_authorizations.client_id=codes.client_id\n  AND device_digest=sha256(convert_to(codes.device_code,\'UTF8\'));'
}

secret_variants() {
  "$PYTHON_BIN" -c '
import base64, json, sys, urllib.parse
raw=sys.stdin.buffer.read(16385)
if not raw or len(raw)>16384 or any(value in raw for value in (b"\x00",b"\n",b"\r",b"\t")): raise SystemExit(1)
text=raw.decode("utf-8")
encoded=base64.b64encode(raw).decode("ascii")
urlsafe=base64.urlsafe_b64encode(raw).decode("ascii")
json_escaped=json.dumps(text,ensure_ascii=False)[1:-1]
variants={text,json_escaped,raw.hex(),raw.hex().upper(),encoded,encoded.rstrip("="),urlsafe,urlsafe.rstrip("="),urllib.parse.quote(text,safe=""),urllib.parse.quote_plus(text,safe="")}
for value in sorted(variants): print(value)
'
}

assert_secret_material_absent() {
  local expression=$1 secret_count secret_index planted encoded_variants variants
  encoded_variants=''
  secret_count="$(value "$expression | length")" || device_secret_fail private-extraction
  for ((secret_index=0; secret_index<secret_count; secret_index+=1)); do
    planted="$(value "$expression | .[$secret_index]")" || device_secret_fail private-extraction
    variants="$(printf '%s' "$planted" | secret_variants | encode_secret_variants)" || device_secret_fail scan-input
    encoded_variants+="${encoded_variants:+$'\n'}$variants"
  done
  assert_secret_variants_absent "$encoded_variants" scan
}

assert_normalized_user_code_absent() {
  local user_code encoded_variants
  user_code="$(value '.private.userCode')" || device_secret_fail normalized-input
  encoded_variants="$(printf '%s' "$user_code" | "$PYTHON_BIN" -c '
import sys
normalized=sys.stdin.read().replace("-","").upper()
if not normalized or len(normalized)>4096: raise SystemExit(1)
sys.stdout.write(normalized)
' | secret_variants | encode_secret_variants)" || device_secret_fail normalized-input
  assert_secret_variants_absent "$encoded_variants" normalized
}

encode_secret_variants() {
  "$PYTHON_BIN" -c '
import base64,sys
values={line.rstrip(b"\n") for line in sys.stdin.buffer.readlines()}
if not values or any(not value or len(value)>65536 for value in values): raise SystemExit(1)
for value in sorted(values): print(base64.b64encode(value).decode("ascii"))
'
}

assert_secret_variants_absent() {
  local encoded_variants=$1 context=$2 normalized_variants matches
  [[ "$context" == scan || "$context" == normalized ]] || die
  [[ -n "$encoded_variants" ]] || device_secret_fail "$context-input"
  normalized_variants="$(printf '%s\n' "$encoded_variants" | "$PYTHON_BIN" -c '
import base64,binascii,sys
payload=sys.stdin.buffer.read(4194305)
if not payload or len(payload)>4194304: raise SystemExit(1)
lines=payload.splitlines()
# The 64 KiB request admits twelve secrets and up to eleven forms per secret.
# Keep conservative headroom for deduplication changes and base64-wrapped expansion.
if not 1<=len(lines)<=256 or any(not line or len(line)>87384 for line in lines): raise SystemExit(1)
try: decoded=[base64.b64decode(line,validate=True) for line in lines]
except binascii.Error: raise SystemExit(1)
if any(not value or len(value)>65536 or base64.b64encode(value)!=line for value,line in zip(decoded,lines)): raise SystemExit(1)
sys.stdout.buffer.write(b"\n".join(sorted(set(lines)))+b"\n")
')" || device_secret_fail "$context-input"
  matches="$(printf '%s\n' "$normalized_variants" | run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres \
    --command=$'SET LOCAL statement_timeout=\'20s\';\nSET LOCAL lock_timeout=\'5s\';' \
    --command='CREATE TEMP TABLE phase2_private_secret_variants(encoded text) ON COMMIT DROP;' \
    --command='COPY phase2_private_secret_variants FROM STDIN;' \
    --command=$'WITH material(body) AS (\n  SELECT to_jsonb(row)::text FROM aster_tenant.device_authorizations row WHERE tenant_id=\'default\'\n  UNION ALL SELECT to_jsonb(row)::text FROM aster_tenant.interactions row WHERE tenant_id=\'default\'\n  UNION ALL SELECT to_jsonb(row)::text FROM aster_tenant.grants row WHERE tenant_id=\'default\'\n  UNION ALL SELECT to_jsonb(row)::text FROM aster_tenant.sessions row WHERE tenant_id=\'default\'\n  UNION ALL SELECT to_jsonb(row)::text FROM aster_tenant.token_families row WHERE tenant_id=\'default\'\n  UNION ALL SELECT to_jsonb(row)::text FROM aster_tenant.refresh_tokens row WHERE tenant_id=\'default\'\n  UNION ALL SELECT to_jsonb(row)::text FROM aster_tenant.session_access_tokens row WHERE tenant_id=\'default\'\n)\nSELECT count(*) FROM phase2_private_secret_variants variants\nWHERE EXISTS (SELECT 1 FROM material WHERE position(decode(variants.encoded,\'base64\') in convert_to(material.body,\'UTF8\'))>0);')" || device_secret_fail "$context-query"
  [[ "$matches" == 0 ]] || device_secret_fail "$context-match"
}

drop_device_failure() {
  run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres >/dev/null <<'SQL'
DROP TRIGGER IF EXISTS phase2_device_transition_failure ON aster_tenant.device_authorizations;
DROP FUNCTION IF EXISTS aster_runtime.phase2_device_transition_failure();
SQL
  device_failure_armed=false
}

device_authority_snapshot() {
  local uid=$1
  run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="uid=$uid" <<'SQL'
WITH device AS (
  SELECT * FROM aster_tenant.device_authorizations
  WHERE tenant_id='default' AND device_uid=:'uid'
), authority AS (
  SELECT jsonb_build_object(
    'device',COALESCE((SELECT to_jsonb(row) FROM device row),'null'::jsonb),
    'interactions',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY encode(handle_digest,'hex')) FROM aster_tenant.interactions row WHERE tenant_id='default'),'[]'::jsonb),
    'grant',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY grant_id) FROM aster_tenant.grants row WHERE tenant_id='default' AND grant_id=(SELECT grant_id FROM device)),'[]'::jsonb),
    'session',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY session_uid) FROM aster_tenant.sessions row WHERE tenant_id='default' AND session_uid=(SELECT session_uid FROM device)),'[]'::jsonb),
    'families',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY family_id) FROM aster_tenant.token_families row WHERE tenant_id='default' AND grant_id=(SELECT grant_id FROM device)),'[]'::jsonb),
    'refresh',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY token_id) FROM aster_tenant.refresh_tokens row WHERE tenant_id='default' AND family_id IN (SELECT family_id FROM aster_tenant.token_families WHERE tenant_id='default' AND grant_id=(SELECT grant_id FROM device))),'[]'::jsonb),
    'access',COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY encode(access_digest,'hex')) FROM aster_tenant.session_access_tokens row WHERE tenant_id='default' AND grant_id=(SELECT grant_id FROM device)),'[]'::jsonb)
  ) value
)
SELECT value FROM authority;
SQL
}

basic_client_id="$(value '.fixture.clients.basic.id')" || die
primary_resource="$(value '.fixture.resources.primary.indicator')" || die
basic_secret=''
if [[ "$operation" == legacy ]]; then
  basic_secret="$(value '.credentials.basic')" || die
fi

if [[ "$operation" != legacy ]]; then
  case "$invariant_id:$operation" in
    device-authorization.forced-rls-isolation:probe)
      probe_uid="phase2-rls-$(value '.fixture.allocationId')"
      probe_client="$(value '.fixture.deviceClients.firstParty.id')"
      catalog="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres \
        --set="probe_uid=$probe_uid" --set="client_id=$probe_client" <<'SQL'
SET LOCAL statement_timeout='20s';
WITH relation AS (
  SELECT relrowsecurity,relforcerowsecurity
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='aster_tenant' AND c.relname='device_authorizations'
), inserted AS (
  INSERT INTO aster_tenant.device_authorizations (
    tenant_id,device_uid,device_digest,user_digest,client_id,request_context,status,issued_at,expires_at
  ) VALUES (
    'default',:'probe_uid',sha256(convert_to(:'probe_uid'||'-device','UTF8')),
    sha256(convert_to(:'probe_uid'||'-user','UTF8')),:'client_id','{}','pending',
    extract(epoch from now())::bigint,extract(epoch from now())::bigint+600
  ) RETURNING 1
)
SELECT jsonb_build_object(
  'rowSecurity',(SELECT relrowsecurity FROM relation),
  'forcedRowSecurity',(SELECT relforcerowsecurity FROM relation),
  'requestPrivileges',(SELECT array_agg(privilege_type ORDER BY privilege_type)
    FROM information_schema.role_table_grants WHERE table_schema='aster_tenant'
      AND table_name='device_authorizations' AND grantee='aster_request'),
  'adminPrivileges',has_table_privilege('aster_admin','aster_tenant.device_authorizations','SELECT,INSERT,UPDATE,DELETE'),
  'workerPrivileges',has_table_privilege('aster_worker','aster_tenant.device_authorizations','SELECT,INSERT,UPDATE,DELETE'),
  'inserted',(SELECT count(*) FROM inserted)
);
SQL
      )" || die
      printf '%s' "$catalog" | "$JQ_BIN" -e '.=={rowSecurity:true,forcedRowSecurity:true,requestPrivileges:["DELETE","INSERT","SELECT","UPDATE"],adminPrivileges:false,workerPrivileges:false,inserted:1}' >/dev/null || die
      deployment_id="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres <<'SQL'
SELECT deployment_id::text FROM aster_control.deployment_state WHERE singleton;
SQL
      )" || die
      [[ "$deployment_id" =~ ^[0-9a-f-]{36}$ ]] || die
      run_sql "$primary_postgres_id" aster_phase1_candidate_primary aster_maintainer >/dev/null <<SQL
SELECT * FROM aster_runtime.run_tenant_maintenance('$deployment_id');
SQL
      rls_seed_default="$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
      rls_seed_foreign="$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
      [[ "$rls_seed_default" =~ ^[0-9a-f]{64}$ && "$rls_seed_foreign" =~ ^[0-9a-f]{64}$ ]] || die
      run_sql "$primary_postgres_id" aster_phase1_candidate_primary aster_control_resolver --set="seed=$rls_seed_default" >/dev/null <<'SQL'
SELECT * FROM aster_runtime.mint_tenant_binding(sha256(decode(:'seed','hex')),'default','request');
SQL
      request_primary="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary aster_request \
        --set="seed=$rls_seed_default" --set="probe_uid=$probe_uid" <<'SQL'
SELECT * FROM aster_runtime.activate_tenant_binding(decode(:'seed','hex')) \g /dev/null
WITH changed AS (
  UPDATE aster_tenant.device_authorizations SET status=status
  WHERE tenant_id='default' AND device_uid=:'probe_uid' RETURNING 1
)
SELECT jsonb_build_object(
  'visible',(SELECT count(*) FROM aster_tenant.device_authorizations WHERE device_uid=:'probe_uid'),
  'updated',(SELECT count(*) FROM changed));
SQL
      )" || die
      printf '%s' "$request_primary" | "$JQ_BIN" -e '.=={visible:1,updated:1}' >/dev/null || die
      run_sql "$primary_postgres_id" aster_phase1_candidate_primary aster_control_resolver --set="seed=$rls_seed_foreign" >/dev/null <<'SQL'
SELECT * FROM aster_runtime.mint_tenant_binding(sha256(decode(:'seed','hex')),'admin','request');
SQL
      request_foreign="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary aster_request \
        --set="seed=$rls_seed_foreign" --set="probe_uid=$probe_uid" <<'SQL'
SELECT * FROM aster_runtime.activate_tenant_binding(decode(:'seed','hex')) \g /dev/null
WITH changed AS (
  UPDATE aster_tenant.device_authorizations SET status=status
  WHERE tenant_id='default' AND device_uid=:'probe_uid' RETURNING 1
)
SELECT jsonb_build_object(
  'visible',(SELECT count(*) FROM aster_tenant.device_authorizations WHERE tenant_id='default' AND device_uid=:'probe_uid'),
  'updated',(SELECT count(*) FROM changed));
SQL
      )" || die
      printf '%s' "$request_foreign" | "$JQ_BIN" -e '.=={visible:0,updated:0}' >/dev/null || die
      expect_rejected_sql <<'SQL'
SET ROLE aster_admin;
SELECT count(*) FROM aster_tenant.device_authorizations;
SQL
      expect_rejected_sql <<'SQL'
SET ROLE aster_worker;
SELECT count(*) FROM aster_tenant.device_authorizations;
SQL
      run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="probe_uid=$probe_uid" >/dev/null <<'SQL'
DELETE FROM aster_tenant.device_authorizations WHERE tenant_id='default' AND device_uid=:'probe_uid';
SQL
      terminal '{"invariant":"forced-rls-isolation","catalog":{"rowSecurity":true,"forcedRowSecurity":true},"privileges":{"request":"select-insert-update-delete","admin":"none","worker":"none"},"requestRole":{"primaryVisible":true,"foreignVisible":false,"foreignUpdate":"rejected"},"adminRole":"rejected","workerRole":"rejected"}'
      ;;
    device-authorization.credentials-digest-only:probe)
      device_code="$(value '.private.deviceCode')" || device_digest_fail private-code-extraction
      user_code="$(value '.private.userCode')" || device_digest_fail private-code-extraction
      row="$(device_row "$device_code" "$user_code")" || device_digest_fail row-sql
      [[ -n "$row" ]] || device_digest_fail row-missing
      printf '%s' "$row" | "$JQ_BIN" -e '
        .status=="pending" and .deviceBytes==32 and .userBytes==32 and .clearAbsent==true' >/dev/null 2>&1 || device_digest_fail row-facts
      clear_columns="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres <<'SQL'
SELECT count(*) FROM information_schema.columns
WHERE table_schema='aster_tenant' AND table_name='device_authorizations'
  AND column_name ~* '(device|user).*(code|credential)|clear|secret|token';
SQL
      )" || device_digest_fail schema-query
      [[ "$clear_columns" == 0 ]] || device_digest_fail schema-clear-columns
      terminal '{"invariant":"credentials-digest-only","schemaClearColumns":"absent","row":{"deviceDigestBytes":32,"userDigestBytes":32,"clearMaterial":"absent","structuredContextClearMaterial":"absent"}}'
      ;;
    device-authorization.cross-tenant-lookup-rejected:arm)
      device_code="$(value '.private.deviceCode')"; user_code="$(value '.private.userCode')"
      row="$(device_row "$device_code" "$user_code")" || die
      printf '%s' "$row" | "$JQ_BIN" -e '.status=="pending"' >/dev/null || die
      uid="$(printf '%s' "$row" | "$JQ_BIN" -er '.uid')" || die
      row_identity="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="uid=$uid" <<'SQL'
SELECT jsonb_build_object(
  'rowHash',encode(sha256(convert_to(to_jsonb(row)::text,'UTF8')),'hex'),
  'deviceDigest',encode(device_digest,'hex'))
FROM aster_tenant.device_authorizations row
WHERE tenant_id='default' AND device_uid=:'uid';
SQL
      )" || die
      printf '%s' "$row_identity" | "$JQ_BIN" -e '(.rowHash|test("^[0-9a-f]{64}$")) and (.deviceDigest|test("^[0-9a-f]{64}$"))' >/dev/null || die
      handle_data="$($JQ_BIN -cn --arg uid "$uid" --argjson identity "$row_identity" '{uid:$uid,rowHash:$identity.rowHash,deviceDigest:$identity.deviceDigest}')" || die
      handle="$(new_device_handle armed "$handle_data")" || die
      control_terminal "$($JQ_BIN -cn --arg handle "$handle" '{handle:$handle}')"
      ;;
    device-authorization.cross-tenant-lookup-rejected:finish)
      [[ "$(value '.observation.foreignStatus')" == 400 && "$(value '.observation.foreignError')" == invalid_grant ]] || die
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      printf '%s' "$saved" | "$JQ_BIN" -e '.stage=="armed"' >/dev/null || die
      uid="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.uid')"
      expected_hash="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.rowHash')"
      device_hash="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.deviceDigest')"
      current_hash="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="uid=$uid" <<'SQL'
SELECT encode(sha256(convert_to(to_jsonb(row)::text,'UTF8')),'hex')
FROM aster_tenant.device_authorizations row
WHERE tenant_id='default' AND device_uid=:'uid';
SQL
      )" || die
      [[ "$current_hash" == "$expected_hash" ]] || die
      foreign_count="$(run_sql "$foreign_postgres_id" aster_phase1_candidate_foreign postgres --set="device_hash=$device_hash" <<'SQL'
SELECT count(*) FROM aster_tenant.device_authorizations
WHERE tenant_id='default' AND device_digest=decode(:'device_hash','hex');
SQL
      )" || die
      [[ "$foreign_count" == 0 ]] || die
      retire_handle
      terminal '{"invariant":"cross-tenant-lookup-rejected","foreignPoll":{"status":400,"error":"invalid_grant"},"foreignRow":"not-visible","primaryState":"unchanged"}'
      ;;
    device-authorization.transition-failure-rolls-back:arm)
      device_code="$(value '.private.deviceCode')"
      row="$(device_row_by_device_code "$device_code")" || die
      uid="$(printf '%s' "$row" | "$JQ_BIN" -er 'if .status=="approved" and (.grantId|type)=="string" then .uid else error("closed") end')" || die
      snapshot_value="$(device_authority_snapshot "$uid")" || die
      device_hash="$(printf '%s' "$row" | "$JQ_BIN" -er '.row.device_digest | if type=="string" then . else error("closed") end' 2>/dev/null || true)"
      device_hash="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="uid=$uid" <<'SQL'
SELECT encode(device_digest,'hex') FROM aster_tenant.device_authorizations
WHERE tenant_id='default' AND device_uid=:'uid' AND status='approved';
SQL
      )" || die
      [[ "$device_hash" =~ ^[0-9a-f]{64}$ ]] || die
      handle_data="$($JQ_BIN -cn --arg uid "$uid" --arg hash "$device_hash" --argjson snapshot "$snapshot_value" '{uid:$uid,deviceHash:$hash,snapshot:$snapshot}')" || die
      handle="$(new_device_handle armed "$handle_data")" || die
      lock_handle "$handle"
      if ! run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="device_hash=$device_hash" >/dev/null <<'SQL'
SELECT format($outer$
CREATE OR REPLACE FUNCTION aster_runtime.phase2_device_transition_failure()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $function$
BEGIN
  IF encode(OLD.device_digest,'hex')=%L AND NEW.status='consumed' THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='phase2 injected device transition failure';
  END IF;
  RETURN NEW;
END
$function$
$outer$, :'device_hash') \gexec
CREATE TRIGGER phase2_device_transition_failure
BEFORE UPDATE OF status ON aster_tenant.device_authorizations
FOR EACH ROW EXECUTE FUNCTION aster_runtime.phase2_device_transition_failure();
SQL
      then
        retire_handle
        die
      fi
      exec {handle_fd}>&-; handle_fd=''
      device_failure_armed=true
      control_terminal "$($JQ_BIN -cn --arg handle "$handle" '{handle:$handle}')"
      ;;
    device-authorization.transition-failure-rolls-back:restore)
      [[ "$(value '.observation.failureStatus')" -ge 500 && "$(value '.observation.failureStatus')" -le 599 && "$(value '.observation.tokenPublished')" == false ]] || die
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      printf '%s' "$saved" | "$JQ_BIN" -e '.stage=="armed"' >/dev/null || die
      uid="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.uid')" || die
      expected_snapshot="$(printf '%s' "$saved" | "$JQ_BIN" -ce '.data.snapshot')" || die
      drop_device_failure
      current_snapshot="$(device_authority_snapshot "$uid")" || die
      [[ "$(printf '%s\n%s' "$expected_snapshot" "$current_snapshot" | "$JQ_BIN" -s '.[0]==.[1]')" == true ]] || die
      restored="$(printf '%s' "$saved" | "$JQ_BIN" -c '.stage="restored"')" || die
      rewrite_handle "$restored"
      exec {handle_fd}>&-; handle_fd=''
      control_terminal '{"ok":true}'
      ;;
    device-authorization.transition-failure-rolls-back:finish)
      [[ "$(value '.observation.retryStatus')" == 200 ]] || die
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      printf '%s' "$saved" | "$JQ_BIN" -e '.stage=="restored"' >/dev/null || die
      uid="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.uid')" || die
      consumed="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="uid=$uid" <<'SQL'
SELECT count(*) FROM aster_tenant.device_authorizations
WHERE tenant_id='default' AND device_uid=:'uid' AND status='consumed' AND consumed_at IS NOT NULL;
SQL
      )" || die
      [[ "$consumed" == 1 ]] || die
      retire_handle
      terminal '{"invariant":"transition-failure-rolls-back","injectedFailure":"observed","rollback":{"deviceState":"approved","interaction":"unchanged","grant":"unchanged","session":"unchanged"},"retry":"issued"}'
      ;;
    device-token.consumed-replay-revokes-grant:arm)
      [[ "$(value '.observation.issuedStatus')" == 200 ]] || die
      device_code="$(value '.private.deviceCode')"
      row="$(device_row_by_device_code "$device_code")" || die
      uid="$(printf '%s' "$row" | "$JQ_BIN" -er 'if .status=="consumed" and (.grantId|type)=="string" then .uid else error("closed") end')" || die
      grant_id="$(printf '%s' "$row" | "$JQ_BIN" -er '.grantId')" || die
      authority_ids="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="grant_id=$grant_id" <<'SQL'
SELECT jsonb_build_object(
  'familyIds',COALESCE((SELECT jsonb_agg(family_id ORDER BY family_id) FROM aster_tenant.token_families WHERE tenant_id='default' AND grant_id=:'grant_id'),'[]'::jsonb),
  'refreshIds',COALESCE((SELECT jsonb_agg(jsonb_build_object('tokenId',token_id,'digest',encode(refresh_digest,'hex')) ORDER BY token_id) FROM aster_tenant.refresh_tokens WHERE tenant_id='default' AND family_id IN (SELECT family_id FROM aster_tenant.token_families WHERE tenant_id='default' AND grant_id=:'grant_id')),'[]'::jsonb),
  'accessDigests',COALESCE((SELECT jsonb_agg(digest ORDER BY digest) FROM (
    SELECT encode(access_digest,'hex') digest FROM aster_tenant.session_access_tokens WHERE tenant_id='default' AND grant_id=:'grant_id'
    UNION SELECT encode(opaque_access_digest,'hex') FROM aster_tenant.refresh_tokens WHERE tenant_id='default' AND opaque_access_digest IS NOT NULL AND family_id IN (SELECT family_id FROM aster_tenant.token_families WHERE tenant_id='default' AND grant_id=:'grant_id')
  ) values),'[]'::jsonb));
SQL
      )" || die
      printf '%s' "$authority_ids" | "$JQ_BIN" -e '
        (.familyIds|length)>0 and (.refreshIds|length)>0 and (.accessDigests|length)>0 and
        all(.familyIds[];type=="string" and length>0) and
        all(.refreshIds[];(.tokenId|type)=="string" and (.digest|test("^[0-9a-f]{64}$"))) and
        all(.accessDigests[];test("^[0-9a-f]{64}$"))' >/dev/null || die
      handle_data="$($JQ_BIN -cn --arg uid "$uid" --arg grantId "$grant_id" --argjson ids "$authority_ids" '{uid:$uid,grantId:$grantId,familyIds:$ids.familyIds,refreshIds:$ids.refreshIds,accessDigests:$ids.accessDigests}')" || die
      handle="$(new_device_handle armed "$handle_data")" || die
      control_terminal "$($JQ_BIN -cn --arg handle "$handle" '{handle:$handle}')"
      ;;
    device-token.consumed-replay-revokes-grant:finish)
      [[ "$(value '.observation.replayStatus')" == 400 && "$(value '.observation.replayError')" == invalid_grant && \
         "$(value '.observation.accessActive')" == false && "$(value '.observation.refreshActive')" == false && \
         "$(value '.observation.refreshStatus')" == 400 && "$(value '.observation.refreshError')" == invalid_grant ]] || die
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      printf '%s' "$saved" | "$JQ_BIN" -e '.stage=="armed"' >/dev/null || die
      uid="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.uid')"; grant_id="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.grantId')"
      family_ids="$(printf '%s' "$saved" | "$JQ_BIN" -ce '.data.familyIds')"
      refresh_ids="$(printf '%s' "$saved" | "$JQ_BIN" -ce '.data.refreshIds')"
      access_digests="$(printf '%s' "$saved" | "$JQ_BIN" -ce '.data.accessDigests')"
      revoked="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="uid=$uid" --set="grant_id=$grant_id" \
        --set="family_ids=$family_ids" --set="refresh_ids=$refresh_ids" --set="access_digests=$access_digests" <<'SQL'
SELECT jsonb_build_object(
  'device',(SELECT count(*) FROM aster_tenant.device_authorizations WHERE tenant_id='default' AND device_uid=:'uid'),
  'grant',(SELECT count(*) FROM aster_tenant.grants WHERE tenant_id='default' AND grant_id=:'grant_id'),
  'families',(SELECT count(*) FROM aster_tenant.token_families WHERE tenant_id='default' AND family_id IN (SELECT jsonb_array_elements_text(:'family_ids'::jsonb))),
  'access',(SELECT count(*) FROM (
    SELECT encode(access_digest,'hex') digest FROM aster_tenant.session_access_tokens WHERE tenant_id='default'
    UNION ALL SELECT encode(opaque_access_digest,'hex') FROM aster_tenant.refresh_tokens WHERE tenant_id='default' AND opaque_access_digest IS NOT NULL
  ) rows WHERE digest IN (SELECT jsonb_array_elements_text(:'access_digests'::jsonb))),
  'refresh',(SELECT count(*) FROM aster_tenant.refresh_tokens token WHERE tenant_id='default' AND EXISTS (
    SELECT 1 FROM jsonb_to_recordset(:'refresh_ids'::jsonb) saved(tokenId text,digest text)
    WHERE token.token_id=saved.tokenId OR token.refresh_digest=decode(saved.digest,'hex')))
);
SQL
      )" || die
      printf '%s' "$revoked" | "$JQ_BIN" -e '.=={device:0,grant:0,families:0,access:0,refresh:0}' >/dev/null || die
      retire_handle
      terminal '{"invariant":"consumed-replay-revokes-grant","replay":{"status":400,"error":"invalid_grant"},"authority":{"device":"removed","grant":"revoked","family":"inactive","access":"inactive","refresh":"inactive"}}'
      ;;
    device-authorization.expired-cleanup-bounded:arm)
      foreign_before="$(run_sql "$foreign_postgres_id" aster_phase1_candidate_foreign postgres <<'SQL'
SELECT count(*) FROM aster_tenant.device_authorizations WHERE tenant_id='default';
SQL
      )" || die
      prefix="phase2-expired-$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
      [[ "$prefix" =~ ^phase2-expired-[0-9a-f]{32}$ ]] || die
      client_id="$(value '.fixture.deviceClients.firstParty.id')"
      seeded="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="prefix=$prefix" --set="client_id=$client_id" <<'SQL'
WITH clock AS (SELECT extract(epoch from now())::bigint now_value), expired AS (
  INSERT INTO aster_tenant.device_authorizations (
    tenant_id,device_uid,device_digest,user_digest,client_id,request_context,status,issued_at,expires_at
  )
  SELECT 'default',:'prefix'||'-'||ordinal,
    sha256(convert_to(:'prefix'||'-device-'||ordinal,'UTF8')),
    sha256(convert_to(:'prefix'||'-user-'||ordinal,'UTF8')),
    :'client_id','{}','pending',clock.now_value-700,clock.now_value-100
  FROM generate_series(0,64) ordinal CROSS JOIN clock RETURNING 1
), sentinel AS (
  INSERT INTO aster_tenant.device_authorizations (
    tenant_id,device_uid,device_digest,user_digest,client_id,request_context,status,issued_at,expires_at
  ) SELECT 'default',:'prefix'||'-sentinel',sha256(convert_to(:'prefix'||'-sentinel-device','UTF8')),
    sha256(convert_to(:'prefix'||'-sentinel-user','UTF8')),:'client_id','{}','pending',clock.now_value,clock.now_value+600
  FROM clock RETURNING 1
)
SELECT jsonb_build_object('expired',(SELECT count(*) FROM expired),'sentinel',(SELECT count(*) FROM sentinel));
SQL
      )" || die
      printf '%s' "$seeded" | "$JQ_BIN" -e '.=={expired:65,sentinel:1}' >/dev/null || die
      handle_data="$($JQ_BIN -cn --arg foreignCount "$foreign_before" --arg prefix "$prefix" '{foreignCount:($foreignCount|tonumber),prefix:$prefix}')" || die
      if ! handle="$(new_device_handle seeded "$handle_data")"; then
        run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="prefix=$prefix" >/dev/null <<'SQL'
DELETE FROM aster_tenant.device_authorizations WHERE tenant_id='default' AND device_uid LIKE :'prefix'||'-%';
SQL
        die
      fi
      control_terminal "$($JQ_BIN -cn --arg handle "$handle" '{handle:$handle}')"
      ;;
    device-authorization.expired-cleanup-bounded:finish)
      [[ "$(value '.observation.authorizationStatus')" == 200 ]] || die
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      printf '%s' "$saved" | "$JQ_BIN" -e '.stage=="seeded"' >/dev/null || die
      prefix="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.prefix')"; foreign_before="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.foreignCount')"
      device_code="$(value '.private.deviceCode')"; user_code="$(value '.private.userCode')"
      cleanup_state="$(printf '%s\t%s\t%s\n' "$device_code" "$user_code" "$prefix" | run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres \
        --command='CREATE TEMP TABLE phase2_private_codes(device_code text,user_code text,prefix text) ON COMMIT DROP;' \
        --command='COPY phase2_private_codes FROM STDIN;' \
        --command=$'SELECT jsonb_build_object(\n  \'expired\',(SELECT count(*) FROM aster_tenant.device_authorizations CROSS JOIN phase2_private_codes codes WHERE tenant_id=\'default\' AND device_uid LIKE codes.prefix||\'-%\' AND device_uid<>codes.prefix||\'-sentinel\' AND expires_at<extract(epoch from now())::bigint),\n  \'sentinel\',(SELECT count(*) FROM aster_tenant.device_authorizations CROSS JOIN phase2_private_codes codes WHERE tenant_id=\'default\' AND device_uid=codes.prefix||\'-sentinel\' AND expires_at>=extract(epoch from now())::bigint),\n  \'newRow\',(SELECT count(*) FROM aster_tenant.device_authorizations CROSS JOIN phase2_private_codes codes WHERE tenant_id=\'default\' AND device_digest=sha256(convert_to(codes.device_code,\'UTF8\')) AND user_digest=sha256(convert_to(upper(replace(codes.user_code,\'-\',\'\')),\'UTF8\')))\n);')" || die
      printf '%s' "$cleanup_state" | "$JQ_BIN" -e '.=={expired:1,sentinel:1,newRow:1}' >/dev/null || die
      foreign_after="$(run_sql "$foreign_postgres_id" aster_phase1_candidate_foreign postgres <<'SQL'
SELECT count(*) FROM aster_tenant.device_authorizations WHERE tenant_id='default';
SQL
      )" || die
      [[ "$foreign_after" == "$foreign_before" ]] || die
      printf '%s\t%s\n' "$device_code" "$prefix" | run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres \
        --command='CREATE TEMP TABLE phase2_private_code(device_code text,prefix text) ON COMMIT DROP;' \
        --command='COPY phase2_private_code FROM STDIN;' \
        --command=$'DELETE FROM aster_tenant.device_authorizations\nWHERE tenant_id=\'default\' AND (device_uid LIKE (SELECT prefix||\'-%\' FROM phase2_private_code) OR device_digest=(SELECT sha256(convert_to(device_code,\'UTF8\')) FROM phase2_private_code));' >/dev/null || die
      retire_handle
      terminal '{"invariant":"expired-cleanup-bounded","cleanup":{"seededExpired":65,"deletedExpired":64,"remainingExpired":1,"sentinel":"preserved","foreignTenant":"unchanged","newAuthorization":"published"}}'
      ;;
    device-evidence.secret-material-absent:probe)
      [[ "$(value '.observation.issuedStatus')" == 200 ]] || die
      device_code="$(value '.private.deviceCode')" || device_secret_fail private-extraction
      user_code="$(value '.private.userCode')" || device_secret_fail private-extraction
      row="$(device_row "$device_code" "$user_code")" || device_secret_fail row-sql
      printf '%s' "$row" | "$JQ_BIN" -e '.status=="consumed" and .deviceBytes==32 and .userBytes==32' >/dev/null || device_secret_fail row-facts
      clear_columns="$(run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres <<'SQL'
SELECT count(*) FROM information_schema.columns
WHERE table_schema='aster_tenant' AND table_name IN ('device_authorizations','interactions','grants','sessions','token_families','refresh_tokens','session_access_tokens')
  AND column_name ~* '(^|_)(password|client_secret|device_code|user_code|xsrf|access_token|refresh_token|id_token)($|_)';
SQL
      )" || device_secret_fail schema-query
      [[ "$clear_columns" == 0 ]] || device_secret_fail schema-clear-columns
      assert_secret_material_absent '.private | [.deviceCode,.userCode,.xsrf,.password]+.clientSecrets+.tokens'
      assert_normalized_user_code_absent
      terminal '{"invariant":"secret-material-absent","database":"clear-material-absent","schema":"closed","evidence":"sanitized","driverOutput":"sanitized"}'
      ;;
    device-authorization.transition-failure-rolls-back:abort)
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      drop_device_failure
      retire_handle
      control_terminal '{"ok":true}'
      ;;
    device-authorization.cross-tenant-lookup-rejected:abort)
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      retire_handle
      control_terminal '{"ok":true}'
      ;;
    device-token.consumed-replay-revokes-grant:abort)
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      retire_handle
      control_terminal '{"ok":true}'
      ;;
    device-authorization.expired-cleanup-bounded:abort)
      handle="$(value '.handle')"; device_handle_document "$handle" || die; saved=$device_handle_value
      prefix="$(printf '%s' "$saved" | "$JQ_BIN" -er '.data.prefix // empty')"
      if [[ -n "$prefix" ]]; then
        run_sql "$primary_postgres_id" aster_phase1_candidate_primary postgres --set="prefix=$prefix" >/dev/null <<'SQL'
DELETE FROM aster_tenant.device_authorizations WHERE tenant_id='default' AND device_uid LIKE :'prefix'||'-%';
SQL
      fi
      retire_handle
      control_terminal '{"ok":true}'
      ;;
    *) die ;;
  esac
  trap - EXIT HUP INT TERM
  exit 0
fi

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
