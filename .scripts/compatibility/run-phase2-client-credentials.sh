#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
readonly ORACLE_IMAGE_PIN='sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd'
readonly ORACLE_SOURCE_COMMIT='6852a7b8c8984c5c12b2061e8c51faa310a36412'
readonly POSTGRES_IMAGE='docker.io/library/postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
readonly REDIS_IMAGE='docker.io/library/redis:6-alpine@sha256:d0c875bdacfb5c4d2c2d9124de3f53cee1dc9ceff8936bd459fabc135cb33015'
readonly EXPECTED_ASTER_SOURCE='https://github.com/qq98982/aster.git'
readonly ORACLE_SERVICES=(
  oracle-primary-postgres oracle-primary-redis oracle-primary-core
  oracle-fetch-observer oracle-primary-smtp
  oracle-foreign-postgres oracle-foreign-redis oracle-foreign-core oracle-google-provider oracle-wechat-provider oracle-sms-provider
  oracle-pwned-clear oracle-pwned-compromised oracle-pwned-unavailable
  oracle-backchannel-accepted oracle-backchannel-rejected oracle-h5-wechat-provider oracle-wechat-multichannel-provider
  oracle-h5-core
  oracle-password-core
)
readonly CANDIDATE_SERVICES=(
  candidate-primary-postgres candidate-primary-init candidate-primary-core candidate-primary-smtp
  candidate-fetch-observer candidate-script-supervisor candidate-script-executor
  candidate-foreign-postgres candidate-foreign-init candidate-foreign-core
  candidate-fixture-coordinator candidate-google-provider candidate-wechat-provider candidate-sms-provider
  candidate-pwned-clear candidate-pwned-compromised candidate-pwned-unavailable
  candidate-backchannel-accepted candidate-backchannel-rejected candidate-h5-wechat-provider candidate-wechat-multichannel-provider
  candidate-h5-core
  candidate-password-smtp
)
readonly PORTS=(3311 3411 3312 3412 3321 3421 3322 3422)
readonly COMPLETION_PORTS=(3351 3352 3353 3354 3361 3363)
readonly LOOPBACK_PROXY_BINDINGS=(
  'oracle|oracle-primary-core|3001|3311'
  'oracle|oracle-primary-core|3411|3411'
  'oracle|oracle-foreign-core|3001|3312'
  'oracle|oracle-foreign-core|3002|3412'
  'candidate|candidate-primary-core|3001|3321'
  'candidate|candidate-primary-core|3421|3421'
  'candidate|candidate-foreign-core|3001|3322'
  'candidate|candidate-foreign-core|3002|3422'
)

failure_stage='initialization'
BUILD_ROOT=''
RUN_DIR=''
RESULT_DIR=''
RESULT_DIR_IDENTITY=''
RESULT_STAGING_DIR=''
RESULT_STAGING_IDENTITY=''
RESULT_ROOT_IDENTITY=''
RESULT_PUBLISHED=0
TOPOLOGY_CLEANED=0
ORACLE_PROJECT_NAME=''
CANDIDATE_PROJECT_NAME=''
ORACLE_PROJECT_STARTED=0
CANDIDATE_PROJECT_STARTED=0
EXTRACTION_CONTAINER_ID=''
PROBE_CONTAINER_ID=''
STATE_HANDLE_ROOT=''
INVARIANT_HANDLE_ROOT=''
INVARIANT_HANDLE_ROOT_IDENTITY=''
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_TOKENS=()
ORACLE_CONTAINER_IDS=()
CANDIDATE_CONTAINER_IDS=()
SCRIPT_SUPERVISOR_IMAGE_ID=''
SCRIPT_EXECUTOR_IMAGE_ID=''

fail() {
  printf 'Aster Phase 2 client credentials live topology failed (%s)\n' "$failure_stage" >&2
  return 1
}

forward_closed_common_row_failures() {
  local file=$1
  [[ -f "$file" && ! -L "$file" ]] || return 1
  /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/(common\.email\.password-registration|common\.password\.recovery|common\.google\.existing-owner)\)\.$' \
    "$file" >&2 || true
  /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/(common\.password\.policy(/(initialization|local-policy(-(write|read|readback))?|compromise-(compromised|clear|unavailable)|recovery|cleanup-policy))?|common\.google\.configured-collision|common\.account\.google-link|common\.wechat\.h5|common\.wechat\.mini|common\.wechat\.mini-phone-registration|common\.wechat\.native|common\.account\.wechat-link|common\.management\.applications-secrets|common\.management\.native-resource-role|common\.management\.connectors-experience|common\.management\.user-suspend-delete|common\.management\.provisioning-convergence|common\.session\.logout-preservation(/(discovery|authority|(google|email-code|wechat-native)-(accepted-rp|rejected-rp|account)-(session-preparation|observation|cleanup)|email-code-(accepted-rp|rejected-rp|account)-session-preparation/email-http-(none|experience-initialize|verification-code-send|verification-code-verify|identification|other)-(none|[1-5][0-9]{2})/email-smtp-(none|entered|completed|failure-(env-missing|socket-shape|recipient|connect|timeout|not-found|response|unknown))))?)\)\.$' \
    "$file" >&2 || true
  /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-completion-(fixture|machine-authority|runtime-read|required-controls|scenarios|owned-app-cleanup|machine-cleanup-result)\)\.$' \
    "$file" >&2 || true
  /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-completion-(owned-app-cleanup|machine-cleanup-result)/(common\.(password\.policy|google\.configured-collision|account\.(google-link|wechat-link)|wechat\.(h5|mini|mini-phone-registration|native)|management\.(applications-secrets|native-resource-role|connectors-experience|user-suspend-delete|provisioning-convergence)|session\.logout-preservation))\)\.$' \
    "$file" >&2 || true
  /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-completion-machine-cleanup-result/(cleanup-only-rejected|common\.google\.configured-collision/(body-after-cleanup-accepted|body-and-cleanup-rejected)/(composition|original-owner-before|colliding-user-before|preconditions|configured-sign-in|original-owner-after|colliding-user-after|projection))\)\.$' \
    "$file" >&2 || true
}

trusted_binary() {
  local name=$1 candidate resolved owner group mode
  if [[ "$name" == /* ]]; then
    candidate=$name
  else
    candidate="$(command -v "$name" 2>/dev/null || true)"
  fi
  resolved="$(/usr/bin/realpath -e -- "$candidate" 2>/dev/null || true)"
  [[ -n "$resolved" && -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || return 1
  owner="$(/usr/bin/stat -c %u -- "$resolved")"
  group="$(/usr/bin/stat -c %g -- "$resolved")"
  mode="$(/usr/bin/stat -c %a -- "$resolved")"
  [[ "$owner" == 0 || "$owner" == "$(/usr/bin/id -u)" ]] || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  ((8#$mode & 8#002)) && return 1
  if ((8#$mode & 8#020)); then
    [[ "$owner" == "$(/usr/bin/id -u)" && "$group" == "$(/usr/bin/id -g)" ]] || return 1
  fi
  printf '%s' "$resolved"
}

trusted_system_binary() {
  local resolved owner mode
  resolved="$(trusted_binary "$1")" || return 1
  owner="$(/usr/bin/stat -c %u -- "$resolved")"
  mode="$(/usr/bin/stat -c %a -- "$resolved")"
  [[ "$owner" == 0 ]] || return 1
  ((8#$mode & 8#022)) && return 1
  printf '%s' "$resolved"
}

require_safe_private_root() {
  local root=$1 resolved identity
  [[ "$root" == /* && "$root" != / && "$root" != */ && "$root" != *//* ]] || return 1
  [[ "$root" != *'/./'* && "$root" != *'/../'* && ! "$root" =~ [[:cntrl:]] ]] || return 1
  case "$root" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/var|/var/tmp|/dev/*|/proc/*|/sys/*) return 1 ;;
  esac
  if [[ ! -e "$root" ]]; then
    /usr/bin/mkdir -m 700 -- "$root" || return 1
  fi
  [[ -d "$root" && ! -L "$root" ]] || return 1
  resolved="$(/usr/bin/realpath -e -- "$root" 2>/dev/null || true)"
  identity="$(/usr/bin/stat -c '%u|%a|%F' -- "$root" 2>/dev/null || true)"
  [[ "$resolved" == "$root" && "$identity" == "$(/usr/bin/id -u)|700|directory" ]]
}

verify_private_socket() {
  local socket=$1 parent resolved
  [[ "$socket" == /* && ${#socket} -le 100 && "$socket" != *//* ]] || return 1
  [[ "$socket" != *'/./'* && "$socket" != *'/../'* && ! "$socket" =~ [[:cntrl:]] ]] || return 1
  [[ -S "$socket" && ! -L "$socket" ]] || return 1
  resolved="$(/usr/bin/realpath -e -- "$socket" 2>/dev/null || true)"
  [[ "$resolved" == "$socket" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%h|%F' -- "$socket")" == "$(/usr/bin/id -u)|600|1|socket" ]] || return 1
  parent="$(/usr/bin/dirname -- "$socket")"
  [[ "$(/usr/bin/realpath -e -- "$parent")" == "$parent" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$parent")" == "$(/usr/bin/id -u)|700|directory" ]]
}

capture_path_identity() {
  /usr/bin/stat -c '%d|%i|%u|%a|%F' -- "$1"
}

assert_path_identity() {
  [[ "$(capture_path_identity "$1" 2>/dev/null || true)" == "$2" ]]
}

random_hex() {
  local value
  value="$($OPENSSL_BIN rand -hex "$1")" || return 1
  [[ "$value" =~ ^[0-9a-f]+$ ]] || return 1
  printf '%s' "$value"
}

random_uuid() {
  local value
  value="$(random_hex 16)" || return 1
  printf '%s-%s-%s-%s-%s' "${value:0:8}" "${value:8:4}" "${value:12:4}" "${value:16:4}" "${value:20:12}"
}

generate_fetch_and_script_host_pki() {
  local serial
  serial="$(random_hex 16)" || return 1
  "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=Aster Phase 2 Fetch Observer CA' -keyout "$OBSERVER_CA_KEY" \
    -out "$FETCH_OBSERVER_CA" >/dev/null 2>&1 || return 1
  "$OPENSSL_BIN" req -newkey rsa:2048 -nodes -sha256 -subj '/CN=fetch-observer.aster.test' \
    -keyout "$OBSERVER_SERVER_KEY" -out "$OBSERVER_SERVER_CSR" >/dev/null 2>&1 || return 1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=DNS:fetch-observer.aster.test,DNS:oauth2.googleapis.com,DNS:openidconnect.googleapis.com,DNS:api.weixin.qq.com,DNS:dysmsapi.aliyuncs.com\nextendedKeyUsage=serverAuth\n' >"$OBSERVER_SERVER_EXT"
  "$OPENSSL_BIN" x509 -req -days 1 -sha256 -set_serial "0x$serial" \
    -in "$OBSERVER_SERVER_CSR" -CA "$FETCH_OBSERVER_CA" -CAkey "$OBSERVER_CA_KEY" \
    -extfile "$OBSERVER_SERVER_EXT" -out "$OBSERVER_SERVER_CERT" >/dev/null 2>&1 || return 1

  "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=Aster Phase 2 Script Host CA' -keyout "$SCRIPT_HOST_CA_KEY" \
    -out "$SCRIPT_HOST_CA" >/dev/null 2>&1 || return 1
  "$OPENSSL_BIN" req -newkey rsa:2048 -nodes -sha256 -subj '/CN=script-host.aster.test' \
    -keyout "$SCRIPT_HOST_SERVER_KEY" -out "$SCRIPT_HOST_SERVER_CSR" >/dev/null 2>&1 || return 1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=DNS:script-host.aster.test,URI:spiffe://aster.test/script\nextendedKeyUsage=serverAuth\n' >"$SCRIPT_HOST_SERVER_EXT"
  "$OPENSSL_BIN" x509 -req -days 1 -sha256 -set_serial "0x$(random_hex 16)" \
    -in "$SCRIPT_HOST_SERVER_CSR" -CA "$SCRIPT_HOST_CA" -CAkey "$SCRIPT_HOST_CA_KEY" \
    -extfile "$SCRIPT_HOST_SERVER_EXT" -out "$SCRIPT_HOST_SERVER_CERT" >/dev/null 2>&1 || return 1
  "$OPENSSL_BIN" req -newkey rsa:2048 -nodes -sha256 -subj '/CN=Aster Phase 2 Data Server' \
    -keyout "$SCRIPT_HOST_CLIENT_KEY" -out "$SCRIPT_HOST_CLIENT_CSR" >/dev/null 2>&1 || return 1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=URI:spiffe://aster.test/server\nextendedKeyUsage=clientAuth\n' >"$SCRIPT_HOST_CLIENT_EXT"
  "$OPENSSL_BIN" x509 -req -days 1 -sha256 -set_serial "0x$(random_hex 16)" \
    -in "$SCRIPT_HOST_CLIENT_CSR" -CA "$SCRIPT_HOST_CA" -CAkey "$SCRIPT_HOST_CA_KEY" \
    -extfile "$SCRIPT_HOST_CLIENT_EXT" -out "$SCRIPT_HOST_CLIENT_CERT" >/dev/null 2>&1 || return 1
  "$OPENSSL_BIN" verify -CAfile "$FETCH_OBSERVER_CA" "$OBSERVER_SERVER_CERT" >/dev/null 2>&1 || return 1
  "$OPENSSL_BIN" verify -CAfile "$SCRIPT_HOST_CA" "$SCRIPT_HOST_SERVER_CERT" \
    "$SCRIPT_HOST_CLIENT_CERT" >/dev/null 2>&1 || return 1
  : >"$ORACLE_OBSERVER_RECEIPT"
  : >"$CANDIDATE_OBSERVER_RECEIPT"
  /usr/bin/chmod 0444 "$FETCH_OBSERVER_CA" "$OBSERVER_SERVER_CERT" "$SCRIPT_HOST_CA" \
    "$SCRIPT_HOST_SERVER_CERT" "$SCRIPT_HOST_CLIENT_CERT"
  /usr/bin/chmod 0400 "$OBSERVER_CA_KEY" "$OBSERVER_SERVER_KEY" "$SCRIPT_HOST_CA_KEY" \
    "$SCRIPT_HOST_CLIENT_KEY"
  /usr/bin/chmod 0600 "$SCRIPT_HOST_SERVER_KEY"
  /usr/bin/chmod 0600 "$ORACLE_OBSERVER_RECEIPT" "$CANDIDATE_OBSERVER_RECEIPT"
}

assert_private_runtime_material() {
  local file identity owner mode links size type
  for file in "$ORACLE_OBSERVER_RECEIPT" "$CANDIDATE_OBSERVER_RECEIPT"; do
    identity="$(/usr/bin/stat -c '%u|%a|%h|%s|%F' -- "$file")" || return 1
    IFS='|' read -r owner mode links size type <<<"$identity"
    [[ "$owner" == "$(/usr/bin/id -u)" && "$mode" == 600 && "$links" == 1 && \
       "$size" =~ ^[0-9]+$ && "$type" =~ ^regular( empty)?\ file$ ]] || return 1
    ((10#$size <= 16384)) || return 1
    [[ "$(/usr/bin/wc -l <"$file" | /usr/bin/tr -d '[:space:]')" =~ ^([0-9]|[1-5][0-9]|6[0-4])$ ]] || return 1
  done
  for file in "$OBSERVER_CA_KEY" "$OBSERVER_SERVER_KEY" "$SCRIPT_HOST_CA_KEY" "$SCRIPT_HOST_CLIENT_KEY"; do
    [[ "$(/usr/bin/stat -c '%u|%a|%h|%F' -- "$file")" == "$(/usr/bin/id -u)|400|1|regular file" ]] || return 1
  done
  [[ "$(/usr/bin/stat -c '%u|%a|%h|%F' -- "$SCRIPT_HOST_SERVER_KEY")" == \
     "$(/usr/bin/id -u)|600|1|regular file" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$SCRIPT_HOST_STATE")" == "$(/usr/bin/id -u)|700|directory" ]]
}

sha256_file() {
  # The awk program intentionally uses the literal first field.
  # shellcheck disable=SC2016
  "$SHA256_BIN" "$1" | "$AWK_BIN" '{print $1}'
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

resolve_provider_fixture_image_id() {
  local fallback=$1 input raw resolved
  input="${ASTER_PHASE2_PROVIDER_FIXTURE_IMAGE_ID-$fallback}"
  [[ "$input" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  raw="$(docker_cli image inspect --format '{{.Id}}' "$input" 2>/dev/null || true)"
  resolved="$(normalize_image_id "$raw")" || return 1
  [[ "$resolved" == "$input" ]] || return 1
  printf '%s' "$resolved"
}

validate_script_host_image_metadata() {
  local configured_image=$1 metadata=$2 raw_id source revision tree reference image_id
  IFS='|' read -r raw_id source revision tree reference <<<"$metadata"
  image_id="$(normalize_image_id "$raw_id")" || return 1
  [[ "$configured_image" == "$image_id" && "$source" == 'https://github.com/qq98982/aster' && \
     "$revision" == "$ASTER_HEAD" && "$tree" == "$ASTER_TREE" && \
     "$reference" == "$ORACLE_SOURCE_COMMIT" ]] || return 1
  printf '%s' "$image_id"
}

port_state() {
  local port=$1 listeners state
  [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  ((10#$port <= 65535)) || return 1
  listeners="$("$SS_BIN" -H -ltn "sport = :${port}")" || return 1
  if [[ -z "$listeners" ]]; then
    printf released
    return 0
  fi
  # The awk program intentionally validates and uses the five ss fields.
  # shellcheck disable=SC2016
  state="$(printf '%s\n' "$listeners" | "$AWK_BIN" -v expected_port="$port" '
    {
      if (NF != 5 || $1 != "LISTEN" || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ ||
          $4 !~ /:/ || $5 !~ /:/) {
        invalid=1
        next
      }
      local_address=$4
      local_port=$4
      peer_address=$5
      peer_port=$5
      sub(/:[^:]*$/, "", local_address)
      sub(/^.*:/, "", local_port)
      sub(/:[^:]*$/, "", peer_address)
      sub(/^.*:/, "", peer_port)
      if (local_address == "" || local_port != expected_port ||
          peer_address == "" || peer_port != "*") {
        invalid=1
        next
      }
      found=1
    }
    END {
      if (invalid || !found) exit 1
      print "listening"
    }
  ')" || return 1
  [[ "$state" == listening || "$state" == released ]] || return 1
  printf '%s' "$state"
}

port_is_released() {
  local state
  state="$(port_state "$1")" || return 1
  [[ "$state" == released ]]
}

port_is_listened_by_pid() {
  local port=$1 pid=$2
  # The awk program intentionally uses the literal fourth field.
  # shellcheck disable=SC2016
  "$SS_BIN" -H -ltnp | "$AWK_BIN" \
    -v expected="127.0.0.1:${port}" -v process="pid=${pid}([,)]|$)" '
      $4 == expected && $0 ~ process { found=1 }
      END { exit found ? 0 : 1 }
    '
}

process_has_token() {
  local pid=$1 token=$2 entry
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$token" =~ ^[0-9a-f]{64}$ && -r "/proc/$pid/environ" ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ "$entry" == "ASTER_PHASE2_PROCESS_TOKEN=$token" ]] && return 0
  done <"/proc/$pid/environ"
  return 1
}

process_group_has_live_members() {
  local pgid=$1
  # The awk program intentionally uses literal fields.
  # shellcheck disable=SC2016
  "$PS_BIN" -eo pgid=,stat= | "$AWK_BIN" -v expected="$pgid" '
    $1 == expected && $2 !~ /^Z/ { found=1 }
    END { exit found ? 0 : 1 }
  '
}

stop_owned_proxy() {
  local pid=$1 pgid=$2 token=$3 attempt
  if process_group_has_live_members "$pgid"; then
    process_has_token "$pid" "$token" || return 1
    kill -TERM -- "-$pgid" 2>/dev/null || return 1
    for ((attempt=0; attempt<50; attempt++)); do
      process_group_has_live_members "$pgid" || break
      /usr/bin/sleep 0.1
    done
    if process_group_has_live_members "$pgid"; then
      process_has_token "$pid" "$token" || return 1
      kill -KILL -- "-$pgid" 2>/dev/null || return 1
    fi
  fi
  wait "$pid" 2>/dev/null || true
  ! process_group_has_live_members "$pgid"
}

docker_cli() {
  verify_private_socket "$ENGINE_SOCKET" || return 1
  "$TIMEOUT_BIN" --signal=TERM --kill-after=5s 180s \
    "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    DOCKER_HOST="unix://${ENGINE_SOCKET}" "$DOCKER_BIN" "$@"
}

compose_oracle() {
  docker_cli compose --env-file "$ORACLE_ENV" --project-name "$ORACLE_PROJECT_NAME" \
    --file "$ORACLE_COMPOSE" "$@"
}

compose_candidate() {
  docker_cli compose --env-file "$CANDIDATE_ENV" --project-name "$CANDIDATE_PROJECT_NAME" \
    --file "$CANDIDATE_COMPOSE" "$@"
}

compose_for() {
  local role=$1
  shift
  case "$role" in
    oracle) compose_oracle "$@" ;;
    candidate) compose_candidate "$@" ;;
    *) return 1 ;;
  esac
}

project_name_for() {
  case "$1" in
    oracle) printf '%s' "$ORACLE_PROJECT_NAME" ;;
    candidate) printf '%s' "$CANDIDATE_PROJECT_NAME" ;;
    *) return 1 ;;
  esac
}

wait_for_service() {
  local role=$1 service=$2 deadline=$((SECONDS + 180)) id metadata status exit_code health project label
  while ((SECONDS < deadline)); do
    id="$(compose_for "$role" ps --all -q "$service" 2>/dev/null || true)"
    if [[ "$id" =~ ^[0-9a-f]{12,64}$ ]]; then
      metadata="$(docker_cli inspect --format '{{.Id}}|{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}' "$id" 2>/dev/null || true)"
      IFS='|' read -r id status exit_code health project label <<<"$metadata"
      [[ "$id" =~ ^[0-9a-f]{64}$ && "$project" == "$(project_name_for "$role")" && "$label" == "$service" ]] || return 1
      if [[ "$status" == running && -n "$health" && "$health" != healthy ]]; then
        "$CURL_BIN" --silent --show-error --connect-timeout 3 --max-time 3 --output /dev/null \
          --write-out '%{http_code}' --unix-socket "$ENGINE_SOCKET" \
          "http://localhost/v${PODMAN_API_VERSION}/libpod/containers/${id}/healthcheck" \
          >/dev/null 2>&1 || true
        /usr/bin/sleep 3
        continue
      fi
      case "$service" in
        candidate-primary-init|candidate-foreign-init)
          [[ "$status|$exit_code|$health" == 'exited|0|' ]] && return 0
          ;;
        *)
          [[ "$status|$exit_code|$health" == 'running|0|healthy' ]] && return 0
          ;;
      esac
      [[ "$status" != exited || "$exit_code" == 0 ]] || return 1
    fi
    /usr/bin/sleep 1
  done
  return 1
}

start_compose_stage() {
  local role=$1 stage=$2 service id
  shift 2
  failure_stage="compose-${role}-${stage}"
  for service in "$@"; do
    compose_for "$role" up --no-deps --detach "$service" >/dev/null 2>&1 || return 1
    id="$(compose_for "$role" ps --all -q "$service")" || return 1
    id="$(docker_cli inspect --format '{{.Id}}' "$id")" || return 1
    [[ "$id" =~ ^[0-9a-f]{64}$ ]] || return 1
    if [[ "$role" == oracle ]]; then
      ORACLE_CONTAINER_IDS+=("$id")
    else
      CANDIDATE_CONTAINER_IDS+=("$id")
    fi
    wait_for_service "$role" "$service" || return 1
  done
}

wait_for_script_host_serving() {
  local supervisor_id probe_program
  supervisor_id="$(compose_candidate ps --all -q candidate-script-supervisor)" || return 1
  supervisor_id="$(docker_cli inspect --format '{{.Id}}' "$supervisor_id")" || return 1
  [[ "$supervisor_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  read -r -d '' probe_program <<'NODE' || true
import fs from 'node:fs';
import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
const definition = protoLoader.loadSync('/opt/proto/aster/script/v1/script_host.proto');
const protocol = grpc.loadPackageDefinition(definition).aster.script.v1;
const credentials = grpc.credentials.createSsl(
  fs.readFileSync('/probe/ca.pem'),
  fs.readFileSync('/probe/client.key'),
  fs.readFileSync('/probe/client.pem'),
);
const client = new protocol.ScriptHost('127.0.0.1:50051', credentials, {
  'grpc.ssl_target_name_override': 'script-host.aster.test',
  'grpc.default_authority': 'script-host.aster.test',
});
const end = Date.now() + 10000;
const check = () => client.negotiate({schemaVersion: 1, protocolVersion: 2, expectedKind: 1},
  {deadline: new Date(Math.min(end, Date.now() + 2000))}, (error, response) => {
    if (!error && response?.schemaVersion === 1 && response?.protocolVersion === 2 &&
        response?.kind === 1 && response?.serving === true) {
      client.close();
      process.exit(0);
    }
    if (Date.now() >= end) { client.close(); process.exit(1); }
    setTimeout(check, 250);
  });
check();
NODE
  # Default rootless UID 0 maps to the invoking host user, which owns the private mTLS key.
  PROBE_CONTAINER_ID="$(docker_cli create --network "container:$supervisor_id" \
    --user 0:0 \
    --pids-limit 32 --memory 192m --cpus 0.25 --cap-drop ALL \
    --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
    --volume "$SCRIPT_HOST_CA:/probe/ca.pem:ro" \
    --volume "$SCRIPT_HOST_CLIENT_CERT:/probe/client.pem:ro" \
    --volume "$SCRIPT_HOST_CLIENT_KEY:/probe/client.key:ro" \
    --entrypoint node "$SCRIPT_SUPERVISOR_IMAGE_ID" --input-type=module -e "$probe_program")" || return 1
  [[ "$PROBE_CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || return 1
  docker_cli start --attach "$PROBE_CONTAINER_ID" >/dev/null 2>&1 || return 1
  remove_owned_container "$PROBE_CONTAINER_ID" || return 1
  PROBE_CONTAINER_ID=''
}

inspect_service() {
  local role=$1 service=$2 id metadata image configured_image project label status exit_code health
  id="$(compose_for "$role" ps --all -q "$service" 2>/dev/null || true)"
  [[ "$id" =~ ^[0-9a-f]{12,64}$ ]] || return 1
  metadata="$(docker_cli inspect --format '{{.Id}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id")" || return 1
  IFS='|' read -r id image configured_image project label status exit_code health <<<"$metadata"
  image="$(normalize_image_id "$image")" || return 1
  [[ "$configured_image" =~ ^[A-Za-z0-9._/@:-]{1,512}$ ]] || return 1
  printf '%s|%s|%s|%s|%s|%s|%s|%s' "$id" "$image" "$configured_image" "$project" "$label" "$status" "$exit_code" "$health"
}

assert_exact_project_services() {
  local role=$1 project expected ids service_name actual service metadata id image configured_image label_project label_service status exit_code health
  shift
  project="$(project_name_for "$role")"
  expected="$(printf '%s\n' "$@" | /usr/bin/sort)"
  ids="$(docker_cli ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=${project}")" || return 1
  actual=''
  while IFS= read -r id; do
    [[ "$id" =~ ^[0-9a-f]{64}$ ]] || return 1
    service_name="$(docker_cli inspect --format \
      '{{index .Config.Labels "com.docker.compose.service"}}' "$id")" || return 1
    [[ -n "$service_name" && ! "$service_name" =~ [[:cntrl:]] ]] || return 1
    actual+="${service_name}"$'\n'
  done <<<"$ids"
  actual="$(printf '%s' "$actual" | /usr/bin/sed '/^$/d' | /usr/bin/sort)"
  [[ "$actual" == "$expected" ]] || return 1
  for service in "$@"; do
    metadata="$(inspect_service "$role" "$service")" || return 1
    IFS='|' read -r id image configured_image label_project label_service status exit_code health <<<"$metadata"
    [[ "$id" =~ ^[0-9a-f]{64}$ && "$image" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    [[ "$configured_image" =~ ^[A-Za-z0-9._/@:-]{1,512}$ ]] || return 1
    [[ "$label_project" == "$project" && "$label_service" == "$service" ]] || return 1
  done
}

assert_distinct_container_ids() {
  local role service metadata id image configured_image project label status exit_code health ids=()
  for role in oracle candidate; do
    if [[ "$role" == oracle ]]; then
      set -- "${ORACLE_SERVICES[@]}"
    else
      set -- "${CANDIDATE_SERVICES[@]}"
    fi
    for service in "$@"; do
      metadata="$(inspect_service "$role" "$service")" || return 1
      IFS='|' read -r id image configured_image project label status exit_code health <<<"$metadata"
      ids+=("$id")
    done
  done
  [[ "$(printf '%s\n' "${ids[@]}" | /usr/bin/sort -u | /usr/bin/wc -l | /usr/bin/tr -d '[:space:]')" == "${#ids[@]}" ]]
}

published_port() {
  local role=$1 service=$2 target_port=$3 id
  id="$(compose_for "$role" ps --all -q "$service")" || return 1
  # shellcheck disable=SC2016
  docker_cli inspect --format '{{json .NetworkSettings.Ports}}' "$id" | \
    "$NODE_BIN" -e '
      let input="";
      process.stdin.on("data", (chunk) => { input += chunk; });
      process.stdin.on("end", () => {
        try {
          const ports = JSON.parse(input);
          const bindings = ports?.[`${process.argv[1]}/tcp`];
          if (!Array.isArray(bindings) || bindings.length !== 1 ||
              bindings[0]?.HostIp !== "127.0.0.1" ||
              !/^[1-9][0-9]{0,4}$/.test(bindings[0]?.HostPort ?? "")) process.exit(1);
          process.stdout.write(bindings[0].HostPort);
        } catch { process.exit(1); }
      });
    ' "$target_port"
}

start_loopback_proxy() {
  local role=$1 service=$2 target_port=$3 host_port=$4 published token pid pgid attempt observed
  port_is_released "$host_port" || return 1
  published="$(published_port "$role" "$service" "$target_port")" || return 1
  token="$(random_hex 32)" || return 1
  ASTER_PHASE2_PROCESS_TOKEN="$token" "$ENV_BIN" -i PATH='/usr/bin:/bin' \
    ASTER_PHASE2_PROCESS_TOKEN="$token" "$SETSID_BIN" "$SOCAT_BIN" \
    "TCP4-LISTEN:${host_port},bind=127.0.0.1,reuseaddr,fork" \
    "TCP4:127.0.0.1:${published}" </dev/null >/dev/null 2>&1 &
  pid=$!
  pgid=$pid
  for ((attempt=0; attempt<100; attempt++)); do
    kill -0 "$pid" 2>/dev/null || break
    observed="$($PS_BIN -o pgid= -p "$pid" 2>/dev/null | /usr/bin/tr -d '[:space:]')"
    if [[ "$observed" == "$pgid" ]] && process_has_token "$pid" "$token" && port_is_listened_by_pid "$host_port" "$pid"; then
      PROXY_PIDS+=("$pid")
      PROXY_PGIDS+=("$pgid")
      PROXY_TOKENS+=("$token")
      return 0
    fi
    /usr/bin/sleep 0.05
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

start_h5_carrier() {
  local listen=$1 upstream=$2 token pid pgid attempt observed
  port_is_released "$listen" || return 1
  token="$(random_hex 32)" || return 1
  ASTER_PHASE2_PROCESS_TOKEN="$token" "$ENV_BIN" -i PATH="$(/usr/bin/dirname -- "$NODE_BIN"):/usr/bin:/bin" \
    ASTER_PHASE2_PROCESS_TOKEN="$token" "$SETSID_BIN" "$NODE_BIN" "$H5_CARRIER_SCRIPT" \
    "$listen" "$upstream" "$H5_SERVER_CERT" "$H5_SERVER_KEY" </dev/null >/dev/null 2>&1 &
  pid=$!
  pgid=$pid
  for ((attempt=0; attempt<100; attempt++)); do
    kill -0 "$pid" 2>/dev/null || break
    observed="$($PS_BIN -o pgid= -p "$pid" 2>/dev/null | /usr/bin/tr -d '[:space:]')"
    if [[ "$observed" == "$pgid" ]] && process_has_token "$pid" "$token" && port_is_listened_by_pid "$listen" "$pid"; then
      PROXY_PIDS+=("$pid"); PROXY_PGIDS+=("$pgid"); PROXY_TOKENS+=("$token")
      return 0
    fi
    /usr/bin/sleep 0.05
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

http_ready() {
  local port=$1 issuer=$2 response attempt
  for ((attempt=0; attempt<90; attempt++)); do
    response="$({
      printf 'GET /oidc/.well-known/openid-configuration HTTP/1.1\r\n'
      printf 'Host: localhost:%s\r\nConnection: close\r\n\r\n' "$port"
    } | "$NC_BIN" -w 3 127.0.0.1 "$port" 2>/dev/null || true)"
    [[ "$response" == *' 200 OK'* && "$response" == *"\"issuer\":\"${issuer}\""* ]] && return 0
    /usr/bin/sleep 1
  done
  return 1
}

https_ready() {
  local port=$1 issuer=$2 response attempt
  for ((attempt=0; attempt<90; attempt++)); do
    response="$($CURL_BIN --silent --show-error --fail --max-time 3 --cacert "$H5_CA" \
      "https://localhost:${port}/oidc/.well-known/openid-configuration" 2>/dev/null || true)"
    [[ "$response" == *"\"issuer\":\"${issuer}\""* ]] && return 0
    /usr/bin/sleep 1
  done
  return 1
}

wait_for_fixture_socket() {
  local socket_path=${1:-$FIXTURE_SOCKET} attempt
  for ((attempt=0; attempt<90; attempt++)); do
    verify_private_socket "$socket_path" && return 0
    /usr/bin/sleep 1
  done
  return 1
}

owned_container_absent() {
  local container_id=$1 remaining
  remaining="$(docker_cli ps -aq --no-trunc --filter "id=${container_id}")" || return 1
  [[ -z "$remaining" ]]
}

remove_owned_container() {
  local container_id=$1
  docker_cli rm --force --volumes "$container_id" >/dev/null 2>&1 || true
  owned_container_absent "$container_id"
}

cleanup_owned_container_array() {
  local array_name=$1 index cleanup_failed=0
  local -a compacted=()
  local -n owned_ids=$array_name
  for ((index=${#owned_ids[@]} - 1; index>=0; index--)); do
    if remove_owned_container "${owned_ids[index]}"; then
      unset 'owned_ids[index]'
    else
      cleanup_failed=1
    fi
  done
  for index in "${!owned_ids[@]}"; do
    compacted+=("${owned_ids[index]}")
  done
  owned_ids=("${compacted[@]}")
  ((cleanup_failed == 0))
}

discover_project_containers() {
  local array_name=$1 project=$2 discovered container_id existing candidate duplicate
  local -a normalized_ids=()
  local -n project_owned_ids=$array_name
  for existing in "${project_owned_ids[@]}"; do
    [[ "$existing" =~ ^[0-9a-f]{64}$ ]] || return 1
    duplicate=0
    for candidate in "${normalized_ids[@]}"; do
      if [[ "$candidate" == "$existing" ]]; then
        duplicate=1
        break
      fi
    done
    ((duplicate == 1)) || normalized_ids+=("$existing")
  done
  project_owned_ids=("${normalized_ids[@]}")
  discovered="$(docker_cli ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=${project}")" || return 1
  while IFS= read -r container_id; do
    [[ -z "$container_id" ]] && continue
    [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
    duplicate=0
    for existing in "${project_owned_ids[@]}"; do
      [[ "$existing" =~ ^[0-9a-f]{64}$ ]] || return 1
      if [[ "$existing" == "$container_id" ]]; then
        duplicate=1
        break
      fi
    done
    ((duplicate == 1)) || project_owned_ids+=("$container_id")
  done <<<"$discovered"
}

compact_proxy_tracking() {
  local index
  local -a pids=() pgids=() tokens=()
  for index in "${!PROXY_PIDS[@]}"; do
    pids+=("${PROXY_PIDS[index]}")
    pgids+=("${PROXY_PGIDS[index]}")
    tokens+=("${PROXY_TOKENS[index]}")
  done
  PROXY_PIDS=("${pids[@]}")
  PROXY_PGIDS=("${pgids[@]}")
  PROXY_TOKENS=("${tokens[@]}")
}

cleanup_project() {
  local role=$1 project containers networks network remaining_networks volumes volume remaining_volumes cleanup_failed=0 array_name
  project="$(project_name_for "$role")" || return 1
  if [[ "$role" == oracle ]]; then
    array_name=ORACLE_CONTAINER_IDS
  else
    array_name=CANDIDATE_CONTAINER_IDS
  fi
  discover_project_containers "$array_name" "$project" || return 1
  cleanup_owned_container_array "$array_name" || cleanup_failed=1
  if [[ "$role" == oracle ]]; then
    ((${#ORACLE_CONTAINER_IDS[@]} == 0)) || return 1
  else
    ((${#CANDIDATE_CONTAINER_IDS[@]} == 0)) || return 1
  fi
  containers="$(docker_cli ps -aq --no-trunc --filter "label=com.docker.compose.project=${project}" 2>/dev/null)" || return 1
  [[ -z "$containers" ]] || return 1
  networks="$(docker_cli network ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null)" || return 1
  while IFS= read -r network; do
    [[ -z "$network" ]] || docker_cli network rm "$network" >/dev/null 2>&1 || cleanup_failed=1
  done <<<"$networks"
  remaining_networks="$(docker_cli network ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null)" || return 1
  [[ -z "$remaining_networks" ]] || cleanup_failed=1
  volumes="$(docker_cli volume ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null)" || return 1
  while IFS= read -r volume; do
    [[ -z "$volume" ]] || docker_cli volume rm "$volume" >/dev/null 2>&1 || cleanup_failed=1
  done <<<"$volumes"
  remaining_volumes="$(docker_cli volume ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null)" || return 1
  [[ -z "$remaining_volumes" ]] || cleanup_failed=1
  ((cleanup_failed == 0))
}

remove_state_handle_root() {
  local root=$1 root_identity entry name identity current_identity cleanup_path hash index current_uid
  local -a entries=() identities=() cleanup_paths=()
  [[ -z "$root" || ( ! -e "$root" && ! -L "$root" ) ]] && return 0
  [[ -d "$root" && ! -L "$root" ]] || return 1
  [[ "$(/usr/bin/realpath -e -- "$root")" == "$root" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$root")" == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  current_uid=$(/usr/bin/id -u) || return 1
  root_identity="$(capture_path_identity "$root")" || return 1
  while IFS= read -r -d '' entry; do
    name=${entry##*/}
    [[ "$name" =~ ^\.(quarantine|cleanup)\.[0-9a-f]{32}$ ]] || return 1
    [[ -f "$entry" && ! -L "$entry" ]] || return 1
    identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%F' -- "$entry" 2>/dev/null)" || return 1
    [[ "$identity" =~ ^[0-9]+\|[0-9]+\|${current_uid}\|600\|1\|34\|regular\ file$ ]] || return 1
    hash="$(/usr/bin/sha256sum -- "$entry")" || return 1
    [[ "${hash%% *}" == 6345c4e1e6e25cbb82cf6f024cca960d61b3631bd85e1c2433de0a1d5a4e05a4 ]] || return 1
    current_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%F' -- "$entry" 2>/dev/null)" || return 1
    [[ "$current_identity" == "$identity" ]] || return 1
    if [[ "$name" =~ ^\.quarantine\. ]]; then
      cleanup_path="$root/.cleanup.${name#*.quarantine.}"
      [[ ! -e "$cleanup_path" && ! -L "$cleanup_path" ]] || return 1
    else
      cleanup_path=$entry
    fi
    entries+=("$entry")
    identities+=("$identity")
    cleanup_paths+=("$cleanup_path")
  done < <(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print0)
  assert_path_identity "$root" "$root_identity" || return 1
  for index in "${!entries[@]}"; do
    entry=${entries[index]}
    identity=${identities[index]}
    cleanup_path=${cleanup_paths[index]}
    if [[ "$entry" != "$cleanup_path" ]]; then
      [[ "$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%F' -- "$entry" 2>/dev/null)" == "$identity" ]] || return 1
      /usr/bin/mv --no-clobber --no-target-directory -- "$entry" "$cleanup_path" || return 1
    fi
    [[ "$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%F' -- "$cleanup_path" 2>/dev/null)" == "$identity" ]] || return 1
    /usr/bin/rm -- "$cleanup_path" || return 1
  done
  assert_path_identity "$root" "$root_identity" || return 1
  /usr/bin/rmdir -- "$root"
}

capture_invariant_handle_identity() {
  local entry=$1 identity device inode owner mode links size type current_uid
  [[ -f "$entry" && ! -L "$entry" ]] || return 1
  current_uid=$(/usr/bin/id -u) || return 1
  identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%F' -- "$entry" 2>/dev/null)" || return 1
  IFS='|' read -r device inode owner mode links size type <<<"$identity"
  [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ && "$owner" == "$current_uid" && \
     "$mode" == 600 && "$links" == 1 && "$size" =~ ^[0-9]+$ && "$type" == 'regular file' ]] || return 1
  ((10#$size >= 1 && 10#$size <= 65536)) || return 1
  printf '%s' "$identity"
}

assert_invariant_handle_root_owned() {
  local root=$1 entry name
  local -a entries=()
  [[ -n "$root" && -d "$root" && ! -L "$root" ]] || return 1
  [[ "$(/usr/bin/realpath -e -- "$root" 2>/dev/null || true)" == "$root" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$root" 2>/dev/null || true)" == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  if [[ -n "${INVARIANT_HANDLE_ROOT:-}" && "$root" == "$INVARIANT_HANDLE_ROOT" ]]; then
    [[ -n "${INVARIANT_HANDLE_ROOT_IDENTITY:-}" ]] || return 1
    assert_path_identity "$root" "$INVARIANT_HANDLE_ROOT_IDENTITY" || return 1
  fi
  shopt -s nullglob dotglob
  entries=("$root"/*)
  shopt -u nullglob dotglob
  ((${#entries[@]} <= 64)) || return 1
  for entry in "${entries[@]}"; do
    name=${entry##*/}
    [[ "$name" =~ ^[0-9a-f]{32}$ || "$name" =~ ^\.quarantine\.[0-9a-f]{32}$ ]] || return 1
    capture_invariant_handle_identity "$entry" >/dev/null || return 1
  done
}

remove_invariant_handle_root() {
  local root=$1 root_identity entry name identity full_identity cleanup_path cleanup_identity index
  local -a entries=() identities=() full_identities=() cleanup_paths=()
  [[ -z "$root" || ( ! -e "$root" && ! -L "$root" ) ]] && return 0
  assert_invariant_handle_root_owned "$root" || return 1
  root_identity="$(capture_path_identity "$root")" || return 1
  shopt -s nullglob dotglob
  entries=("$root"/*)
  shopt -u nullglob dotglob
  for index in "${!entries[@]}"; do
    entry=${entries[index]}
    name=${entry##*/}
    identity="$(capture_invariant_handle_identity "$entry")" || return 1
    full_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%y|%z|%F' -- "$entry" 2>/dev/null || true)" || return 1
    if [[ "$name" =~ ^[0-9a-f]{32}$ ]]; then
      cleanup_path="$root/.cleanup.armed.$name"
    else
      cleanup_path="$root/.cleanup.retired.${name#*.quarantine.}"
    fi
    [[ ! -e "$cleanup_path" && ! -L "$cleanup_path" ]] || return 1
    identities+=("$identity")
    full_identities+=("$full_identity")
    cleanup_paths+=("$cleanup_path")
  done
  assert_path_identity "$root" "$root_identity" || return 1
  for index in "${!entries[@]}"; do
    entry=${entries[index]}
    identity=${identities[index]}
    full_identity=${full_identities[index]}
    cleanup_path=${cleanup_paths[index]}
    assert_path_identity "$root" "$root_identity" || return 1
    [[ "$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%y|%z|%F' -- "$entry" 2>/dev/null || true)" == "$full_identity" ]] || return 1
    /usr/bin/mv --no-clobber --no-target-directory -- "$entry" "$cleanup_path" || return 1
    [[ ! -e "$entry" && ! -L "$entry" ]] || return 1
    cleanup_identity="$(capture_invariant_handle_identity "$cleanup_path")" || return 1
    [[ "$cleanup_identity" == "$identity" ]] || return 1
    full_identity="$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%y|%z|%F' -- "$cleanup_path" 2>/dev/null || true)" || return 1
    [[ "$(/usr/bin/stat -c '%d|%i|%u|%a|%h|%s|%y|%z|%F' -- "$cleanup_path" 2>/dev/null || true)" == "$full_identity" ]] || return 1
    /usr/bin/rm -- "$cleanup_path" || return 1
    assert_path_identity "$root" "$root_identity" || return 1
  done
  assert_path_identity "$root" "$root_identity" || return 1
  /usr/bin/rmdir -- "$root"
}

assert_ports_released() {
  local port attempt state released
  for port in "$@"; do
    released=0
    for ((attempt=0; attempt<=100; attempt++)); do
      state="$(port_state "$port")" || return 1
      if [[ "$state" == released ]]; then
        released=1
        break
      fi
      if ((attempt < 100)); then
        /usr/bin/sleep 0.05
      fi
    done
    [[ "$released" == 1 ]] || return 1
  done
  return 0
}

remove_run_root() {
  local root=$1
  [[ -n "$root" ]] || return 1
  [[ ! -e "$root" && ! -L "$root" ]] && return 0
  [[ -d "$root" && ! -L "$root" ]] || return 1
  if [[ "$root" == "$RUN_DIR" && -n "${RUN_DIR_IDENTITY:-}" ]]; then
    assert_path_identity "$root" "$RUN_DIR_IDENTITY" || return 1
  fi
  if [[ -n "${BUILD_ROOT:-}" && -n "${BUILD_ROOT_IDENTITY:-}" ]]; then
    assert_path_identity "$BUILD_ROOT" "$BUILD_ROOT_IDENTITY" || return 1
  fi
  /usr/bin/rm -rf -- "$root"
}

remove_owned_result_directory() {
  local directory=$1 identity=$2
  [[ -z "$directory" || ! -e "$directory" ]] && return 0
  [[ -n "$RESULT_ROOT" && -n "$RESULT_ROOT_IDENTITY" ]] || return 1
  assert_path_identity "$RESULT_ROOT" "$RESULT_ROOT_IDENTITY" || return 1
  case "$directory" in
    "$RESULT_ROOT"/.staging.*|"$RESULT_ROOT"/result.*) ;;
    *) return 1 ;;
  esac
  [[ -n "$identity" && -d "$directory" && ! -L "$directory" ]] || return 1
  assert_path_identity "$directory" "$identity" || return 1
  /usr/bin/rm -rf -- "$directory"
}

verify_published_result_directory() {
  local directory=$1 oracle_sha=$2 differential_sha=$3 invariant_sha=$4 files
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$directory")" == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  files="$(/usr/bin/find "$directory" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | /usr/bin/sort)"
  [[ "$files" == $'phase-2-client-credentials-candidate-invariants.json\nphase-2-client-credentials-differential.json\nphase-2-client-credentials-oracle.json' ]] || return 1
  [[ "$(/usr/bin/stat -c '%a' -- "$directory"/*.json | /usr/bin/sort -u)" == 600 ]] || return 1
  [[ "$(sha256_file "$directory/phase-2-client-credentials-oracle.json")" == "$oracle_sha" ]] || return 1
  [[ "$(sha256_file "$directory/phase-2-client-credentials-differential.json")" == "$differential_sha" ]] || return 1
  [[ "$(sha256_file "$directory/phase-2-client-credentials-candidate-invariants.json")" == "$invariant_sha" ]]
}

cleanup_resources() {
  local original_status=$1 cleanup_failed=0 index
  set +e
  if [[ "$TOPOLOGY_CLEANED" == 0 ]]; then
    if [[ -n "$EXTRACTION_CONTAINER_ID" ]]; then
      if remove_owned_container "$EXTRACTION_CONTAINER_ID"; then
        EXTRACTION_CONTAINER_ID=''
      else
        cleanup_failed=1
      fi
    fi
    if [[ -n "$PROBE_CONTAINER_ID" ]]; then
      if remove_owned_container "$PROBE_CONTAINER_ID"; then
        PROBE_CONTAINER_ID=''
      else
        cleanup_failed=1
      fi
    fi
    for ((index=${#PROXY_PIDS[@]} - 1; index>=0; index--)); do
      if stop_owned_proxy "${PROXY_PIDS[index]}" "${PROXY_PGIDS[index]}" "${PROXY_TOKENS[index]}"; then
        unset 'PROXY_PIDS[index]' 'PROXY_PGIDS[index]' 'PROXY_TOKENS[index]'
      else
        cleanup_failed=1
      fi
    done
    compact_proxy_tracking
    if [[ "$CANDIDATE_PROJECT_STARTED" == 1 ]]; then
      if cleanup_project candidate; then
        CANDIDATE_PROJECT_STARTED=0
        CANDIDATE_CONTAINER_IDS=()
      else
        cleanup_failed=1
      fi
    fi
    if [[ "$ORACLE_PROJECT_STARTED" == 1 ]]; then
      if cleanup_project oracle; then
        ORACLE_PROJECT_STARTED=0
        ORACLE_CONTAINER_IDS=()
      else
        cleanup_failed=1
      fi
    fi
    if [[ -z "$EXTRACTION_CONTAINER_ID" && -z "$PROBE_CONTAINER_ID" && ${#PROXY_PIDS[@]} == 0 && "$CANDIDATE_PROJECT_STARTED" == 0 && "$ORACLE_PROJECT_STARTED" == 0 ]]; then
      remove_invariant_handle_root "$INVARIANT_HANDLE_ROOT" || cleanup_failed=1
      remove_state_handle_root "$STATE_HANDLE_ROOT" || cleanup_failed=1
      assert_ports_released "${PORTS[@]}" "${COMPLETION_PORTS[@]}" || cleanup_failed=1
      if [[ -n "$RUN_DIR" ]]; then
        remove_run_root "$RUN_DIR" || cleanup_failed=1
      fi
      if [[ "$cleanup_failed" == 0 ]]; then
        TOPOLOGY_CLEANED=1
      fi
    else
      cleanup_failed=1
    fi
  fi
  if [[ "$original_status" != 0 ]]; then
    remove_owned_result_directory "$RESULT_DIR" "$RESULT_DIR_IDENTITY" || cleanup_failed=1
    remove_owned_result_directory "$RESULT_STAGING_DIR" "$RESULT_STAGING_IDENTITY" || cleanup_failed=1
  fi
  if [[ "$original_status" == 0 && "$cleanup_failed" != 0 ]]; then
    return 1
  fi
  return "$original_status"
}

cleanup_trap() {
  local status=$? cleanup_complete=0 attempt
  trap - EXIT INT TERM HUP
  for attempt in 1 2; do
    if cleanup_resources 0; then
      cleanup_complete=1
      break
    fi
  done
  if [[ "$status" != 0 ]]; then
    remove_owned_result_directory "$RESULT_DIR" "$RESULT_DIR_IDENTITY" || cleanup_complete=0
    remove_owned_result_directory "$RESULT_STAGING_DIR" "$RESULT_STAGING_IDENTITY" || cleanup_complete=0
  fi
  if [[ "$cleanup_complete" != 1 ]]; then
    printf 'Aster Phase 2 client credentials cleanup incomplete\n' >&2
  fi
  if [[ "$status" != 0 ]]; then
    exit "$status"
  fi
  [[ "$cleanup_complete" == 1 ]] || exit 1
  exit 0
}

git_text() {
  local root=$1
  shift
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$BUILD_ROOT" LC_ALL=C \
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 \
    "$GIT_BIN" --no-replace-objects -C "$root" "$@"
}

capture_repository_identity() {
  local root=$1 expected=$2 top head tree status origin directory
  top="$(git_text "$root" rev-parse --show-toplevel 2>/dev/null || true)"
  head="$(git_text "$root" rev-parse HEAD 2>/dev/null || true)"
  tree="$(git_text "$root" rev-parse 'HEAD^{tree}' 2>/dev/null || true)"
  status="$(git_text "$root" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)"
  origin="$(git_text "$root" remote get-url origin 2>/dev/null || true)"
  directory="$(capture_path_identity "$root" 2>/dev/null || true)"
  [[ "$top" == "$root" && "$head" =~ ^[0-9a-f]{40}$ && "$tree" =~ ^[0-9a-f]{40}$ && -z "$status" ]] || return 1
  case "$expected|$origin" in
    logto\|https://github.com/qq98982/logto.git|logto\|git@github.com:qq98982/logto.git|logto\|ssh://git@github.com/qq98982/logto.git) ;;
    aster\|https://github.com/qq98982/aster.git|aster\|git@github.com:qq98982/aster.git|aster\|ssh://git@github.com/qq98982/aster.git) ;;
    *) return 1 ;;
  esac
  printf '%s|%s|%s|%s' "$head" "$tree" "$origin" "$directory"
}

assert_source_identity_unchanged() {
  [[ "$(capture_repository_identity "$REPO_ROOT" logto)" == "$H_SOURCE_IDENTITY" ]] || return 1
  [[ "$(capture_repository_identity "$ASTER_ROOT" aster)" == "$ASTER_SOURCE_IDENTITY" ]]
}

artifact_identity() {
  local file=$1
  printf '%s|%s' "$(capture_path_identity "$file")" "$(sha256_file "$file")"
}

socket_identity() {
  local socket=$1
  verify_private_socket "$socket" || return 1
  capture_path_identity "$socket"
}

core_identity() {
  local role=$1 service=$2 expected_image=$3 expected_project metadata id image configured_image project label status exit_code health
  expected_project="$(project_name_for "$role")"
  metadata="$(inspect_service "$role" "$service")" || return 1
  IFS='|' read -r id image configured_image project label status exit_code health <<<"$metadata"
  [[ "$id" =~ ^[0-9a-f]{64}$ && "$image" == "$expected_image" \
    && "$configured_image" =~ ^[A-Za-z0-9._/@:-]{1,512}$ \
    && "$project" == "$expected_project" && "$label" == "$service" \
    && "$status" == running && "$exit_code" == 0 && "$health" == healthy ]] || return 1
  printf '%s' "$metadata"
}

assert_expected_fixture_images() {
  local role service expected metadata id image configured_image project label status exit_code health
  while IFS='|' read -r role service expected; do
    metadata="$(inspect_service "$role" "$service")" || return 1
    IFS='|' read -r id image configured_image project label status exit_code health <<<"$metadata"
    [[ "$id" =~ ^[0-9a-f]{64}$ && "$image" == "$expected" \
      && "$configured_image" =~ ^[A-Za-z0-9._/@:-]{1,512}$ \
      && "$project" == "$(project_name_for "$role")" && "$label" == "$service" \
      && "$status" == running && "$exit_code" == 0 && "$health" == healthy ]] || return 1
  done <<EOF
oracle|oracle-fetch-observer|$ORACLE_IMAGE_ID
oracle|oracle-primary-smtp|$SCRIPT_SUPERVISOR_IMAGE_ID
candidate|candidate-fetch-observer|$ORACLE_IMAGE_ID
candidate|candidate-script-supervisor|$SCRIPT_SUPERVISOR_IMAGE_ID
candidate|candidate-script-executor|$SCRIPT_EXECUTOR_IMAGE_ID
candidate|candidate-primary-smtp|$SCRIPT_SUPERVISOR_IMAGE_ID
candidate|candidate-password-smtp|$SCRIPT_SUPERVISOR_IMAGE_ID
EOF

  while IFS='|' read -r role service; do
    metadata="$(inspect_service "$role" "$service")" || return 1
    IFS='|' read -r id image configured_image project label status exit_code health <<<"$metadata"
    [[ "$id" =~ ^[0-9a-f]{64}$ && "$image" == "$PROVIDER_FIXTURE_IMAGE_ID" \
      && "$configured_image" =~ ^[A-Za-z0-9._/@:-]{1,512}$ \
      && "$project" == "$(project_name_for "$role")" && "$label" == "$service" ]] || return 1
  done <<'EOF'
oracle|oracle-google-provider
candidate|candidate-google-provider
oracle|oracle-wechat-provider
candidate|candidate-wechat-provider
oracle|oracle-sms-provider
candidate|candidate-sms-provider
oracle|oracle-pwned-clear
oracle|oracle-pwned-compromised
oracle|oracle-pwned-unavailable
candidate|candidate-pwned-clear
candidate|candidate-pwned-compromised
candidate|candidate-pwned-unavailable
oracle|oracle-backchannel-accepted
oracle|oracle-backchannel-rejected
candidate|candidate-backchannel-accepted
candidate|candidate-backchannel-rejected
oracle|oracle-h5-wechat-provider
candidate|candidate-h5-wechat-provider
oracle|oracle-wechat-multichannel-provider
candidate|candidate-wechat-multichannel-provider
EOF
}

assert_google_provider_private_material() {
  local expected_inputs=$1 expected_mutable=$2 directory file identity owner mode links size type
  for directory in "$GOOGLE_PROVIDER_ROOT" \
    "$GOOGLE_PROVIDER_ROOT/oracle" "$GOOGLE_PROVIDER_ROOT/oracle/configuration" \
    "$GOOGLE_PROVIDER_ROOT/oracle/receipts" "$GOOGLE_PROVIDER_ROOT/oracle/diagnostics" \
    "$GOOGLE_PROVIDER_ROOT/candidate" "$GOOGLE_PROVIDER_ROOT/candidate/configuration" \
    "$GOOGLE_PROVIDER_ROOT/candidate/receipts" "$GOOGLE_PROVIDER_ROOT/candidate/diagnostics"; do
    [[ "$directory" == /* && -d "$directory" && ! -L "$directory" \
      && "$(/usr/bin/realpath -e -- "$directory")" == "$directory" \
      && "$(/usr/bin/stat -c '%u|%a|%F' -- "$directory")" \
        == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  done
  for file in "$ORACLE_GOOGLE_CONFIG" "$ORACLE_GOOGLE_RECEIPT" \
    "$ORACLE_GOOGLE_DIAGNOSTIC" "$CANDIDATE_GOOGLE_CONFIG" \
    "$CANDIDATE_GOOGLE_RECEIPT" "$CANDIDATE_GOOGLE_DIAGNOSTIC"; do
    [[ "$file" == /* && -f "$file" && ! -L "$file" \
      && "$(/usr/bin/realpath -e -- "$file")" == "$file" ]] || return 1
    identity="$(/usr/bin/stat -c '%u|%a|%h|%s|%F' -- "$file")" || return 1
    IFS='|' read -r owner mode links size type <<<"$identity"
    [[ "$owner" == "$(/usr/bin/id -u)" && "$mode" == 600 && "$links" == 1 \
      && "$size" =~ ^[0-9]+$ && "$type" =~ ^regular(\ empty)?\ file$ ]] || return 1
    ((10#$size <= 65536)) || return 1
    if [[ "$expected_mutable" == empty ]]; then
      [[ "$size" == 0 ]] || return 1
    elif [[ "$expected_mutable" != bounded ]]; then
      return 1
    fi
  done
  for file in "$ORACLE_GOOGLE_PROVIDER_INPUT" "$CANDIDATE_GOOGLE_PROVIDER_INPUT"; do
    if [[ "$expected_inputs" == absent ]]; then
      [[ ! -e "$file" && ! -L "$file" ]] || return 1
    elif [[ "$expected_inputs" == present ]]; then
      [[ -f "$file" && ! -L "$file" \
        && "$(/usr/bin/realpath -e -- "$file")" == "$file" ]] || return 1
      identity="$(/usr/bin/stat -c '%u|%a|%h|%s|%F' -- "$file")" || return 1
      IFS='|' read -r owner mode links size type <<<"$identity"
      [[ "$owner" == "$(/usr/bin/id -u)" && "$mode" == 600 && "$links" == 1 \
        && "$size" =~ ^[1-9][0-9]*$ && "$type" == 'regular file' ]] || return 1
      ((10#$size <= 65536)) || return 1
    else
      return 1
    fi
  done
}

assert_google_provider_state() {
  local role=$1 service=$2 expected_status=$3 expected_running=$4 expected_ip=$5 id document expected_mac
  case "$role" in
    oracle) expected_mac='02:42:ac:1e:e7:34' ;;
    candidate) expected_mac='02:42:ac:1e:f1:34' ;;
    *) return 1 ;;
  esac
  id="$(compose_for "$role" ps --all -q "$service")" || return 1
  document="$(docker_cli inspect "$id")" || return 1
  # The jq program intentionally uses literal container fields.
  # shellcheck disable=SC2016
  "$JQ_BIN" -e --arg id "$id" --arg image "$PROVIDER_FIXTURE_IMAGE_ID" \
    --arg project "$(project_name_for "$role")" --arg service "$service" \
    --arg status "$expected_status" --argjson running "$expected_running" --arg ip "$expected_ip" \
    --arg mac "$expected_mac" '
    length==1 and .[0].Id==$id and .[0].Image==$image
    and .[0].Config.Labels["com.docker.compose.project"]==$project
    and .[0].Config.Labels["com.docker.compose.service"]==$service
    and .[0].State.Status==$status and .[0].State.Running==$running
    and ([.[0].NetworkSettings.Networks[] | .IPAddress] |
      if $running then index($ip)!=null else all(.=="" or .==$ip) end)
    and ([.[0].NetworkSettings.Networks[] | .MacAddress] |
      if $running then .==[$mac] else all(.=="" or .==$mac) end)
    and .[0].HostConfig.ReadonlyRootfs==true
    and (.[0].HostConfig.CapAdd==null or .[0].HostConfig.CapAdd==[])
    and (.[0].HostConfig.SecurityOpt==["no-new-privileges"] or
      .[0].HostConfig.SecurityOpt==["no-new-privileges:true"])
  ' <<<"$document" >/dev/null
}

prove_google_provider_runtime() {
  local role=$1 service=$2 expected_ip=$3 id status_file sysctl_file field
  start_compose_stage "$role" google-proof "$service" || return 1
  assert_google_provider_state "$role" "$service" running true "$expected_ip" || return 1
  id="$(compose_for "$role" ps --all -q "$service")" || return 1
  status_file="$RUN_DIR/$role-google-provider-status"
  sysctl_file="$RUN_DIR/$role-google-provider-port-start"
  docker_cli exec "$id" /bin/cat /proc/1/status >"$status_file" 2>/dev/null || return 1
  for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    [[ "$(/usr/bin/awk -v key="$field:" '$1==key{print $2}' "$status_file")" \
      == 0000000000000000 ]] || return 1
  done
  [[ "$(/usr/bin/awk '$1=="NoNewPrivs:"{print $2}' "$status_file")" == 1 ]] || return 1
  docker_cli exec "$id" /bin/cat /proc/sys/net/ipv4/ip_unprivileged_port_start \
    >"$sysctl_file" 2>/dev/null || return 1
  [[ "$(<"$sysctl_file")" == 443 ]] || return 1
  /usr/bin/rm -- "$status_file" "$sysctl_file" || return 1
  compose_for "$role" stop --timeout 5 "$service" >/dev/null || return 1
  assert_google_provider_state "$role" "$service" exited false "$expected_ip"
}

assert_wechat_provider_private_material() {
  local expected_inputs=$1 expected_mutable=$2 directory file identity owner mode links size type
  for directory in "$WECHAT_PROVIDER_ROOT" \
    "$WECHAT_PROVIDER_ROOT/oracle" "$WECHAT_PROVIDER_ROOT/oracle/configuration" \
    "$WECHAT_PROVIDER_ROOT/oracle/receipts" "$WECHAT_PROVIDER_ROOT/oracle/diagnostics" \
    "$WECHAT_PROVIDER_ROOT/candidate" "$WECHAT_PROVIDER_ROOT/candidate/configuration" \
    "$WECHAT_PROVIDER_ROOT/candidate/receipts" "$WECHAT_PROVIDER_ROOT/candidate/diagnostics"; do
    [[ "$directory" == /* && -d "$directory" && ! -L "$directory" \
      && "$(/usr/bin/realpath -e -- "$directory")" == "$directory" \
      && "$(/usr/bin/stat -c '%u|%a|%F' -- "$directory")" \
        == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  done
  for file in "$ORACLE_WECHAT_CONFIG" "$ORACLE_WECHAT_RECEIPT" \
    "$ORACLE_WECHAT_DIAGNOSTIC" "$CANDIDATE_WECHAT_CONFIG" \
    "$CANDIDATE_WECHAT_RECEIPT" "$CANDIDATE_WECHAT_DIAGNOSTIC"; do
    [[ "$file" == /* && -f "$file" && ! -L "$file" \
      && "$(/usr/bin/realpath -e -- "$file")" == "$file" ]] || return 1
    identity="$(/usr/bin/stat -c '%u|%a|%h|%s|%F' -- "$file")" || return 1
    IFS='|' read -r owner mode links size type <<<"$identity"
    [[ "$owner" == "$(/usr/bin/id -u)" && "$mode" == 600 && "$links" == 1 \
      && "$size" =~ ^[0-9]+$ && "$type" =~ ^regular(\ empty)?\ file$ ]] || return 1
    ((10#$size <= 65536)) || return 1
    if [[ "$expected_mutable" == empty ]]; then
      [[ "$size" == 0 ]] || return 1
    elif [[ "$expected_mutable" != bounded ]]; then
      return 1
    fi
  done
  for file in "$ORACLE_WECHAT_PROVIDER_INPUT" "$CANDIDATE_WECHAT_PROVIDER_INPUT"; do
    if [[ "$expected_inputs" == absent ]]; then
      [[ ! -e "$file" && ! -L "$file" ]] || return 1
    elif [[ "$expected_inputs" == present ]]; then
      [[ -f "$file" && ! -L "$file" \
        && "$(/usr/bin/realpath -e -- "$file")" == "$file" ]] || return 1
      identity="$(/usr/bin/stat -c '%u|%a|%h|%s|%F' -- "$file")" || return 1
      IFS='|' read -r owner mode links size type <<<"$identity"
      [[ "$owner" == "$(/usr/bin/id -u)" && "$mode" == 600 && "$links" == 1 \
        && "$size" =~ ^[1-9][0-9]*$ && "$type" == 'regular file' ]] || return 1
      ((10#$size <= 65536)) || return 1
    else
      return 1
    fi
  done
}

assert_wechat_provider_state() {
  local role=$1 service=$2 expected_status=$3 expected_running=$4 expected_ip=$5 id document expected_mac
  case "$role" in
    oracle) expected_mac='02:42:ac:1e:e7:35' ;;
    candidate) expected_mac='02:42:ac:1e:f1:35' ;;
    *) return 1 ;;
  esac
  id="$(compose_for "$role" ps --all -q "$service")" || return 1
  document="$(docker_cli inspect "$id")" || return 1
  # The jq program intentionally uses literal container fields.
  # shellcheck disable=SC2016
  "$JQ_BIN" -e --arg id "$id" --arg image "$PROVIDER_FIXTURE_IMAGE_ID" \
    --arg project "$(project_name_for "$role")" --arg service "$service" \
    --arg status "$expected_status" --argjson running "$expected_running" --arg ip "$expected_ip" \
    --arg mac "$expected_mac" '
    length==1 and .[0].Id==$id and .[0].Image==$image
    and .[0].Config.Labels["com.docker.compose.project"]==$project
    and .[0].Config.Labels["com.docker.compose.service"]==$service
    and .[0].State.Status==$status and .[0].State.Running==$running
    and ([.[0].NetworkSettings.Networks[] | .IPAddress] |
      if $running then index($ip)!=null else all(.=="" or .==$ip) end)
    and ([.[0].NetworkSettings.Networks[] | .MacAddress] |
      if $running then .==[$mac] else all(.=="" or .==$mac) end)
    and .[0].HostConfig.ReadonlyRootfs==true
    and (.[0].HostConfig.CapAdd==null or .[0].HostConfig.CapAdd==[])
    and (.[0].HostConfig.SecurityOpt==["no-new-privileges"] or
      .[0].HostConfig.SecurityOpt==["no-new-privileges:true"])
  ' <<<"$document" >/dev/null
}

prove_wechat_provider_runtime() {
  local role=$1 service=$2 expected_ip=$3 id status_file sysctl_file field
  start_compose_stage "$role" wechat-proof "$service" || return 1
  assert_wechat_provider_state "$role" "$service" running true "$expected_ip" || return 1
  id="$(compose_for "$role" ps --all -q "$service")" || return 1
  status_file="$RUN_DIR/$role-wechat-provider-status"
  sysctl_file="$RUN_DIR/$role-wechat-provider-port-start"
  docker_cli exec "$id" /bin/cat /proc/1/status >"$status_file" 2>/dev/null || return 1
  for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    [[ "$(/usr/bin/awk -v key="$field:" '$1==key{print $2}' "$status_file")" \
      == 0000000000000000 ]] || return 1
  done
  [[ "$(/usr/bin/awk '$1=="NoNewPrivs:"{print $2}' "$status_file")" == 1 ]] || return 1
  docker_cli exec "$id" /bin/cat /proc/sys/net/ipv4/ip_unprivileged_port_start \
    >"$sysctl_file" 2>/dev/null || return 1
  [[ "$(<"$sysctl_file")" == 443 ]] || return 1
  /usr/bin/rm -- "$status_file" "$sysctl_file" || return 1
  compose_for "$role" stop --timeout 5 "$service" >/dev/null || return 1
  assert_wechat_provider_state "$role" "$service" exited false "$expected_ip"
}

topology_identity() {
  local role service metadata
  for role in oracle candidate; do
    if [[ "$role" == oracle ]]; then
      set -- "${ORACLE_SERVICES[@]}"
    else
      set -- "${CANDIDATE_SERVICES[@]}"
    fi
    for service in "$@"; do
      metadata="$(inspect_service "$role" "$service")" || return 1
      case "$service" in
        oracle-google-provider|candidate-google-provider|oracle-wechat-provider|candidate-wechat-provider|\
        oracle-sms-provider|candidate-sms-provider|oracle-pwned-*|candidate-pwned-*|\
        oracle-backchannel-*|candidate-backchannel-*|oracle-h5-wechat-provider|candidate-h5-wechat-provider|\
        oracle-wechat-multichannel-provider|candidate-wechat-multichannel-provider)
          IFS='|' read -r id image configured project label _ <<<"$metadata"
          printf '%s|%s|%s|%s|%s|%s\n' \
            "$role" "$id" "$image" "$configured" "$project" "$label" || return 1
          ;;
        *) printf '%s|%s\n' "$role" "$metadata" || return 1 ;;
      esac
    done
  done
}

assert_state_handle_root_clean() {
  [[ ! -e "$STATE_HANDLE_ROOT" && ! -L "$STATE_HANDLE_ROOT" ]] && return 0
  [[ -d "$STATE_HANDLE_ROOT" && ! -L "$STATE_HANDLE_ROOT" ]] || return 1
  [[ "$(/usr/bin/realpath -e -- "$STATE_HANDLE_ROOT")" == "$STATE_HANDLE_ROOT" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$STATE_HANDLE_ROOT")" == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  [[ -z "$(/usr/bin/find "$STATE_HANDLE_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]
}

assert_runtime_identity_unchanged() {
  local oracle_image candidate_metadata candidate_id candidate_source candidate_revision candidate_tree
  local image_role image_id image_id_variable image_metadata
  oracle_image="$(docker_cli image inspect --format '{{.Id}}' "$ORACLE_IMAGE_PIN" 2>/dev/null || true)"
  oracle_image="$(normalize_image_id "$oracle_image")" || return 1
  [[ "$oracle_image" == "$ORACLE_IMAGE_ID" ]] || return 1
  candidate_metadata="$(docker_cli image inspect --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "io.aster.source.tree"}}' "$CANDIDATE_IMAGE_ID" 2>/dev/null || true)"
  IFS='|' read -r candidate_id candidate_source candidate_revision candidate_tree <<<"$candidate_metadata"
  candidate_id="$(normalize_image_id "$candidate_id")" || return 1
  [[ "$candidate_id" == "$CANDIDATE_IMAGE_ID" && "$candidate_source" == "$EXPECTED_ASTER_SOURCE" && "$candidate_revision" == "$ASTER_HEAD" && "$candidate_tree" == "$ASTER_TREE" ]] || return 1
  for image_role in SUPERVISOR EXECUTOR; do
    image_id_variable="SCRIPT_${image_role}_IMAGE_ID"
    image_id="${!image_id_variable}"
    image_metadata="$(docker_cli image inspect --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "io.aster.source.tree"}}|{{index .Config.Labels "dev.aster.reference.revision"}}' "$image_id" 2>/dev/null || true)"
    [[ "$(validate_script_host_image_metadata "$image_id" "$image_metadata")" == "$image_id" ]] || return 1
  done
  [[ "$(core_identity oracle oracle-primary-core "$ORACLE_IMAGE_ID")" == "$ORACLE_PRIMARY_CORE_IDENTITY" ]] || return 1
  [[ "$(core_identity oracle oracle-foreign-core "$ORACLE_IMAGE_ID")" == "$ORACLE_FOREIGN_CORE_IDENTITY" ]] || return 1
  [[ "$(core_identity candidate candidate-primary-core "$CANDIDATE_IMAGE_ID")" == "$CANDIDATE_PRIMARY_CORE_IDENTITY" ]] || return 1
  [[ "$(core_identity candidate candidate-foreign-core "$CANDIDATE_IMAGE_ID")" == "$CANDIDATE_FOREIGN_CORE_IDENTITY" ]] || return 1
  [[ "$(core_identity oracle oracle-h5-core "$ORACLE_IMAGE_ID")" == "$ORACLE_H5_CORE_IDENTITY" ]] || return 1
  [[ "$(core_identity candidate candidate-h5-core "$CANDIDATE_IMAGE_ID")" == "$CANDIDATE_H5_CORE_IDENTITY" ]] || return 1
  [[ "$(core_identity oracle oracle-password-core "$ORACLE_IMAGE_ID")" == "$ORACLE_PASSWORD_CORE_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$ORACLE_STATE_DRIVER")" == "$ORACLE_STATE_DRIVER_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$CANDIDATE_STATE_DRIVER")" == "$CANDIDATE_STATE_DRIVER_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$CANDIDATE_INVARIANT_DRIVER")" == "$CANDIDATE_INVARIANT_DRIVER_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$ASTER_ADMIN_BIN")" == "$ASTER_ADMIN_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$ORACLE_GOOGLE_PROVIDER_INPUT")" \
    == "$ORACLE_GOOGLE_PROVIDER_INPUT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$CANDIDATE_GOOGLE_PROVIDER_INPUT")" \
    == "$CANDIDATE_GOOGLE_PROVIDER_INPUT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$ORACLE_WECHAT_PROVIDER_INPUT")" \
    == "$ORACLE_WECHAT_PROVIDER_INPUT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$CANDIDATE_WECHAT_PROVIDER_INPUT")" \
    == "$CANDIDATE_WECHAT_PROVIDER_INPUT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$ORACLE_COMPLETION_INPUT")" == "$ORACLE_COMPLETION_INPUT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$CANDIDATE_COMPLETION_INPUT")" == "$CANDIDATE_COMPLETION_INPUT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$CANDIDATE_IDENTITY_CONFIG")" == "$CANDIDATE_IDENTITY_CONFIG_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$IDENTITY_CA")" == "$IDENTITY_CA_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$IDENTITY_CA_BUNDLE")" == "$IDENTITY_CA_BUNDLE_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$IDENTITY_SERVER_CERT")" == "$IDENTITY_SERVER_CERT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$IDENTITY_SERVER_KEY")" == "$IDENTITY_SERVER_KEY_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$H5_CA")" == "$H5_CA_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$H5_SERVER_CERT")" == "$H5_SERVER_CERT_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$H5_SERVER_KEY")" == "$H5_SERVER_KEY_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$H5_SPKI")" == "$H5_SPKI_IDENTITY" ]] || return 1
  [[ "$(artifact_identity "$H5_CANDIDATE_CONFIG")" == "$H5_CANDIDATE_CONFIG_IDENTITY" ]] || return 1
  [[ "$(socket_identity "$ENGINE_SOCKET")" == "$ENGINE_SOCKET_IDENTITY" ]] || return 1
  [[ "$(socket_identity "$FIXTURE_SOCKET")" == "$FIXTURE_SOCKET_IDENTITY" ]] || return 1
  [[ "$(topology_identity)" == "$TOPOLOGY_IDENTITY" ]] || return 1
  assert_expected_fixture_images || return 1
  assert_google_provider_private_material present empty || return 1
  assert_wechat_provider_private_material present empty || return 1
  assert_private_runtime_material || return 1
  assert_invariant_handle_root_owned "$INVARIANT_HANDLE_ROOT" || return 1
  assert_state_handle_root_clean || return 1
  assert_path_identity "$BUILD_ROOT" "$BUILD_ROOT_IDENTITY" || return 1
  assert_path_identity "$RUN_DIR" "$RUN_DIR_IDENTITY"
}

write_descriptors() {
  # The jq programs intentionally use literal jq variables.
  # shellcheck disable=SC2016
  "$JQ_BIN" -n \
    --arg sourceCommit "$ORACLE_SOURCE_COMMIT" --arg imageDigest "$ORACLE_IMAGE_ID" \
    --arg projectName "$ORACLE_PROJECT_NAME" \
    --arg primaryContainerId "$ORACLE_PRIMARY_CORE_ID" --arg foreignContainerId "$ORACLE_FOREIGN_CORE_ID" \
    --arg driverPath "$ORACLE_STATE_DRIVER" --arg driverSha "$ORACLE_STATE_DRIVER_SHA256" \
    --arg socket "$ENGINE_SOCKET" --arg fetchReceipt "$ORACLE_OBSERVER_RECEIPT" '
      {schemaVersion:1,kind:"oracle",sourceCommit:$sourceCommit,imageDigest:$imageDigest,
       projectName:$projectName,primaryContainerId:$primaryContainerId,foreignContainerId:$foreignContainerId,
       target:{label:"oracle",coreUrl:"http://localhost:3311/",adminUrl:"http://localhost:3411/"},
       foreignTarget:{label:"oracle",coreUrl:"http://localhost:3312/",adminUrl:"http://localhost:3412/"},
       stateDriver:{path:$driverPath,sha256:$driverSha,controlSocket:$socket},
       fetchObserverReceiptFile:$fetchReceipt}' >"$ORACLE_DESCRIPTOR" || return 1
  # shellcheck disable=SC2016
  "$JQ_BIN" -n \
    --arg sourceCommit "$ASTER_HEAD" --arg imageDigest "$CANDIDATE_IMAGE_ID" \
    --arg projectName "$CANDIDATE_PROJECT_NAME" \
    --arg primaryContainerId "$CANDIDATE_PRIMARY_CORE_ID" --arg foreignContainerId "$CANDIDATE_FOREIGN_CORE_ID" \
    --arg statePath "$CANDIDATE_STATE_DRIVER" --arg stateSha "$CANDIDATE_STATE_DRIVER_SHA256" \
    --arg fixturePath "$ASTER_ADMIN_BIN" --arg fixtureSha "$ASTER_ADMIN_SHA256" --arg fixtureSocket "$FIXTURE_SOCKET" \
    --arg invariantPath "$CANDIDATE_INVARIANT_DRIVER" --arg invariantSha "$CANDIDATE_INVARIANT_DRIVER_SHA256" \
    --arg socket "$ENGINE_SOCKET" --arg fetchReceipt "$CANDIDATE_OBSERVER_RECEIPT" '
      {schemaVersion:1,kind:"candidate",sourceCommit:$sourceCommit,imageDigest:$imageDigest,
       projectName:$projectName,primaryContainerId:$primaryContainerId,foreignContainerId:$foreignContainerId,
       target:{label:"candidate",coreUrl:"http://localhost:3321/",adminUrl:"http://localhost:3421/"},
       foreignTarget:{label:"candidate",coreUrl:"http://localhost:3322/",adminUrl:"http://localhost:3422/"},
       stateDriver:{path:$statePath,sha256:$stateSha,controlSocket:$socket},
       fixtureExecutable:{path:$fixturePath,sha256:$fixtureSha},fixtureSocket:$fixtureSocket,
       invariantDriver:{path:$invariantPath,sha256:$invariantSha,controlSocket:$socket},
       fetchObserverReceiptFile:$fetchReceipt}' >"$CANDIDATE_DESCRIPTOR" || return 1
  /usr/bin/chmod 0600 "$ORACLE_DESCRIPTOR" "$CANDIDATE_DESCRIPTOR"
}

scan_evidence_for_private_values() {
  "$NODE_BIN" --input-type=module - \
    "$PROFILE_SOURCE" "$SCHEMA_SOURCE" "$ORACLE_EVIDENCE" "$DIFFERENTIAL_EVIDENCE" "$INVARIANT_EVIDENCE" \
    "$ORACLE_ENV" "$CANDIDATE_ENV" "$H_HEAD" "$H_TREE" "$ORACLE_SOURCE_COMMIT" "$ASTER_HEAD" \
    "$ORACLE_IMAGE_ID" "$CANDIDATE_IMAGE_ID" "$ORACLE_STATE_DRIVER_SHA256" "$CANDIDATE_STATE_DRIVER_SHA256" \
    "$CANDIDATE_INVARIANT_DRIVER_SHA256" "$ASTER_ADMIN_SHA256" \
    "$ORACLE_GOOGLE_PROVIDER_INPUT" "$CANDIDATE_GOOGLE_PROVIDER_INPUT" \
    "$ORACLE_WECHAT_PROVIDER_INPUT" "$CANDIDATE_WECHAT_PROVIDER_INPUT" \
    "$SMS_PROVIDER_ROOT/o/configuration.json" "$SMS_PROVIDER_ROOT/c/configuration.json" \
    "$RUN_DIR" "$REPO_ROOT" "$ASTER_ROOT" \
    "$ENGINE_SOCKET" "$FIXTURE_SOCKET" "$STATE_HANDLE_ROOT" "$ORACLE_PROJECT_NAME" "$CANDIDATE_PROJECT_NAME" \
    "$ORACLE_PRIMARY_CORE_ID" "$ORACLE_FOREIGN_CORE_ID" "$CANDIDATE_PRIMARY_CORE_ID" "$CANDIDATE_FOREIGN_CORE_ID" <<'NODE'
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';

const [profilePath, schemaPath, oraclePath, differentialPath, invariantPath,
  oracleEnvPath, candidateEnvPath, harnessHead, harnessTree, oracleCommit, candidateCommit,
  oracleImage, candidateImage, oracleStateSha, candidateStateSha, invariantSha, fixtureSha,
  oracleGoogleProviderPath, candidateGoogleProviderPath, oracleWechatProviderPath, candidateWechatProviderPath,
  oracleSmsProviderPath, candidateSmsProviderPath, ...forbiddenPrivateValues] = process.argv.slice(2);
const fail = () => process.exit(1);
const readJson = async (file) => JSON.parse(await readFile(file, 'utf8'));
const hash = async (file) => createHash('sha256').update(await readFile(file)).digest('hex');
const [profile, oracle, differential, invariants] = await Promise.all([
  readJson(profilePath), readJson(oraclePath), readJson(differentialPath), readJson(invariantPath),
]);
const profileSha = await hash(profilePath);
const schemaSha = await hash(schemaPath);
const exact = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && Object.keys(value).every((key) => keys.includes(key));
const common = (value, mode) => {
  const provenanceKeys = mode === 'oracle'
    ? ['profileSha256','schemaSha256','baseAcceptance','harness','oracle']
    : mode === 'differential'
      ? ['profileSha256','schemaSha256','baseAcceptance','harness','oracle','candidate']
      : ['profileSha256','schemaSha256','baseAcceptance','harness','candidate'];
  if (!exactKeys(value, ['schemaVersion','mode','provenance','sanitizerSuccess','payload']) ||
      !exactKeys(value.provenance, provenanceKeys) ||
      !exactKeys(value.provenance?.harness, ['repositoryUrl','headCommit','headTree','runtimeBundleSha256']) ||
      value.schemaVersion !== 1 || value.mode !== mode || value.sanitizerSuccess !== true ||
      value.provenance?.profileSha256 !== profileSha || value.provenance?.schemaSha256 !== schemaSha ||
      !exact(value.provenance?.baseAcceptance, profile.baseAcceptance) ||
      value.provenance?.harness?.headCommit !== harnessHead ||
      value.provenance?.harness?.headTree !== harnessTree ||
      !/^[0-9a-f]{64}$/.test(value.provenance?.harness?.runtimeBundleSha256 ?? '')) fail();
};
common(oracle, 'oracle');
common(differential, 'differential');
common(invariants, 'candidate-invariants');
const bundles = [oracle, differential, invariants].map((value) => value.provenance.harness.runtimeBundleSha256);
if (new Set(bundles).size !== 1) fail();
const checkTopology = (target, kind, sourceCommit, imageDigest, stateSha, fixture, invariant) => {
  const driverKeys = fixture ? ['state','fixture','invariant'] : ['state'];
  if (!exactKeys(target, ['sourceCommit','imageDigest','topology','drivers']) ||
      !exactKeys(target?.topology, ['primaryRole','foreignRole']) ||
      !exactKeys(target?.drivers, driverKeys) ||
      !exactKeys(target?.drivers?.state, ['role','sha256']) ||
      target?.sourceCommit !== sourceCommit || target?.imageDigest !== imageDigest ||
      !exact(target?.topology, {primaryRole:`${kind}-primary-core`,foreignRole:`${kind}-foreign-core`}) ||
      target?.drivers?.state?.role !== 'state-driver' || target?.drivers?.state?.sha256 !== stateSha) fail();
  if (fixture) {
    if (!exactKeys(target?.drivers?.fixture, ['role','sha256']) ||
        !exactKeys(target?.drivers?.invariant, ['role','sha256']) ||
        target?.drivers?.fixture?.role !== 'fixture-executable' || target?.drivers?.fixture?.sha256 !== fixtureSha ||
        target?.drivers?.invariant?.role !== 'invariant-driver' || target?.drivers?.invariant?.sha256 !== invariantSha) fail();
  } else if (target?.drivers?.fixture !== undefined || target?.drivers?.invariant !== undefined) fail();
};
checkTopology(oracle.provenance.oracle, 'oracle', oracleCommit, oracleImage, oracleStateSha, false, false);
checkTopology(differential.provenance.oracle, 'oracle', oracleCommit, oracleImage, oracleStateSha, false, false);
checkTopology(differential.provenance.candidate, 'candidate', candidateCommit, candidateImage, candidateStateSha, true, true);
checkTopology(invariants.provenance.candidate, 'candidate', candidateCommit, candidateImage, candidateStateSha, true, true);

const oracleScenarios = oracle.payload?.target?.scenarios;
const scenarioCount = oracleScenarios?.length;
const oracleControls = oracle.payload?.target?.controls;
const expectedControlNames = [
  'status','challenge','error','audience','scope','client-id','organization-id','typ','alg','kid',
  'discovery-grant-order','unexpected-field','status','path','cookie-clearing','oauth','claimKeys',
  'discovery-fields',
];
const expectedControlCount = expectedControlNames.length;
const controlsAreExact = (controls) => Array.isArray(controls) && controls.every((control, index) =>
  exactKeys(control, ['name','pointer','detected']) &&
  control.name === expectedControlNames[index] &&
  typeof control.pointer === 'string' && control.detected === true);
if (!exactKeys(oracle.payload, ['schemaVersion','mode','target']) ||
    !exactKeys(oracle.payload?.target, ['target','scenarios','discovery','controls']) ||
    oracle.payload.schemaVersion !== 1 || oracle.payload.mode !== 'oracle' ||
    oracle.payload.target.target !== 'oracle' ||
    scenarioCount !== 206 || oracleControls?.length !== expectedControlCount ||
    oracleScenarios.some((scenario) => !exactKeys(scenario, ['id','projection'])) ||
    !controlsAreExact(oracleControls) ||
    !exact(oracleScenarios.map(({id}) => id), profile.differentialScenarios)) fail();
for (const side of [differential.payload?.oracle, differential.payload?.candidate]) {
  if (!exactKeys(side, ['target','scenarios','discovery','controls']) ||
      side?.scenarios?.length !== 206 || side?.controls?.length !== expectedControlCount ||
      side.scenarios.some((scenario) => !exactKeys(scenario, ['id','projection'])) ||
      !controlsAreExact(side.controls) || !exact(side.controls, oracleControls) ||
      !exact(side.scenarios.map(({id}) => id), profile.differentialScenarios)) fail();
}
if (!exactKeys(differential.payload, ['schemaVersion','mode','oracle','candidate','comparisons']) ||
    differential.payload.schemaVersion !== 1 || differential.payload.mode !== 'differential' ||
    differential.payload.oracle.target !== 'oracle' ||
    differential.payload.candidate.target !== 'candidate') fail();
const comparisonCount = differential.payload?.comparisons?.length;
if (comparisonCount !== 206 || differential.payload.comparisons.some((comparison, index) =>
  !exactKeys(comparison, ['scenarioId','differenceCount']) ||
  comparison.scenarioId !== profile.differentialScenarios[index] || comparison.differenceCount !== 0)) fail();
const invariantCount = invariants.payload?.invariants?.length;
if (!exactKeys(invariants.payload, ['schemaVersion','mode','invariants']) ||
    invariants.payload.schemaVersion !== 1 || invariants.payload.mode !== 'candidate-invariants' ||
    invariantCount !== 24 || !exact(invariants.payload.invariants.map(({id}) => id), profile.candidateInvariantScenarios) ||
    invariants.payload.invariants.some((entry) =>
      !exactKeys(entry, ['id','candidate','positiveControl','negativeControl']) ||
      entry.positiveControl?.detected !== true || entry.negativeControl?.detected !== true ||
      typeof entry.negativeControl?.pointer !== 'string')) fail();

const serialized = [oracle, differential, invariants].map((value) => JSON.stringify(value));
const envValues = [];
for (const envPath of [oracleEnvPath, candidateEnvPath]) {
  for (const line of (await readFile(envPath, 'utf8')).split('\n')) {
    const separator = line.indexOf('=');
    if (separator > 0 && /(?:PASSWORD|SECRET_VAULT_KEK|STATUS_API_KEY)$/.test(line.slice(0, separator))) {
      envValues.push(line.slice(separator + 1));
    }
  }
}
const providerValues = (await Promise.all([
  oracleGoogleProviderPath, candidateGoogleProviderPath, oracleWechatProviderPath, candidateWechatProviderPath,
  oracleSmsProviderPath, candidateSmsProviderPath,
].map(readJson))).flatMap((provider) => [
  'clientId', 'clientSecret', 'googleSubject', 'originalOwnerEmail', 'changedProviderEmail', 'wechatSubject', 'unionId',
  'accessKeyId', 'accessKeySecret', 'signName', 'controlCapability',
].map((key) => provider[key]).filter((value) => typeof value === 'string' && value.length > 0));
for (const text of serialized) {
  if (forbiddenPrivateValues.some((value) => value && text.includes(value)) ||
      envValues.some((value) => value && text.includes(value)) ||
      providerValues.some((value) => text.includes(value)) ||
      /(?:\/home\/|\/var\/tmp\/|\.sock(?:"|\\)|"(?:containerId|projectName|socket)"\s*:)/u.test(text)) fail();
}
for (const file of [oraclePath, differentialPath, invariantPath]) {
  if (((await stat(file)).mode & 0o777) !== 0o600) fail();
}
NODE
}

bootstrap_playwright() {
  local launcher_path browser_executable browser_identity
  local -a browser_executables=()
  launcher_path="$(/usr/bin/dirname -- "$NODE_BIN"):$(/usr/bin/dirname -- "$PNPM_BIN"):/usr/bin:/bin"
  "$ENV_BIN" -i PATH="$launcher_path" HOME="$PRIVATE_HOME" \
    PLAYWRIGHT_BROWSERS_PATH="$BROWSER_CACHE" TMPDIR="$BROWSER_TMP" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME" CI=true \
    "$PNPM_BIN" --dir "$REPO_ROOT/packages/integration-tests" exec playwright install chromium \
    >"$PLAYWRIGHT_BOOTSTRAP_LOG" 2>&1 || return 1
  mapfile -t browser_executables < <(
    /usr/bin/find "$BROWSER_CACHE" -type f \
      -path '*/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell' -print
  )
  [[ "${#browser_executables[@]}" -eq 1 ]] || return 1
  browser_executable="${browser_executables[0]}"
  [[ "$(/usr/bin/realpath -e -- "$browser_executable")" == "$BROWSER_CACHE"/* ]] || return 1
  browser_identity="$(/usr/bin/stat -c '%u|%a|%h|%F' -- "$browser_executable")" || return 1
  [[ "$browser_identity" =~ ^$(/usr/bin/id -u)\|[0-7]*[1357][0-7][0-7]\|1\|regular\ file$ \
    && -x "$browser_executable" && ! -L "$browser_executable" ]]
}

main() {
  [[ $# == 0 ]] || { failure_stage='arguments'; fail; return 1; }

  GIT_BIN="$(trusted_system_binary /usr/bin/git)" || { failure_stage='trusted-git'; fail; return 1; }
  DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)" || { failure_stage='trusted-docker'; fail; return 1; }
  CURL_BIN="$(trusted_system_binary /usr/bin/curl)" || { failure_stage='trusted-curl'; fail; return 1; }
  ENV_BIN="$(trusted_system_binary /usr/bin/env)" || { failure_stage='trusted-env'; fail; return 1; }
  TIMEOUT_BIN="$(trusted_system_binary /usr/bin/timeout)" || { failure_stage='trusted-timeout'; fail; return 1; }
  SETSID_BIN="$(trusted_system_binary /usr/bin/setsid)" || { failure_stage='trusted-setsid'; fail; return 1; }
  SOCAT_BIN="$(trusted_system_binary /usr/bin/socat)" || { failure_stage='trusted-socat'; fail; return 1; }
  SS_BIN="$(trusted_system_binary /usr/bin/ss)" || { failure_stage='trusted-ss'; fail; return 1; }
  PS_BIN="$(trusted_system_binary /usr/bin/ps)" || { failure_stage='trusted-ps'; fail; return 1; }
  AWK_BIN="$(trusted_system_binary /usr/bin/awk)" || { failure_stage='trusted-awk'; fail; return 1; }
  SHA256_BIN="$(trusted_system_binary /usr/bin/sha256sum)" || { failure_stage='trusted-sha256'; fail; return 1; }
  OPENSSL_BIN="$(trusted_system_binary /usr/bin/openssl)" || { failure_stage='trusted-openssl'; fail; return 1; }
  JQ_BIN="$(trusted_system_binary /usr/bin/jq)" || { failure_stage='trusted-jq'; fail; return 1; }
  NC_BIN="$(trusted_system_binary /usr/bin/nc)" || { failure_stage='trusted-nc'; fail; return 1; }
  READELF_BIN="$(trusted_system_binary /usr/bin/readelf)" || { failure_stage='trusted-readelf'; fail; return 1; }
  LDD_BIN="$(trusted_system_binary /usr/bin/ldd)" || { failure_stage='trusted-ldd'; fail; return 1; }
  NODE_BIN="$(trusted_binary node)" || { failure_stage='trusted-node'; fail; return 1; }
  PNPM_BIN="$(trusted_binary pnpm)" || { failure_stage='trusted-pnpm'; fail; return 1; }
  readonly GIT_BIN DOCKER_BIN CURL_BIN ENV_BIN TIMEOUT_BIN SETSID_BIN SOCAT_BIN SS_BIN PS_BIN
  readonly AWK_BIN SHA256_BIN OPENSSL_BIN JQ_BIN NC_BIN READELF_BIN LDD_BIN NODE_BIN PNPM_BIN
  [[ "$($ENV_BIN -i PATH='/usr/bin:/bin' "$NODE_BIN" --version)" == v22.23.2 ]] || { failure_stage='node-version'; fail; return 1; }
  [[ "$($ENV_BIN -i PATH="$(/usr/bin/dirname -- "$PNPM_BIN"):/usr/bin:/bin" HOME="${HOME:?}" "$PNPM_BIN" --version)" == 10.15.1 ]] || { failure_stage='pnpm-version'; fail; return 1; }

  SCRIPT_DIR="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
  readonly SCRIPT_DIR REPO_ROOT
  SOURCE_COMPOSE="$REPO_ROOT/docker-compose.phase1-runtime-candidate-differential.yml"
  PODMAN_GENERATOR="$REPO_ROOT/.scripts/compatibility/phase1-podman-differential-topology.mjs"
  STATE_DRIVER_SOURCE="$REPO_ROOT/.scripts/compatibility/phase2-client-credentials-state-driver.sh"
  INVARIANT_DRIVER_SOURCE="$REPO_ROOT/.scripts/compatibility/phase2-client-credentials-invariant-driver.sh"
  GOOGLE_PROVIDER_SCRIPT="$REPO_ROOT/.scripts/compatibility/phase2-google-provider.mjs"
  GOOGLE_TOPOLOGY_MODULE="$REPO_ROOT/.scripts/compatibility/phase2-google-provider-topology.mjs"
  GOOGLE_RUNTIME_HELPER="$REPO_ROOT/.scripts/compatibility/phase2-google-provider-runtime.mjs"
  WECHAT_PROVIDER_SCRIPT="$REPO_ROOT/.scripts/compatibility/phase2-wechat-provider.mjs"
  WECHAT_TOPOLOGY_MODULE="$REPO_ROOT/.scripts/compatibility/phase2-wechat-provider-topology.mjs"
  WECHAT_RUNTIME_HELPER="$REPO_ROOT/.scripts/compatibility/phase2-wechat-provider-runtime.mjs"
  SMS_PROVIDER_SCRIPT="$REPO_ROOT/.scripts/compatibility/phase2-sms-provider.mjs"
  SMS_TOPOLOGY_MODULE="$REPO_ROOT/.scripts/compatibility/phase2-sms-provider-topology.mjs"
  SMS_RUNTIME_HELPER="$REPO_ROOT/.scripts/compatibility/phase2-sms-provider-runtime.mjs"
  IDENTITY_PKI_SCRIPT="$REPO_ROOT/.scripts/compatibility/generate-identity-transport-pki.sh"
  H5_PKI_SCRIPT="$REPO_ROOT/.scripts/compatibility/generate-h5-pki.sh"
  COMPLETION_DESCRIPTOR_GENERATOR="$REPO_ROOT/.scripts/compatibility/generate-runtime-descriptors.mjs"
  OWNED_ATTEMPT_TOPOLOGY="$REPO_ROOT/.scripts/compatibility/extend-owned-attempt-services.mjs"
  H5_WECHAT_TOPOLOGY="$REPO_ROOT/.scripts/compatibility/extend-h5-wechat-topology.mjs"
  H5_CORE_TOPOLOGY="$REPO_ROOT/.scripts/compatibility/extend-h5-core-topology.mjs"
  PASSWORD_CORE_TOPOLOGY="$REPO_ROOT/.scripts/compatibility/extend-password-core-topology.mjs"
  MULTICHANNEL_TOPOLOGY="$REPO_ROOT/.scripts/compatibility/extend-wechat-multichannel-topology.mjs"
  CANDIDATE_IDENTITY_TOPOLOGY="$REPO_ROOT/.scripts/compatibility/apply-candidate-identity-config.mjs"
  PWNED_PROVIDER_SCRIPT="$REPO_ROOT/.scripts/compatibility/pwned-range-provider.mjs"
  BACKCHANNEL_RECEIVER_SCRIPT="$REPO_ROOT/.scripts/compatibility/backchannel-receiver.mjs"
  MULTICHANNEL_PROVIDER_SCRIPT="$REPO_ROOT/.scripts/compatibility/wechat-multichannel-provider.mjs"
  H5_CARRIER_SCRIPT="$REPO_ROOT/.scripts/compatibility/h5-https-carrier.mjs"
  LAUNCHER_SOURCE="$REPO_ROOT/packages/integration-tests/src/compatibility/phase-2/launcher.mjs"
  readonly SOURCE_COMPOSE PODMAN_GENERATOR STATE_DRIVER_SOURCE INVARIANT_DRIVER_SOURCE
  readonly GOOGLE_PROVIDER_SCRIPT GOOGLE_TOPOLOGY_MODULE GOOGLE_RUNTIME_HELPER LAUNCHER_SOURCE
  readonly WECHAT_PROVIDER_SCRIPT WECHAT_TOPOLOGY_MODULE WECHAT_RUNTIME_HELPER
  readonly SMS_PROVIDER_SCRIPT SMS_TOPOLOGY_MODULE SMS_RUNTIME_HELPER
  readonly IDENTITY_PKI_SCRIPT H5_PKI_SCRIPT COMPLETION_DESCRIPTOR_GENERATOR OWNED_ATTEMPT_TOPOLOGY
  readonly H5_WECHAT_TOPOLOGY H5_CORE_TOPOLOGY PASSWORD_CORE_TOPOLOGY MULTICHANNEL_TOPOLOGY CANDIDATE_IDENTITY_TOPOLOGY
  readonly PWNED_PROVIDER_SCRIPT BACKCHANNEL_RECEIVER_SCRIPT MULTICHANNEL_PROVIDER_SCRIPT H5_CARRIER_SCRIPT
  for tracked_input in "$SOURCE_COMPOSE" "$PODMAN_GENERATOR" "$STATE_DRIVER_SOURCE" \
    "$INVARIANT_DRIVER_SOURCE" "$GOOGLE_PROVIDER_SCRIPT" "$GOOGLE_TOPOLOGY_MODULE" \
    "$GOOGLE_RUNTIME_HELPER" "$WECHAT_PROVIDER_SCRIPT" "$WECHAT_TOPOLOGY_MODULE" \
    "$WECHAT_RUNTIME_HELPER" "$SMS_PROVIDER_SCRIPT" "$SMS_TOPOLOGY_MODULE" \
    "$SMS_RUNTIME_HELPER" "$IDENTITY_PKI_SCRIPT" "$H5_PKI_SCRIPT" \
    "$COMPLETION_DESCRIPTOR_GENERATOR" "$OWNED_ATTEMPT_TOPOLOGY" "$H5_WECHAT_TOPOLOGY" "$H5_CORE_TOPOLOGY" "$PASSWORD_CORE_TOPOLOGY" \
    "$MULTICHANNEL_TOPOLOGY" "$CANDIDATE_IDENTITY_TOPOLOGY" "$PWNED_PROVIDER_SCRIPT" \
    "$BACKCHANNEL_RECEIVER_SCRIPT" "$MULTICHANNEL_PROVIDER_SCRIPT" "$H5_CARRIER_SCRIPT" \
    "$LAUNCHER_SOURCE"; do
    [[ -f "$tracked_input" && ! -L "$tracked_input" ]] \
      || { failure_stage='tracked-inputs'; fail; return 1; }
  done

  [[ -n "${ASTER_PHASE2_ASTER_ROOT+x}" && -n "${ASTER_PHASE2_ORACLE_IMAGE+x}" && -n "${ASTER_PHASE2_CANDIDATE_IMAGE+x}" && -n "${ASTER_PHASE2_SCRIPT_SUPERVISOR_IMAGE+x}" && -n "${ASTER_PHASE2_SCRIPT_EXECUTOR_IMAGE+x}" && -n "${ASTER_PHASE2_ENGINE_SOCKET+x}" ]] || { failure_stage='required-environment'; fail; return 1; }
  [[ "$ASTER_PHASE2_ORACLE_IMAGE" == "$ORACLE_IMAGE_PIN" ]] || { failure_stage='oracle-pin'; fail; return 1; }
  [[ "$ASTER_PHASE2_CANDIDATE_IMAGE" =~ ^sha256:[0-9a-f]{64}$ && "$ASTER_PHASE2_CANDIDATE_IMAGE" != "$ORACLE_IMAGE_PIN" ]] || { failure_stage='candidate-pin'; fail; return 1; }
  BUILD_ROOT="${ASTER_PHASE2_BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
  require_safe_private_root "$BUILD_ROOT" || { failure_stage='build-root'; fail; return 1; }
  BUILD_ROOT_IDENTITY="$(capture_path_identity "$BUILD_ROOT")"
  BROWSER_CACHE="$BUILD_ROOT/aster-playwright-browsers"
  require_safe_private_root "$BROWSER_CACHE" || { failure_stage='browser-cache'; fail; return 1; }
  BROWSER_CACHE_IDENTITY="$(capture_path_identity "$BROWSER_CACHE")"
  readonly BUILD_ROOT BUILD_ROOT_IDENTITY
  readonly BROWSER_CACHE BROWSER_CACHE_IDENTITY
  ENGINE_SOCKET="$ASTER_PHASE2_ENGINE_SOCKET"
  verify_private_socket "$ENGINE_SOCKET" || { failure_stage='engine-socket'; fail; return 1; }
  ENGINE_SOCKET_IDENTITY="$(socket_identity "$ENGINE_SOCKET")"
  STATE_HANDLE_ROOT="$(/usr/bin/dirname -- "$ENGINE_SOCKET")/phase2-client-credentials-state"
  INVARIANT_HANDLE_ROOT="$(/usr/bin/dirname -- "$ENGINE_SOCKET")/phase2-device-invariants"
  [[ ! -e "$STATE_HANDLE_ROOT" && ! -L "$STATE_HANDLE_ROOT" ]] || { failure_stage='state-handle-root'; fail; return 1; }
  [[ ! -e "$INVARIANT_HANDLE_ROOT" && ! -L "$INVARIANT_HANDLE_ROOT" ]] || { failure_stage='invariant-handle-root'; fail; return 1; }
  readonly ENGINE_SOCKET ENGINE_SOCKET_IDENTITY STATE_HANDLE_ROOT INVARIANT_HANDLE_ROOT

  ASTER_ROOT="$ASTER_PHASE2_ASTER_ROOT"
  [[ "$ASTER_ROOT" == /* && -d "$ASTER_ROOT" && ! -L "$ASTER_ROOT" ]] || { failure_stage='aster-root'; fail; return 1; }
  ASTER_ROOT="$(/usr/bin/realpath -e -- "$ASTER_ROOT")"
  H_SOURCE_IDENTITY="$(capture_repository_identity "$REPO_ROOT" logto)" || { failure_stage='h-source'; fail; return 1; }
  ASTER_SOURCE_IDENTITY="$(capture_repository_identity "$ASTER_ROOT" aster)" || { failure_stage='aster-source'; fail; return 1; }
  IFS='|' read -r H_HEAD H_TREE _ <<<"$H_SOURCE_IDENTITY"
  IFS='|' read -r ASTER_HEAD ASTER_TREE _ <<<"$ASTER_SOURCE_IDENTITY"
  readonly ASTER_ROOT H_SOURCE_IDENTITY ASTER_SOURCE_IDENTITY H_HEAD H_TREE ASTER_HEAD ASTER_TREE

  PROFILE_SOURCE="$ASTER_ROOT/compatibility/phase-2-profile.json"
  SCHEMA_SOURCE="$ASTER_ROOT/compatibility/phase-2-profile.schema.json"
  [[ -f "$PROFILE_SOURCE" && -f "$SCHEMA_SOURCE" && ! -L "$PROFILE_SOURCE" && ! -L "$SCHEMA_SOURCE" ]] || { failure_stage='phase2-profile'; fail; return 1; }
  readonly PROFILE_SOURCE SCHEMA_SOURCE

  PRIVATE_BASE="$BUILD_ROOT/aster-phase2-client-credentials-live"
  RESULT_ROOT="$BUILD_ROOT/aster-phase2-client-credentials-results"
  require_safe_private_root "$PRIVATE_BASE" || { failure_stage='run-root'; fail; return 1; }
  require_safe_private_root "$RESULT_ROOT" || { failure_stage='result-root'; fail; return 1; }
  RESULT_ROOT_IDENTITY="$(capture_path_identity "$RESULT_ROOT")"
  RUN_DIR="$(/usr/bin/mktemp -d "$PRIVATE_BASE/run.XXXXXX")"
  /usr/bin/chmod 0700 "$RUN_DIR"
  RUN_DIR_IDENTITY="$(capture_path_identity "$RUN_DIR")"
  readonly PRIVATE_BASE RESULT_ROOT RESULT_ROOT_IDENTITY RUN_DIR RUN_DIR_IDENTITY
  PRIVATE_HOME="$RUN_DIR/home"
  BROWSER_TMP="$RUN_DIR/browser-tmp"
  XDG_RUNTIME="$RUN_DIR/xdg-runtime"
  PLAYWRIGHT_BOOTSTRAP_LOG="$RUN_DIR/playwright-bootstrap.log"
  CONFIG_DIR="$RUN_DIR/config"
  FIXTURE_DIRECTORY="$RUN_DIR/fixture"
  HOST_BIN_DIRECTORY="$RUN_DIR/host-bin"
  PRIMARY_KEYRING_DIRECTORY="$RUN_DIR/candidate-primary-keys"
  FOREIGN_KEYRING_DIRECTORY="$RUN_DIR/candidate-foreign-keys"
  EVIDENCE_DIR="$RUN_DIR/evidence"
  TLS_DIRECTORY="$RUN_DIR/tls"
  ORACLE_OBSERVER_RECEIPT_DIRECTORY="$RUN_DIR/oracle-fetch-observer-receipts"
  CANDIDATE_OBSERVER_RECEIPT_DIRECTORY="$RUN_DIR/candidate-fetch-observer-receipts"
  SCRIPT_HOST_STATE="$RUN_DIR/script-host-state"
  GOOGLE_PROVIDER_ROOT="$RUN_DIR/google-provider"
  WECHAT_PROVIDER_ROOT="$RUN_DIR/wechat-provider"
  SMS_PROVIDER_ROOT="$RUN_DIR/s"
  COMPLETION_ROOT="$RUN_DIR/common-completion"
  IDENTITY_TLS_ROOT="$COMPLETION_ROOT/runtime-identity"
  H5_RUNTIME_ROOT="$COMPLETION_ROOT/runtime-h5"
  ORACLE_SMS_PROVIDER_INPUT="$SMS_PROVIDER_ROOT/o/input.json"
  CANDIDATE_SMS_PROVIDER_INPUT="$SMS_PROVIDER_ROOT/c/input.json"
  readonly SMS_PROVIDER_ROOT ORACLE_SMS_PROVIDER_INPUT CANDIDATE_SMS_PROVIDER_INPUT
  for directory in "$PRIVATE_HOME" "$BROWSER_TMP" "$XDG_RUNTIME" "$CONFIG_DIR" \
    "$FIXTURE_DIRECTORY" "$HOST_BIN_DIRECTORY" \
    "$PRIMARY_KEYRING_DIRECTORY" "$FOREIGN_KEYRING_DIRECTORY" "$EVIDENCE_DIR" "$TLS_DIRECTORY" \
    "$ORACLE_OBSERVER_RECEIPT_DIRECTORY" "$CANDIDATE_OBSERVER_RECEIPT_DIRECTORY" \
    "$SCRIPT_HOST_STATE" "$COMPLETION_ROOT" "$IDENTITY_TLS_ROOT" "$H5_RUNTIME_ROOT"; do
    /usr/bin/mkdir -m 700 -- "$directory"
  done
  readonly PRIVATE_HOME BROWSER_TMP XDG_RUNTIME PLAYWRIGHT_BOOTSTRAP_LOG
  readonly CONFIG_DIR FIXTURE_DIRECTORY HOST_BIN_DIRECTORY
  readonly PRIMARY_KEYRING_DIRECTORY FOREIGN_KEYRING_DIRECTORY EVIDENCE_DIR
  readonly TLS_DIRECTORY ORACLE_OBSERVER_RECEIPT_DIRECTORY
  readonly CANDIDATE_OBSERVER_RECEIPT_DIRECTORY SCRIPT_HOST_STATE GOOGLE_PROVIDER_ROOT WECHAT_PROVIDER_ROOT
  ORACLE_PROJECT_NAME="aster-phase2-client-credentials-$(random_hex 8)"
  CANDIDATE_PROJECT_NAME="aster-phase2-client-credentials-$(random_hex 8)"
  [[ "$ORACLE_PROJECT_NAME" != "$CANDIDATE_PROJECT_NAME" ]] || { failure_stage='project-names'; fail; return 1; }
  readonly ORACLE_PROJECT_NAME CANDIDATE_PROJECT_NAME

  ORACLE_ENV="$CONFIG_DIR/oracle-compose.env"
  CANDIDATE_ENV="$CONFIG_DIR/candidate-compose.env"
  ORACLE_COMPOSE="$CONFIG_DIR/oracle-compose.json"
  CANDIDATE_COMPOSE="$CONFIG_DIR/candidate-compose.json"
  ORACLE_DESCRIPTOR="$CONFIG_DIR/oracle-target.json"
  CANDIDATE_DESCRIPTOR="$CONFIG_DIR/candidate-target.json"
  PRIMARY_CONFIG_FILE="$CONFIG_DIR/candidate-primary.conf"
  FOREIGN_CONFIG_FILE="$CONFIG_DIR/candidate-foreign.conf"
  FIXTURE_SOCKET="$FIXTURE_DIRECTORY/aster-fixture.sock"
  ORACLE_SMTP_SOCKET="$FIXTURE_DIRECTORY/oracle-smtp.sock"
  CANDIDATE_PASSWORD_SMTP_SOCKET="$FIXTURE_DIRECTORY/password-smtp.sock"
  ORACLE_STATE_DRIVER="$HOST_BIN_DIRECTORY/oracle-state-driver"
  CANDIDATE_STATE_DRIVER="$HOST_BIN_DIRECTORY/candidate-state-driver"
  CANDIDATE_INVARIANT_DRIVER="$HOST_BIN_DIRECTORY/candidate-invariant-driver"
  ASTER_ADMIN_BIN="$HOST_BIN_DIRECTORY/aster-admin"
  ORACLE_EVIDENCE="$EVIDENCE_DIR/phase-2-client-credentials-oracle.json"
  DIFFERENTIAL_EVIDENCE="$EVIDENCE_DIR/phase-2-client-credentials-differential.json"
  INVARIANT_EVIDENCE="$EVIDENCE_DIR/phase-2-client-credentials-candidate-invariants.json"
  FETCH_OBSERVER_SCRIPT="$REPO_ROOT/.scripts/compatibility/phase2-fetch-observer.mjs"
  FETCH_OBSERVER_CA="$TLS_DIRECTORY/fetch-observer-ca.pem"
  OBSERVER_CA_KEY="$TLS_DIRECTORY/fetch-observer-ca.key"
  OBSERVER_SERVER_CERT="$TLS_DIRECTORY/fetch-observer-server.pem"
  OBSERVER_SERVER_KEY="$TLS_DIRECTORY/fetch-observer-server.key"
  OBSERVER_SERVER_CSR="$TLS_DIRECTORY/fetch-observer-server.csr"
  OBSERVER_SERVER_EXT="$TLS_DIRECTORY/fetch-observer-server.ext"
  SCRIPT_HOST_CA="$TLS_DIRECTORY/script-host-ca.pem"
  SCRIPT_HOST_CA_KEY="$TLS_DIRECTORY/script-host-ca.key"
  SCRIPT_HOST_SERVER_CERT="$TLS_DIRECTORY/script-host-server.pem"
  SCRIPT_HOST_SERVER_KEY="$TLS_DIRECTORY/script-host-server.key"
  SCRIPT_HOST_SERVER_CSR="$TLS_DIRECTORY/script-host-server.csr"
  SCRIPT_HOST_SERVER_EXT="$TLS_DIRECTORY/script-host-server.ext"
  SCRIPT_HOST_CLIENT_CERT="$TLS_DIRECTORY/script-host-client.pem"
  SCRIPT_HOST_CLIENT_KEY="$TLS_DIRECTORY/script-host-client.key"
  SCRIPT_HOST_CLIENT_CSR="$TLS_DIRECTORY/script-host-client.csr"
  SCRIPT_HOST_CLIENT_EXT="$TLS_DIRECTORY/script-host-client.ext"
  ORACLE_OBSERVER_RECEIPT="$ORACLE_OBSERVER_RECEIPT_DIRECTORY/observations.ndjson"
  CANDIDATE_OBSERVER_RECEIPT="$CANDIDATE_OBSERVER_RECEIPT_DIRECTORY/observations.ndjson"
  ORACLE_GOOGLE_CONFIG="$GOOGLE_PROVIDER_ROOT/oracle/configuration/configuration.json"
  ORACLE_GOOGLE_RECEIPT="$GOOGLE_PROVIDER_ROOT/oracle/receipts/observations.json"
  ORACLE_GOOGLE_DIAGNOSTIC="$GOOGLE_PROVIDER_ROOT/oracle/diagnostics/health.json"
  ORACLE_GOOGLE_PROVIDER_INPUT="$GOOGLE_PROVIDER_ROOT/oracle/provider-input.json"
  CANDIDATE_GOOGLE_CONFIG="$GOOGLE_PROVIDER_ROOT/candidate/configuration/configuration.json"
  CANDIDATE_GOOGLE_RECEIPT="$GOOGLE_PROVIDER_ROOT/candidate/receipts/observations.json"
  CANDIDATE_GOOGLE_DIAGNOSTIC="$GOOGLE_PROVIDER_ROOT/candidate/diagnostics/health.json"
  CANDIDATE_GOOGLE_PROVIDER_INPUT="$GOOGLE_PROVIDER_ROOT/candidate/provider-input.json"
  ORACLE_WECHAT_CONFIG="$WECHAT_PROVIDER_ROOT/oracle/configuration/configuration.json"
  ORACLE_WECHAT_RECEIPT="$WECHAT_PROVIDER_ROOT/oracle/receipts/observations.json"
  ORACLE_WECHAT_DIAGNOSTIC="$WECHAT_PROVIDER_ROOT/oracle/diagnostics/health.json"
  ORACLE_WECHAT_PROVIDER_INPUT="$WECHAT_PROVIDER_ROOT/oracle/provider-input.json"
  CANDIDATE_WECHAT_CONFIG="$WECHAT_PROVIDER_ROOT/candidate/configuration/configuration.json"
  CANDIDATE_WECHAT_RECEIPT="$WECHAT_PROVIDER_ROOT/candidate/receipts/observations.json"
  CANDIDATE_WECHAT_DIAGNOSTIC="$WECHAT_PROVIDER_ROOT/candidate/diagnostics/health.json"
  CANDIDATE_WECHAT_PROVIDER_INPUT="$WECHAT_PROVIDER_ROOT/candidate/provider-input.json"
  ORACLE_COMPLETION_INPUT="$COMPLETION_ROOT/runtime-common/oracle-descriptor.json"
  CANDIDATE_COMPLETION_INPUT="$COMPLETION_ROOT/runtime-common/candidate-descriptor.json"
  CANDIDATE_IDENTITY_CONFIG="$IDENTITY_TLS_ROOT/candidate-identity-transports.json"
  IDENTITY_CA="$IDENTITY_TLS_ROOT/identity-ca.pem"
  IDENTITY_CA_BUNDLE="$IDENTITY_TLS_ROOT/core-extra-ca-bundle.pem"
  IDENTITY_SERVER_CERT="$IDENTITY_TLS_ROOT/identity-server.pem"
  IDENTITY_SERVER_KEY="$IDENTITY_TLS_ROOT/identity-server.key"
  H5_CA="$H5_RUNTIME_ROOT/h5-loopback-ca.pem"
  H5_SERVER_CERT="$H5_RUNTIME_ROOT/h5-loopback-server.pem"
  H5_SERVER_KEY="$H5_RUNTIME_ROOT/h5-loopback-server.key"
  H5_SPKI="$H5_RUNTIME_ROOT/h5-loopback-server.spki"
  H5_CANDIDATE_CONFIG="$CONFIG_DIR/candidate-h5.conf"
  readonly ORACLE_ENV CANDIDATE_ENV ORACLE_COMPOSE CANDIDATE_COMPOSE ORACLE_DESCRIPTOR CANDIDATE_DESCRIPTOR
  readonly PRIMARY_CONFIG_FILE FOREIGN_CONFIG_FILE FIXTURE_SOCKET ORACLE_SMTP_SOCKET CANDIDATE_PASSWORD_SMTP_SOCKET ORACLE_STATE_DRIVER CANDIDATE_STATE_DRIVER
  readonly CANDIDATE_INVARIANT_DRIVER ASTER_ADMIN_BIN ORACLE_EVIDENCE DIFFERENTIAL_EVIDENCE INVARIANT_EVIDENCE
  readonly COMPLETION_ROOT IDENTITY_TLS_ROOT H5_RUNTIME_ROOT ORACLE_COMPLETION_INPUT CANDIDATE_COMPLETION_INPUT
  readonly CANDIDATE_IDENTITY_CONFIG IDENTITY_CA IDENTITY_CA_BUNDLE IDENTITY_SERVER_CERT IDENTITY_SERVER_KEY H5_CA H5_SERVER_CERT H5_SERVER_KEY H5_SPKI H5_CANDIDATE_CONFIG
  [[ ${#FIXTURE_SOCKET} -le 100 ]] || { failure_stage='fixture-socket-path'; fail; return 1; }
  [[ ${#ORACLE_SMTP_SOCKET} -le 100 ]] || { failure_stage='oracle-smtp-socket-path'; fail; return 1; }
  [[ ${#CANDIDATE_PASSWORD_SMTP_SOCKET} -le 100 ]] || { failure_stage='candidate-password-smtp-socket-path'; fail; return 1; }
  trap cleanup_trap EXIT
  bootstrap_playwright || { failure_stage='playwright-bootstrap'; fail; return 1; }
  assert_path_identity "$BROWSER_CACHE" "$BROWSER_CACHE_IDENTITY" \
    || { failure_stage='browser-cache-identity'; fail; return 1; }
  [[ -f "$FETCH_OBSERVER_SCRIPT" && ! -L "$FETCH_OBSERVER_SCRIPT" ]] || { failure_stage='fetch-observer-script'; fail; return 1; }
  generate_fetch_and_script_host_pki || { failure_stage='private-pki'; fail; return 1; }
  "$IDENTITY_PKI_SCRIPT" "$IDENTITY_TLS_ROOT" || { failure_stage='identity-fixture-pki'; fail; return 1; }
  /usr/bin/cat -- "$FETCH_OBSERVER_CA" "$IDENTITY_CA" >"$IDENTITY_CA_BUNDLE" \
    || { failure_stage='identity-fixture-ca-bundle'; fail; return 1; }
  /usr/bin/chmod 0444 "$IDENTITY_CA_BUNDLE"
  "$H5_PKI_SCRIPT" generate "$H5_RUNTIME_ROOT" >/dev/null || { failure_stage='h5-loopback-pki'; fail; return 1; }
  "$JQ_BIN" -cn '{schemaVersion:1,passwordCompromise:{peer:"172.30.241.56:443",caFile:"/run/aster/identity-fixture-ca.pem"},backchannel:{origin:"https://backchannel.aster.test:8443",peer:"172.30.241.55:8443",caFile:"/run/aster/identity-fixture-ca.pem"}}' >"$CANDIDATE_IDENTITY_CONFIG"
  /usr/bin/chmod 0400 "$CANDIDATE_IDENTITY_CONFIG"
  assert_private_runtime_material || { failure_stage='private-runtime-material'; fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$GOOGLE_RUNTIME_HELPER" prepare "$GOOGLE_PROVIDER_ROOT" \
    || { failure_stage='google-provider-private'; fail; return 1; }
  assert_google_provider_private_material absent empty \
    || { failure_stage='google-provider-private'; fail; return 1; }

  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$WECHAT_RUNTIME_HELPER" prepare "$WECHAT_PROVIDER_ROOT" \
    || { failure_stage='wechat-provider-private'; fail; return 1; }
  assert_wechat_provider_private_material absent empty \
    || { failure_stage='wechat-provider-private'; fail; return 1; }

  /usr/bin/mkdir -m 700 -- "$INVARIANT_HANDLE_ROOT" || { failure_stage='invariant-handle-root'; fail; return 1; }
  INVARIANT_HANDLE_ROOT_IDENTITY="$(capture_path_identity "$INVARIANT_HANDLE_ROOT")" || { failure_stage='invariant-handle-root'; fail; return 1; }
  assert_invariant_handle_root_owned "$INVARIANT_HANDLE_ROOT" || { failure_stage='invariant-handle-root'; fail; return 1; }
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  failure_stage='podman-api'
  [[ "$($CURL_BIN --silent --show-error --max-time 30 --output /dev/null --write-out '%{http_code}' --unix-socket "$ENGINE_SOCKET" http://localhost/libpod/_ping)" == 200 ]] || { fail; return 1; }
  PODMAN_API_VERSION="$("$CURL_BIN" --fail --silent --show-error --max-time 30 --unix-socket "$ENGINE_SOCKET" http://localhost/version | "$NODE_BIN" -e '
    let s=""; process.stdin.on("data", c => s += c).on("end", () => {
      const v=JSON.parse(s).Components?.find(c => c.Name === "Podman Engine")?.Details?.APIVersion;
      if (!/^\d+\.\d+\.\d+$/.test(v ?? "")) process.exit(1); process.stdout.write(v);
    });')" || { fail; return 1; }
  readonly PODMAN_API_VERSION
  docker_cli compose version >/dev/null 2>&1 || { failure_stage='compose-provider'; fail; return 1; }

  failure_stage='images'
  raw_oracle_image_id="$(docker_cli image inspect --format '{{.Id}}' "$ORACLE_IMAGE_PIN" 2>/dev/null || true)"
  ORACLE_IMAGE_ID="$(normalize_image_id "$raw_oracle_image_id")" || { fail; return 1; }
  [[ "$ORACLE_IMAGE_ID" == "$ORACLE_IMAGE_PIN" ]] || { fail; return 1; }
  PROVIDER_FIXTURE_IMAGE_ID="$(resolve_provider_fixture_image_id "$ORACLE_IMAGE_ID")" || { fail; return 1; }
  candidate_metadata="$(docker_cli image inspect --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "io.aster.source.tree"}}' "$ASTER_PHASE2_CANDIDATE_IMAGE" 2>/dev/null || true)"
  IFS='|' read -r raw_candidate_image_id candidate_source candidate_revision candidate_tree <<<"$candidate_metadata"
  CANDIDATE_IMAGE_ID="$(normalize_image_id "$raw_candidate_image_id")" || { fail; return 1; }
  [[ "$CANDIDATE_IMAGE_ID" == "$ASTER_PHASE2_CANDIDATE_IMAGE" && "$candidate_source" == "$EXPECTED_ASTER_SOURCE" && "$candidate_revision" == "$ASTER_HEAD" && "$candidate_tree" == "$ASTER_TREE" ]] || { fail; return 1; }
  for image_role in SUPERVISOR EXECUTOR; do
    image_variable="ASTER_PHASE2_SCRIPT_${image_role}_IMAGE"
    image_value="${!image_variable}"
    [[ "$image_value" =~ ^sha256:[0-9a-f]{64}$ ]] || { fail; return 1; }
    image_metadata="$(docker_cli image inspect --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "io.aster.source.tree"}}|{{index .Config.Labels "dev.aster.reference.revision"}}' "$image_value" 2>/dev/null || true)"
    normalized_image_id="$(validate_script_host_image_metadata "$image_value" "$image_metadata")" || { fail; return 1; }
    printf -v "SCRIPT_${image_role}_IMAGE_ID" '%s' "$normalized_image_id"
  done
  readonly ORACLE_IMAGE_ID PROVIDER_FIXTURE_IMAGE_ID CANDIDATE_IMAGE_ID SCRIPT_SUPERVISOR_IMAGE_ID SCRIPT_EXECUTOR_IMAGE_ID

  failure_stage='private-executables'
  /usr/bin/cp --reflink=never -- "$STATE_DRIVER_SOURCE" "$ORACLE_STATE_DRIVER"
  /usr/bin/cp --reflink=never -- "$STATE_DRIVER_SOURCE" "$CANDIDATE_STATE_DRIVER"
  /usr/bin/cp --reflink=never -- "$INVARIANT_DRIVER_SOURCE" "$CANDIDATE_INVARIANT_DRIVER"
  /usr/bin/chmod 0500 "$ORACLE_STATE_DRIVER" "$CANDIDATE_STATE_DRIVER" "$CANDIDATE_INVARIANT_DRIVER"
  EXTRACTION_CONTAINER_ID="$(docker_cli create --network none "$CANDIDATE_IMAGE_ID" unknown)"
  [[ "$EXTRACTION_CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || { fail; return 1; }
  docker_cli cp "$EXTRACTION_CONTAINER_ID:/usr/local/bin/aster-admin" "$ASTER_ADMIN_BIN" >/dev/null 2>&1 || { fail; return 1; }
  docker_cli rm --force --volumes "$EXTRACTION_CONTAINER_ID" >/dev/null 2>&1 || { fail; return 1; }
  EXTRACTION_CONTAINER_ID=''
  /usr/bin/chmod 0500 "$ASTER_ADMIN_BIN"
  [[ "$(/usr/bin/stat -c '%u|%a|%h|%F' -- "$ASTER_ADMIN_BIN")" == "$(/usr/bin/id -u)|500|1|regular file" ]] || { fail; return 1; }
  "$READELF_BIN" -l "$ASTER_ADMIN_BIN" | /usr/bin/grep -F -q '[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]' || { fail; return 1; }
  "$LDD_BIN" "$ASTER_ADMIN_BIN" 2>&1 | /usr/bin/grep -F -q 'not found' && { fail; return 1; }
  ORACLE_STATE_DRIVER_SHA256="$(sha256_file "$ORACLE_STATE_DRIVER")"
  CANDIDATE_STATE_DRIVER_SHA256="$(sha256_file "$CANDIDATE_STATE_DRIVER")"
  CANDIDATE_INVARIANT_DRIVER_SHA256="$(sha256_file "$CANDIDATE_INVARIANT_DRIVER")"
  ASTER_ADMIN_SHA256="$(sha256_file "$ASTER_ADMIN_BIN")"
  readonly ORACLE_STATE_DRIVER_SHA256 CANDIDATE_STATE_DRIVER_SHA256 CANDIDATE_INVARIANT_DRIVER_SHA256 ASTER_ADMIN_SHA256

  primary_deployment_id="$(random_uuid)"
  foreign_deployment_id="$(random_uuid)"
  primary_sentinel="$(random_hex 32)"
  foreign_sentinel="$(random_hex 32)"
  [[ "$primary_deployment_id" != "$foreign_deployment_id" && "$primary_sentinel" != "$foreign_sentinel" ]] || { failure_stage='candidate-config'; fail; return 1; }
  printf 'deployment_id=%s\ndatabase_sentinel=%s\n' "$primary_deployment_id" "$primary_sentinel" >"$PRIMARY_CONFIG_FILE"
  printf 'deployment_id=%s\ndatabase_sentinel=%s\n' "$foreign_deployment_id" "$foreign_sentinel" >"$FOREIGN_CONFIG_FILE"
  /usr/bin/chmod 0400 "$PRIMARY_CONFIG_FILE" "$FOREIGN_CONFIG_FILE"
  /usr/bin/cp -- "$PRIMARY_CONFIG_FILE" "$H5_CANDIDATE_CONFIG"
  /usr/bin/chmod 0400 "$H5_CANDIDATE_CONFIG"

  cat >"$ORACLE_ENV" <<EOF
ASTER_PHASE1_POSTGRES_IMAGE=$POSTGRES_IMAGE
ASTER_PHASE1_REDIS_IMAGE=$REDIS_IMAGE
ASTER_PHASE1_ORACLE_IMAGE=$ORACLE_IMAGE_ID
ASTER_PHASE1_RUNTIME_UID=$(/usr/bin/id -u)
ASTER_PHASE1_RUNTIME_GID=$(/usr/bin/id -g)
ASTER_PHASE2_FETCH_OBSERVER_SCRIPT=$FETCH_OBSERVER_SCRIPT
ASTER_PHASE2_ORACLE_OBSERVER_CERT=$OBSERVER_SERVER_CERT
ASTER_PHASE2_ORACLE_OBSERVER_KEY=$OBSERVER_SERVER_KEY
ASTER_PHASE2_ORACLE_OBSERVER_CA=$FETCH_OBSERVER_CA
ASTER_PHASE2_ORACLE_OBSERVER_RECEIPT=$ORACLE_OBSERVER_RECEIPT
ASTER_PHASE2_ORACLE_OBSERVER_RECEIPT_DIRECTORY=$ORACLE_OBSERVER_RECEIPT_DIRECTORY
ASTER_PHASE2_SCRIPT_SUPERVISOR_IMAGE=$SCRIPT_SUPERVISOR_IMAGE_ID
ASTER_PHASE1_FIXTURE_DIRECTORY=$FIXTURE_DIRECTORY
ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_ORACLE_PRIMARY_SECRET_VAULT_KEK=$(random_hex 32)
ASTER_PHASE1_ORACLE_PRIMARY_STATUS_API_KEY=$(random_hex 32)
ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_ORACLE_FOREIGN_SECRET_VAULT_KEK=$(random_hex 32)
ASTER_PHASE1_ORACLE_FOREIGN_STATUS_API_KEY=$(random_hex 32)
EOF
  cat >"$CANDIDATE_ENV" <<EOF
ASTER_PHASE1_POSTGRES_IMAGE=$POSTGRES_IMAGE
ASTER_PHASE1_CANDIDATE_IMAGE=$CANDIDATE_IMAGE_ID
ASTER_PHASE1_ORACLE_IMAGE=$ORACLE_IMAGE_ID
ASTER_PHASE2_SCRIPT_SUPERVISOR_IMAGE=$SCRIPT_SUPERVISOR_IMAGE_ID
ASTER_PHASE2_SCRIPT_EXECUTOR_IMAGE=$SCRIPT_EXECUTOR_IMAGE_ID
ASTER_PHASE2_FETCH_OBSERVER_SCRIPT=$FETCH_OBSERVER_SCRIPT
ASTER_PHASE2_CANDIDATE_OBSERVER_CERT=$OBSERVER_SERVER_CERT
ASTER_PHASE2_CANDIDATE_OBSERVER_KEY=$OBSERVER_SERVER_KEY
ASTER_PHASE2_CANDIDATE_OBSERVER_CA=$FETCH_OBSERVER_CA
ASTER_PHASE2_CANDIDATE_OBSERVER_RECEIPT=$CANDIDATE_OBSERVER_RECEIPT
ASTER_PHASE2_CANDIDATE_OBSERVER_RECEIPT_DIRECTORY=$CANDIDATE_OBSERVER_RECEIPT_DIRECTORY
ASTER_PHASE2_SCRIPT_HOST_CA=$SCRIPT_HOST_CA
ASTER_PHASE2_SCRIPT_HOST_SERVER_CERT=$SCRIPT_HOST_SERVER_CERT
ASTER_PHASE2_SCRIPT_HOST_SERVER_KEY=$SCRIPT_HOST_SERVER_KEY
ASTER_PHASE2_SCRIPT_HOST_STATE=$SCRIPT_HOST_STATE
ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_RUNTIME_UID=$(/usr/bin/id -u)
ASTER_PHASE1_RUNTIME_GID=$(/usr/bin/id -g)
ASTER_PHASE1_PRIMARY_CONFIG_FILE=$PRIMARY_CONFIG_FILE
ASTER_PHASE1_FOREIGN_CONFIG_FILE=$FOREIGN_CONFIG_FILE
ASTER_PHASE1_PRIMARY_KEYRING_DIRECTORY=$PRIMARY_KEYRING_DIRECTORY
ASTER_PHASE1_FOREIGN_KEYRING_DIRECTORY=$FOREIGN_KEYRING_DIRECTORY
ASTER_PHASE1_FIXTURE_DIRECTORY=$FIXTURE_DIRECTORY
ASTER_PHASE1_FIXTURE_SOCKET=$FIXTURE_SOCKET
EOF
  /usr/bin/chmod 0600 "$ORACLE_ENV" "$CANDIDATE_ENV"

  failure_stage='compose-config'
  generated="$RUN_DIR/podman-differential-compose.json"
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" "$NODE_BIN" "$PODMAN_GENERATOR" \
    "$SOURCE_COMPOSE" "$RUN_DIR" "$generated" >/dev/null 2>&1 || { fail; return 1; }
  "$NODE_BIN" --input-type=module - "$generated" "$ORACLE_COMPOSE" "$CANDIDATE_COMPOSE" \
    "$SCRIPT_HOST_CA" "$SCRIPT_HOST_CLIENT_CERT" "$SCRIPT_HOST_CLIENT_KEY" "$FETCH_OBSERVER_CA" \
    "$CANDIDATE_PROJECT_NAME" <<'NODE'
import { open, readFile } from 'node:fs/promises';
const [source, oracleOutput, candidateOutput, scriptCa, scriptCert, scriptKey, observerCa,
  candidateProject = 'fixture-candidate-project'] = process.argv.slice(2);
if (!/^aster-phase2-client-credentials-[0-9a-f]{16}$/.test(candidateProject) &&
    candidateProject !== 'fixture-candidate-project') {
  throw new Error('candidate project name contract');
}
const document = JSON.parse(await readFile(source, 'utf8'));
const phase2Services = document['x-phase2-services'];
document.services['oracle-primary-smtp'] = structuredClone(document.services['candidate-primary-smtp']);
document.services['oracle-primary-smtp'].environment.ASTER_SMTP_BIND = '0.0.0.0';
document.services['oracle-primary-smtp'].environment.ASTER_SMTP_CONTROL_SOCKET =
  '/run/aster-smtp/oracle-smtp.sock';
document.services['oracle-primary-smtp'].volumes = [
  '${ASTER_PHASE1_FIXTURE_DIRECTORY}:/run/aster-smtp:rw',
];
delete document.services['oracle-primary-smtp'].network_mode;
document.services['oracle-primary-smtp'].networks = {
  'oracle-primary': { ipv4_address: '172.30.231.49' },
};
const select = (services, networks, volumes) => {
  const output = { services: {}, networks: {}, volumes: {} };
  for (const name of services) {
    const service = document.services?.[name] ?? phase2Services?.[name];
    if (!service) throw new Error('service closure');
    output.services[name] = structuredClone(service);
  }
  for (const name of networks) {
    if (!document.networks?.[name]) throw new Error('network closure');
    output.networks[name] = document.networks[name];
  }
  for (const name of volumes) {
    if (!document.volumes?.[name]) throw new Error('volume closure');
    output.volumes[name] = document.volumes[name];
  }
  return output;
};
const oracle = select(
  ['oracle-primary-postgres','oracle-primary-redis','oracle-primary-core','oracle-fetch-observer','oracle-primary-smtp','oracle-foreign-postgres','oracle-foreign-redis','oracle-foreign-core'],
  ['oracle-primary','oracle-foreign'],
  ['oracle-primary-postgres','oracle-primary-redis','oracle-foreign-postgres','oracle-foreign-redis'],
);
for (const name of ['oracle-primary-core','oracle-foreign-core']) {
  oracle.services[name].environment.DEV_FEATURES_ENABLED = 'true';
}
const candidate = select(
  ['candidate-primary-postgres','candidate-primary-init','candidate-primary-core','candidate-primary-smtp','candidate-fetch-observer','candidate-script-supervisor','candidate-script-executor','candidate-foreign-postgres','candidate-foreign-init','candidate-foreign-core','candidate-fixture-coordinator'],
  ['candidate-primary','candidate-foreign'],
  ['candidate-primary-postgres','candidate-foreign-postgres','candidate-primary-keyring','candidate-foreign-keyring'],
);
for (const [observer, source] of [
  [oracle.services['oracle-fetch-observer'], '${ASTER_PHASE2_ORACLE_OBSERVER_RECEIPT_DIRECTORY}'],
  [candidate.services['candidate-fetch-observer'], '${ASTER_PHASE2_CANDIDATE_OBSERVER_RECEIPT_DIRECTORY}'],
]) {
  observer.volumes = observer.volumes.map((mount) =>
    mount.endsWith('/run/aster-fetch-observer/receipts/observations.ndjson:rw')
      ? `${source}:/run/aster-fetch-observer/receipts:rw`
      : mount
  );
}
oracle.services['oracle-fetch-observer'].environment.ASTER_FETCH_OBSERVER_RECEIPT_FILE =
  '/run/aster-fetch-observer/receipts/observations.ndjson';
candidate.services['candidate-fetch-observer'].environment.ASTER_FETCH_OBSERVER_RECEIPT_FILE =
  '/run/aster-fetch-observer/receipts/observations.ndjson';
const candidateCoreContainer = `${candidateProject}-candidate-primary-core`;
candidate.services['candidate-primary-core'].container_name = candidateCoreContainer;
candidate.services['candidate-primary-smtp'].userns_mode = `container:${candidateCoreContainer}`;
candidate.services['candidate-primary-smtp'].environment.ASTER_SMTP_CONTROL_SOCKET =
  '/run/aster-smtp/verification-smtp.sock';
candidate.services['candidate-primary-smtp'].volumes = [
  '${ASTER_PHASE1_FIXTURE_DIRECTORY}:/run/aster-smtp:rw',
];
candidate.services['candidate-fetch-observer'].userns_mode = 'host';
candidate.services['candidate-fetch-observer'].user = '0:0';
candidate.services['candidate-fetch-observer'].tmpfs = [
  '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
  '/run/aster-fetch-observer:rw,noexec,nosuid,nodev,size=1m,mode=0755',
];
candidate.services['candidate-script-supervisor'].userns_mode = 'keep-id';
candidate.services['candidate-script-supervisor'].tmpfs = ['/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777'];
delete candidate.services['candidate-script-executor'].userns_mode;
candidate.services['candidate-script-executor'].tmpfs =
  ['/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777'];
oracle.services['oracle-fetch-observer'].userns_mode = 'host';
oracle.services['oracle-fetch-observer'].user = '0:0';
oracle.services['oracle-fetch-observer'].tmpfs = [
  '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
  '/run/aster-fetch-observer:rw,noexec,nosuid,nodev,size=1m,mode=0755',
];
oracle.services['oracle-primary-smtp'].userns_mode = 'keep-id';
const healthcheckIntervals = {
  'oracle-primary-postgres': '3s', 'oracle-primary-redis': '3s', 'oracle-primary-core': '3s',
  'oracle-fetch-observer': '1s', 'oracle-primary-smtp': '1s', 'oracle-foreign-postgres': '3s',
  'oracle-foreign-redis': '3s', 'oracle-foreign-core': '3s',
  'candidate-primary-postgres': '2s', 'candidate-primary-core': '2s',
  'candidate-primary-smtp': '1s', 'candidate-password-smtp': '1s',
  'candidate-fetch-observer': '1s', 'candidate-script-supervisor': '1s',
  'candidate-script-executor': '1s', 'candidate-foreign-postgres': '2s',
  'candidate-foreign-core': '2s', 'candidate-fixture-coordinator': '1s',
};
for (const output of [oracle, candidate]) {
  for (const [name, service] of Object.entries(output.services)) {
    const expectedInterval = healthcheckIntervals[name];
    if (expectedInterval === undefined) {
      if (service.healthcheck !== undefined) throw new Error('unexpected healthcheck');
      continue;
    }
    const healthcheck = service.healthcheck;
    if (!healthcheck || healthcheck.interval !== expectedInterval ||
        !Array.isArray(healthcheck.test) || healthcheck.test.length < 2 ||
        typeof healthcheck.timeout !== 'string' || !/^[1-9][0-9]*s$/u.test(healthcheck.timeout) ||
        !Number.isInteger(healthcheck.retries) || healthcheck.retries < 1) {
      throw new Error('healthcheck contract');
    }
    healthcheck.interval = '0s';
  }
}
candidate.services['candidate-primary-core'].environment = {
  ...candidate.services['candidate-primary-core'].environment,
  ASTER_SCRIPT_HOST_ADDRESS: 'candidate-script-supervisor:50051',
  ASTER_SCRIPT_HOST_DNS_NAME: 'script-host.aster.test',
  ASTER_SCRIPT_HOST_CA_FILE: '/run/aster/script-host-ca.pem',
  ASTER_SCRIPT_HOST_CERT_FILE: '/run/aster/script-host-client.pem',
  ASTER_SCRIPT_HOST_KEY_FILE: '/run/aster/script-host-client.key',
  ASTER_SCRIPT_FETCH_POLICY_FILE: '/usr/local/share/aster/compatibility/phase-2-script-fetch-policy.json',
  ASTER_DEVELOPMENT_FEATURES_ENABLED: 'true',
  SSL_CERT_FILE: '/run/aster/fetch-observer-ca.pem',
};
candidate.services['candidate-primary-core'].volumes.push(
  `${scriptCa}:/run/aster/script-host-ca.pem:ro`,
  `${scriptCert}:/run/aster/script-host-client.pem:ro`,
  `${scriptKey}:/run/aster/script-host-client.key:ro`,
  `${observerCa}:/run/aster/fetch-observer-ca.pem:ro`,
);
oracle.services['oracle-primary-core'].environment.NODE_EXTRA_CA_CERTS = '/run/aster/fetch-observer-ca.pem';
oracle.services['oracle-primary-core'].volumes = [
  ...(oracle.services['oracle-primary-core'].volumes ?? []),
  `${observerCa}:/run/aster/fetch-observer-ca.pem:ro`,
];
for (const [file, value] of [[oracleOutput, oracle], [candidateOutput, candidate]]) {
  const handle = await open(file, 'wx', 0o600);
  await handle.writeFile(JSON.stringify(value));
  await handle.sync();
  await handle.close();
}
NODE
  /usr/bin/rm -f -- "$generated"
  /usr/bin/chmod 0600 "$ORACLE_COMPOSE" "$CANDIDATE_COMPOSE"
  "$NODE_BIN" --input-type=module - "$GOOGLE_TOPOLOGY_MODULE" \
    "$ORACLE_COMPOSE" "$CANDIDATE_COMPOSE" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$GOOGLE_PROVIDER_SCRIPT" "$FETCH_OBSERVER_CA" "$OBSERVER_SERVER_CERT" \
    "$OBSERVER_SERVER_KEY" "$ORACLE_GOOGLE_CONFIG" "$ORACLE_GOOGLE_RECEIPT" \
    "$CANDIDATE_GOOGLE_CONFIG" "$CANDIDATE_GOOGLE_RECEIPT" <<'GOOGLE_TOPOLOGY' \
    || { failure_stage='google-provider-topology'; fail; return 1; }
import { open, readFile, rename } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const [modulePath, oraclePath, candidatePath, image, providerScript, ca, certificate, privateKey,
  oracleConfiguration, oracleReceipt, candidateConfiguration, candidateReceipt] =
  process.argv.slice(2);
const { bindGoogleProviderTopology } = await import(pathToFileURL(modulePath).href);
const [oracle, candidate] = await Promise.all([
  readFile(oraclePath, 'utf8').then((value) => JSON.parse(value)),
  readFile(candidatePath, 'utf8').then((value) => JSON.parse(value)),
]);
for (const [document, core, address] of [
  [oracle, 'oracle-primary-core', '172.30.231.52'],
  [candidate, 'candidate-primary-core', '172.30.241.52'],
]) {
  const current = document.services?.[core]?.extra_hosts ?? [];
  if (
    !Array.isArray(current) ||
    current.some(
      (value) =>
        typeof value !== 'string' ||
        /^(?:oauth2|openidconnect)\.googleapis\.com:/u.test(value)
    )
  ) {
    throw new TypeError('Invalid Google provider host mapping');
  }
  document.services[core].extra_hosts = [
    ...current,
    `oauth2.googleapis.com:${address}`,
    `openidconnect.googleapis.com:${address}`,
  ];
}
const bound = bindGoogleProviderTopology(oracle, candidate, {
  fixtureImage: image,
  runtimeUid: process.getuid(),
  runtimeGid: process.getgid(),
  providerScript,
  caFile: ca,
  certificateFile: certificate,
  privateKeyFile: privateKey,
  oracleConfigurationFile: oracleConfiguration,
  oracleReceiptFile: oracleReceipt,
  candidateConfigurationFile: candidateConfiguration,
  candidateReceiptFile: candidateReceipt,
});
for (const [destination, value] of [
  [oraclePath, bound.oracle],
  [candidatePath, bound.candidate],
]) {
  const temporary = `${destination}.google-provider`;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(JSON.stringify(value));
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, destination);
}
GOOGLE_TOPOLOGY
  "$NODE_BIN" --input-type=module - "$WECHAT_TOPOLOGY_MODULE" \
    "$ORACLE_COMPOSE" "$CANDIDATE_COMPOSE" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$WECHAT_PROVIDER_SCRIPT" "$FETCH_OBSERVER_CA" "$OBSERVER_SERVER_CERT" \
    "$OBSERVER_SERVER_KEY" "$ORACLE_WECHAT_CONFIG" "$ORACLE_WECHAT_RECEIPT" \
    "$CANDIDATE_WECHAT_CONFIG" "$CANDIDATE_WECHAT_RECEIPT" <<'WECHAT_TOPOLOGY' \
    || { failure_stage='wechat-provider-topology'; fail; return 1; }
import { open, readFile, rename } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const [modulePath, oraclePath, candidatePath, image, providerScript, ca, certificate, privateKey,
  oracleConfiguration, oracleReceipt, candidateConfiguration, candidateReceipt] =
  process.argv.slice(2);
const { bindWechatProviderTopology } = await import(pathToFileURL(modulePath).href);
const [oracle, candidate] = await Promise.all([
  readFile(oraclePath, 'utf8').then((value) => JSON.parse(value)),
  readFile(candidatePath, 'utf8').then((value) => JSON.parse(value)),
]);
for (const [document, core, address] of [
  [oracle, 'oracle-primary-core', '172.30.231.53'],
  [candidate, 'candidate-primary-core', '172.30.241.53'],
]) {
  const current = document.services?.[core]?.extra_hosts ?? [];
  if (
    !Array.isArray(current) ||
    current.some(
      (value) =>
        typeof value !== 'string' ||
        /^api\.weixin\.qq\.com:/u.test(value)
    )
  ) {
    throw new TypeError('Invalid Wechat provider host mapping');
  }
  document.services[core].extra_hosts = [
    ...current,
    `api.weixin.qq.com:${address}`,
  ];
}
const bound = bindWechatProviderTopology(oracle, candidate, {
  fixtureImage: image,
  runtimeUid: process.getuid(),
  runtimeGid: process.getgid(),
  providerScript,
  caFile: ca,
  certificateFile: certificate,
  privateKeyFile: privateKey,
  oracleConfigurationFile: oracleConfiguration,
  oracleReceiptFile: oracleReceipt,
  candidateConfigurationFile: candidateConfiguration,
  candidateReceiptFile: candidateReceipt,
});
for (const [destination, value] of [
  [oraclePath, bound.oracle],
  [candidatePath, bound.candidate],
]) {
  const temporary = `${destination}.wechat-provider`;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(JSON.stringify(value));
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, destination);
}
WECHAT_TOPOLOGY
  "$NODE_BIN" --input-type=module - "$SMS_RUNTIME_HELPER" "$SMS_TOPOLOGY_MODULE" \
    "$SMS_PROVIDER_ROOT" "$ORACLE_COMPOSE" "$CANDIDATE_COMPOSE" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$SMS_PROVIDER_SCRIPT" "$FETCH_OBSERVER_CA" "$OBSERVER_SERVER_CERT" \
    "$OBSERVER_SERVER_KEY" <<'SMS_TOPOLOGY' \
    || { failure_stage='sms-provider-topology'; fail; return 1; }
import { open, readFile, rename } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const [runtimeModule, topologyModule, root, oraclePath, candidatePath, fixtureImage,
  providerScript, caFile, certificateFile, privateKeyFile] = process.argv.slice(2);
const { createSmsProviderRuntime } = await import(pathToFileURL(runtimeModule).href);
const { bindSmsProviderTopology } = await import(pathToFileURL(topologyModule).href);
const roles = await createSmsProviderRuntime(root);
const [oracle, candidate] = await Promise.all([oraclePath, candidatePath].map(async (file) =>
  JSON.parse(await readFile(file, 'utf8'))));
const bound = bindSmsProviderTopology(oracle, candidate, { fixtureImage, providerScript,
  caFile, certificateFile, privateKeyFile, runtimeUid: process.getuid(), runtimeGid: process.getgid(),
  oracleConfigurationFile: roles.oracle.configurationFile,
  oracleReceiptFile: roles.oracle.receiptFile, oracleControlDirectory: roles.oracle.controlDirectory,
  candidateConfigurationFile: roles.candidate.configurationFile,
  candidateReceiptFile: roles.candidate.receiptFile, candidateControlDirectory: roles.candidate.controlDirectory });
for (const [destination, value] of [[oraclePath, bound.oracle], [candidatePath, bound.candidate]]) {
  const temporary = `${destination}.sms-provider`;
  const handle = await open(temporary, 'wx', 0o600);
  try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); }
  finally { await handle.close(); }
  await rename(temporary, destination);
}
SMS_TOPOLOGY
  failure_stage='completion-runtime-descriptors'
  "$ENV_BIN" -i PATH="$(/usr/bin/dirname -- "$NODE_BIN"):/usr/bin:/bin" HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$COMPLETION_DESCRIPTOR_GENERATOR" "$COMPLETION_ROOT" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$ORACLE_PROJECT_NAME" "$CANDIDATE_PROJECT_NAME" "$ORACLE_GOOGLE_PROVIDER_INPUT" \
    "$CANDIDATE_GOOGLE_PROVIDER_INPUT" "$ORACLE_WECHAT_PROVIDER_INPUT" \
    "$CANDIDATE_WECHAT_PROVIDER_INPUT" "$SMS_PROVIDER_ROOT" "$FIXTURE_DIRECTORY" || { fail; return 1; }
  "$NODE_BIN" --input-type=module - "$ORACLE_COMPLETION_INPUT" "$CANDIDATE_COMPLETION_INPUT" \
    "$ORACLE_SMTP_SOCKET" "$CANDIDATE_PASSWORD_SMTP_SOCKET" <<'PASSWORD_SOCKET_BINDING' \
    || { failure_stage='completion-password-socket-binding'; fail; return 1; }
import { readFile } from 'node:fs/promises';
const inputs = process.argv.slice(2);
if (inputs.length !== 4) throw new TypeError('Invalid Common206 password socket binding');
for (const [descriptorFile, expectedSocket] of [[inputs[0], inputs[2]], [inputs[1], inputs[3]]]) {
  const descriptor = JSON.parse(await readFile(descriptorFile, 'utf8'));
  if (descriptor?.password?.smtpSocket !== expectedSocket) {
    throw new TypeError('Invalid Common206 password socket binding');
  }
}
PASSWORD_SOCKET_BINDING
  "$NODE_BIN" --input-type=module - "$ORACLE_COMPOSE" "$CANDIDATE_COMPOSE" \
    "$ORACLE_COMPLETION_INPUT" "$CANDIDATE_COMPLETION_INPUT" "$OWNED_ATTEMPT_TOPOLOGY" \
    "$H5_WECHAT_TOPOLOGY" "$H5_CORE_TOPOLOGY" "$PASSWORD_CORE_TOPOLOGY" "$MULTICHANNEL_TOPOLOGY" "$CANDIDATE_IDENTITY_TOPOLOGY" \
    "$PWNED_PROVIDER_SCRIPT" "$BACKCHANNEL_RECEIVER_SCRIPT" "$WECHAT_PROVIDER_SCRIPT" \
    "$MULTICHANNEL_PROVIDER_SCRIPT" "$IDENTITY_CA_BUNDLE" "$IDENTITY_CA" "$IDENTITY_SERVER_CERT" \
    "$IDENTITY_SERVER_KEY" "$CANDIDATE_IDENTITY_CONFIG" "$H5_CANDIDATE_CONFIG" <<'COMPLETION_TOPOLOGY' \
    || { failure_stage='completion-topology'; fail; return 1; }
import { open, readFile, rename } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const [oraclePath,candidatePath,oracleDescriptorPath,candidateDescriptorPath,attemptModule,h5Module,h5CoreModule,passwordCoreModule,
 multichannelModule,candidateIdentityModule,pwnedScript,backchannelScript,legacyWechatScript,
 multichannelScript,coreCaBundleFile,identityCaFile,certificateFile,privateKeyFile,candidateIdentityFile,h5CandidateConfig]=process.argv.slice(2);
const [{extendOwnedAttemptServices},{extendH5WechatTopology},{extendH5CoreTopology},{extendPasswordCoreTopology},{extendWechatMultichannelTopology},
 {applyCandidateIdentityConfig}]=await Promise.all([attemptModule,h5Module,h5CoreModule,passwordCoreModule,multichannelModule,candidateIdentityModule]
 .map(async value=>import(pathToFileURL(value).href)));
for(const [role,composePath,descriptorPath] of [['oracle',oraclePath,oracleDescriptorPath],['candidate',candidatePath,candidateDescriptorPath]]){
 const descriptor=JSON.parse(await readFile(descriptorPath,'utf8'));
 let document=JSON.parse(await readFile(composePath,'utf8'));
 document=await extendOwnedAttemptServices(document,{backchannelScript,coreCaBundleFile,certificateFile,
   descriptorFile:descriptorPath,privateKeyFile,pwnedScript});
 document=extendH5WechatTopology(document,{certificateFile,descriptor:descriptor.h5Wechat,
   privateKeyFile,role,script:legacyWechatScript});
 if(role==='candidate')document=applyCandidateIdentityConfig(document,{configurationFile:candidateIdentityFile,caFile:identityCaFile});
 document=extendH5CoreTopology(document,{candidateConfigFile:h5CandidateConfig,
   ...(role==='candidate'&&{candidateContainerName:`${descriptor.h5Wechat.project}-candidate-h5-core`}),role});
 document=extendPasswordCoreTopology(document,{role});
 document=extendWechatMultichannelTopology(document,{certificateFile,
   configurationFile:descriptor.wechat.configFile,fixtureImage:descriptor.wechat.image,
   privateKeyFile,receiptFile:descriptor.wechat.receiptFile,role,script:multichannelScript});
 const temporary=`${composePath}.completion`;
 const handle=await open(temporary,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(document));await handle.sync();}finally{await handle.close();}
 await rename(temporary,composePath);
}
COMPLETION_TOPOLOGY
  compose_oracle config --quiet >/dev/null 2>&1 || { fail; return 1; }
  compose_candidate config --quiet >/dev/null 2>&1 || { fail; return 1; }

  for port in "${PORTS[@]}"; do
    port_is_released "$port" || { failure_stage="port-${port}"; fail; return 1; }
  done

  ORACLE_PROJECT_STARTED=1
  start_compose_stage oracle dependencies oracle-primary-postgres oracle-primary-redis oracle-foreign-postgres oracle-foreign-redis || { fail; return 1; }
  start_compose_stage oracle observer oracle-fetch-observer || { fail; return 1; }
  start_compose_stage oracle core oracle-primary-core oracle-foreign-core || { fail; return 1; }
  start_compose_stage oracle h5-core oracle-h5-core || { fail; return 1; }
  start_compose_stage oracle password-core oracle-password-core || { fail; return 1; }
  start_compose_stage oracle smtp oracle-primary-smtp || { fail; return 1; }
  CANDIDATE_PROJECT_STARTED=1
  start_compose_stage candidate postgres candidate-primary-postgres candidate-foreign-postgres || { fail; return 1; }
  start_compose_stage candidate init candidate-primary-init candidate-foreign-init || { fail; return 1; }
  start_compose_stage candidate observer candidate-fetch-observer || { fail; return 1; }
  start_compose_stage candidate script-host candidate-script-supervisor candidate-script-executor || { fail; return 1; }
  wait_for_script_host_serving || { failure_stage='script-host-readiness'; fail; return 1; }
  start_compose_stage candidate core candidate-primary-core candidate-foreign-core || { fail; return 1; }
  start_compose_stage candidate h5-core candidate-h5-core || { fail; return 1; }
  start_compose_stage candidate smtp candidate-primary-smtp candidate-password-smtp || { fail; return 1; }
  start_compose_stage candidate fixture candidate-fixture-coordinator || { fail; return 1; }

  failure_stage='google-provider-create'
  compose_oracle create oracle-google-provider >/dev/null || { fail; return 1; }
  compose_candidate create candidate-google-provider >/dev/null || { fail; return 1; }
  ORACLE_GOOGLE_PROVIDER_ID="$(compose_oracle ps --all -q oracle-google-provider)"
  CANDIDATE_GOOGLE_PROVIDER_ID="$(compose_candidate ps --all -q candidate-google-provider)"
  ORACLE_GOOGLE_PROVIDER_ID="$(docker_cli inspect --format '{{.Id}}' "$ORACLE_GOOGLE_PROVIDER_ID")"
  CANDIDATE_GOOGLE_PROVIDER_ID="$(docker_cli inspect --format '{{.Id}}' "$CANDIDATE_GOOGLE_PROVIDER_ID")"
  [[ "$ORACLE_GOOGLE_PROVIDER_ID" =~ ^[0-9a-f]{64}$ \
    && "$CANDIDATE_GOOGLE_PROVIDER_ID" =~ ^[0-9a-f]{64}$ \
    && "$ORACLE_GOOGLE_PROVIDER_ID" != "$CANDIDATE_GOOGLE_PROVIDER_ID" ]] \
    || { fail; return 1; }
  ORACLE_CONTAINER_IDS+=("$ORACLE_GOOGLE_PROVIDER_ID")
  CANDIDATE_CONTAINER_IDS+=("$CANDIDATE_GOOGLE_PROVIDER_ID")
  ORACLE_GOOGLE_PROVIDER_NAME="$(docker_cli inspect --format '{{.Name}}' \
    "$ORACLE_GOOGLE_PROVIDER_ID")"
  CANDIDATE_GOOGLE_PROVIDER_NAME="$(docker_cli inspect --format '{{.Name}}' \
    "$CANDIDATE_GOOGLE_PROVIDER_ID")"
  ORACLE_GOOGLE_PROVIDER_NAME="${ORACLE_GOOGLE_PROVIDER_NAME#/}"
  CANDIDATE_GOOGLE_PROVIDER_NAME="${CANDIDATE_GOOGLE_PROVIDER_NAME#/}"
  [[ "$ORACLE_GOOGLE_PROVIDER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ \
    && "$CANDIDATE_GOOGLE_PROVIDER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] \
    || { fail; return 1; }
  assert_google_provider_state oracle oracle-google-provider created false 172.30.231.52 \
    || { fail; return 1; }
  assert_google_provider_state candidate candidate-google-provider created false 172.30.241.52 \
    || { fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$GOOGLE_RUNTIME_HELPER" write "$GOOGLE_PROVIDER_ROOT" \
    "$ORACLE_GOOGLE_PROVIDER_NAME" "$ORACLE_PROJECT_NAME" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$CANDIDATE_GOOGLE_PROVIDER_NAME" "$CANDIDATE_PROJECT_NAME" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$PRIVATE_HOME" "$PODMAN_API_VERSION" \
    oracle-google-provider candidate-google-provider \
    || { failure_stage='google-provider-input'; fail; return 1; }
  assert_google_provider_private_material present empty \
    || { failure_stage='google-provider-input'; fail; return 1; }
  ORACLE_GOOGLE_PROVIDER_INPUT_IDENTITY="$(artifact_identity "$ORACLE_GOOGLE_PROVIDER_INPUT")"
  CANDIDATE_GOOGLE_PROVIDER_INPUT_IDENTITY="$(artifact_identity \
    "$CANDIDATE_GOOGLE_PROVIDER_INPUT")"
  readonly ORACLE_GOOGLE_PROVIDER_INPUT_IDENTITY CANDIDATE_GOOGLE_PROVIDER_INPUT_IDENTITY

  failure_stage='wechat-provider-create'
  compose_oracle create oracle-wechat-provider >/dev/null || { fail; return 1; }
  compose_candidate create candidate-wechat-provider >/dev/null || { fail; return 1; }
  ORACLE_WECHAT_PROVIDER_ID="$(compose_oracle ps --all -q oracle-wechat-provider)"
  CANDIDATE_WECHAT_PROVIDER_ID="$(compose_candidate ps --all -q candidate-wechat-provider)"
  ORACLE_WECHAT_PROVIDER_ID="$(docker_cli inspect --format '{{.Id}}' "$ORACLE_WECHAT_PROVIDER_ID")"
  CANDIDATE_WECHAT_PROVIDER_ID="$(docker_cli inspect --format '{{.Id}}' "$CANDIDATE_WECHAT_PROVIDER_ID")"
  [[ "$ORACLE_WECHAT_PROVIDER_ID" =~ ^[0-9a-f]{64}$ \
    && "$CANDIDATE_WECHAT_PROVIDER_ID" =~ ^[0-9a-f]{64}$ \
    && "$ORACLE_WECHAT_PROVIDER_ID" != "$CANDIDATE_WECHAT_PROVIDER_ID" ]] \
    || { fail; return 1; }
  ORACLE_CONTAINER_IDS+=("$ORACLE_WECHAT_PROVIDER_ID")
  CANDIDATE_CONTAINER_IDS+=("$CANDIDATE_WECHAT_PROVIDER_ID")
  ORACLE_WECHAT_PROVIDER_NAME="$(docker_cli inspect --format '{{.Name}}' \
    "$ORACLE_WECHAT_PROVIDER_ID")"
  CANDIDATE_WECHAT_PROVIDER_NAME="$(docker_cli inspect --format '{{.Name}}' \
    "$CANDIDATE_WECHAT_PROVIDER_ID")"
  ORACLE_WECHAT_PROVIDER_NAME="${ORACLE_WECHAT_PROVIDER_NAME#/}"
  CANDIDATE_WECHAT_PROVIDER_NAME="${CANDIDATE_WECHAT_PROVIDER_NAME#/}"
  [[ "$ORACLE_WECHAT_PROVIDER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ \
    && "$CANDIDATE_WECHAT_PROVIDER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] \
    || { fail; return 1; }
  assert_wechat_provider_state oracle oracle-wechat-provider created false 172.30.231.53 \
    || { fail; return 1; }
  assert_wechat_provider_state candidate candidate-wechat-provider created false 172.30.241.53 \
    || { fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$WECHAT_RUNTIME_HELPER" write "$WECHAT_PROVIDER_ROOT" \
    "$ORACLE_WECHAT_PROVIDER_NAME" "$ORACLE_PROJECT_NAME" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$CANDIDATE_WECHAT_PROVIDER_NAME" "$CANDIDATE_PROJECT_NAME" "$PROVIDER_FIXTURE_IMAGE_ID" \
    "$PRIVATE_HOME" "$PODMAN_API_VERSION" \
    oracle-wechat-provider candidate-wechat-provider \
    || { failure_stage='wechat-provider-input'; fail; return 1; }
  assert_wechat_provider_private_material present empty \
    || { failure_stage='wechat-provider-input'; fail; return 1; }
  ORACLE_WECHAT_PROVIDER_INPUT_IDENTITY="$(artifact_identity "$ORACLE_WECHAT_PROVIDER_INPUT")"
  CANDIDATE_WECHAT_PROVIDER_INPUT_IDENTITY="$(artifact_identity \
    "$CANDIDATE_WECHAT_PROVIDER_INPUT")"
  readonly ORACLE_WECHAT_PROVIDER_INPUT_IDENTITY CANDIDATE_WECHAT_PROVIDER_INPUT_IDENTITY

  failure_stage='completion-services-create'
  for service in oracle-pwned-clear oracle-pwned-compromised oracle-pwned-unavailable \
    oracle-backchannel-accepted oracle-backchannel-rejected oracle-h5-wechat-provider \
    oracle-wechat-multichannel-provider; do
    compose_oracle create "$service" >/dev/null || { fail; return 1; }
  done
  for service in candidate-pwned-clear candidate-pwned-compromised candidate-pwned-unavailable \
    candidate-backchannel-accepted candidate-backchannel-rejected candidate-h5-wechat-provider \
    candidate-wechat-multichannel-provider; do
    compose_candidate create "$service" >/dev/null || { fail; return 1; }
  done

  failure_stage='service-closure-oracle'
  start_compose_stage oracle sms oracle-sms-provider || { failure_stage='oracle-sms-provider-start'; fail; return 1; }
  start_compose_stage candidate sms candidate-sms-provider || { failure_stage='candidate-sms-provider-start'; fail; return 1; }

  assert_exact_project_services oracle "${ORACLE_SERVICES[@]}" || { fail; return 1; }
  failure_stage='service-closure-candidate'
  assert_exact_project_services candidate "${CANDIDATE_SERVICES[@]}" || { fail; return 1; }
  failure_stage='service-closure-container-ids'
  assert_distinct_container_ids || { fail; return 1; }
  assert_expected_fixture_images || { failure_stage='service-image-identity'; fail; return 1; }

  for binding in "${LOOPBACK_PROXY_BINDINGS[@]}"; do
    IFS='|' read -r proxy_role proxy_service proxy_target proxy_host <<<"$binding"
    start_loopback_proxy "$proxy_role" "$proxy_service" "$proxy_target" "$proxy_host" || { failure_stage="proxy-${proxy_host}"; fail; return 1; }
  done
  start_loopback_proxy oracle oracle-h5-core 3001 3353 || { failure_stage='h5-upstream-oracle'; fail; return 1; }
  start_loopback_proxy candidate candidate-h5-core 3001 3354 || { failure_stage='h5-upstream-candidate'; fail; return 1; }
  start_h5_carrier 3351 3353 || { failure_stage='h5-carrier-oracle'; fail; return 1; }
  start_h5_carrier 3352 3354 || { failure_stage='h5-carrier-candidate'; fail; return 1; }
  start_loopback_proxy oracle oracle-password-core 3001 3363 || { failure_stage='password-upstream-oracle'; fail; return 1; }
  start_h5_carrier 3361 3363 || { failure_stage='password-carrier-oracle'; fail; return 1; }
  https_ready 3351 'https://localhost:3351/oidc' || { failure_stage='h5-readiness-oracle'; fail; return 1; }
  https_ready 3352 'https://localhost:3352/oidc' || { failure_stage='h5-readiness-candidate'; fail; return 1; }
  https_ready 3361 'https://localhost:3361/oidc' || { failure_stage='password-readiness-oracle'; fail; return 1; }

  for readiness in \
    '3311|http://localhost:3311/oidc' '3411|http://localhost:3411/oidc' \
    '3312|http://localhost:3312/oidc' '3412|http://localhost:3412/oidc' \
    '3321|http://localhost:3321/oidc' '3421|http://localhost:3421/oidc' \
    '3322|http://localhost:3322/oidc' '3422|http://localhost:3422/oidc'; do
    IFS='|' read -r readiness_port readiness_issuer <<<"$readiness"
    failure_stage="http-readiness-${readiness_port}"
    http_ready "$readiness_port" "$readiness_issuer" || { fail; return 1; }
  done
  wait_for_fixture_socket || { failure_stage='fixture-socket'; fail; return 1; }
  wait_for_fixture_socket "$ORACLE_SMTP_SOCKET" || { failure_stage='oracle-smtp-socket'; fail; return 1; }
  wait_for_fixture_socket "$CANDIDATE_PASSWORD_SMTP_SOCKET" || { failure_stage='candidate-password-smtp-socket'; fail; return 1; }

  oracle_primary_metadata="$(inspect_service oracle oracle-primary-core)"
  oracle_foreign_metadata="$(inspect_service oracle oracle-foreign-core)"
  candidate_primary_metadata="$(inspect_service candidate candidate-primary-core)"
  candidate_foreign_metadata="$(inspect_service candidate candidate-foreign-core)"
  IFS='|' read -r ORACLE_PRIMARY_CORE_ID _ <<<"$oracle_primary_metadata"
  IFS='|' read -r ORACLE_FOREIGN_CORE_ID _ <<<"$oracle_foreign_metadata"
  IFS='|' read -r CANDIDATE_PRIMARY_CORE_ID _ <<<"$candidate_primary_metadata"
  IFS='|' read -r CANDIDATE_FOREIGN_CORE_ID _ <<<"$candidate_foreign_metadata"
  readonly ORACLE_PRIMARY_CORE_ID ORACLE_FOREIGN_CORE_ID CANDIDATE_PRIMARY_CORE_ID CANDIDATE_FOREIGN_CORE_ID

  failure_stage='descriptors'
  write_descriptors || { fail; return 1; }
  ORACLE_PRIMARY_CORE_IDENTITY="$(core_identity oracle oracle-primary-core "$ORACLE_IMAGE_ID")"
  ORACLE_FOREIGN_CORE_IDENTITY="$(core_identity oracle oracle-foreign-core "$ORACLE_IMAGE_ID")"
  CANDIDATE_PRIMARY_CORE_IDENTITY="$(core_identity candidate candidate-primary-core "$CANDIDATE_IMAGE_ID")"
  CANDIDATE_FOREIGN_CORE_IDENTITY="$(core_identity candidate candidate-foreign-core "$CANDIDATE_IMAGE_ID")"
  ORACLE_H5_CORE_IDENTITY="$(core_identity oracle oracle-h5-core "$ORACLE_IMAGE_ID")"
  CANDIDATE_H5_CORE_IDENTITY="$(core_identity candidate candidate-h5-core "$CANDIDATE_IMAGE_ID")"
  ORACLE_PASSWORD_CORE_IDENTITY="$(core_identity oracle oracle-password-core "$ORACLE_IMAGE_ID")"
  ORACLE_STATE_DRIVER_IDENTITY="$(artifact_identity "$ORACLE_STATE_DRIVER")"
  CANDIDATE_STATE_DRIVER_IDENTITY="$(artifact_identity "$CANDIDATE_STATE_DRIVER")"
  CANDIDATE_INVARIANT_DRIVER_IDENTITY="$(artifact_identity "$CANDIDATE_INVARIANT_DRIVER")"
  ASTER_ADMIN_IDENTITY="$(artifact_identity "$ASTER_ADMIN_BIN")"
  FIXTURE_SOCKET_IDENTITY="$(socket_identity "$FIXTURE_SOCKET")"
  ORACLE_COMPLETION_INPUT_IDENTITY="$(artifact_identity "$ORACLE_COMPLETION_INPUT")"
  CANDIDATE_COMPLETION_INPUT_IDENTITY="$(artifact_identity "$CANDIDATE_COMPLETION_INPUT")"
  CANDIDATE_IDENTITY_CONFIG_IDENTITY="$(artifact_identity "$CANDIDATE_IDENTITY_CONFIG")"
  IDENTITY_CA_IDENTITY="$(artifact_identity "$IDENTITY_CA")"
  IDENTITY_CA_BUNDLE_IDENTITY="$(artifact_identity "$IDENTITY_CA_BUNDLE")"
  IDENTITY_SERVER_CERT_IDENTITY="$(artifact_identity "$IDENTITY_SERVER_CERT")"
  IDENTITY_SERVER_KEY_IDENTITY="$(artifact_identity "$IDENTITY_SERVER_KEY")"
  H5_CA_IDENTITY="$(artifact_identity "$H5_CA")"
  H5_SERVER_CERT_IDENTITY="$(artifact_identity "$H5_SERVER_CERT")"
  H5_SERVER_KEY_IDENTITY="$(artifact_identity "$H5_SERVER_KEY")"
  H5_SPKI_IDENTITY="$(artifact_identity "$H5_SPKI")"
  H5_CANDIDATE_CONFIG_IDENTITY="$(artifact_identity "$H5_CANDIDATE_CONFIG")"
  TOPOLOGY_IDENTITY="$(topology_identity)"
  readonly ORACLE_PRIMARY_CORE_IDENTITY ORACLE_FOREIGN_CORE_IDENTITY CANDIDATE_PRIMARY_CORE_IDENTITY CANDIDATE_FOREIGN_CORE_IDENTITY
  readonly ORACLE_H5_CORE_IDENTITY CANDIDATE_H5_CORE_IDENTITY
  readonly ORACLE_PASSWORD_CORE_IDENTITY
  readonly ORACLE_STATE_DRIVER_IDENTITY CANDIDATE_STATE_DRIVER_IDENTITY CANDIDATE_INVARIANT_DRIVER_IDENTITY ASTER_ADMIN_IDENTITY FIXTURE_SOCKET_IDENTITY TOPOLOGY_IDENTITY
  readonly ORACLE_COMPLETION_INPUT_IDENTITY CANDIDATE_COMPLETION_INPUT_IDENTITY CANDIDATE_IDENTITY_CONFIG_IDENTITY
  readonly IDENTITY_CA_IDENTITY IDENTITY_CA_BUNDLE_IDENTITY IDENTITY_SERVER_CERT_IDENTITY IDENTITY_SERVER_KEY_IDENTITY
  readonly H5_CA_IDENTITY H5_SERVER_CERT_IDENTITY H5_SERVER_KEY_IDENTITY H5_SPKI_IDENTITY
  readonly H5_CANDIDATE_CONFIG_IDENTITY
  assert_source_identity_unchanged || { failure_stage='source-fence-before'; fail; return 1; }
  assert_runtime_identity_unchanged || { failure_stage='runtime-fence-before'; fail; return 1; }

  launcher_path="$(/usr/bin/dirname -- "$NODE_BIN"):$(/usr/bin/dirname -- "$PNPM_BIN"):/usr/bin:/bin"
  failure_stage='evidence-sequence'
  "$ENV_BIN" -i PATH="$launcher_path" HOME="$PRIVATE_HOME" LC_ALL=C \
    PLAYWRIGHT_BROWSERS_PATH="$BROWSER_CACHE" TMPDIR="$BROWSER_TMP" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME" \
    ASTER_PHASE2_ORACLE_SMTP_SOCKET="$ORACLE_SMTP_SOCKET" \
    ASTER_PHASE2_ORACLE_SMS_PROVIDER_INPUT="$ORACLE_SMS_PROVIDER_INPUT" \
    ASTER_PHASE2_CANDIDATE_SMS_PROVIDER_INPUT="$CANDIDATE_SMS_PROVIDER_INPUT" \
    ASTER_PHASE2_ENGINE_SOCKET="$ENGINE_SOCKET" \
    ASTER_PHASE2_ORACLE_GOOGLE_PROVIDER_INPUT="$ORACLE_GOOGLE_PROVIDER_INPUT" \
    ASTER_PHASE2_CANDIDATE_GOOGLE_PROVIDER_INPUT="$CANDIDATE_GOOGLE_PROVIDER_INPUT" \
    ASTER_PHASE2_ORACLE_WECHAT_PROVIDER_INPUT="$ORACLE_WECHAT_PROVIDER_INPUT" \
    ASTER_PHASE2_CANDIDATE_WECHAT_PROVIDER_INPUT="$CANDIDATE_WECHAT_PROVIDER_INPUT" \
    ASTER_PHASE2_ORACLE_COMPLETION_INPUT="$ORACLE_COMPLETION_INPUT" \
    ASTER_PHASE2_CANDIDATE_COMPLETION_INPUT="$CANDIDATE_COMPLETION_INPUT" \
    NODE_EXTRA_CA_CERTS="$H5_CA" \
    "$NODE_BIN" --input-type=module - "$LAUNCHER_SOURCE" "$PROFILE_SOURCE" "$SCHEMA_SOURCE" \
    "$ORACLE_DESCRIPTOR" "$CANDIDATE_DESCRIPTOR" "$ORACLE_EVIDENCE" "$DIFFERENTIAL_EVIDENCE" \
    "$INVARIANT_EVIDENCE" "$EVIDENCE_DIR" <<'NODE' >/dev/null 2>"$RUN_DIR/evidence-sequence.stderr" || {
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const [launcherPath, profile, schema, oracleTarget, candidateTarget,
  oracleOutput, differentialOutput, invariantOutput, temporaryRoot] = process.argv.slice(2);
const { launchPhase2Batch, diagnosticForPhase2Batch } = await import(pathToFileURL(launcherPath).href);
const maximumArtifactBytes = 16 * 1024 * 1024;
const immutableArtifact = async (file) => {
  const [state, resolved] = await Promise.all([lstat(file), realpath(file)]);
  if (state.isSymbolicLink() || !state.isFile() || state.nlink !== 1 ||
      state.uid !== process.getuid() || (state.mode & 0o777) !== 0o600 || resolved !== file ||
      state.size <= 0 || state.size > maximumArtifactBytes) throw new Error('artifact');
  const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.dev !== state.dev || opened.ino !== state.ino || opened.uid !== state.uid ||
        opened.mode !== state.mode || opened.nlink !== state.nlink || opened.size !== state.size) {
      throw new Error('artifact');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.mode !== opened.mode ||
        after.nlink !== opened.nlink || after.size !== opened.size) throw new Error('artifact');
    return Object.freeze({dev: state.dev, ino: state.ino, uid: state.uid, mode: state.mode,
      nlink: state.nlink, size: state.size, mtimeMs: state.mtimeMs, ctimeMs: state.ctimeMs,
      sha256: createHash('sha256').update(bytes).digest('hex')});
  } finally {
    await handle.close();
  }
};
const assertExactArtifacts = async (expected) => {
  const actual = (await readdir(temporaryRoot)).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) throw new Error('artifact');
};
const runBatch = async (mode, command) => {
  const code = await launchPhase2Batch(Object.freeze([command]));
  if (code !== 0) throw new Error(mode);
};
const oracleCommand = Object.freeze(['oracle', '--profile', profile, '--schema', schema,
  '--target', oracleTarget, '--output', oracleOutput, '--temp-root', temporaryRoot]);
const differentialCommand = Object.freeze(['differential', '--profile', profile, '--schema', schema,
  '--oracle-evidence', oracleOutput, '--candidate-target', candidateTarget,
  '--output', differentialOutput, '--temp-root', temporaryRoot]);
const invariantCommand = Object.freeze(['candidate-invariants', '--profile', profile,
  '--schema', schema, '--target', candidateTarget, '--output', invariantOutput,
  '--temp-root', temporaryRoot]);
let sequenceStage = 'oracle-run';
try {
  await runBatch('oracle', oracleCommand);
  sequenceStage = 'oracle-artifact-set';
  await assertExactArtifacts(['phase-2-client-credentials-oracle.json']);
  sequenceStage = 'oracle-artifact-identity';
  const oracleIdentity = await immutableArtifact(oracleOutput);
  sequenceStage = 'differential-run';
  await runBatch('differential', differentialCommand);
  sequenceStage = 'differential-artifact-set';
  await assertExactArtifacts(['phase-2-client-credentials-oracle.json',
    'phase-2-client-credentials-differential.json']);
  sequenceStage = 'oracle-identity-after-differential';
  if (JSON.stringify(await immutableArtifact(oracleOutput)) !== JSON.stringify(oracleIdentity)) {
    throw new Error('differential');
  }
  sequenceStage = 'differential-artifact-identity';
  await immutableArtifact(differentialOutput);
  sequenceStage = 'candidate-invariants-run';
  await runBatch('candidate-invariants', invariantCommand);
  sequenceStage = 'candidate-invariants-artifact-set';
  await assertExactArtifacts(['phase-2-client-credentials-oracle.json',
    'phase-2-client-credentials-differential.json',
    'phase-2-client-credentials-candidate-invariants.json']);
  sequenceStage = 'oracle-identity-after-invariants';
  if (JSON.stringify(await immutableArtifact(oracleOutput)) !== JSON.stringify(oracleIdentity)) {
    throw new Error('candidate-invariants');
  }
  sequenceStage = 'final-artifact-identities';
  await immutableArtifact(differentialOutput);
  await immutableArtifact(invariantOutput);
} catch (error) {
  process.stderr.write(`Phase 2 evidence sequence failed (${sequenceStage}).\n`);
  process.stderr.write(diagnosticForPhase2Batch(error));
  process.exitCode = 1;
}
NODE
    if /usr/bin/grep -Eq '^Phase 2 evidence sequence failed \((oracle-run|oracle-artifact-set|oracle-artifact-identity|differential-run|differential-artifact-set|oracle-identity-after-differential|differential-artifact-identity|candidate-invariants-run|candidate-invariants-artifact-set|oracle-identity-after-invariants|final-artifact-identities)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 evidence sequence failed \((oracle-run|oracle-artifact-set|oracle-artifact-identity|differential-run|differential-artifact-set|oracle-identity-after-differential|differential-artifact-identity|candidate-invariants-run|candidate-invariants-artifact-set|oracle-identity-after-invariants|final-artifact-identities)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-invariant-legacy-[0-4]\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-invariant-legacy-[0-4]\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-invariant-device-7-(prepare|approval|issuance|evidence-(open|values|validation|lease)|driver-unclassified)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-invariant-device-7-(prepare|approval|issuance|evidence-(open|values|validation|lease)|driver-unclassified)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)-custom-jwt-([0-9]|1[0-9]|2[0-3])(:http-[1-5][0-9]{2}|:issuance-(admission|authorization|bootstrap|verification|identification|submit|bridge-(url|send|http-([1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(http|body|type|access|refresh)))?\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-custom-jwt-([0-9]|1[0-9]|2[0-3])(:http-[1-5][0-9]{2}|:issuance-(admission|authorization|bootstrap|verification|identification|submit|bridge-(url|send|http-([1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(http|body|type|access|refresh)))?\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)-custom-jwt-fetch-[0-5]\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-custom-jwt-fetch-[0-5]\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)-custom-jwt-22:(authorize|approval-(authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final)|token-poll|initial-lease|refresh-request|refresh-http|jwt-verify|projection)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-custom-jwt-22:(authorize|approval-(authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final)|token-poll|initial-lease|refresh-request|refresh-http|jwt-verify|projection)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-admin-bearer-(admission|authorization|bootstrap|password|identification|submit|bridge|consent|resume|code-token|management-refresh|jwks)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-admin-bearer-(admission|authorization|bootstrap|password|identification|submit|bridge|consent|resume|code-token|management-refresh|jwks)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-admin-consumer-unknown\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-admin-consumer-unknown\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-fixture-(provision|readiness|public-jwks|cleanup|body-cleanup)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-fixture-(provision|readiness|public-jwks|cleanup|body-cleanup)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/common\.native\.code-pkce\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/common\.native\.code-pkce\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/common\.email\.password-sign-in\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/common\.email\.password-sign-in\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/common\.email\.code-sign-in\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/common\.email\.code-sign-in\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/common\.email\.code-registration\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/common\.email\.code-registration\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)-phone-(registration|sign-in)-(admission|capability|discovery|subject|sms-lease|controls|fixture|fixture-cleanup|other|(registration|sign-in)-(input|initialization|identifier|delivery|code-format|code-fill|consent|callback|profile|refresh|subject))\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-phone-(registration|sign-in)-(admission|capability|discovery|subject|sms-lease|controls|fixture|fixture-cleanup|other|(registration|sign-in)-(input|initialization|identifier|delivery|code-format|code-fill|consent|callback|profile|refresh|subject))\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    forward_closed_common_row_failures "$RUN_DIR/evidence-sequence.stderr" || true
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((candidate-invariant-device-([0-7]|1-(private-code-extraction|row-sql|row-missing|row-facts|schema-query|schema-clear-columns)|2-(arm|abort|foreign-poll-(error|invalid-client|authorization-pending|status)|response|finish)|7-(private-extraction|row-sql|row-facts|schema-query|schema-clear-columns|scan-(input|query|match)|normalized-(input|query|match)))|(oracle|candidate)(/(client-credentials\.[a-z-]+|token-status\.[a-z-]+|logout\.[a-z-]+|account-sessions\.[a-z-]+|verification-code\.[a-z-]+|device-(authorization|verification|consent|token|token-status|discovery)\.[a-z-]+(:((lifecycle-request|lifecycle-response|token-response|credential-lease|projection|scenario|approval(-(authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final))?|transition|verification-get|verification-post|projection-(status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other))))?)|-(fixture|discovery|controls|sanitizer(-(target|discovery|controls|ids|((client|device)-([0-9]|[1-9][0-9]|1[0-6][0-9]|17[0-5])|native-176|email-177|code-178|registration-179|password-registration-180|recovery-181|google-182)))?|comparison|logout-session|verification-code|custom-jwt|target-(path|read|verify|prepare)|execution|harness|evidence|publish|cleanup|status-(admission|authorization|bootstrap|verification|identification|submit|bridge-(url|send|http-([1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(http|body|type|access|refresh)|introspection)|status-comparison-(kind|status|headers|body(-(sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-case-([0-9]|1[0-9]|2[0-6])-(kind|status|headers|body(-(sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-scope-([0-9]|1[0-9]|2[0-6])-(short|full|resource|offline|other)-(short|full|resource|offline|other)))|differential-(target-path|target-read|target-pair|target-verify|target-prepare|execution|harness|evidence|publish|cleanup))\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((candidate-invariant-device-([0-7]|1-(private-code-extraction|row-sql|row-missing|row-facts|schema-query|schema-clear-columns)|2-(arm|abort|foreign-poll-(error|invalid-client|authorization-pending|status)|response|finish)|7-(private-extraction|row-sql|row-facts|schema-query|schema-clear-columns|scan-(input|query|match)|normalized-(input|query|match)))|(oracle|candidate)(/(client-credentials\.[a-z-]+|token-status\.[a-z-]+|logout\.[a-z-]+|account-sessions\.[a-z-]+|verification-code\.[a-z-]+|device-(authorization|verification|consent|token|token-status|discovery)\.[a-z-]+(:((lifecycle-request|lifecycle-response|token-response|credential-lease|projection|scenario|approval(-(authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final))?|transition|verification-get|verification-post|projection-(status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other))))?)|-(fixture|discovery|controls|sanitizer(-(target|discovery|controls|ids|((client|device)-([0-9]|[1-9][0-9]|1[0-6][0-9]|17[0-5])|native-176|email-177|code-178|registration-179|password-registration-180|recovery-181|google-182)))?|comparison|logout-session|verification-code|custom-jwt|target-(path|read|verify|prepare)|execution|harness|evidence|publish|cleanup|status-(admission|authorization|bootstrap|verification|identification|submit|bridge-(url|send|http-([1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(http|body|type|access|refresh)|introspection)|status-comparison-(kind|status|headers|body(-(sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-case-([0-9]|1[0-9]|2[0-6])-(kind|status|headers|body(-(sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-scope-([0-9]|1[0-9]|2[0-6])-(short|full|resource|offline|other)-(short|full|resource|offline|other)))|differential-(target-path|target-read|target-pair|target-verify|target-prepare|execution|harness|evidence|publish|cleanup))\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/device-consent\.[a-z-]+:projection-(firstIssued|consent|completion)-(status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/device-consent\.[a-z-]+:projection-(firstIssued|consent|completion)-(status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/(device-token-status\.[a-z-]+|device-token\.session-bound-expiry):projection-sequence-(before|action|after|siblingBefore|siblingAfter)-(status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/(device-token-status\.[a-z-]+|device-token\.session-bound-expiry):projection-sequence-(before|action|after|siblingBefore|siblingAfter)-(status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)/device-(authorization|verification|consent|token|token-status|discovery)\.[a-z-]+:projection-id-(claimKeys|claimTypes-(aud|created_at|email|email_verified|exp|iat|iss|name|picture|preferred_username|sub|updated_at|username|auth_time|acr|amr|sid)|header|signature|format|issuer|audience|subject|issuedAt|lifetimeSeconds|other)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)/device-(authorization|verification|consent|token|token-status|discovery)\.[a-z-]+:projection-id-(claimKeys|claimTypes-(aud|created_at|email|email_verified|exp|iat|iss|name|picture|preferred_username|sub|updated_at|username|auth_time|acr|amr|sid)|header|signature|format|issuer|audience|subject|issuedAt|lifetimeSeconds|other)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)-common-ready-account-((password|email)-other|phone-(admission|discovery|account-transport|fixture|token-issuance|browser-login|provider-lease|flow))\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-common-ready-account-((password|email)-other|phone-(admission|discovery|account-transport|fixture|token-issuance|browser-login|provider-lease|flow))\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    readonly id_claim_name='(iss|aud|sub|iat|exp|nbf|auth_time|sid|jti|client_id|acr|amr|name|picture|username|email|email_verified|phone_number|phone_number_verified|family_name|given_name|middle_name|nickname|preferred_username|profile|website|gender|birthdate|zoneinfo|locale|address|created_at|updated_at|roles|organizations|organization_roles|organization_id|permissions)'
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \((oracle|candidate)-common-ready-(password-registration|recovery|google|google-registration|wechat-web)-(admission|capability|discovery|subject|lease|cleanup|fixture|browser|admin|context|consent-field-invalid-(route|operation|status|binding|code|authorization|state|tuple)|context-adapter|context-flow|context-after-flow|context-control-(open|route|count|reset|click|response|owner)|context-positive-(admission|initialization|provider-count|provider-click|consent-route|consent-click|callback|profile|refresh|provider)|context-positive-consent-(response|authorization|state|route|complete)|credentials|management|other|wrong-state-owner-before|wrong-state-browser|wrong-state-owner-after|wrong-state-provider|flow-admission|flow-initialization|flow-identifier|flow-delivery|flow-verification|flow-credential-fulfillment|flow-persisted-user|flow-callback|flow-registration-profile-refresh|flow-fresh-sign-in|flow-fresh-profile-refresh|flow-initial-password|flow-forgot-password|flow-passcode-retrieval|flow-passcode-format|flow-passcode-fill|flow-new-password-reset|flow-prior-access|flow-prior-refresh|flow-new-password-sign-in|flow-old-password-rejection|flow-profile|flow-refresh|flow-provider|flow-provider-count|flow-provider-click|flow-consent|flow-provider-case|flow-authorization|controls-admission|controls-incomplete-before|controls-incomplete-proof|controls-incomplete-identification|controls-incomplete-after|controls-duplicate-before|controls-duplicate-proof|controls-duplicate-identification|controls-duplicate-after|controls-policy-before|controls-policy-proof|controls-policy-profile|controls-policy-after|controls-replay|controls-wrong-purpose|flow-callback-callback-route|flow-callback-cardinality|flow-callback-signin-authority|flow-callback-signin-response|flow-callback-signin-client|flow-callback-signin-redirect|flow-callback-signin-mode|flow-callback-signin-scope|flow-callback-signin-resource|flow-callback-signin-pkce|flow-callback-callback-authority|flow-callback-callback-response|flow-callback-callback-state|flow-callback-callback-issuer|flow-callback-callback-code|flow-callback-exchange-authority|flow-callback-exchange-response|flow-callback-exchange-correlation|flow-callback-exchange-client|flow-callback-exchange-refresh|flow-callback-exchange-target|flow-callback-exchange-scope|flow-callback-exchange-access|fixture-read-sie|fixture-get-app|fixture-patch-app|fixture-read-app|fixture-read-resource|fixture-create-role|fixture-create-connector|fixture-prepare-connector|fixture-prepare-connector-docker-environment|fixture-prepare-connector-admission|fixture-prepare-connector-configuration-file|fixture-prepare-connector-receipt-file|fixture-prepare-connector-container-admission|fixture-prepare-connector-configuration-write|fixture-prepare-connector-start|fixture-prepare-connector-health|fixture-prepare-connector-compensation|fixture-prepare-connector-unknown|fixture-patch-sie|fixture-read-sie-updated|fixture-existing-owner-create-user|fixture-existing-owner-associate|fixture-existing-owner-read-before|fixture-existing-owner-use|fixture-existing-owner-read-after|fixture-existing-owner-cleanup-user|fixture-stop-provider|fixture-restore-app|fixture-delete-role|fixture-restore-sie|fixture-delete-connector|fixture-input|scenario-fixture|scenario-projection|wrong-state-authorization|wrong-state-authorization-request-count|wrong-state-authorization-query-shape|wrong-state-authorization-client|wrong-state-authorization-callback|wrong-state-authorization-response-type|wrong-state-authorization-scope|wrong-state-authorization-state-format|wrong-state-authorization-state-round-trip|wrong-state-authorization-fulfilled|flow-callback-callback-facts-s0-c0-i0|flow-callback-callback-facts-s0-c0-i1|flow-callback-callback-facts-s0-c0-imany|flow-callback-callback-facts-s0-c1-i0|flow-callback-callback-facts-s0-c1-i1|flow-callback-callback-facts-s0-c1-imany|flow-callback-callback-facts-s0-cmany-i0|flow-callback-callback-facts-s0-cmany-i1|flow-callback-callback-facts-s0-cmany-imany|flow-callback-callback-facts-s1-c0-i0|flow-callback-callback-facts-s1-c0-i1|flow-callback-callback-facts-s1-c0-imany|flow-callback-callback-facts-s1-c1-i0|flow-callback-callback-facts-s1-c1-i1|flow-callback-callback-facts-s1-c1-imany|flow-callback-callback-facts-s1-cmany-i0|flow-callback-callback-facts-s1-cmany-i1|flow-callback-callback-facts-s1-cmany-imany|flow-callback-callback-facts-smany-c0-i0|flow-callback-callback-facts-smany-c0-i1|flow-callback-callback-facts-smany-c0-imany|flow-callback-callback-facts-smany-c1-i0|flow-callback-callback-facts-smany-c1-i1|flow-callback-callback-facts-smany-c1-imany|flow-callback-callback-facts-smany-cmany-i0|flow-callback-callback-facts-smany-cmany-i1|flow-callback-callback-facts-smany-cmany-imany|wrong-state-open|wrong-state-sign-in|wrong-state-provider-count|wrong-state-provider-click|wrong-state-callback-outcome|wrong-state-callback-signal|wrong-state-callback-guard|wrong-state-callback-observation-other|wrong-state-callback-external-callback-method|wrong-state-callback-external-callback-query|wrong-state-callback-external-callback-fragment|wrong-state-callback-cardinality|authorization|callback|initialization|missing-owner|owner-lookup|profile|provider-count|provider-click|refresh|registration-route|registration-transition|consent-click|consent-route|consent-route-(sign-in|register|continue|demo|error|callback|other)-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(complete|missing-resume-(not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(user-identity_not_exist|user-missing_profile|session-verification_session_not_found|session-interaction_not_found|session-invalid_credentials|user-suspended|user-sign_in_method_not_enabled|session-identity_conflict|user-email_already_in_use|verification_record-permission_denied|guard-invalid_input|connector-general|connector-wechat_unionid_required|connector-social_auth_code_invalid|connector-invalid_response|unknown|none)-auth-[01]{9}-state-(stored|cleared|unavailable)|fixture-registration-owner-before|fixture-registration-owner-use|fixture-registration-owner-after|fixture-registration-owner-cleanup|fixture-registration-owner-discovery|controls-no-union-id|controls-invalid-code|controls-replay|controls-malformed-provider|controls-cross-interaction(-(execution(-(target|result|not-observed|after-control|browser|context|init-request|init-status|replay-request|replay-body|cleanup|first-response|owner-before|request|owner-after|fulfill))?|status|error|accepted))?|controls-missing-state|controls-wrong-state|controls-wrong-callback|unverified-email-control-(invalid-status|disallowed-error)-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(connector\.general|guard\.invalid_input|user\.identity_not_exist|user\.missing_profile|verification_record\.permission_denied|session\.identity_conflict|user\.email_already_in_use|none)|occupied-email-control-(invalid-status|disallowed-error)-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(connector\.general|guard\.invalid_input|user\.identity_not_exist|user\.missing_profile|verification_record\.permission_denied|session\.identity_conflict|user\.email_already_in_use|none)|unverified-email-control-rejected-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(user\.identity_not_exist|session\.verification_session_not_found|session\.interaction_not_found|session\.invalid_credentials|user\.suspended|user\.sign_in_method_not_enabled|connector\.wechat_unionid_required|connector\.social_auth_code_invalid|connector\.invalid_response)|unverified-email-control-unknown-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)|unverified-email-control-observed-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(known|unknown)-(incomplete|other)|unverified-email-control(-(response|consent|profile-route|profile-input|outcome|outcome-code|outcome-status|outcome-error|outcome-accepted|link-count|link-click|link-complete))?|unverified-email-owner|occupied-email-control(-(response|consent|profile-route|profile-input|outcome|outcome-code|outcome-status|outcome-error|outcome-accepted|link-count|link-click|link-complete))?|occupied-email-owner|control-publication)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \((oracle|candidate)-common-ready-(password-registration|recovery|google|google-registration|wechat-web)-(admission|capability|discovery|subject|lease|cleanup|fixture|browser|admin|context|consent-field-invalid-(route|operation|status|binding|code|authorization|state|tuple)|context-adapter|context-flow|context-after-flow|context-control-(open|route|count|reset|click|response|owner)|context-positive-(admission|initialization|provider-count|provider-click|consent-route|consent-click|callback|profile|refresh|provider)|context-positive-consent-(response|authorization|state|route|complete)|credentials|management|other|wrong-state-owner-before|wrong-state-browser|wrong-state-owner-after|wrong-state-provider|flow-admission|flow-initialization|flow-identifier|flow-delivery|flow-verification|flow-credential-fulfillment|flow-persisted-user|flow-callback|flow-registration-profile-refresh|flow-fresh-sign-in|flow-fresh-profile-refresh|flow-initial-password|flow-forgot-password|flow-passcode-retrieval|flow-passcode-format|flow-passcode-fill|flow-new-password-reset|flow-prior-access|flow-prior-refresh|flow-new-password-sign-in|flow-old-password-rejection|flow-profile|flow-refresh|flow-provider|flow-provider-count|flow-provider-click|flow-consent|flow-provider-case|flow-authorization|controls-admission|controls-incomplete-before|controls-incomplete-proof|controls-incomplete-identification|controls-incomplete-after|controls-duplicate-before|controls-duplicate-proof|controls-duplicate-identification|controls-duplicate-after|controls-policy-before|controls-policy-proof|controls-policy-profile|controls-policy-after|controls-replay|controls-wrong-purpose|flow-callback-callback-route|flow-callback-cardinality|flow-callback-signin-authority|flow-callback-signin-response|flow-callback-signin-client|flow-callback-signin-redirect|flow-callback-signin-mode|flow-callback-signin-scope|flow-callback-signin-resource|flow-callback-signin-pkce|flow-callback-callback-authority|flow-callback-callback-response|flow-callback-callback-state|flow-callback-callback-issuer|flow-callback-callback-code|flow-callback-exchange-authority|flow-callback-exchange-response|flow-callback-exchange-correlation|flow-callback-exchange-client|flow-callback-exchange-refresh|flow-callback-exchange-target|flow-callback-exchange-scope|flow-callback-exchange-access|fixture-read-sie|fixture-get-app|fixture-patch-app|fixture-read-app|fixture-read-resource|fixture-create-role|fixture-create-connector|fixture-prepare-connector|fixture-prepare-connector-docker-environment|fixture-prepare-connector-admission|fixture-prepare-connector-configuration-file|fixture-prepare-connector-receipt-file|fixture-prepare-connector-container-admission|fixture-prepare-connector-configuration-write|fixture-prepare-connector-start|fixture-prepare-connector-health|fixture-prepare-connector-compensation|fixture-prepare-connector-unknown|fixture-patch-sie|fixture-read-sie-updated|fixture-existing-owner-create-user|fixture-existing-owner-associate|fixture-existing-owner-read-before|fixture-existing-owner-use|fixture-existing-owner-read-after|fixture-existing-owner-cleanup-user|fixture-stop-provider|fixture-restore-app|fixture-delete-role|fixture-restore-sie|fixture-delete-connector|fixture-input|scenario-fixture|scenario-projection|wrong-state-authorization|wrong-state-authorization-request-count|wrong-state-authorization-query-shape|wrong-state-authorization-client|wrong-state-authorization-callback|wrong-state-authorization-response-type|wrong-state-authorization-scope|wrong-state-authorization-state-format|wrong-state-authorization-state-round-trip|wrong-state-authorization-fulfilled|flow-callback-callback-facts-s0-c0-i0|flow-callback-callback-facts-s0-c0-i1|flow-callback-callback-facts-s0-c0-imany|flow-callback-callback-facts-s0-c1-i0|flow-callback-callback-facts-s0-c1-i1|flow-callback-callback-facts-s0-c1-imany|flow-callback-callback-facts-s0-cmany-i0|flow-callback-callback-facts-s0-cmany-i1|flow-callback-callback-facts-s0-cmany-imany|flow-callback-callback-facts-s1-c0-i0|flow-callback-callback-facts-s1-c0-i1|flow-callback-callback-facts-s1-c0-imany|flow-callback-callback-facts-s1-c1-i0|flow-callback-callback-facts-s1-c1-i1|flow-callback-callback-facts-s1-c1-imany|flow-callback-callback-facts-s1-cmany-i0|flow-callback-callback-facts-s1-cmany-i1|flow-callback-callback-facts-s1-cmany-imany|flow-callback-callback-facts-smany-c0-i0|flow-callback-callback-facts-smany-c0-i1|flow-callback-callback-facts-smany-c0-imany|flow-callback-callback-facts-smany-c1-i0|flow-callback-callback-facts-smany-c1-i1|flow-callback-callback-facts-smany-c1-imany|flow-callback-callback-facts-smany-cmany-i0|flow-callback-callback-facts-smany-cmany-i1|flow-callback-callback-facts-smany-cmany-imany|wrong-state-open|wrong-state-sign-in|wrong-state-provider-count|wrong-state-provider-click|wrong-state-callback-outcome|wrong-state-callback-signal|wrong-state-callback-guard|wrong-state-callback-observation-other|wrong-state-callback-external-callback-method|wrong-state-callback-external-callback-query|wrong-state-callback-external-callback-fragment|wrong-state-callback-cardinality|authorization|callback|initialization|missing-owner|owner-lookup|profile|provider-count|provider-click|refresh|registration-route|registration-transition|consent-click|consent-route|consent-route-(sign-in|register|continue|demo|error|callback|other)-(social-verify|identification|submit|resume|none)-(200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(complete|missing-resume-(not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(user-identity_not_exist|user-missing_profile|session-verification_session_not_found|session-interaction_not_found|session-invalid_credentials|user-suspended|user-sign_in_method_not_enabled|session-identity_conflict|user-email_already_in_use|verification_record-permission_denied|guard-invalid_input|connector-general|connector-wechat_unionid_required|connector-social_auth_code_invalid|connector-invalid_response|unknown|none)-auth-[01]{9}-state-(stored|cleared|unavailable)|fixture-registration-owner-before|fixture-registration-owner-use|fixture-registration-owner-after|fixture-registration-owner-cleanup|fixture-registration-owner-discovery|controls-no-union-id|controls-invalid-code|controls-replay|controls-malformed-provider|controls-cross-interaction(-(execution(-(target|result|not-observed|after-control|browser|context|init-request|init-status|replay-request|replay-body|cleanup|first-response|owner-before|request|owner-after|fulfill))?|status|error|accepted))?|controls-missing-state|controls-wrong-state|controls-wrong-callback|unverified-email-control(-(response|consent|profile-route|profile-input|outcome|outcome-code|outcome-status|outcome-error|outcome-accepted|link-count|link-click|link-complete))?|unverified-email-owner|occupied-email-control(-(response|consent|profile-route|profile-input|outcome|outcome-code|outcome-status|outcome-error|outcome-accepted|link-count|link-click|link-complete))?|occupied-email-owner|control-publication)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-(google-projection-((wrong-state-status|replay-second-status)-o[1-5][0-9]{2}-c[1-5][0-9]{2}|wrong-state-error-o(none|session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general|unknown)-c(none|session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general|unknown)|replay-second-error-o(session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general)-c(session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general)|contract-o(true|false)-c(true|false)|other))\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-(google-projection-((wrong-state-status|replay-second-status)-o[1-5][0-9]{2}-c[1-5][0-9]{2}|wrong-state-error-o(none|session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general|unknown)-c(none|session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general|unknown)|replay-second-error-o(session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general)-c(session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general)|contract-o(true|false)-c(true|false)|other))\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    readonly id_claim_set="(none|${id_claim_name}(,${id_claim_name})*)"
    if /usr/bin/grep -Eq "^Phase 2 device ID claimKeys differ \(only on oracle: ${id_claim_set}; only on candidate: ${id_claim_set}\)\.$" "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E "^Phase 2 device ID claimKeys differ \(only on oracle: ${id_claim_set}; only on candidate: ${id_claim_set}\)\.$" "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials command failed \(candidate-((google-registration|wechat-web)-projection-(contract-o(true|false)-c(true|false)|(unverified-email|occupied-email|no-union-id|invalid-code|replay|malformed-provider|cross-interaction|missing-state|wrong-state|wrong-callback)-(status-o[1-5][0-9]{2}-c[1-5][0-9]{2}|error-o(connector\.(general|wechat_unionid_required|social_auth_code_invalid|invalid_response)|guard\.invalid_input|verification_record\.permission_denied|session\.(identity_conflict|verification_session_not_found)|user\.email_already_in_use|unknown|none)-c(connector\.(general|wechat_unionid_required|social_auth_code_invalid|invalid_response)|guard\.invalid_input|verification_record\.permission_denied|session\.(identity_conflict|verification_session_not_found)|user\.email_already_in_use|unknown|none))|other))\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials command failed \(candidate-((google-registration|wechat-web)-projection-(contract-o(true|false)-c(true|false)|(unverified-email|occupied-email|no-union-id|invalid-code|replay|malformed-provider|cross-interaction|missing-state|wrong-state|wrong-callback)-(status-o[1-5][0-9]{2}-c[1-5][0-9]{2}|error-o(connector\.(general|wechat_unionid_required|social_auth_code_invalid|invalid_response)|guard\.invalid_input|verification_record\.permission_denied|session\.(identity_conflict|verification_session_not_found)|user\.email_already_in_use|unknown|none)-c(connector\.(general|wechat_unionid_required|social_auth_code_invalid|invalid_response)|guard\.invalid_input|verification_record\.permission_denied|session\.(identity_conflict|verification_session_not_found)|user\.email_already_in_use|unknown|none))|other))\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials launcher child failed \((timeout|signal|stderr-bytes-[1-9][0-9]*-sha256-[0-9a-f]{64}|exit-code)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials launcher child failed \((timeout|signal|stderr-bytes-[1-9][0-9]*-sha256-[0-9a-f]{64}|exit-code)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    if /usr/bin/grep -Eq '^Phase 2 client credentials batch failed \((oracle|differential|candidate-invariants)\)\.$' "$RUN_DIR/evidence-sequence.stderr"; then
      /usr/bin/grep -E '^Phase 2 client credentials batch failed \((oracle|differential|candidate-invariants)\)\.$' "$RUN_DIR/evidence-sequence.stderr" >&2
    fi
    fail; return 1;
  }
  assert_google_provider_private_material present empty \
    || { failure_stage='google-provider-proof-reset'; fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$GOOGLE_RUNTIME_HELPER" probe "$GOOGLE_PROVIDER_ROOT" \
    || { failure_stage='google-provider-proof-configuration'; fail; return 1; }
  prove_google_provider_runtime oracle oracle-google-provider 172.30.231.52 \
    || { failure_stage='oracle-google-provider-runtime'; fail; return 1; }
  prove_google_provider_runtime candidate candidate-google-provider 172.30.241.52 \
    || { failure_stage='candidate-google-provider-runtime'; fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$GOOGLE_RUNTIME_HELPER" clear-probe "$GOOGLE_PROVIDER_ROOT" \
    || { failure_stage='google-provider-proof-clear'; fail; return 1; }
  assert_google_provider_private_material present empty \
    || { failure_stage='google-provider-proof-clear'; fail; return 1; }
  assert_wechat_provider_private_material present empty \
    || { failure_stage='wechat-provider-proof-reset'; fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$WECHAT_RUNTIME_HELPER" probe "$WECHAT_PROVIDER_ROOT" \
    || { failure_stage='wechat-provider-proof-configuration'; fail; return 1; }
  prove_wechat_provider_runtime oracle oracle-wechat-provider 172.30.231.53 \
    || { failure_stage='oracle-wechat-provider-runtime'; fail; return 1; }
  prove_wechat_provider_runtime candidate candidate-wechat-provider 172.30.241.53 \
    || { failure_stage='candidate-wechat-provider-runtime'; fail; return 1; }
  "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
    "$NODE_BIN" "$WECHAT_RUNTIME_HELPER" clear-probe "$WECHAT_PROVIDER_ROOT" \
    || { failure_stage='wechat-provider-proof-clear'; fail; return 1; }
  assert_wechat_provider_private_material present empty \
    || { failure_stage='wechat-provider-proof-clear'; fail; return 1; }
  remove_state_handle_root "$STATE_HANDLE_ROOT" || { failure_stage='state-handle-sweep-after-evidence'; fail; return 1; }
  assert_runtime_identity_unchanged || { failure_stage='runtime-fence-after-evidence'; fail; return 1; }

  failure_stage='evidence-validation'
  assert_source_identity_unchanged || { fail; return 1; }
  assert_runtime_identity_unchanged || { fail; return 1; }
  scan_evidence_for_private_values || { fail; return 1; }

  RESULT_STAGING_DIR="$(/usr/bin/mktemp -d "$RESULT_ROOT/.staging.XXXXXX")"
  /usr/bin/chmod 0700 "$RESULT_STAGING_DIR"
  RESULT_STAGING_IDENTITY="$(capture_path_identity "$RESULT_STAGING_DIR")"
  /usr/bin/mv -- "$ORACLE_EVIDENCE" "$RESULT_STAGING_DIR/phase-2-client-credentials-oracle.json"
  /usr/bin/mv -- "$DIFFERENTIAL_EVIDENCE" "$RESULT_STAGING_DIR/phase-2-client-credentials-differential.json"
  /usr/bin/mv -- "$INVARIANT_EVIDENCE" "$RESULT_STAGING_DIR/phase-2-client-credentials-candidate-invariants.json"
  /usr/bin/chmod 0600 "$RESULT_STAGING_DIR"/*.json
  oracle_sha256="$(sha256_file "$RESULT_STAGING_DIR/phase-2-client-credentials-oracle.json")"
  differential_sha256="$(sha256_file "$RESULT_STAGING_DIR/phase-2-client-credentials-differential.json")"
  invariant_sha256="$(sha256_file "$RESULT_STAGING_DIR/phase-2-client-credentials-candidate-invariants.json")"
  [[ "$oracle_sha256" =~ ^[0-9a-f]{64}$ && "$differential_sha256" =~ ^[0-9a-f]{64}$ && "$invariant_sha256" =~ ^[0-9a-f]{64}$ ]] || { failure_stage='result-hashes'; fail; return 1; }

  cleanup_complete=0
  for _ in 1 2; do
    if cleanup_resources 0; then
      cleanup_complete=1
      break
    fi
  done
  [[ "$cleanup_complete" == 1 ]] || { failure_stage='cleanup'; fail; return 1; }

  failure_stage='result-publication'
  assert_path_identity "$RESULT_ROOT" "$RESULT_ROOT_IDENTITY" || { fail; return 1; }
  RESULT_DIR="$RESULT_ROOT/result.$(random_hex 8)"
  RESULT_DIR_IDENTITY="$RESULT_STAGING_IDENTITY"
  [[ ! -e "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || { fail; return 1; }
  /usr/bin/mv --no-clobber --no-target-directory "$RESULT_STAGING_DIR" "$RESULT_DIR" || { fail; return 1; }
  [[ ! -e "$RESULT_STAGING_DIR" && ! -L "$RESULT_STAGING_DIR" ]] || { fail; return 1; }
  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || { fail; return 1; }
  assert_path_identity "$RESULT_DIR" "$RESULT_DIR_IDENTITY" || { fail; return 1; }
  verify_published_result_directory "$RESULT_DIR" "$oracle_sha256" "$differential_sha256" "$invariant_sha256" || { fail; return 1; }
  RESULT_STAGING_DIR=''
  RESULT_STAGING_IDENTITY=''
  RESULT_PUBLISHED=1
  [[ "$RESULT_PUBLISHED" == 1 ]] || { fail; return 1; }
  trap - EXIT INT TERM HUP
  printf 'Aster Phase 2 client credentials live topology passed\nresult=%s\noracle_sha256=%s\ndifferential_sha256=%s\ncandidate_invariants_sha256=%s\n' \
    "$RESULT_DIR" "$oracle_sha256" "$differential_sha256" "$invariant_sha256"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
