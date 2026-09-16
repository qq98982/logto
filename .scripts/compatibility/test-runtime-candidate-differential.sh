#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
BUILD_ROOT="${ASTER_PHASE1_BUILD_ROOT:-${DEFAULT_BUILD_ROOT}}"
readonly BUILD_ROOT
readonly DEFAULT_RUN_ROOT="${BUILD_ROOT}/aster-phase1-runtime-candidate-differential"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly COMPOSE_FILE="${REPO_ROOT}/docker-compose.phase1-runtime-candidate-differential.yml"
readonly PHASE1_CLI="${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/cli.js"
readonly SERVICES=(
  oracle-primary-postgres oracle-primary-redis oracle-primary-core
  oracle-foreign-postgres oracle-foreign-redis oracle-foreign-core
  oracle-phase0-postgres oracle-phase0-redis oracle-phase0-core
  candidate-primary-postgres candidate-primary-init candidate-primary-core
  candidate-foreign-postgres candidate-foreign-init candidate-foreign-core
  candidate-fixture-coordinator
  candidate-phase0-postgres candidate-phase0-init candidate-phase0-core
  candidate-phase0-fixture-coordinator
)
readonly PORTS=(3311 3411 3312 3412 3321 3421 3322 3422 3331 3431 3341 3441)
readonly LOOPBACK_PROXY_BINDINGS=(
  'oracle-primary-core|oracle-primary|3311|3001'
  'oracle-primary-core|oracle-primary|3411|3411'
  'oracle-foreign-core|oracle-foreign|3312|3001'
  'oracle-foreign-core|oracle-foreign|3412|3002'
  'candidate-primary-core|candidate-primary|3321|3001'
  'candidate-primary-core|candidate-primary|3421|3421'
  'candidate-foreign-core|candidate-foreign|3322|3001'
  'candidate-foreign-core|candidate-foreign|3422|3002'
  'oracle-phase0-core|oracle-phase0|3331|3001'
  'oracle-phase0-core|oracle-phase0|3431|3431'
  'candidate-phase0-core|candidate-phase0|3341|3001'
  'candidate-phase0-core|candidate-phase0|3441|3441'
)
failure_stage=initialization
fail() {
  printf 'Aster runtime candidate differential smoke failed (%s)\n' "${failure_stage}" >&2
  exit 1
}

require_safe_build_root() {
  local root=$1

  [[ "${root}" == /* && "${root}" != */ && "${root}" != *'//'* ]] || fail
  [[ "${root}" != *'/./'* && "${root}" != *'/../'* && ! "${root}" =~ [[:cntrl:]] ]] || fail
  case "${root}" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/var|/var/tmp|/dev/*|/proc/*|/sys/*) fail ;;
  esac
}

BUILD_ROOT_DEVICE=''
BUILD_ROOT_INODE=''

capture_build_root_identity() {
  local resolved owner mode

  require_safe_build_root "${BUILD_ROOT}"
  [[ -d "${BUILD_ROOT}" && ! -L "${BUILD_ROOT}" ]] || fail
  resolved="$(/usr/bin/realpath -e -- "${BUILD_ROOT}" 2>/dev/null || true)"
  owner="$(/usr/bin/stat -c %u -- "${BUILD_ROOT}" 2>/dev/null || true)"
  mode="$(/usr/bin/stat -c %a -- "${BUILD_ROOT}" 2>/dev/null || true)"
  [[ "${resolved}" == "${BUILD_ROOT}" && "${owner}" == "$(/usr/bin/id -u)" && "${mode}" == 700 ]] || fail
  BUILD_ROOT_DEVICE="$(/usr/bin/stat -c %d -- "${BUILD_ROOT}" 2>/dev/null || true)"
  BUILD_ROOT_INODE="$(/usr/bin/stat -c %i -- "${BUILD_ROOT}" 2>/dev/null || true)"
  [[ "${BUILD_ROOT_DEVICE}" =~ ^[0-9]+$ && "${BUILD_ROOT_INODE}" =~ ^[0-9]+$ ]] || fail
}

assert_build_root_identity() {
  local resolved owner mode device inode

  [[ -d "${BUILD_ROOT}" && ! -L "${BUILD_ROOT}" ]] || fail
  resolved="$(/usr/bin/realpath -e -- "${BUILD_ROOT}" 2>/dev/null || true)"
  owner="$(/usr/bin/stat -c %u -- "${BUILD_ROOT}" 2>/dev/null || true)"
  mode="$(/usr/bin/stat -c %a -- "${BUILD_ROOT}" 2>/dev/null || true)"
  device="$(/usr/bin/stat -c %d -- "${BUILD_ROOT}" 2>/dev/null || true)"
  inode="$(/usr/bin/stat -c %i -- "${BUILD_ROOT}" 2>/dev/null || true)"
  [[ "${resolved}" == "${BUILD_ROOT}" && "${owner}" == "$(/usr/bin/id -u)" && "${mode}" == 700 ]] || fail
  [[ "${device}" == "${BUILD_ROOT_DEVICE}" && "${inode}" == "${BUILD_ROOT_INODE}" ]] || fail
}

trusted_binary() {
  local name=$1 candidate resolved owner group mode
  if [[ "${name}" == /* ]]; then
    candidate="${name}"
  else
    candidate="$(command -v "${name}" 2>/dev/null || true)"
  fi
  resolved="$(realpath -e -- "${candidate}" 2>/dev/null || true)"
  [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] || fail
  owner="$(stat -c %u -- "${resolved}" 2>/dev/null || true)"
  group="$(stat -c %g -- "${resolved}" 2>/dev/null || true)"
  mode="$(stat -c %a -- "${resolved}" 2>/dev/null || true)"
  [[ "${owner}" == 0 || "${owner}" == "$(id -u)" ]] || fail
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#${mode} & 8#002)) && fail
  if ((8#${mode} & 8#020)); then
    [[ "${owner}" == "$(id -u)" && "${group}" == "$(id -g)" ]] || fail
  fi
  printf '%s' "${resolved}"
}

trusted_system_binary() {
  local resolved owner mode
  resolved="$(trusted_binary "$1")"
  owner="$(stat -c %u -- "${resolved}" 2>/dev/null || true)"
  mode="$(stat -c %a -- "${resolved}" 2>/dev/null || true)"
  [[ "${owner}" == 0 ]] || fail
  ((8#${mode} & 8#022)) && fail
  printf '%s' "${resolved}"
}

GIT_BIN="$(trusted_system_binary /usr/bin/git)"
NODE_BIN="$(trusted_binary node)"
PNPM_BIN="$(trusted_binary pnpm)"
SS_BIN="$(trusted_system_binary /usr/bin/ss)"
SETSID_BIN="$(trusted_system_binary /usr/bin/setsid)"
SOCAT_BIN="$(trusted_system_binary /usr/bin/socat)"
ENV_BIN="$(trusted_system_binary /usr/bin/env)"
PS_BIN="$(trusted_system_binary /usr/bin/ps)"
AWK_BIN="$(trusted_system_binary /usr/bin/awk)"
SHA256_BIN="$(trusted_system_binary /usr/bin/sha256sum)"
DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)"
readonly GIT_BIN NODE_BIN PNPM_BIN SS_BIN SETSID_BIN SOCAT_BIN ENV_BIN PS_BIN AWK_BIN SHA256_BIN
readonly DOCKER_BIN
export GIT_NO_REPLACE_OBJECTS=1
readonly GIT_AUTHORITY=("${GIT_BIN}" --no-replace-objects)

random_hex() {
  "${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" -e "process.stdout.write(require('node:crypto').randomBytes(Number(process.argv[1])).toString('hex'))" "$1"
}

require_private_root() {
  local root=$1 parent resolved owner mode

  assert_build_root_identity
  if [[ "${root}" != "${BUILD_ROOT}/"* || "${root}" == "${BUILD_ROOT}" || "${root}" == *'/../'* ]]; then
    fail
  fi
  parent="$(dirname -- "${root}")"
  resolved="$(/usr/bin/realpath -e -- "${parent}" 2>/dev/null || true)"
  [[ "${resolved}" == "${parent}" ]] || fail
  if [[ ! -e "${root}" ]]; then
    /usr/bin/mkdir -m 700 -- "${root}" || fail
  fi
  [[ -d "${root}" && ! -L "${root}" ]] || fail
  resolved="$(/usr/bin/realpath -e -- "${root}" 2>/dev/null || true)"
  owner="$(/usr/bin/stat -c %u -- "${root}" 2>/dev/null || true)"
  mode="$(/usr/bin/stat -c %a -- "${root}" 2>/dev/null || true)"
  [[ "${resolved}" == "${root}" && "${owner}" == "$(/usr/bin/id -u)" && "${mode}" == 700 ]] || fail
  assert_build_root_identity
}

immutable_image() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ || "$1" =~ ^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]
}

port_is_listening() {
  # shellcheck disable=SC2016
  "${SS_BIN}" -H -ltn | "${AWK_BIN}" -v expected="$1" '
    { address=$4; sub(/^.*:/, "", address); if (address == expected) found=1 }
    END { exit found ? 0 : 1 }
  '
}

port_is_listened_by_pid() {
  local port=$1 pid=$2

  [[ "${port}" =~ ^[1-9][0-9]{0,4}$ && "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  # shellcheck disable=SC2016
  "${SS_BIN}" -H -ltnp | "${AWK_BIN}" \
    -v expected_address="127.0.0.1:${port}" \
    -v expected_process="pid=${pid}([,)]|$)" '
      $4 == expected_address && $0 ~ expected_process { found=1 }
      END { exit found ? 0 : 1 }
    '
}

capture_build_root_identity
readonly BUILD_ROOT_DEVICE BUILD_ROOT_INODE

RUN_ROOT="${ASTER_RUN_ROOT:-${DEFAULT_RUN_ROOT}}"
require_private_root "${RUN_ROOT}"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_ROOT}/run.XXXXXX")"
EVIDENCE_DIR="${RUN_DIR}/evidence"
CONFORMANCE_ROOT="${RUN_DIR}/conformance"
SNAPSHOT_ROOT="${RUN_DIR}/snapshots"
ORACLE_SNAPSHOT_PATH="${SNAPSHOT_ROOT}/oracle-snapshots.json"
/usr/bin/mkdir -m 700 -- "${EVIDENCE_DIR}" "${CONFORMANCE_ROOT}" "${SNAPSHOT_ROOT}"
assert_build_root_identity
readonly RUN_DIR EVIDENCE_DIR CONFORMANCE_ROOT SNAPSHOT_ROOT ORACLE_SNAPSHOT_PATH

project_started=0
container_ids=()
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_TOKENS=()
NODE_RUN_PID=''
NODE_RUN_PGID=''
NODE_RUN_TOKEN=''
COMPOSE_ENV="${RUN_DIR}/compose.env"
PRIVATE_HOME="${RUN_DIR}/home"
BROWSER_TMP="${RUN_DIR}/browser-tmp"
XDG_RUNTIME="${RUN_DIR}/xdg-runtime"
PRIMARY_KEYRING_DIRECTORY="${RUN_DIR}/candidate-primary-keys"
FOREIGN_KEYRING_DIRECTORY="${RUN_DIR}/candidate-foreign-keys"
PHASE0_KEYRING_DIRECTORY="${RUN_DIR}/candidate-phase0-keys"
FIXTURE_DIRECTORY="${RUN_DIR}/fixture"
PHASE0_FIXTURE_DIRECTORY="${RUN_DIR}/phase0-fixture"
PRIMARY_CONFIG_FILE="${RUN_DIR}/candidate-primary.conf"
FOREIGN_CONFIG_FILE="${RUN_DIR}/candidate-foreign.conf"
PHASE0_CONFIG_FILE="${RUN_DIR}/candidate-phase0.conf"
FIXTURE_SOCKET="${FIXTURE_DIRECTORY}/aster-fixture.sock"
PHASE0_FIXTURE_SOCKET="${PHASE0_FIXTURE_DIRECTORY}/aster-fixture.sock"
REVIEW_PROFILE="${RUN_DIR}/review-profile.json"
/usr/bin/mkdir -m 700 -- "${PRIVATE_HOME}" "${BROWSER_TMP}" "${XDG_RUNTIME}" \
  "${PRIMARY_KEYRING_DIRECTORY}" "${FOREIGN_KEYRING_DIRECTORY}" \
  "${PHASE0_KEYRING_DIRECTORY}" "${FIXTURE_DIRECTORY}" "${PHASE0_FIXTURE_DIRECTORY}"
assert_build_root_identity
readonly COMPOSE_ENV PRIVATE_HOME BROWSER_TMP XDG_RUNTIME
readonly PRIMARY_KEYRING_DIRECTORY FOREIGN_KEYRING_DIRECTORY PHASE0_KEYRING_DIRECTORY
readonly FIXTURE_DIRECTORY PHASE0_FIXTURE_DIRECTORY PRIMARY_CONFIG_FILE FOREIGN_CONFIG_FILE
readonly PHASE0_CONFIG_FILE FIXTURE_SOCKET PHASE0_FIXTURE_SOCKET REVIEW_PROFILE
CLOSED_NODE_ENV=(
  env -i
  PATH='/usr/bin:/bin'
  HOME="${PRIVATE_HOME}"
  TMPDIR="${BROWSER_TMP}"
  XDG_RUNTIME_DIR="${XDG_RUNTIME}"
)
readonly CLOSED_NODE_ENV
CLOSED_BUILD_ENV=(
  env -i
  PATH="$(dirname -- "${NODE_BIN}"):$(dirname -- "${PNPM_BIN}"):/usr/bin:/bin"
  HOME="${PRIVATE_HOME}"
  TMPDIR="${BROWSER_TMP}"
  XDG_RUNTIME_DIR="${XDG_RUNTIME}"
  CI='true'
)
readonly CLOSED_BUILD_ENV
[[ "$("${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" --version 2>/dev/null || true)" == 'v22.23.2' ]] || fail
[[ "$("${CLOSED_BUILD_ENV[@]}" "${PNPM_BIN}" --version 2>/dev/null || true)" == '10.15.1' ]] || fail
project_name="aster-phase1-$(random_hex 8)"
readonly project_name

docker_cli() {
  "${ENV_BIN}" -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" "${DOCKER_BIN}" "$@"
}

compose() {
  docker_cli compose --env-file "${COMPOSE_ENV}" \
    --project-name "${project_name}" --file "${COMPOSE_FILE}" "$@"
}

container_network_ipv4() {
  local service=$1 network=$2 container_id network_name result

  container_id="$(compose ps -q "${service}" 2>/dev/null || true)"
  [[ "${container_id}" =~ ^[0-9a-f]{12,64}$ ]] || fail
  network_name="${project_name}_${network}"
  result="$(docker_cli inspect --format \
    "{{with index .NetworkSettings.Networks \"${network_name}\"}}{{.IPAddress}}{{end}}" \
    "${container_id}" 2>/dev/null || true)"
  [[ "${result}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail
  printf '%s' "${result}"
}

start_loopback_proxy() {
  local service=$1 network=$2 host_port=$3 container_port=$4
  local target_ip ownership_token proxy_pid proxy_pgid observed_pgid ownership_index attempt

  target_ip="$(container_network_ipv4 "${service}" "${network}")"
  ownership_token="$(random_hex 32)"
  ASTER_PHASE1_PROCESS_TOKEN="${ownership_token}" \
    "${ENV_BIN}" -i PATH='/usr/bin:/bin' "ASTER_PHASE1_PROCESS_TOKEN=${ownership_token}" \
    "${SETSID_BIN}" "${SOCAT_BIN}" \
    "TCP4-LISTEN:${host_port},bind=127.0.0.1,reuseaddr,fork" \
    "TCP4:${target_ip}:${container_port}" </dev/null >/dev/null 2>&1 &
  proxy_pid=$!
  proxy_pgid="${proxy_pid}"
  PROXY_PIDS+=("${proxy_pid}")
  PROXY_PGIDS+=("${proxy_pgid}")
  PROXY_TOKENS+=("${ownership_token}")
  for ((attempt=0; attempt<100; attempt++)); do
    kill -0 "${proxy_pid}" 2>/dev/null || break
    observed_pgid="$("${PS_BIN}" -o pgid= -p "${proxy_pid}" 2>/dev/null | /usr/bin/tr -d '[:space:]')"
    if [[ "${observed_pgid}" == "${proxy_pgid}" ]] && \
      process_has_ownership_token "${proxy_pid}" "${ownership_token}" && \
      port_is_listened_by_pid "${host_port}" "${proxy_pid}"; then
      return 0
    fi
    /usr/bin/sleep 0.05
  done
  if terminate_owned_process_group "${proxy_pid}" "${proxy_pgid}" "${ownership_token}"; then
    ownership_index=$((${#PROXY_PIDS[@]} - 1))
    unset "PROXY_PIDS[${ownership_index}]" "PROXY_PGIDS[${ownership_index}]" \
      "PROXY_TOKENS[${ownership_index}]"
  fi
  fail
}

owned_process_group_exists() {
  local pgid=$1

  [[ "${pgid}" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 -- "-${pgid}" 2>/dev/null
}

process_group_has_live_members() {
  local pgid=$1 process_table

  [[ "${pgid}" =~ ^[1-9][0-9]*$ ]] || return 2
  process_table="$("${PS_BIN}" -eo pgid=,stat=)" || return 2
  # shellcheck disable=SC2016
  "${AWK_BIN}" -v expected="${pgid}" '
    $1 == expected && $2 !~ /^Z/ { found=1 }
    END { exit found ? 0 : 1 }
  ' <<<"${process_table}"
}

process_has_ownership_token() {
  local pid=$1 token=$2 entry

  [[ "${pid}" =~ ^[1-9][0-9]*$ && "${token}" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ -r "/proc/${pid}/environ" ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ "${entry}" == "ASTER_PHASE1_PROCESS_TOKEN=${token}" ]] && return 0
  done <"/proc/${pid}/environ"
  return 1
}

process_group_has_trusted_leader() {
  local pid=$1 pgid=$2 token=$3 leader_identity observed_pgid observed_sid

  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  leader_identity="$("${PS_BIN}" -o pgid=,sid= -p "${pid}" 2>/dev/null || true)"
  read -r observed_pgid observed_sid <<<"${leader_identity}"
  [[ "${observed_pgid}" == "${pgid}" && "${observed_sid}" == "${pgid}" ]] || return 1
  process_has_ownership_token "${pid}" "${token}"
}

process_group_is_owned() {
  local pgid=$1 token=$2 member_pid member_pgid member_sid member_state
  local process_table found=0

  process_table="$("${PS_BIN}" -eo pid=,pgid=,sid=,stat=)" || return 1

  while read -r member_pid member_pgid member_sid member_state; do
    [[ "${member_pgid}" == "${pgid}" && "${member_state}" != Z* ]] || continue
    [[ "${member_sid}" == "${pgid}" ]] || return 1
    process_has_ownership_token "${member_pid}" "${token}" || return 1
    found=1
  done <<<"${process_table}"
  [[ "${found}" == 1 ]]
}

process_group_is_same_session() {
  local pgid=$1 member_pid member_pgid member_sid member_state process_table found=0

  process_table="$("${PS_BIN}" -eo pid=,pgid=,sid=,stat=)" || return 1
  while read -r member_pid member_pgid member_sid member_state; do
    [[ "${member_pgid}" == "${pgid}" && "${member_state}" != Z* ]] || continue
    [[ "${member_sid}" == "${pgid}" ]] || return 1
    found=1
  done <<<"${process_table}"
  [[ "${found}" == 1 ]]
}

terminate_owned_process_group() {
  local pid=$1 pgid=$2 token=$3 attempt group_status trusted_session=0

  group_status=0
  process_group_has_live_members "${pgid}" || group_status=$?
  if ((group_status == 0)); then
    if process_group_has_trusted_leader "${pid}" "${pgid}" "${token}"; then
      trusted_session=1
    else
      process_group_is_owned "${pgid}" "${token}" || return 1
    fi
    kill -TERM -- "-${pgid}" 2>/dev/null || true
    for ((attempt=0; attempt<20; attempt++)); do
      group_status=0
      process_group_has_live_members "${pgid}" || group_status=$?
      ((group_status == 0)) || break
      /usr/bin/sleep 0.05
    done
    ((group_status < 2)) || return 1
    if ((group_status == 0)); then
      if ((trusted_session == 1)); then
        process_group_is_same_session "${pgid}" || return 1
      else
        process_group_is_owned "${pgid}" "${token}" || return 1
      fi
      kill -KILL -- "-${pgid}" 2>/dev/null || true
    fi
    for ((attempt=0; attempt<200; attempt++)); do
      group_status=0
      process_group_has_live_members "${pgid}" || group_status=$?
      ((group_status == 0)) || break
      /usr/bin/sleep 0.01
    done
    ((group_status < 2)) || return 1
  elif ((group_status > 1)); then
    return 1
  elif [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    process_has_ownership_token "${pid}" "${token}" || return 1
    kill -TERM -- "${pid}" 2>/dev/null || true
    for ((attempt=0; attempt<20; attempt++)); do
      kill -0 "${pid}" 2>/dev/null || break
      /usr/bin/sleep 0.05
    done
    if kill -0 "${pid}" 2>/dev/null; then
      process_has_ownership_token "${pid}" "${token}" || return 1
      kill -KILL -- "${pid}" 2>/dev/null || true
    fi
  fi
  [[ -z "${pid}" ]] || wait "${pid}" 2>/dev/null || true
  group_status=0
  process_group_has_live_members "${pgid}" || group_status=$?
  ((group_status == 1))
}

cleanup() {
  local exit_code=$? cleanup_failed=0 remaining
  trap - EXIT INT TERM HUP

  if [[ -n "${NODE_RUN_PGID}" ]]; then
    terminate_owned_process_group \
      "${NODE_RUN_PID}" "${NODE_RUN_PGID}" "${NODE_RUN_TOKEN}" || cleanup_failed=1
  elif [[ -n "${NODE_RUN_PID}" ]] && kill -0 "${NODE_RUN_PID}" 2>/dev/null; then
    process_has_ownership_token "${NODE_RUN_PID}" "${NODE_RUN_TOKEN}" || cleanup_failed=1
    if [[ "${cleanup_failed}" == 0 ]]; then
      kill -TERM -- "${NODE_RUN_PID}" 2>/dev/null || cleanup_failed=1
      wait "${NODE_RUN_PID}" 2>/dev/null || true
    fi
  fi
  NODE_RUN_PID=''
  NODE_RUN_PGID=''
  NODE_RUN_TOKEN=''

  for ((index=${#PROXY_PGIDS[@]} - 1; index >= 0; index--)); do
    terminate_owned_process_group \
      "${PROXY_PIDS[index]}" "${PROXY_PGIDS[index]}" "${PROXY_TOKENS[index]}" || cleanup_failed=1
  done
  PROXY_PIDS=()
  PROXY_PGIDS=()
  PROXY_TOKENS=()

  if [[ "${project_started}" == 1 ]]; then
    for ((index=${#container_ids[@]} - 1; index >= 0; index--)); do
      docker_cli rm --force "${container_ids[index]}" >/dev/null 2>&1 || cleanup_failed=1
    done
    remaining="$(docker_cli ps -aq --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    while IFS= read -r resource_id; do
      [[ -z "${resource_id}" ]] || docker_cli rm --force "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
    done <<<"${remaining}"
    remaining="$(docker_cli ps -aq --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "${remaining}" ]] || cleanup_failed=1
    remaining="$(docker_cli network ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    while IFS= read -r resource_id; do
      [[ -z "${resource_id}" ]] || docker_cli network rm "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
    done <<<"${remaining}"
    remaining="$(docker_cli network ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "${remaining}" ]] || cleanup_failed=1
    remaining="$(docker_cli volume ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    while IFS= read -r resource_id; do
      [[ -z "${resource_id}" ]] || docker_cli volume rm "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
    done <<<"${remaining}"
    remaining="$(docker_cli volume ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "${remaining}" ]] || cleanup_failed=1
  fi
  rm -f -- "${COMPOSE_ENV}"
  if [[ "${cleanup_failed}" == 0 && -d "${RUN_DIR}" && ! -L "${RUN_DIR}" ]]; then
    rm -rf -- "${RUN_DIR}" || cleanup_failed=1
  fi
  if [[ "${exit_code}" == 0 && "${cleanup_failed}" != 0 ]]; then
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

docker_cli compose version >/dev/null 2>&1 || fail
[[ -f "${COMPOSE_FILE}" && -f "${PHASE1_CLI}" ]] || fail
[[ -f "${REPO_ROOT}/.scripts/compatibility/phase1-candidate-state-driver.sh" ]] || fail

repo_origin="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
case "${repo_origin}" in
  'https://github.com/qq98982/logto.git'|'git@github.com:qq98982/logto.git'|'ssh://git@github.com/qq98982/logto.git') ;;
  *) fail ;;
esac
[[ -z "$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail

ASTER_ROOT="${ASTER_PHASE1_ASTER_ROOT:?required}"
ORACLE_IMAGE_INPUT="${ASTER_PHASE1_ORACLE_IMAGE:?required}"
CANDIDATE_IMAGE_INPUT="${ASTER_PHASE1_CANDIDATE_IMAGE:?required}"
[[ "${ASTER_ROOT}" == /* && -d "${ASTER_ROOT}" && ! -L "${ASTER_ROOT}" ]] || fail
ASTER_ROOT="$(/usr/bin/realpath -e -- "${ASTER_ROOT}")"
readonly ASTER_ROOT ORACLE_IMAGE_INPUT CANDIDATE_IMAGE_INPUT
aster_origin="$("${GIT_AUTHORITY[@]}" -C "${ASTER_ROOT}" remote get-url origin 2>/dev/null || true)"
case "${aster_origin}" in
  'https://github.com/qq98982/aster.git'|'git@github.com:qq98982/aster.git'|'ssh://git@github.com/qq98982/aster.git') ;;
  *) fail ;;
esac
[[ -z "$("${GIT_AUTHORITY[@]}" -C "${ASTER_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail
PROFILE_SOURCE="${ASTER_ROOT}/compatibility/phase-1-profile.json"
SCHEMA_SOURCE="${ASTER_ROOT}/compatibility/phase-1-profile.schema.json"
[[ -f "${PROFILE_SOURCE}" && -f "${SCHEMA_SOURCE}" && ! -L "${PROFILE_SOURCE}" && ! -L "${SCHEMA_SOURCE}" ]] || fail
readonly PROFILE_SOURCE SCHEMA_SOURCE

readonly POSTGRES_IMAGE='docker.io/library/postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
readonly REDIS_IMAGE='docker.io/library/redis:6-alpine@sha256:d0c875bdacfb5c4d2c2d9124de3f53cee1dc9ceff8936bd459fabc135cb33015'
immutable_image "${POSTGRES_IMAGE}" || fail
immutable_image "${REDIS_IMAGE}" || fail
immutable_image "${ORACLE_IMAGE_INPUT}" || fail
immutable_image "${CANDIDATE_IMAGE_INPUT}" || fail
ORACLE_IMAGE="$(docker_cli image inspect --format '{{.Id}}' "${ORACLE_IMAGE_INPUT}" 2>/dev/null || true)"
CANDIDATE_IMAGE="$(docker_cli image inspect --format '{{.Id}}' "${CANDIDATE_IMAGE_INPUT}" 2>/dev/null || true)"
[[ "${ORACLE_IMAGE}" =~ ^sha256:[0-9a-f]{64}$ && "${CANDIDATE_IMAGE}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
readonly ORACLE_IMAGE CANDIDATE_IMAGE

random_uuid() {
  local value
  value="$(random_hex 16)"
  printf '%s-%s-%s-%s-%s' "${value:0:8}" "${value:8:4}" "${value:12:4}" "${value:16:4}" "${value:20:12}"
}

primary_deployment_id="$(random_uuid)"
foreign_deployment_id="$(random_uuid)"
phase0_deployment_id="$(random_uuid)"
primary_sentinel="$(random_hex 32)"
foreign_sentinel="$(random_hex 32)"
phase0_sentinel="$(random_hex 32)"
[[ "$(printf '%s\n' "${primary_deployment_id}" "${foreign_deployment_id}" "${phase0_deployment_id}" | /usr/bin/sort -u | /usr/bin/wc -l)" == 3 ]] || fail
[[ "$(printf '%s\n' "${primary_sentinel}" "${foreign_sentinel}" "${phase0_sentinel}" | /usr/bin/sort -u | /usr/bin/wc -l)" == 3 ]] || fail
printf 'deployment_id=%s\ndatabase_sentinel=%s\n' "${primary_deployment_id}" "${primary_sentinel}" >"${PRIMARY_CONFIG_FILE}"
printf 'deployment_id=%s\ndatabase_sentinel=%s\n' "${foreign_deployment_id}" "${foreign_sentinel}" >"${FOREIGN_CONFIG_FILE}"
printf 'deployment_id=%s\ndatabase_sentinel=%s\n' "${phase0_deployment_id}" "${phase0_sentinel}" >"${PHASE0_CONFIG_FILE}"
/usr/bin/chmod 0400 "${PRIMARY_CONFIG_FILE}" "${FOREIGN_CONFIG_FILE}" "${PHASE0_CONFIG_FILE}"

failure_stage=build
"${CLOSED_BUILD_ENV[@]}" "${PNPM_BIN}" --dir "${REPO_ROOT}/packages/integration-tests" build >/dev/null || fail
H_HEAD="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" rev-parse HEAD)"
[[ "${H_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
failure_stage=review-profile
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${PHASE1_CLI}" prepare-review-profile \
  --source-profile "${PROFILE_SOURCE}" --schema "${SCHEMA_SOURCE}" \
  --harness-commit "${H_HEAD}" --output "${REVIEW_PROFILE}" >/dev/null || fail
[[ -f "${REVIEW_PROFILE}" && ! -L "${REVIEW_PROFILE}" ]] || fail

for port in "${PORTS[@]}"; do
  port_is_listening "${port}" && fail
done

cat >"${COMPOSE_ENV}" <<EOF
ASTER_PHASE1_POSTGRES_IMAGE=${POSTGRES_IMAGE}
ASTER_PHASE1_REDIS_IMAGE=${REDIS_IMAGE}
ASTER_PHASE1_ORACLE_IMAGE=${ORACLE_IMAGE}
ASTER_PHASE1_CANDIDATE_IMAGE=${CANDIDATE_IMAGE}
ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_ORACLE_PRIMARY_SECRET_VAULT_KEK=$(random_hex 32)
ASTER_PHASE1_ORACLE_PRIMARY_STATUS_API_KEY=$(random_hex 32)
ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_ORACLE_FOREIGN_SECRET_VAULT_KEK=$(random_hex 32)
ASTER_PHASE1_ORACLE_FOREIGN_STATUS_API_KEY=$(random_hex 32)
ASTER_PHASE1_ORACLE_PHASE0_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_ORACLE_PHASE0_SECRET_VAULT_KEK=$(random_hex 32)
ASTER_PHASE1_ORACLE_PHASE0_STATUS_API_KEY=$(random_hex 32)
ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_CANDIDATE_PHASE0_POSTGRES_PASSWORD=$(random_hex 32)
ASTER_PHASE1_RUNTIME_UID=$(id -u)
ASTER_PHASE1_RUNTIME_GID=$(id -g)
ASTER_PHASE1_PRIMARY_CONFIG_FILE=${PRIMARY_CONFIG_FILE}
ASTER_PHASE1_FOREIGN_CONFIG_FILE=${FOREIGN_CONFIG_FILE}
ASTER_PHASE1_PHASE0_CONFIG_FILE=${PHASE0_CONFIG_FILE}
ASTER_PHASE1_PRIMARY_KEYRING_DIRECTORY=${PRIMARY_KEYRING_DIRECTORY}
ASTER_PHASE1_FOREIGN_KEYRING_DIRECTORY=${FOREIGN_KEYRING_DIRECTORY}
ASTER_PHASE1_PHASE0_KEYRING_DIRECTORY=${PHASE0_KEYRING_DIRECTORY}
ASTER_PHASE1_FIXTURE_DIRECTORY=${FIXTURE_DIRECTORY}
ASTER_PHASE1_FIXTURE_SOCKET=${FIXTURE_SOCKET}
ASTER_PHASE1_PHASE0_FIXTURE_DIRECTORY=${PHASE0_FIXTURE_DIRECTORY}
ASTER_PHASE1_PHASE0_FIXTURE_SOCKET=${PHASE0_FIXTURE_SOCKET}
EOF
/usr/bin/chmod 0600 "${COMPOSE_ENV}"

compose config --quiet >/dev/null || fail
project_started=1
failure_stage=compose-up
compose up --detach "${SERVICES[@]}" >/dev/null || fail

failure_stage=topology-readiness
deadline=$((SECONDS + 600))
while ((SECONDS < deadline)); do
  ready=1
  for service in "${SERVICES[@]}"; do
    container_id="$(compose ps -q "${service}" 2>/dev/null || true)"
    [[ "${container_id}" =~ ^[0-9a-f]{12,64}$ ]] || { ready=0; break; }
    state="$(docker_cli inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${container_id}")"
    case "${service}" in
      candidate-primary-init|candidate-foreign-init|candidate-phase0-init)
        [[ "${state}" == 'exited|0|' ]] || ready=0
        ;;
      *)
        [[ "${state}" == 'running|0|healthy' ]] || ready=0
        ;;
    esac
    ((ready == 1)) || break
  done
  ((ready == 1)) && break
  /usr/bin/sleep 1
done
((ready == 1)) || fail

ORACLE_PRIMARY_POSTGRES_CONTAINER_ID=''
ORACLE_FOREIGN_POSTGRES_CONTAINER_ID=''
CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID=''
CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID=''
for service in "${SERVICES[@]}"; do
  container_id="$(compose ps -q "${service}")"
  container_ids+=("${container_id}")
  case "${service}" in
    oracle-primary-postgres) ORACLE_PRIMARY_POSTGRES_CONTAINER_ID="${container_id}" ;;
    oracle-foreign-postgres) ORACLE_FOREIGN_POSTGRES_CONTAINER_ID="${container_id}" ;;
    candidate-primary-postgres) CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID="${container_id}" ;;
    candidate-foreign-postgres) CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID="${container_id}" ;;
  esac
done
[[ -n "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" && -n "${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}" && -n "${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}" && -n "${CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID}" ]] || fail

for binding in "${LOOPBACK_PROXY_BINDINGS[@]}"; do
  IFS='|' read -r proxy_service proxy_network proxy_host_port proxy_container_port <<<"${binding}"
  start_loopback_proxy "${proxy_service}" "${proxy_network}" "${proxy_host_port}" "${proxy_container_port}"
done

http_ready() {
  local port=$1 path=$2 marker=$3 response
  for _ in {1..90}; do
    response="$({ printf 'GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' "${path}"; } | /usr/bin/nc -w 2 127.0.0.1 "${port}" 2>/dev/null || true)"
    [[ "${response}" == *' 200 OK'* && "${response}" == *"${marker}"* ]] && return 0
    /usr/bin/sleep 1
  done
  return 1
}
for port in "${PORTS[@]}"; do
  http_ready "${port}" '/oidc/.well-known/openid-configuration' 'issuer' || fail
done
[[ -S "${FIXTURE_SOCKET}" && -S "${PHASE0_FIXTURE_SOCKET}" && "${FIXTURE_SOCKET}" != "${PHASE0_FIXTURE_SOCKET}" ]] || fail

key_set_sha256() {
  local container_id=$1 tenant_id=$2 config_key=$3 result
  result="$(docker_cli exec --interactive --user postgres "${container_id}" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --set="tenant_id=${tenant_id}" --set="config_key=${config_key}" \
    --username aster --dbname aster <<'SQL'
with key_ids as (
  select element ->> 'id' as id from logto_configs
  cross join lateral jsonb_array_elements(value) as element
  where tenant_id = :'tenant_id' and key = :'config_key'
)
select encode(sha256(convert_to(string_agg(id, ',' order by id), 'UTF8')), 'hex')
from key_ids having count(*) > 0 and bool_and(id is not null and id <> '');
SQL
)" || fail
  result="$(printf '%s' "${result}" | /usr/bin/tr -d '[:space:]')"
  [[ "${result}" =~ ^[0-9a-f]{64}$ ]] || fail
  printf '%s' "${result}"
}

candidate_key_id() {
  local service=$1 file=$2 line
  line="$(docker_cli exec --user "$(id -u):$(id -g)" "$(compose ps -q "${service}")" \
    /usr/local/bin/aster-admin master-key active-id --file "${file}" 2>/dev/null)" || fail
  [[ "${line}" =~ ^active\ master\ key:\ generation=1\ key_id=(aster-mk-[0-9a-f]{32})$ ]] || fail
  printf '%s' "${BASH_REMATCH[1]}"
}

domain_sha256() {
  # The awk program intentionally uses the literal first field.
  # shellcheck disable=SC2016
  printf '%s' "$1" | "${SHA256_BIN}" | "${AWK_BIN}" '{print $1}'
}

ORACLE_DATA_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" default oidc.cookieKeys)"
ORACLE_DATA_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" default oidc.privateKeys)"
ORACLE_ADMIN_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" admin oidc.cookieKeys)"
ORACLE_ADMIN_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" admin oidc.privateKeys)"
ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}" default oidc.cookieKeys)"
ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}" default oidc.privateKeys)"
primary_key_id="$(candidate_key_id candidate-primary-core /var/lib/aster/primary/aster-master-key.json)"
foreign_key_id="$(candidate_key_id candidate-foreign-core /var/lib/aster/foreign/aster-master-key.json)"
CANDIDATE_DATA_COOKIE_KEY_SET_SHA256="$(domain_sha256 "${primary_key_id}:data:cookie")"
CANDIDATE_DATA_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${primary_key_id}:data:signing")"
CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256="$(domain_sha256 "${primary_key_id}:admin:cookie")"
CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${primary_key_id}:admin:signing")"
CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256="$(domain_sha256 "${foreign_key_id}:data:cookie")"
CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${foreign_key_id}:data:signing")"

NODE_RUN_TOKEN="$(random_hex 32)"
PUBLIC_ENV=(
  env -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${BROWSER_TMP}" XDG_RUNTIME_DIR="${XDG_RUNTIME}"
  ASTER_PHASE1_MODE='runtime-candidate' ASTER_PHASE1_PROCESS_TOKEN="${NODE_RUN_TOKEN}"
  ASTER_PHASE1_BUILD_ROOT="${BUILD_ROOT}" ASTER_PHASE1_ORACLE_IMAGE_DIGEST="${ORACLE_IMAGE}"
  ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST="${CANDIDATE_IMAGE}" ASTER_PHASE1_TOPOLOGY_ID="${project_name}"
  ASTER_PHASE1_CONFORMANCE_ROOT="${CONFORMANCE_ROOT}" ASTER_PHASE1_ORACLE_SNAPSHOT_PATH="${ORACLE_SNAPSHOT_PATH}"
  ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_CONTAINER_ID="${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}"
  ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_CONTAINER_ID="${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}"
  ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID="${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}"
  ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID="${CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID}"
  ASTER_PHASE1_ORACLE_DATA_COOKIE_KEY_SET_SHA256="${ORACLE_DATA_COOKIE_KEY_SET_SHA256}"
  ASTER_PHASE1_ORACLE_DATA_SIGNING_KEY_SET_SHA256="${ORACLE_DATA_SIGNING_KEY_SET_SHA256}"
  ASTER_PHASE1_ORACLE_ADMIN_COOKIE_KEY_SET_SHA256="${ORACLE_ADMIN_COOKIE_KEY_SET_SHA256}"
  ASTER_PHASE1_ORACLE_ADMIN_SIGNING_KEY_SET_SHA256="${ORACLE_ADMIN_SIGNING_KEY_SET_SHA256}"
  ASTER_PHASE1_ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256="${ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256}"
  ASTER_PHASE1_ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256="${ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256}"
  ASTER_PHASE1_CANDIDATE_DATA_COOKIE_KEY_SET_SHA256="${CANDIDATE_DATA_COOKIE_KEY_SET_SHA256}"
  ASTER_PHASE1_CANDIDATE_DATA_SIGNING_KEY_SET_SHA256="${CANDIDATE_DATA_SIGNING_KEY_SET_SHA256}"
  ASTER_PHASE1_CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256="${CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256}"
  ASTER_PHASE1_CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256="${CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256}"
  ASTER_PHASE1_CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256="${CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256}"
  ASTER_PHASE1_CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="${CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256}"
  ASTER_PHASE1_ORACLE_URL='http://localhost:3311' ASTER_PHASE1_ORACLE_ADMIN_URL='http://localhost:3411'
  ASTER_PHASE1_ORACLE_FOREIGN_URL='http://localhost:3312' ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL='http://localhost:3412'
  ASTER_PHASE1_CANDIDATE_URL='http://localhost:3321' ASTER_PHASE1_CANDIDATE_ADMIN_URL='http://localhost:3421'
  ASTER_PHASE1_CANDIDATE_FOREIGN_URL='http://localhost:3322' ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL='http://localhost:3422'
  ASTER_PHASE1_PHASE0_ORACLE_URL='http://localhost:3331' ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL='http://localhost:3431'
  ASTER_PHASE1_PHASE0_CANDIDATE_URL='http://localhost:3341' ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL='http://localhost:3441'
  ASTER_FIXTURE_SOCKET="${FIXTURE_SOCKET}" ASTER_PHASE1_PHASE0_CANDIDATE_FIXTURE_SOCKET="${PHASE0_FIXTURE_SOCKET}"
  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"
)
ASTER_PHASE1_PROCESS_TOKEN="${NODE_RUN_TOKEN}" "${SETSID_BIN}" "${PUBLIC_ENV[@]}" \
  "${NODE_BIN}" "${PHASE1_CLI}" run-differential --mode runtime-candidate \
  --profile "${REVIEW_PROFILE}" --schema "${SCHEMA_SOURCE}" \
  --observation-controls --discovery-extra-control --candidate-invariant-controls >/dev/null &
NODE_RUN_PID=$!
NODE_RUN_PGID="${NODE_RUN_PID}"
wait "${NODE_RUN_PID}" || fail
NODE_RUN_PID=''
NODE_RUN_PGID=''
NODE_RUN_TOKEN=''

[[ -f "${EVIDENCE_DIR}/phase-1-differential.json" && ! -L "${EVIDENCE_DIR}/phase-1-differential.json" ]] || fail
[[ "$(find "${EVIDENCE_DIR}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n')" == 'phase-1-differential.json' ]] || fail
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" --input-type=module - "${EVIDENCE_DIR}/phase-1-differential.json" <<'NODE'
import { readFile } from 'node:fs/promises';
const value = JSON.parse(await readFile(process.argv[2], 'utf8'));
if (value.schemaVersion !== 1 || value.mode !== 'runtime-candidate' || value.sanitizerSuccess !== true) process.exit(1);
if (!Array.isArray(value.scenarios) || value.scenarios.length !== 22) process.exit(1);
if (value.scenarios.some((scenario) => !Array.isArray(scenario.differences) || scenario.differences.length !== 0)) process.exit(1);
const ids = value.scenarios.map(({ id }) => id);
if (JSON.stringify(ids) !== JSON.stringify([...ids].sort())) process.exit(1);
NODE

printf '%s\n' 'Aster runtime candidate differential smoke passed'
