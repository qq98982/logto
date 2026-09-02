#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly REFERENCE_COMMIT='6852a7b8c8984c5c12b2061e8c51faa310a36412'
readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
BUILD_ROOT="${ASTER_PHASE1_BUILD_ROOT:-${DEFAULT_BUILD_ROOT}}"
readonly BUILD_ROOT
readonly DEFAULT_RUN_ROOT="${BUILD_ROOT}/aster-phase1-compatibility"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly COMPOSE_FILE="${REPO_ROOT}/docker-compose.phase1-compatibility.yml"
readonly SNAPSHOT_CLI="${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/snapshots/cli.js"
readonly MANIFEST_CLI="${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/evidence-manifest.js"
readonly RESULT_CLI="${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/harness-result.js"
readonly SERVICES=(
  oracle-primary-postgres oracle-primary-redis oracle-primary-core
  oracle-foreign-postgres oracle-foreign-redis oracle-foreign-core
  candidate-primary-postgres candidate-primary-redis candidate-primary-core
  candidate-foreign-postgres candidate-foreign-redis candidate-foreign-core
  oracle-phase0-postgres oracle-phase0-redis oracle-phase0-core
  candidate-phase0-postgres candidate-phase0-redis candidate-phase0-core
)
readonly PORTS=(3311 3411 3312 3412 3321 3421 3322 3422 3331 3431 3341 3441)
readonly EVIDENCE_NAMES=(
  phase-1-browser.json
  phase-1-candidate-invariants.json
  phase-1-conformance.json
  phase-1-differential.json
)

fail() {
  printf '%s\n' 'Phase 1 lifecycle failed.' >&2
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
TAR_BIN="$(trusted_system_binary /usr/bin/tar)"
SS_BIN="$(trusted_system_binary /usr/bin/ss)"
SETSID_BIN="$(trusted_system_binary /usr/bin/setsid)"
DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)"
readonly GIT_BIN NODE_BIN PNPM_BIN TAR_BIN SS_BIN SETSID_BIN DOCKER_BIN
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
  "${SS_BIN}" -H -ltn | awk -v expected="$1" '
    { address=$4; sub(/^.*:/, "", address); if (address == expected) found=1 }
    END { exit found ? 0 : 1 }
  '
}

capture_build_root_identity
readonly BUILD_ROOT_DEVICE BUILD_ROOT_INODE

RUN_ROOT="${ASTER_RUN_ROOT:-${DEFAULT_RUN_ROOT}}"
require_private_root "${RUN_ROOT}"
SNAPSHOT_ROOT="${RUN_ROOT}/snapshots"
require_private_root "${SNAPSHOT_ROOT}"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_ROOT}/run.XXXXXX")"
EVIDENCE_DIR="${RUN_DIR}/evidence"
CONFORMANCE_ROOT="${RUN_DIR}/conformance"
ORACLE_SNAPSHOT_PATH="${SNAPSHOT_ROOT}/oracle-snapshots.json"
/usr/bin/mkdir -m 700 -- "${EVIDENCE_DIR}" "${CONFORMANCE_ROOT}"
assert_build_root_identity
readonly RUN_DIR EVIDENCE_DIR CONFORMANCE_ROOT SNAPSHOT_ROOT ORACLE_SNAPSHOT_PATH

project_started=0
container_ids=()
NODE_RUN_PID=''
NODE_RUN_PGID=''
COMPOSE_ENV="${RUN_DIR}/compose.env"
PRIVATE_HOME="${RUN_DIR}/home"
BROWSER_TMP="${RUN_DIR}/browser-tmp"
XDG_RUNTIME="${RUN_DIR}/xdg-runtime"
/usr/bin/mkdir -m 700 -- "${PRIVATE_HOME}" "${BROWSER_TMP}" "${XDG_RUNTIME}"
assert_build_root_identity
readonly COMPOSE_ENV PRIVATE_HOME BROWSER_TMP XDG_RUNTIME
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

compose() {
  env -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" \
    "${DOCKER_BIN}" compose --env-file "${COMPOSE_ENV}" \
    --project-name "${project_name}" --file "${COMPOSE_FILE}" "$@"
}

owned_process_group_exists() {
  local pgid=$1

  [[ "${pgid}" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 -- "-${pgid}" 2>/dev/null
}

terminate_owned_process_group() {
  local pid=$1 pgid=$2 attempt

  if owned_process_group_exists "${pgid}"; then
    kill -TERM -- "-${pgid}" 2>/dev/null || true
    for ((attempt=0; attempt<20; attempt++)); do
      owned_process_group_exists "${pgid}" || break
      /usr/bin/sleep 0.05
    done
    if owned_process_group_exists "${pgid}"; then
      kill -KILL -- "-${pgid}" 2>/dev/null || true
    fi
    for ((attempt=0; attempt<200; attempt++)); do
      owned_process_group_exists "${pgid}" || break
      /usr/bin/sleep 0.01
    done
  fi
  [[ -z "${pid}" ]] || wait "${pid}" 2>/dev/null || true
  ! owned_process_group_exists "${pgid}"
}

cleanup() {
  local exit_code=$? cleanup_failed=0 remaining
  trap - EXIT INT TERM HUP

  if [[ -n "${NODE_RUN_PGID}" ]]; then
    terminate_owned_process_group "${NODE_RUN_PID}" "${NODE_RUN_PGID}" || cleanup_failed=1
  elif [[ -n "${NODE_RUN_PID}" ]] && kill -0 "${NODE_RUN_PID}" 2>/dev/null; then
    kill -TERM -- "${NODE_RUN_PID}" 2>/dev/null || cleanup_failed=1
    wait "${NODE_RUN_PID}" 2>/dev/null || true
  fi
  NODE_RUN_PID=''
  NODE_RUN_PGID=''

  if [[ "${project_started}" == 1 ]]; then
    for ((index=${#container_ids[@]} - 1; index >= 0; index--)); do
      "${DOCKER_BIN}" rm --force "${container_ids[index]}" >/dev/null 2>&1 || cleanup_failed=1
    done
    remaining="$("${DOCKER_BIN}" ps -aq --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    while IFS= read -r resource_id; do
      [[ -z "${resource_id}" ]] || "${DOCKER_BIN}" rm --force "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
    done <<<"${remaining}"
    remaining="$("${DOCKER_BIN}" ps -aq --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "${remaining}" ]] || cleanup_failed=1
    remaining="$("${DOCKER_BIN}" network ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    while IFS= read -r resource_id; do
      [[ -z "${resource_id}" ]] || "${DOCKER_BIN}" network rm "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
    done <<<"${remaining}"
    remaining="$("${DOCKER_BIN}" network ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "${remaining}" ]] || cleanup_failed=1
    remaining="$("${DOCKER_BIN}" volume ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    while IFS= read -r resource_id; do
      [[ -z "${resource_id}" ]] || "${DOCKER_BIN}" volume rm "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
    done <<<"${remaining}"
    remaining="$("${DOCKER_BIN}" volume ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "${remaining}" ]] || cleanup_failed=1
  fi
  rm -f -- "${COMPOSE_ENV}"
  rm -rf -- "${BROWSER_TMP}" "${XDG_RUNTIME}"
  if [[ "${exit_code}" == 0 && "${cleanup_failed}" != 0 ]]; then
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

"${DOCKER_BIN}" compose version >/dev/null 2>&1 || fail
[[ -f "${REPO_ROOT}/.scripts/compatibility/run-phase1-conformance.sh" ]] || fail
[[ -f "${REPO_ROOT}/.scripts/compatibility/phase1-reference-state-driver.sh" ]] || fail

repo_origin="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
case "${repo_origin}" in
  'https://github.com/qq98982/logto.git'|'git@github.com:qq98982/logto.git'|'ssh://git@github.com/qq98982/logto.git') ;;
  *) fail ;;
esac
[[ -z "$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail

prepare_mirror_image() {
  local context iid_file image_id

  [[ "$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)" =~ ^[0-9a-f]{40}$ ]] || fail
  "${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" cat-file -e "${REFERENCE_COMMIT}^{commit}" 2>/dev/null || fail
  [[ "$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" rev-parse "${REFERENCE_COMMIT}^{commit}" 2>/dev/null || true)" == "${REFERENCE_COMMIT}" ]] || fail
  context="${RUN_DIR}/oracle-source"
  mkdir -m 700 -- "${context}"
  "${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" archive --format=tar "${REFERENCE_COMMIT}" | "${TAR_BIN}" -x -C "${context}" || fail
  [[ -f "${context}/Dockerfile.integration" ]] || fail
  iid_file="${RUN_DIR}/mirror-image-id"
  "${DOCKER_BIN}" build --iidfile "${iid_file}" --file "${context}/Dockerfile.integration" "${context}" >/dev/null || fail
  image_id="$(tr -d '[:space:]' <"${iid_file}")"
  immutable_image "${image_id}" || fail
  "${CLOSED_BUILD_ENV[@]}" "${PNPM_BIN}" --dir "${REPO_ROOT}/packages/integration-tests" build >/dev/null || fail
  "${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${SNAPSHOT_CLI}" write-prepared-mirror \
    --output "${RUN_ROOT}/prepared-mirror.json" \
    --source-commit "${REFERENCE_COMMIT}" \
    --image-digest "${image_id}" >/dev/null || fail
}

if (($# == 1)) && [[ "$1" == '--prepare-mirror-image' ]]; then
  prepare_mirror_image
  exit 0
fi
(($# == 0)) || fail

MODE="${ASTER_PHASE1_MODE:-}"
PROFILE="${ASTER_PHASE1_PROFILE:-}"
SCHEMA="${ASTER_PHASE1_SCHEMA:-}"
[[ "${MODE}" == 'review-candidate' || "${MODE}" == 'mirror-control' || "${MODE}" == 'runtime-candidate' ]] || fail
[[ "${PROFILE}" == /* && -f "${PROFILE}" && ! -L "${PROFILE}" ]] || fail
[[ "${SCHEMA}" == /* && -f "${SCHEMA}" && ! -L "${SCHEMA}" ]] || fail
"${CLOSED_BUILD_ENV[@]}" "${PNPM_BIN}" --dir "${REPO_ROOT}/packages/integration-tests" build >/dev/null || fail

POSTGRES_IMAGE="${ASTER_PHASE1_POSTGRES_IMAGE:-}"
REDIS_IMAGE="${ASTER_PHASE1_REDIS_IMAGE:-}"
immutable_image "${POSTGRES_IMAGE}" || fail
immutable_image "${REDIS_IMAGE}" || fail

if [[ "${MODE}" == 'mirror-control' ]]; then
  MIRROR_IMAGE="${ASTER_PHASE1_MIRROR_IMAGE_DIGEST:-}"
  [[ "${MIRROR_IMAGE}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
  "${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${SNAPSHOT_CLI}" verify-prepared-mirror \
    --input "${RUN_ROOT}/prepared-mirror.json" \
    --source-commit "${REFERENCE_COMMIT}" \
    --image-digest "${MIRROR_IMAGE}" >/dev/null || fail
  ORACLE_IMAGE="${MIRROR_IMAGE}"
  CANDIDATE_IMAGE="${MIRROR_IMAGE}"
else
  ORACLE_IMAGE="${ASTER_PHASE1_ORACLE_IMAGE_DIGEST:-}"
  CANDIDATE_IMAGE="${ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST:-}"
  immutable_image "${ORACLE_IMAGE}" || fail
  immutable_image "${CANDIDATE_IMAGE}" || fail
fi

assert_build_root_identity
{
  printf 'ASTER_PHASE1_POSTGRES_IMAGE=%s\n' "${POSTGRES_IMAGE}"
  printf 'ASTER_PHASE1_REDIS_IMAGE=%s\n' "${REDIS_IMAGE}"
  printf 'ASTER_PHASE1_ORACLE_IMAGE=%s\n' "${ORACLE_IMAGE}"
  printf 'ASTER_PHASE1_CANDIDATE_IMAGE=%s\n' "${CANDIDATE_IMAGE}"
  for stack in \
    ORACLE_PRIMARY ORACLE_FOREIGN CANDIDATE_PRIMARY CANDIDATE_FOREIGN \
    ORACLE_PHASE0 CANDIDATE_PHASE0; do
    for suffix in POSTGRES_PASSWORD SECRET_VAULT_KEK STATUS_API_KEY; do
      printf 'ASTER_PHASE1_%s_%s=%s\n' "${stack}" "${suffix}" "$(random_hex 32)"
    done
  done
} >"${COMPOSE_ENV}"
/usr/bin/chmod 600 "${COMPOSE_ENV}"
assert_build_root_identity

for port in "${PORTS[@]}"; do
  port_is_listening "${port}" && fail
done

compose config --quiet >/dev/null || fail
project_started=1
compose up --detach --wait --wait-timeout 600 "${SERVICES[@]}" >/dev/null || fail
ORACLE_PRIMARY_POSTGRES_CONTAINER_ID=''
ORACLE_FOREIGN_POSTGRES_CONTAINER_ID=''
CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID=''
CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID=''
for service in "${SERVICES[@]}"; do
  container_id="$(compose ps -q "${service}" 2>/dev/null || true)"
  [[ "${container_id}" =~ ^[0-9a-f]{12,64}$ ]] || fail
  container_ids+=("${container_id}")
  case "${service}" in
    oracle-primary-postgres) ORACLE_PRIMARY_POSTGRES_CONTAINER_ID="${container_id}" ;;
    oracle-foreign-postgres) ORACLE_FOREIGN_POSTGRES_CONTAINER_ID="${container_id}" ;;
    candidate-primary-postgres) CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID="${container_id}" ;;
    candidate-foreign-postgres) CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID="${container_id}" ;;
  esac
done
[[ -n "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" && -n "${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}" && -n "${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}" && -n "${CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID}" ]] || fail
readonly ORACLE_PRIMARY_POSTGRES_CONTAINER_ID ORACLE_FOREIGN_POSTGRES_CONTAINER_ID
readonly CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID
rm -f -- "${COMPOSE_ENV}"

http_ready() {
  local port=$1 path=$2 marker=$3 attempt response
  for ((attempt=0; attempt<60; attempt++)); do
    response=''
    if exec 9<>"/dev/tcp/127.0.0.1/${port}"; then
      printf 'GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' "${path}" >&9
      while IFS= read -r -t 1 line <&9; do response+="${line}"; done
      exec 9>&-
      if [[ "${response}" == HTTP/*' 200 '* && "${response}" == *"${marker}"* ]]; then return 0; fi
    fi
    sleep 1
  done
  return 1
}

for core_port in 3311 3312 3321 3322 3331 3341; do
  http_ready "${core_port}" '/oidc/.well-known/openid-configuration' 'issuer' || fail
done
for admin_port in 3411 3412 3421 3422 3431 3441; do
  http_ready "${admin_port}" '/api/.well-known/endpoints/default' 'http' || fail
done

key_set_sha256() {
  local container_id=$1 tenant_id=$2 config_key=$3 result
  result="$("${DOCKER_BIN}" exec --interactive --user postgres "${container_id}" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --set="tenant_id=${tenant_id}" --set="config_key=${config_key}" \
    --username aster --dbname aster <<'SQL'
with key_ids as (
  select element ->> 'id' as id
  from logto_configs
  cross join lateral jsonb_array_elements(value) as element
  where tenant_id = :'tenant_id' and key = :'config_key'
)
select encode(sha256(convert_to(string_agg(id, ',' order by id), 'UTF8')), 'hex')
from key_ids
having count(*) > 0 and bool_and(id is not null and id <> '');
SQL
)" || fail
  result="$(printf '%s' "${result}" | tr -d '[:space:]')"
  [[ "${result}" =~ ^[0-9a-f]{64}$ ]] || fail
  printf '%s' "${result}"
}

ORACLE_DATA_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" default oidc.cookieKeys)"
ORACLE_DATA_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" default oidc.privateKeys)"
ORACLE_ADMIN_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" admin oidc.cookieKeys)"
ORACLE_ADMIN_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_PRIMARY_POSTGRES_CONTAINER_ID}" admin oidc.privateKeys)"
ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}" default oidc.cookieKeys)"
ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${ORACLE_FOREIGN_POSTGRES_CONTAINER_ID}" default oidc.privateKeys)"
CANDIDATE_DATA_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}" default oidc.cookieKeys)"
CANDIDATE_DATA_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}" default oidc.privateKeys)"
CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}" admin oidc.cookieKeys)"
CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID}" admin oidc.privateKeys)"
CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256="$(key_set_sha256 "${CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID}" default oidc.cookieKeys)"
CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="$(key_set_sha256 "${CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID}" default oidc.privateKeys)"
readonly ORACLE_DATA_COOKIE_KEY_SET_SHA256 ORACLE_DATA_SIGNING_KEY_SET_SHA256
readonly ORACLE_ADMIN_COOKIE_KEY_SET_SHA256 ORACLE_ADMIN_SIGNING_KEY_SET_SHA256
readonly ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256 ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256
readonly CANDIDATE_DATA_COOKIE_KEY_SET_SHA256 CANDIDATE_DATA_SIGNING_KEY_SET_SHA256
readonly CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256 CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256
readonly CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256 CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256

canonical_image_id() {
  local image_id
  image_id="$("${DOCKER_BIN}" image inspect --format '{{.Id}}' "$1" 2>/dev/null || true)"
  [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
  printf '%s' "${image_id}"
}

ORACLE_IMAGE_DIGEST="$(canonical_image_id "${ORACLE_IMAGE}")"
CANDIDATE_IMAGE_DIGEST="$(canonical_image_id "${CANDIDATE_IMAGE}")"
if [[ "${MODE}" == 'mirror-control' ]]; then
  [[ "${ORACLE_IMAGE_DIGEST}" == "${CANDIDATE_IMAGE_DIGEST}" ]] || fail
fi
readonly ORACLE_IMAGE_DIGEST CANDIDATE_IMAGE_DIGEST

PLAYWRIGHT_PATH="${PLAYWRIGHT_BROWSERS_PATH:-}"
[[ "${PLAYWRIGHT_PATH}" == /* && -d "${PLAYWRIGHT_PATH}" && ! -L "${PLAYWRIGHT_PATH}" ]] || fail
readonly PLAYWRIGHT_PATH

run_arguments=(
  run --mode "${MODE}" --profile "${PROFILE}" --schema "${SCHEMA}"
  --observation-controls --discovery-extra-control --candidate-invariant-controls
)
if [[ "${ASTER_PHASE1_RECORD_ORACLE:-0}" == 1 ]]; then
  [[ "${MODE}" == 'review-candidate' ]] || fail
  [[ -z "$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail
  run_arguments+=(--record-oracle)
fi
PUBLIC_ENV=(
  env -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}"
  TMPDIR="${BROWSER_TMP}"
  XDG_RUNTIME_DIR="${XDG_RUNTIME}"
  PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_PATH}"
  ASTER_PHASE1_MODE="${MODE}"
  ASTER_PHASE1_BUILD_ROOT="${BUILD_ROOT}"
  ASTER_PHASE1_ORACLE_IMAGE_DIGEST="${ORACLE_IMAGE_DIGEST}"
  ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST="${CANDIDATE_IMAGE_DIGEST}"
  ASTER_PHASE1_TOPOLOGY_ID="${project_name}"
  ASTER_PHASE1_CONFORMANCE_ROOT="${CONFORMANCE_ROOT}"
  ASTER_PHASE1_ORACLE_SNAPSHOT_PATH="${ORACLE_SNAPSHOT_PATH}"
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
  ASTER_PHASE1_ORACLE_URL='http://localhost:3311'
  ASTER_PHASE1_ORACLE_ADMIN_URL='http://localhost:3411'
  ASTER_PHASE1_ORACLE_FOREIGN_URL='http://localhost:3312'
  ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL='http://localhost:3412'
  ASTER_PHASE1_CANDIDATE_URL='http://localhost:3321'
  ASTER_PHASE1_CANDIDATE_ADMIN_URL='http://localhost:3421'
  ASTER_PHASE1_CANDIDATE_FOREIGN_URL='http://localhost:3322'
  ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL='http://localhost:3422'
  ASTER_PHASE1_PHASE0_ORACLE_URL='http://localhost:3331'
  ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL='http://localhost:3431'
  ASTER_PHASE1_PHASE0_CANDIDATE_URL='http://localhost:3341'
  ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL='http://localhost:3441'
  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"
)
"${SETSID_BIN}" "${PUBLIC_ENV[@]}" "${NODE_BIN}" "${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/cli.js" "${run_arguments[@]}" >/dev/null &
NODE_RUN_PID=$!
NODE_RUN_PGID="${NODE_RUN_PID}"
observed_node_pgid="$(/usr/bin/ps -o pgid= -p "${NODE_RUN_PID}" 2>/dev/null | /usr/bin/tr -d '[:space:]')"
[[ -n "${observed_node_pgid}" ]] || fail
[[ "${observed_node_pgid}" == "${NODE_RUN_PGID}" ]] || fail
node_run_status=0
wait "${NODE_RUN_PID}" || node_run_status=$?
terminate_owned_process_group "${NODE_RUN_PID}" "${NODE_RUN_PGID}" || fail
NODE_RUN_PID=''
NODE_RUN_PGID=''
((node_run_status == 0)) || fail

for artifact in "${EVIDENCE_NAMES[@]}"; do
  [[ -f "${EVIDENCE_DIR}/${artifact}" && ! -L "${EVIDENCE_DIR}/${artifact}" ]] || fail
done
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${SNAPSHOT_CLI}" verify-artifacts --directory "${EVIDENCE_DIR}" --stage evidence >/dev/null || fail
[[ -f "${MANIFEST_CLI}" ]] || fail
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${MANIFEST_CLI}" --mode "${MODE}" --directory "${EVIDENCE_DIR}" \
  --output "${EVIDENCE_DIR}/evidence-manifest.json" >/dev/null || fail
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${SNAPSHOT_CLI}" verify-artifacts --directory "${EVIDENCE_DIR}" --stage manifest >/dev/null || fail
[[ -f "${RESULT_CLI}" ]] || fail
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${RESULT_CLI}" --mode "${MODE}" --profile "${PROFILE}" --schema "${SCHEMA}" \
  --image-digest "${ORACLE_IMAGE_DIGEST}" \
  --manifest "${EVIDENCE_DIR}/evidence-manifest.json" \
  --output "${EVIDENCE_DIR}/harness-result.json" >/dev/null || fail
"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" "${SNAPSHOT_CLI}" verify-artifacts --directory "${EVIDENCE_DIR}" --stage final >/dev/null || fail
