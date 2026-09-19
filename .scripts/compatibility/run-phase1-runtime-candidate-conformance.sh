#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly SUITE_REPOSITORY='https://gitlab.com/openid/conformance-suite.git'
readonly SUITE_COMMIT='0dc0e3a21ec411e92c808e5b2e2258592c22b594'
readonly SUITE_MAVEN_RESOLUTION='source-pom-not-fully-offline-locked'
readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
readonly MAX_CANDIDATE_ARCHIVE_SIZE=34359738368
BUILD_ROOT="${ASTER_PHASE1_BUILD_ROOT:-${DEFAULT_BUILD_ROOT}}"
readonly BUILD_ROOT
readonly DEFAULT_RUN_ROOT="${BUILD_ROOT}/aster-phase1-runtime-candidate-conformance"
readonly TOPOLOGY_ID='runtime-candidate-conformance'
readonly RUNNER_DRIVER_PATH='/opt/aster/phase1-conformance-driver.sh'
readonly RUNNER_SCRIPT_PATH='/opt/aster/phase1-conformance-runner.mjs'
readonly POSTGRES_IMAGE='docker.io/library/postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
readonly MONGO_IMAGE='docker.io/library/mongo:6.0.13@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070'
readonly NGINX_IMAGE='docker.io/library/nginx:1.27.3-alpine@sha256:814a8e88df978ade80e584cc5b333144b9372a8e3c98872d07137dbf3b44d0e4'
readonly RUNNER_IMAGE='docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32'
readonly SERVICES=(
  candidate-primary-postgres candidate-primary-init candidate-conformance-core
  candidate-fixture-coordinator suite-mongo suite-server suite-nginx oidf-runner
)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly COMPOSE_FILE="${REPO_ROOT}/docker-compose.phase1-runtime-candidate-conformance.yml"
readonly SUITE_DOCKERFILE="${REPO_ROOT}/Dockerfile.phase1-oidf-suite"
readonly PKI_SCRIPT="${REPO_ROOT}/.scripts/compatibility/phase1-conformance-pki.sh"
readonly DRIVER_FILE="${REPO_ROOT}/.scripts/compatibility/phase1-conformance-driver.sh"
readonly RUNNER_FILE="${REPO_ROOT}/.scripts/compatibility/phase1-conformance-runner.mjs"
readonly PHASE1_CLI="${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/cli.js"
readonly ARTIFACT_CONTRACT="${REPO_ROOT}/packages/integration-tests/lib/compatibility/phase-1/artifact-contract.js"
readonly EXPORT_NAME='phase-1-conformance.json'

failure_stage=initialization
fail() {
  printf 'Aster runtime candidate conformance gate failed (%s)\n' "${failure_stage}" >&2
  exit 1
}

require_safe_build_root() {
  local value=$1

  [[ "${value}" == /* && "${value}" != */ && "${value}" != *'//'* ]] || fail
  [[ "${value}" != *'/./'* && "${value}" != *'/../'* && ! "${value}" =~ [[:cntrl:]] ]] || fail
  case "${value}" in
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

require_private_root() {
  local root=$1 resolved metadata

  assert_build_root_identity
  [[ "${root}" == "${BUILD_ROOT}/"* && "${root}" != "${BUILD_ROOT}" && "${root}" != *'/../'* ]] || fail
  if [[ ! -e "${root}" ]]; then
    /usr/bin/mkdir -m 700 -- "${root}" || fail
  fi
  [[ -d "${root}" && ! -L "${root}" ]] || fail
  resolved="$(/usr/bin/realpath -e -- "${root}" 2>/dev/null || true)"
  metadata="$(/usr/bin/stat -c '%u|%g|%a|%F' -- "${root}" 2>/dev/null || true)"
  [[ "${resolved}" == "${root}" ]] || fail
  [[ "${metadata}" == "$(/usr/bin/id -u)|$(/usr/bin/id -g)|700|directory" ]] || fail
  assert_build_root_identity
}

trusted_binary() {
  local candidate=$1 resolved owner group mode

  if [[ "${candidate}" != /* ]]; then
    candidate="$(command -v "${candidate}" 2>/dev/null || true)"
  fi
  resolved="$(/usr/bin/realpath -e -- "${candidate}" 2>/dev/null || true)"
  [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] || fail
  owner="$(/usr/bin/stat -c %u -- "${resolved}" 2>/dev/null || true)"
  group="$(/usr/bin/stat -c %g -- "${resolved}" 2>/dev/null || true)"
  mode="$(/usr/bin/stat -c %a -- "${resolved}" 2>/dev/null || true)"
  [[ "${owner}" == 0 || "${owner}" == "$(/usr/bin/id -u)" ]] || fail
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#${mode} & 8#002)) && fail
  if ((8#${mode} & 8#020)); then
    [[ "${owner}" == "$(/usr/bin/id -u)" && "${group}" == "$(/usr/bin/id -g)" ]] || fail
  fi
  printf '%s' "${resolved}"
}

trusted_system_binary() {
  local resolved owner mode

  resolved="$(trusted_binary "$1")"
  owner="$(/usr/bin/stat -c %u -- "${resolved}" 2>/dev/null || true)"
  mode="$(/usr/bin/stat -c %a -- "${resolved}" 2>/dev/null || true)"
  [[ "${owner}" == 0 ]] || fail
  ((8#${mode} & 8#022)) && fail
  printf '%s' "${resolved}"
}

immutable_image() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ || "$1" =~ ^[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}$ ]]
}

candidate_archive_identity() {
  local input=$1 resolved metadata owner group mode type size device inode

  [[ "${input}" == /* && ! "${input}" =~ [[:cntrl:]] ]] || return 1
  [[ "${input}" == "${BUILD_ROOT}/"* && "${input}" != "${BUILD_ROOT}" ]] || return 1
  [[ -f "${input}" && ! -L "${input}" ]] || return 1
  resolved="$(/usr/bin/realpath -e -- "${input}" 2>/dev/null || true)"
  [[ "${resolved}" == "${input}" ]] || return 1
  metadata="$(/usr/bin/stat -c '%u|%g|%a|%F|%s|%d|%i' -- "${input}" 2>/dev/null || true)"
  IFS='|' read -r owner group mode type size device inode <<<"${metadata}"
  [[ "${owner}" == "$(/usr/bin/id -u)" && "${group}" == "$(/usr/bin/id -g)" ]] || return 1
  [[ "${mode}" == 400 || "${mode}" == 600 ]] || return 1
  [[ "${type}" == 'regular file' && "${size}" =~ ^[0-9]+$ ]] || return 1
  ((size > 0 && size <= MAX_CANDIDATE_ARCHIVE_SIZE)) || return 1
  [[ "${device}" =~ ^[0-9]+$ && "${inode}" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "${owner}|${group}|${mode}|${type}|${size}|${device}|${inode}"
}

GIT_BIN="$(trusted_system_binary /usr/bin/git)"
DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)"
PODMAN_BIN="$(trusted_system_binary /usr/bin/podman)"
FLOCK_BIN="$(trusted_system_binary /usr/bin/flock)"
SETSID_BIN="$(trusted_system_binary /usr/bin/setsid)"
TIMEOUT_BIN="$(trusted_system_binary /usr/bin/timeout)"
ENV_BIN="$(trusted_system_binary /usr/bin/env)"
PS_BIN="$(trusted_system_binary /usr/bin/ps)"
AWK_BIN="$(trusted_system_binary /usr/bin/awk)"
SHA256_BIN="$(trusted_system_binary /usr/bin/sha256sum)"
NODE_BIN="$(trusted_binary node)"
PNPM_BIN="$(trusted_binary pnpm)"
readonly GIT_BIN DOCKER_BIN PODMAN_BIN FLOCK_BIN
readonly SETSID_BIN TIMEOUT_BIN ENV_BIN PS_BIN AWK_BIN SHA256_BIN NODE_BIN PNPM_BIN
export GIT_NO_REPLACE_OBJECTS=1
readonly GIT_AUTHORITY=("${GIT_BIN}" --no-replace-objects)

capture_build_root_identity
readonly BUILD_ROOT_DEVICE BUILD_ROOT_INODE
RUN_ROOT="${ASTER_RUN_ROOT:-${DEFAULT_RUN_ROOT}}"
require_private_root "${RUN_ROOT}"
readonly RUN_ROOT
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_ROOT}/run.XXXXXX")"
RUN_DIR_IDENTITY="$(/usr/bin/stat -c '%d|%i' -- "${RUN_DIR}")"
readonly RUN_DIR RUN_DIR_IDENTITY
EXPORT_DIR="${ASTER_PHASE1_CONFORMANCE_EXPORT_DIR-}"
readonly EXPORT_DIR
export_directory_safe() {
  [[ "${EXPORT_DIR}" == "${BUILD_ROOT}/"* && "${EXPORT_DIR}" != "${RUN_ROOT}" && \
    "${EXPORT_DIR}" != "${RUN_ROOT}/"* && "${EXPORT_DIR}" != *'//'* && \
    "${EXPORT_DIR}" != *'/./'* && "${EXPORT_DIR}" != *'/../'* && \
    ! "${EXPORT_DIR}" =~ [[:cntrl:]] && -d "${EXPORT_DIR}" && ! -L "${EXPORT_DIR}" ]] || return 1
  [[ "$(/usr/bin/realpath -e -- "${EXPORT_DIR}" 2>/dev/null || true)" == "${EXPORT_DIR}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%g|%a|%F' -- "${EXPORT_DIR}" 2>/dev/null || true)" == \
    "$(/usr/bin/id -u)|$(/usr/bin/id -g)|700|directory" ]] || return 1
  [[ "$(/usr/bin/stat -c '%d|%i' -- "${EXPORT_DIR}" 2>/dev/null || true)" == "${EXPORT_IDENTITY}" ]]
}
EXPORT_IDENTITY=''
EXPORT_FD=''
EXPORT_TEMP_NAME=''
RUN_DIR_FD=''
export_directory_stable() {
  export_directory_safe && [[ "${EXPORT_FD}" =~ ^[0-9]+$ ]] && \
    [[ "$(/usr/bin/stat -L -c '%d|%i' -- "/proc/self/fd/${EXPORT_FD}" 2>/dev/null || true)" == \
      "${EXPORT_IDENTITY}" ]]
}
run_directory_owned() {
  [[ -d "${RUN_DIR}" && ! -L "${RUN_DIR}" ]] && \
    [[ "$(/usr/bin/realpath -e -- "${RUN_DIR}" 2>/dev/null || true)" == "${RUN_DIR}" ]] && \
    [[ "$(/usr/bin/stat -c '%d|%i|%u|%g|%a|%F' -- "${RUN_DIR}" 2>/dev/null || true)" == \
      "${RUN_DIR_IDENTITY}|$(/usr/bin/id -u)|$(/usr/bin/id -g)|700|directory" ]]
}
run_directory_fd_owned() {
  [[ "${RUN_DIR_FD}" =~ ^[0-9]+$ ]] && \
    [[ "$(/usr/bin/stat -L -c '%d|%i' -- "/proc/self/fd/${RUN_DIR_FD}" 2>/dev/null || true)" == \
      "${RUN_DIR_IDENTITY}" ]]
}
PODMAN_GRAPH_ROOT="${BUILD_ROOT}/aster-phase1-conformance-podman-graph"
require_private_root "${PODMAN_GRAPH_ROOT}"
# shellcheck disable=SC2016
run_root_hash="$(printf '%s' "${PODMAN_GRAPH_ROOT}" | "${SHA256_BIN}" | "${AWK_BIN}" '{print substr($1, 1, 20)}')"
[[ "${run_root_hash}" =~ ^[0-9a-f]{20}$ ]] || fail
PODMAN_RUN_ROOT="/run/user/$(/usr/bin/id -u)/aster-p1c-${run_root_hash}"
if [[ ! -e "${PODMAN_RUN_ROOT}" ]]; then
  /usr/bin/mkdir -m 700 -- "${PODMAN_RUN_ROOT}" || fail
fi
[[ -d "${PODMAN_RUN_ROOT}" && ! -L "${PODMAN_RUN_ROOT}" ]] || fail
[[ "$(/usr/bin/realpath -e -- "${PODMAN_RUN_ROOT}" 2>/dev/null || true)" == "${PODMAN_RUN_ROOT}" ]] || fail
[[ "$(/usr/bin/stat -c '%u|%g|%a|%F' -- "${PODMAN_RUN_ROOT}" 2>/dev/null || true)" == \
  "$(/usr/bin/id -u)|$(/usr/bin/id -g)|700|directory" ]] || fail
PODMAN_SOCKET="/run/user/$(/usr/bin/id -u)/aster-p1c-${run_root_hash}.sock"
[[ "${#PODMAN_SOCKET}" -le 100 && ! -e "${PODMAN_SOCKET}" && ! -L "${PODMAN_SOCKET}" ]] || fail
PODMAN_LOG="${RUN_DIR}/podman-service.log"
PODMAN_LOCK_FILE="${BUILD_ROOT}/aster-phase1-conformance-podman.lock"
exec {PODMAN_LOCK_FD}>>"${PODMAN_LOCK_FILE}"
"${FLOCK_BIN}" -x "${PODMAN_LOCK_FD}" || fail
readonly PODMAN_GRAPH_ROOT PODMAN_RUN_ROOT PODMAN_SOCKET PODMAN_LOG PODMAN_LOCK_FILE PODMAN_LOCK_FD
CONFORMANCE_ROOT="${RUN_DIR}/conformance"
EVIDENCE_DIR="${RUN_DIR}/evidence"
SECRET_DIR="${RUN_DIR}/secrets"
PRIVATE_HOME="${RUN_DIR}/home"
PRIVATE_TMP="${RUN_DIR}/tmp"
SUITE_CHECKOUT="${RUN_DIR}/oidf-suite"
PRIMARY_KEYRING_DIR="${RUN_DIR}/primary-keyring"
FIXTURE_DIR="${RUN_DIR}/fixture"
PRIMARY_CONFIG_FILE="${RUN_DIR}/primary.conf"
POSTGRES_PASSWORD_FILE="${RUN_DIR}/postgres-password"
COMPOSE_ENV="${RUN_DIR}/compose.env"
DESCRIPTOR_FILE="${CONFORMANCE_ROOT}/runtime-candidate-conformance.json"
REVIEW_PROFILE="${RUN_DIR}/review-profile.json"
OIDF_PASSWORD_FILE="${SECRET_DIR}/phase1-user"
OIDF_BASIC_1_SECRET_FILE="${SECRET_DIR}/oidf-basic-1"
OIDF_BASIC_2_SECRET_FILE="${SECRET_DIR}/oidf-basic-2"
OIDF_POST_1_SECRET_FILE="${SECRET_DIR}/oidf-post-1"
OIDF_PUBLIC_MAP_FILE="${SECRET_DIR}/oidf-conformance-public.json"
OIDF_PROVISION_DESCRIPTOR="${FIXTURE_DIR}/oidf-conformance-provision.json"
OIDF_PROVISION_RESPONSE="${FIXTURE_DIR}/oidf-conformance-provision-response.json"
OIDF_CLEANUP_DESCRIPTOR="${FIXTURE_DIR}/oidf-conformance-cleanup.json"
OIDF_CLEANUP_RESPONSE="${FIXTURE_DIR}/oidf-conformance-cleanup-response.json"
FIXTURE_BASELINE_PROVISION_DESCRIPTOR="${FIXTURE_DIR}/baseline-release-provision.json"
FIXTURE_BASELINE_PROVISION_RESPONSE="${FIXTURE_DIR}/baseline-release-provision-response.json"
FIXTURE_BASELINE_CLEANUP_DESCRIPTOR="${FIXTURE_DIR}/baseline-release-cleanup.json"
FIXTURE_BASELINE_CLEANUP_RESPONSE="${FIXTURE_DIR}/baseline-release-cleanup-response.json"
readonly CONFORMANCE_ROOT EVIDENCE_DIR SECRET_DIR PRIVATE_HOME PRIVATE_TMP SUITE_CHECKOUT
readonly PRIMARY_KEYRING_DIR FIXTURE_DIR PRIMARY_CONFIG_FILE POSTGRES_PASSWORD_FILE COMPOSE_ENV
readonly DESCRIPTOR_FILE REVIEW_PROFILE
readonly OIDF_PASSWORD_FILE OIDF_BASIC_1_SECRET_FILE OIDF_BASIC_2_SECRET_FILE
readonly OIDF_POST_1_SECRET_FILE OIDF_PUBLIC_MAP_FILE OIDF_PROVISION_DESCRIPTOR
readonly OIDF_PROVISION_RESPONSE OIDF_CLEANUP_DESCRIPTOR OIDF_CLEANUP_RESPONSE
readonly FIXTURE_BASELINE_PROVISION_DESCRIPTOR FIXTURE_BASELINE_PROVISION_RESPONSE
readonly FIXTURE_BASELINE_CLEANUP_DESCRIPTOR FIXTURE_BASELINE_CLEANUP_RESPONSE
/usr/bin/mkdir -m 700 -- "${CONFORMANCE_ROOT}" "${EVIDENCE_DIR}" "${SECRET_DIR}" \
  "${PRIVATE_HOME}" "${PRIVATE_TMP}" "${SUITE_CHECKOUT}" "${PRIMARY_KEYRING_DIR}" "${FIXTURE_DIR}"
assert_build_root_identity

CLOSED_ENV=(env -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" LC_ALL=C)
CLOSED_BUILD_ENV=(
  env -i
  PATH="$(dirname -- "${NODE_BIN}"):$(dirname -- "${PNPM_BIN}"):/usr/bin:/bin"
  HOME="${PRIVATE_HOME}"
  TMPDIR="${PRIVATE_TMP}"
  CI=true
  LC_ALL=C
)
readonly CLOSED_ENV CLOSED_BUILD_ENV
[[ "$("${CLOSED_ENV[@]}" "${NODE_BIN}" --version 2>/dev/null || true)" == 'v22.23.2' ]] || fail
[[ "$("${CLOSED_BUILD_ENV[@]}" "${PNPM_BIN}" --version 2>/dev/null || true)" == '10.15.1' ]] || fail

random_hex() {
  "${CLOSED_ENV[@]}" "${NODE_BIN}" -e \
    'process.stdout.write(require("node:crypto").randomBytes(Number(process.argv[1])).toString("hex"))' "$1"
}

random_uuid() {
  local value
  value="$(random_hex 16)"
  printf '%s-%s-%s-%s-%s' "${value:0:8}" "${value:8:4}" "${value:12:4}" "${value:16:4}" "${value:20:12}"
}

project_name="aster-phase1-conformance-$(random_hex 8)"
readonly project_name
project_started=0
container_ids=()
NODE_RUN_PID=''
NODE_RUN_PGID=''
NODE_RUN_TOKEN=''
SETUP_RUN_PID=''
SETUP_RUN_PGID=''
SETUP_RUN_TOKEN=''
PODMAN_SERVICE_PID=''
PODMAN_SERVICE_PGID=''
PODMAN_SERVICE_TOKEN=''
COORDINATOR_CONTAINER_ID=''
OIDF_ALLOCATION_ID=''
OIDF_FIXTURE_PROVISIONED=0

docker_cli() {
  "${TIMEOUT_BIN}" --signal=TERM --kill-after=5s 30s \
    "${ENV_BIN}" -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" \
      DOCKER_HOST="unix://${PODMAN_SOCKET}" DOCKER_CLIENT_TIMEOUT=20 \
      "${DOCKER_BIN}" "$@"
}

compose() {
  "${TIMEOUT_BIN}" --signal=TERM --kill-after=5s 120s \
    "${ENV_BIN}" -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" \
      DOCKER_HOST="unix://${PODMAN_SOCKET}" DOCKER_CLIENT_TIMEOUT=90 COMPOSE_HTTP_TIMEOUT=90 \
      "${DOCKER_BIN}" compose --env-file "${COMPOSE_ENV}" \
        --project-name "${project_name}" --file "${COMPOSE_FILE}" "$@"
}

podman_cli() {
  "${TIMEOUT_BIN}" --signal=TERM --kill-after=5s 120s \
    "${ENV_BIN}" -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
      XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
      "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" --runroot "${PODMAN_RUN_ROOT}" "$@"
}

system_docker_cli() {
  "${TIMEOUT_BIN}" --signal=TERM --kill-after=5s 30s \
    "${ENV_BIN}" -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" DOCKER_CLIENT_TIMEOUT=20 \
      "${DOCKER_BIN}" "$@"
}

process_has_ownership_token() {
  local pid=$1 token=$2 entry

  [[ "${pid}" =~ ^[1-9][0-9]*$ && "${token}" =~ ^[0-9a-f]{64}$ && -r "/proc/${pid}/environ" ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ "${entry}" == "ASTER_PHASE1_PROCESS_TOKEN=${token}" ]] && return 0
  done <"/proc/${pid}/environ"
  return 1
}

process_group_has_live_members() {
  local pgid=$1

  # shellcheck disable=SC2016
  "${PS_BIN}" -eo pgid=,stat= | "${AWK_BIN}" -v expected="${pgid}" '
    $1 == expected && $2 !~ /^Z/ { found=1 }
    END { exit found ? 0 : 1 }
  '
}

terminate_owned_process_group() {
  local pid=$1 pgid=$2 token=$3 attempt member_pid member_pgid member_sid member_state found

  [[ "${pid}" =~ ^[1-9][0-9]*$ && "${pgid}" == "${pid}" ]] || return 1
  if process_group_has_live_members "${pgid}"; then
    found=0
    while read -r member_pid member_pgid member_sid member_state; do
      [[ "${member_pgid}" == "${pgid}" && "${member_state}" != Z* ]] || continue
      [[ "${member_sid}" == "${pgid}" ]] || return 1
      process_has_ownership_token "${member_pid}" "${token}" || return 1
      found=1
    done < <("${PS_BIN}" -eo pid=,pgid=,sid=,stat=)
    [[ "${found}" == 1 ]] || return 1
    kill -TERM -- "-${pgid}" 2>/dev/null || true
    for ((attempt=0; attempt<20; attempt++)); do
      process_group_has_live_members "${pgid}" || break
      /usr/bin/sleep 0.05
    done
    if process_group_has_live_members "${pgid}"; then
      kill -KILL -- "-${pgid}" 2>/dev/null || true
    fi
  fi
  wait "${pid}" 2>/dev/null || true
  ! process_group_has_live_members "${pgid}"
}

run_owned_command() {
  local timeout_seconds=$1 stdout_path=$2 stderr_path=$3 status=0
  shift 3

  [[ "${timeout_seconds}" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  [[ -z "${SETUP_RUN_PGID}" && "$#" -gt 0 ]] || return 1
  SETUP_RUN_TOKEN="$(random_hex 32)"
  ASTER_PHASE1_PROCESS_TOKEN="${SETUP_RUN_TOKEN}" \
    "${SETSID_BIN}" "${TIMEOUT_BIN}" --signal=TERM --kill-after=10s \
      "${timeout_seconds}s" "${ENV_BIN}" -i \
      "ASTER_PHASE1_PROCESS_TOKEN=${SETUP_RUN_TOKEN}" "$@" \
      >"${stdout_path}" 2>"${stderr_path}" &
  SETUP_RUN_PID=$!
  SETUP_RUN_PGID="${SETUP_RUN_PID}"
  wait "${SETUP_RUN_PID}" || status=$?
  terminate_owned_process_group \
    "${SETUP_RUN_PID}" "${SETUP_RUN_PGID}" "${SETUP_RUN_TOKEN}" || status=1
  SETUP_RUN_PID=''
  SETUP_RUN_PGID=''
  SETUP_RUN_TOKEN=''
  return "${status}"
}

compose_up_phase() {
  [[ "$#" -gt 0 ]] || return 1
  run_owned_command 600 /dev/null /dev/null \
    PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" DOCKER_HOST="unix://${PODMAN_SOCKET}" \
    DOCKER_CLIENT_TIMEOUT=540 COMPOSE_HTTP_TIMEOUT=540 \
    "${DOCKER_BIN}" compose --env-file "${COMPOSE_ENV}" --project-name "${project_name}" \
      --file "${COMPOSE_FILE}" up --detach --no-build --no-deps "$@"
}

cleanup_oidf_fixture() {
  local cleanup_status=0

  [[ "${OIDF_FIXTURE_PROVISIONED}" == 1 ]] || return 0
  [[ "${COORDINATOR_CONTAINER_ID}" =~ ^[0-9a-f]{64}$ ]] || return 1
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${OIDF_CLEANUP_DESCRIPTOR}" "${OIDF_ALLOCATION_ID}" "${OIDF_PUBLIC_MAP_FILE}" <<'NODE' || return 1
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
const [output, allocationId, publicMapPath] = process.argv.slice(2);
const descriptor = {
  schemaVersion: 1,
  operation: 'cleanup',
  recipe: 'oidfConformance',
  allocationId,
};
if (existsSync(publicMapPath)) descriptor.public = JSON.parse(readFileSync(publicMapPath, 'utf8'));
writeFileSync(output, JSON.stringify(descriptor), { flag: 'wx', mode: 0o400 });
NODE
  docker_cli exec --interactive --user "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
    "${COORDINATOR_CONTAINER_ID}" \
    /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin \
    ASTER_FIXTURE_SOCKET=/run/aster-fixture/coordinator.sock \
    /usr/local/bin/aster-admin fixture apply \
    <"${OIDF_CLEANUP_DESCRIPTOR}" >"${OIDF_CLEANUP_RESPONSE}" || cleanup_status=1
  if [[ "${cleanup_status}" == 0 ]]; then
    "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
      "${OIDF_CLEANUP_RESPONSE}" <<'NODE' || cleanup_status=1
import { readFileSync } from 'node:fs';
const value = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const keys = Object.keys(value ?? {});
if (!value || Array.isArray(value) || keys.length !== 3 ||
  !['schemaVersion', 'operation', 'ok'].every((key) => keys.includes(key)) ||
  value.schemaVersion !== 1 || value.operation !== 'cleanup' || value.ok !== true) process.exit(1);
NODE
  fi
  /usr/bin/rm -f -- "${OIDF_CLEANUP_DESCRIPTOR}" "${OIDF_CLEANUP_RESPONSE}" || cleanup_status=1
  [[ "${cleanup_status}" != 0 ]] || OIDF_FIXTURE_PROVISIONED=0
  return "${cleanup_status}"
}

remove_oidf_private_material() {
  /usr/bin/rm -f -- \
    "${OIDF_PASSWORD_FILE}" "${OIDF_BASIC_1_SECRET_FILE}" \
    "${OIDF_BASIC_2_SECRET_FILE}" "${OIDF_POST_1_SECRET_FILE}" \
    "${OIDF_PUBLIC_MAP_FILE}" "${OIDF_PROVISION_DESCRIPTOR}" \
    "${OIDF_PROVISION_RESPONSE}" "${OIDF_CLEANUP_DESCRIPTOR}" \
    "${OIDF_CLEANUP_RESPONSE}" "${FIXTURE_BASELINE_PROVISION_DESCRIPTOR}" \
    "${FIXTURE_BASELINE_PROVISION_RESPONSE}" "${FIXTURE_BASELINE_CLEANUP_DESCRIPTOR}" \
    "${FIXTURE_BASELINE_CLEANUP_RESPONSE}"
}

export_artifact() {
  local action=$1 digest=${2-} size=${3-} inode=${4-}
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${action}" "${EXPORT_DIR}" "${EXPORT_FD}" "${EXPORT_IDENTITY}" \
    "${EXPORT_TEMP_NAME}" "${EXPORT_NAME}" "${EVIDENCE_DIR}/${EXPORT_NAME}" \
    "${CANDIDATE_IMAGE_ID}" "${ARTIFACT_CONTRACT}" "${digest}" "${size}" "${inode}" <<'NODE'
import { createHash } from 'node:crypto';
import { constants, fstatSync } from 'node:fs';
import { link, lstat, open, readdir, realpath, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [action, directory, fdText, identity, tempName, name, source, imageDigest,
  contractPath, expectedDigest, expectedSize, expectedInode] = process.argv.slice(2);
const fd = Number(fdText);
const anchor = `/proc/self/fd/${fd}`;
const temporary = join(anchor, tempName);
const destination = join(anchor, name);
let tempCreated = false;
let finalCreated = false;
let stagedInode = '';
const digestOf = (bytes) => createHash('sha256').update(bytes).digest('hex');
const assertDirectoryFd = () => {
  const dir = fstatSync(fd);
  if (!dir.isDirectory() || dir.mode % 0o1000 !== 0o700 ||
    dir.uid !== process.getuid() || dir.gid !== process.getgid() ||
    `${dir.dev}|${dir.ino}` !== identity) throw new Error('export directory identity');
  return dir;
};
const assertCurrentDirectory = async () => {
  const anchored = assertDirectoryFd();
  const named = await lstat(directory);
  if (!named.isDirectory() || named.isSymbolicLink() ||
    named.dev !== anchored.dev || named.ino !== anchored.ino ||
    await realpath(directory) !== directory) throw new Error('export directory moved');
};
const assertOwnedArtifact = (file, inode, links = 1) => {
  if (!file.isFile() || file.uid !== process.getuid() || file.gid !== process.getgid() ||
    file.nlink !== links || String(file.ino) !== inode)
    throw new Error('export artifact identity');
};
const assertArtifact = (file, inode, links = 1) => {
  assertOwnedArtifact(file, inode, links);
  if (file.mode % 0o1000 !== 0o600) throw new Error('export artifact mode');
};
const removeOwned = async (filename, inode, links = 1) => {
  let file;
  try {
    file = await lstat(filename);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  assertOwnedArtifact(file, inode, links);
  await unlink(filename);
};
try {
  if (!Number.isSafeInteger(fd) || fd < 3 ||
    !/^\.aster-conformance-[0-9a-f]{32}\.tmp$/.test(tempName)) throw new Error('export input');
  assertDirectoryFd();
  if (action === 'stage') {
    await assertCurrentDirectory();
    if ((await readdir(anchor)).length !== 0) throw new Error('export directory not empty');
    const { parseStrictPhase1ArtifactJson, assertPhase1PublicArtifactValue } =
      await import(pathToFileURL(contractPath).href);
    const input = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
    let bytes;
    try {
      const file = await input.stat();
      if (!file.isFile() || file.uid !== process.getuid() || file.gid !== process.getgid() ||
        file.nlink !== 1 || ![0o400, 0o600].includes(file.mode % 0o1000))
        throw new Error('source metadata');
      bytes = await input.readFile();
    } finally {
      await input.close();
    }
    const value = parseStrictPhase1ArtifactJson(bytes);
    assertPhase1PublicArtifactValue(value);
    if (value.schemaVersion !== 1 || value.mode !== 'runtime-candidate' ||
      value.sanitizerSuccess !== true || value.provenance?.imageDigest !== imageDigest ||
      !Array.isArray(value.adapterControls) || value.adapterControls.length !== 3 ||
      !Array.isArray(value.officialResultIds) || value.officialResultIds.length !== 2 ||
      !Array.isArray(value.planResults) || value.planResults.length !== 2)
      throw new Error('conformance contract');
    const output = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    tempCreated = true;
    try {
      stagedInode = String((await output.stat()).ino);
      await output.writeFile(bytes);
      await output.sync();
    } finally {
      await output.close();
    }
    assertArtifact(await lstat(temporary), stagedInode);
    await assertCurrentDirectory();
    if (JSON.stringify(await readdir(anchor)) !== JSON.stringify([tempName]))
      throw new Error('staged artifact tree');
    process.stdout.write(`${digestOf(bytes)}|${bytes.length}|${stagedInode}`);
  } else if (action === 'publish') {
    await assertCurrentDirectory();
    if (JSON.stringify(await readdir(anchor)) !== JSON.stringify([tempName]))
      throw new Error('staged artifact tree');
    const file = await open(temporary, constants.O_RDONLY | constants.O_NOFOLLOW);
    let bytes;
    try {
      assertArtifact(await file.stat(), expectedInode);
      bytes = await file.readFile();
    } finally {
      await file.close();
    }
    if (bytes.length !== Number(expectedSize) || digestOf(bytes) !== expectedDigest)
      throw new Error('staged artifact changed');
    await link(temporary, destination);
    finalCreated = true;
    await unlink(temporary);
    const published = await open(destination, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      assertArtifact(await published.stat(), expectedInode);
      if (!(await published.readFile()).equals(bytes)) throw new Error('published bytes');
    } finally {
      await published.close();
    }
    await assertCurrentDirectory();
    if (JSON.stringify(await readdir(anchor)) !== JSON.stringify([name]))
      throw new Error('published artifact tree');
  } else if (action === 'discard' || action === 'rollback') {
    await removeOwned(action === 'discard' ? temporary : destination, expectedInode);
    if ((await readdir(anchor)).length !== 0) throw new Error('export cleanup incomplete');
  } else {
    throw new Error('export action');
  }
} catch {
  if (tempCreated) {
    try { await removeOwned(temporary, stagedInode); } catch { process.exitCode = 1; }
  }
  if (finalCreated) {
    try {
      const file = await lstat(destination);
      if (file.nlink === 2) assertOwnedArtifact(await lstat(temporary), expectedInode, 2);
      await removeOwned(destination, expectedInode, file.nlink);
    } catch { process.exitCode = 1; }
  }
  process.exitCode = 1;
}
NODE
}

prepare_oidf_fixture_baseline() {
  local allocation_id
  allocation_id="baseline-release-$(random_hex 8)"
  [[ "${COORDINATOR_CONTAINER_ID}" =~ ^[0-9a-f]{64}$ ]] || return 1
  # The initialized candidate contains only key material for default/admin. The coordinator's
  # closed `none` lifecycle is the supported transition that removes that key-only baseline before
  # a mutable oidfConformance fixture can recreate and activate the default tenant.
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${FIXTURE_BASELINE_PROVISION_DESCRIPTOR}" "${allocation_id}" <<'NODE' || return 1
import { writeFileSync } from 'node:fs';
const [output, allocationId] = process.argv.slice(2);
writeFileSync(output, JSON.stringify({
  schemaVersion: 1,
  operation: 'provision',
  recipe: 'none',
  allocationId,
  profile: { fixtures: {} },
  seeds: { passwords: [], clientSecrets: [] },
}), { flag: 'wx', mode: 0o400 });
NODE
  docker_cli exec --interactive --user "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
    "${COORDINATOR_CONTAINER_ID}" \
    /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin \
    ASTER_FIXTURE_SOCKET=/run/aster-fixture/coordinator.sock \
    /usr/local/bin/aster-admin fixture apply \
    <"${FIXTURE_BASELINE_PROVISION_DESCRIPTOR}" \
    >"${FIXTURE_BASELINE_PROVISION_RESPONSE}" || return 1
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${FIXTURE_BASELINE_PROVISION_RESPONSE}" "${FIXTURE_BASELINE_CLEANUP_DESCRIPTOR}" \
    "${allocation_id}" <<'NODE' || return 1
import { readFileSync, writeFileSync } from 'node:fs';
const [responsePath, output, allocationId] = process.argv.slice(2);
const value = JSON.parse(readFileSync(responsePath, 'utf8'));
const publicMap = value?.public;
if (value?.schemaVersion !== 1 || value?.operation !== 'provision' ||
  publicMap?.schemaVersion !== 1 || publicMap?.recipe !== 'none' ||
  !Array.isArray(publicMap.allocations) || publicMap.allocations.length !== 0) process.exit(1);
writeFileSync(output, JSON.stringify({
  schemaVersion: 1,
  operation: 'cleanup',
  recipe: 'none',
  allocationId,
  public: publicMap,
}), { flag: 'wx', mode: 0o400 });
NODE
  docker_cli exec --interactive --user "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
    "${COORDINATOR_CONTAINER_ID}" \
    /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin \
    ASTER_FIXTURE_SOCKET=/run/aster-fixture/coordinator.sock \
    /usr/local/bin/aster-admin fixture apply \
    <"${FIXTURE_BASELINE_CLEANUP_DESCRIPTOR}" \
    >"${FIXTURE_BASELINE_CLEANUP_RESPONSE}" || return 1
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${FIXTURE_BASELINE_CLEANUP_RESPONSE}" <<'NODE' || return 1
import { readFileSync } from 'node:fs';
const value = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (value?.schemaVersion !== 1 || value?.operation !== 'cleanup' || value?.ok !== true ||
  Object.keys(value).length !== 3) process.exit(1);
NODE
  /usr/bin/rm -f -- \
    "${FIXTURE_BASELINE_PROVISION_DESCRIPTOR}" "${FIXTURE_BASELINE_PROVISION_RESPONSE}" \
    "${FIXTURE_BASELINE_CLEANUP_DESCRIPTOR}" "${FIXTURE_BASELINE_CLEANUP_RESPONSE}"
}

provision_oidf_fixture() {
  [[ "${COORDINATOR_CONTAINER_ID}" =~ ^[0-9a-f]{64}$ ]] || return 1
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${OIDF_PROVISION_DESCRIPTOR}" "${PROFILE_SOURCE}" "${OIDF_ALLOCATION_ID}" \
    "${OIDF_PASSWORD_FILE}" "${OIDF_BASIC_1_SECRET_FILE}" "${OIDF_BASIC_2_SECRET_FILE}" \
    "${OIDF_POST_1_SECRET_FILE}" <<'NODE' || return 1
import { readFileSync, writeFileSync } from 'node:fs';
const [output, profilePath, allocationId, passwordPath, basic1Path, basic2Path, post1Path] =
  process.argv.slice(2);
const profile = JSON.parse(readFileSync(profilePath, 'utf8'));
if (!profile || Array.isArray(profile) || typeof profile.fixtures !== 'object' ||
  profile.fixtures === null || typeof profile.conformance !== 'object' ||
  profile.conformance === null) process.exit(1);
const text = (secretPath) => readFileSync(secretPath, 'utf8');
writeFileSync(output, JSON.stringify({
  schemaVersion: 1,
  operation: 'provision',
  recipe: 'oidfConformance',
  allocationId,
  profile: { fixtures: profile.fixtures, conformance: profile.conformance },
  seeds: {
    passwords: [{ logicalId: 'phase1-user', value: text(passwordPath) }],
    clientSecrets: [
      { logicalId: 'oidf-basic-1', value: text(basic1Path) },
      { logicalId: 'oidf-basic-2', value: text(basic2Path) },
      { logicalId: 'oidf-post-1', value: text(post1Path) },
    ],
  },
}), { flag: 'wx', mode: 0o400 });
NODE
  OIDF_FIXTURE_PROVISIONED=1
  docker_cli exec --interactive --user "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
    "${COORDINATOR_CONTAINER_ID}" \
    /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin \
    ASTER_FIXTURE_SOCKET=/run/aster-fixture/coordinator.sock \
    /usr/local/bin/aster-admin fixture apply \
    <"${OIDF_PROVISION_DESCRIPTOR}" >"${OIDF_PROVISION_RESPONSE}" || return 1
  "${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
    "${OIDF_PROVISION_RESPONSE}" "${OIDF_PUBLIC_MAP_FILE}" "${OIDF_ALLOCATION_ID}" \
    "${OIDF_PASSWORD_FILE}" "${OIDF_BASIC_1_SECRET_FILE}" "${OIDF_BASIC_2_SECRET_FILE}" \
    "${OIDF_POST_1_SECRET_FILE}" <<'NODE' || return 1
import { readFileSync, writeFileSync } from 'node:fs';
const [responsePath, output, allocationId, ...secretPaths] = process.argv.slice(2);
const value = JSON.parse(readFileSync(responsePath, 'utf8'));
const keys = Object.keys(value ?? {});
if (!value || Array.isArray(value) || keys.length !== 3 ||
  !['schemaVersion', 'operation', 'public'].every((key) => keys.includes(key)) ||
  value.schemaVersion !== 1 || value.operation !== 'provision') process.exit(1);
const publicMap = value.public;
if (!publicMap || Array.isArray(publicMap) || publicMap.schemaVersion !== 1 ||
  publicMap.recipe !== 'oidfConformance' || !Array.isArray(publicMap.allocations) ||
  publicMap.allocations.length !== 1 ||
  publicMap.allocations[0]?.allocationId !== allocationId) process.exit(1);
const serialized = JSON.stringify(publicMap);
for (const secretPath of secretPaths) {
  const secret = readFileSync(secretPath, 'utf8');
  if (secret.length === 0 || serialized.includes(secret)) process.exit(1);
}
writeFileSync(output, serialized, { flag: 'wx', mode: 0o400 });
NODE
  /usr/bin/rm -f -- "${OIDF_PROVISION_DESCRIPTOR}" "${OIDF_PROVISION_RESPONSE}" || return 1
  [[ "$(/usr/bin/stat -c '%a|%F' -- "${OIDF_PUBLIC_MAP_FILE}" 2>/dev/null || true)" == \
    '400|regular file' ]] || return 1
}

cleanup() {
  local exit_code=$? cleanup_failed=0 publication_failed=0 remaining resource_id index
  local staged=0 published=0 staged_metadata='' digest='' size='' inode='' entries=''
  trap - EXIT INT TERM HUP

  if [[ -n "${SETUP_RUN_PGID}" ]]; then
    terminate_owned_process_group \
      "${SETUP_RUN_PID}" "${SETUP_RUN_PGID}" "${SETUP_RUN_TOKEN}" || cleanup_failed=1
  fi
  SETUP_RUN_PID=''
  SETUP_RUN_PGID=''
  SETUP_RUN_TOKEN=''

  if [[ -n "${NODE_RUN_PGID}" ]]; then
    terminate_owned_process_group "${NODE_RUN_PID}" "${NODE_RUN_PGID}" "${NODE_RUN_TOKEN}" || cleanup_failed=1
  fi
  NODE_RUN_PID=''
  NODE_RUN_PGID=''
  NODE_RUN_TOKEN=''

  cleanup_oidf_fixture || cleanup_failed=1
  remove_oidf_private_material || cleanup_failed=1

  if [[ "${project_started}" == 1 ]]; then
    for ((index=${#container_ids[@]} - 1; index >= 0; index--)); do
      docker_cli rm --force "${container_ids[index]}" >/dev/null 2>&1 || cleanup_failed=1
    done
    if remaining="$(docker_cli ps -aq --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)"; then
      while IFS= read -r resource_id; do
        [[ -z "${resource_id}" ]] || docker_cli rm --force "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
      done <<<"${remaining}"
    else
      cleanup_failed=1
    fi
    if ! remaining="$(docker_cli ps -aq --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)"; then
      cleanup_failed=1
    elif [[ -n "${remaining}" ]]; then
      cleanup_failed=1
    fi
    if remaining="$(docker_cli network ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)"; then
      while IFS= read -r resource_id; do
        [[ -z "${resource_id}" ]] || docker_cli network rm "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
      done <<<"${remaining}"
    else
      cleanup_failed=1
    fi
    if ! remaining="$(docker_cli network ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)"; then
      cleanup_failed=1
    elif [[ -n "${remaining}" ]]; then
      cleanup_failed=1
    fi
    if remaining="$(docker_cli volume ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)"; then
      while IFS= read -r resource_id; do
        [[ -z "${resource_id}" ]] || docker_cli volume rm "${resource_id}" >/dev/null 2>&1 || cleanup_failed=1
      done <<<"${remaining}"
    else
      cleanup_failed=1
    fi
    if ! remaining="$(docker_cli volume ls -q --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)"; then
      cleanup_failed=1
    elif [[ -n "${remaining}" ]]; then
      cleanup_failed=1
    fi
  fi
  if [[ -n "${PODMAN_SERVICE_PGID}" ]]; then
    terminate_owned_process_group \
      "${PODMAN_SERVICE_PID}" "${PODMAN_SERVICE_PGID}" "${PODMAN_SERVICE_TOKEN}" || cleanup_failed=1
  elif [[ -n "${PODMAN_SERVICE_PID}" ]] && kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
    if process_has_ownership_token "${PODMAN_SERVICE_PID}" "${PODMAN_SERVICE_TOKEN}"; then
      kill -TERM -- "${PODMAN_SERVICE_PID}" 2>/dev/null || cleanup_failed=1
      for ((index=0; index<20; index++)); do
        kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null || break
        /usr/bin/sleep 0.05
      done
      if kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
        process_has_ownership_token "${PODMAN_SERVICE_PID}" "${PODMAN_SERVICE_TOKEN}" || cleanup_failed=1
        kill -KILL -- "${PODMAN_SERVICE_PID}" 2>/dev/null || cleanup_failed=1
      fi
      wait "${PODMAN_SERVICE_PID}" 2>/dev/null || true
    else
      cleanup_failed=1
    fi
  fi
  PODMAN_SERVICE_PID=''
  PODMAN_SERVICE_PGID=''
  PODMAN_SERVICE_TOKEN=''
  if [[ -e "${PODMAN_SOCKET}" || -L "${PODMAN_SOCKET}" ]]; then
    if [[ -S "${PODMAN_SOCKET}" && ! -L "${PODMAN_SOCKET}" ]] && \
      [[ "$(/usr/bin/stat -c %u -- "${PODMAN_SOCKET}" 2>/dev/null || true)" == \
        "$(/usr/bin/id -u)" ]]; then
      /usr/bin/rm -f -- "${PODMAN_SOCKET}" || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  if [[ "${cleanup_failed}" == 0 ]]; then
    if ! run_directory_owned || ! exec {RUN_DIR_FD}<"${RUN_DIR}" || ! run_directory_fd_owned; then
      cleanup_failed=1
    fi
  fi
  if [[ "${exit_code}" == 0 && "${cleanup_failed}" == 0 && -n "${EXPORT_DIR}" ]]; then
    if export_directory_safe && exec {EXPORT_FD}<"${EXPORT_DIR}" && \
      export_directory_stable && \
      entries="$(/usr/bin/find "${EXPORT_DIR}" -mindepth 1 -maxdepth 1 -printf '%f\n')" && \
      [[ -z "${entries}" ]]; then
      EXPORT_TEMP_NAME=".aster-conformance-$(random_hex 16).tmp"
      if staged_metadata="$(export_artifact stage)"; then
        IFS='|' read -r digest size inode <<<"${staged_metadata}"
        if [[ "${digest}" =~ ^[0-9a-f]{64}$ && "${size}" =~ ^[1-9][0-9]*$ && \
          "${inode}" =~ ^[1-9][0-9]*$ ]]; then
          staged=1
        else
          publication_failed=1
        fi
      else
        publication_failed=1
      fi
    else
      publication_failed=1
    fi
  fi
  if [[ "${cleanup_failed}" == 0 ]]; then
    if run_directory_owned && run_directory_fd_owned; then
      /usr/bin/rm -rf -- "${RUN_DIR}" || cleanup_failed=1
      [[ ! -e "${RUN_DIR}" && ! -L "${RUN_DIR}" ]] || cleanup_failed=1
      [[ "$(/usr/bin/stat -L -c %h -- "/proc/self/fd/${RUN_DIR_FD}" 2>/dev/null || true)" == 0 ]] || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  if [[ "${exit_code}" == 0 && "${cleanup_failed}" == 0 && "${publication_failed}" == 0 && \
    "${staged}" == 1 ]]; then
    if export_directory_stable && export_artifact publish "${digest}" "${size}" "${inode}"; then
      if export_directory_stable; then
        published=1
        staged=0
      else
        publication_failed=1
        export_artifact rollback "${digest}" "${size}" "${inode}" || cleanup_failed=1
      fi
    else
      publication_failed=1
    fi
  fi
  if [[ "${staged}" == 1 ]]; then
    export_artifact discard "${digest}" "${size}" "${inode}" || cleanup_failed=1
  fi
  if [[ "${exit_code}" == 0 && ( "${cleanup_failed}" != 0 || "${publication_failed}" != 0 ) ]]; then
    exit_code=1
  fi
  if [[ "${exit_code}" == 0 ]]; then
    if [[ "${published}" == 1 ]]; then
      printf 'ASTER_PHASE1_CONFORMANCE_EXPORT_SHA256=%s\n' "${digest}"
      printf 'ASTER_PHASE1_CONFORMANCE_EXPORT_BYTES=%s\n' "${size}"
    fi
    printf '%s\n' 'Aster runtime candidate conformance gate passed'
  elif [[ "${cleanup_failed}" != 0 || "${publication_failed}" != 0 ]]; then
    printf 'Aster runtime candidate conformance gate failed (cleanup)\n' >&2
  fi
  exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

start_private_podman() {
  local attempt observed_pgid

  PODMAN_SERVICE_TOKEN="$(random_hex 32)"
  ASTER_PHASE1_PROCESS_TOKEN="${PODMAN_SERVICE_TOKEN}" \
    env -i PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
      XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
      ASTER_PHASE1_PROCESS_TOKEN="${PODMAN_SERVICE_TOKEN}" \
      "${SETSID_BIN}" "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" \
        --runroot "${PODMAN_RUN_ROOT}" system service --time=0 \
        "unix://${PODMAN_SOCKET}" >"${PODMAN_LOG}" 2>&1 &
  PODMAN_SERVICE_PID=$!
  # shellcheck disable=SC2016
  observed_pgid="$("${PS_BIN}" -o pgid= -p "${PODMAN_SERVICE_PID}" 2>/dev/null | \
    "${AWK_BIN}" '{gsub(/[[:space:]]/, "", $0); print}')"
  [[ "${observed_pgid}" == "${PODMAN_SERVICE_PID}" ]] || fail
  PODMAN_SERVICE_PGID="${observed_pgid}"
  for ((attempt=0; attempt<100; attempt++)); do
    if docker_cli ps >/dev/null 2>&1; then
      [[ -S "${PODMAN_SOCKET}" && ! -L "${PODMAN_SOCKET}" ]] || fail
      [[ "$(/usr/bin/stat -c %u -- "${PODMAN_SOCKET}" 2>/dev/null || true)" == \
        "$(/usr/bin/id -u)" ]] || fail
      return 0
    fi
    kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null || fail
    /usr/bin/sleep 0.1
  done
  fail
}

inspect_image_id() {
  local input=$1 result

  immutable_image "${input}" || fail
  result="$(docker_cli image inspect --format '{{.Id}}' "${input}" 2>/dev/null || true)"
  [[ "${result}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
  printf '%s' "${result}"
}

inspect_system_image_id() {
  local input=$1 result

  immutable_image "${input}" || fail
  result="$(system_docker_cli image inspect --format '{{.Id}}' "${input}" 2>/dev/null || true)"
  [[ "${result}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
  printf '%s' "${result}"
}

remove_private_image_if_present() {
  local image_id=$1 status=0

  [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  podman_cli image exists "${image_id}" >/dev/null 2>&1 || status=$?
  case "${status}" in
    0)
      run_owned_command 300 /dev/null /dev/null \
        PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
        XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
        "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" --runroot "${PODMAN_RUN_ROOT}" \
          rmi "${image_id}" || return 1
      status=0
      podman_cli image exists "${image_id}" >/dev/null 2>&1 || status=$?
      [[ "${status}" == 1 ]] || return 1
      ;;
    1) ;;
    *) return 1 ;;
  esac
}

expected_image_for_service() {
  case "$1" in
    candidate-primary-postgres) printf '%s' "${POSTGRES_IMAGE_ID}" ;;
    candidate-primary-init|candidate-conformance-core|candidate-fixture-coordinator) printf '%s' "${CANDIDATE_IMAGE_ID}" ;;
    suite-mongo) printf '%s' "${MONGO_IMAGE_ID}" ;;
    suite-server) printf '%s' "${SUITE_IMAGE_ID}" ;;
    suite-nginx) printf '%s' "${NGINX_IMAGE_ID}" ;;
    oidf-runner) printf '%s' "${RUNNER_IMAGE_ID}" ;;
    *) return 1 ;;
  esac
}

wait_for_topology() {
  local attempt service container_id metadata status health exit_code image project service_label topology
  local -a services=("$@")

  [[ "${#services[@]}" -gt 0 ]] || fail

  for ((attempt=0; attempt<180; attempt++)); do
    container_ids=()
    for service in "${services[@]}"; do
      container_id="$(compose ps --all -q "${service}" 2>/dev/null || true)"
      [[ "${container_id}" =~ ^[0-9a-f]{12,64}$ ]] || break
      metadata="$(docker_cli inspect --format '{{.Id}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}|{{.Image}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.aster.phase1.topology"}}' "${container_id}" 2>/dev/null || true)"
      IFS='|' read -r container_id status health exit_code image project service_label topology <<<"${metadata}"
      [[ "${container_id}" =~ ^[0-9a-f]{64}$ ]] || break
      [[ "${project}" == "${project_name}" && "${service_label}" == "${service}" && "${topology}" == "${TOPOLOGY_ID}" ]] || fail
      [[ "${image}" == "$(expected_image_for_service "${service}")" ]] || fail
      if [[ "${service}" != 'candidate-primary-init' && "${status}" == running && \
        "${health}" != healthy ]]; then
        podman_cli healthcheck run "${container_id}" >/dev/null 2>&1 || true
        metadata="$(docker_cli inspect --format '{{.Id}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}|{{.Image}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.aster.phase1.topology"}}' "${container_id}" 2>/dev/null || true)"
        IFS='|' read -r container_id status health exit_code image project service_label topology <<<"${metadata}"
        [[ "${project}" == "${project_name}" && "${service_label}" == "${service}" && \
          "${topology}" == "${TOPOLOGY_ID}" && \
          "${image}" == "$(expected_image_for_service "${service}")" ]] || fail
      fi
      if [[ "${service}" == 'candidate-primary-init' ]]; then
        [[ "${status}" == exited && "${exit_code}" == 0 ]] || break
      else
        [[ "${status}" == running && "${health}" == healthy ]] || break
      fi
      container_ids+=("${container_id}")
    done
    if [[ "${#container_ids[@]}" == "${#services[@]}" ]]; then
      return 0
    fi
    /usr/bin/sleep 1
  done
  fail
}

failure_stage=export-directory
if [[ -n "${EXPORT_DIR}" ]]; then
  EXPORT_IDENTITY="$(/usr/bin/stat -c '%d|%i' -- "${EXPORT_DIR}" 2>/dev/null || true)"
  export_directory_safe || fail
  export_entries="$(/usr/bin/find "${EXPORT_DIR}" -mindepth 1 -maxdepth 1 -printf '%f\n')" || fail
  [[ -z "${export_entries}" ]] || fail
fi
readonly EXPORT_IDENTITY

failure_stage=authority
[[ "$#" == 0 ]] || fail
for file in "${COMPOSE_FILE}" "${SUITE_DOCKERFILE}" "${PKI_SCRIPT}" "${DRIVER_FILE}" \
  "${RUNNER_FILE}" "${PHASE1_CLI}"; do
  [[ -f "${file}" && ! -L "${file}" ]] || fail
done
repo_origin="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
case "${repo_origin}" in
  'https://github.com/qq98982/logto.git'|'git@github.com:qq98982/logto.git'|'ssh://git@github.com/qq98982/logto.git') ;;
  *) fail ;;
esac
[[ -z "$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail
H_HEAD="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
[[ "${H_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
DRIVER_BLOB="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" rev-parse 'HEAD:.scripts/compatibility/phase1-conformance-driver.sh' 2>/dev/null || true)"
ACTUAL_DRIVER_BLOB="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" hash-object --no-filters "${DRIVER_FILE}" 2>/dev/null || true)"
[[ "${DRIVER_BLOB}" =~ ^[0-9a-f]{40}$ && "${ACTUAL_DRIVER_BLOB}" == "${DRIVER_BLOB}" ]] || fail
# shellcheck disable=SC2016
DRIVER_SHA256="$("${SHA256_BIN}" "${DRIVER_FILE}" | "${AWK_BIN}" '{print $1}')"
[[ "${DRIVER_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
RUNNER_SCRIPT_BLOB="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" rev-parse 'HEAD:.scripts/compatibility/phase1-conformance-runner.mjs' 2>/dev/null || true)"
ACTUAL_RUNNER_SCRIPT_BLOB="$("${GIT_AUTHORITY[@]}" -C "${REPO_ROOT}" hash-object --no-filters "${RUNNER_FILE}" 2>/dev/null || true)"
[[ "${RUNNER_SCRIPT_BLOB}" =~ ^[0-9a-f]{40}$ && "${ACTUAL_RUNNER_SCRIPT_BLOB}" == "${RUNNER_SCRIPT_BLOB}" ]] || fail
# shellcheck disable=SC2016
RUNNER_SCRIPT_SHA256="$("${SHA256_BIN}" "${RUNNER_FILE}" | "${AWK_BIN}" '{print $1}')"
[[ "${RUNNER_SCRIPT_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
readonly H_HEAD DRIVER_BLOB DRIVER_SHA256 RUNNER_SCRIPT_BLOB RUNNER_SCRIPT_SHA256

ASTER_ROOT="${ASTER_PHASE1_ASTER_ROOT:?required}"
CANDIDATE_IMAGE_INPUT="${ASTER_PHASE1_CANDIDATE_IMAGE-}"
CANDIDATE_ARCHIVE_INPUT="${ASTER_PHASE1_CANDIDATE_ARCHIVE-}"
EXPECTED_CANDIDATE_IMAGE_ID="${ASTER_PHASE1_CANDIDATE_IMAGE_ID-}"
[[ "${ASTER_ROOT}" == /* && -d "${ASTER_ROOT}" && ! -L "${ASTER_ROOT}" ]] || fail
ASTER_ROOT="$(/usr/bin/realpath -e -- "${ASTER_ROOT}")"
if [[ -n "${CANDIDATE_IMAGE_INPUT}" ]]; then
  [[ -z "${CANDIDATE_ARCHIVE_INPUT}" && -z "${EXPECTED_CANDIDATE_IMAGE_ID}" ]] || fail
  CANDIDATE_INPUT_CHANNEL='system-image'
  CANDIDATE_ARCHIVE_IDENTITY=''
else
  [[ -n "${CANDIDATE_ARCHIVE_INPUT}" && -n "${EXPECTED_CANDIDATE_IMAGE_ID}" ]] || fail
  [[ "${EXPECTED_CANDIDATE_IMAGE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
  assert_build_root_identity
  CANDIDATE_ARCHIVE_IDENTITY="$(candidate_archive_identity "${CANDIDATE_ARCHIVE_INPUT}" 2>/dev/null || true)"
  [[ -n "${CANDIDATE_ARCHIVE_IDENTITY}" ]] || fail
  assert_build_root_identity
  CANDIDATE_INPUT_CHANNEL='archive'
fi
readonly ASTER_ROOT CANDIDATE_IMAGE_INPUT CANDIDATE_ARCHIVE_INPUT
readonly EXPECTED_CANDIDATE_IMAGE_ID CANDIDATE_INPUT_CHANNEL CANDIDATE_ARCHIVE_IDENTITY
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

failure_stage=container-engine
start_private_podman
compose version >/dev/null 2>&1 || fail

failure_stage=images
SYSTEM_CANDIDATE_IMAGE_ID=''
if [[ "${CANDIDATE_INPUT_CHANNEL}" == 'system-image' ]]; then
  SYSTEM_CANDIDATE_IMAGE_ID="$(inspect_system_image_id "${CANDIDATE_IMAGE_INPUT}")"
  CANDIDATE_ARCHIVE="${RUN_DIR}/candidate-image.tar"
  run_owned_command 1800 /dev/null /dev/null \
    PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" DOCKER_CLIENT_TIMEOUT=1200 \
    "${DOCKER_BIN}" image save --output "${CANDIDATE_ARCHIVE}" "${CANDIDATE_IMAGE_INPUT}" || fail
  [[ -f "${CANDIDATE_ARCHIVE}" && ! -L "${CANDIDATE_ARCHIVE}" ]] || fail
  [[ "$(/usr/bin/stat -c '%u|%g|%a|%F' -- "${CANDIDATE_ARCHIVE}" 2>/dev/null || true)" == \
    "$(/usr/bin/id -u)|$(/usr/bin/id -g)|600|regular file" ]] || fail
  run_owned_command 600 /dev/null /dev/null \
    PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
    XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
    "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" --runroot "${PODMAN_RUN_ROOT}" \
      load --input "${CANDIDATE_ARCHIVE}" || fail
  /usr/bin/rm -f -- "${CANDIDATE_ARCHIVE}" || fail
  EXPECTED_PRIVATE_CANDIDATE_IMAGE_ID="${SYSTEM_CANDIDATE_IMAGE_ID}"
else
  assert_build_root_identity
  [[ "$(candidate_archive_identity "${CANDIDATE_ARCHIVE_INPUT}" 2>/dev/null || true)" == \
    "${CANDIDATE_ARCHIVE_IDENTITY}" ]] || fail
  remove_private_image_if_present "${EXPECTED_CANDIDATE_IMAGE_ID}" || fail
  run_owned_command 1800 /dev/null /dev/null \
    PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
    XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
    "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" --runroot "${PODMAN_RUN_ROOT}" \
      load --input "${CANDIDATE_ARCHIVE_INPUT}" || fail
  assert_build_root_identity
  [[ "$(candidate_archive_identity "${CANDIDATE_ARCHIVE_INPUT}" 2>/dev/null || true)" == \
    "${CANDIDATE_ARCHIVE_IDENTITY}" ]] || fail
  EXPECTED_PRIVATE_CANDIDATE_IMAGE_ID="${EXPECTED_CANDIDATE_IMAGE_ID}"
fi
CANDIDATE_IMAGE_ID="$(inspect_image_id "${EXPECTED_PRIVATE_CANDIDATE_IMAGE_ID}")"
[[ "${CANDIDATE_IMAGE_ID}" == "${EXPECTED_PRIVATE_CANDIDATE_IMAGE_ID}" ]] || fail
for image in "${POSTGRES_IMAGE}" "${MONGO_IMAGE}" "${NGINX_IMAGE}" "${RUNNER_IMAGE}"; do
  run_owned_command 900 /dev/null /dev/null \
    PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
    XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
    "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" --runroot "${PODMAN_RUN_ROOT}" \
      pull "${image}" || fail
done
POSTGRES_IMAGE_ID="$(inspect_image_id "${POSTGRES_IMAGE}")"
MONGO_IMAGE_ID="$(inspect_image_id "${MONGO_IMAGE}")"
NGINX_IMAGE_ID="$(inspect_image_id "${NGINX_IMAGE}")"
RUNNER_IMAGE_ID="$(inspect_image_id "${RUNNER_IMAGE}")"
readonly SYSTEM_CANDIDATE_IMAGE_ID EXPECTED_PRIVATE_CANDIDATE_IMAGE_ID CANDIDATE_IMAGE_ID
readonly POSTGRES_IMAGE_ID MONGO_IMAGE_ID NGINX_IMAGE_ID RUNNER_IMAGE_ID

failure_stage=suite-checkout
"${CLOSED_ENV[@]}" "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" init -q >/dev/null 2>&1 || fail
"${CLOSED_ENV[@]}" "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" remote add origin "${SUITE_REPOSITORY}" >/dev/null 2>&1 || fail
run_owned_command 600 /dev/null /dev/null \
  PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" LC_ALL=C \
  GIT_ASKPASS=/bin/false GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1 \
  SSH_ASKPASS=/bin/false "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" \
    fetch --no-tags --depth=1 origin "${SUITE_COMMIT}" || fail
"${CLOSED_ENV[@]}" "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" checkout --detach -q FETCH_HEAD >/dev/null 2>&1 || fail
[[ "$("${CLOSED_ENV[@]}" "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" rev-parse HEAD 2>/dev/null || true)" == "${SUITE_COMMIT}" ]] || fail
[[ "$("${CLOSED_ENV[@]}" "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" remote get-url origin 2>/dev/null || true)" == "${SUITE_REPOSITORY}" ]] || fail
[[ -z "$("${CLOSED_ENV[@]}" "${GIT_BIN}" --no-replace-objects -C "${SUITE_CHECKOUT}" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)" ]] || fail

failure_stage=suite-build
SUITE_IID_FILE="${RUN_DIR}/suite-image-id"
run_owned_command 1800 /dev/null /dev/null \
  PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" \
  XDG_RUNTIME_DIR="/run/user/$(/usr/bin/id -u)" \
  "${PODMAN_BIN}" --root "${PODMAN_GRAPH_ROOT}" --runroot "${PODMAN_RUN_ROOT}" \
    build --iidfile "${SUITE_IID_FILE}" --file "${SUITE_DOCKERFILE}" \
    --build-arg "ASTER_PHASE1_OIDF_SUITE_COMMIT=${SUITE_COMMIT}" "${SUITE_CHECKOUT}" || fail
SUITE_IMAGE_ID="$(/usr/bin/tr -d '[:space:]' <"${SUITE_IID_FILE}")"
if [[ "${SUITE_IMAGE_ID}" =~ ^[0-9a-f]{64}$ ]]; then
  SUITE_IMAGE_ID="sha256:${SUITE_IMAGE_ID}"
fi
[[ "${SUITE_IMAGE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
suite_metadata="$(docker_cli image inspect --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "com.aster.phase1.maven-resolution"}}' "${SUITE_IMAGE_ID}" 2>/dev/null || true)"
IFS='|' read -r inspected_suite_id inspected_suite_revision inspected_maven_resolution <<<"${suite_metadata}"
[[ "${inspected_suite_id}" == "${SUITE_IMAGE_ID}" && "${inspected_suite_revision}" == "${SUITE_COMMIT}" && "${inspected_maven_resolution}" == "${SUITE_MAVEN_RESOLUTION}" ]] || fail
readonly SUITE_IMAGE_ID

failure_stage=private-material
printf '%s\n' "$(random_hex 32)" >"${POSTGRES_PASSWORD_FILE}"
printf 'deployment_id=%s\ndatabase_sentinel=%s\n' "$(random_uuid)" "$(random_hex 32)" >"${PRIMARY_CONFIG_FILE}"
printf '%s' "$(random_hex 32)" >"${OIDF_PASSWORD_FILE}"
printf '%s' "$(random_hex 32)" >"${OIDF_BASIC_1_SECRET_FILE}"
printf '%s' "$(random_hex 32)" >"${OIDF_BASIC_2_SECRET_FILE}"
printf '%s' "$(random_hex 32)" >"${OIDF_POST_1_SECRET_FILE}"
/usr/bin/chmod 0400 "${POSTGRES_PASSWORD_FILE}" "${PRIMARY_CONFIG_FILE}" \
  "${OIDF_PASSWORD_FILE}" "${OIDF_BASIC_1_SECRET_FILE}" "${OIDF_BASIC_2_SECRET_FILE}" \
  "${OIDF_POST_1_SECRET_FILE}"
for secret_file in "${OIDF_PASSWORD_FILE}" "${OIDF_BASIC_1_SECRET_FILE}" \
  "${OIDF_BASIC_2_SECRET_FILE}" "${OIDF_POST_1_SECRET_FILE}"; do
  [[ "$(/usr/bin/stat -c '%u|%g|%a|%F' -- "${secret_file}" 2>/dev/null || true)" == \
    "$(/usr/bin/id -u)|$(/usr/bin/id -g)|400|regular file" ]] || fail
done
OIDF_ALLOCATION_ID="oidf-conformance-$(random_hex 16)"
readonly OIDF_ALLOCATION_ID
run_owned_command 180 /dev/null /dev/null \
  PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" LC_ALL=C \
  "${PKI_SCRIPT}" "${RUN_DIR}" "$(/usr/bin/id -u)" "$(/usr/bin/id -g)" || fail

failure_stage=build
run_owned_command 600 /dev/null /dev/null \
  PATH="$(dirname -- "${NODE_BIN}"):$(dirname -- "${PNPM_BIN}"):/usr/bin:/bin" \
  HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" CI=true LC_ALL=C \
  "${PNPM_BIN}" --dir "${REPO_ROOT}/packages/integration-tests" build || fail
run_owned_command 60 /dev/null /dev/null \
  PATH='/usr/bin:/bin' HOME="${PRIVATE_HOME}" TMPDIR="${PRIVATE_TMP}" LC_ALL=C \
  "${NODE_BIN}" "${PHASE1_CLI}" prepare-review-profile \
    --source-profile "${PROFILE_SOURCE}" --schema "${SCHEMA_SOURCE}" \
    --harness-commit "${H_HEAD}" --output "${REVIEW_PROFILE}" || fail
[[ -f "${REVIEW_PROFILE}" && ! -L "${REVIEW_PROFILE}" ]] || fail

{
  printf 'ASTER_PHASE1_CONFORMANCE_PROJECT_NAME=%s\n' "${project_name}"
  printf 'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST=%s\n' "${CANDIDATE_IMAGE_ID}"
  printf 'ASTER_PHASE1_OIDF_SUITE_IMAGE_DIGEST=%s\n' "${SUITE_IMAGE_ID}"
  printf 'ASTER_PHASE1_RUNTIME_UID=%s\n' "$(/usr/bin/id -u)"
  printf 'ASTER_PHASE1_RUNTIME_GID=%s\n' "$(/usr/bin/id -g)"
  printf 'ASTER_PHASE1_CONFORMANCE_POSTGRES_PASSWORD_FILE=%s\n' "${POSTGRES_PASSWORD_FILE}"
  printf 'ASTER_PHASE1_CONFORMANCE_PRIMARY_CONFIG_FILE=%s\n' "${PRIMARY_CONFIG_FILE}"
  printf 'ASTER_PHASE1_CONFORMANCE_PRIMARY_KEYRING_DIRECTORY=%s\n' "${PRIMARY_KEYRING_DIR}"
  printf 'ASTER_PHASE1_CONFORMANCE_FIXTURE_DIRECTORY=%s\n' "${FIXTURE_DIR}"
  printf 'ASTER_PHASE1_CONFORMANCE_PKI_ROOT_FILE=%s\n' "${RUN_DIR}/pki/root-ca.crt"
  printf 'ASTER_PHASE1_CONFORMANCE_ASTER_CERTIFICATE_FILE=%s\n' "${RUN_DIR}/pki/aster/tls.crt"
  printf 'ASTER_PHASE1_CONFORMANCE_ASTER_PRIVATE_KEY_FILE=%s\n' "${RUN_DIR}/pki/aster/tls.key"
  printf 'ASTER_PHASE1_CONFORMANCE_SUITE_CERTIFICATE_FILE=%s\n' "${RUN_DIR}/pki/suite/tls.crt"
  printf 'ASTER_PHASE1_CONFORMANCE_SUITE_PRIVATE_KEY_FILE=%s\n' "${RUN_DIR}/pki/suite/tls.key"
  printf 'ASTER_PHASE1_CONFORMANCE_SECRET_DIRECTORY=%s\n' "${SECRET_DIR}"
  printf 'ASTER_PHASE1_CONFORMANCE_EVIDENCE_DIRECTORY=%s\n' "${EVIDENCE_DIR}"
  printf 'ASTER_PHASE1_CONFORMANCE_DRIVER_FILE=%s\n' "${DRIVER_FILE}"
  printf 'ASTER_PHASE1_CONFORMANCE_RUNNER_FILE=%s\n' "${RUNNER_FILE}"
} >"${COMPOSE_ENV}"
/usr/bin/chmod 0400 "${COMPOSE_ENV}"

failure_stage=topology
project_started=1
compose config --quiet >/dev/null 2>&1 || fail
compose_up_phase candidate-primary-postgres suite-mongo || fail
wait_for_topology candidate-primary-postgres suite-mongo
compose_up_phase candidate-primary-init suite-server || fail
wait_for_topology candidate-primary-init suite-server
compose_up_phase candidate-conformance-core || fail
wait_for_topology candidate-conformance-core
compose_up_phase candidate-fixture-coordinator suite-nginx || fail
wait_for_topology candidate-fixture-coordinator suite-nginx
COORDINATOR_CONTAINER_ID="$(compose ps --all -q candidate-fixture-coordinator 2>/dev/null || true)"
[[ "${COORDINATOR_CONTAINER_ID}" =~ ^[0-9a-f]{64}$ ]] || fail
readonly COORDINATOR_CONTAINER_ID
failure_stage=fixture-baseline
prepare_oidf_fixture_baseline || fail
failure_stage=fixture-provision
provision_oidf_fixture || fail
compose_up_phase oidf-runner || fail
wait_for_topology oidf-runner
wait_for_topology "${SERVICES[@]}"
runner_index=$((${#SERVICES[@]} - 1))
RUNNER_CONTAINER_ID="${container_ids[runner_index]}"
readonly RUNNER_CONTAINER_ID

failure_stage=descriptor
"${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - \
  "${DESCRIPTOR_FILE}" "${project_name}" "${RUNNER_CONTAINER_ID}" "${SUITE_COMMIT}" \
  "${SUITE_IMAGE_ID}" "${CANDIDATE_IMAGE_ID}" "${RUNNER_IMAGE_ID}" "${RUNNER_DRIVER_PATH}" \
  "${DRIVER_BLOB}" "${DRIVER_SHA256}" "${RUNNER_SCRIPT_PATH}" "${RUNNER_SCRIPT_BLOB}" \
  "${RUNNER_SCRIPT_SHA256}" "${PODMAN_SOCKET}" "${TOPOLOGY_ID}" <<'NODE'
import { writeFileSync } from 'node:fs';
const [output, projectName, runnerContainerId, suiteCommit, suiteImageId, candidateImageId,
  runnerImageId, driverPath, driverBlob, driverSha256, runnerPath, runnerBlob, runnerSha256,
  engineSocket, topologyId] = process.argv.slice(2);
writeFileSync(output, `${JSON.stringify({
  schemaVersion: 1,
  kind: 'aster-phase1-runtime-candidate-conformance-descriptor',
  projectName,
  runnerContainerId,
  suiteCommit,
  suiteImageId,
  candidateImageId,
  runnerImageId,
  driverPath,
  driverBlob,
  driverSha256,
  runnerPath,
  runnerBlob,
  runnerSha256,
  engineSocket,
  topologyId,
})}\n`, { flag: 'wx', mode: 0o400 });
NODE
[[ "$(/usr/bin/stat -c '%u|%g|%a|%F' -- "${DESCRIPTOR_FILE}")" == "$(/usr/bin/id -u)|$(/usr/bin/id -g)|400|regular file" ]] || fail

failure_stage=conformance
NODE_RUN_TOKEN="$(random_hex 32)"
PUBLIC_ENV=(
  env -i
  PATH='/usr/bin:/bin'
  HOME="${PRIVATE_HOME}"
  TMPDIR="${PRIVATE_TMP}"
  ASTER_PHASE1_MODE='runtime-candidate'
  ASTER_PHASE1_PROCESS_TOKEN="${NODE_RUN_TOKEN}"
  ASTER_PHASE1_BUILD_ROOT="${BUILD_ROOT}"
  ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST="${CANDIDATE_IMAGE_ID}"
  ASTER_PHASE1_TOPOLOGY_ID="${project_name}"
  ASTER_PHASE1_CONFORMANCE_ROOT="${CONFORMANCE_ROOT}"
  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"
)
ASTER_PHASE1_PROCESS_TOKEN="${NODE_RUN_TOKEN}" "${SETSID_BIN}" "${PUBLIC_ENV[@]}" \
  "${NODE_BIN}" "${PHASE1_CLI}" run-conformance --mode runtime-candidate \
  --profile "${REVIEW_PROFILE}" --schema "${SCHEMA_SOURCE}" \
  --observation-controls --discovery-extra-control --candidate-invariant-controls >/dev/null &
NODE_RUN_PID=$!
NODE_RUN_PGID="${NODE_RUN_PID}"
node_run_status=0
wait "${NODE_RUN_PID}" || node_run_status=$?
if ! terminate_owned_process_group "${NODE_RUN_PID}" "${NODE_RUN_PGID}" "${NODE_RUN_TOKEN}"; then
  fail
fi
NODE_RUN_PID=''
NODE_RUN_PGID=''
NODE_RUN_TOKEN=''
[[ "${node_run_status}" == 0 ]] || fail

artifact_path="${EVIDENCE_DIR}/${EXPORT_NAME}"
[[ -f "${artifact_path}" && ! -L "${artifact_path}" ]] || fail
[[ "$(/usr/bin/find "${EVIDENCE_DIR}" -mindepth 1 -maxdepth 1 -printf '%f|%y\n')" == "${EXPORT_NAME}|f" ]] || fail
"${CLOSED_ENV[@]}" "${NODE_BIN}" --input-type=module - "${artifact_path}" "${CANDIDATE_IMAGE_ID}" "${ARTIFACT_CONTRACT}" <<'NODE'
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const { parseStrictPhase1ArtifactJson, assertPhase1PublicArtifactValue } =
  await import(pathToFileURL(process.argv[4]).href);
const value = parseStrictPhase1ArtifactJson(await readFile(process.argv[2]));
assertPhase1PublicArtifactValue(value);
if (value.schemaVersion !== 1 || value.mode !== 'runtime-candidate' ||
  value.sanitizerSuccess !== true || value.provenance?.imageDigest !== process.argv[3] ||
  !Array.isArray(value.adapterControls) || value.adapterControls.length !== 3 ||
  !Array.isArray(value.officialResultIds) || value.officialResultIds.length !== 2 ||
  !Array.isArray(value.planResults) || value.planResults.length !== 2) process.exit(1);
NODE
