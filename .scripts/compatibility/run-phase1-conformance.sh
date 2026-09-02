#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly SUITE_REPOSITORY='https://gitlab.com/openid/conformance-suite.git'
readonly SUITE_COMMIT='0dc0e3a21ec411e92c808e5b2e2258592c22b594'
readonly BUILD_ROOT='/var/tmp/henry-build'
readonly DEFAULT_ROOT="${BUILD_ROOT}/aster-phase1-conformance"
readonly TRUSTED_PATH='/usr/bin:/bin'
readonly DRIVER_RELATIVE='.scripts/compatibility/phase1-conformance-driver.sh'
readonly WRAPPER_RELATIVE='.scripts/compatibility/run-phase1-conformance.sh'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly SCRIPT_PATH="${REPO_ROOT}/${WRAPPER_RELATIVE}"
readonly DRIVER_PATH="${REPO_ROOT}/${DRIVER_RELATIVE}"

fail() {
  printf '%s\n' 'phase 1 conformance wrapper failed' >&2
  exit 1
}

root="${ASTER_PHASE1_CONFORMANCE_ROOT:-${DEFAULT_ROOT}}"
driver="${ASTER_PHASE1_CONFORMANCE_DRIVER:-}"
harness_commit="${ASTER_PHASE1_HARNESS_COMMIT:-}"

GIT_PATH=''
for candidate in /usr/bin/git /bin/git; do
  resolved_candidate="$(realpath -e -- "${candidate}" 2>/dev/null || true)"
  if [[ -n "${resolved_candidate}" && -f "${resolved_candidate}" && ! -L "${resolved_candidate}" && \
    -x "${resolved_candidate}" ]] && \
    [[ "$(stat -c %u -- "${resolved_candidate}" 2>/dev/null || true)" = 0 ]]; then
    candidate_mode="$(stat -c %a -- "${resolved_candidate}" 2>/dev/null || true)"
    if [[ "${candidate_mode}" =~ ^[0-7]{3,4}$ ]] && ! ((8#${candidate_mode} & 8#022)); then
      GIT_PATH="${resolved_candidate}"
      break
    fi
  fi
done
readonly GIT_PATH
export GIT_NO_REPLACE_OBJECTS=1
git_authority=("${GIT_PATH}" --no-replace-objects)

if [[ "$(realpath -e -- "${BASH_SOURCE[0]}" 2>/dev/null || true)" != "${SCRIPT_PATH}" ]] || \
  [[ "$(stat -c %u -- "${SCRIPT_PATH}" 2>/dev/null || true)" != "$(id -u)" ]]; then
  fail
fi
if [[ "${PATH:-}" != "${TRUSTED_PATH}" || -z "${GIT_PATH}" ]] || \
  [[ ! "${harness_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  fail
fi
repo_origin="$("${git_authority[@]}" -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
case "${repo_origin}" in
  'https://github.com/qq98982/logto.git'|'git@github.com:qq98982/logto.git'|'ssh://git@github.com/qq98982/logto.git') ;;
  *) fail ;;
esac
actual_head="$("${git_authority[@]}" -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
if [[ "${actual_head}" != "${harness_commit}" ]] || \
  [[ -n "$("${git_authority[@]}" -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)" ]]; then
  fail
fi
for repository_file in "${WRAPPER_RELATIVE}" "${DRIVER_RELATIVE}"; do
  if ! "${git_authority[@]}" -C "${REPO_ROOT}" ls-files --error-unmatch -- "${repository_file}" \
    >/dev/null 2>&1; then
    fail
  fi
  expected_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" rev-parse "HEAD:${repository_file}" 2>/dev/null || true)"
  actual_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" hash-object --no-filters "${REPO_ROOT}/${repository_file}" 2>/dev/null || true)"
  if [[ ! "${expected_blob}" =~ ^[0-9a-f]{40}$ || "${actual_blob}" != "${expected_blob}" ]]; then
    fail
  fi
done

if [[ "${root}" != "${BUILD_ROOT}/"* || "${root}" == "${BUILD_ROOT}" || "${root}" == */../* ]]; then
  fail
fi
if [[ ! -e "${root}" ]]; then
  mkdir -m 700 -- "${root}" || fail
fi
if [[ ! -d "${root}" || -L "${root}" ]] || \
  [[ "$(realpath -e -- "${root}" 2>/dev/null || true)" != "${root}" ]] || \
  [[ "$(stat -c %u -- "${root}" 2>/dev/null || true)" != "$(id -u)" ]] || \
  [[ "$(stat -c %a -- "${root}" 2>/dev/null || true)" != 700 ]]; then
  fail
fi
if [[ "${driver}" != "${DRIVER_PATH}" || \
  ! -f "${driver}" || -L "${driver}" || ! -x "${driver}" ]] || \
  [[ "$(realpath -e -- "${driver}" 2>/dev/null || true)" != "${driver}" ]] || \
  [[ "$(stat -c %u -- "${driver}" 2>/dev/null || true)" != "$(id -u)" ]]; then
  fail
fi
driver_mode="$(stat -c %a -- "${driver}" 2>/dev/null || true)"
if [[ ! "${driver_mode}" =~ ^[0-7]{3,4}$ ]] || ((8#${driver_mode} & 8#022)); then
  fail
fi

work="$(mktemp -d "${root}/run.XXXXXX")"
checkout="${work}/suite"
private_home="${work}/home"
private_tmp="${work}/tmp"
mkdir -m 700 -- "${private_home}" "${private_tmp}"

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM HUP
  rm -rf -- "${work}"
  exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

env_command=(
  env -i
  "PATH=${TRUSTED_PATH}"
  "HOME=${private_home}"
  "TMPDIR=${private_tmp}"
  'GIT_ASKPASS=/bin/false'
  'GIT_CONFIG_GLOBAL=/dev/null'
  'GIT_CONFIG_NOSYSTEM=1'
  'GIT_CONFIG_SYSTEM=/dev/null'
  'GIT_TERMINAL_PROMPT=0'
  'GIT_NO_REPLACE_OBJECTS=1'
  'LC_ALL=C'
  'SSH_ASKPASS=/bin/false'
)

mkdir -m 700 -- "${checkout}"
"${env_command[@]}" "${GIT_PATH}" --no-replace-objects -C "${checkout}" init -q >/dev/null 2>&1 || fail
"${env_command[@]}" "${GIT_PATH}" --no-replace-objects -C "${checkout}" remote add origin "${SUITE_REPOSITORY}" \
  >/dev/null 2>&1 || fail
"${env_command[@]}" "${GIT_PATH}" --no-replace-objects -C "${checkout}" fetch --no-tags --depth=1 origin \
  "${SUITE_COMMIT}" >/dev/null 2>&1 || fail
"${env_command[@]}" "${GIT_PATH}" --no-replace-objects -C "${checkout}" checkout --detach -q FETCH_HEAD \
  >/dev/null 2>&1 || fail
if [[ "$("${env_command[@]}" "${GIT_PATH}" --no-replace-objects -C "${checkout}" rev-parse HEAD 2>/dev/null)" != \
  "${SUITE_COMMIT}" ]]; then
  fail
fi

# The driver emits one terminal JSON object. This wrapper deliberately does not parse or log it;
# the TypeScript adapter owns strict terminal validation and redaction.
env -i \
  "PATH=${TRUSTED_PATH}" \
  "HOME=${private_home}" \
  "TMPDIR=${private_tmp}" \
  "ASTER_PHASE1_CONFORMANCE_SUITE_ROOT=${checkout}" \
  "${driver}" "$@" 2>/dev/null
