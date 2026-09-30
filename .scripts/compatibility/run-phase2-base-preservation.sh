#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ACCEPTED_H_COMMIT='83d08f0821345d1bdc01491152949cc6f044ecfb'
readonly PHASE1_RUNNER_RELATIVE='.scripts/compatibility/run-phase1-runtime-candidate.sh'
readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
readonly ARTIFACT_NAME='phase-2-base-preservation.json'
readonly CLEANUP_PORTS=(3311 3411 3312 3412 3321 3421 3322 3422 3331 3431 3341 3441)

BUILD_ROOT=''
RESULT_ROOT=''
STAGING_ROOT=''
WORK_ROOT=''
RESULT_DIR=''
RESULT_IDENTITY=''
STAGING_DIR=''
STAGING_IDENTITY=''
CLEANUP_DESCRIPTOR=''
ENGINE_HOME=''
PUBLISHED_RESULT=''
PUBLISHED_IDENTITY=''
H_HEAD=''
H_TREE=''
PHASE1_ASTER_ROOT=''
PHASE2_ASTER_ROOT=''
PHASE1_ASTER_SOURCE_IDENTITY=''
PHASE2_ASTER_SOURCE_IDENTITY=''

fail() {
  printf '%s\n' 'Aster Phase 2 base-preservation live gate failed.' >&2
  return 1
}

trusted_binary() {
  local name=$1 candidate resolved owner group mode
  if [[ "$name" == /* ]]; then
    candidate=$name
  else
    candidate="$(command -v "$name" 2>/dev/null)" || return 1
  fi
  [[ -n "$candidate" && ! -L "$candidate" ]] || return 1
  resolved="$(/usr/bin/realpath -e -- "$candidate" 2>/dev/null)" || return 1
  [[ "$resolved" == "$candidate" && -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || return 1
  owner="$(/usr/bin/stat -c %u -- "$resolved" 2>/dev/null)" || return 1
  group="$(/usr/bin/stat -c %g -- "$resolved" 2>/dev/null)" || return 1
  mode="$(/usr/bin/stat -c %a -- "$resolved" 2>/dev/null)" || return 1
  [[ "$owner" == 0 || "$owner" == "$(/usr/bin/id -u)" ]] || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  ((8#$mode & 8#002)) && return 1
  if ((8#$mode & 8#020)); then
    [[ "$owner" == "$(/usr/bin/id -u)" && "$group" == "$(/usr/bin/id -g)" ]] || return 1
  fi
  printf '%s' "$resolved"
}

resolve_trusted_node() {
  local node version
  node="$(trusted_binary "${1:-node}")" || return 1
  version="$(/usr/bin/env -i PATH='/usr/bin:/bin' HOME='/' LC_ALL=C \
    "$node" --version 2>/dev/null)" || return 1
  [[ "$version" == 'v22.23.2' ]] || return 1
  printf '%s' "$node"
}

require_private_root() {
  local root=$1 resolved identity
  [[ "$root" == /* && "$root" != / && "$root" != */ && "$root" != *//* ]] || return 1
  [[ "$root" != *'/./'* && "$root" != *'/../'* && ! "$root" =~ [[:cntrl:]] ]] || return 1
  case "$root" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/var|/var/tmp|/dev/*|/proc/*|/sys/*) return 1 ;;
  esac
  [[ -e "$root" ]] || /usr/bin/mkdir -m 700 -- "$root" || return 1
  [[ -d "$root" && ! -L "$root" ]] || return 1
  resolved="$(/usr/bin/realpath -e -- "$root" 2>/dev/null || true)"
  identity="$(/usr/bin/stat -c '%u|%a|%F' -- "$root" 2>/dev/null || true)"
  [[ "$resolved" == "$root" && "$identity" == "$(/usr/bin/id -u)|700|directory" ]]
}

random_hex() {
  "$NODE_BIN" -e "process.stdout.write(require('node:crypto').randomBytes(Number(process.argv[1])).toString('hex'))" "$1"
}

capture_path_identity() {
  /usr/bin/stat -c '%d|%i|%u|%a|%F' -- "$1"
}

assert_path_identity() {
  [[ "$(capture_path_identity "$1" 2>/dev/null || true)" == "$2" ]]
}

capture_aster_source_identity() {
  local root=$1 resolved top head tree status origin directory
  [[ "$root" == /* && "$root" != / && "$root" != */ && "$root" != *//* ]] || return 1
  [[ "$root" != *'/./'* && "$root" != *'/../'* && ! "$root" =~ [[:cntrl:]] ]] || return 1
  [[ -d "$root" && ! -L "$root" ]] || return 1
  resolved="$(/usr/bin/realpath -e -- "$root" 2>/dev/null)" || return 1
  [[ "$resolved" == "$root" ]] || return 1
  top="$($GIT_BIN --no-replace-objects -C "$root" rev-parse --show-toplevel 2>/dev/null)" || return 1
  head="$($GIT_BIN --no-replace-objects -C "$root" rev-parse HEAD 2>/dev/null)" || return 1
  tree="$($GIT_BIN --no-replace-objects -C "$root" rev-parse 'HEAD^{tree}' 2>/dev/null)" || return 1
  status="$($GIT_BIN --no-replace-objects -C "$root" status --porcelain=v1 --untracked-files=all 2>/dev/null)" || return 1
  origin="$($GIT_BIN --no-replace-objects -C "$root" remote get-url origin 2>/dev/null)" || return 1
  directory="$(capture_path_identity "$root" 2>/dev/null)" || return 1
  [[ "$top" == "$root" && "$head" =~ ^[0-9a-f]{40}$ && "$tree" =~ ^[0-9a-f]{40}$ && \
    -z "$status" ]] || return 1
  case "$origin" in
    'https://github.com/qq98982/aster.git'|'git@github.com:qq98982/aster.git'|'ssh://git@github.com/qq98982/aster.git') ;;
    *) return 1 ;;
  esac
  printf '%s|%s|%s|%s' "$head" "$tree" "$origin" "$directory"
}

load_required_aster_roots() {
  local phase1 phase2 phase1_identity phase2_identity
  [[ -n "${ASTER_PHASE1_ASTER_ROOT+x}" && -n "${ASTER_PHASE2_ASTER_ROOT+x}" ]] || return 1
  phase1=$ASTER_PHASE1_ASTER_ROOT
  phase2=$ASTER_PHASE2_ASTER_ROOT
  [[ -n "$phase1" && -n "$phase2" && "$phase1" != "$phase2" ]] || return 1
  phase1_identity="$(capture_aster_source_identity "$phase1")" || return 1
  phase2_identity="$(capture_aster_source_identity "$phase2")" || return 1
  [[ "$phase1_identity" != "$phase2_identity" ]] || return 1
  PHASE1_ASTER_ROOT=$phase1
  PHASE2_ASTER_ROOT=$phase2
  PHASE1_ASTER_SOURCE_IDENTITY=$phase1_identity
  PHASE2_ASTER_SOURCE_IDENTITY=$phase2_identity
}

validate_engine_socket() {
  local socket=$1 parent
  [[ "$socket" == /* && ${#socket} -le 100 && "$socket" != *//* ]] || return 1
  [[ "$socket" != *'/./'* && "$socket" != *'/../'* && ! "$socket" =~ [[:cntrl:]] ]] || return 1
  [[ -S "$socket" && ! -L "$socket" ]] || return 1
  [[ "$(/usr/bin/realpath -e -- "$socket" 2>/dev/null || true)" == "$socket" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%F' -- "$socket" 2>/dev/null || true)" == \
    "$(/usr/bin/id -u)|socket" ]] || return 1
  parent="$(/usr/bin/dirname -- "$socket")"
  [[ "$(/usr/bin/realpath -e -- "$parent" 2>/dev/null || true)" == "$parent" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$parent" 2>/dev/null || true)" == \
    "$(/usr/bin/id -u)|700|directory" ]]
}

engine_cli() {
  [[ -n "$ENGINE_HOME" && -d "$ENGINE_HOME" && ! -L "$ENGINE_HOME" ]] || return 1
  if [[ -n "${ASTER_PHASE1_ENGINE_SOCKET+x}" ]]; then
    validate_engine_socket "${ASTER_PHASE1_ENGINE_SOCKET}" || return 1
    "$TIMEOUT_BIN" --signal=TERM --kill-after=5s 180s \
      "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$ENGINE_HOME" \
      DOCKER_HOST="unix://${ASTER_PHASE1_ENGINE_SOCKET}" "$DOCKER_BIN" "$@"
  else
    "$TIMEOUT_BIN" --signal=TERM --kill-after=5s 180s \
      "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$ENGINE_HOME" "$DOCKER_BIN" "$@"
  fi
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
  [[ "$state" == listening ]] || return 1
  printf '%s' "$state"
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

project_resources_absent() {
  local project=$1 containers networks volumes
  [[ "$project" =~ ^aster-phase1-[0-9a-f]{16}$ ]] || return 1
  containers="$(engine_cli ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=${project}")" || return 1
  networks="$(engine_cli network ls -q \
    --filter "label=com.docker.compose.project=${project}")" || return 1
  volumes="$(engine_cli volume ls -q \
    --filter "label=com.docker.compose.project=${project}")" || return 1
  [[ -z "$containers" && -z "$networks" && -z "$volumes" ]]
}

verify_cleanup_state() {
  local descriptor=$1 values project run_root descriptor_state owner mode links size kind
  [[ -n "$BUILD_ROOT" && -f "$descriptor" && ! -L "$descriptor" ]] || return 1
  [[ "$(/usr/bin/realpath -e -- "$descriptor" 2>/dev/null || true)" == "$descriptor" ]] || return 1
  descriptor_state="$(/usr/bin/stat -c '%u|%a|%h|%s|%F' -- "$descriptor" 2>/dev/null)" || return 1
  IFS='|' read -r owner mode links size kind <<<"$descriptor_state"
  [[ "$owner" == "$(/usr/bin/id -u)" && "$mode" == 600 && "$links" == 1 && \
    "$size" =~ ^[1-9][0-9]{0,3}$ && "$kind" == 'regular file' ]] || return 1
  values="$("$NODE_BIN" --input-type=module - "$descriptor" "$BUILD_ROOT" <<'NODE'
import { readFile } from 'node:fs/promises';
const [descriptorPath, buildRoot] = process.argv.slice(2);
const value = JSON.parse(await readFile(descriptorPath, 'utf8'));
const keys = Reflect.ownKeys(value).toSorted();
const expectedKeys = ['ports', 'projectName', 'runRoot', 'schemaVersion'];
const expectedPorts = [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441];
const leaf = typeof value.runRoot === 'string' ? value.runRoot.split('/').at(-1) : undefined;
if (Object.getPrototypeOf(value) !== Object.prototype ||
    JSON.stringify(keys) !== JSON.stringify(expectedKeys) || value.schemaVersion !== 1 ||
    !/^aster-phase1-[0-9a-f]{16}$/.test(value.projectName ?? '') ||
    value.runRoot !== `${buildRoot}/aster-phase1-runtime-candidate-differential/${leaf}` ||
    !/^run\.[A-Za-z0-9]{6}$/.test(leaf ?? '') ||
    JSON.stringify(value.ports) !== JSON.stringify(expectedPorts)) process.exit(1);
process.stdout.write(`${value.projectName}\t${value.runRoot}`);
NODE
)" || return 1
  [[ "$values" != *$'\n'* && "$values" == *$'\t'* ]] || return 1
  IFS=$'\t' read -r project run_root <<<"$values"
  [[ -n "$project" && -n "$run_root" && "$run_root" == \
    "$BUILD_ROOT"/aster-phase1-runtime-candidate-differential/run.* ]] || return 1
  [[ ! -e "$run_root" && ! -L "$run_root" ]] || return 1
  project_resources_absent "$project" || return 1
  assert_ports_released "${CLEANUP_PORTS[@]}"
}

assert_finalized_artifact() {
  local artifact=$1
  "$NODE_BIN" --input-type=module - "$artifact" <<'NODE' || return 1
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
const file = process.argv[2];
const expectedPorts = [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441];
const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
try {
  const state = await handle.stat();
  if (!state.isFile() || state.nlink !== 1 || state.uid !== process.getuid() ||
      (state.mode & 0o777) !== 0o600 || state.size <= 0 || state.size > 8 * 1024 * 1024) process.exit(1);
  const value = JSON.parse(await handle.readFile('utf8'));
  const cleanup = value.cleanup;
  if (typeof cleanup !== 'object' || cleanup === null || Array.isArray(cleanup) ||
      Object.getPrototypeOf(cleanup) !== Object.prototype ||
      JSON.stringify(Reflect.ownKeys(cleanup).toSorted()) !== JSON.stringify([
        'containersAbsent', 'networksAbsent', 'portsReleased', 'runRootAbsent', 'status', 'volumesAbsent',
      ]) || cleanup.status !== 'verified' || cleanup.containersAbsent !== true ||
      cleanup.networksAbsent !== true || cleanup.volumesAbsent !== true ||
      cleanup.runRootAbsent !== true ||
      JSON.stringify(cleanup.portsReleased) !== JSON.stringify(expectedPorts)) process.exit(1);
} finally {
  await handle.close();
}
NODE
}

finalize_cleanup_evidence() {
  local artifact=$1
  "$NODE_BIN" --input-type=module - "$artifact" <<'NODE' || return 1
import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname } from 'node:path';
import { lstat, open, rename, unlink } from 'node:fs/promises';
const file = process.argv[2];
const expectedNegative = {
  scenarioId: 'discovery.config',
  detected: true,
  errorName: 'Error',
  error: 'Phase 1 candidate discovery contains unapproved metadata',
};
const cleanup = {
  status: 'verified',
  containersAbsent: true,
  networksAbsent: true,
  volumesAbsent: true,
  runRootAbsent: true,
  portsReleased: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
};
const source = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
let temporary = '';
try {
  const state = await source.stat();
  if (!state.isFile() || state.nlink !== 1 || state.uid !== process.getuid() ||
      (state.mode & 0o777) !== 0o600 || state.size <= 0 || state.size > 8 * 1024 * 1024) process.exit(1);
  const value = JSON.parse(await source.readFile('utf8'));
  const negative = value.rawPhase1NegativeControl;
  if (Object.getPrototypeOf(value) !== Object.prototype || Object.hasOwn(value, 'cleanup') ||
      typeof negative !== 'object' || negative === null || Array.isArray(negative) ||
      Object.getPrototypeOf(negative) !== Object.prototype ||
      JSON.stringify(Reflect.ownKeys(negative).toSorted()) !==
        JSON.stringify(Reflect.ownKeys(expectedNegative).toSorted()) ||
      Object.entries(expectedNegative).some(([key, expected]) => negative[key] !== expected)) process.exit(1);
  const current = await lstat(file);
  if (current.dev !== state.dev || current.ino !== state.ino || current.isSymbolicLink()) process.exit(1);
  temporary = `${file}.cleanup.${randomBytes(8).toString('hex')}`;
  const output = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    await output.writeFile(`${JSON.stringify({ ...value, cleanup })}\n`, 'utf8');
    await output.sync();
  } finally {
    await output.close();
  }
  await rename(temporary, file);
  temporary = '';
  const parent = await open(dirname(file), constants.O_RDONLY | constants.O_DIRECTORY);
  try { await parent.sync(); } finally { await parent.close(); }
} finally {
  await source.close();
  if (temporary) await unlink(temporary).catch(() => {});
}
NODE
  assert_finalized_artifact "$artifact"
}

transform_phase1_runner() {
  local source=$1 destination=$2
  "$NODE_BIN" --input-type=module - "$source" "$destination" <<'TRANSFORM_NODE'
import { readFile, writeFile } from 'node:fs/promises';
const [sourcePath, destination] = process.argv.slice(2);
let source = await readFile(sourcePath, 'utf8');
const replaceExact = (before, after, count = 1) => {
  const pieces = source.split(before);
  if (pieces.length !== count + 1) throw new Error('source contract');
  source = pieces.join(after);
};
replaceExact(
  'SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"',
  'SCRIPT_DIR="${ASTER_PHASE2_BASE_SCRIPT_DIR:?required}"',
  2
);
replaceExact(
  'differential) RESULT_ROOT="${BUILD_ROOT}/aster-phase1-differential-evidence" ;;',
  'differential) RESULT_ROOT="${ASTER_PHASE2_BASE_STAGING_ROOT:?required}" ;;'
);
replaceExact(
  'env -i PATH="${HOST_BIN_DIRECTORY}:/usr/bin:/bin" HOME="${PRIVATE_HOME}"',
  'env -i PATH="$(dirname -- "${NODE_BIN}"):$(dirname -- "${PNPM_BIN}"):${HOST_BIN_DIRECTORY}:/usr/bin:/bin" HOME="${PRIVATE_HOME}"'
);
replaceExact(
  'ASTER_ROOT="${ASTER_PHASE1_ASTER_ROOT:?required}"\nORACLE_IMAGE_INPUT=',
  'ASTER_ROOT="${ASTER_PHASE1_ASTER_ROOT:?required}"\nPHASE2_ASTER_ROOT="${ASTER_PHASE2_ASTER_ROOT:?required}"\nORACLE_IMAGE_INPUT='
);
replaceExact(
  'ASTER_ROOT="$(/usr/bin/realpath -e -- "${ASTER_ROOT}")"\nreadonly ASTER_ROOT ORACLE_IMAGE_INPUT CANDIDATE_IMAGE_INPUT',
  'ASTER_ROOT="$(/usr/bin/realpath -e -- "${ASTER_ROOT}")"\n[[ "${PHASE2_ASTER_ROOT}" == /* && -d "${PHASE2_ASTER_ROOT}" && ! -L "${PHASE2_ASTER_ROOT}" ]] || fail\nPHASE2_ASTER_ROOT="$(/usr/bin/realpath -e -- "${PHASE2_ASTER_ROOT}")"\n[[ "${ASTER_ROOT}" != "${PHASE2_ASTER_ROOT}" ]] || fail\nreadonly ASTER_ROOT PHASE2_ASTER_ROOT ORACLE_IMAGE_INPUT CANDIDATE_IMAGE_INPUT'
);
const phase2RootSetup = String.raw`[[ -z "$("\${GIT_AUTHORITY[@]}" -C "\${ASTER_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail
phase2_aster_origin="$("\${GIT_AUTHORITY[@]}" -C "\${PHASE2_ASTER_ROOT}" remote get-url origin 2>/dev/null || true)"
case "\${phase2_aster_origin}" in
  'https://github.com/qq98982/aster.git'|'git@github.com:qq98982/aster.git'|'ssh://git@github.com/qq98982/aster.git') ;;
  *) fail ;;
esac
[[ -z "$("\${GIT_AUTHORITY[@]}" -C "\${PHASE2_ASTER_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail
PROFILE_SOURCE="\${ASTER_ROOT}/compatibility/phase-1-profile.json"
SCHEMA_SOURCE="\${ASTER_ROOT}/compatibility/phase-1-profile.schema.json"
PHASE2_PROFILE_SOURCE="\${PHASE2_ASTER_ROOT}/compatibility/phase-2-profile.json"
PHASE2_SCHEMA_SOURCE="\${PHASE2_ASTER_ROOT}/compatibility/phase-2-profile.schema.json"
[[ -f "\${PROFILE_SOURCE}" && -f "\${SCHEMA_SOURCE}" && ! -L "\${PROFILE_SOURCE}" && ! -L "\${SCHEMA_SOURCE}" ]] || fail
[[ -f "\${PHASE2_PROFILE_SOURCE}" && -f "\${PHASE2_SCHEMA_SOURCE}" && ! -L "\${PHASE2_PROFILE_SOURCE}" && ! -L "\${PHASE2_SCHEMA_SOURCE}" ]] || fail
readonly PROFILE_SOURCE SCHEMA_SOURCE PHASE2_PROFILE_SOURCE PHASE2_SCHEMA_SOURCE
`.replaceAll('\\${', '${');
replaceExact(
  '[[ -z "$("${GIT_AUTHORITY[@]}" -C "${ASTER_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail\nPROFILE_SOURCE="${ASTER_ROOT}/compatibility/phase-1-profile.json"\nSCHEMA_SOURCE="${ASTER_ROOT}/compatibility/phase-1-profile.schema.json"\n[[ -f "${PROFILE_SOURCE}" && -f "${SCHEMA_SOURCE}" && ! -L "${PROFILE_SOURCE}" && ! -L "${SCHEMA_SOURCE}" ]] || fail\nreadonly PROFILE_SOURCE SCHEMA_SOURCE',
  phase2RootSetup
);
replaceExact(
  '  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"\n)',
  '  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"\n  ASTER_PHASE2_CANDIDATE_SOURCE_COMMIT="${CANDIDATE_SOURCE_COMMIT}"\n)'
);
replaceExact(
  'CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${foreign_key_id}:data:signing")"\n\nNODE_RUN_TOKEN=',
  'CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${foreign_key_id}:data:signing")"\nCANDIDATE_SOURCE_COMMIT="$("${GIT_AUTHORITY[@]}" -C "${PHASE2_ASTER_ROOT}" rev-parse HEAD)"\n[[ "${CANDIDATE_SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || fail\n[[ -z "$("${GIT_AUTHORITY[@]}" -C "${PHASE2_ASTER_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || fail\nreadonly CANDIDATE_SOURCE_COMMIT\n\nNODE_RUN_TOKEN='
);
replaceExact(
  "differential) gate_command='run-differential'; artifact_name='phase-1-differential.json' ;;",
  "differential) gate_command='run-differential'; artifact_name='phase-2-base-preservation.json' ;;"
);
const executionStart = source.indexOf('ASTER_PHASE1_PROCESS_TOKEN="${NODE_RUN_TOKEN}" "${SETSID_BIN}" "${PUBLIC_ENV[@]}" \\\n  "${NODE_BIN}" "${PHASE1_CLI}"');
const artifactStart = source.indexOf('\nartifact_path="${EVIDENCE_DIR}/${artifact_name}"', executionStart);
if (executionStart < 0 || artifactStart < 0) throw new Error('execution markers');
const execution = String.raw`failure_stage=base-preservation
ASTER_PHASE1_PROCESS_TOKEN="\${NODE_RUN_TOKEN}" "\${SETSID_BIN}" "\${PUBLIC_ENV[@]}" \
  "\${NODE_BIN}" "\${REPO_ROOT}/packages/integration-tests/src/compatibility/phase-2/base-preservation/launcher.mjs" \
  run --phase1-profile "\${REVIEW_PROFILE}" --phase1-schema "\${SCHEMA_SOURCE}" \
  --phase2-profile "\${PHASE2_PROFILE_SOURCE}" \
  --phase2-schema "\${PHASE2_SCHEMA_SOURCE}" \
  --output "\${EVIDENCE_DIR}/phase-2-base-preservation.json" --temp-root "\${EVIDENCE_DIR}" \
  >/dev/null 2>&1 &
NODE_RUN_PID=$!
NODE_RUN_PGID="\${NODE_RUN_PID}"
wait "\${NODE_RUN_PID}" || {
  node_run_status=$?
  case "\${node_run_status}" in
    40) failure_stage=base-preservation-arguments ;;
    41) failure_stage=base-preservation-paths ;;
    42) failure_stage=base-preservation-profile ;;
    43) failure_stage=base-preservation-harness ;;
    44) failure_stage=base-preservation-closure ;;
    45) failure_stage=base-preservation-phase1 ;;
    46) failure_stage=base-preservation-runtime ;;
    47) failure_stage=base-preservation-harness-recheck ;;
    48) failure_stage=base-preservation-publish ;;
  esac
  fail
}
NODE_RUN_PID=''
NODE_RUN_PGID=''
NODE_RUN_TOKEN=''
`.replaceAll('\\${', '${');
source = source.slice(0, executionStart) + execution + source.slice(artifactStart + 1);
const validationStart = source.indexOf('"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" --input-type=module - "${artifact_path}"');
const resultStart = source.indexOf('\nRESULT_DIR="$(/usr/bin/mktemp -d', validationStart);
if (validationStart < 0 || resultStart < 0) throw new Error('validation markers');
const validation = String.raw`"\${CLOSED_NODE_ENV[@]}" "\${NODE_BIN}" --input-type=module - "\${artifact_path}" "\${ORACLE_IMAGE}" "\${CANDIDATE_IMAGE}" "\${CANDIDATE_SOURCE_COMMIT}" <<'NODE'
import { readFile } from 'node:fs/promises';
const value = JSON.parse(await readFile(process.argv[2], 'utf8'));
if (value.schemaVersion !== 1 || value.mode !== 'phase-2-base-preservation' || value.sanitizerSuccess !== true) process.exit(1);
if (value.provenance?.oracle?.imageDigest !== process.argv[3] || value.provenance?.candidate?.imageDigest !== process.argv[4]) process.exit(1);
if (value.provenance?.candidate?.sourceCommit !== process.argv[5]) process.exit(1);
if (!Array.isArray(value.scenarios) || value.scenarios.length !== 22 || value.scenarios.some((item) => item.differences?.length !== 0)) process.exit(1);
if (!Array.isArray(value.discoveryAppendProofs) || value.discoveryAppendProofs.length !== 2) process.exit(1);
const negative = value.rawPhase1NegativeControl;
if (negative?.scenarioId !== 'discovery.config' || negative?.detected !== true ||
    negative?.errorName !== 'Error' ||
    negative?.error !== 'Phase 1 candidate discovery contains unapproved metadata' ||
    Reflect.ownKeys(negative).length !== 4 || Object.hasOwn(value, 'cleanup')) process.exit(1);
if (!Array.isArray(value.provenance?.sourceClosure?.files) || value.provenance.sourceClosure.files.length === 0) process.exit(1);
NODE
`.replaceAll('\\${', '${');
source = source.slice(0, validationStart) + validation + source.slice(resultStart + 1);
const completion = String.raw`"\${CLOSED_NODE_ENV[@]}" "\${NODE_BIN}" --input-type=module - \
  "\${ASTER_PHASE2_BASE_CLEANUP_DESCRIPTOR:?required}" "\${project_name}" "\${RUN_DIR}" <<'NODE'
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
const [file, projectName, runRoot] = process.argv.slice(2);
if (!file.startsWith('/') || file.length > 4096 || /[\u0000-\u001f\u007f]/u.test(file) ||
    !/^aster-phase1-[0-9a-f]{16}$/u.test(projectName) ||
    !/^\/.+\/aster-phase1-runtime-candidate-differential\/run\.[A-Za-z0-9]{6}$/u.test(runRoot)) process.exit(1);
const value = {
  schemaVersion: 1,
  projectName,
  runRoot,
  ports: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
};
const handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
try {
  await handle.writeFile(JSON.stringify(value) + "\n", 'utf8');
  await handle.sync();
} finally {
  await handle.close();
}
NODE
printf 'Aster Phase 2 base-preservation staging complete\nresult=%s\nsha256=%s\n' \
  "\${RESULT_DIR}" "\${artifact_sha256}"
`.replaceAll('\\${', '${');
replaceExact(
  "printf 'Aster runtime candidate %s gate passed\\nresult=%s\\nsha256=%s\\n' \\\n  \"${RUNTIME_GATE}\" \"${RESULT_DIR}\" \"${artifact_sha256}\"",
  completion
);
await writeFile(destination, source, { mode: 0o500 });
TRANSFORM_NODE
}

publish_verified_result() {
  local staging=$1 files destination staging_identity staging_device result_device
  [[ -n "$RESULT_ROOT" && -n "$STAGING_ROOT" ]] || return 1
  require_private_root "$RESULT_ROOT" || return 1
  require_private_root "$STAGING_ROOT" || return 1
  [[ "$staging" == "$STAGING_ROOT"/result.* && -d "$staging" && ! -L "$staging" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$staging")" == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  files="$(/usr/bin/find "$staging" -mindepth 1 -maxdepth 1 -type f -printf '%f\n')"
  [[ "$files" == "$ARTIFACT_NAME" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%h|%F' -- "$staging/$ARTIFACT_NAME")" == \
    "$(/usr/bin/id -u)|600|1|regular file" ]] || return 1
  assert_finalized_artifact "$staging/$ARTIFACT_NAME" || return 1
  staging_identity="$(capture_path_identity "$staging")" || return 1
  [[ -z "$STAGING_IDENTITY" || "$staging_identity" == "$STAGING_IDENTITY" ]] || return 1
  staging_device="$(/usr/bin/stat -c %d -- "$staging")" || return 1
  result_device="$(/usr/bin/stat -c %d -- "$RESULT_ROOT")" || return 1
  [[ "$staging_device" == "$result_device" ]] || return 1
  destination="$RESULT_ROOT/result.$(random_hex 8)"
  [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
  PUBLISHED_RESULT="$destination"
  PUBLISHED_IDENTITY="$staging_identity"
  /usr/bin/mv --no-clobber --no-target-directory "$staging" "$destination" || return 1
  printf '%s' "$destination"
}

run_transformed_topology() {
  local generated=$1
  ASTER_PHASE1_RUNTIME_GATE=differential \
  ASTER_PHASE1_ASTER_ROOT="$PHASE1_ASTER_ROOT" \
  ASTER_PHASE2_ASTER_ROOT="$PHASE2_ASTER_ROOT" \
  ASTER_PHASE2_BASE_SCRIPT_DIR="$SCRIPT_DIR" \
  ASTER_PHASE2_BASE_STAGING_ROOT="$STAGING_ROOT" \
  ASTER_PHASE2_BASE_CLEANUP_DESCRIPTOR="$CLEANUP_DESCRIPTOR" \
    /usr/bin/bash "$generated" >/dev/null 2>&1
}

remove_owned_result() {
  local directory=$1 identity=$2 root=$3
  [[ -z "$directory" || (! -e "$directory" && ! -L "$directory") ]] && return 0
  [[ -n "$identity" && -d "$directory" && ! -L "$directory" ]] || return 1
  [[ "$directory" == "$root"/result.* ]] || return 1
  assert_path_identity "$directory" "$identity" || return 1
  /usr/bin/rm -rf -- "$directory"
}

assert_source_identity_unchanged() {
  local head tree status phase1_aster phase2_aster
  head="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" rev-parse HEAD)" || return 1
  tree="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" || return 1
  status="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" || return 1
  [[ "$head" == "$H_HEAD" && "$tree" == "$H_TREE" && -z "$status" ]] || return 1
  phase1_aster="$(capture_aster_source_identity "$PHASE1_ASTER_ROOT")" || return 1
  phase2_aster="$(capture_aster_source_identity "$PHASE2_ASTER_ROOT")" || return 1
  [[ "$phase1_aster" == "$PHASE1_ASTER_SOURCE_IDENTITY" && \
    "$phase2_aster" == "$PHASE2_ASTER_SOURCE_IDENTITY" ]]
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ "$status" != 0 ]]; then
    remove_owned_result "$PUBLISHED_RESULT" "$PUBLISHED_IDENTITY" "$RESULT_ROOT" || status=1
    remove_owned_result "$RESULT_DIR" "$RESULT_IDENTITY" "$RESULT_ROOT" || status=1
    remove_owned_result "$STAGING_DIR" "$STAGING_IDENTITY" "$STAGING_ROOT" || status=1
  fi
  if [[ -n "$WORK_ROOT" && -d "$WORK_ROOT" && ! -L "$WORK_ROOT" ]]; then
    /usr/bin/rm -rf -- "$WORK_ROOT" || status=1
  fi
  exit "$status"
}

main() {
  [[ $# == 0 ]] || { fail; return 1; }
  GIT_BIN=/usr/bin/git
  DOCKER_BIN=/usr/bin/docker
  TIMEOUT_BIN=/usr/bin/timeout
  ENV_BIN=/usr/bin/env
  SS_BIN=/usr/bin/ss
  AWK_BIN=/usr/bin/awk
  NODE_BIN="$(resolve_trusted_node node)" || { fail; return 1; }
  [[ -x "$DOCKER_BIN" && -x "$TIMEOUT_BIN" && \
    -x "$ENV_BIN" && -x "$SS_BIN" && -x "$AWK_BIN" ]] || { fail; return 1; }
  SCRIPT_DIR="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
  readonly GIT_BIN DOCKER_BIN TIMEOUT_BIN ENV_BIN SS_BIN AWK_BIN NODE_BIN SCRIPT_DIR REPO_ROOT
  PHASE1_RUNNER="$REPO_ROOT/$PHASE1_RUNNER_RELATIVE"
  local accepted_blob current_blob status
  accepted_blob="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" rev-parse "$ACCEPTED_H_COMMIT:$PHASE1_RUNNER_RELATIVE")" || { fail; return 1; }
  current_blob="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" hash-object --no-filters -- "$PHASE1_RUNNER")" || { fail; return 1; }
  [[ "$accepted_blob" =~ ^[0-9a-f]{40}$ && "$current_blob" == "$accepted_blob" ]] || { fail; return 1; }
  H_HEAD="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" rev-parse HEAD)" || { fail; return 1; }
  H_TREE="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" || { fail; return 1; }
  status="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" || { fail; return 1; }
  [[ "$H_HEAD" =~ ^[0-9a-f]{40}$ && "$H_TREE" =~ ^[0-9a-f]{40}$ && -z "$status" ]] || { fail; return 1; }
  load_required_aster_roots || { fail; return 1; }
  readonly PHASE1_ASTER_ROOT PHASE2_ASTER_ROOT
  readonly PHASE1_ASTER_SOURCE_IDENTITY PHASE2_ASTER_SOURCE_IDENTITY
  local build_root="${ASTER_PHASE1_BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
  require_private_root "$build_root" || { fail; return 1; }
  BUILD_ROOT="$build_root"
  RESULT_ROOT="$build_root/aster-phase2-base-preservation-results"
  require_private_root "$RESULT_ROOT" || { fail; return 1; }
  WORK_ROOT="$(/usr/bin/mktemp -d "$build_root/aster-phase2-base-preservation.XXXXXX")"
  /usr/bin/chmod 0700 "$WORK_ROOT"
  STAGING_ROOT="$WORK_ROOT/staging"
  require_private_root "$STAGING_ROOT" || { fail; return 1; }
  ENGINE_HOME="$WORK_ROOT/engine-home"
  /usr/bin/mkdir -m 700 -- "$ENGINE_HOME"
  CLEANUP_DESCRIPTOR="$WORK_ROOT/cleanup-descriptor.json"
  [[ ! -e "$CLEANUP_DESCRIPTOR" && ! -L "$CLEANUP_DESCRIPTOR" ]] || { fail; return 1; }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  local generated="$WORK_ROOT/phase1-derived-runner.sh"
  transform_phase1_runner "$PHASE1_RUNNER" "$generated" || { fail; return 1; }
  run_transformed_topology "$generated" || { fail; return 1; }
  assert_source_identity_unchanged || { fail; return 1; }
  verify_cleanup_state "$CLEANUP_DESCRIPTOR" || { fail; return 1; }
  local staging
  staging="$(/usr/bin/find "$STAGING_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'result.*' -print)"
  [[ -n "$staging" && "$staging" != *$'\n'* ]] || { fail; return 1; }
  STAGING_DIR="$staging"
  STAGING_IDENTITY="$(capture_path_identity "$STAGING_DIR")" || { fail; return 1; }
  finalize_cleanup_evidence "$staging/$ARTIFACT_NAME" || { fail; return 1; }
  assert_source_identity_unchanged || { fail; return 1; }
  publish_verified_result "$staging" >/dev/null || { fail; return 1; }
  RESULT_DIR="$PUBLISHED_RESULT"
  RESULT_IDENTITY="$PUBLISHED_IDENTITY"
  STAGING_DIR=''
  STAGING_IDENTITY=''
  local sha256
  sha256="$(/usr/bin/sha256sum "$RESULT_DIR/$ARTIFACT_NAME" | /usr/bin/awk '{print $1}')"
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || { fail; return 1; }
  assert_finalized_artifact "$RESULT_DIR/$ARTIFACT_NAME" || { fail; return 1; }
  assert_source_identity_unchanged || { fail; return 1; }
  /usr/bin/rm -rf -- "$WORK_ROOT"
  WORK_ROOT=''
  trap - EXIT INT TERM HUP
  printf 'Aster Phase 2 base-preservation live gate passed\nresult=%s\nsha256=%s\n' "$RESULT_DIR" "$sha256"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
