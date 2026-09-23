#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ACCEPTED_H_COMMIT='83d08f0821345d1bdc01491152949cc6f044ecfb'
readonly PHASE1_RUNNER_RELATIVE='.scripts/compatibility/run-phase1-runtime-candidate.sh'
readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
readonly ARTIFACT_NAME='phase-2-base-preservation.json'

RESULT_ROOT=''
STAGING_ROOT=''
WORK_ROOT=''
RESULT_DIR=''

fail() {
  printf '%s\n' 'Aster Phase 2 base-preservation live gate failed.' >&2
  return 1
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
  '  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"\n)',
  '  ASTER_PHASE1_EVIDENCE_DIR="${EVIDENCE_DIR}"\n  ASTER_PHASE2_CANDIDATE_SOURCE_COMMIT="${CANDIDATE_SOURCE_COMMIT}"\n)'
);
replaceExact(
  'CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${foreign_key_id}:data:signing")"\n\nNODE_RUN_TOKEN=',
  'CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256="$(domain_sha256 "${foreign_key_id}:data:signing")"\nCANDIDATE_SOURCE_COMMIT="$("${GIT_AUTHORITY[@]}" -C "${ASTER_ROOT}" rev-parse HEAD)"\n[[ "${CANDIDATE_SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || fail\nreadonly CANDIDATE_SOURCE_COMMIT\n\nNODE_RUN_TOKEN='
);
replaceExact(
  "differential) gate_command='run-differential'; artifact_name='phase-1-differential.json' ;;",
  "differential) gate_command='run-differential'; artifact_name='phase-2-base-preservation.json' ;;"
);
replaceExact(
  '--harness-commit "${H_HEAD}" --output "${REVIEW_PROFILE}"',
  '--harness-commit "83d08f0821345d1bdc01491152949cc6f044ecfb" --output "${REVIEW_PROFILE}"'
);
const executionStart = source.indexOf('ASTER_PHASE1_PROCESS_TOKEN="${NODE_RUN_TOKEN}" "${SETSID_BIN}" "${PUBLIC_ENV[@]}" \\\n  "${NODE_BIN}" "${PHASE1_CLI}"');
const artifactStart = source.indexOf('\nartifact_path="${EVIDENCE_DIR}/${artifact_name}"', executionStart);
if (executionStart < 0 || artifactStart < 0) throw new Error('execution markers');
const execution = String.raw`failure_stage=raw-phase1-negative-control
raw_error_path="\${RUN_DIR}/raw-phase1-negative-control.stderr"
ASTER_PHASE1_PROCESS_TOKEN="\${NODE_RUN_TOKEN}" "\${SETSID_BIN}" "\${PUBLIC_ENV[@]}" \
  "\${NODE_BIN}" "\${PHASE1_CLI}" run-differential --mode runtime-candidate \
  --profile "\${REVIEW_PROFILE}" --schema "\${SCHEMA_SOURCE}" \
  --observation-controls --discovery-extra-control --candidate-invariant-controls \
  >/dev/null 2>"\${raw_error_path}" &
NODE_RUN_PID=$!
NODE_RUN_PGID="\${NODE_RUN_PID}"
if wait "\${NODE_RUN_PID}"; then raw_status=0; else raw_status=$?; fi
NODE_RUN_PID=''
NODE_RUN_PGID=''
raw_stderr="$(<"\${raw_error_path}")"
[[ "\${raw_status}" == 1 ]]
[[ "\${raw_stderr}" == 'Phase 1 run failed.' ]]
[[ -z "$(find "\${EVIDENCE_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]]

failure_stage=base-preservation
ASTER_PHASE1_PROCESS_TOKEN="\${NODE_RUN_TOKEN}" "\${SETSID_BIN}" "\${PUBLIC_ENV[@]}" \
  "\${NODE_BIN}" "\${REPO_ROOT}/packages/integration-tests/src/compatibility/phase-2/base-preservation/launcher.mjs" \
  run --phase1-profile "\${REVIEW_PROFILE}" --phase1-schema "\${SCHEMA_SOURCE}" \
  --phase2-profile "\${ASTER_ROOT}/compatibility/phase-2-profile.json" \
  --phase2-schema "\${ASTER_ROOT}/compatibility/phase-2-profile.schema.json" \
  --output "\${EVIDENCE_DIR}/phase-2-base-preservation.json" --temp-root "\${EVIDENCE_DIR}" \
  >/dev/null 2>&1 &
NODE_RUN_PID=$!
NODE_RUN_PGID="\${NODE_RUN_PID}"
wait "\${NODE_RUN_PID}" || fail
NODE_RUN_PID=''
NODE_RUN_PGID=''
NODE_RUN_TOKEN=''
`.replaceAll('\\${', '${');
source = source.slice(0, executionStart) + execution + source.slice(artifactStart + 1);
const validationStart = source.indexOf('"${CLOSED_NODE_ENV[@]}" "${NODE_BIN}" --input-type=module - "${artifact_path}"');
const resultStart = source.indexOf('\nRESULT_DIR="$(/usr/bin/mktemp -d', validationStart);
if (validationStart < 0 || resultStart < 0) throw new Error('validation markers');
const validation = String.raw`"\${CLOSED_NODE_ENV[@]}" "\${NODE_BIN}" --input-type=module - "\${artifact_path}" "\${ORACLE_IMAGE}" "\${CANDIDATE_IMAGE}" <<'NODE'
import { readFile } from 'node:fs/promises';
const value = JSON.parse(await readFile(process.argv[2], 'utf8'));
if (value.schemaVersion !== 1 || value.mode !== 'phase-2-base-preservation' || value.sanitizerSuccess !== true) process.exit(1);
if (value.provenance?.oracle?.imageDigest !== process.argv[3] || value.provenance?.candidate?.imageDigest !== process.argv[4]) process.exit(1);
if (!Array.isArray(value.scenarios) || value.scenarios.length !== 22 || value.scenarios.some((item) => item.differences?.length !== 0)) process.exit(1);
if (!Array.isArray(value.discoveryAppendProofs) || value.discoveryAppendProofs.length !== 2) process.exit(1);
if (value.rawPhase1NegativeControl?.scenarioId !== 'discovery.config' || value.rawPhase1NegativeControl?.detected !== true) process.exit(1);
if (!Array.isArray(value.provenance?.sourceClosure?.files) || value.provenance.sourceClosure.files.length === 0) process.exit(1);
NODE
`.replaceAll('\\${', '${');
source = source.slice(0, validationStart) + validation + source.slice(resultStart + 1);
source = source.replace(
  "printf 'Aster runtime candidate %s gate passed\\nresult=%s\\nsha256=%s\\n' \\\n  \"${RUNTIME_GATE}\" \"${RESULT_DIR}\" \"${artifact_sha256}\"",
  "printf 'Aster Phase 2 base-preservation staging complete\\nresult=%s\\nsha256=%s\\n' \\\n  \"${RESULT_DIR}\" \"${artifact_sha256}\""
);
await writeFile(destination, source, { mode: 0o500 });
TRANSFORM_NODE
}

publish_verified_result() {
  local staging=$1 files destination
  [[ -n "$RESULT_ROOT" && -n "$STAGING_ROOT" ]] || return 1
  require_private_root "$RESULT_ROOT" || return 1
  require_private_root "$STAGING_ROOT" || return 1
  [[ "$staging" == "$STAGING_ROOT"/result.* && -d "$staging" && ! -L "$staging" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u|%a|%F' -- "$staging")" == "$(/usr/bin/id -u)|700|directory" ]] || return 1
  files="$(/usr/bin/find "$staging" -mindepth 1 -maxdepth 1 -type f -printf '%f\n')"
  [[ "$files" == "$ARTIFACT_NAME" ]] || return 1
  [[ "$(/usr/bin/stat -c '%a|%F' -- "$staging/$ARTIFACT_NAME")" == '600|regular file' ]] || return 1
  destination="$RESULT_ROOT/result.$(random_hex 8)"
  [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
  /usr/bin/mv --no-clobber --no-target-directory "$staging" "$destination" || return 1
  RESULT_DIR="$destination"
  printf '%s' "$destination"
}

run_transformed_topology() {
  local generated=$1
  ASTER_PHASE1_RUNTIME_GATE=differential \
  ASTER_PHASE2_BASE_SCRIPT_DIR="$SCRIPT_DIR" \
  ASTER_PHASE2_BASE_STAGING_ROOT="$STAGING_ROOT" \
    /usr/bin/bash "$generated" >/dev/null 2>&1
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ "$status" != 0 && -n "$RESULT_DIR" && -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]]; then
    /usr/bin/rm -rf -- "$RESULT_DIR" || status=1
  fi
  if [[ -n "$WORK_ROOT" && -d "$WORK_ROOT" && ! -L "$WORK_ROOT" ]]; then
    /usr/bin/rm -rf -- "$WORK_ROOT" || status=1
  fi
  exit "$status"
}

main() {
  [[ $# == 0 ]] || { fail; return 1; }
  GIT_BIN=/usr/bin/git
  NODE_BIN="$(command -v node)"
  [[ -x "$NODE_BIN" && ! -L "$NODE_BIN" ]] || { fail; return 1; }
  SCRIPT_DIR="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
  readonly GIT_BIN NODE_BIN SCRIPT_DIR REPO_ROOT
  PHASE1_RUNNER="$REPO_ROOT/$PHASE1_RUNNER_RELATIVE"
  local accepted_blob current_blob status
  accepted_blob="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" rev-parse "$ACCEPTED_H_COMMIT:$PHASE1_RUNNER_RELATIVE")" || { fail; return 1; }
  current_blob="$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" hash-object --no-filters -- "$PHASE1_RUNNER")" || { fail; return 1; }
  [[ "$accepted_blob" =~ ^[0-9a-f]{40}$ && "$current_blob" == "$accepted_blob" ]] || { fail; return 1; }
  [[ -z "$($GIT_BIN --no-replace-objects -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]] || { fail; return 1; }
  local build_root="${ASTER_PHASE1_BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
  require_private_root "$build_root" || { fail; return 1; }
  STAGING_ROOT="$build_root/aster-phase2-base-preservation-staging"
  RESULT_ROOT="$build_root/aster-phase2-base-preservation-results"
  require_private_root "$STAGING_ROOT" || { fail; return 1; }
  require_private_root "$RESULT_ROOT" || { fail; return 1; }
  WORK_ROOT="$(/usr/bin/mktemp -d "$build_root/aster-phase2-base-preservation.XXXXXX")"
  /usr/bin/chmod 0700 "$WORK_ROOT"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  local generated="$WORK_ROOT/phase1-derived-runner.sh"
  transform_phase1_runner "$PHASE1_RUNNER" "$generated" || { fail; return 1; }
  run_transformed_topology "$generated" || { fail; return 1; }
  local staging
  staging="$(/usr/bin/find "$STAGING_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'result.*' -print)"
  [[ -n "$staging" && "$staging" != *$'\n'* ]] || { fail; return 1; }
  local published
  published="$(publish_verified_result "$staging")" || { fail; return 1; }
  RESULT_DIR="$published"
  local sha256
  sha256="$(/usr/bin/sha256sum "$RESULT_DIR/$ARTIFACT_NAME" | /usr/bin/awk '{print $1}')"
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || { fail; return 1; }
  /usr/bin/rm -rf -- "$WORK_ROOT"
  WORK_ROOT=''
  trap - EXIT INT TERM HUP
  printf 'Aster Phase 2 base-preservation live gate passed\nresult=%s\nsha256=%s\n' "$RESULT_DIR" "$sha256"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
