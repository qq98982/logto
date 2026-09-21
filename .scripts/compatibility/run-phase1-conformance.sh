#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly SUITE_REPOSITORY='https://gitlab.com/openid/conformance-suite.git'
readonly SUITE_COMMIT='0dc0e3a21ec411e92c808e5b2e2258592c22b594'
readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
BUILD_ROOT="${ASTER_PHASE1_BUILD_ROOT:-${DEFAULT_BUILD_ROOT}}"
readonly BUILD_ROOT
readonly DEFAULT_ROOT="${BUILD_ROOT}/aster-phase1-conformance"
readonly TRUSTED_PATH='/usr/bin:/bin'
readonly DRIVER_RELATIVE='.scripts/compatibility/phase1-conformance-driver.sh'
readonly RUNNER_RELATIVE='.scripts/compatibility/phase1-conformance-runner.mjs'
readonly HANDOFF_RELATIVE='.scripts/compatibility/phase1-screenshot-handoff.mjs'
readonly WRAPPER_RELATIVE='.scripts/compatibility/run-phase1-conformance.sh'
readonly RUNTIME_DESCRIPTOR_NAME='runtime-candidate-conformance.json'
readonly RUNTIME_DESCRIPTOR_KIND='aster-phase1-runtime-candidate-conformance-descriptor'
readonly RUNTIME_TOPOLOGY_ID='runtime-candidate-conformance'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly SCRIPT_PATH="${REPO_ROOT}/${WRAPPER_RELATIVE}"
readonly DRIVER_PATH="${REPO_ROOT}/${DRIVER_RELATIVE}"
readonly RUNNER_PATH="${REPO_ROOT}/${RUNNER_RELATIVE}"
readonly HANDOFF_PATH="${REPO_ROOT}/${HANDOFF_RELATIVE}"

fail() {
  printf '%s\n' 'phase 1 conformance wrapper failed' >&2
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
DOCKER_PATH=''
NODE_PATH=''
for candidate in /usr/bin/docker /bin/docker; do
  resolved_candidate="$(realpath -e -- "${candidate}" 2>/dev/null || true)"
  if [[ -n "${resolved_candidate}" && -f "${resolved_candidate}" && ! -L "${resolved_candidate}" && \
    -x "${resolved_candidate}" ]] && \
    [[ "$(stat -c %u -- "${resolved_candidate}" 2>/dev/null || true)" = 0 ]]; then
    candidate_mode="$(stat -c %a -- "${resolved_candidate}" 2>/dev/null || true)"
    if [[ "${candidate_mode}" =~ ^[0-7]{3,4}$ ]] && ! ((8#${candidate_mode} & 8#022)); then
      DOCKER_PATH="${resolved_candidate}"
      break
    fi
  fi
done
for candidate in /usr/bin/node /bin/node; do
  resolved_candidate="$(realpath -e -- "${candidate}" 2>/dev/null || true)"
  if [[ -n "${resolved_candidate}" && -f "${resolved_candidate}" && ! -L "${resolved_candidate}" && \
    -x "${resolved_candidate}" ]] && \
    [[ "$(stat -c %u -- "${resolved_candidate}" 2>/dev/null || true)" = 0 ]]; then
    candidate_mode="$(stat -c %a -- "${resolved_candidate}" 2>/dev/null || true)"
    if [[ "${candidate_mode}" =~ ^[0-7]{3,4}$ ]] && ! ((8#${candidate_mode} & 8#022)); then
      NODE_PATH="${resolved_candidate}"
      break
    fi
  fi
done
readonly DOCKER_PATH NODE_PATH
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
for repository_file in "${WRAPPER_RELATIVE}" "${DRIVER_RELATIVE}" "${HANDOFF_RELATIVE}"; do
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

capture_build_root_identity
readonly BUILD_ROOT_DEVICE BUILD_ROOT_INODE

if [[ "${root}" != "${BUILD_ROOT}/"* || "${root}" == "${BUILD_ROOT}" || "${root}" == */../* ]]; then
  fail
fi
if [[ ! -e "${root}" ]]; then
  /usr/bin/mkdir -m 700 -- "${root}" || fail
fi
if [[ ! -d "${root}" || -L "${root}" ]] || \
  [[ "$(realpath -e -- "${root}" 2>/dev/null || true)" != "${root}" ]] || \
  [[ "$(stat -c %u -- "${root}" 2>/dev/null || true)" != "$(id -u)" ]] || \
  [[ "$(stat -c %a -- "${root}" 2>/dev/null || true)" != 700 ]]; then
  fail
fi
assert_build_root_identity
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

runtime_descriptor="${root}/${RUNTIME_DESCRIPTOR_NAME}"
if [[ -e "${runtime_descriptor}" || -L "${runtime_descriptor}" ]]; then
  if [[ -z "${DOCKER_PATH}" || -z "${NODE_PATH}" || ! -f "${runtime_descriptor}" || \
    -L "${runtime_descriptor}" ]]; then
    fail
  fi
  descriptor_metadata="$(stat -c '%u|%g|%a|%F' -- "${runtime_descriptor}" 2>/dev/null || true)"
  if [[ "${descriptor_metadata}" != "$(id -u)|$(id -g)|400|regular file" ]] || \
    [[ "$(realpath -e -- "${runtime_descriptor}" 2>/dev/null || true)" != "${runtime_descriptor}" ]]; then
    fail
  fi
  descriptor_output="$("${NODE_PATH}" - "${runtime_descriptor}" "${RUNTIME_DESCRIPTOR_KIND}" \
    "${SUITE_COMMIT}" "${RUNTIME_TOPOLOGY_ID}" "${BUILD_ROOT}" "$(id -u)" <<'NODE'
const fs = require("node:fs");
const crypto = require("node:crypto");
const [descriptorPath, expectedKind, expectedCommit, expectedTopology, buildRoot, uid] = process.argv.slice(2);
const fail = () => process.exit(1);
let value;
try {
  const bytes = fs.readFileSync(descriptorPath);
  if (bytes.length < 2 || bytes.length > 16_384 || bytes.at(-1) !== 0x0a) fail();
  value = Reflect.get(JSON, "parse")(bytes.toString("utf8"));
} catch {
  fail();
}
const keys = [
  "schemaVersion", "kind", "projectName", "runnerContainerId", "suiteCommit",
  "suiteImageId", "candidateImageId", "runnerImageId", "driverPath", "driverBlob",
  "driverSha256", "runnerPath", "runnerBlob", "runnerSha256", "handoffPath",
  "handoffBlob", "handoffSha256", "screenshotRoot", "phase0ImageId",
  "phase0PostgresImageId", "phase0RedisImageId", "engineSocket", "topologyId",
];
const actualKeys = Object.keys(value ?? {});
const image = /^sha256:[0-9a-f]{64}$/;
if (
  !value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
  actualKeys.length !== keys.length || actualKeys.some((key, index) => key !== keys[index]) ||
  value.schemaVersion !== 1 || value.kind !== expectedKind ||
  !/^aster-phase1-conformance-[0-9a-f]{16}$/.test(value.projectName) ||
  !/^[0-9a-f]{64}$/.test(value.runnerContainerId) || value.suiteCommit !== expectedCommit ||
  !image.test(value.suiteImageId) || !image.test(value.candidateImageId) ||
  !image.test(value.runnerImageId) ||
  !image.test(value.phase0ImageId) || !image.test(value.phase0PostgresImageId) ||
  !image.test(value.phase0RedisImageId) ||
  value.driverPath !== "/opt/aster/phase1-conformance-driver.sh" ||
  !/^[0-9a-f]{40}$/.test(value.driverBlob) || !/^[0-9a-f]{64}$/.test(value.driverSha256) ||
  value.runnerPath !== "/opt/aster/phase1-conformance-runner.mjs" ||
  !/^[0-9a-f]{40}$/.test(value.runnerBlob) || !/^[0-9a-f]{64}$/.test(value.runnerSha256) ||
  value.handoffPath !== "/opt/aster/phase1-screenshot-handoff.mjs" ||
  !/^[0-9a-f]{40}$/.test(value.handoffBlob) || !/^[0-9a-f]{64}$/.test(value.handoffSha256) ||
  value.screenshotRoot !== `${buildRoot}/aster-phase1-screenshot-evidence/${value.screenshotRoot.split('/').at(-1)}` ||
  !/^run\.[A-Za-z0-9_-]{6,64}$/.test(value.screenshotRoot.split('/').at(-1) ?? '') ||
  value.engineSocket !== `/run/user/${uid}/aster-p1c-${crypto.createHash("sha256").update(`${buildRoot}/aster-phase1-conformance-podman-graph`).digest("hex").slice(0, 20)}.sock` ||
  value.topologyId !== expectedTopology ||
  /password|secret|token|private.?key|credential/i.test(JSON.stringify(value))
) fail();
for (const key of keys.slice(2)) process.stdout.write(`${value[key]}\n`);
NODE
)" || fail
  mapfile -t descriptor_values <<<"${descriptor_output}"
  [[ "${#descriptor_values[@]}" == 21 ]] || fail
  project_name="${descriptor_values[0]}"
  runner_container_id="${descriptor_values[1]}"
  suite_commit="${descriptor_values[2]}"
  suite_image_id="${descriptor_values[3]}"
  candidate_image_id="${descriptor_values[4]}"
  runner_image_id="${descriptor_values[5]}"
  driver_container_path="${descriptor_values[6]}"
  driver_blob="${descriptor_values[7]}"
  driver_sha256="${descriptor_values[8]}"
  runner_container_path="${descriptor_values[9]}"
  runner_blob="${descriptor_values[10]}"
  runner_sha256="${descriptor_values[11]}"
  handoff_container_path="${descriptor_values[12]}"
  handoff_blob="${descriptor_values[13]}"
  handoff_sha256="${descriptor_values[14]}"
  screenshot_root="${descriptor_values[15]}"
  phase0_image_id="${descriptor_values[16]}"
  phase0_postgres_image_id="${descriptor_values[17]}"
  phase0_redis_image_id="${descriptor_values[18]}"
  engine_socket="${descriptor_values[19]}"
  topology_id="${descriptor_values[20]}"
  [[ "${suite_commit}" == "${SUITE_COMMIT}" && "${topology_id}" == "${RUNTIME_TOPOLOGY_ID}" ]] || fail
  if [[ ! -S "${engine_socket}" || -L "${engine_socket}" ]] || \
    [[ "$(realpath -e -- "${engine_socket}" 2>/dev/null || true)" != "${engine_socket}" ]] || \
    [[ "$(stat -c %u -- "${engine_socket}" 2>/dev/null || true)" != "$(id -u)" ]]; then
    fail
  fi
  expected_driver_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" rev-parse "HEAD:${DRIVER_RELATIVE}" 2>/dev/null || true)"
  actual_driver_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" hash-object --no-filters "${driver}" 2>/dev/null || true)"
  actual_driver_sha256="$(sha256sum "${driver}" 2>/dev/null | awk '{print $1}')"
  [[ "${driver_blob}" == "${expected_driver_blob}" && "${driver_blob}" == "${actual_driver_blob}" && \
    "${driver_sha256}" == "${actual_driver_sha256}" ]] || fail
  if [[ ! -f "${RUNNER_PATH}" || -L "${RUNNER_PATH}" ]] || \
    [[ "$(realpath -e -- "${RUNNER_PATH}" 2>/dev/null || true)" != "${RUNNER_PATH}" ]] || \
    [[ "$(stat -c %u -- "${RUNNER_PATH}" 2>/dev/null || true)" != "$(id -u)" ]]; then
    fail
  fi
  runner_mode="$(stat -c %a -- "${RUNNER_PATH}" 2>/dev/null || true)"
  [[ "${runner_mode}" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#${runner_mode} & 8#022)) && fail
  expected_runner_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" rev-parse "HEAD:${RUNNER_RELATIVE}" 2>/dev/null || true)"
  actual_runner_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" hash-object --no-filters "${RUNNER_PATH}" 2>/dev/null || true)"
  actual_runner_sha256="$(sha256sum "${RUNNER_PATH}" 2>/dev/null | awk '{print $1}')"
  [[ "${runner_blob}" == "${expected_runner_blob}" && "${runner_blob}" == "${actual_runner_blob}" && \
    "${runner_sha256}" == "${actual_runner_sha256}" ]] || fail
  if [[ ! -f "${HANDOFF_PATH}" || -L "${HANDOFF_PATH}" ]] || \
    [[ "$(realpath -e -- "${HANDOFF_PATH}" 2>/dev/null || true)" != "${HANDOFF_PATH}" ]] || \
    [[ "$(stat -c %u -- "${HANDOFF_PATH}" 2>/dev/null || true)" != "$(id -u)" ]]; then
    fail
  fi
  handoff_mode="$(stat -c %a -- "${HANDOFF_PATH}" 2>/dev/null || true)"
  [[ "${handoff_mode}" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#${handoff_mode} & 8#022)) && fail
  expected_handoff_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" rev-parse "HEAD:${HANDOFF_RELATIVE}" 2>/dev/null || true)"
  actual_handoff_blob="$("${git_authority[@]}" -C "${REPO_ROOT}" hash-object --no-filters "${HANDOFF_PATH}" 2>/dev/null || true)"
  actual_handoff_sha256="$(sha256sum "${HANDOFF_PATH}" 2>/dev/null | awk '{print $1}')"
  [[ "${handoff_blob}" == "${expected_handoff_blob}" && \
    "${handoff_blob}" == "${actual_handoff_blob}" && \
    "${handoff_sha256}" == "${actual_handoff_sha256}" ]] || fail
  if [[ ! -d "${screenshot_root}" || -L "${screenshot_root}" ]] || \
    [[ "$(realpath -e -- "${screenshot_root}" 2>/dev/null || true)" != "${screenshot_root}" ]] || \
    [[ "$(stat -c '%u|%g|%a|%F' -- "${screenshot_root}" 2>/dev/null || true)" != \
      "$(id -u)|$(id -g)|700|directory" ]]; then
    fail
  fi

  engine_docker=(
    env -i PATH="${TRUSTED_PATH}" HOME="${root}"
    DOCKER_HOST="unix://${engine_socket}" "${DOCKER_PATH}"
  )
  mapfile -t project_container_ids < <("${engine_docker[@]}" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null)
  [[ "${#project_container_ids[@]}" == 14 ]] || fail
  for container_id in "${project_container_ids[@]}"; do
    [[ "${container_id}" =~ ^[0-9a-f]{64}$ ]] || fail
  done
  inspect_output="$("${engine_docker[@]}" inspect "${project_container_ids[@]}" 2>/dev/null)" || fail
  # shellcheck disable=SC2016
  "${NODE_PATH}" -e '
const fs = require("node:fs");
const [project, runnerId, suiteImage, candidateImage, runnerImage, driverSource, driverTarget,
  runnerSource, runnerTarget, handoffSource, handoffTarget, screenshotRoot, topology,
  phase0Image, phase0PostgresImage, phase0RedisImage] = process.argv.slice(1);
const fail = () => process.exit(1);
let containers;
try { containers = Reflect.get(JSON, "parse")(fs.readFileSync(0, "utf8")); } catch { fail(); }
const services = new Set([
  "candidate-primary-postgres", "candidate-primary-init", "candidate-conformance-core",
  "candidate-fixture-coordinator", "suite-mongo", "suite-server", "suite-nginx", "oidf-runner",
  "oracle-phase0-postgres", "oracle-phase0-redis", "oracle-phase0-core",
  "candidate-phase0-postgres", "candidate-phase0-redis", "candidate-phase0-core",
]);
if (!Array.isArray(containers) || containers.length !== services.size) fail();
for (const container of containers) {
  const labels = container?.Config?.Labels;
  const service = labels?.["com.docker.compose.service"];
  if (
    typeof container?.Id !== "string" || !/^[0-9a-f]{64}$/.test(container.Id) ||
    labels?.["com.docker.compose.project"] !== project ||
    labels?.["com.aster.phase1.topology"] !== topology || !services.delete(service)
  ) fail();
  const publishedPorts = Object.entries(container?.NetworkSettings?.Ports ?? {})
    .filter(([, bindings]) => Array.isArray(bindings) && bindings.length > 0);
  const control = /^(oracle|candidate)-phase0-(postgres|redis|core)$/.exec(service);
  if (control) {
    const [, side, kind] = control;
    const network = `${project}_${side}-phase0`;
    const networks = Object.keys(container?.NetworkSettings?.Networks ?? {});
    if (networks.length !== 1 || networks[0] !== network ||
      container.Image !== ({postgres: phase0PostgresImage, redis: phase0RedisImage, core: phase0Image})[kind]) fail();
    if (kind === "core") {
      const dataPort = side === "oracle" ? "3331" : "3341";
      const adminPort = side === "oracle" ? "3431" : "3441";
      const expected = {"3001/tcp": dataPort, [`${adminPort}/tcp`]: adminPort};
      if (publishedPorts.length !== 2) fail();
      for (const [port, bindings] of publishedPorts) {
        if (!Object.hasOwn(expected, port) || bindings.length !== 1 ||
          bindings[0]?.HostIp !== "127.0.0.1" || bindings[0]?.HostPort !== expected[port]) fail();
      }
      const env = Object.fromEntries((container?.Config?.Env ?? []).map((entry) => {
        const index = entry.indexOf("=");
        return [entry.slice(0, index), entry.slice(index + 1)];
      }));
      if (env.ENDPOINT !== `http://localhost:${dataPort}` ||
        env.ADMIN_ENDPOINT !== `http://localhost:${adminPort}` || env.ADMIN_PORT !== adminPort) fail();
      try {
        const database = new URL(env.DB_URL);
        const redis = new URL(env.REDIS_URL);
        if (database.hostname !== `${side}-phase0-postgres` || database.port !== "5432" ||
          database.protocol !== "postgres:" || database.pathname !== "/aster" ||
          redis.hostname !== `${side}-phase0-redis` || redis.protocol !== "redis:" || redis.port !== "6379") fail();
      } catch { fail(); }
    } else {
      const destination = kind === "postgres" ? "/var/lib/postgresql/data" : "/data";
      const mounts = container?.Mounts?.filter(({Destination}) => Destination === destination);
      if (publishedPorts.length !== 0 || mounts?.length !== 1 || mounts[0].Type !== "volume" ||
        mounts[0].Name !== `${project}_${side}-phase0-${kind}`) fail();
    }
  } else if (service !== "candidate-conformance-core" && publishedPorts.length !== 0) fail();
  if (service === "candidate-primary-init") {
    if (container?.State?.Status !== "exited" || container?.State?.ExitCode !== 0) fail();
  } else if (container?.State?.Status !== "running" || container?.State?.Health?.Status !== "healthy") fail();
  if (
    (["candidate-primary-init", "candidate-conformance-core", "candidate-fixture-coordinator"].includes(service) && container.Image !== candidateImage) ||
    (service === "suite-server" && container.Image !== suiteImage) ||
    (service === "oidf-runner" && (container.Id !== runnerId || container.Image !== runnerImage))
  ) fail();
}
if (services.size !== 0) fail();
const runner = containers.find(({ Id }) => Id === runnerId);
const driverMount = runner?.Mounts?.find(({ Destination }) => Destination === driverTarget);
const runnerMount = runner?.Mounts?.find(({ Destination }) => Destination === runnerTarget);
const handoffMount = runner?.Mounts?.find(({ Destination }) => Destination === handoffTarget);
const screenshotMount = runner?.Mounts?.find(({ Destination }) => Destination === screenshotRoot);
const environment = new Map((runner?.Config?.Env ?? []).map((entry) => {
  const separator = entry.indexOf("=");
  return [entry.slice(0, separator), entry.slice(separator + 1)];
}));
const core = containers.find(({ Config }) => Config?.Labels?.["com.docker.compose.service"] === "candidate-conformance-core");
const ports = core?.NetworkSettings?.Ports;
if (!driverMount || driverMount.Type !== "bind" || driverMount.Source !== driverSource || driverMount.RW !== false ||
  !runnerMount || runnerMount.Type !== "bind" || runnerMount.Source !== runnerSource || runnerMount.RW !== false ||
  !handoffMount || handoffMount.Type !== "bind" || handoffMount.Source !== handoffSource || handoffMount.RW !== false ||
  !screenshotMount || screenshotMount.Type !== "bind" || screenshotMount.Source !== screenshotRoot || screenshotMount.RW !== true ||
  environment.get("ASTER_PHASE1_SCREENSHOT_IPC_ROOT") !== screenshotRoot ||
  !ports || Object.keys(ports).length !== 1 || !Array.isArray(ports["3443/tcp"]) ||
  ports["3443/tcp"].length !== 1 || ports["3443/tcp"][0]?.HostIp !== "127.0.0.1" ||
  ports["3443/tcp"][0]?.HostPort !== "3443") fail();
' "${project_name}" "${runner_container_id}" "${suite_image_id}" "${candidate_image_id}" \
    "${runner_image_id}" "${driver}" "${driver_container_path}" "${RUNNER_PATH}" \
    "${runner_container_path}" "${HANDOFF_PATH}" "${handoff_container_path}" \
    "${screenshot_root}" "${topology_id}" "${phase0_image_id}" \
    "${phase0_postgres_image_id}" "${phase0_redis_image_id}" \
    <<<"${inspect_output}" || fail

  if [[ "$#" == 1 && "$1" == --verify-runtime ]]; then
    exit 0
  fi
  exec "${engine_docker[@]}" exec --interactive \
    "${runner_container_id}" "${driver_container_path}" "$@" 2>/dev/null
fi

work="$(/usr/bin/mktemp -d "${root}/run.XXXXXX")"
assert_build_root_identity
checkout="${work}/suite"
private_home="${work}/home"
private_tmp="${work}/tmp"
/usr/bin/mkdir -m 700 -- "${private_home}" "${private_tmp}"
assert_build_root_identity

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
