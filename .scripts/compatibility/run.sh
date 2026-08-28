#!/usr/bin/env bash
set -euo pipefail
umask 077

REFERENCE_COMMIT=6852a7b8c8984c5c12b2061e8c51faa310a36412
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.compatibility.yml"
PROJECT_NAME="aster-lab-$$"
DEFAULT_RUN_ROOT=/var/tmp/henry-build/aster-compatibility
RUN_ROOT="${ASTER_RUN_ROOT:-${DEFAULT_RUN_ROOT}}"
SERVICES=(
  postgres-oracle
  redis-oracle
  aster-oracle
  postgres-candidate
  redis-candidate
  aster-candidate
)

prepare_run_root() {
  local parent_root resolved_parent resolved_root owner mode

  if [[ "${RUN_ROOT}" != /* ]] || [[ "${RUN_ROOT}" == / || "${RUN_ROOT}" == /tmp || "${RUN_ROOT}" == /var/tmp ]]; then
    printf '[aster] ASTER_RUN_ROOT must be a safe absolute private directory\n' >&2
    exit 1
  fi

  if [[ ! -e "${RUN_ROOT}" ]]; then
    parent_root="$(dirname -- "${RUN_ROOT}")"
    resolved_parent="$(realpath -e -- "${parent_root}" 2>/dev/null || true)"
    if [[ -z "${resolved_parent}" || "${resolved_parent}" != "${parent_root}" ]]; then
      printf '[aster] ASTER_RUN_ROOT parent is unsafe\n' >&2
      exit 1
    fi
    mkdir -m 700 -- "${RUN_ROOT}"
  fi

  if [[ ! -d "${RUN_ROOT}" || -L "${RUN_ROOT}" ]]; then
    printf '[aster] ASTER_RUN_ROOT must be a real directory\n' >&2
    exit 1
  fi

  resolved_root="$(realpath -e -- "${RUN_ROOT}" 2>/dev/null || true)"
  owner="$(stat -c %u -- "${RUN_ROOT}" 2>/dev/null || true)"
  mode="$(stat -c %a -- "${RUN_ROOT}" 2>/dev/null || true)"
  if [[ "${resolved_root}" != "${RUN_ROOT}" || "${owner}" != "$(id -u)" || "${mode}" != 700 ]]; then
    printf '[aster] ASTER_RUN_ROOT must be owned by the current user with mode 0700\n' >&2
    exit 1
  fi
}

prepare_run_root
RUN_DIR="$(mktemp -d "${RUN_ROOT}/run.XXXXXX")"
export ASTER_ORACLE_MESSAGE_DIR="${RUN_DIR}/oracle-messages"
export ASTER_CANDIDATE_MESSAGE_DIR="${RUN_DIR}/candidate-messages"
export ASTER_EVIDENCE_DIR="${RUN_DIR}/evidence"
mkdir -p \
  "${ASTER_ORACLE_MESSAGE_DIR}" \
  "${ASTER_CANDIDATE_MESSAGE_DIR}" \
  "${ASTER_EVIDENCE_DIR}"
chmod 700 \
  "${ASTER_ORACLE_MESSAGE_DIR}" \
  "${ASTER_CANDIDATE_MESSAGE_DIR}" \
  "${ASTER_EVIDENCE_DIR}"

export ASTER_POSTGRES_PASSWORD
export ASTER_SECRET_VAULT_KEK
export ASTER_STATUS_API_KEY
ASTER_POSTGRES_PASSWORD="$(node -e "process.stdout.write(require('node:crypto').randomBytes(24).toString('hex'))")"
ASTER_SECRET_VAULT_KEK="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))")"
ASTER_STATUS_API_KEY="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"

compose=()
inspect_command=()
podman_command=()
PODMAN_SERVICE_PID=
PODMAN_SERVICE_PGID=
USE_PRIVATE_PODMAN=0
PROJECT_MAY_HAVE_CONTAINERS=0

dump_logs() {
  local service

  if ((${#compose[@]} == 0)); then
    return
  fi

  for service in "${SERVICES[@]}"; do
    "${compose[@]}" logs "${service}" >"${RUN_DIR}/${service}.log" 2>&1 || true
  done
}

stop_private_podman() {
  local wait_attempt

  if [[ -z "${PODMAN_SERVICE_PID}" ]]; then
    return
  fi

  if kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
    if [[ -n "${PODMAN_SERVICE_PGID}" ]]; then
      kill -TERM -- "-${PODMAN_SERVICE_PGID}" 2>/dev/null || true
    else
      kill -TERM -- "${PODMAN_SERVICE_PID}" 2>/dev/null || true
    fi
  fi

  for ((wait_attempt = 0; wait_attempt < 50; wait_attempt++)); do
    if ! kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
    if [[ -n "${PODMAN_SERVICE_PGID}" ]]; then
      kill -KILL -- "-${PODMAN_SERVICE_PGID}" 2>/dev/null || true
    else
      kill -KILL -- "${PODMAN_SERVICE_PID}" 2>/dev/null || true
    fi
  fi
  wait "${PODMAN_SERVICE_PID}" 2>/dev/null || true
}

cleanup() {
  local exit_code=$?
  local down_status=0 verification_status=0 remaining_containers=

  trap - EXIT INT TERM
  dump_logs
  if [[ "${PROJECT_MAY_HAVE_CONTAINERS}" == "1" ]]; then
    "${compose[@]}" down -v --remove-orphans >"${RUN_DIR}/compose-down.log" 2>&1 || \
      down_status=$?

    if [[ "${USE_PRIVATE_PODMAN}" == "1" ]]; then
      if remaining_containers="$("${podman_command[@]}" ps -a -q \
        --filter "label=com.docker.compose.project=${PROJECT_NAME}" 2>>"${RUN_DIR}/compose-down.log")"; then
        :
      else
        verification_status=$?
      fi
    elif remaining_containers="$(docker ps -a -q \
      --filter "label=com.docker.compose.project=${PROJECT_NAME}" 2>>"${RUN_DIR}/compose-down.log")"; then
      :
    else
      verification_status=$?
    fi

    if [[ -n "${remaining_containers}" ]]; then
      verification_status=1
    fi
  fi
  stop_private_podman
  printf '[aster] evidence: %s\n' "${RUN_DIR}"

  if [[ "${exit_code}" == "0" && ("${down_status}" != "0" || "${verification_status}" != "0") ]]; then
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "${REPO_ROOT}"
if ! git cat-file -e "${REFERENCE_COMMIT}^{commit}" 2>/dev/null; then
  printf '[aster] reference commit is unavailable\n' >&2
  exit 1
fi

if ! git diff --quiet "${REFERENCE_COMMIT}" -- . \
  ':(exclude)docs/superpowers/**' \
  ':(exclude)packages/integration-tests/**' \
  ':(exclude)compatibility/**' \
  ':(exclude).scripts/compatibility/**' \
  ':(exclude)docker-compose.compatibility.yml' \
  ':(exclude).github/workflows/compatibility-test.yml'; then
  printf '[aster] runtime source differs from the pinned reference commit\n' >&2
  exit 1
fi

untracked_runtime="$(git ls-files --others --exclude-standard | grep -Ev \
  '^(docs/superpowers/|packages/integration-tests/|compatibility/|\.scripts/compatibility/|docker-compose\.compatibility\.yml$|\.github/workflows/compatibility-test\.yml$)' || true)"
if [[ -n "${untracked_runtime}" ]]; then
  printf '[aster] untracked runtime input:\n%s\n' "${untracked_runtime}" >&2
  exit 1
fi

prepare_reference_context() {
  local reference_context

  reference_context="${RUN_DIR}/reference-source"
  mkdir -m 700 -- "${reference_context}"
  git archive "${REFERENCE_COMMIT}" | tar -x -C "${reference_context}"

  if [[ ! -f "${reference_context}/Dockerfile.integration" ]]; then
    printf '[aster] pinned reference build context is invalid\n' >&2
    exit 1
  fi

  export ASTER_REFERENCE_CONTEXT="${reference_context}"
}

prepare_reference_context

port_is_listening() {
  local port=$1

  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn | awk -v expected_port="${port}" '
      {
        address = $4
        sub(/^.*:/, "", address)
        if (address == expected_port) {
          found = 1
        }
      }
      END { exit found ? 0 : 1 }
    '
    return
  fi

  timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" 2>/dev/null
}

for port in 3101 3201 3102 3202; do
  if port_is_listening "${port}"; then
    printf '[aster] port %s is already in use\n' "${port}" >&2
    exit 1
  fi
done

start_private_podman() {
  local docker_path=$1
  local podman_graph_root podman_run_root podman_socket podman_log
  local run_root_hash service_pgid attempt

  if ! command -v docker-compose >/dev/null 2>&1; then
    printf '[aster] classic docker-compose is required for the Podman compatibility path\n' >&2
    exit 1
  fi

  podman_graph_root="${RUN_ROOT}/podman-graph"
  # Podman 4.9 rejects run-root paths longer than 50 characters.
  # A persistent Podman graph database must always use the same run-root path.
  if [[ "${RUN_ROOT}" == "${DEFAULT_RUN_ROOT}" ]]; then
    podman_run_root="/run/user/$(id -u)/aster-compatibility"
  else
    if ! run_root_hash="$(printf '%s' "${RUN_ROOT}" | sha256sum | cut -c1-20)" || \
      [[ ! "${run_root_hash}" =~ ^[0-9a-f]{20}$ ]]; then
      printf '[aster] unable to derive the private Podman run root\n' >&2
      exit 1
    fi
    podman_run_root="/run/user/$(id -u)/aster-${run_root_hash}"
  fi
  mkdir -p "${podman_graph_root}" "${podman_run_root}"
  chmod 700 "${podman_graph_root}" "${podman_run_root}"

  exec {PODMAN_LOCK_FD}>"${RUN_ROOT}/podman.lock"
  flock -x "${PODMAN_LOCK_FD}"

  podman_socket="${RUN_DIR}/podman.sock"
  podman_log="${RUN_DIR}/podman-service.log"

  setsid "${docker_path}" \
    --root "${podman_graph_root}" \
    --runroot "${podman_run_root}" \
    system service --time=0 "unix://${podman_socket}" >"${podman_log}" 2>&1 &
  PODMAN_SERVICE_PID=$!
  if ! kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
    printf '[aster] private Podman service exited during startup\n' >&2
    exit 1
  fi
  service_pgid="$(ps -o pgid= -p "${PODMAN_SERVICE_PID}" | tr -d '[:space:]')"
  if [[ -z "${service_pgid}" || "${service_pgid}" != "${PODMAN_SERVICE_PID}" ]]; then
    printf '[aster] private Podman service process group is invalid\n' >&2
    exit 1
  fi
  PODMAN_SERVICE_PGID="${service_pgid}"

  export DOCKER_HOST="unix://${podman_socket}"
  export DOCKER_BUILDKIT=0
  export COMPOSE_DOCKER_CLI_BUILD=0
  compose=(
    env PYTHONNOUSERSITE=1 docker-compose
    -p "${PROJECT_NAME}"
    -f "${COMPOSE_FILE}"
  )
  inspect_command=(
    "${docker_path}"
    --root "${podman_graph_root}"
    --runroot "${podman_run_root}"
    inspect
  )
  podman_command=(
    "${docker_path}"
    --root "${podman_graph_root}"
    --runroot "${podman_run_root}"
  )
  USE_PRIVATE_PODMAN=1

  for ((attempt = 0; attempt < 60; attempt++)); do
    if "${compose[@]}" ps >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${PODMAN_SERVICE_PID}" 2>/dev/null; then
      printf '[aster] private Podman service exited before becoming ready\n' >&2
      exit 1
    fi
    sleep 1
  done

  printf '[aster] private Podman service readiness timed out\n' >&2
  exit 1
}

if ! docker_binary="$(command -v docker)" || \
  ! docker_path="$(readlink -f "${docker_binary}")" || \
  [[ -z "${docker_path}" ]]; then
  printf '[aster] Docker is unavailable\n' >&2
  exit 1
fi

if [[ "${docker_path}" == */podman ]]; then
  start_private_podman "${docker_path}"
else
  if docker compose version >/dev/null 2>&1; then
    compose=(docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}")
  elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}")
  else
    printf '[aster] Docker Compose is unavailable\n' >&2
    exit 1
  fi
  inspect_command=(docker inspect)
fi

wait_for_services() {
  local deadline service container_id health state all_ready failed
  local services=("$@")

  deadline=$((SECONDS + 600))
  while ((SECONDS < deadline)); do
    all_ready=1
    failed=0
    for service in "${services[@]}"; do
      container_id="$(container_id_for_service "${service}")"
      if [[ -z "${container_id}" ]]; then
        all_ready=0
        continue
      fi

      state="$("${inspect_command[@]}" --format '{{.State.Status}}' "${container_id}" 2>/dev/null || true)"
      health="$("${inspect_command[@]}" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${container_id}" 2>/dev/null || true)"
      if [[ "${USE_PRIVATE_PODMAN}" == "1" && "${state}" == "running" && "${health}" != "healthy" ]]; then
        "${podman_command[@]}" healthcheck run "${container_id}" >/dev/null 2>&1 || true
        health="$("${inspect_command[@]}" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${container_id}" 2>/dev/null || true)"
      fi
      if [[ "${state}" != "running" || "${health}" != "healthy" ]]; then
        all_ready=0
      fi
      if [[ "${state}" == "exited" || "${state}" == "dead" ]]; then
        failed=1
      fi
    done

    if [[ "${all_ready}" == "1" ]]; then
      return 0
    fi
    if [[ "${failed}" == "1" ]]; then
      printf '[aster] service exited before becoming ready\n' >&2
      "${compose[@]}" ps >"${RUN_DIR}/compose-ps.txt" 2>&1 || true
      return 1
    fi
    sleep 3
  done

  printf '[aster] service readiness timed out\n' >&2
  "${compose[@]}" ps >"${RUN_DIR}/compose-ps.txt" 2>&1 || true
  return 1
}

container_id_for_service() {
  local service=$1

  "${compose[@]}" ps -q "${service}" 2>/dev/null || true
}

canonical_image_id() {
  local container_id=$1
  local image_id

  image_id="$("${inspect_command[@]}" --format '{{.Image}}' "${container_id}")"
  if [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '%s' "${image_id}"
    return 0
  fi
  if [[ "${image_id}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'sha256:%s' "${image_id}"
    return 0
  fi

  return 1
}

"${compose[@]}" config --quiet
"${compose[@]}" build aster-oracle
if [[ "${USE_PRIVATE_PODMAN}" == "1" ]]; then
  PROJECT_MAY_HAVE_CONTAINERS=1
  "${compose[@]}" up -d \
    postgres-oracle redis-oracle postgres-candidate redis-candidate
  wait_for_services \
    postgres-oracle redis-oracle postgres-candidate redis-candidate
  "${compose[@]}" up -d --no-deps aster-oracle aster-candidate
else
  PROJECT_MAY_HAVE_CONTAINERS=1
  "${compose[@]}" up -d
fi
wait_for_services "${SERVICES[@]}"

pnpm -r --filter '@logto/integration-tests...' build

export ASTER_ORACLE_URL=http://localhost:3101
export ASTER_ORACLE_ADMIN_URL=http://localhost:3201
export ASTER_CANDIDATE_URL=http://localhost:3102
export ASTER_CANDIDATE_ADMIN_URL=http://localhost:3202
export ASTER_REPO_ROOT="${REPO_ROOT}"
export ASTER_ORACLE_IMAGE_DIGEST
export ASTER_CANDIDATE_IMAGE_DIGEST
ASTER_ORACLE_IMAGE_DIGEST="$(canonical_image_id "$(container_id_for_service aster-oracle)")"
ASTER_CANDIDATE_IMAGE_DIGEST="$(canonical_image_id "$(container_id_for_service aster-candidate)")"

if [[ ! "${ASTER_ORACLE_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
  [[ ! "${ASTER_CANDIDATE_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf '[aster] container image digest is invalid\n' >&2
  exit 1
fi

cd "${REPO_ROOT}/packages/integration-tests"
if [[ "${ASTER_WRITE_BASELINE:-0}" == "1" ]]; then
  ASTER_ALLOW_MANIFEST_WRITE=1 pnpm compatibility:inventory --target oracle --write
else
  pnpm compatibility:inventory --target oracle --check
  pnpm compatibility:inventory --target candidate --check
fi

pnpm compatibility:run
printf '[aster] positive control: zero differences\n'

set +e
pnpm compatibility:run --fault-injection discovery-issuer
negative_exit=$?
set -e
if [[ "${negative_exit}" != "2" ]]; then
  printf '[aster] negative control failed with exit %s\n' "${negative_exit}" >&2
  exit 1
fi
printf '[aster] negative control: expected difference detected\n'

pnpm compatibility:run --finalize-run \
  --negative-control-path /observations/0/value/issuer
ASTER_RUN_DUAL_TARGET=1 \
  pnpm test:only -i --config=jest.config.compatibility.js \
    ./lib/compatibility/tests/reference-parity.test.js
