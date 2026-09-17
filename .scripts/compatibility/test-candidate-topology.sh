#!/usr/bin/env bash

set -euo pipefail
umask 077
export LC_ALL=C

readonly FORMAL_RUNNER_SHA256='d1bc2e9d191402cae9225bcf1728f8b384706ae6f88b877240b62842712edc07'
readonly DEFAULT_BUILD_ROOT='/var/tmp/henry-build'
readonly POSTGRES_IMAGE='docker.io/library/postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
readonly HOST_FIXTURE_IMAGE='docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32'
readonly FIXTURE_RECIPE_ORDER='none fullPhase1 corsBoundary dataProtocol passwordMatrix adminConsole consentBoundary'
readonly SERVICES=(
  candidate-primary-postgres candidate-primary-init candidate-primary-core
  candidate-foreign-postgres candidate-foreign-init candidate-foreign-core
  candidate-fixture-coordinator
  candidate-connector-host candidate-saml-host candidate-script-host
)
readonly LOOPBACK_PROXY_BINDINGS=(
  'candidate-primary-core|candidate-primary|172.30.241.12|3321|3001'
  'candidate-primary-core|candidate-primary|172.30.241.12|3421|3421'
  'candidate-foreign-core|candidate-foreign|172.30.242.12|3322|3001'
  'candidate-foreign-core|candidate-foreign|172.30.242.12|3422|3002'
)
readonly ASTER_ADMIN_LDD_ALLOWLIST=(
  /lib64/ld-linux-x86-64.so.2
  libc.so.6
  libgcc_s.so.1
  libm.so.6
  linux-vdso.so.1
)

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
readonly REPO_ROOT
readonly COMPOSE_FILE="$REPO_ROOT/docker-compose.phase1-aster-candidate.yml"
readonly FORMAL_RUNNER="$REPO_ROOT/.scripts/compatibility/run-phase1.sh"
BUILD_ROOT="${ASTER_PHASE1_BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
readonly BUILD_ROOT
ASTER_ROOT="${ASTER_PHASE1_ASTER_ROOT:?required}"
CANDIDATE_IMAGE_INPUT="${ASTER_PHASE1_CANDIDATE_IMAGE:?required}"
readonly CANDIDATE_IMAGE_INPUT
NODE_INPUT="${ASTER_PHASE1_NODE_BIN:?required}"
readonly NODE_INPUT
failure_stage=initialization

fail() {
  printf 'Aster candidate topology smoke failed (%s)\n' "$failure_stage" >&2
  exit 1
}

trusted_system_binary() {
  local path=$1 resolved owner mode
  resolved="$(/usr/bin/realpath -e -- "$path" 2>/dev/null || true)"
  [[ -n "$resolved" && -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || fail
  owner="$(/usr/bin/stat -c %u -- "$resolved" 2>/dev/null || true)"
  mode="$(/usr/bin/stat -c %a -- "$resolved" 2>/dev/null || true)"
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#$mode & 8#022)) && fail
  printf '%s' "$resolved"
}

DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)"
ENV_BIN="$(trusted_system_binary /usr/bin/env)"
SETSID_BIN="$(trusted_system_binary /usr/bin/setsid)"
SOCAT_BIN="$(trusted_system_binary /usr/bin/socat)"
SS_BIN="$(trusted_system_binary /usr/bin/ss)"
AWK_BIN="$(trusted_system_binary /usr/bin/awk)"
OPENSSL_BIN="$(trusted_system_binary /usr/bin/openssl)"
STAT_BIN="$(trusted_system_binary /usr/bin/stat)"
REALPATH_BIN="$(trusted_system_binary /usr/bin/realpath)"
SHA256_BIN="$(trusted_system_binary /usr/bin/sha256sum)"
TAR_BIN="$(trusted_system_binary /usr/bin/tar)"
READELF_BIN="$(trusted_system_binary /usr/bin/readelf)"
LDD_BIN="$(trusted_system_binary /usr/bin/ldd)"
NODE_BIN="$($REALPATH_BIN -e -- "$NODE_INPUT" 2>/dev/null || true)"
[[ -f "$NODE_BIN" && -x "$NODE_BIN" && ! -L "$NODE_BIN" ]] || fail
node_owner="$($STAT_BIN -c %u -- "$NODE_BIN")"
node_group="$($STAT_BIN -c %g -- "$NODE_BIN")"
node_mode="$($STAT_BIN -c %a -- "$NODE_BIN")"
[[ "$node_owner" == 0 || "$node_owner" == "$(id -u)" ]] || fail
((8#$node_mode & 8#002)) && fail
if ((8#$node_mode & 8#020)); then
  [[ "$node_owner" == "$(id -u)" && "$node_group" == "$(id -g)" ]] || fail
fi
[[ "$($ENV_BIN -i PATH='/usr/bin:/bin' "$NODE_BIN" --version)" == v22.23.2 ]] || fail
readonly DOCKER_BIN ENV_BIN SETSID_BIN SOCAT_BIN SS_BIN AWK_BIN OPENSSL_BIN
readonly STAT_BIN REALPATH_BIN SHA256_BIN TAR_BIN READELF_BIN LDD_BIN NODE_BIN

require_private_root() {
  local root=$1 resolved owner mode
  [[ "$root" == /* && "$root" != */ && "$root" != *//* && "$root" != *'/../'* ]] || fail
  if [[ ! -e "$root" ]]; then
    /usr/bin/mkdir -m 700 -- "$root" || fail
  fi
  [[ -d "$root" && ! -L "$root" ]] || fail
  resolved="$($REALPATH_BIN -e -- "$root" 2>/dev/null || true)"
  owner="$($STAT_BIN -c %u -- "$root" 2>/dev/null || true)"
  mode="$($STAT_BIN -c %a -- "$root" 2>/dev/null || true)"
  [[ "$resolved" == "$root" && "$owner" == "$(id -u)" && "$mode" == 700 ]] || fail
}

declare -A PATH_DEVICES=()
declare -A PATH_INODES=()

capture_path_identity() {
  local path=$1
  require_private_root "$path"
  PATH_DEVICES["$path"]="$($STAT_BIN -c %d -- "$path")"
  PATH_INODES["$path"]="$($STAT_BIN -c %i -- "$path")"
  [[ "${PATH_DEVICES[$path]}" =~ ^[0-9]+$ && "${PATH_INODES[$path]}" =~ ^[0-9]+$ ]] || fail
}

assert_path_identity() {
  local path=$1
  require_private_root "$path"
  [[ "$($STAT_BIN -c %d -- "$path")" == "${PATH_DEVICES[$path]}" ]] || fail
  [[ "$($STAT_BIN -c %i -- "$path")" == "${PATH_INODES[$path]}" ]] || fail
}

random_hex() {
  local value
  value="$($OPENSSL_BIN rand -hex "$1")"
  [[ "$value" =~ ^[0-9a-f]+$ ]] || fail
  printf '%s' "$value"
}

random_uuid() {
  local value
  value="$(random_hex 16)"
  printf '%s-%s-%s-%s-%s' \
    "${value:0:8}" "${value:8:4}" "${value:12:4}" "${value:16:4}" "${value:20:12}"
}

immutable_image() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ || "$1" =~ ^[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}$ ]]
}

RUN_ROOT="$BUILD_ROOT/aster-candidate-topology"
require_private_root "$BUILD_ROOT"
capture_path_identity "$RUN_ROOT"
RUN_DIR="$(/usr/bin/mktemp -d "$RUN_ROOT/run.XXXXXX")"
/usr/bin/chmod 0700 "$RUN_DIR"
capture_path_identity "$RUN_DIR"
readonly RUN_ROOT RUN_DIR
PRIVATE_HOME="$RUN_DIR/home"
PRIMARY_KEYRING_DIRECTORY="$RUN_DIR/candidate-primary-keys"
FOREIGN_KEYRING_DIRECTORY="$RUN_DIR/candidate-foreign-keys"
FIXTURE_DIRECTORY="$RUN_DIR/fixture"
HOST_BIN_DIRECTORY="$RUN_DIR/host-bin"
for directory in "$PRIVATE_HOME" "$PRIMARY_KEYRING_DIRECTORY" "$FOREIGN_KEYRING_DIRECTORY" \
  "$FIXTURE_DIRECTORY" "$HOST_BIN_DIRECTORY"; do
  /usr/bin/mkdir -m 700 -- "$directory"
  capture_path_identity "$directory"
done
readonly PRIVATE_HOME PRIMARY_KEYRING_DIRECTORY FOREIGN_KEYRING_DIRECTORY FIXTURE_DIRECTORY
readonly HOST_BIN_DIRECTORY

PRIMARY_CONFIG_FILE="$RUN_DIR/candidate-primary.conf"
FOREIGN_CONFIG_FILE="$RUN_DIR/candidate-foreign.conf"
FIXTURE_SOCKET="$FIXTURE_DIRECTORY/aster-fixture.sock"
COMPOSE_ENV="$RUN_DIR/compose.env"
fixture_node_script="$RUN_DIR/fixture-smoke.mjs"
readonly PRIMARY_CONFIG_FILE FOREIGN_CONFIG_FILE FIXTURE_SOCKET COMPOSE_ENV fixture_node_script
primary_deployment_id="$(random_uuid)"
foreign_deployment_id="$(random_uuid)"
primary_sentinel="$(random_hex 32)"
foreign_sentinel="$(random_hex 32)"
primary_password="$(random_hex 32)"
foreign_password="$(random_hex 32)"
[[ "$primary_deployment_id" != "$foreign_deployment_id" \
  && "$primary_sentinel" != "$foreign_sentinel" \
  && "$primary_password" != "$foreign_password" ]] || fail
printf 'deployment_id=%s\ndatabase_sentinel=%s\n' \
  "$primary_deployment_id" "$primary_sentinel" >"$PRIMARY_CONFIG_FILE"
printf 'deployment_id=%s\ndatabase_sentinel=%s\n' \
  "$foreign_deployment_id" "$foreign_sentinel" >"$FOREIGN_CONFIG_FILE"
/usr/bin/chmod 0400 "$PRIMARY_CONFIG_FILE" "$FOREIGN_CONFIG_FILE"

project_name="aster-phase1-$(random_hex 8)"
readonly project_name
fixture_socket_device=''
fixture_socket_inode=''
candidate_image_id=''
extract_container_id=''
extract_container_name="${project_name}-extract"
project_started=0
coordinator_stopped=0
container_ids=()
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_START_TIMES=()
PROXY_EXECUTABLES=()

docker_cli() {
  local duration=${DOCKER_COMMAND_TIMEOUT:-60s}
  /usr/bin/timeout --signal=TERM --kill-after=10s "$duration" \
    "$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" "$DOCKER_BIN" "$@"
}

compose() {
  DOCKER_COMMAND_TIMEOUT=${COMPOSE_COMMAND_TIMEOUT:-300s} docker_cli compose --env-file "$COMPOSE_ENV" \
    --project-name "$project_name" --file "$COMPOSE_FILE" "$@"
}

service_container_id() {
  local service=$1 result
  result="$(docker_cli ps -aq \
    --filter "label=com.docker.compose.project=${project_name}" \
    --filter "label=com.docker.compose.service=${service}")"
  [[ "$result" =~ ^[0-9a-f]{12,64}$ ]] || fail
  printf '%s' "$result"
}

container_network_ipv4() {
  local service=$1 network=$2 expected=$3 container_id network_name result
  container_id="$(service_container_id "$service")"
  network_name="${project_name}_${network}"
  result="$(docker_cli inspect --format \
    "{{with index .NetworkSettings.Networks \"${network_name}\"}}{{.IPAddress}}{{end}}" \
    "$container_id")"
  [[ "$result" == "$expected" ]] || fail
  printf '%s' "$result"
}

read_process_identity() {
  local pid=$1 stat remainder
  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/${pid}/stat" ]] || return 1
  stat="$(<"/proc/${pid}/stat")"
  remainder=${stat##*) }
  local -a fields=()
  read -r -a fields <<<"$remainder"
  [[ "${#fields[@]}" -ge 20 ]] || return 1
  observed_state=${fields[0]}
  observed_pgid=${fields[2]}
  observed_start_time=${fields[19]}
  observed_executable="$($REALPATH_BIN -e -- "/proc/${pid}/exe" 2>/dev/null || true)"
}

port_is_listened_by_pid() {
  local port=$1 pid=$2
  # The awk program must receive literal field references.
  # shellcheck disable=SC2016
  "$SS_BIN" -H -ltnp | "$AWK_BIN" \
    -v expected_address="127.0.0.1:${port}" \
    -v expected_process="pid=${pid}([,)]|$)" '
      $4 == expected_address && $0 ~ expected_process { found=1 }
      END { exit found ? 0 : 1 }
    '
}

process_group_exists() {
  kill -0 -- "-$1" 2>/dev/null
}

terminate_owned_process_group() {
  local pid=$1 pgid=$2 start_time=$3 executable=$4
  if read_process_identity "$pid"; then
    [[ "$observed_start_time" == "$start_time" && "$observed_pgid" == "$pgid" ]] || return 1
    if [[ "$observed_state" != Z ]]; then
      [[ "$observed_executable" == "$executable" ]] || return 1
    fi
  fi
  if process_group_exists "$pgid"; then
    kill -TERM -- "-$pgid" 2>/dev/null || return 1
  fi
  for _ in {1..50}; do
    if ! read_process_identity "$pid" || [[ "$observed_state" == Z ]]; then
      break
    fi
    /usr/bin/sleep 0.1
  done
  if read_process_identity "$pid" && [[ "$observed_state" != Z ]]; then
    [[ "$observed_start_time" == "$start_time" && "$observed_pgid" == "$pgid" \
      && "$observed_executable" == "$executable" ]] || return 1
    kill -KILL -- "-$pgid" 2>/dev/null || return 1
  fi
  wait "$pid" 2>/dev/null || true
  for _ in {1..50}; do
    process_group_exists "$pgid" || return 0
    /usr/bin/sleep 0.1
  done
  kill -KILL -- "-$pgid" 2>/dev/null || return 1
  for _ in {1..50}; do
    process_group_exists "$pgid" || return 0
    /usr/bin/sleep 0.1
  done
  return 1
}

start_loopback_proxy() {
  local service=$1 network=$2 expected_ip=$3 host_port=$4 container_port=$5
  local target_ip pid executable
  target_ip="$(container_network_ipv4 "$service" "$network" "$expected_ip")"
  # The awk program must receive a literal $4 field reference.
  # shellcheck disable=SC2016
  ! "$SS_BIN" -H -ltn | "$AWK_BIN" -v expected="127.0.0.1:${host_port}" \
    '$4 == expected { found=1 } END { exit found ? 0 : 1 }' || fail
  "$SETSID_BIN" "$ENV_BIN" -i PATH='/usr/bin:/bin' "$SOCAT_BIN" \
    "TCP4-LISTEN:${host_port},bind=127.0.0.1,reuseaddr,fork" \
    "TCP4:${target_ip}:${container_port}" </dev/null >/dev/null 2>&1 &
  pid=$!
  executable="$($REALPATH_BIN -e -- "$SOCAT_BIN")"
  for _ in {1..100}; do
    if read_process_identity "$pid" \
      && [[ "$observed_state" != Z && "$observed_pgid" == "$pid" \
        && "$observed_executable" == "$executable" ]] \
      && port_is_listened_by_pid "$host_port" "$pid"; then
      PROXY_PIDS+=("$pid")
      PROXY_PGIDS+=("$observed_pgid")
      PROXY_START_TIMES+=("$observed_start_time")
      PROXY_EXECUTABLES+=("$executable")
      return 0
    fi
    /usr/bin/sleep 0.05
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  fail
}

remove_owned_fixture_socket() {
  if [[ ! -e "$FIXTURE_SOCKET" && ! -L "$FIXTURE_SOCKET" && ! -S "$FIXTURE_SOCKET" ]]; then
    return 0
  fi
  [[ ! -L "$FIXTURE_SOCKET" && -S "$FIXTURE_SOCKET" ]] || return 1
  [[ "$($STAT_BIN -c %u -- "$FIXTURE_SOCKET")" == "$(id -u)" ]] || return 1
  [[ "$($STAT_BIN -c %a -- "$FIXTURE_SOCKET")" == 600 ]] || return 1
  [[ "$($STAT_BIN -c %d -- "$FIXTURE_SOCKET")" == "$fixture_socket_device" ]] || return 1
  [[ "$($STAT_BIN -c %i -- "$FIXTURE_SOCKET")" == "$fixture_socket_inode" ]] || return 1
  /usr/bin/rm -f -- "$FIXTURE_SOCKET"
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  trap '' TERM INT
  local cleanup_failed=0 index
  if [[ "$project_started" == 1 && "$coordinator_stopped" == 0 ]]; then
    compose stop -t 20 candidate-fixture-coordinator >/dev/null 2>&1 || cleanup_failed=1
    coordinator_stopped=1
  fi
  remove_owned_fixture_socket || cleanup_failed=1
  for ((index = ${#PROXY_PGIDS[@]} - 1; index >= 0; index--)); do
    terminate_owned_process_group \
      "${PROXY_PIDS[$index]}" "${PROXY_PGIDS[$index]}" \
      "${PROXY_START_TIMES[$index]}" "${PROXY_EXECUTABLES[$index]}" || cleanup_failed=1
  done
  PROXY_PIDS=()
  PROXY_PGIDS=()
  PROXY_START_TIMES=()
  PROXY_EXECUTABLES=()
  if [[ "$project_started" == 1 ]]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || cleanup_failed=1
    remaining_project_containers="$(docker_cli ps -aq \
      --filter "label=com.docker.compose.project=${project_name}" 2>/dev/null || true)"
    [[ -z "$remaining_project_containers" ]] || cleanup_failed=1
  fi
  if [[ "$extract_container_id" =~ ^[0-9a-f]{12,64}$ ]]; then
    docker_cli rm --force --volumes "$extract_container_id" >/dev/null 2>&1 || cleanup_failed=1
  fi
  docker_cli rm --force --volumes "$extract_container_name" >/dev/null 2>&1 || true
  if docker_cli container inspect "$extract_container_name" >/dev/null 2>&1; then
    cleanup_failed=1
  fi
  for container_id in "${container_ids[@]}"; do
    if docker_cli container inspect "$container_id" >/dev/null 2>&1; then
      cleanup_failed=1
    fi
  done
  for path in "$FIXTURE_DIRECTORY" "$PRIMARY_KEYRING_DIRECTORY" "$FOREIGN_KEYRING_DIRECTORY" \
    "$HOST_BIN_DIRECTORY" "$RUN_DIR"; do
    assert_path_identity "$path" || cleanup_failed=1
  done
  if [[ "$cleanup_failed" == 0 ]]; then
    /usr/bin/rm -rf -- "$RUN_DIR" || cleanup_failed=1
  fi
  if [[ "$cleanup_failed" != 0 ]]; then
    printf '%s\n' 'Aster candidate topology cleanup failed' >&2
    exit 1
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

failure_stage=formal-runner
# The awk program must receive the literal first field.
# shellcheck disable=SC2016
[[ "$($SHA256_BIN "$FORMAL_RUNNER" | "$AWK_BIN" '{print $1}')" == "$FORMAL_RUNNER_SHA256" ]] || fail
failure_stage=aster-input
[[ "$ASTER_ROOT" == /* && -d "$ASTER_ROOT" && ! -L "$ASTER_ROOT" ]] || fail
ASTER_ROOT="$($REALPATH_BIN -e -- "$ASTER_ROOT")"
readonly ASTER_ROOT
PROFILE_PATH="$ASTER_ROOT/compatibility/phase-1-profile.json"
SCHEMA_PATH="$ASTER_ROOT/compatibility/phase-1-profile.schema.json"
[[ -f "$PROFILE_PATH" && -f "$SCHEMA_PATH" && ! -L "$PROFILE_PATH" && ! -L "$SCHEMA_PATH" ]] || fail
readonly PROFILE_PATH SCHEMA_PATH
immutable_image "$CANDIDATE_IMAGE_INPUT" || fail
immutable_image "$POSTGRES_IMAGE" || fail
immutable_image "$HOST_FIXTURE_IMAGE" || fail
failure_stage=candidate-image
candidate_image_id="$(docker_cli image inspect --format '{{.Id}}' "$CANDIDATE_IMAGE_INPUT")"
if [[ "$candidate_image_id" =~ ^[0-9a-f]{64}$ ]]; then
  candidate_image_id="sha256:${candidate_image_id}"
fi
[[ "$candidate_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || fail
failure_stage=postgres-image
DOCKER_COMMAND_TIMEOUT=600s docker_cli pull "$POSTGRES_IMAGE" \
  >"$RUN_DIR/postgres-pull.log" 2>&1 || fail
DOCKER_COMMAND_TIMEOUT=600s docker_cli pull "$HOST_FIXTURE_IMAGE" \
  >"$RUN_DIR/host-fixture-pull.log" 2>&1 || fail

failure_stage=extract-create
extract_container_id="$(docker_cli create --name "$extract_container_name" "$candidate_image_id" unknown)"
[[ "$extract_container_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
rootfs_archive="$RUN_DIR/candidate-rootfs.tar"
failure_stage=extract-export
docker_cli export --output "$rootfs_archive" "$extract_container_id" || fail
ASTER_ADMIN_BIN="$HOST_BIN_DIRECTORY/aster-admin"
failure_stage=extract-file
"$TAR_BIN" -xOf "$rootfs_archive" usr/local/bin/aster-admin >"$ASTER_ADMIN_BIN"
/usr/bin/chmod 0555 "$ASTER_ADMIN_BIN"
[[ ! -L "$ASTER_ADMIN_BIN" && -f "$ASTER_ADMIN_BIN" ]] || fail
[[ "$($STAT_BIN -c '%u|%g|%a' -- "$ASTER_ADMIN_BIN")" == "$(id -u)|$(id -g)|555" ]] || fail
failure_stage=extract-elf
"$READELF_BIN" -l "$ASTER_ADMIN_BIN" >"$RUN_DIR/aster-admin.readelf"
/usr/bin/grep -F -q 'Requesting program interpreter: /lib64/ld-linux-x86-64.so.2' \
"$RUN_DIR/aster-admin.readelf" || fail
failure_stage=extract-ldd
"$LDD_BIN" "$ASTER_ADMIN_BIN" >"$RUN_DIR/aster-admin.ldd" 2>&1 || fail
! /usr/bin/grep -F -q 'not found' "$RUN_DIR/aster-admin.ldd" || fail
mapfile -t observed_libraries < <(
  # The awk program intentionally uses literal fields.
  # shellcheck disable=SC2016
  "$AWK_BIN" '
    /=>/ { print $1; next }
    /linux-vdso/ { print $1; next }
    $1 ~ /^\// { print $1 }
  ' "$RUN_DIR/aster-admin.ldd" | /usr/bin/sort -u
)
[[ "${observed_libraries[*]}" == "${ASTER_ADMIN_LDD_ALLOWLIST[*]}" ]] || fail
failure_stage=extract-remove
docker_cli rm --force --volumes "$extract_container_id" >/dev/null || fail
extract_container_id=''

cat >"$COMPOSE_ENV" <<EOF
ASTER_PHASE1_POSTGRES_IMAGE=$POSTGRES_IMAGE
ASTER_PHASE1_CANDIDATE_IMAGE=$candidate_image_id
ASTER_PHASE1_HOST_FIXTURE_IMAGE=$HOST_FIXTURE_IMAGE
ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_PASSWORD=$primary_password
ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_PASSWORD=$foreign_password
ASTER_PHASE1_RUNTIME_UID=$(id -u)
ASTER_PHASE1_RUNTIME_GID=$(id -g)
ASTER_PHASE1_PRIMARY_CONFIG_FILE=$PRIMARY_CONFIG_FILE
ASTER_PHASE1_FOREIGN_CONFIG_FILE=$FOREIGN_CONFIG_FILE
ASTER_PHASE1_PRIMARY_KEYRING_DIRECTORY=$PRIMARY_KEYRING_DIRECTORY
ASTER_PHASE1_FOREIGN_KEYRING_DIRECTORY=$FOREIGN_KEYRING_DIRECTORY
ASTER_PHASE1_FIXTURE_DIRECTORY=$FIXTURE_DIRECTORY
ASTER_PHASE1_FIXTURE_SOCKET=$FIXTURE_SOCKET
EOF
/usr/bin/chmod 0600 "$COMPOSE_ENV"
project_started=1
failure_stage=compose-up
compose up --detach >"$RUN_DIR/compose-up.stdout" 2>"$RUN_DIR/compose-up.stderr" || fail

failure_stage=topology-readiness
deadline=$((SECONDS + 240))
while ((SECONDS < deadline)); do
  primary_init_id="$(service_container_id candidate-primary-init 2>/dev/null || true)"
  foreign_init_id="$(service_container_id candidate-foreign-init 2>/dev/null || true)"
  primary_core_id="$(service_container_id candidate-primary-core 2>/dev/null || true)"
  foreign_core_id="$(service_container_id candidate-foreign-core 2>/dev/null || true)"
  coordinator_id="$(service_container_id candidate-fixture-coordinator 2>/dev/null || true)"
  if [[ "$primary_init_id" =~ ^[0-9a-f]{12,64}$ \
    && "$foreign_init_id" =~ ^[0-9a-f]{12,64}$ \
    && "$primary_core_id" =~ ^[0-9a-f]{12,64}$ \
    && "$foreign_core_id" =~ ^[0-9a-f]{12,64}$ \
    && "$coordinator_id" =~ ^[0-9a-f]{12,64}$ ]]; then
    primary_init_state="$(docker_cli inspect --format '{{.State.Status}}|{{.State.ExitCode}}' "$primary_init_id")"
    foreign_init_state="$(docker_cli inspect --format '{{.State.Status}}|{{.State.ExitCode}}' "$foreign_init_id")"
    primary_health="$(docker_cli inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$primary_core_id")"
    foreign_health="$(docker_cli inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$foreign_core_id")"
    coordinator_health="$(docker_cli inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$coordinator_id")"
    if [[ "$primary_init_state" == 'exited|0' && "$foreign_init_state" == 'exited|0' \
      && "$primary_health" == healthy && "$foreign_health" == healthy \
      && "$coordinator_health" == healthy ]]; then
      break
    fi
  fi
  /usr/bin/sleep 1
done
[[ "${primary_init_state-}" == 'exited|0' && "${foreign_init_state-}" == 'exited|0' \
  && "${primary_health-}" == healthy && "${foreign_health-}" == healthy \
  && "${coordinator_health-}" == healthy ]] || fail
primary_postgres_id="$(service_container_id candidate-primary-postgres)"
for service in "${SERVICES[@]}"; do
  container_ids+=("$(service_container_id "$service")")
done

failure_stage=fixture-socket
assert_path_identity "$FIXTURE_DIRECTORY"
[[ ! -L "$FIXTURE_SOCKET" && -S "$FIXTURE_SOCKET" ]] || fail
[[ "$($STAT_BIN -c '%u|%g|%a' -- "$FIXTURE_SOCKET")" == "$(id -u)|$(id -g)|600" ]] || fail
fixture_socket_device="$($STAT_BIN -c %d -- "$FIXTURE_SOCKET")"
fixture_socket_inode="$($STAT_BIN -c %i -- "$FIXTURE_SOCKET")"
[[ "$fixture_socket_device" =~ ^[0-9]+$ && "$fixture_socket_inode" =~ ^[0-9]+$ ]] || fail

for binding in "${LOOPBACK_PROXY_BINDINGS[@]}"; do
  IFS='|' read -r proxy_service proxy_network proxy_ip proxy_host_port proxy_container_port <<<"$binding"
  start_loopback_proxy \
    "$proxy_service" "$proxy_network" "$proxy_ip" "$proxy_host_port" "$proxy_container_port"
done

failure_stage=http-readiness
http_discovery_ready() {
  local port=$1 expected_issuer=$2 response
  response="$({
    printf 'GET /oidc/.well-known/openid-configuration HTTP/1.1\r\n'
    printf 'Host: localhost\r\nConnection: close\r\n\r\n'
  } | /usr/bin/nc -w 3 127.0.0.1 "$port" 2>/dev/null || true)"
  [[ "$response" == *' 200 OK'* && "$response" == *"\"issuer\":\"${expected_issuer}\""* ]]
}
for readiness in \
  '3321|http://localhost:3321/oidc' \
  '3421|http://localhost:3421/oidc' \
  '3322|http://localhost:3322/oidc' \
  '3422|http://localhost:3422/oidc'; do
  IFS='|' read -r readiness_port readiness_issuer <<<"$readiness"
  http_discovery_ready "$readiness_port" "$readiness_issuer" || fail
done

failure_stage=host-admin
active_metadata="$(
  "$ENV_BIN" -i PATH='/usr/bin:/bin' "$ASTER_ADMIN_BIN" master-key active-id \
    --file "$PRIMARY_KEYRING_DIRECTORY/aster-master-key.json"
)"
[[ "$active_metadata" =~ ^active\ master\ key:\ generation=1\ key_id=aster-mk-[0-9a-f]{32}$ ]] || fail

cat >"$fixture_node_script" <<'NODE'
import { pathToFileURL } from 'node:url';

let stage = 'startup';
try {
  const [profileModulePath, commandModulePath, referenceStateModulePath, candidateDriverPath, primaryContainerId, projectName, profilePath, schemaPath, fixtureCommandPath, fixtureSocket, recipeOrder] = process.argv.slice(2);
  const { loadPhase1Profile } = await import(pathToFileURL(profileModulePath).href);
  const { createCommandPhase1FixtureProvisioner, runPhase1FixtureCommand } = await import(pathToFileURL(commandModulePath).href);
  const { readReferenceStateDriver } = await import(pathToFileURL(referenceStateModulePath).href);
  const profile = await loadPhase1Profile({ profilePath, schemaPath });
  const runner = async (request) => {
    const descriptor = JSON.parse(request.stdin);
    const result = await runPhase1FixtureCommand({
      ...request,
      env: { PATH: fixtureCommandPath, ASTER_FIXTURE_SOCKET: fixtureSocket },
    });
    const tracksCurrentOperation =
      descriptor.operation === 'provision' || stage.endsWith(`-${descriptor.operation}`);
    if (tracksCurrentOperation) {
      stage = `${stage}-${result.exitCode === 0 && result.signal === null && result.reaped ? 'command-ok' : 'command-failed'}`;
    }
    return result;
  };
  const provisioner = createCommandPhase1FixtureProvisioner({
    profile,
    target: { label: 'candidate', coreUrl: 'http://localhost:3321/', adminUrl: 'http://localhost:3421/' },
    foreignTarget: { label: 'candidate', coreUrl: 'http://localhost:3322/', adminUrl: 'http://localhost:3422/' },
    runner,
    environment: { PATH: fixtureCommandPath, ASTER_FIXTURE_SOCKET: fixtureSocket },
  });
  const byRole = (fixture, role) => {
    const allocation = fixture.public.allocations.find((candidate) => candidate.role === role);
    if (!allocation) throw new Error('missing fixture role');
    return allocation;
  };
  const lifecycle = async (recipe, validate = () => undefined) => {
    stage = `${recipe}-provision`;
    const fixture = await provisioner.provision(recipe);
    let failedStage;
    try {
      stage = `${recipe}-projectState`;
      await provisioner.projectState(fixture);
      await validate(fixture);
    } catch (error) {
      failedStage = stage;
      throw error;
    } finally {
      stage = `${recipe}-cleanup`;
      await provisioner.cleanup(fixture);
      if (failedStage) stage = failedStage;
    }
  };
  await lifecycle('none');
  await lifecycle('fullPhase1', async (fixture) => {
    const data = byRole(fixture, 'data');
    const admin = byRole(fixture, 'admin');
    if (data.isolation.persistenceId !== admin.isolation.persistenceId) throw new Error('primary persistence split');
    if (new Set([data.isolation.cookieKeyId, admin.isolation.cookieKeyId]).size !== 2) throw new Error('primary cookie key collision');
    if (new Set([data.isolation.signingKeyId, admin.isolation.signingKeyId]).size !== 2) throw new Error('primary signing key collision');
    stage = 'fullPhase1-candidate-state-driver-read';
    const snapshot = await readReferenceStateDriver({
      source: 'primary',
      projectName,
      expectedService: 'candidate-primary-postgres',
      containerId: primaryContainerId,
      scenarioId: 'management.application-read',
      stepId: 'state',
      signal: new AbortController().signal,
    }, { driverPath: candidateDriverPath, environment: { PATH: '/usr/bin:/bin' } });
    stage = 'fullPhase1-candidate-state-driver-validate';
    const userIds = snapshot.users.map(({ tenantId, id }) => `${tenantId}:${id}`).toSorted();
    if (snapshot.models.length !== 0 || !userIds.includes('default:zdata-user') || !userIds.includes('admin:phase1-admin')) throw new Error('candidate state snapshot mismatch');
  });
  await lifecycle('corsBoundary', (fixture) => {
    const data = byRole(fixture, 'data');
    const admin = byRole(fixture, 'admin');
    const foreign = byRole(fixture, 'foreign');
    if (data.isolation.persistenceId !== admin.isolation.persistenceId) throw new Error('primary persistence split');
    if (data.isolation.persistenceId === foreign.isolation.persistenceId) throw new Error('foreign persistence collision');
    if (new Set([data.isolation.cookieKeyId, admin.isolation.cookieKeyId, foreign.isolation.cookieKeyId]).size !== 3) throw new Error('cookie key collision');
    if (new Set([data.isolation.signingKeyId, admin.isolation.signingKeyId, foreign.isolation.signingKeyId]).size !== 3) throw new Error('signing key collision');
  });
  for (const recipe of recipeOrder.split(' ').slice(3)) {
    await lifecycle(recipe);
  }
  process.stdout.write('candidate fixture lifecycles passed\n');
} catch {
  process.stderr.write(`ASTER_FIXTURE_STAGE=${stage}\n`);
  process.exitCode = 1;
}
NODE
/usr/bin/chmod 0500 "$fixture_node_script"
fixture_command_path="$HOST_BIN_DIRECTORY:/usr/bin:/bin"
failure_stage=fixture-lifecycles
fixture_status=0
"$ENV_BIN" -i PATH='/usr/bin:/bin' HOME="$PRIVATE_HOME" \
  "$NODE_BIN" "$fixture_node_script" \
  "$REPO_ROOT/packages/integration-tests/lib/compatibility/phase-1/profile.js" \
  "$REPO_ROOT/packages/integration-tests/lib/compatibility/phase-1/clients/command-provisioner.js" \
  "$REPO_ROOT/packages/integration-tests/lib/compatibility/phase-1/differential/reference-state.js" \
  "$REPO_ROOT/.scripts/compatibility/phase1-candidate-state-driver.sh" \
  "$primary_postgres_id" "$project_name" \
  "$PROFILE_PATH" "$SCHEMA_PATH" "$fixture_command_path" "$FIXTURE_SOCKET" \
  "$FIXTURE_RECIPE_ORDER" >"$RUN_DIR/fixture.stdout" 2>"$RUN_DIR/fixture.stderr" || fixture_status=$?
if [[ "$fixture_status" -ne 0 ]]; then
  fixture_diagnostic="$(<"$RUN_DIR/fixture.stderr")"
  if [[ "$fixture_diagnostic" =~ ^ASTER_FIXTURE_STAGE=([A-Za-z0-9-]+)$ ]]; then
    failure_stage="fixture-${BASH_REMATCH[1]}"
  fi
  fail
fi
[[ "$(<"$RUN_DIR/fixture.stdout")" == 'candidate fixture lifecycles passed' ]] || fail
[[ ! -s "$RUN_DIR/fixture.stderr" ]] || fail

printf '%s\n' 'Aster candidate topology smoke passed'
