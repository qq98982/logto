#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() {
  printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
  exit 1
}

trusted_binary() {
  local name=$1 candidate resolved owner mode
  candidate="$(command -v "$name" 2>/dev/null || true)"
  resolved="$(realpath -e -- "$candidate" 2>/dev/null || true)"
  [[ -n "$resolved" && -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || fail
  owner="$(stat -c %u -- "$resolved" 2>/dev/null || true)"
  mode="$(stat -c %a -- "$resolved" 2>/dev/null || true)"
  [[ "$owner" == 0 || "$owner" == "$(id -u)" ]] || fail
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || fail
  ((8#$mode & 8#022)) && fail
  printf '%s' "$resolved"
}

invariant_id=''
project_name=''
primary_container_id=''
foreign_container_id=''
while (($# > 0)); do
  case "$1" in
    --invariant-id)
      [[ -z "$invariant_id" && $# -ge 2 ]] || fail
      invariant_id=$2
      shift 2
      ;;
    --project-name)
      [[ -z "$project_name" && $# -ge 2 ]] || fail
      project_name=$2
      shift 2
      ;;
    --primary-container-id)
      [[ -z "$primary_container_id" && $# -ge 2 ]] || fail
      primary_container_id=$2
      shift 2
      ;;
    --foreign-container-id)
      [[ -z "$foreign_container_id" && $# -ge 2 ]] || fail
      foreign_container_id=$2
      shift 2
      ;;
    *) fail ;;
  esac
done

case "$invariant_id" in
  database.owner-role-membership-boundary|tenant.suspended-epoch-rejected|tenant.cross-tenant-read-rejected|tenant.admin-operation-binding|tenant.admin-operation-status-matrix|reaper.activity-visibility-redaction) ;;
  *) fail ;;
esac
[[ "$project_name" =~ ^aster-phase1-[0-9a-f]{16}$ ]] || fail
[[ "$primary_container_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
[[ "$foreign_container_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
[[ "$primary_container_id" != "$foreign_container_id" ]] || fail

DOCKER_BIN="$(trusted_binary docker)"
readonly DOCKER_BIN
primary_labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$primary_container_id" 2>/dev/null || true)"
foreign_labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$foreign_container_id" 2>/dev/null || true)"
[[ "$primary_labels" == "candidate-primary-postgres|$project_name" ]] || fail
[[ "$foreign_labels" == "candidate-foreign-postgres|$project_name" ]] || fail

database='aster_phase1_candidate_primary'

if [[ "$invariant_id" == tenant.* ]]; then
  driver_directory="$(dirname -- "$(realpath -e -- "${BASH_SOURCE[0]}")")"
  sql_file="${driver_directory}/phase1-candidate-invariants.sql"
  [[ -f "$sql_file" && ! -L "$sql_file" ]] || fail

  run_fixture_sql() {
    local action=$1
    "$DOCKER_BIN" exec --interactive --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --set="action=$action" --username postgres --dbname "$database" \
      <"$sql_file"
  }

  cleanup_required=false
  cleanup_action=''
  cleanup_fixture() {
    [[ -n "$cleanup_action" ]] || return 1
    run_fixture_sql "$cleanup_action" >/dev/null 2>&1
  }
  # Invoked indirectly by the EXIT trap.
  # shellcheck disable=SC2329
  cleanup_on_exit() {
    local exit_code=$?
    trap - EXIT
    if [[ "$cleanup_required" == true ]] && ! cleanup_fixture; then
      if ((exit_code == 0)); then
        printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
        exit_code=1
      fi
    fi
    exit "$exit_code"
  }
  deployment_id="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command 'SELECT deployment_id::text FROM aster_control.deployment_state WHERE singleton' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$deployment_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || fail

  refresh_maintenance() {
    "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username aster_maintainer --dbname "$database" \
      --command "SELECT * FROM aster_runtime.run_tenant_maintenance('$deployment_id')" \
      >/dev/null 2>&1
  }
fi

if [[ "$invariant_id" == 'tenant.suspended-epoch-rejected' ]]; then
  cleanup_action=cleanup-suspended-epoch
  cleanup_required=true
  trap cleanup_on_exit EXIT

  run_fixture_sql setup-suspended-epoch >/dev/null || fail

  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_control_resolver --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('a3', 32), 'hex')), 'phase1-invariant-suspended-epoch', 'request')" \
    >/dev/null 2>&1 || fail

  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_admin_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('b4', 32), 'hex')), 'phase1-invariant-suspended-epoch', 'key_lifecycle')" \
    >/dev/null 2>&1 || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" \
    --command "BEGIN; SELECT * FROM aster_runtime.activate_tenant_binding(pg_catalog.decode(pg_catalog.repeat('b4', 32), 'hex')); SELECT aster_runtime.suspend_tenant(7); COMMIT" \
    >/dev/null 2>&1 || fail

  stale_error=''
  stale_status=0
  stale_error="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --username aster_request --dbname "$database" \
    --command "SELECT * FROM aster_runtime.activate_tenant_binding(pg_catalog.decode(pg_catalog.repeat('a3', 32), 'hex'))" \
    2>&1 >/dev/null)" || stale_status=$?
  ((stale_status != 0)) || fail
  [[ "$stale_error" =~ ERROR:[[:space:]]+42501:[[:space:]]+Aster\ tenant\ binding\ rejected ]] || fail

  terminal="$(run_fixture_sql project-suspended-epoch)" || fail
  [[ -n "$terminal" ]] || fail
  cleanup_fixture || fail
  cleanup_required=false
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'tenant.cross-tenant-read-rejected' ]]; then
  cleanup_action=cleanup-cross-tenant
  cleanup_required=true
  trap cleanup_on_exit EXIT

  run_fixture_sql setup-cross-tenant >/dev/null || fail
  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_control_resolver --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('d1', 32), 'hex')), 'phase1-invariant-cross-a', 'request')" \
    >/dev/null 2>&1 || fail
  "$DOCKER_BIN" exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_request --dbname "$database" >/dev/null 2>&1 <<'SQL' || fail
BEGIN;
SELECT *
FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('d1', 32), 'hex')
) \g /dev/null
INSERT INTO aster_tenant.rls_sentinel (item_id, test_value)
VALUES ('00000000-0000-4000-8000-0000000000a1', 'sentinel-a');
COMMIT;
SQL

  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_control_resolver --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('d2', 32), 'hex')), 'phase1-invariant-cross-b', 'worker')" \
    >/dev/null 2>&1 || fail
  "$DOCKER_BIN" exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_worker --dbname "$database" >/dev/null 2>&1 <<'SQL' || fail
BEGIN;
SELECT *
FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('d2', 32), 'hex')
) \g /dev/null
INSERT INTO aster_tenant.rls_sentinel (item_id, test_value)
VALUES ('00000000-0000-4000-8000-0000000000b1', 'sentinel-b');
COMMIT;
SQL

  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_control_resolver --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('c5', 32), 'hex')), 'phase1-invariant-cross-a', 'request')" \
    >/dev/null 2>&1 || fail

  relationship_error=''
  relationship_status=0
  relationship_error="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --username aster_request --dbname "$database" 2>&1 >/dev/null <<'SQL'
BEGIN;
SELECT *
FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('c5', 32), 'hex')
) \g /dev/null
INSERT INTO aster_tenant.rls_sentinel (parent_item_id, test_value)
VALUES (
  '00000000-0000-4000-8000-0000000000b1',
  'forbidden-cross-tenant-parent'
);
COMMIT;
SQL
)" || relationship_status=$?
  ((relationship_status != 0)) || fail
  [[ "$relationship_error" =~ ERROR:[[:space:]]+23503: ]] || fail

  cross_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username aster_request --dbname "$database" <<'SQL'
BEGIN;
SELECT *
FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('c5', 32), 'hex')
) \g /dev/null
WITH visible AS (
  SELECT COALESCE(
    pg_catalog.string_agg(test_value, ',' ORDER BY test_value),
    ''
  ) AS labels
  FROM aster_tenant.rls_sentinel
), cross_rows AS (
  SELECT pg_catalog.count(*) AS row_count
  FROM aster_tenant.rls_sentinel
  WHERE tenant_id = 'phase1-invariant-cross-b'
)
SELECT CASE
  WHEN aster_runtime.bound_tenant_id(NULL) = 'phase1-invariant-cross-a'
   AND visible.labels = 'sentinel-a'
   AND cross_rows.row_count = 0
  THEN 'tenant-a|sentinel-a|0'
  ELSE 'invalid'
END
FROM visible, cross_rows;
ROLLBACK;
SQL
)" || fail
  [[ "$cross_observation" == 'tenant-a|sentinel-a|0' ]] || fail

  terminal="$(run_fixture_sql project-cross-tenant)" || fail
  [[ -n "$terminal" ]] || fail
  cleanup_fixture || fail
  cleanup_required=false
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'tenant.admin-operation-binding' ]]; then
  cleanup_action=cleanup-admin-binding
  cleanup_required=true
  trap cleanup_on_exit EXIT

  run_fixture_sql setup-admin-binding >/dev/null || fail
  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_admin_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('e1', 32), 'hex')), 'phase1-invariant-admin-a', 'provision')" \
    >/dev/null 2>&1 || fail

  admin_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SELECT *
FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('e1', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.probe_admin_provision_write('admin-binding-provision') \g /dev/null

SAVEPOINT tenant_mismatch;
\set ON_ERROR_STOP off
SELECT aster_runtime.create_inactive_tenant('phase1-invariant-admin-b-forbidden') \g /dev/null
\set tenant_state :SQLSTATE
ROLLBACK TO SAVEPOINT tenant_mismatch;
\set ON_ERROR_STOP on

SAVEPOINT operation_class_mismatch;
\set ON_ERROR_STOP off
SELECT aster_runtime.probe_admin_rewrap_write('forbidden-admin-rewrap') \g /dev/null
\set operation_state :SQLSTATE
ROLLBACK TO SAVEPOINT operation_class_mismatch;
\set ON_ERROR_STOP on

\echo :tenant_state|:operation_state
COMMIT;
SQL
)" || fail
  [[ "$admin_observation" == '42501|42501' ]] || fail

  terminal="$(run_fixture_sql project-admin-binding)" || fail
  [[ -n "$terminal" ]] || fail
  cleanup_fixture || fail
  cleanup_required=false
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'tenant.admin-operation-status-matrix' ]]; then
  cleanup_action=cleanup-admin-matrix
  cleanup_required=true
  trap cleanup_on_exit EXIT

  run_fixture_sql setup-admin-matrix >/dev/null || fail

  probe_matrix_mint() {
    local tenant=$1 operation=$2 seed=$3 error='' status=0
    [[ "$tenant" =~ ^phase1-invariant-matrix-[a-z-]+$ ]] || fail
    case "$operation" in
      provision|key_lifecycle|rewrap|key_audit) ;;
      *) fail ;;
    esac
    [[ "$seed" =~ ^[0-9a-f]{2}$ ]] || fail
    refresh_maintenance || fail
    error="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
      --username aster_admin --dbname "$database" \
      --command "BEGIN; SELECT * FROM aster_runtime.mint_admin_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('$seed', 32), 'hex')), '$tenant', '$operation'); ROLLBACK" \
      2>&1 >/dev/null)" || status=$?
    if ((status == 0)); then
      printf '%s' true
      return
    fi
    [[ "$error" =~ ERROR:[[:space:]]+42501: ]] || fail
    printf '%s' false
  }

  inactive_provision="$(probe_matrix_mint phase1-invariant-matrix-inactive provision 61)"
  inactive_key_lifecycle="$(probe_matrix_mint phase1-invariant-matrix-inactive key_lifecycle 62)"
  inactive_rewrap="$(probe_matrix_mint phase1-invariant-matrix-inactive rewrap 63)"
  inactive_key_audit="$(probe_matrix_mint phase1-invariant-matrix-inactive key_audit 64)"
  active_provision="$(probe_matrix_mint phase1-invariant-matrix-active provision 65)"
  active_key_lifecycle="$(probe_matrix_mint phase1-invariant-matrix-active key_lifecycle 66)"
  active_rewrap="$(probe_matrix_mint phase1-invariant-matrix-active rewrap 67)"
  active_key_audit="$(probe_matrix_mint phase1-invariant-matrix-active key_audit 68)"
  suspended_provision="$(probe_matrix_mint phase1-invariant-matrix-suspended provision 69)"
  suspended_key_lifecycle="$(probe_matrix_mint phase1-invariant-matrix-suspended key_lifecycle 6a)"
  suspended_rewrap="$(probe_matrix_mint phase1-invariant-matrix-suspended rewrap 6b)"
  suspended_key_audit="$(probe_matrix_mint phase1-invariant-matrix-suspended key_audit 6c)"
  deleted_provision="$(probe_matrix_mint phase1-invariant-matrix-deleted provision 6d)"
  deleted_key_lifecycle="$(probe_matrix_mint phase1-invariant-matrix-deleted key_lifecycle 6e)"
  deleted_rewrap="$(probe_matrix_mint phase1-invariant-matrix-deleted rewrap 6f)"
  deleted_key_audit="$(probe_matrix_mint phase1-invariant-matrix-deleted key_audit 70)"

  [[ "$inactive_provision" == true && "$inactive_key_lifecycle" == false && \
     "$inactive_rewrap" == true && "$inactive_key_audit" == true && \
     "$active_provision" == false && "$active_key_lifecycle" == true && \
     "$active_rewrap" == true && "$active_key_audit" == true && \
     "$suspended_provision" == false && "$suspended_key_lifecycle" == true && \
     "$suspended_rewrap" == true && "$suspended_key_audit" == true && \
     "$deleted_provision" == false && "$deleted_key_lifecycle" == false && \
     "$deleted_rewrap" == false && "$deleted_key_audit" == false ]] || fail

  refresh_maintenance || fail
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" \
    --command "SELECT * FROM aster_runtime.mint_admin_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('71', 32), 'hex')), 'phase1-invariant-matrix-inactive', 'provision')" \
    >/dev/null 2>&1 || fail
  narrowing_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SELECT *
FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('71', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.probe_admin_provision_write('matrix-function-narrowing') \g /dev/null
SAVEPOINT operation_class_mismatch;
\set ON_ERROR_STOP off
SELECT aster_runtime.probe_admin_rewrap_write('forbidden-matrix-rewrap') \g /dev/null
\set operation_state :SQLSTATE
ROLLBACK TO SAVEPOINT operation_class_mismatch;
\set ON_ERROR_STOP on
\echo :operation_state
ROLLBACK;
SQL
)" || fail
  [[ "$narrowing_observation" == '42501' ]] || fail

  mint_epoch_binding() {
    local tenant=$1 operation=$2 seed=$3
    refresh_maintenance || fail
    "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username aster_admin --dbname "$database" \
      --command "SELECT * FROM aster_runtime.mint_admin_tenant_binding(pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('$seed', 32), 'hex')), '$tenant', '$operation')" \
      >/dev/null 2>&1
  }
  mint_epoch_binding phase1-invariant-matrix-epoch-provision provision 72 || fail
  mint_epoch_binding phase1-invariant-matrix-epoch-key-lifecycle key_lifecycle 73 || fail
  mint_epoch_binding phase1-invariant-matrix-epoch-rewrap rewrap 74 || fail
  mint_epoch_binding phase1-invariant-matrix-epoch-key-audit key_audit 75 || fail
  run_fixture_sql advance-admin-matrix-epochs >/dev/null || fail

  stale_admin_binding_rejected() {
    local seed=$1 error='' status=0
    error="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
      --username aster_admin --dbname "$database" \
      --command "SELECT * FROM aster_runtime.activate_tenant_binding(pg_catalog.decode(pg_catalog.repeat('$seed', 32), 'hex'))" \
      2>&1 >/dev/null)" || status=$?
    ((status != 0)) || return 1
    [[ "$error" =~ ERROR:[[:space:]]+42501: ]]
  }
  stale_admin_binding_rejected 72 || fail
  stale_admin_binding_rejected 73 || fail
  stale_admin_binding_rejected 74 || fail
  stale_admin_binding_rejected 75 || fail

  terminal="$(run_fixture_sql project-admin-matrix)" || fail
  [[ -n "$terminal" ]] || fail
  cleanup_fixture || fail
  cleanup_required=false
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'reaper.activity-visibility-redaction' ]]; then
  request_client_pid=''
  worker_client_pid=''

  cleanup_reaper_clients() {
    local cleanup_failed=0 client_pid
    "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" \
      --command "SELECT pg_catalog.pg_terminate_backend(activity.pid, 2000) FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.usename IN ('aster_request', 'aster_worker') AND activity.application_name IN ('phase1-invariant-reaper-request', 'phase1-invariant-reaper-worker') AND activity.backend_type = 'client backend' AND activity.pid <> pg_catalog.pg_backend_pid()" \
      >/dev/null 2>&1 || cleanup_failed=1
    for client_pid in "$request_client_pid" "$worker_client_pid"; do
      [[ -n "$client_pid" ]] || continue
      if kill -0 "$client_pid" 2>/dev/null; then
        kill -TERM "$client_pid" 2>/dev/null || cleanup_failed=1
      fi
      wait "$client_pid" 2>/dev/null || true
    done
    request_client_pid=''
    worker_client_pid=''
    return "$cleanup_failed"
  }

  # Invoked indirectly by the EXIT trap.
  # shellcheck disable=SC2329
  cleanup_reaper_on_exit() {
    local exit_code=$?
    trap - EXIT
    if ! cleanup_reaper_clients && ((exit_code == 0)); then
      printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
      exit_code=1
    fi
    exit "$exit_code"
  }
  trap cleanup_reaper_on_exit EXIT

  start_reaper_client() {
    local role=$1 application_name=$2 sentinel=$3
    case "$role" in
      aster_request|aster_worker) ;;
      *) fail ;;
    esac
    [[ "$application_name" =~ ^phase1-invariant-reaper-(request|worker)$ ]] || fail
    [[ "$sentinel" =~ ^phase1-reaper-(request|worker)-sentinel$ ]] || fail
    "$DOCKER_BIN" exec --interactive --user postgres \
      --env "PGAPPNAME=$application_name" "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username "$role" --dbname "$database" >/dev/null 2>&1 <<SQL &
BEGIN;
SET LOCAL transaction_timeout = '0';
SET LOCAL statement_timeout = '0';
SET LOCAL idle_in_transaction_session_timeout = '0';
SELECT pg_catalog.pg_sleep(90), '$sentinel'::text;
COMMIT;
SQL
    started_client_pid=$!
  }

  started_client_pid=''
  start_reaper_client \
    aster_request phase1-invariant-reaper-request phase1-reaper-request-sentinel
  request_client_pid=$started_client_pid
  start_reaper_client \
    aster_worker phase1-invariant-reaper-worker phase1-reaper-worker-sentinel
  worker_client_pid=$started_client_pid
  [[ "$request_client_pid" =~ ^[1-9][0-9]*$ && "$worker_client_pid" =~ ^[1-9][0-9]*$ ]] || fail

  backends_ready=false
  for _ in {1..100}; do
    if ! kill -0 "$request_client_pid" 2>/dev/null || ! kill -0 "$worker_client_pid" 2>/dev/null; then
      break
    fi
    readiness="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" \
      --command "SELECT CASE WHEN pg_catalog.count(*) = 2 AND pg_catalog.bool_and((activity.application_name = 'phase1-invariant-reaper-request' AND activity.usename = 'aster_request' AND activity.query LIKE '%phase1-reaper-request-sentinel%') OR (activity.application_name = 'phase1-invariant-reaper-worker' AND activity.usename = 'aster_worker' AND activity.query LIKE '%phase1-reaper-worker-sentinel%')) AND pg_catalog.bool_and(activity.backend_type = 'client backend' AND activity.state = 'active' AND activity.xact_start IS NOT NULL) THEN 'true' ELSE 'false' END FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.application_name IN ('phase1-invariant-reaper-request', 'phase1-invariant-reaper-worker')" \
      2>/dev/null | tr -d '[:space:]')" || fail
    if [[ "$readiness" == true ]]; then
      backends_ready=true
      break
    fi
    sleep 0.1
  done
  [[ "$backends_ready" == true ]] || fail

  backends_overdue=false
  for _ in {1..300}; do
    overdue="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" \
      --command "SELECT CASE WHEN pg_catalog.count(*) = 2 AND pg_catalog.bool_and(activity.xact_start <= pg_catalog.clock_timestamp() - interval '20 seconds') THEN 'true' ELSE 'false' END FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.application_name IN ('phase1-invariant-reaper-request', 'phase1-invariant-reaper-worker') AND activity.usename IN ('aster_request', 'aster_worker') AND activity.backend_type = 'client backend'" \
      2>/dev/null | tr -d '[:space:]')" || fail
    if [[ "$overdue" == true ]]; then
      backends_overdue=true
      break
    fi
    sleep 0.1
  done
  [[ "$backends_overdue" == true ]] || fail

  deployment_id="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command 'SELECT deployment_id::text FROM aster_control.deployment_state WHERE singleton' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$deployment_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || fail
  reaper_result="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username aster_maintainer --dbname "$database" \
    --command "SELECT terminated_count::text || '|' || deleted_count::text FROM aster_runtime.run_tenant_maintenance('$deployment_id')" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$reaper_result" =~ ^2\|([0-9]+)$ ]] || fail
  ((BASH_REMATCH[1] <= 2000)) || fail

  wait "$request_client_pid" 2>/dev/null || true
  wait "$worker_client_pid" 2>/dev/null || true
  request_client_pid=''
  worker_client_pid=''
  gone="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.application_name IN ('phase1-invariant-reaper-request', 'phase1-invariant-reaper-worker')) THEN 'true' ELSE 'false' END" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$gone" == true ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'reaper.activity-visibility-redaction',
  'projection', pg_catalog.jsonb_build_object(
    'observations', pg_catalog.jsonb_build_array(
      pg_catalog.jsonb_build_object(
        'roleClass', 'request',
        'backendClass', 'client',
        'stateClass', 'in-transaction',
        'timingClass', 'overdue',
        'terminated', true
      ),
      pg_catalog.jsonb_build_object(
        'roleClass', 'worker',
        'backendClass', 'client',
        'stateClass', 'in-transaction',
        'timingClass', 'overdue',
        'terminated', true
      )
    ),
    'summary', pg_catalog.jsonb_build_object('eligible', 2, 'terminated', 2, 'missed', 0),
    'sentinelMatches', 0
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
  [[ "$terminal" != *'phase1-reaper-request-sentinel'* && \
     "$terminal" != *'phase1-reaper-worker-sentinel'* ]] || fail
  cleanup_reaper_clients || fail
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

can_set_owner_role() {
  local role=$1
  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username "$role" --dbname "$database" \
    --command 'SET ROLE aster_owner; SELECT current_user;' \
    >/dev/null 2>&1
}

request_set_role=false
worker_set_role=false
admin_set_role=false
maintainer_set_role=false
resolver_set_role=false
key_runtime_set_role=false
migrator_set_role=false
can_set_owner_role aster_request && request_set_role=true
can_set_owner_role aster_worker && worker_set_role=true
can_set_owner_role aster_admin && admin_set_role=true
can_set_owner_role aster_maintainer && maintainer_set_role=true
can_set_owner_role aster_control_resolver && resolver_set_role=true
can_set_owner_role aster_key_runtime && key_runtime_set_role=true
can_set_owner_role aster_migrator && migrator_set_role=true

terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
  psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
  --set=ON_ERROR_STOP=1 \
  --set="request_set_role=$request_set_role" \
  --set="worker_set_role=$worker_set_role" \
  --set="admin_set_role=$admin_set_role" \
  --set="maintainer_set_role=$maintainer_set_role" \
  --set="resolver_set_role=$resolver_set_role" \
  --set="key_runtime_set_role=$key_runtime_set_role" \
  --set="migrator_set_role=$migrator_set_role" \
  --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '5s';
SET LOCAL idle_in_transaction_session_timeout = '20s';
SET LOCAL search_path = pg_catalog;

with designed(role_name, ordinal) as (
  values
    ('aster_request'::text, 1),
    ('aster_worker', 2),
    ('aster_admin', 3),
    ('aster_maintainer', 4),
    ('aster_control_resolver', 5),
    ('aster_key_runtime', 6),
    ('aster_migrator', 7),
    ('aster_owner', 8),
    ('aster_key_control_owner', 9),
    ('aster_key_usage_owner', 10),
    ('aster_key_lifecycle_owner', 11),
    ('aster_reaper_owner', 12)
), role_projection as (
  select designed.ordinal, designed.role_name,
    pg_catalog.jsonb_strip_nulls(
      pg_catalog.jsonb_build_object(
        'login', role.rolcanlogin,
        'inherit', case when designed.role_name = 'aster_migrator' then role.rolinherit else null end,
        'bypassRls', role.rolbypassrls,
        'memberOf', coalesce((
          select pg_catalog.jsonb_agg(parent.rolname order by pg_catalog.array_position(
            array[
              'aster_owner',
              'aster_key_control_owner',
              'aster_key_usage_owner',
              'aster_key_lifecycle_owner',
              'aster_reaper_owner',
              'pg_signal_backend',
              'pg_read_all_stats'
            ]::text[], parent.rolname
          ))
          from pg_catalog.pg_auth_members as membership
          join pg_catalog.pg_roles as parent on parent.oid = membership.roleid
          where membership.member = role.oid
        ), '[]'::jsonb),
        'setRoleOwner', case designed.role_name
          when 'aster_request' then :'request_set_role'::boolean
          when 'aster_worker' then :'worker_set_role'::boolean
          when 'aster_admin' then :'admin_set_role'::boolean
          when 'aster_maintainer' then :'maintainer_set_role'::boolean
          when 'aster_control_resolver' then :'resolver_set_role'::boolean
          when 'aster_key_runtime' then :'key_runtime_set_role'::boolean
          when 'aster_migrator' then :'migrator_set_role'::boolean
          else false
        end,
        'ownerMembershipGrantable', case when designed.role_name = 'aster_migrator' then (
          select pg_catalog.count(*) = 5
          from pg_catalog.pg_auth_members as membership
          join pg_catalog.pg_roles as parent on parent.oid = membership.roleid
          where membership.member = role.oid
            and parent.rolname = any(array[
              'aster_owner',
              'aster_key_control_owner',
              'aster_key_usage_owner',
              'aster_key_lifecycle_owner',
              'aster_reaper_owner'
            ]::text[])
        ) else false end
      )
    ) as value
  from designed
  join pg_catalog.pg_roles as role on role.rolname = designed.role_name
), projection as (
  select pg_catalog.jsonb_build_object(
    'roles', pg_catalog.jsonb_object_agg(role_name, value order by ordinal)
  ) as value
  from role_projection
)
select pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'database.owner-role-membership-boundary',
  'projection', projection.value
)::text
from projection;
SQL
)" || fail

[[ -n "$terminal" ]] || fail
byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
[[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
printf '%s' "$terminal"
