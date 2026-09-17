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
  database.owner-role-membership-boundary|tenant.suspended-epoch-rejected|tenant.cross-tenant-read-rejected|tenant.admin-operation-binding|tenant.admin-operation-status-matrix|reaper.activity-visibility-redaction|reaper.object-audit-disabled|keystore.required-readable-key-set|keystore.stale-keyring-rejoin-rejected|keystore.forced-rls-owner-boundary) ;;
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

if [[ "$invariant_id" == 'reaper.object-audit-disabled' ]]; then
  SHA256_BIN="$(trusted_binary sha256sum)"
  readonly SHA256_BIN
  primary_core_id="$($DOCKER_BIN ps -aq \
    --filter "label=com.docker.compose.project=$project_name" \
    --filter 'label=com.docker.compose.service=candidate-primary-core' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$primary_core_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
  core_labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$primary_core_id" 2>/dev/null || true)"
  [[ "$core_labels" == "candidate-primary-core|$project_name" ]] || fail
  core_state="$($DOCKER_BIN inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$primary_core_id" 2>/dev/null || true)"
  [[ "$core_state" == 'running|healthy' ]] || fail
  managed_export_ids="$($DOCKER_BIN ps -aq \
    --filter "label=com.docker.compose.project=$project_name" \
    --filter 'label=com.docker.compose.service=candidate-managed-export' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ -z "$managed_export_ids" ]] || fail

  audit_settings_closed() {
    local role=$1 result
    case "$role" in
      aster_request|aster_worker) ;;
      *) fail ;;
    esac
    result="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username "$role" --dbname "$database" \
      --command "SELECT CASE WHEN pg_catalog.current_setting('log_statement') = 'none' AND pg_catalog.current_setting('log_min_error_statement') = 'panic' AND pg_catalog.current_setting('log_duration') = 'off' AND pg_catalog.current_setting('log_min_duration_statement') = '-1' AND pg_catalog.current_setting('log_min_duration_sample') = '-1' AND pg_catalog.current_setting('log_statement_sample_rate') = '0' AND pg_catalog.current_setting('log_parameter_max_length') = '0' AND pg_catalog.current_setting('log_parameter_max_length_on_error') = '0' AND pg_catalog.current_setting('auto_explain.log_min_duration', true) = '-1' AND pg_catalog.current_setting('auto_explain.log_parameter_max_length', true) = '0' AND pg_catalog.current_setting('pgaudit.log', true) = 'none' AND pg_catalog.current_setting('pgaudit.log_statement', true) = 'off' AND pg_catalog.current_setting('pgaudit.log_parameter', true) = 'off' AND pg_catalog.current_setting('pgaudit.role', true) = '' THEN 'true' ELSE 'false' END" \
      2>/dev/null | tr -d '[:space:]')" || fail
    [[ "$result" == true ]]
  }
  audit_settings_closed aster_request || fail
  audit_settings_closed aster_worker || fail

  audit_catalog_closed="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS membership JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member WHERE member_role.rolname IN ('aster_request', 'aster_worker')) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting AS role_setting JOIN pg_catalog.pg_roles AS configured_role ON configured_role.oid = role_setting.setrole CROSS JOIN LATERAL pg_catalog.unnest(role_setting.setconfig) AS configured_value WHERE role_setting.setdatabase = (SELECT database_catalog.oid FROM pg_catalog.pg_database AS database_catalog WHERE database_catalog.datname = pg_catalog.current_database()) AND configured_role.rolname IN ('aster_request', 'aster_worker') AND configured_value LIKE 'pgaudit.role=%' AND configured_value <> 'pgaudit.role=') THEN 'true' ELSE 'false' END" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$audit_catalog_closed" == true ]] || fail

  request_audit_pid=''
  worker_audit_pid=''
  cleanup_audit_clients() {
    local cleanup_failed=0 client_pid
    "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" \
      --command "SELECT pg_catalog.pg_terminate_backend(activity.pid, 2000) FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.usename IN ('aster_request', 'aster_worker') AND activity.application_name IN ('phase1-invariant-audit-request', 'phase1-invariant-audit-worker') AND activity.backend_type = 'client backend' AND activity.pid <> pg_catalog.pg_backend_pid()" \
      >/dev/null 2>&1 || cleanup_failed=1
    for client_pid in "$request_audit_pid" "$worker_audit_pid"; do
      [[ -n "$client_pid" ]] || continue
      if kill -0 "$client_pid" 2>/dev/null; then
        kill -TERM "$client_pid" 2>/dev/null || cleanup_failed=1
      fi
      wait "$client_pid" 2>/dev/null || true
    done
    request_audit_pid=''
    worker_audit_pid=''
    return "$cleanup_failed"
  }

  # Invoked indirectly by the EXIT trap.
  # shellcheck disable=SC2329
  cleanup_audit_on_exit() {
    local exit_code=$?
    trap - EXIT
    if ! cleanup_audit_clients && ((exit_code == 0)); then
      printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
      exit_code=1
    fi
    exit "$exit_code"
  }
  trap cleanup_audit_on_exit EXIT

  start_audit_client() {
    local role=$1 application_name=$2 sentinel=$3 byte_seed=$4
    case "$role" in
      aster_request|aster_worker) ;;
      *) fail ;;
    esac
    [[ "$application_name" =~ ^phase1-invariant-audit-(request|worker)$ ]] || fail
    [[ "$sentinel" =~ ^phase1-audit-(request|worker)-sentinel$ ]] || fail
    [[ "$byte_seed" =~ ^[0-9a-f]{2}$ ]] || fail
    "$DOCKER_BIN" exec --interactive --user postgres \
      --env "PGAPPNAME=$application_name" "$primary_container_id" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username "$role" --dbname "$database" >/dev/null 2>&1 <<SQL &
BEGIN;
SET LOCAL transaction_timeout = '0';
SET LOCAL statement_timeout = '0';
SET LOCAL idle_in_transaction_session_timeout = '0';
SELECT pg_catalog.pg_sleep(30), '$sentinel'::text,
       pg_catalog.decode(pg_catalog.repeat('$byte_seed', 32), 'hex');
COMMIT;
SQL
    started_audit_pid=$!
  }

  started_audit_pid=''
  start_audit_client \
    aster_request phase1-invariant-audit-request phase1-audit-request-sentinel a7
  request_audit_pid=$started_audit_pid
  start_audit_client \
    aster_worker phase1-invariant-audit-worker phase1-audit-worker-sentinel b8
  worker_audit_pid=$started_audit_pid
  [[ "$request_audit_pid" =~ ^[1-9][0-9]*$ && "$worker_audit_pid" =~ ^[1-9][0-9]*$ ]] || fail

  audit_backends_ready=false
  for _ in {1..100}; do
    if ! kill -0 "$request_audit_pid" 2>/dev/null || ! kill -0 "$worker_audit_pid" 2>/dev/null; then
      break
    fi
    readiness="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" \
      --command "SELECT CASE WHEN pg_catalog.count(*) = 2 AND pg_catalog.bool_and((activity.application_name = 'phase1-invariant-audit-request' AND activity.usename = 'aster_request' AND activity.query LIKE '%phase1-audit-request-sentinel%') OR (activity.application_name = 'phase1-invariant-audit-worker' AND activity.usename = 'aster_worker' AND activity.query LIKE '%phase1-audit-worker-sentinel%')) AND pg_catalog.bool_and(activity.backend_type = 'client backend' AND activity.state = 'active' AND activity.xact_start IS NOT NULL) THEN 'true' ELSE 'false' END FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.application_name IN ('phase1-invariant-audit-request', 'phase1-invariant-audit-worker')" \
      2>/dev/null | tr -d '[:space:]')" || fail
    if [[ "$readiness" == true ]]; then
      audit_backends_ready=true
      break
    fi
    sleep 0.1
  done
  [[ "$audit_backends_ready" == true ]] || fail
  cleanup_audit_clients || fail
  gone="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity AS activity WHERE activity.datname = pg_catalog.current_database() AND activity.application_name IN ('phase1-invariant-audit-request', 'phase1-invariant-audit-worker')) THEN 'true' ELSE 'false' END" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$gone" == true ]] || fail

  postgres_logs="$($DOCKER_BIN logs "$primary_container_id" 2>&1)" || fail
  application_logs="$($DOCKER_BIN logs "$primary_core_id" 2>&1)" || fail
  managed_export_logs=''
  for artifact in "$postgres_logs" "$managed_export_logs" "$application_logs"; do
    artifact_bytes="$(printf '%s' "$artifact" | wc -c | tr -d '[:space:]')"
    [[ "$artifact_bytes" =~ ^[0-9]+$ && "$artifact_bytes" -le 1048576 ]] || fail
    [[ "$artifact" != *'phase1-audit-request-sentinel'* && \
       "$artifact" != *'phase1-audit-worker-sentinel'* ]] || fail
    artifact_hash="$(printf '%s' "$artifact" | "$SHA256_BIN")"
    artifact_hash=${artifact_hash%% *}
    [[ "$artifact_hash" =~ ^[0-9a-f]{64}$ ]] || fail
  done

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'reaper.object-audit-disabled',
  'projection', pg_catalog.jsonb_build_object(
    'settings', pg_catalog.jsonb_build_object(
      'logStatement', 'none',
      'minimumErrorStatement', 'panic',
      'logDuration', false,
      'minimumDuration', 'disabled',
      'minimumSampleDuration', 'disabled',
      'statementSampleRate', 0,
      'parameterLogging', false,
      'parameterMaximumLength', 0,
      'errorParameterMaximumLength', 0,
      'autoExplain', pg_catalog.jsonb_build_object(
        'minimumDuration', 'disabled',
        'parameterMaximumLength', 0
      ),
      'pgauditLog', 'none',
      'pgauditStatement', false,
      'pgauditParameter', false,
      'pgauditRole', 'empty',
      'objectAudit', pg_catalog.jsonb_build_object(
        'membershipClosure', 'clear',
        'reachableAsterRelations', 0
      ),
      'managedAuditPolicy', pg_catalog.jsonb_build_object(
        'requestWorkerRolesExcluded', true,
        'statementCapture', false,
        'parameterCapture', false
      )
    ),
    'artifacts', pg_catalog.jsonb_build_array(
      pg_catalog.jsonb_build_object(
        'sink', 'postgres',
        'sha256', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'matches', pg_catalog.jsonb_build_array()
      ),
      pg_catalog.jsonb_build_object(
        'sink', 'managed-export',
        'sha256', 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'matches', pg_catalog.jsonb_build_array()
      ),
      pg_catalog.jsonb_build_object(
        'sink', 'application',
        'sha256', 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        'matches', pg_catalog.jsonb_build_array()
      )
    ),
    'allClear', true
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
  [[ "$terminal" != *'phase1-audit-request-sentinel'* && \
     "$terminal" != *'phase1-audit-worker-sentinel'* ]] || fail
  cleanup_audit_clients || fail
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'keystore.required-readable-key-set' ]]; then
  required_readable_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SELECT pg_catalog.set_config('search_path', 'pg_catalog', false),
       pg_catalog.set_config('transaction_timeout', '20s', false),
       pg_catalog.set_config('statement_timeout', '15s', false),
       pg_catalog.set_config('idle_in_transaction_session_timeout', '5s', false),
       pg_catalog.set_config('log_min_messages', 'panic', false),
       pg_catalog.set_config('log_min_error_statement', 'panic', false),
       pg_catalog.set_config('log_statement', 'none', false),
       pg_catalog.set_config('log_duration', 'off', false),
       pg_catalog.set_config('log_min_duration_statement', '-1', false),
       pg_catalog.set_config('log_min_duration_sample', '-1', false),
       pg_catalog.set_config('log_statement_sample_rate', '0', false),
       pg_catalog.set_config('log_transaction_sample_rate', '0', false),
       pg_catalog.set_config('log_parameter_max_length', '0', false),
       pg_catalog.set_config('log_parameter_max_length_on_error', '0', false),
       pg_catalog.set_config('log_statement_stats', 'off', false),
       pg_catalog.set_config('log_parser_stats', 'off', false),
       pg_catalog.set_config('log_planner_stats', 'off', false),
       pg_catalog.set_config('log_executor_stats', 'off', false),
       pg_catalog.set_config('log_lock_waits', 'off', false),
       pg_catalog.set_config('log_temp_files', '-1', false),
       pg_catalog.set_config('track_activities', 'on', false),
       pg_catalog.set_config('auto_explain.log_min_duration', '-1', false),
       pg_catalog.set_config('auto_explain.log_parameter_max_length', '0', false),
       pg_catalog.set_config('pgaudit.log', 'none', false),
       pg_catalog.set_config('pgaudit.log_statement', 'off', false),
       pg_catalog.set_config('pgaudit.log_parameter', 'off', false),
       pg_catalog.set_config('pgaudit.role', '', false) \g /dev/null

SELECT deployment_id::text AS deployment_id
FROM aster_control.deployment_state
WHERE singleton \gset
SELECT active_key_id AS active_key_id
FROM aster_control.wrapping_key_runtime_state
WHERE singleton \gset

-- phase1-required-old-referenced
-- phase1-required-rollback-retained
-- phase1-required-staged-optional
-- phase1-required-removable-optional
INSERT INTO aster_control.wrapping_key_registry (
  key_id,
  writer_generation,
  lifecycle_state,
  required_readable,
  reference_count
) VALUES
  ('aster-mk-1000000000000001', 2, 'retained', true, 1),
  ('aster-mk-1000000000000002', 2, 'retained', true, 0),
  ('aster-mk-1000000000000003', 2, 'staged', false, 0),
  ('aster-mk-1000000000000004', 2, 'removable', false, 0);
INSERT INTO aster_control.wrapping_key_history (key_id, writer_generation)
VALUES ('aster-mk-10000000000000aa', 2);
UPDATE aster_control.wrapping_key_runtime_state
SET minimum_keyring_generation = 2
WHERE singleton;

SET SESSION AUTHORIZATION aster_key_runtime;
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id',
  pg_catalog.decode(pg_catalog.repeat('81', 32), 'hex'),
  2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'active_key_id',
      'aster-mk-1000000000000001',
      'aster-mk-1000000000000002',
      'aster-mk-1000000000000003',
      'aster-mk-1000000000000004'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) AS lease_ms \gset

SAVEPOINT missing_required;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id', pg_catalog.decode(pg_catalog.repeat('82', 32), 'hex'), 2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'active_key_id',
      'aster-mk-1000000000000001',
      'aster-mk-1000000000000003',
      'aster-mk-1000000000000004'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) \g /dev/null
\set missing_state :SQLSTATE
ROLLBACK TO SAVEPOINT missing_required;
\set ON_ERROR_STOP on

SAVEPOINT unknown_key;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id', pg_catalog.decode(pg_catalog.repeat('83', 32), 'hex'), 2,
  ARRAY[:'active_key_id', 'not-a-wrapping-key']::text[]
) \g /dev/null
\set unknown_state :SQLSTATE
ROLLBACK TO SAVEPOINT unknown_key;
\set ON_ERROR_STOP on

SAVEPOINT tombstoned_key;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id', pg_catalog.decode(pg_catalog.repeat('84', 32), 'hex'), 2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'active_key_id',
      'aster-mk-1000000000000001',
      'aster-mk-1000000000000002',
      'aster-mk-10000000000000aa'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) \g /dev/null
\set tombstoned_state :SQLSTATE
ROLLBACK TO SAVEPOINT tombstoned_key;
\set ON_ERROR_STOP on

SAVEPOINT non_live_key;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id', pg_catalog.decode(pg_catalog.repeat('85', 32), 'hex'), 2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'active_key_id',
      'aster-mk-1000000000000001',
      'aster-mk-1000000000000002',
      'aster-mk-10000000000000bb'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) \g /dev/null
\set non_live_state :SQLSTATE
ROLLBACK TO SAVEPOINT non_live_key;
\set ON_ERROR_STOP on

SELECT CASE WHEN state.minimum_keyring_generation = 2
  AND state.live_key_ids = ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'active_key_id',
      'aster-mk-1000000000000001',
      'aster-mk-1000000000000002',
      'aster-mk-1000000000000003',
      'aster-mk-1000000000000004'
    ]::text[]) AS live(key_id)
    ORDER BY key_id COLLATE "C"
  )
  AND state.required_readable_key_ids = ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'active_key_id',
      'aster-mk-1000000000000001',
      'aster-mk-1000000000000002'
    ]::text[]) AS required(key_id)
    ORDER BY key_id COLLATE "C"
  )
  AND state.active_writer_lease_count = 1
THEN 'true' ELSE 'false' END AS state_ok
FROM aster_runtime.read_key_runtime_state(:'deployment_id') AS state \gset

\echo :lease_ms|:missing_state|:unknown_state|:tombstoned_state|:non_live_state|:state_ok
RESET SESSION AUTHORIZATION;
ROLLBACK;
SQL
)" || fail
  [[ "$required_readable_observation" == '15000|42501|42501|42501|42501|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.required-readable-key-set',
  'projection', pg_catalog.jsonb_build_object(
    'replica', pg_catalog.jsonb_build_object(
      'generation', 2,
      'requiredReadable', pg_catalog.jsonb_build_array(
        '<key.active>', '<key.old-referenced>', '<key.rollback-retained>'
      ),
      'locallyLoaded', pg_catalog.jsonb_build_array(
        '<key.active>', '<key.old-referenced>', '<key.rollback-retained>',
        '<key.staged-optional>', '<key.removable-optional>'
      ),
      'live', pg_catalog.jsonb_build_array(
        '<key.active>', '<key.old-referenced>', '<key.rollback-retained>',
        '<key.staged-optional>', '<key.removable-optional>'
      ),
      'missingRequired', pg_catalog.jsonb_build_array(),
      'optionalAccepted', pg_catalog.jsonb_build_array(
        '<key.staged-optional>', '<key.removable-optional>'
      ),
      'negativeCategories', pg_catalog.jsonb_build_object(
        'unknown', pg_catalog.jsonb_build_object(
          'ids', pg_catalog.jsonb_build_array('<key.unknown>'), 'accepted', false
        ),
        'tombstoned', pg_catalog.jsonb_build_object(
          'ids', pg_catalog.jsonb_build_array('<key.tombstoned>'), 'accepted', false
        ),
        'nonLive', pg_catalog.jsonb_build_object(
          'ids', pg_catalog.jsonb_build_array('<key.non-live>'), 'accepted', false
        )
      ),
      'readiness', 'ready'
    )
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'keystore.stale-keyring-rejoin-rejected' ]]; then
  stale_keyring_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SELECT pg_catalog.set_config('search_path', 'pg_catalog', false),
       pg_catalog.set_config('transaction_timeout', '20s', false),
       pg_catalog.set_config('statement_timeout', '15s', false),
       pg_catalog.set_config('idle_in_transaction_session_timeout', '5s', false),
       pg_catalog.set_config('log_min_messages', 'panic', false),
       pg_catalog.set_config('log_min_error_statement', 'panic', false),
       pg_catalog.set_config('log_statement', 'none', false),
       pg_catalog.set_config('log_duration', 'off', false),
       pg_catalog.set_config('log_min_duration_statement', '-1', false),
       pg_catalog.set_config('log_min_duration_sample', '-1', false),
       pg_catalog.set_config('log_statement_sample_rate', '0', false),
       pg_catalog.set_config('log_transaction_sample_rate', '0', false),
       pg_catalog.set_config('log_parameter_max_length', '0', false),
       pg_catalog.set_config('log_parameter_max_length_on_error', '0', false),
       pg_catalog.set_config('log_statement_stats', 'off', false),
       pg_catalog.set_config('log_parser_stats', 'off', false),
       pg_catalog.set_config('log_planner_stats', 'off', false),
       pg_catalog.set_config('log_executor_stats', 'off', false),
       pg_catalog.set_config('log_lock_waits', 'off', false),
       pg_catalog.set_config('log_temp_files', '-1', false),
       pg_catalog.set_config('track_activities', 'on', false),
       pg_catalog.set_config('auto_explain.log_min_duration', '-1', false),
       pg_catalog.set_config('auto_explain.log_parameter_max_length', '0', false),
       pg_catalog.set_config('pgaudit.log', 'none', false),
       pg_catalog.set_config('pgaudit.log_statement', 'off', false),
       pg_catalog.set_config('pgaudit.log_parameter', 'off', false),
       pg_catalog.set_config('pgaudit.role', '', false) \g /dev/null

SELECT deployment_id::text AS deployment_id
FROM aster_control.deployment_state
WHERE singleton \gset
SELECT active_key_id AS old_active_key_id
FROM aster_control.wrapping_key_runtime_state
WHERE singleton \gset

-- phase1-stale-keyring-pre-reload
UPDATE aster_control.wrapping_key_registry
SET lifecycle_state = 'retained', required_readable = true
WHERE key_id = :'old_active_key_id';
INSERT INTO aster_control.wrapping_key_registry (
  key_id,
  writer_generation,
  lifecycle_state,
  required_readable,
  reference_count
) VALUES ('aster-mk-2000000000000001', 2, 'active', true, 0);
UPDATE aster_control.wrapping_key_runtime_state
SET active_key_id = 'aster-mk-2000000000000001',
    minimum_keyring_generation = 2
WHERE singleton;
INSERT INTO aster_control.wrapping_key_history (key_id, writer_generation)
VALUES ('aster-mk-20000000000000aa', 2);

SET SESSION AUTHORIZATION aster_key_runtime;
SAVEPOINT stale_generation;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id',
  pg_catalog.decode(pg_catalog.repeat('91', 32), 'hex'),
  1,
  ARRAY[:'old_active_key_id']::text[]
) \g /dev/null
\set stale_state :SQLSTATE
ROLLBACK TO SAVEPOINT stale_generation;
\set ON_ERROR_STOP on

-- phase1-stale-keyring-post-reload
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id',
  pg_catalog.decode(pg_catalog.repeat('92', 32), 'hex'),
  2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'old_active_key_id',
      'aster-mk-2000000000000001'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) AS reload_lease_ms \gset

SAVEPOINT tombstoned_key;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id',
  pg_catalog.decode(pg_catalog.repeat('93', 32), 'hex'),
  2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'old_active_key_id',
      'aster-mk-2000000000000001',
      'aster-mk-20000000000000aa'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) \g /dev/null
\set tombstoned_state :SQLSTATE
ROLLBACK TO SAVEPOINT tombstoned_key;
\set ON_ERROR_STOP on

SAVEPOINT non_live_key;
\set ON_ERROR_STOP off
SELECT aster_runtime.upsert_own_writer_lease(
  :'deployment_id',
  pg_catalog.decode(pg_catalog.repeat('94', 32), 'hex'),
  2,
  ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'old_active_key_id',
      'aster-mk-2000000000000001',
      'aster-mk-20000000000000bb'
    ]::text[]) AS loaded(key_id)
    ORDER BY key_id COLLATE "C"
  )
) \g /dev/null
\set non_live_state :SQLSTATE
ROLLBACK TO SAVEPOINT non_live_key;
\set ON_ERROR_STOP on

SELECT CASE WHEN state.active_key_id = 'aster-mk-2000000000000001'
  AND state.writer_generation = 2
  AND state.minimum_keyring_generation = 2
  AND state.live_key_ids = ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'old_active_key_id',
      'aster-mk-2000000000000001'
    ]::text[]) AS live(key_id)
    ORDER BY key_id COLLATE "C"
  )
  AND state.required_readable_key_ids = ARRAY(
    SELECT key_id
    FROM pg_catalog.unnest(ARRAY[
      :'old_active_key_id',
      'aster-mk-2000000000000001'
    ]::text[]) AS required(key_id)
    ORDER BY key_id COLLATE "C"
  )
  AND state.active_writer_lease_count = 1
THEN 'true' ELSE 'false' END AS state_ok
FROM aster_runtime.read_key_runtime_state(:'deployment_id') AS state \gset

\echo :stale_state|:reload_lease_ms|:tombstoned_state|:non_live_state|:state_ok
RESET SESSION AUTHORIZATION;
ROLLBACK;
SQL
)" || fail
  [[ "$stale_keyring_observation" == '42501|15000|42501|42501|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.stale-keyring-rejoin-rejected',
  'projection', pg_catalog.jsonb_build_object(
    'replica', pg_catalog.jsonb_build_object(
      'loadedGeneration', 1,
      'minimumGeneration', 2,
      'loadedSetFingerprint',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'allowedSetFingerprint',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'requiredSetFingerprint',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      'preReload', pg_catalog.jsonb_build_object(
        'heartbeat', 'rejected',
        'readiness', 'not-ready',
        'reasonClass', 'stale-generation'
      ),
      'postReload', pg_catalog.jsonb_build_object(
        'loadedGeneration', 2,
        'heartbeat', 'accepted',
        'readiness', 'ready',
        'reasonClass', 'current-generation'
      ),
      'heartbeat', 'rejected',
      'readiness', 'not-ready',
      'reasonClass', 'stale-generation',
      'fullReloadRequired', true,
      'writerResumed', false,
      'tombstonedIdAccepted', false,
      'nonLiveIdAccepted', false
    )
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'keystore.forced-rls-owner-boundary' ]]; then
  forced_rls_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SELECT pg_catalog.set_config('search_path', 'pg_catalog', false),
       pg_catalog.set_config('transaction_timeout', '20s', false),
       pg_catalog.set_config('statement_timeout', '15s', false),
       pg_catalog.set_config('idle_in_transaction_session_timeout', '5s', false),
       pg_catalog.set_config('log_min_messages', 'panic', false),
       pg_catalog.set_config('log_min_error_statement', 'panic', false),
       pg_catalog.set_config('log_statement', 'none', false),
       pg_catalog.set_config('log_duration', 'off', false),
       pg_catalog.set_config('log_min_duration_statement', '-1', false),
       pg_catalog.set_config('log_min_duration_sample', '-1', false),
       pg_catalog.set_config('log_statement_sample_rate', '0', false),
       pg_catalog.set_config('log_transaction_sample_rate', '0', false),
       pg_catalog.set_config('log_parameter_max_length', '0', false),
       pg_catalog.set_config('log_parameter_max_length_on_error', '0', false),
       pg_catalog.set_config('log_statement_stats', 'off', false),
       pg_catalog.set_config('log_parser_stats', 'off', false),
       pg_catalog.set_config('log_planner_stats', 'off', false),
       pg_catalog.set_config('log_executor_stats', 'off', false),
       pg_catalog.set_config('log_lock_waits', 'off', false),
       pg_catalog.set_config('log_temp_files', '-1', false),
       pg_catalog.set_config('track_activities', 'on', false),
       pg_catalog.set_config('auto_explain.log_min_duration', '-1', false),
       pg_catalog.set_config('auto_explain.log_parameter_max_length', '0', false),
       pg_catalog.set_config('pgaudit.log', 'none', false),
       pg_catalog.set_config('pgaudit.log_statement', 'off', false),
       pg_catalog.set_config('pgaudit.log_parameter', 'off', false),
       pg_catalog.set_config('pgaudit.role', '', false) \g /dev/null

SELECT deployment_id::text AS deployment_id
FROM aster_control.deployment_state
WHERE singleton \gset
SELECT state.active_key_id AS active_key_id,
       registry.writer_generation AS writer_generation
FROM aster_control.wrapping_key_runtime_state AS state
JOIN aster_control.wrapping_key_registry AS registry
  ON registry.key_id = state.active_key_id
WHERE state.singleton \gset

INSERT INTO aster_control.tenants (
  tenant_id, status, status_epoch, provisioning_verified
) VALUES
  ('phase1-key-tenant-a', 'inactive', 1, false),
  ('phase1-key-tenant-b', 'inactive', 1, false);
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat(seed, 32), 'hex')),
       tenant_id, 1, :'deployment_id'::uuid, 'admin', 'provision',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM (
  VALUES
    ('a1'::text, 'phase1-key-tenant-a'::text),
    ('a2'::text, 'phase1-key-tenant-b'::text)
) AS fixture(seed, tenant_id)
CROSS JOIN LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('a1', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1',
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1',
  1,
  '{}',
  pg_catalog.decode(pg_catalog.repeat('11', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('21', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('31', 24), 'hex'),
  :'active_key_id',
  :'writer_generation'::bigint
) \g /dev/null
SELECT aster_runtime.provision_cookie_key(
  'ccccccccccccccccccccccccccccccc1',
  'ddddddddddddddddddddddddddddddd1',
  1,
  pg_catalog.decode(pg_catalog.repeat('12', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('22', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('32', 24), 'hex'),
  :'active_key_id',
  :'writer_generation'::bigint
) \g /dev/null
SELECT aster_runtime.complete_bound_tenant_key_provisioning(
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1',
  'ccccccccccccccccccccccccccccccc1'
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-key-tenant-a';

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('a2', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2',
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2',
  1,
  '{}',
  pg_catalog.decode(pg_catalog.repeat('13', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('23', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('33', 24), 'hex'),
  :'active_key_id',
  :'writer_generation'::bigint
) \g /dev/null
SELECT aster_runtime.provision_cookie_key(
  'ccccccccccccccccccccccccccccccc2',
  'ddddddddddddddddddddddddddddddd2',
  1,
  pg_catalog.decode(pg_catalog.repeat('14', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('24', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('34', 24), 'hex'),
  :'active_key_id',
  :'writer_generation'::bigint
) \g /dev/null
SELECT aster_runtime.complete_bound_tenant_key_provisioning(
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2',
  'ccccccccccccccccccccccccccccccc2'
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-key-tenant-b';

UPDATE aster_control.tenants
SET status = 'active', status_epoch = 2
WHERE tenant_id IN ('phase1-key-tenant-a', 'phase1-key-tenant-b');
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('a3', 32), 'hex')),
       'phase1-key-tenant-a', 2, :'deployment_id'::uuid, 'admin', 'key_lifecycle',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

-- phase1-key-owner-probe
CREATE FUNCTION aster_runtime.phase1_key_owner_probe(target_tenant text, mutate boolean)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp
AS $phase1_probe$
DECLARE
  bound_tenant text := aster_runtime.bound_tenant_id('key_lifecycle');
  affected bigint;
BEGIN
  IF bound_tenant IS NULL OR target_tenant IS NULL OR mutate IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501';
  END IF;
  IF NOT mutate THEN
    SELECT pg_catalog.count(*) INTO affected
    FROM aster_tenant.signing_key_metadata
    WHERE tenant_id = bound_tenant;
    RETURN affected;
  END IF;
  DELETE FROM aster_tenant.signing_key_material
  WHERE tenant_id = target_tenant;
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected;
END
$phase1_probe$;
REVOKE ALL ON FUNCTION aster_runtime.phase1_key_owner_probe(text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aster_runtime.phase1_key_owner_probe(text, boolean) TO aster_admin;

SELECT CASE WHEN pg_catalog.count(*) = 4
  AND pg_catalog.bool_and(relation.relrowsecurity AND relation.relforcerowsecurity)
  AND NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polrelid IN (
      'aster_tenant.signing_key_metadata'::pg_catalog.regclass,
      'aster_tenant.signing_key_material'::pg_catalog.regclass,
      'aster_tenant.cookie_key_metadata'::pg_catalog.regclass,
      'aster_tenant.cookie_key_material'::pg_catalog.regclass
    )
      AND (
        pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) = 'true'
        OR pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) = 'true'
      )
  )
THEN 'true' ELSE 'false' END AS catalog_ok
FROM pg_catalog.pg_class AS relation
WHERE relation.oid IN (
  'aster_tenant.signing_key_metadata'::pg_catalog.regclass,
  'aster_tenant.signing_key_material'::pg_catalog.regclass,
  'aster_tenant.cookie_key_metadata'::pg_catalog.regclass,
  'aster_tenant.cookie_key_material'::pg_catalog.regclass
) \gset

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('a3', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.phase1_key_owner_probe(
  'phase1-key-tenant-a', false
) AS visible_count \gset
SELECT aster_runtime.phase1_key_owner_probe(
  'phase1-key-tenant-a', true
) AS mutation_count \gset
SAVEPOINT cross_tenant_mutation;
\set ON_ERROR_STOP off
SELECT aster_runtime.phase1_key_owner_probe(
  'phase1-key-tenant-b', true
) \g /dev/null
\set cross_state :SQLSTATE
ROLLBACK TO SAVEPOINT cross_tenant_mutation;
\set ON_ERROR_STOP on
RESET SESSION AUTHORIZATION;

SELECT CASE WHEN
  (SELECT pg_catalog.count(*) FROM aster_tenant.signing_key_material
    WHERE tenant_id = 'phase1-key-tenant-a') = 0
  AND (SELECT pg_catalog.count(*) FROM aster_tenant.signing_key_material
    WHERE tenant_id = 'phase1-key-tenant-b') = 1
  AND (SELECT pg_catalog.count(*) FROM aster_tenant.signing_key_metadata
    WHERE tenant_id = 'phase1-key-tenant-a') = 1
  AND (SELECT pg_catalog.count(*) FROM aster_tenant.signing_key_metadata
    WHERE tenant_id = 'phase1-key-tenant-b') = 1
THEN 'true' ELSE 'false' END AS state_ok \gset

\echo :visible_count|:mutation_count|:cross_state|:catalog_ok|:state_ok
ROLLBACK;
SQL
)" || fail
  [[ "$forced_rls_observation" == '1|1|42501|true|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.forced-rls-owner-boundary',
  'projection', pg_catalog.jsonb_build_object(
    'policy', pg_catalog.jsonb_build_object('forceRls', true, 'usingTrue', false),
    'binding', pg_catalog.jsonb_build_object(
      'tenantId', 'tenant-a', 'operationClass', 'key-lifecycle'
    ),
    'semanticState', pg_catalog.jsonb_build_object(
      'visibleRows', pg_catalog.jsonb_build_array(
        pg_catalog.jsonb_build_object('tenantId', 'tenant-a', 'count', 1)
      ),
      'crossTenantRows', pg_catalog.jsonb_build_array(),
      'mutations', pg_catalog.jsonb_build_array(
        pg_catalog.jsonb_build_object('tenantId', 'tenant-a', 'count', 1)
      ),
      'crossTenantMutations', 0
    )
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
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
