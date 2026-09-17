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
  database.owner-role-membership-boundary|tenant.suspended-epoch-rejected|tenant.cross-tenant-read-rejected|tenant.admin-operation-binding|tenant.admin-operation-status-matrix|reaper.activity-visibility-redaction|reaper.object-audit-disabled|keystore.required-readable-key-set|keystore.stale-keyring-rejoin-rejected|keystore.forced-rls-owner-boundary|keystore.metadata-dml-boundary|keystore.reference-count-ledger|keystore.reference-ledger-verifier-boundary|keystore.unwrap-failure-rolls-back-code|keystore.live-ledger-limit-and-tombstone|keystore.wrapping-fence-late-commit|keystore.sign-seal-during-rewrap|hosts.unavailable-pkce-independent) ;;
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

if [[ "$invariant_id" == 'keystore.metadata-dml-boundary' ]]; then
  metadata_dml_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
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
) VALUES ('phase1-metadata-tenant-a', 'inactive', 1, false);
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('b1', 32), 'hex')),
       'phase1-metadata-tenant-a', 1, :'deployment_id'::uuid, 'admin', 'provision',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('b1', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1',
  'fffffffffffffffffffffffffffffff1',
  1,
  '{}',
  pg_catalog.decode(pg_catalog.repeat('15', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('25', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('35', 24), 'hex'),
  :'active_key_id',
  :'writer_generation'::bigint
) \g /dev/null
SELECT aster_runtime.provision_cookie_key(
  'ddddddddddddddddddddddddddddddd1',
  'ccccccccccccccccccccccccccccccc1',
  1,
  pg_catalog.decode(pg_catalog.repeat('16', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('26', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('36', 24), 'hex'),
  :'active_key_id',
  :'writer_generation'::bigint
) \g /dev/null
SELECT aster_runtime.complete_bound_tenant_key_provisioning(
  'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1',
  'ddddddddddddddddddddddddddddddd1'
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-metadata-tenant-a';
UPDATE aster_control.tenants
SET status = 'active', status_epoch = 2
WHERE tenant_id = 'phase1-metadata-tenant-a';
UPDATE aster_tenant.signing_key_metadata
SET last_signed_at = pg_catalog.clock_timestamp() - interval '1 day'
WHERE tenant_id = 'phase1-metadata-tenant-a';
UPDATE aster_tenant.cookie_key_metadata
SET last_sealed_at = pg_catalog.clock_timestamp() - interval '1 day'
WHERE tenant_id = 'phase1-metadata-tenant-a';
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('b2', 32), 'hex')),
       'phase1-metadata-tenant-a', 2, :'deployment_id'::uuid, 'request', NULL,
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

-- phase1-metadata-dml-probe
SET SESSION AUTHORIZATION aster_request;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('b2', 32), 'hex')
) \g /dev/null

SAVEPOINT caller_time;
\set ON_ERROR_STOP off
UPDATE aster_tenant.signing_key_metadata
SET last_signed_at = pg_catalog.clock_timestamp() + interval '1 day'
WHERE tenant_id = 'phase1-metadata-tenant-a';
\set caller_time_state :SQLSTATE
ROLLBACK TO SAVEPOINT caller_time;
\set ON_ERROR_STOP on

SAVEPOINT lifecycle_change;
\set ON_ERROR_STOP off
UPDATE aster_tenant.signing_key_metadata
SET lifecycle_state = 'retained'
WHERE tenant_id = 'phase1-metadata-tenant-a';
\set lifecycle_state :SQLSTATE
ROLLBACK TO SAVEPOINT lifecycle_change;
\set ON_ERROR_STOP on

SAVEPOINT generation_change;
\set ON_ERROR_STOP off
UPDATE aster_tenant.signing_key_metadata
SET generation = 2
WHERE tenant_id = 'phase1-metadata-tenant-a';
\set generation_state :SQLSTATE
ROLLBACK TO SAVEPOINT generation_change;
\set ON_ERROR_STOP on

SAVEPOINT tenant_change;
\set ON_ERROR_STOP off
UPDATE aster_tenant.signing_key_metadata
SET tenant_id = 'phase1-metadata-other'
WHERE tenant_id = 'phase1-metadata-tenant-a';
\set tenant_state :SQLSTATE
ROLLBACK TO SAVEPOINT tenant_change;
\set ON_ERROR_STOP on

SAVEPOINT material_change;
\set ON_ERROR_STOP off
UPDATE aster_tenant.signing_key_material
SET ciphertext = pg_catalog.decode(pg_catalog.repeat('99', 64), 'hex')
WHERE tenant_id = 'phase1-metadata-tenant-a';
\set material_state :SQLSTATE
ROLLBACK TO SAVEPOINT material_change;
\set ON_ERROR_STOP on

SAVEPOINT public_metadata_change;
\set ON_ERROR_STOP off
UPDATE aster_tenant.signing_key_metadata
SET public_metadata_fingerprint = pg_catalog.decode(pg_catalog.repeat('99', 32), 'hex')
WHERE tenant_id = 'phase1-metadata-tenant-a';
\set public_metadata_state :SQLSTATE
ROLLBACK TO SAVEPOINT public_metadata_change;
\set ON_ERROR_STOP on

SELECT aster_runtime.record_signing_use(
  'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1', 1
) \g /dev/null
SELECT aster_runtime.record_cookie_seal(
  'ddddddddddddddddddddddddddddddd1', 1
) \g /dev/null
RESET SESSION AUTHORIZATION;

SELECT CASE WHEN signing.lifecycle_state = 'active'
  AND signing.generation = 1
  AND signing.tenant_id = 'phase1-metadata-tenant-a'
  AND signing.material_id = 'fffffffffffffffffffffffffffffff1'
  AND signing.public_metadata_fingerprint = pg_catalog.decode(pg_catalog.repeat('15', 32), 'hex')
  AND signing.last_signed_at > pg_catalog.clock_timestamp() - interval '1 minute'
  AND signing.last_signed_at <= pg_catalog.clock_timestamp()
  AND cookie.lifecycle_state = 'active'
  AND cookie.generation = 1
  AND cookie.tenant_id = 'phase1-metadata-tenant-a'
  AND cookie.material_id = 'ccccccccccccccccccccccccccccccc1'
  AND cookie.public_metadata_fingerprint = pg_catalog.decode(pg_catalog.repeat('16', 32), 'hex')
  AND cookie.last_sealed_at > pg_catalog.clock_timestamp() - interval '1 minute'
  AND cookie.last_sealed_at <= pg_catalog.clock_timestamp()
  AND material.ciphertext = pg_catalog.decode(pg_catalog.repeat('25', 64), 'hex')
  AND material.wrapping_key_id = :'active_key_id'
  AND material.writer_generation = :'writer_generation'::bigint
THEN 'true' ELSE 'false' END AS state_ok
FROM aster_tenant.signing_key_metadata AS signing
JOIN aster_tenant.cookie_key_metadata AS cookie
  ON cookie.tenant_id = signing.tenant_id
JOIN aster_tenant.signing_key_material AS material
  ON material.tenant_id = signing.tenant_id
 AND material.material_id = signing.material_id
WHERE signing.tenant_id = 'phase1-metadata-tenant-a' \gset

\echo :caller_time_state|:lifecycle_state|:generation_state|:tenant_state|:material_state|:public_metadata_state|:state_ok
ROLLBACK;
SQL
)" || fail
  [[ "$metadata_dml_observation" == '42501|42501|42501|42501|42501|42501|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.metadata-dml-boundary',
  'projection', pg_catalog.jsonb_build_object(
    'semanticState', pg_catalog.jsonb_build_object(
      'keyMetadata', pg_catalog.jsonb_build_object(
        'activeGeneration', '<generation.1>',
        'lifecycle', 'active',
        'tenant', 'tenant-a',
        'materialRelationship', 'unchanged',
        'publicFingerprint',
          'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
      ),
      'before', pg_catalog.jsonb_build_object(
        'activeGeneration', '<generation.1>',
        'lifecycle', 'active',
        'tenant', 'tenant-a',
        'materialRelationship', 'unchanged',
        'publicFingerprint',
          'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        'lastSignedAt', 'baseline',
        'lastSealedAt', 'baseline'
      ),
      'after', pg_catalog.jsonb_build_object(
        'activeGeneration', '<generation.1>',
        'lifecycle', 'active',
        'tenant', 'tenant-a',
        'materialRelationship', 'unchanged',
        'publicFingerprint',
          'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        'lastSignedAt', 'advanced-by-database',
        'lastSealedAt', 'advanced-by-database'
      ),
      'allowedColumnDeltas', pg_catalog.jsonb_build_array('lastSignedAt', 'lastSealedAt'),
      'deniedOperations', pg_catalog.jsonb_build_array(
        'caller-time',
        'lifecycle-change',
        'generation-change',
        'tenant-change',
        'material-change',
        'public-metadata-change'
      )
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

if [[ "$invariant_id" == 'keystore.reference-count-ledger' ]]; then
  reference_ledger_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
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
SELECT state.active_key_id AS old_key_id,
       registry.writer_generation AS old_generation
FROM aster_control.wrapping_key_runtime_state AS state
JOIN aster_control.wrapping_key_registry AS registry
  ON registry.key_id = state.active_key_id
WHERE state.singleton \gset

UPDATE aster_control.wrapping_key_registry
SET lifecycle_state = 'retained', required_readable = true
WHERE key_id = :'old_key_id';
INSERT INTO aster_control.wrapping_key_registry (
  key_id, writer_generation, lifecycle_state, required_readable, reference_count
) VALUES ('aster-mk-3100000000000001', 1, 'active', true, 0);
UPDATE aster_control.wrapping_key_runtime_state
SET active_key_id = 'aster-mk-3100000000000001',
    minimum_keyring_generation = 1,
    write_fenced = false
WHERE singleton;
\set old_key_id 'aster-mk-3100000000000001'
\set old_generation 1

INSERT INTO aster_control.tenants (
  tenant_id, status, status_epoch, provisioning_verified
) VALUES
  ('phase1-ledger-tenant-a', 'inactive', 1, false),
  ('phase1-ledger-tenant-b', 'inactive', 1, false);
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat(seed, 32), 'hex')),
       tenant_id, 1, :'deployment_id'::uuid, 'admin', 'provision',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM (
  VALUES
    ('c1'::text, 'phase1-ledger-tenant-a'::text),
    ('c2'::text, 'phase1-ledger-tenant-b'::text)
) AS fixture(seed, tenant_id)
CROSS JOIN LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('c1', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  '111111111111111111111111111111a1',
  '222222222222222222222222222222a1', 1, '{}',
  pg_catalog.decode(pg_catalog.repeat('41', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('51', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('61', 24), 'hex'),
  :'old_key_id', :'old_generation'::bigint
) \g /dev/null
SELECT aster_runtime.provision_cookie_key(
  '333333333333333333333333333333a1',
  '444444444444444444444444444444a1', 1,
  pg_catalog.decode(pg_catalog.repeat('42', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('52', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('62', 24), 'hex'),
  :'old_key_id', :'old_generation'::bigint
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-ledger-tenant-a';

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('c2', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  '111111111111111111111111111111b1',
  '222222222222222222222222222222b1', 1, '{}',
  pg_catalog.decode(pg_catalog.repeat('43', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('53', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('63', 24), 'hex'),
  :'old_key_id', :'old_generation'::bigint
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-ledger-tenant-b';

UPDATE aster_control.tenants
SET status = 'active', status_epoch = 2
WHERE tenant_id IN ('phase1-ledger-tenant-a', 'phase1-ledger-tenant-b');
UPDATE aster_control.wrapping_key_registry
SET lifecycle_state = 'retained', required_readable = true
WHERE key_id = :'old_key_id';
INSERT INTO aster_control.wrapping_key_registry (
  key_id, writer_generation, lifecycle_state, required_readable, reference_count
) VALUES ('aster-mk-3000000000000001', 2, 'active', true, 0);
UPDATE aster_control.wrapping_key_runtime_state
SET active_key_id = 'aster-mk-3000000000000001',
    minimum_keyring_generation = 2,
    write_fenced = false
WHERE singleton;
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('c3', 32), 'hex')),
       'phase1-ledger-tenant-b', 2, :'deployment_id'::uuid, 'admin', 'rewrap',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('c3', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.rewrap_signing_key_material(
  '222222222222222222222222222222b1',
  pg_catalog.decode(pg_catalog.repeat('53', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('63', 24), 'hex'),
  :'old_key_id', :'old_generation'::bigint,
  pg_catalog.decode(pg_catalog.repeat('54', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('64', 24), 'hex'),
  'aster-mk-3000000000000001', 2
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-ledger-tenant-b';

INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('c4', 32), 'hex')),
       'phase1-ledger-tenant-b', 2, :'deployment_id'::uuid, 'admin', 'key_lifecycle',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

-- phase1-reference-ledger-probe
CREATE FUNCTION aster_runtime.phase1_reference_delete_probe(target_tenant text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp
AS $phase1_probe$
DECLARE affected bigint;
BEGIN
  IF aster_runtime.bound_tenant_id('key_lifecycle') IS DISTINCT FROM target_tenant THEN
    RAISE EXCEPTION USING ERRCODE = '42501';
  END IF;
  DELETE FROM aster_tenant.signing_key_material
  WHERE tenant_id = target_tenant;
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected;
END
$phase1_probe$;
REVOKE ALL ON FUNCTION aster_runtime.phase1_reference_delete_probe(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aster_runtime.phase1_reference_delete_probe(text) TO aster_admin;

SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('c4', 32), 'hex')
) \g /dev/null
SAVEPOINT delete_rollback;
SELECT aster_runtime.phase1_reference_delete_probe(
  'phase1-ledger-tenant-b'
) AS deleted_rows \gset
ROLLBACK TO SAVEPOINT delete_rollback;
RESET SESSION AUTHORIZATION;

WITH material_counts AS (
  SELECT wrapping_key_id, pg_catalog.count(*)::bigint AS expected
  FROM (
    SELECT wrapping_key_id FROM aster_tenant.signing_key_material
    WHERE tenant_id IN ('phase1-ledger-tenant-a', 'phase1-ledger-tenant-b')
    UNION ALL
    SELECT wrapping_key_id FROM aster_tenant.cookie_key_material
    WHERE tenant_id IN ('phase1-ledger-tenant-a', 'phase1-ledger-tenant-b')
  ) AS material
  GROUP BY wrapping_key_id
), ledger AS (
  SELECT registry.key_id,
         registry.reference_count AS actual,
         COALESCE(material_counts.expected, 0) AS expected
  FROM aster_control.wrapping_key_registry AS registry
  LEFT JOIN material_counts ON material_counts.wrapping_key_id = registry.key_id
  WHERE registry.key_id IN (:'old_key_id', 'aster-mk-3000000000000001')
)
SELECT CASE WHEN pg_catalog.count(*) = 2
  AND pg_catalog.bool_and(actual = expected)
  AND pg_catalog.sum(expected) = 3
  AND pg_catalog.sum(actual) = 3
  AND pg_catalog.count(*) FILTER (
    WHERE key_id = :'old_key_id' AND expected = 2 AND actual = 2
  ) = 1
  AND pg_catalog.count(*) FILTER (
    WHERE key_id = 'aster-mk-3000000000000001' AND expected = 1 AND actual = 1
  ) = 1
THEN 'true' ELSE 'false' END AS ledger_ok
FROM ledger \gset
SELECT CASE WHEN NOT EXISTS (
  SELECT 1 FROM aster_control.wrapping_key_registry WHERE reference_count < 0
) THEN 'true' ELSE 'false' END AS nonnegative_ok \gset

\echo :ledger_ok|:deleted_rows|:nonnegative_ok
ROLLBACK;
SQL
)" || fail
  [[ "$reference_ledger_observation" == 'true|1|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.reference-count-ledger',
  'projection', pg_catalog.jsonb_build_object(
    'ledger', pg_catalog.jsonb_build_object(
      'entries', pg_catalog.jsonb_build_array(
        pg_catalog.jsonb_build_object(
          'keyId', '<wrapping-key.1>', 'generation', 1, 'expected', 2, 'actual', 2
        ),
        pg_catalog.jsonb_build_object(
          'keyId', '<wrapping-key.2>', 'generation', 2, 'expected', 1, 'actual', 1
        )
      ),
      'mismatches', pg_catalog.jsonb_build_array(),
      'negativeCounts', 0,
      'uncommittedDeltas', 0
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

if [[ "$invariant_id" == 'keystore.reference-ledger-verifier-boundary' ]]; then
  reference_verifier_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
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
SELECT state.active_key_id,
       registry.writer_generation AS active_generation
FROM aster_control.wrapping_key_runtime_state AS state
JOIN aster_control.wrapping_key_registry AS registry
  ON registry.key_id = state.active_key_id
WHERE state.singleton \gset

INSERT INTO aster_control.wrapping_key_registry (
  key_id, writer_generation, lifecycle_state, required_readable, reference_count
)
SELECT 'aster-mk-6000000000000001', :'active_generation'::bigint + 1,
       'staged', false, 0
WHERE (SELECT pg_catalog.count(*) FROM aster_control.wrapping_key_registry) = 1;
UPDATE aster_control.wrapping_key_runtime_state
SET write_fenced = true
WHERE singleton;

SELECT CASE WHEN state.write_fenced THEN 'true' ELSE 'false' END AS fence_ok,
       CASE WHEN deployment.deployment_id::text = :'deployment_id'
         THEN 'true' ELSE 'false' END AS deployment_ok
FROM aster_control.wrapping_key_runtime_state AS state
CROSS JOIN aster_control.deployment_state AS deployment
WHERE state.singleton AND deployment.singleton \gset
SELECT pg_catalog.jsonb_agg(
         pg_catalog.jsonb_build_object(
           'keyId', registry.key_id,
           'generation', registry.writer_generation,
           'count', registry.reference_count
         )
         ORDER BY registry.key_id COLLATE "C"
       ) AS expected_entries,
       pg_catalog.count(*)::text AS input_count
FROM aster_control.wrapping_key_registry AS registry \gset
SELECT COALESCE(
         pg_catalog.sum(
           stats.n_tup_ins + stats.n_tup_upd + stats.n_tup_del
         ),
         0
       )::bigint AS dml_before
FROM pg_catalog.pg_stat_xact_user_tables AS stats
WHERE stats.schemaname IN ('aster_control', 'aster_tenant') \gset

-- phase1-reference-verifier-probe
SET SESSION AUTHORIZATION aster_admin;
SELECT result.matched::text AS positive_matched,
       pg_catalog.jsonb_array_length(result.mismatches)::text AS mismatch_count
FROM aster_runtime.verify_wrapping_reference_ledger(
  :'deployment_id', :'expected_entries'::jsonb
) AS result \gset
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION aster_request;
SAVEPOINT non_admin_denial;
\set ON_ERROR_STOP off
SELECT * FROM aster_runtime.verify_wrapping_reference_ledger(
  :'deployment_id', :'expected_entries'::jsonb
) \g /dev/null
\set non_admin_state :SQLSTATE
ROLLBACK TO SAVEPOINT non_admin_denial;
\set ON_ERROR_STOP on
RESET SESSION AUTHORIZATION;

SELECT pg_catalog.jsonb_agg(
         pg_catalog.jsonb_build_object(
           'keyId', 'aster-mk-' || pg_catalog.lpad(pg_catalog.to_hex(item), 16, '0'),
           'generation', item,
           'count', 0
         )
         ORDER BY item
       ) AS oversized_entries
FROM pg_catalog.generate_series(1, 33) AS fixture(item) \gset
SET SESSION AUTHORIZATION aster_admin;
SAVEPOINT oversized_denial;
\set ON_ERROR_STOP off
SELECT * FROM aster_runtime.verify_wrapping_reference_ledger(
  :'deployment_id', :'oversized_entries'::jsonb
) \g /dev/null
\set oversized_state :SQLSTATE
ROLLBACK TO SAVEPOINT oversized_denial;
\set ON_ERROR_STOP on

SELECT pg_catalog.jsonb_build_array(
         pg_catalog.jsonb_build_object(
           'keyId', :'active_key_id',
           'generation', :'active_generation'::bigint,
           'count', 0
         ),
         pg_catalog.jsonb_build_object(
           'keyId', 'aster-mk-6000000000000001',
           'generation', 'malformed',
           'count', 0
         )
       ) AS malformed_entries \gset
SAVEPOINT malformed_denial;
\set ON_ERROR_STOP off
SELECT * FROM aster_runtime.verify_wrapping_reference_ledger(
  :'deployment_id', :'malformed_entries'::jsonb
) \g /dev/null
\set malformed_state :SQLSTATE
ROLLBACK TO SAVEPOINT malformed_denial;
\set ON_ERROR_STOP on
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION aster_key_runtime;
SAVEPOINT runtime_denial;
\set ON_ERROR_STOP off
SELECT * FROM aster_runtime.verify_wrapping_reference_ledger(
  :'deployment_id', :'expected_entries'::jsonb
) \g /dev/null
\set runtime_denial_state :SQLSTATE
ROLLBACK TO SAVEPOINT runtime_denial;
\set ON_ERROR_STOP on
RESET SESSION AUTHORIZATION;

SELECT COALESCE(
         pg_catalog.sum(
           stats.n_tup_ins + stats.n_tup_upd + stats.n_tup_del
         ),
         0
       )::bigint AS dml_after
FROM pg_catalog.pg_stat_xact_user_tables AS stats
WHERE stats.schemaname IN ('aster_control', 'aster_tenant') \gset
SELECT (:'dml_after'::bigint - :'dml_before'::bigint)::text AS dml_delta \gset

\echo :fence_ok|:deployment_ok|:positive_matched|:input_count|:mismatch_count|:non_admin_state|:oversized_state|:malformed_state|:runtime_denial_state|:dml_delta
ROLLBACK;
SQL
)" || fail
  [[ "$reference_verifier_observation" == 'true|true|true|2|0|42501|42501|42501|42501|0' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.reference-ledger-verifier-boundary',
  'projection', pg_catalog.jsonb_build_object(
    'verifier', pg_catalog.jsonb_build_object(
      'fenceHeld', true,
      'deploymentMatched', true,
      'maximumEntries', 32,
      'cases', pg_catalog.jsonb_build_array(
        pg_catalog.jsonb_build_object(
          'caseClass', 'successful-admin',
          'callerClass', 'aster-admin',
          'inputClass', 'sorted-unique-bounded',
          'inputCount', 2,
          'resultClass', 'matched',
          'denialClass', NULL
        ),
        pg_catalog.jsonb_build_object(
          'caseClass', 'non-admin-denial',
          'callerClass', 'non-admin',
          'inputClass', 'sorted-unique-bounded',
          'inputCount', 2,
          'resultClass', 'denied',
          'denialClass', 'caller-not-admin'
        ),
        pg_catalog.jsonb_build_object(
          'caseClass', 'oversized-denial',
          'callerClass', 'aster-admin',
          'inputClass', 'oversized',
          'inputCount', 33,
          'resultClass', 'denied',
          'denialClass', 'input-too-large'
        ),
        pg_catalog.jsonb_build_object(
          'caseClass', 'malformed-denial',
          'callerClass', 'aster-admin',
          'inputClass', 'malformed',
          'inputCount', 2,
          'resultClass', 'denied',
          'denialClass', 'input-malformed'
        ),
        pg_catalog.jsonb_build_object(
          'caseClass', 'runtime-role-denial',
          'callerClass', 'aster-key-runtime',
          'inputClass', 'sorted-unique-bounded',
          'inputCount', 2,
          'resultClass', 'denied',
          'denialClass', 'runtime-role-denied'
        )
      ),
      'mismatchCount', 0,
      'disclosedTenantIds', pg_catalog.jsonb_build_array(),
      'dmlCount', 0
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

if [[ "$invariant_id" == 'keystore.unwrap-failure-rolls-back-code' ]]; then
  primary_core_id="$($DOCKER_BIN ps -aq \
    --filter "label=com.docker.compose.project=$project_name" \
    --filter 'label=com.docker.compose.service=candidate-primary-core' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$primary_core_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
  core_labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$primary_core_id" 2>/dev/null || true)"
  [[ "$core_labels" == "candidate-primary-core|$project_name" ]] || fail
  core_state="$($DOCKER_BIN inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$primary_core_id" 2>/dev/null || true)"
  [[ "$core_state" == 'running|healthy' ]] || fail

  unwrap_baseline_captured=false
  unwrap_material_id=''
  unwrap_original_sha256=''
  unwrap_flipped_sha256=''
  unwrap_last_signed_epoch=''
  unwrap_last_signed_null=''
  fixture_created=false

  toggle_signing_ciphertext() {
    local changed
    changed="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --set="material_id=$unwrap_material_id" \
      --set="original_sha256=$unwrap_original_sha256" \
      --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SET LOCAL session_replication_role = replica;
-- phase1-unwrap-toggle
WITH changed AS (
  UPDATE aster_tenant.signing_key_material
  SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 1)
  WHERE tenant_id = 'default'
    AND material_id = :'material_id'
    AND pg_catalog.encode(pg_catalog.sha256(ciphertext), 'hex') = :'original_sha256'
  RETURNING 1
)
SELECT pg_catalog.count(*)::text FROM changed;
COMMIT;
SQL
)" || return 1
    [[ "$changed" == 1 ]]
  }

  restore_unwrap_key_state() {
    local restored
    [[ "$unwrap_baseline_captured" == true ]] || return 0
    restored="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --set="material_id=$unwrap_material_id" \
      --set="original_sha256=$unwrap_original_sha256" \
      --set="flipped_sha256=$unwrap_flipped_sha256" \
      --set="last_signed_epoch=$unwrap_last_signed_epoch" \
      --set="last_signed_null=$unwrap_last_signed_null" \
      --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
SET LOCAL session_replication_role = replica;
-- phase1-unwrap-restore
UPDATE aster_tenant.signing_key_material
SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 1)
WHERE tenant_id = 'default'
  AND material_id = :'material_id'
  AND pg_catalog.encode(pg_catalog.sha256(ciphertext), 'hex') = :'flipped_sha256';
UPDATE aster_tenant.signing_key_metadata AS metadata
SET last_signed_at = CASE
  WHEN :'last_signed_null'::boolean THEN NULL
  ELSE pg_catalog.to_timestamp(:'last_signed_epoch'::numeric)
END
WHERE metadata.tenant_id = 'default'
  AND metadata.material_id = :'material_id'
  AND EXISTS (
    SELECT 1
    FROM aster_tenant.signing_key_material AS material
    WHERE material.tenant_id = metadata.tenant_id
      AND material.material_id = metadata.material_id
      AND pg_catalog.encode(pg_catalog.sha256(material.ciphertext), 'hex') = :'original_sha256'
  );
SELECT CASE WHEN
  (SELECT pg_catalog.encode(pg_catalog.sha256(ciphertext), 'hex')
   FROM aster_tenant.signing_key_material
   WHERE tenant_id = 'default' AND material_id = :'material_id') = :'original_sha256'
  AND (SELECT last_signed_at IS NOT DISTINCT FROM CASE
         WHEN :'last_signed_null'::boolean THEN NULL
         ELSE pg_catalog.to_timestamp(:'last_signed_epoch'::numeric)
       END
       FROM aster_tenant.signing_key_metadata
       WHERE tenant_id = 'default' AND material_id = :'material_id')
THEN 'true' ELSE 'false' END;
COMMIT;
SQL
)" || return 1
    [[ "$restored" == true ]]
  }

  cleanup_unwrap_fixture() {
    local cleanup_state
    restore_unwrap_key_state || return 1
    cleanup_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
-- phase1-unwrap-cleanup
DELETE FROM aster_tenant.grants
WHERE tenant_id = 'default' AND grant_id = 'phase1-unwrap-grant';
DELETE FROM aster_tenant.users
WHERE tenant_id = 'default' AND user_id = 'unwrap-user';
DELETE FROM aster_tenant.oidc_clients
WHERE tenant_id = 'default' AND client_id = 'unwrap-client';
SELECT
  (SELECT pg_catalog.count(*) FROM aster_tenant.grants
   WHERE tenant_id = 'default' AND grant_id = 'phase1-unwrap-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.authorization_codes
   WHERE tenant_id = 'default' AND grant_id = 'phase1-unwrap-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.token_families
   WHERE tenant_id = 'default' AND grant_id = 'phase1-unwrap-grant')::text || '|' ||
  (SELECT pg_catalog.count(*)
   FROM aster_tenant.refresh_tokens AS token
   JOIN aster_tenant.token_families AS family
     ON family.tenant_id = token.tenant_id AND family.family_id = token.family_id
   WHERE family.tenant_id = 'default' AND family.grant_id = 'phase1-unwrap-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.users
   WHERE tenant_id = 'default' AND user_id = 'unwrap-user')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.oidc_clients
   WHERE tenant_id = 'default' AND client_id = 'unwrap-client')::text;
COMMIT;
SQL
)" || return 1
    [[ "$cleanup_state" == '0|0|0|0|0|0' ]]
  }

  # Invoked indirectly by the EXIT trap.
  # shellcheck disable=SC2329
  cleanup_unwrap_on_exit() {
    local exit_code=$?
    trap - EXIT
    if [[ "$fixture_created" == true || "$unwrap_baseline_captured" == true ]]; then
      if ! cleanup_unwrap_fixture && ((exit_code == 0)); then
        printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
        exit_code=1
      fi
    fi
    exit "$exit_code"
  }
  trap cleanup_unwrap_on_exit EXIT

  setup_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
-- phase1-unwrap-setup
DELETE FROM aster_tenant.grants
WHERE tenant_id = 'default' AND grant_id = 'phase1-unwrap-grant';
DELETE FROM aster_tenant.users
WHERE tenant_id = 'default' AND user_id = 'unwrap-user';
DELETE FROM aster_tenant.oidc_clients
WHERE tenant_id = 'default' AND client_id = 'unwrap-client';

INSERT INTO aster_tenant.oidc_clients (
  tenant_id, client_id, name, redirect_uris, authentication_method, is_third_party
) VALUES (
  'default', 'unwrap-client', 'Unwrap invariant client',
  ARRAY['http://localhost/callback']::text[], 'none', false
);
INSERT INTO aster_tenant.users (
  tenant_id, user_id, username, is_suspended,
  name, avatar, primary_email, primary_phone, first_consent_client_id
) VALUES (
  'default', 'unwrap-user', 'unwrap-user', false,
  'Unwrap User', NULL, NULL, NULL, NULL
);
INSERT INTO aster_tenant.user_token_claims (
  tenant_id, user_id, primary_email_verified, primary_phone_verified,
  address, created_at_ms, updated_at_ms
) VALUES ('default', 'unwrap-user', false, false, NULL, 1000, 1000);

WITH observed AS (
  SELECT extract(epoch FROM pg_catalog.clock_timestamp())::bigint AS now
)
INSERT INTO aster_tenant.grants (
  tenant_id, grant_id, account_id, client_id, expires_at, permission_data
)
SELECT 'default', 'phase1-unwrap-grant', 'unwrap-user', 'unwrap-client', now + 3600,
       '{"approved":{"scope":"openid offline_access profile","claims":[],"resources":{}},"rejected":null}'::jsonb
FROM observed;

WITH observed AS (
  SELECT extract(epoch FROM pg_catalog.clock_timestamp())::bigint AS now
)
INSERT INTO aster_tenant.authorization_codes (
  tenant_id, code_digest, grant_id, account_id, client_id, redirect_uri,
  issued_at, expires_at, pkce_challenge, code_context, consumed
)
SELECT 'default', pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.repeat('u', 43), 'UTF8')),
       'phase1-unwrap-grant', 'unwrap-user', 'unwrap-client',
       'http://localhost/callback', now, now + 300,
       pg_catalog.convert_to('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'UTF8'),
       pg_catalog.jsonb_build_object(
         'auth_time', now,
         'acr', NULL,
         'amr', NULL,
         'nonce', NULL,
         'scope', 'openid offline_access profile',
         'resources', pg_catalog.jsonb_build_array(),
         'requested_claims', NULL,
         'sid', NULL,
         'session_uid', NULL,
         'expires_with_session', false
       ),
       false
FROM observed;

SELECT CASE WHEN
  (SELECT pg_catalog.count(*) FROM aster_tenant.authorization_codes
   WHERE tenant_id = 'default' AND grant_id = 'phase1-unwrap-grant' AND NOT consumed) = 1
  AND (SELECT pg_catalog.count(*) FROM aster_tenant.signing_key_metadata
       WHERE tenant_id = 'default' AND lifecycle_state = 'active') = 1
  AND (SELECT pg_catalog.count(*)
       FROM aster_tenant.signing_key_material AS material
       JOIN aster_tenant.signing_key_metadata AS metadata
         ON metadata.tenant_id = material.tenant_id
        AND metadata.material_id = material.material_id
        AND metadata.key_version_id = material.key_version_id
       WHERE metadata.tenant_id = 'default' AND metadata.lifecycle_state = 'active') = 1
THEN 'true' ELSE 'false' END;
COMMIT;
SQL
)" || fail
  [[ "$setup_state" == true ]] || fail
  fixture_created=true

  unwrap_baseline="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "SELECT material.material_id || '|' || pg_catalog.encode(pg_catalog.sha256(material.ciphertext), 'hex') || '|' || pg_catalog.encode(pg_catalog.sha256(pg_catalog.set_byte(material.ciphertext, 0, pg_catalog.get_byte(material.ciphertext, 0) # 1)), 'hex') || '|' || COALESCE(extract(epoch FROM metadata.last_signed_at)::text, 'null') FROM aster_tenant.signing_key_material AS material JOIN aster_tenant.signing_key_metadata AS metadata ON metadata.tenant_id=material.tenant_id AND metadata.material_id=material.material_id AND metadata.key_version_id=material.key_version_id WHERE metadata.tenant_id='default' AND metadata.lifecycle_state='active'" \
    2>/dev/null | tr -d '[:space:]')" || fail
  IFS='|' read -r unwrap_material_id unwrap_original_sha256 unwrap_flipped_sha256 unwrap_last_signed_epoch <<<"$unwrap_baseline"
  [[ "$unwrap_material_id" =~ ^[0-9a-f]{32}$ && \
     "$unwrap_original_sha256" =~ ^[0-9a-f]{64}$ && \
     "$unwrap_flipped_sha256" =~ ^[0-9a-f]{64}$ && \
     "$unwrap_original_sha256" != "$unwrap_flipped_sha256" ]] || fail
  if [[ "$unwrap_last_signed_epoch" == null ]]; then
    unwrap_last_signed_null=true
    unwrap_last_signed_epoch=0
  else
    [[ "$unwrap_last_signed_epoch" =~ ^[0-9]+([.][0-9]+)?$ ]] || fail
    unwrap_last_signed_null=false
  fi
  unwrap_baseline_captured=true
  unset unwrap_baseline

  raw_code="$(printf 'u%.0s' {1..43})"
  request_body="grant_type=authorization_code&client_id=unwrap-client&code=${raw_code}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback"
  request_bytes="$(printf '%s' "$request_body" | wc -c | tr -d '[:space:]')"
  [[ "$request_bytes" =~ ^[0-9]+$ && "$request_bytes" -le 4096 ]] || fail

  send_unwrap_token_request() {
    printf 'POST /oidc/token HTTP/1.1\r\nHost: localhost:3321\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "$request_bytes" "$request_body" |
      "$DOCKER_BIN" exec --interactive "$primary_core_id" \
        nc -w 15 127.0.0.1 3001
  }

  toggle_signing_ciphertext || fail
  failure_response="$(send_unwrap_token_request)" || fail
  response_bytes="$(printf '%s' "$failure_response" | wc -c | tr -d '[:space:]')"
  [[ "$response_bytes" =~ ^[0-9]+$ && "$response_bytes" -le 65536 ]] || fail
  [[ "$failure_response" == $'HTTP/1.1 503 Service Unavailable\r\n'* ]] || fail
  [[ "$failure_response" == *'"error":"temporarily_unavailable"'* ]] || fail
  [[ "$failure_response" != *'"access_token"'* && \
     "$failure_response" != *'"id_token"'* && \
     "$failure_response" != *'"refresh_token"'* ]] || fail
  unset failure_response

  failure_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
-- phase1-unwrap-failure-state
SELECT code.consumed::text || '|' ||
       (SELECT pg_catalog.count(*) FROM aster_tenant.token_families AS family
        WHERE family.tenant_id = code.tenant_id AND family.grant_id = code.grant_id)::text || '|' ||
       (SELECT pg_catalog.count(*)
        FROM aster_tenant.refresh_tokens AS token
        JOIN aster_tenant.token_families AS family
          ON family.tenant_id = token.tenant_id AND family.family_id = token.family_id
        WHERE family.tenant_id = code.tenant_id AND family.grant_id = code.grant_id)::text
FROM aster_tenant.authorization_codes AS code
WHERE code.tenant_id = 'default' AND code.grant_id = 'phase1-unwrap-grant';
SQL
)" || fail
  [[ "$failure_state" == 'false|0|0' ]] || fail

  restore_unwrap_key_state || fail
  retry_response="$(send_unwrap_token_request)" || fail
  response_bytes="$(printf '%s' "$retry_response" | wc -c | tr -d '[:space:]')"
  [[ "$response_bytes" =~ ^[0-9]+$ && "$response_bytes" -le 65536 ]] || fail
  [[ "$retry_response" == $'HTTP/1.1 200 OK\r\n'* ]] || fail
  [[ "$retry_response" == *'"access_token"'* && \
     "$retry_response" == *'"id_token"'* && \
     "$retry_response" == *'"refresh_token"'* ]] || fail
  unset retry_response raw_code request_body

  retry_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
-- phase1-unwrap-retry-state
SELECT code.consumed::text || '|' ||
       (SELECT pg_catalog.count(*) FROM aster_tenant.token_families AS family
        WHERE family.tenant_id = code.tenant_id AND family.grant_id = code.grant_id)::text || '|' ||
       (SELECT pg_catalog.count(*)
        FROM aster_tenant.refresh_tokens AS token
        JOIN aster_tenant.token_families AS family
          ON family.tenant_id = token.tenant_id AND family.family_id = token.family_id
        WHERE family.tenant_id = code.tenant_id AND family.grant_id = code.grant_id)::text
FROM aster_tenant.authorization_codes AS code
WHERE code.tenant_id = 'default' AND code.grant_id = 'phase1-unwrap-grant';
SQL
)" || fail
  [[ "$retry_state" == 'true|1|1' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.unwrap-failure-rolls-back-code',
  'projection', pg_catalog.jsonb_build_object(
    'publicOutcome', pg_catalog.jsonb_build_object(
      'errorClass', 'key-unwrap-failed',
      'retryable', true
    ),
    'semanticState', pg_catalog.jsonb_build_object(
      'code', pg_catalog.jsonb_build_object('consumed', false),
      'rows', pg_catalog.jsonb_build_object('familyRows', 0, 'materialRows', 0)
    ),
    'retryProbe', pg_catalog.jsonb_build_object('succeeded', true)
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
  cleanup_unwrap_fixture || fail
  fixture_created=false
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'hosts.unavailable-pkce-independent' ]]; then
  primary_core_id="$($DOCKER_BIN ps -aq \
    --filter "label=com.docker.compose.project=$project_name" \
    --filter 'label=com.docker.compose.service=candidate-primary-core' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$primary_core_id" =~ ^[0-9a-f]{12,64}$ ]] || fail
  core_labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$primary_core_id" 2>/dev/null || true)"
  [[ "$core_labels" == "candidate-primary-core|$project_name" ]] || fail

  connector_id="$($DOCKER_BIN ps -aq --filter "label=com.docker.compose.project=$project_name" --filter 'label=com.docker.compose.service=candidate-connector-host' | tr -d '[:space:]')" || fail
  saml_id="$($DOCKER_BIN ps -aq --filter "label=com.docker.compose.project=$project_name" --filter 'label=com.docker.compose.service=candidate-saml-host' | tr -d '[:space:]')" || fail
  script_id="$($DOCKER_BIN ps -aq --filter "label=com.docker.compose.project=$project_name" --filter 'label=com.docker.compose.service=candidate-script-host' | tr -d '[:space:]')" || fail
  for host_id in "$connector_id" "$saml_id" "$script_id"; do
    [[ "$host_id" =~ ^[0-9a-f]{12,64}$ && "$host_id" != "$primary_core_id" ]] || fail
  done
  [[ "$connector_id" != "$saml_id" && "$connector_id" != "$script_id" && "$saml_id" != "$script_id" ]] || fail

  inspect_host() {
    local host_id=$1 service=$2 boundary=$3 expected_kind=$4 expected_peer=$5 expected_version=$6
    local labels state environment mounts ports networks
    labels="$($DOCKER_BIN inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project" }}' "$host_id" 2>/dev/null || true)"
    [[ "$labels" == "$service|$project_name" ]] || return 1
    state="$($DOCKER_BIN inspect --format '{{.State.Status}}' "$host_id" 2>/dev/null || true)"
    [[ "$state" == running ]] || return 1
    environment="$($DOCKER_BIN inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$host_id" 2>/dev/null || true)"
    [[ "$environment" == *"ASTER_HOST_KIND=$expected_kind"* && \
       "$environment" == *"ASTER_HOST_PEER_ID=$expected_peer"* && \
       "$environment" == *"ASTER_HOST_PROTOCOL_VERSION=$expected_version"* ]] || return 1
    [[ ! "$environment" =~ (DB_URL|POSTGRES|PASSWORD|SECRET|TOKEN|COOKIE|SIGNING|MASTER_KEY) ]] || return 1
    mounts="$($DOCKER_BIN inspect --format '{{json .Mounts}}' "$host_id" 2>/dev/null || true)"
    ports="$($DOCKER_BIN inspect --format '{{json .HostConfig.PortBindings}}' "$host_id" 2>/dev/null || true)"
    networks="$($DOCKER_BIN inspect --format '{{json .NetworkSettings.Networks}}' "$host_id" 2>/dev/null || true)"
    [[ "$mounts" == '[]' && "$ports" == '{}' ]] || return 1
    [[ "$networks" == *"$boundary"* && "$networks" != *'candidate-primary'* ]] || return 1
  }

  inspect_host "$connector_id" candidate-connector-host candidate-connector-boundary connector spiffe://aster.test/connector 1 || fail
  inspect_host "$saml_id" candidate-saml-host candidate-saml-boundary saml spiffe://aster.test/connector 1 || fail
  inspect_host "$script_id" candidate-script-host candidate-script-boundary script spiffe://aster.test/script 2 || fail

  fixture_created=false
  cleanup_host_fixture() {
    local cleanup_state
    cleanup_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
-- phase1-host-cleanup
DELETE FROM aster_tenant.grants
WHERE tenant_id = 'default' AND grant_id = 'phase1-host-grant';
DELETE FROM aster_tenant.users
WHERE tenant_id = 'default' AND user_id = 'host-user';
DELETE FROM aster_tenant.oidc_clients
WHERE tenant_id = 'default' AND client_id = 'host-client';
SELECT
  (SELECT pg_catalog.count(*) FROM aster_tenant.grants WHERE tenant_id='default' AND grant_id='phase1-host-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.authorization_codes WHERE tenant_id='default' AND grant_id='phase1-host-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.token_families WHERE tenant_id='default' AND grant_id='phase1-host-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.refresh_tokens AS token JOIN aster_tenant.token_families AS family USING (tenant_id,family_id) WHERE family.tenant_id='default' AND family.grant_id='phase1-host-grant')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.users WHERE tenant_id='default' AND user_id='host-user')::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.oidc_clients WHERE tenant_id='default' AND client_id='host-client')::text;
COMMIT;
SQL
)" || return 1
    [[ "$cleanup_state" == '0|0|0|0|0|0' ]]
  }
  # shellcheck disable=SC2329
  cleanup_host_on_exit() {
    local exit_code=$?
    trap - EXIT
    if [[ "$fixture_created" == true ]] && ! cleanup_host_fixture && ((exit_code == 0)); then
      printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
      exit_code=1
    fi
    exit "$exit_code"
  }
  trap cleanup_host_on_exit EXIT

  setup_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" 2>/dev/null <<'SQL'
BEGIN;
-- phase1-host-setup
DELETE FROM aster_tenant.grants WHERE tenant_id='default' AND grant_id='phase1-host-grant';
DELETE FROM aster_tenant.users WHERE tenant_id='default' AND user_id='host-user';
DELETE FROM aster_tenant.oidc_clients WHERE tenant_id='default' AND client_id='host-client';
INSERT INTO aster_tenant.oidc_clients (tenant_id,client_id,name,redirect_uris,authentication_method,is_third_party)
VALUES ('default','host-client','Host invariant client',ARRAY['http://localhost/callback']::text[],'none',false);
INSERT INTO aster_tenant.users (tenant_id,user_id,username,is_suspended,name)
VALUES ('default','host-user','host-user',false,'Host User');
INSERT INTO aster_tenant.user_token_claims (tenant_id,user_id,primary_email_verified,primary_phone_verified,address,created_at_ms,updated_at_ms)
VALUES ('default','host-user',false,false,NULL,1000,1000);
WITH observed AS (SELECT extract(epoch FROM pg_catalog.clock_timestamp())::bigint AS now)
INSERT INTO aster_tenant.grants (tenant_id,grant_id,account_id,client_id,expires_at,permission_data)
SELECT 'default','phase1-host-grant','host-user','host-client',now+3600,
       '{"approved":{"scope":"openid offline_access profile","claims":[],"resources":{}},"rejected":null}'::jsonb FROM observed;
WITH observed AS (SELECT extract(epoch FROM pg_catalog.clock_timestamp())::bigint AS now)
INSERT INTO aster_tenant.authorization_codes (tenant_id,code_digest,grant_id,account_id,client_id,redirect_uri,issued_at,expires_at,pkce_challenge,code_context,consumed)
SELECT 'default',pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.repeat('h',43),'UTF8')),
       'phase1-host-grant','host-user','host-client','http://localhost/callback',now,now+300,
       pg_catalog.convert_to('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM','UTF8'),
       pg_catalog.jsonb_build_object('auth_time',now,'acr',NULL,'amr',NULL,'nonce',NULL,
         'scope','openid offline_access profile','resources',pg_catalog.jsonb_build_array(),
         'requested_claims',NULL,'sid',NULL,'session_uid',NULL,'expires_with_session',false),false FROM observed;
SELECT CASE WHEN (SELECT pg_catalog.count(*) FROM aster_tenant.authorization_codes WHERE tenant_id='default' AND grant_id='phase1-host-grant' AND NOT consumed)=1 THEN 'true' ELSE 'false' END;
COMMIT;
SQL
)" || fail
  [[ "$setup_state" == true ]] || fail
  fixture_created=true

  for host_id in "$connector_id" "$saml_id" "$script_id"; do
    $DOCKER_BIN stop --time 10 "$host_id" >/dev/null 2>&1 || fail
    [[ "$($DOCKER_BIN inspect --format '{{.State.Status}}' "$host_id" 2>/dev/null || true)" == exited ]] || fail
  done
  [[ "$($DOCKER_BIN inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$primary_core_id" 2>/dev/null || true)" == 'running|healthy' ]] || fail

  auth_response="$(printf 'GET /oidc/auth?client_id=host-client&redirect_uri=http%%3A%%2F%%2Flocalhost%%2Fcallback&response_type=code&prompt=login&scope=openid%%20offline_access%%20profile&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=host-state HTTP/1.1\r\nHost: localhost:3321\r\nConnection: close\r\n\r\n' | "$DOCKER_BIN" exec --interactive "$primary_core_id" nc -w 15 127.0.0.1 3001)" || fail
  [[ "$auth_response" == $'HTTP/1.1 302 '* || "$auth_response" == $'HTTP/1.1 303 '* ]] || fail
  [[ "$auth_response" == *$'\r\nlocation: /sign-in?app_id=host-client\r\n'* || \
     "$auth_response" == *$'\r\nLocation: /sign-in?app_id=host-client\r\n'* ]] || fail
  unset auth_response

  raw_code="$(printf 'h%.0s' {1..43})"
  request_body="grant_type=authorization_code&client_id=host-client&code=${raw_code}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback"
  request_bytes="$(printf '%s' "$request_body" | wc -c | tr -d '[:space:]')"
  token_response="$(printf 'POST /oidc/token HTTP/1.1\r\nHost: localhost:3321\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "$request_bytes" "$request_body" | "$DOCKER_BIN" exec --interactive "$primary_core_id" nc -w 15 127.0.0.1 3001)" || fail
  [[ "$token_response" == $'HTTP/1.1 200 OK\r\n'* && "$token_response" == *'"access_token"'* && "$token_response" == *'"id_token"'* && "$token_response" == *'"refresh_token"'* ]] || fail
  unset token_response raw_code request_body

  retry_state="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" 2>/dev/null <<'SQL'
-- phase1-host-retry-state
SELECT code.consumed::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.token_families AS family WHERE family.tenant_id=code.tenant_id AND family.grant_id=code.grant_id)::text || '|' ||
  (SELECT pg_catalog.count(*) FROM aster_tenant.refresh_tokens AS token JOIN aster_tenant.token_families AS family USING (tenant_id,family_id) WHERE family.tenant_id=code.tenant_id AND family.grant_id=code.grant_id)::text
FROM aster_tenant.authorization_codes AS code WHERE code.tenant_id='default' AND code.grant_id='phase1-host-grant';
SQL
)" || fail
  [[ "$retry_state" == 'true|1|1' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout='20s';
SET LOCAL search_path=pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion',1,'kind','phase1-candidate-invariant-terminal','invariantId','hosts.unavailable-pkce-independent',
  'projection',pg_catalog.jsonb_build_object(
    'protocol',pg_catalog.jsonb_build_object('pkce',pg_catalog.jsonb_build_object('available',true,'startStatus','continued','exchangeStatus','succeeded')),
    'hosts',pg_catalog.jsonb_build_array(
      pg_catalog.jsonb_build_object('kind','connector','availability','unavailable','errorClass','host-unavailable'),
      pg_catalog.jsonb_build_object('kind','saml','availability','rejected','errorClass','peer-identity-invalid'),
      pg_catalog.jsonb_build_object('kind','script','availability','rejected','errorClass','protocol-version-invalid')),
    'authority',pg_catalog.jsonb_build_object('identityAcceptedFromHost',false,'databaseAccess',false,'sensitiveAccess',false)))::text;
SQL
)" || fail
  cleanup_host_fixture || fail
  fixture_created=false
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ -n "$terminal" && "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'keystore.live-ledger-limit-and-tombstone' ]]; then
  deployment_id="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command 'SELECT deployment_id::text FROM aster_control.deployment_state WHERE singleton' \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$deployment_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || fail
  active_state="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "SELECT state.active_key_id || '|' || registry.writer_generation::text FROM aster_control.wrapping_key_runtime_state AS state JOIN aster_control.wrapping_key_registry AS registry ON registry.key_id = state.active_key_id WHERE state.singleton" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$active_state" =~ ^(aster-mk-[0-9a-f]{16,48})\|([1-9][0-9]*)$ ]] || fail
  active_key_id=${BASH_REMATCH[1]}
  active_generation=${BASH_REMATCH[2]}

  cleanup_live_ledger() {
    local result
    result="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
      psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --username postgres --dbname "$database" \
      --command "DELETE FROM aster_control.wrapping_key_registry WHERE key_id LIKE 'aster-mk-4%'; SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM aster_control.wrapping_key_registry WHERE key_id LIKE 'aster-mk-4%') THEN 'true' ELSE 'false' END" \
      2>/dev/null | tail -n 1 | tr -d '[:space:]')" || return 1
    [[ "$result" == true ]]
  }
  # Invoked indirectly by the EXIT trap.
  # shellcheck disable=SC2329
  cleanup_live_ledger_on_exit() {
    local exit_code=$?
    trap - EXIT
    if ! cleanup_live_ledger && ((exit_code == 0)); then
      printf '%s\n' 'Phase 1 candidate invariant execution failed.' >&2
      exit_code=1
    fi
    exit "$exit_code"
  }
  trap cleanup_live_ledger_on_exit EXIT

  setup_result="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "INSERT INTO aster_control.wrapping_key_registry (key_id, writer_generation, lifecycle_state, required_readable, reference_count) SELECT 'aster-mk-4' || pg_catalog.lpad(pg_catalog.to_hex(item), 15, '0'), item + 1, CASE WHEN item <= 2 THEN 'removable' ELSE 'staged' END, false, CASE WHEN item = 1 THEN 1 ELSE 0 END FROM pg_catalog.generate_series(1, 31) AS fixture(item) WHERE (SELECT pg_catalog.count(*) FROM aster_control.wrapping_key_registry) = 1; SELECT CASE WHEN (SELECT pg_catalog.count(*) FROM aster_control.wrapping_key_registry) = 32 AND (SELECT pg_catalog.count(*) FROM aster_control.wrapping_key_registry WHERE key_id LIKE 'aster-mk-4%') = 31 THEN 'true' ELSE 'false' END" \
    2>/dev/null | tail -n 1 | tr -d '[:space:]')" || fail
  [[ "$setup_result" == true ]] || fail

  row33_error=''
  row33_status=0
  row33_error="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --username aster_admin --dbname "$database" \
    --command "SELECT aster_runtime.stage_wrapping_key('$deployment_id', '$active_key_id', $active_generation, 'aster-mk-400000000000ff01', 33)" \
    2>&1 >/dev/null)" || row33_status=$?
  ((row33_status != 0)) || fail
  [[ "$row33_error" =~ ERROR:[[:space:]]+55000: ]] || fail

  referenced_error=''
  referenced_status=0
  referenced_error="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --username aster_admin --dbname "$database" \
    --command "DELETE FROM aster_control.wrapping_key_registry WHERE key_id = 'aster-mk-4000000000000001'" \
    2>&1 >/dev/null)" || referenced_status=$?
  ((referenced_status != 0)) || fail
  [[ "$referenced_error" =~ ERROR:[[:space:]]+42501: ]] || fail

  removed_rows="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "WITH removed AS (DELETE FROM aster_control.wrapping_key_registry WHERE key_id = 'aster-mk-4000000000000002' AND lifecycle_state = 'removable' AND reference_count = 0 RETURNING 1) SELECT pg_catalog.count(*)::text FROM removed" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$removed_rows" == 1 ]] || fail

  "$DOCKER_BIN" exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username aster_admin --dbname "$database" \
    --command "SELECT aster_runtime.stage_wrapping_key('$deployment_id', '$active_key_id', $active_generation, 'aster-mk-400000000000ff02', 33)" \
    >/dev/null 2>&1 || fail

  reuse_error=''
  reuse_status=0
  reuse_error="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --username aster_admin --dbname "$database" \
    --command "SELECT aster_runtime.stage_wrapping_key('$deployment_id', '$active_key_id', $active_generation, 'aster-mk-4000000000000002', 34)" \
    2>&1 >/dev/null)" || reuse_status=$?
  ((reuse_status != 0)) || fail
  [[ "$reuse_error" =~ ERROR:[[:space:]]+55000: ]] || fail

  ledger_state="$($DOCKER_BIN exec --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --username postgres --dbname "$database" \
    --command "WITH fixture_history AS (SELECT history.key_id FROM aster_control.wrapping_key_history AS history WHERE history.key_id LIKE 'aster-mk-4%'), tombstones AS (SELECT history.key_id FROM fixture_history AS history WHERE NOT EXISTS (SELECT 1 FROM aster_control.wrapping_key_registry AS registry WHERE registry.key_id = history.key_id)) SELECT CASE WHEN (SELECT pg_catalog.count(*) FROM aster_control.wrapping_key_registry) = 32 AND (SELECT pg_catalog.count(*) FROM tombstones) = 1 AND (SELECT pg_catalog.min(key_id) FROM tombstones) = 'aster-mk-4000000000000002' AND EXISTS (SELECT 1 FROM aster_control.wrapping_key_registry WHERE key_id = 'aster-mk-400000000000ff02' AND writer_generation = 33) AND EXISTS (SELECT 1 FROM aster_control.wrapping_key_registry WHERE key_id = 'aster-mk-4000000000000001' AND reference_count = 1) AND NOT EXISTS (SELECT 1 FROM aster_control.wrapping_key_registry WHERE key_id = 'aster-mk-400000000000ff01') THEN 'true' ELSE 'false' END AS tombstone_count" \
    2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$ledger_state" == true ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.live-ledger-limit-and-tombstone',
  'projection', pg_catalog.jsonb_build_object(
    'liveLedger', pg_catalog.jsonb_build_object(
      'alertAt', 28,
      'liveCount', 32,
      'liveIds', pg_catalog.jsonb_build_array(
        '<wrapping-key.01>', '<wrapping-key.02>', '<wrapping-key.03>', '<wrapping-key.04>',
        '<wrapping-key.05>', '<wrapping-key.06>', '<wrapping-key.07>', '<wrapping-key.08>',
        '<wrapping-key.09>', '<wrapping-key.10>', '<wrapping-key.11>', '<wrapping-key.12>',
        '<wrapping-key.13>', '<wrapping-key.14>', '<wrapping-key.15>', '<wrapping-key.16>',
        '<wrapping-key.17>', '<wrapping-key.18>', '<wrapping-key.19>', '<wrapping-key.20>',
        '<wrapping-key.21>', '<wrapping-key.22>', '<wrapping-key.23>', '<wrapping-key.24>',
        '<wrapping-key.25>', '<wrapping-key.26>', '<wrapping-key.27>', '<wrapping-key.28>',
        '<wrapping-key.29>', '<wrapping-key.30>', '<wrapping-key.31>', '<wrapping-key.32>'
      ),
      'limit', 32,
      'row33Denied', true,
      'referencedRemovalDenied', true,
      'removableZeroCountTombstoned', true,
      'tombstoneCount', 1,
      'tombstoneIds', pg_catalog.jsonb_build_array('<wrapping-key.old>'),
      'tombstonesConsumeLiveCapacity', false,
      'reusedTombstoneId', NULL
    )
  )
)::text;
SQL
)" || fail
  [[ -n "$terminal" ]] || fail
  cleanup_live_ledger || fail
  trap - EXIT
  byte_count="$(printf '%s' "$terminal" | wc -c | tr -d '[:space:]')"
  [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -le 65536 ]] || fail
  printf '%s' "$terminal"
  exit 0
fi

if [[ "$invariant_id" == 'keystore.wrapping-fence-late-commit' ]]; then
  wrapping_fence_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
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
SELECT active_key_id AS root_key_id
FROM aster_control.wrapping_key_runtime_state
WHERE singleton \gset
UPDATE aster_control.wrapping_key_registry
SET lifecycle_state = 'retained', required_readable = true
WHERE key_id = :'root_key_id';
INSERT INTO aster_control.wrapping_key_registry (
  key_id, writer_generation, lifecycle_state, required_readable, reference_count
) VALUES
  ('aster-mk-5000000000000001', 1, 'retained', true, 0),
  ('aster-mk-5000000000000002', 2, 'active', true, 0);
UPDATE aster_control.wrapping_key_runtime_state
SET active_key_id = 'aster-mk-5000000000000002',
    minimum_keyring_generation = 2,
    write_fenced = false
WHERE singleton;

INSERT INTO aster_control.tenants (
  tenant_id, status, status_epoch, provisioning_verified
) VALUES ('phase1-fence-tenant-a', 'inactive', 1, false);
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('d1', 32), 'hex')),
       'phase1-fence-tenant-a', 1, :'deployment_id'::uuid, 'admin', 'provision',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

-- phase1-wrapping-fence-late-probe
SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('d1', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  '55555555555555555555555555555551',
  '66666666666666666666666666666661', 1, '{}',
  pg_catalog.decode(pg_catalog.repeat('71', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('72', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('73', 24), 'hex'),
  'aster-mk-5000000000000002', 2
) \g /dev/null
RESET SESSION AUTHORIZATION;
UPDATE aster_control.wrapping_key_runtime_state
SET write_fenced = true
WHERE singleton;
SET SESSION AUTHORIZATION aster_admin;
SAVEPOINT late_old_key_write;
\set ON_ERROR_STOP off
SELECT aster_runtime.provision_cookie_key(
  '77777777777777777777777777777771',
  '88888888888888888888888888888881', 1,
  pg_catalog.decode(pg_catalog.repeat('74', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('75', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('76', 24), 'hex'),
  'aster-mk-5000000000000001', 1
) \g /dev/null
\set late_state :SQLSTATE
ROLLBACK TO SAVEPOINT late_old_key_write;
\set ON_ERROR_STOP on
RESET SESSION AUTHORIZATION;

SELECT CASE WHEN runtime.active_key_id = 'aster-mk-5000000000000002'
  AND runtime.minimum_keyring_generation = 2
  AND runtime.write_fenced
  AND old_key.reference_count = 0
  AND new_key.reference_count = 1
  AND (SELECT pg_catalog.count(*) FROM aster_tenant.signing_key_material
    WHERE tenant_id = 'phase1-fence-tenant-a'
      AND wrapping_key_id = 'aster-mk-5000000000000002') = 1
  AND (SELECT pg_catalog.count(*) FROM aster_tenant.cookie_key_material
    WHERE tenant_id = 'phase1-fence-tenant-a'
      AND wrapping_key_id = 'aster-mk-5000000000000001') = 0
THEN 'true' ELSE 'false' END AS state_ok
FROM aster_control.wrapping_key_runtime_state AS runtime
JOIN aster_control.wrapping_key_registry AS old_key
  ON old_key.key_id = 'aster-mk-5000000000000001'
JOIN aster_control.wrapping_key_registry AS new_key
  ON new_key.key_id = 'aster-mk-5000000000000002'
WHERE runtime.singleton \gset

\echo :late_state|:state_ok
ROLLBACK;
SQL
)" || fail
  [[ "$wrapping_fence_observation" == '55000|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.wrapping-fence-late-commit',
  'projection', pg_catalog.jsonb_build_object(
    'fence', pg_catalog.jsonb_build_object('generation', 2, 'status', 'completed'),
    'lateCommit', pg_catalog.jsonb_build_object(
      'accepted', false, 'errorClass', 'wrapping-fence'
    ),
    'semanticState', pg_catalog.jsonb_build_object(
      'ledger', pg_catalog.jsonb_build_object('oldKeyReferences', 0),
      'material', pg_catalog.jsonb_build_object(
        'oldKeyReferences', 0, 'newKeyReferences', 1
      )
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

if [[ "$invariant_id" == 'keystore.sign-seal-during-rewrap' ]]; then
  sign_seal_observation="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
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
SELECT active_key_id AS root_key_id
FROM aster_control.wrapping_key_runtime_state
WHERE singleton \gset
UPDATE aster_control.wrapping_key_registry
SET lifecycle_state = 'retained', required_readable = true
WHERE key_id = :'root_key_id';
INSERT INTO aster_control.wrapping_key_registry (
  key_id, writer_generation, lifecycle_state, required_readable, reference_count
) VALUES ('aster-mk-6000000000000001', 1, 'active', true, 0);
UPDATE aster_control.wrapping_key_runtime_state
SET active_key_id = 'aster-mk-6000000000000001',
    minimum_keyring_generation = 1,
    write_fenced = false
WHERE singleton;

INSERT INTO aster_control.tenants (
  tenant_id, status, status_epoch, provisioning_verified
) VALUES ('phase1-sign-seal-tenant', 'inactive', 1, false);
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('e1', 32), 'hex')),
       'phase1-sign-seal-tenant', 1, :'deployment_id'::uuid, 'admin', 'provision',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;

-- phase1-sign-seal-rewrap-probe
SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('e1', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.provision_signing_key(
  '99999999999999999999999999999991',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9', 1, '{}',
  pg_catalog.decode(pg_catalog.repeat('81', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('82', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('83', 24), 'hex'),
  'aster-mk-6000000000000001', 1
) \g /dev/null
SELECT aster_runtime.provision_cookie_key(
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9',
  'ccccccccccccccccccccccccccccccc9', 1,
  pg_catalog.decode(pg_catalog.repeat('84', 32), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('85', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('86', 24), 'hex'),
  'aster-mk-6000000000000001', 1
) \g /dev/null
SELECT aster_runtime.complete_bound_tenant_key_provisioning(
  '99999999999999999999999999999991',
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9'
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-sign-seal-tenant';
UPDATE aster_control.tenants
SET status = 'active', status_epoch = 2
WHERE tenant_id = 'phase1-sign-seal-tenant';

INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('e2', 32), 'hex')),
       'phase1-sign-seal-tenant', 2, :'deployment_id'::uuid, 'request', NULL,
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;
SET SESSION AUTHORIZATION aster_request;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('e2', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.record_signing_use(
  '99999999999999999999999999999991', 1
) \g /dev/null
SELECT aster_runtime.record_cookie_seal(
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9', 1
) \g /dev/null
SELECT pg_catalog.count(*) AS signing_before
FROM aster_runtime.read_active_signing_key_material() \gset
SELECT pg_catalog.count(*) AS cookie_before
FROM aster_runtime.read_cookie_key_material(false) \gset
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-sign-seal-tenant';

UPDATE aster_control.wrapping_key_registry
SET lifecycle_state = 'retained', required_readable = true
WHERE key_id = 'aster-mk-6000000000000001';
INSERT INTO aster_control.wrapping_key_registry (
  key_id, writer_generation, lifecycle_state, required_readable, reference_count
) VALUES ('aster-mk-6000000000000002', 2, 'active', true, 0);
UPDATE aster_control.wrapping_key_runtime_state
SET active_key_id = 'aster-mk-6000000000000002',
    minimum_keyring_generation = 2,
    write_fenced = false
WHERE singleton;
INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('e3', 32), 'hex')),
       'phase1-sign-seal-tenant', 2, :'deployment_id'::uuid, 'admin', 'rewrap',
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;
SET SESSION AUTHORIZATION aster_admin;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('e3', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.rewrap_signing_key_material(
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9',
  pg_catalog.decode(pg_catalog.repeat('82', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('83', 24), 'hex'),
  'aster-mk-6000000000000001', 1,
  pg_catalog.decode(pg_catalog.repeat('87', 64), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('88', 24), 'hex'),
  'aster-mk-6000000000000002', 2
) \g /dev/null
SELECT aster_runtime.rewrap_cookie_key_material(
  'ccccccccccccccccccccccccccccccc9',
  pg_catalog.decode(pg_catalog.repeat('85', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('86', 24), 'hex'),
  'aster-mk-6000000000000001', 1,
  pg_catalog.decode(pg_catalog.repeat('89', 48), 'hex'),
  pg_catalog.decode(pg_catalog.repeat('8a', 24), 'hex'),
  'aster-mk-6000000000000002', 2
) \g /dev/null
RESET SESSION AUTHORIZATION;
RESET aster.binding_digest;
DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-sign-seal-tenant';

INSERT INTO aster_control.tenant_bindings (
  capability_digest, tenant_id, status_epoch, deployment_id, audience,
  admin_operation, issued_at, expires_at, cleanup_at
)
SELECT pg_catalog.sha256(pg_catalog.decode(pg_catalog.repeat('e4', 32), 'hex')),
       'phase1-sign-seal-tenant', 2, :'deployment_id'::uuid, 'request', NULL,
       observed_at, observed_at + interval '30 seconds', observed_at + interval '30 seconds'
FROM LATERAL (SELECT pg_catalog.clock_timestamp() AS observed_at) AS observed;
SET SESSION AUTHORIZATION aster_request;
SELECT * FROM aster_runtime.activate_tenant_binding(
  pg_catalog.decode(pg_catalog.repeat('e4', 32), 'hex')
) \g /dev/null
SELECT aster_runtime.record_signing_use(
  '99999999999999999999999999999991', 1
) \g /dev/null
SELECT aster_runtime.record_cookie_seal(
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9', 1
) \g /dev/null
SELECT pg_catalog.count(*) AS signing_after
FROM aster_runtime.read_active_signing_key_material() \gset
SELECT pg_catalog.count(*) AS cookie_after
FROM aster_runtime.read_cookie_key_material(false) \gset
RESET SESSION AUTHORIZATION;

SELECT CASE WHEN old_key.reference_count = 0
  AND new_key.reference_count = 2
  AND signing.lifecycle_state = 'active'
  AND signing.generation = 1
  AND signing.public_metadata_fingerprint = pg_catalog.decode(pg_catalog.repeat('81', 32), 'hex')
  AND signing.last_signed_at IS NOT NULL
  AND cookie.lifecycle_state = 'active'
  AND cookie.generation = 1
  AND cookie.public_metadata_fingerprint = pg_catalog.decode(pg_catalog.repeat('84', 32), 'hex')
  AND cookie.last_sealed_at IS NOT NULL
  AND signing_material.ciphertext = pg_catalog.decode(pg_catalog.repeat('87', 64), 'hex')
  AND signing_material.wrapping_key_id = 'aster-mk-6000000000000002'
  AND signing_material.writer_generation = 2
  AND cookie_material.ciphertext = pg_catalog.decode(pg_catalog.repeat('89', 48), 'hex')
  AND cookie_material.wrapping_key_id = 'aster-mk-6000000000000002'
  AND cookie_material.writer_generation = 2
THEN 'true' ELSE 'false' END AS state_ok
FROM aster_control.wrapping_key_registry AS old_key
JOIN aster_control.wrapping_key_registry AS new_key ON true
JOIN aster_tenant.signing_key_metadata AS signing ON true
JOIN aster_tenant.cookie_key_metadata AS cookie
  ON cookie.tenant_id = signing.tenant_id
JOIN aster_tenant.signing_key_material AS signing_material
  ON signing_material.tenant_id = signing.tenant_id
 AND signing_material.material_id = signing.material_id
JOIN aster_tenant.cookie_key_material AS cookie_material
  ON cookie_material.tenant_id = cookie.tenant_id
 AND cookie_material.material_id = cookie.material_id
WHERE old_key.key_id = 'aster-mk-6000000000000001'
  AND new_key.key_id = 'aster-mk-6000000000000002'
  AND signing.tenant_id = 'phase1-sign-seal-tenant' \gset

\echo :signing_before|:cookie_before|:signing_after|:cookie_after|:state_ok
ROLLBACK;
SQL
)" || fail
  [[ "$sign_seal_observation" == '1|1|1|1|true' ]] || fail

  terminal="$($DOCKER_BIN exec --interactive --user postgres "$primary_container_id" \
    psql --no-psqlrc --quiet --tuples-only --no-align --single-transaction \
    --set=ON_ERROR_STOP=1 --username postgres --dbname "$database" <<'SQL'
SET TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '20s';
SET LOCAL search_path = pg_catalog;
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'keystore.sign-seal-during-rewrap',
  'projection', pg_catalog.jsonb_build_object(
    'availability', pg_catalog.jsonb_build_object(
      'tokenSigning', true,
      'cookieSealing', true,
      'cookieVerification', true
    ),
    'semanticState', pg_catalog.jsonb_build_object(
      'changedColumns', pg_catalog.jsonb_build_array(
        'envelopeMaterial', 'referenceLedger', 'lastSignedAt', 'lastSealedAt'
      ),
      'forbiddenColumnDeltas', pg_catalog.jsonb_build_array()
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
