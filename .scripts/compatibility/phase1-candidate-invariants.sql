\set ON_ERROR_STOP on

BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '5s';
SET LOCAL idle_in_transaction_session_timeout = '20s';
SET LOCAL search_path = pg_catalog;

DELETE FROM aster_control.tenant_bindings
WHERE tenant_id = 'phase1-invariant-suspended-epoch'
  AND :'action' IN ('setup-suspended-epoch', 'cleanup-suspended-epoch');

DELETE FROM aster_control.tenants
WHERE tenant_id = 'phase1-invariant-suspended-epoch'
  AND :'action' IN ('setup-suspended-epoch', 'cleanup-suspended-epoch');

INSERT INTO aster_control.tenants (
  tenant_id,
  status,
  status_epoch,
  provisioning_verified
)
SELECT 'phase1-invariant-suspended-epoch', 'active', 7, true
WHERE :'action' = 'setup-suspended-epoch';

SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'tenant.suspended-epoch-rejected',
  'projection', pg_catalog.jsonb_build_object(
    'activation', pg_catalog.jsonb_build_object(
      'mintedEpoch', request_binding.status_epoch,
      'currentEpoch', tenant.status_epoch,
      'accepted', false,
      'errorClass', 'stale-epoch'
    ),
    'repositoriesCreated', false,
    'mutations', pg_catalog.jsonb_build_object('binding', 0, 'business', 0)
  )
)::text
FROM aster_control.tenants AS tenant
JOIN aster_control.tenant_bindings AS request_binding
  ON request_binding.tenant_id = tenant.tenant_id
 AND request_binding.audience = 'request'
 AND request_binding.admin_operation IS NULL
WHERE :'action' = 'project-suspended-epoch'
  AND tenant.tenant_id = 'phase1-invariant-suspended-epoch'
  AND tenant.status = 'suspended'
  AND tenant.status_epoch = 8
  AND request_binding.status_epoch = 7
  AND request_binding.issued_at <= pg_catalog.clock_timestamp()
  AND request_binding.expires_at > pg_catalog.clock_timestamp()
  AND request_binding.activated_at IS NULL
  AND request_binding.activated_backend_pid IS NULL
  AND request_binding.activated_xid IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM aster_tenant.rls_sentinel AS sentinel
    WHERE sentinel.tenant_id = tenant.tenant_id
  );

COMMIT;
