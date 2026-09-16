\set ON_ERROR_STOP on

BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '5s';
SET LOCAL idle_in_transaction_session_timeout = '20s';
SET LOCAL search_path = pg_catalog;

DELETE FROM aster_tenant.rls_sentinel
WHERE (
    tenant_id IN ('phase1-invariant-cross-a', 'phase1-invariant-cross-b')
    AND :'action' IN ('setup-cross-tenant', 'cleanup-cross-tenant')
  ) OR (
    tenant_id IN (
      'phase1-invariant-admin-a',
      'phase1-invariant-admin-b',
      'phase1-invariant-admin-b-forbidden'
    )
    AND :'action' IN ('setup-admin-binding', 'cleanup-admin-binding')
  );

DELETE FROM aster_control.tenant_bindings
WHERE (
    tenant_id = 'phase1-invariant-suspended-epoch'
    AND :'action' IN ('setup-suspended-epoch', 'cleanup-suspended-epoch')
  ) OR (
    tenant_id IN ('phase1-invariant-cross-a', 'phase1-invariant-cross-b')
    AND :'action' IN ('setup-cross-tenant', 'cleanup-cross-tenant')
  ) OR (
    tenant_id IN (
      'phase1-invariant-admin-a',
      'phase1-invariant-admin-b',
      'phase1-invariant-admin-b-forbidden'
    )
    AND :'action' IN ('setup-admin-binding', 'cleanup-admin-binding')
  );

DELETE FROM aster_control.tenants
WHERE (
    tenant_id = 'phase1-invariant-suspended-epoch'
    AND :'action' IN ('setup-suspended-epoch', 'cleanup-suspended-epoch')
  ) OR (
    tenant_id IN ('phase1-invariant-cross-a', 'phase1-invariant-cross-b')
    AND :'action' IN ('setup-cross-tenant', 'cleanup-cross-tenant')
  ) OR (
    tenant_id IN (
      'phase1-invariant-admin-a',
      'phase1-invariant-admin-b',
      'phase1-invariant-admin-b-forbidden'
    )
    AND :'action' IN ('setup-admin-binding', 'cleanup-admin-binding')
  );

INSERT INTO aster_control.tenants (
  tenant_id,
  status,
  status_epoch,
  provisioning_verified
)
SELECT 'phase1-invariant-suspended-epoch', 'active', 7, true
WHERE :'action' = 'setup-suspended-epoch';

INSERT INTO aster_control.tenants (
  tenant_id,
  status,
  status_epoch,
  provisioning_verified
)
SELECT fixture.tenant_id, 'active', 1, true
FROM (
  VALUES
    ('phase1-invariant-cross-a'::text),
    ('phase1-invariant-cross-b'::text)
) AS fixture(tenant_id)
WHERE :'action' = 'setup-cross-tenant';

INSERT INTO aster_control.tenants (
  tenant_id,
  status,
  status_epoch,
  provisioning_verified
)
SELECT fixture.tenant_id, 'inactive', 1, false
FROM (
  VALUES
    ('phase1-invariant-admin-a'::text),
    ('phase1-invariant-admin-b'::text)
) AS fixture(tenant_id)
WHERE :'action' = 'setup-admin-binding';

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

SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'tenant.cross-tenant-read-rejected',
  'projection', pg_catalog.jsonb_build_object(
    'outcome', pg_catalog.jsonb_build_object(
      'boundTenant', 'tenant-a',
      'visibleSentinels', pg_catalog.jsonb_build_array('sentinel-a'),
      'crossTenantRows', pg_catalog.jsonb_build_array()
    ),
    'mutations', pg_catalog.jsonb_build_object('tenantA', 0, 'tenantB', 0)
  )
)::text
FROM aster_control.tenants AS tenant_a
JOIN aster_control.tenants AS tenant_b
  ON tenant_b.tenant_id = 'phase1-invariant-cross-b'
WHERE :'action' = 'project-cross-tenant'
  AND tenant_a.tenant_id = 'phase1-invariant-cross-a'
  AND tenant_a.status = 'active'
  AND tenant_a.status_epoch = 1
  AND tenant_b.status = 'active'
  AND tenant_b.status_epoch = 1
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_tenant.rls_sentinel AS sentinel
    WHERE sentinel.tenant_id IN ('phase1-invariant-cross-a', 'phase1-invariant-cross-b')
  ) = 2
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_tenant.rls_sentinel AS sentinel
    WHERE sentinel.tenant_id = 'phase1-invariant-cross-a'
      AND sentinel.item_id = '00000000-0000-4000-8000-0000000000a1'
      AND sentinel.parent_item_id IS NULL
      AND sentinel.test_value = 'sentinel-a'
  ) = 1
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_tenant.rls_sentinel AS sentinel
    WHERE sentinel.tenant_id = 'phase1-invariant-cross-b'
      AND sentinel.item_id = '00000000-0000-4000-8000-0000000000b1'
      AND sentinel.parent_item_id IS NULL
      AND sentinel.test_value = 'sentinel-b'
  ) = 1
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_control.tenant_bindings AS binding
    WHERE binding.tenant_id = 'phase1-invariant-cross-a'
      AND binding.status_epoch = 1
      AND binding.audience = 'request'
      AND binding.admin_operation IS NULL
      AND binding.issued_at <= pg_catalog.clock_timestamp()
      AND binding.expires_at > pg_catalog.clock_timestamp()
      AND binding.activated_at IS NULL
      AND binding.activated_backend_pid IS NULL
      AND binding.activated_xid IS NULL
  ) = 1;

SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', 1,
  'kind', 'phase1-candidate-invariant-terminal',
  'invariantId', 'tenant.admin-operation-binding',
  'projection', pg_catalog.jsonb_build_object(
    'capability', pg_catalog.jsonb_build_object(
      'tenantId', 'tenant-a',
      'operationClass', 'provision'
    ),
    'mutations', pg_catalog.jsonb_build_array(
      pg_catalog.jsonb_build_object('tenantId', 'tenant-a', 'operationClass', 'provision'),
      pg_catalog.jsonb_build_object('tenantId', NULL, 'operationClass', 'provision')
    ),
    'denials', pg_catalog.jsonb_build_array(
      pg_catalog.jsonb_build_object('reasonClass', 'tenant-mismatch'),
      pg_catalog.jsonb_build_object('reasonClass', 'operation-class-mismatch')
    )
  )
)::text
FROM aster_control.tenants AS tenant_a
JOIN aster_control.tenants AS tenant_b
  ON tenant_b.tenant_id = 'phase1-invariant-admin-b'
WHERE :'action' = 'project-admin-binding'
  AND tenant_a.tenant_id = 'phase1-invariant-admin-a'
  AND tenant_a.status = 'inactive'
  AND tenant_a.status_epoch = 1
  AND tenant_b.status = 'inactive'
  AND tenant_b.status_epoch = 1
  AND NOT EXISTS (
    SELECT 1
    FROM aster_control.tenants AS forbidden
    WHERE forbidden.tenant_id = 'phase1-invariant-admin-b-forbidden'
  )
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_tenant.rls_sentinel AS sentinel
    WHERE sentinel.tenant_id IN (
      'phase1-invariant-admin-a',
      'phase1-invariant-admin-b',
      'phase1-invariant-admin-b-forbidden'
    )
  ) = 1
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_tenant.rls_sentinel AS sentinel
    WHERE sentinel.tenant_id = 'phase1-invariant-admin-a'
      AND sentinel.parent_item_id IS NULL
      AND sentinel.test_value = 'admin-binding-provision'
  ) = 1
  AND (
    SELECT pg_catalog.count(*)
    FROM aster_control.tenant_bindings AS binding
    WHERE binding.tenant_id = 'phase1-invariant-admin-a'
      AND binding.status_epoch = 1
      AND binding.audience = 'admin'
      AND binding.admin_operation = 'provision'
      AND binding.issued_at <= pg_catalog.clock_timestamp()
      AND binding.expires_at > pg_catalog.clock_timestamp()
      AND binding.activated_at IS NOT NULL
      AND binding.activated_backend_pid IS NOT NULL
      AND binding.activated_xid IS NOT NULL
  ) = 1;

COMMIT;
