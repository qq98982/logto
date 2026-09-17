/* eslint-disable max-lines -- One shared fake Docker process keeps the shell driver's closed protocol and cleanup behavior testable across all live invariant IDs. */
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import { candidateInvariantContracts } from './index.js';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const driver = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase1-candidate-invariants-driver.sh'
);
const roots = new Set<string>();
const projectName = 'aster-phase1-0123456789abcdef';
const primaryContainerId = '1'.repeat(64);
const foreignContainerId = '2'.repeat(64);
const ownerRoleInvariantId = 'database.owner-role-membership-boundary';
const suspendedEpochInvariantId = 'tenant.suspended-epoch-rejected';
const crossTenantInvariantId = 'tenant.cross-tenant-read-rejected';
const adminBindingInvariantId = 'tenant.admin-operation-binding';
const adminMatrixInvariantId = 'tenant.admin-operation-status-matrix';
const reaperActivityInvariantId = 'reaper.activity-visibility-redaction';
const reaperAuditInvariantId = 'reaper.object-audit-disabled';
const requiredReadableInvariantId = 'keystore.required-readable-key-set';
const staleKeyringInvariantId = 'keystore.stale-keyring-rejoin-rejected';
const forcedRlsInvariantId = 'keystore.forced-rls-owner-boundary';
const metadataDmlInvariantId = 'keystore.metadata-dml-boundary';
const referenceLedgerInvariantId = 'keystore.reference-count-ledger';
const liveLedgerInvariantId = 'keystore.live-ledger-limit-and-tombstone';
const wrappingFenceInvariantId = 'keystore.wrapping-fence-late-commit';
const projection = (invariantId: string) =>
  candidateInvariantContracts.find(({ id }) => id === invariantId)?.positiveControl
    .expectedProjection;
const ownerRoleProjection = projection(ownerRoleInvariantId);
const suspendedEpochProjection = projection(suspendedEpochInvariantId);
const crossTenantProjection = projection(crossTenantInvariantId);
const adminBindingProjection = projection(adminBindingInvariantId);
const adminMatrixProjection = projection(adminMatrixInvariantId);
const reaperActivityProjection = projection(reaperActivityInvariantId);
const reaperAuditProjection = projection(reaperAuditInvariantId);
const requiredReadableProjection = projection(requiredReadableInvariantId);
const staleKeyringProjection = projection(staleKeyringInvariantId);
const forcedRlsProjection = projection(forcedRlsInvariantId);
const metadataDmlProjection = projection(metadataDmlInvariantId);
const referenceLedgerProjection = projection(referenceLedgerInvariantId);
const liveLedgerProjection = projection(liveLedgerInvariantId);
const wrappingFenceProjection = projection(wrappingFenceInvariantId);

if (
  !ownerRoleProjection ||
  !suspendedEpochProjection ||
  !crossTenantProjection ||
  !adminBindingProjection ||
  !adminMatrixProjection ||
  !reaperActivityProjection ||
  !reaperAuditProjection ||
  !requiredReadableProjection ||
  !staleKeyringProjection ||
  !forcedRlsProjection ||
  !metadataDmlProjection ||
  !referenceLedgerProjection ||
  !liveLedgerProjection ||
  !wrappingFenceProjection
) {
  throw new Error('missing candidate invariant projection');
}

const output = (invariantId: string, expectedProjection: unknown) =>
  JSON.stringify({
    schemaVersion: 1,
    kind: 'phase1-candidate-invariant-terminal',
    invariantId,
    projection: expectedProjection,
  });
const ownerRoleOutput = output(ownerRoleInvariantId, ownerRoleProjection);
const suspendedEpochOutput = output(suspendedEpochInvariantId, suspendedEpochProjection);
const crossTenantOutput = output(crossTenantInvariantId, crossTenantProjection);
const adminBindingOutput = output(adminBindingInvariantId, adminBindingProjection);
const adminMatrixOutput = output(adminMatrixInvariantId, adminMatrixProjection);
const reaperActivityOutput = output(reaperActivityInvariantId, reaperActivityProjection);
const reaperAuditOutput = output(reaperAuditInvariantId, reaperAuditProjection);
const requiredReadableOutput = output(requiredReadableInvariantId, requiredReadableProjection);
const staleKeyringOutput = output(staleKeyringInvariantId, staleKeyringProjection);
const forcedRlsOutput = output(forcedRlsInvariantId, forcedRlsProjection);
const metadataDmlOutput = output(metadataDmlInvariantId, metadataDmlProjection);
const referenceLedgerOutput = output(referenceLedgerInvariantId, referenceLedgerProjection);
const liveLedgerOutput = output(liveLedgerInvariantId, liveLedgerProjection);
const wrappingFenceOutput = output(wrappingFenceInvariantId, wrappingFenceProjection);

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const fakeDocker = async (
  primaryService = 'candidate-primary-postgres',
  foreignService = 'candidate-foreign-postgres',
  project = projectName
) => {
  const root = await mkdtemp('/var/tmp/henry-build/candidate-invariant-driver-');
  roots.add(root);
  const binary = path.join(root, 'docker');
  const calls = path.join(root, 'calls');
  const stdin = path.join(root, 'stdin.sql');
  await writeFile(
    binary,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$CALLS"
if [[ "$1" == ps ]]; then
  if [[ "$*" == *'com.docker.compose.service=candidate-primary-core'* ]]; then printf '%s' "$CORE_ID"; fi
  exit 0
fi
if [[ "$1" == inspect ]]; then
  if [[ "${'$'}{*: -1}" == "$PRIMARY_ID" ]]; then printf '%s|%s' "$PRIMARY_SERVICE" "$PROJECT"; exit 0; fi
  if [[ "${'$'}{*: -1}" == "$FOREIGN_ID" ]]; then printf '%s|%s' "$FOREIGN_SERVICE" "$PROJECT"; exit 0; fi
  if [[ "${'$'}{*: -1}" == "$CORE_ID" ]]; then
    if [[ "$*" == *'.State.Status'* ]]; then printf '%s' 'running|healthy'; else printf '%s|%s' 'candidate-primary-core' "$PROJECT"; fi
    exit 0
  fi
  exit 1
fi
if [[ "$1" == logs ]]; then
  if [[ "${'$'}{AUDIT_LOG_SENTINEL:-0}" == 1 ]]; then printf '%s' 'phase1-audit-request-sentinel'; else printf '%s' 'closed-log-artifact'; fi
  exit 0
fi
if [[ "$1" == exec ]]; then
  if [[ "$*" == *'PGAPPNAME=phase1-invariant-audit-'* ]]; then
    cat >>"$STDIN"
    sleep "${'$'}{AUDIT_CLIENT_SLEEP:-1}"
    exit 0
  fi
  if [[ "$*" == *'PGAPPNAME=phase1-invariant-reaper-'* ]]; then
    cat >>"$STDIN"
    sleep "${'$'}{REAPER_CLIENT_SLEEP:-1}"
    exit 0
  fi
  if [[ "$*" == *'SET ROLE aster_owner'* ]]; then
    if [[ "$*" == *'--username aster_migrator'* ]]; then exit 0; fi
    exit 1
  fi
  if [[ "$*" == *'--set=action=setup-suspended-epoch'* ]]; then cat >>"$STDIN"; exit 0; fi
  if [[ "$*" == *'--set=action=cleanup-suspended-epoch'* ]]; then cat >>"$STDIN"; exit "${'$'}{CLEANUP_STATUS:-0}"; fi
  if [[ "$*" == *'--set=action=project-suspended-epoch'* ]]; then
    cat >>"$STDIN"
    printf '%s' "$SUSPENDED_OUTPUT"
    exit 0
  fi
  if [[ "$*" == *'--set=action=setup-cross-tenant'* ]]; then cat >>"$STDIN"; exit 0; fi
  if [[ "$*" == *'--set=action=cleanup-cross-tenant'* ]]; then cat >>"$STDIN"; exit "${'$'}{CLEANUP_STATUS:-0}"; fi
  if [[ "$*" == *'--set=action=project-cross-tenant'* ]]; then
    cat >>"$STDIN"
    printf '%s' "$CROSS_TENANT_OUTPUT"
    exit 0
  fi
  if [[ "$*" == *'--set=action=setup-admin-binding'* ]]; then cat >>"$STDIN"; exit 0; fi
  if [[ "$*" == *'--set=action=cleanup-admin-binding'* ]]; then cat >>"$STDIN"; exit "${'$'}{CLEANUP_STATUS:-0}"; fi
  if [[ "$*" == *'--set=action=project-admin-binding'* ]]; then
    cat >>"$STDIN"
    printf '%s' "$ADMIN_BINDING_OUTPUT"
    exit 0
  fi
  if [[ "$*" == *'--set=action=setup-admin-matrix'* ]]; then cat >>"$STDIN"; exit 0; fi
  if [[ "$*" == *'--set=action=advance-admin-matrix-epochs'* ]]; then cat >>"$STDIN"; exit 0; fi
  if [[ "$*" == *'--set=action=cleanup-admin-matrix'* ]]; then cat >>"$STDIN"; exit "${'$'}{CLEANUP_STATUS:-0}"; fi
  if [[ "$*" == *'--set=action=project-admin-matrix'* ]]; then
    cat >>"$STDIN"
    printf '%s' "$ADMIN_MATRIX_OUTPUT"
    exit 0
  fi
  if [[ "$*" == *'SELECT deployment_id::text FROM aster_control.deployment_state'* ]]; then
    printf '%s' '01234567-89ab-cdef-0123-456789abcdef'
    exit 0
  fi
  if [[ "$*" == *'wrapping_key_runtime_state'* && "$*" == *'writer_generation'* && "$*" == *'active_key_id'* ]]; then
    printf '%s' 'aster-mk-9999999999999999|1'
    exit 0
  fi
  if [[ "$*" == *'generate_series(1, 31)'* ]]; then printf '%s' 'true'; exit 0; fi
  if [[ "$*" == *"key_id LIKE 'aster-mk-4%'"* ]]; then printf '%s' 'true'; exit 0; fi
  if [[ "$*" == *'aster-mk-4000000000000002'* && "$*" == *'--username postgres'* && "$*" == *'DELETE FROM'* ]]; then printf '%s' '1'; exit 0; fi
  if [[ "$*" == *'tombstone_count'* && "$*" == *'aster-mk-400000000000ff02'* ]]; then printf '%s' 'true'; exit 0; fi
  if [[ "$*" == *'pg_stat_activity'* && "$*" == *'phase1-invariant-reaper-'* ]]; then
    printf '%s' 'true'
    exit 0
  fi
  if [[ "$*" == *'pg_stat_activity'* && "$*" == *'phase1-invariant-audit-'* ]]; then
    printf '%s' 'true'
    exit 0
  fi
  if [[ "$*" == *'logStatement'* || "$*" == *"current_setting('log_statement')"* ]]; then
    printf '%s' 'true'
    exit 0
  fi
  if [[ "$*" == *'pg_db_role_setting'* && "$*" == *'pgaudit.role'* ]]; then
    printf '%s' 'true'
    exit 0
  fi
  if [[ "$*" == *'aster_runtime.run_tenant_maintenance'* && "$*" == *'terminated_count::text'* ]]; then
    printf '%s' "${'$'}{REAPER_RESULT:-2|0}"
    exit 0
  fi
  if [[ "$*" == *'--username aster_request'* ]]; then
    if [[ "$*" == *'--interactive'* ]]; then
      input="$(cat)"
      printf '%s' "$input" >>"$STDIN"
      if [[ "$input" == *'INSERT INTO aster_tenant.rls_sentinel'* && "$input" == *"'sentinel-a'"* ]]; then exit 0; fi
      if [[ "$input" == *'forbidden-cross-tenant-parent'* ]]; then
        printf '%s\n' 'ERROR:  23503: relationship rejected' >&2
        exit 1
      fi
      printf '%s' "${'$'}{CROSS_PROBE_OUTPUT:-tenant-a|sentinel-a|0}"
      exit "${'$'}{CROSS_PROBE_STATUS:-0}"
    fi
    if [[ "${'$'}{STALE_ACTIVATION_ACCEPTED:-0}" == 1 ]]; then exit 0; fi
    printf '%s\n' 'ERROR:  42501: Aster tenant binding rejected' >&2
    exit 1
  fi
  if [[ "$*" == *'--username aster_worker'* && "$*" == *'--interactive'* ]]; then
    cat >>"$STDIN"
    exit 0
  fi
  if [[ "$*" == *'--username aster_admin'* && "$*" == *'--interactive'* ]]; then
    input="$(cat)"
    printf '%s' "$input" >>"$STDIN"
    if [[ "$input" == *'matrix-function-narrowing'* ]]; then
      printf '%s' "${'$'}{MATRIX_NARROWING_OUTPUT:-42501}"
      exit "${'$'}{MATRIX_NARROWING_STATUS:-0}"
    fi
    printf '%s' "${'$'}{ADMIN_PROBE_OUTPUT:-42501|42501}"
    exit "${'$'}{ADMIN_PROBE_STATUS:-0}"
  fi
  if [[ "$*" == *'--username aster_admin'* && "$*" == *'phase1-invariant-matrix-'* && "$*" == *'mint_admin_tenant_binding'* ]]; then
    if [[ "${'$'}{MATRIX_FORBIDDEN_ALLOWED:-0}" == 1 && "$*" == *'phase1-invariant-matrix-active'* && "$*" == *"'provision'"* ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-inactive'* && ( "$*" == *"'provision'"* || "$*" == *"'rewrap'"* || "$*" == *"'key_audit'"* ) ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-active'* && ( "$*" == *"'key_lifecycle'"* || "$*" == *"'rewrap'"* || "$*" == *"'key_audit'"* ) ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-suspended'* && ( "$*" == *"'key_lifecycle'"* || "$*" == *"'rewrap'"* || "$*" == *"'key_audit'"* ) ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-epoch-provision'* && "$*" == *"'provision'"* ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-epoch-key-lifecycle'* && "$*" == *"'key_lifecycle'"* ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-epoch-rewrap'* && "$*" == *"'rewrap'"* ]]; then exit 0; fi
    if [[ "$*" == *'phase1-invariant-matrix-epoch-key-audit'* && "$*" == *"'key_audit'"* ]]; then exit 0; fi
    printf '%s\n' 'ERROR:  42501: matrix mint rejected' >&2
    exit 1
  fi
  if [[ "$*" == *'--username aster_admin'* && "$*" == *'aster_runtime.activate_tenant_binding'* && "$*" != *'suspend_tenant(7)'* ]]; then
    printf '%s\n' 'ERROR:  42501: stale matrix binding rejected' >&2
    exit 1
  fi
  if [[ "$*" == *'--username aster_admin'* && "$*" == *'aster_runtime.stage_wrapping_key'* ]]; then
    if [[ "$*" == *'aster-mk-400000000000ff01'* ]]; then
      if [[ "${'$'}{LIVE_LEDGER_ROW33_ALLOWED:-0}" == 1 ]]; then exit 0; fi
      printf '%s\n' 'ERROR:  55000: live ledger full' >&2
      exit 1
    fi
    if [[ "$*" == *'aster-mk-4000000000000002'* ]]; then
      printf '%s\n' 'ERROR:  55000: historical key id rejected' >&2
      exit 1
    fi
    exit 0
  fi
  if [[ "$*" == *'--username aster_admin'* && "$*" == *'DELETE FROM aster_control.wrapping_key_registry'* ]]; then
    printf '%s\n' 'ERROR:  42501: direct delete rejected' >&2
    exit 1
  fi
  if [[ "$*" == *'--username aster_maintainer'* || "$*" == *'--username aster_control_resolver'* || "$*" == *'--username aster_admin'* ]]; then exit 0; fi
  input="$(cat)"
  printf '%s' "$input" >>"$STDIN"
  [[ "${'$'}{FINAL_STATUS:-0}" == 0 ]] || exit "$FINAL_STATUS"
  if [[ "$input" == *'reaper.activity-visibility-redaction'* ]]; then
    printf '%s' "$REAPER_ACTIVITY_OUTPUT"
  elif [[ "$input" == *'reaper.object-audit-disabled'* ]]; then
    printf '%s' "$REAPER_AUDIT_OUTPUT"
  elif [[ "$input" == *'phase1-stale-keyring-pre-reload'* ]]; then
    printf '%s' "${'$'}{STALE_KEYRING_TOKEN:-42501|15000|42501|42501|true}"
  elif [[ "$input" == *'phase1-key-owner-probe'* ]]; then
    printf '%s' "${'$'}{FORCED_RLS_TOKEN:-1|1|42501|true|true}"
  elif [[ "$input" == *'phase1-metadata-dml-probe'* ]]; then
    printf '%s' "${'$'}{METADATA_DML_TOKEN:-42501|42501|42501|42501|42501|42501|true}"
  elif [[ "$input" == *'phase1-reference-ledger-probe'* ]]; then
    printf '%s' "${'$'}{REFERENCE_LEDGER_TOKEN:-true|1|true}"
  elif [[ "$input" == *'phase1-wrapping-fence-late-probe'* ]]; then
    printf '%s' "${'$'}{WRAPPING_FENCE_TOKEN:-55000|true}"
  elif [[ "$input" == *'SET SESSION AUTHORIZATION aster_key_runtime'* ]]; then
    printf '%s' "${'$'}{REQUIRED_READABLE_TOKEN:-15000|42501|42501|42501|42501|true}"
  elif [[ "$input" == *'keystore.required-readable-key-set'* ]]; then
    printf '%s' "$REQUIRED_READABLE_OUTPUT"
  elif [[ "$input" == *'keystore.stale-keyring-rejoin-rejected'* ]]; then
    printf '%s' "$STALE_KEYRING_OUTPUT"
  elif [[ "$input" == *'keystore.forced-rls-owner-boundary'* ]]; then
    printf '%s' "$FORCED_RLS_OUTPUT"
  elif [[ "$input" == *'keystore.metadata-dml-boundary'* ]]; then
    printf '%s' "$METADATA_DML_OUTPUT"
  elif [[ "$input" == *'keystore.reference-count-ledger'* ]]; then
    printf '%s' "$REFERENCE_LEDGER_OUTPUT"
  elif [[ "$input" == *'keystore.live-ledger-limit-and-tombstone'* ]]; then
    printf '%s' "$LIVE_LEDGER_OUTPUT"
  elif [[ "$input" == *'keystore.wrapping-fence-late-commit'* ]]; then
    printf '%s' "$WRAPPING_FENCE_OUTPUT"
  else
    printf '%s' "$OWNER_OUTPUT"
  fi
  exit 0
fi
exit 1
`,
    { mode: 0o700 }
  );
  await chmod(binary, 0o700);

  return {
    calls,
    stdin,
    env: {
      PATH: `${root}:/usr/bin:/bin`,
      CALLS: calls,
      STDIN: stdin,
      PRIMARY_ID: primaryContainerId,
      FOREIGN_ID: foreignContainerId,
      PRIMARY_SERVICE: primaryService,
      FOREIGN_SERVICE: foreignService,
      PROJECT: project,
      OWNER_OUTPUT: ownerRoleOutput,
      SUSPENDED_OUTPUT: suspendedEpochOutput,
      CROSS_TENANT_OUTPUT: crossTenantOutput,
      ADMIN_BINDING_OUTPUT: adminBindingOutput,
      ADMIN_MATRIX_OUTPUT: adminMatrixOutput,
      REAPER_ACTIVITY_OUTPUT: reaperActivityOutput,
      REAPER_AUDIT_OUTPUT: reaperAuditOutput,
      REQUIRED_READABLE_OUTPUT: requiredReadableOutput,
      STALE_KEYRING_OUTPUT: staleKeyringOutput,
      FORCED_RLS_OUTPUT: forcedRlsOutput,
      METADATA_DML_OUTPUT: metadataDmlOutput,
      REFERENCE_LEDGER_OUTPUT: referenceLedgerOutput,
      LIVE_LEDGER_OUTPUT: liveLedgerOutput,
      WRAPPING_FENCE_OUTPUT: wrappingFenceOutput,
      CORE_ID: '3'.repeat(64),
    },
  };
};

const args = (id = ownerRoleInvariantId) => [
  '--invariant-id',
  id,
  '--project-name',
  projectName,
  '--primary-container-id',
  primaryContainerId,
  '--foreign-container-id',
  foreignContainerId,
];

describe('Phase 1 candidate invariant shell driver', () => {
  it('executes actual owner-role attempts and emits one exact terminal object', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(), { env: fake.env });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(ownerRoleOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    for (const role of [
      'aster_request',
      'aster_worker',
      'aster_admin',
      'aster_maintainer',
      'aster_control_resolver',
      'aster_key_runtime',
      'aster_migrator',
    ]) {
      expect(calls).toContain(`--username ${role}`);
    }
    expect(calls).toContain('--username postgres');
    expect(calls).toContain('--dbname aster_phase1_candidate_primary');
    expect(sql).toContain('pg_catalog.pg_auth_members');
    expect(sql).toContain('pg_catalog.count(*) = 5');
    expect(sql).not.toContain('admin_option');
    expect(sql).toContain("'phase1-candidate-invariant-terminal'");
    expect(sql).not.toMatch(/password|secret|private_key/iu);
  });

  it('rejects a stale request capability after an actual admin suspension and epoch change', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(suspendedEpochInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(suspendedEpochOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    for (const role of [
      'aster_maintainer',
      'aster_control_resolver',
      'aster_admin',
      'aster_request',
    ]) {
      expect(calls).toContain(`--username ${role}`);
    }
    expect(calls).toContain('aster_runtime.run_tenant_maintenance');
    expect(calls).toContain('aster_runtime.mint_tenant_binding');
    expect(calls).toContain('aster_runtime.mint_admin_tenant_binding');
    expect(calls).toContain('aster_runtime.suspend_tenant(7)');
    expect(calls).toContain('aster_runtime.activate_tenant_binding');
    expect(sql).toContain("'phase1-invariant-suspended-epoch'");
    expect(sql).toContain("'project-suspended-epoch'");
    expect(sql).toContain("'cleanup-suspended-epoch'");
    expect(sql).toContain('request_binding.expires_at > pg_catalog.clock_timestamp()');
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed and cleans the epoch fixture when stale activation is accepted', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(suspendedEpochInvariantId), {
        env: { ...fake.env, STALE_ACTIVATION_ACCEPTED: '1' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain('--set=action=cleanup-suspended-epoch');
  });

  it('fails the invariant when reverse cleanup fails', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(suspendedEpochInvariantId), {
        env: { ...fake.env, CLEANUP_STATUS: '1' },
      })
    ).rejects.toThrow();
  });

  it('projects only the bound tenant after actual RLS and relationship denials', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(crossTenantInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(crossTenantOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    for (const role of [
      'aster_maintainer',
      'aster_control_resolver',
      'aster_request',
      'aster_worker',
    ]) {
      expect(calls).toContain(`--username ${role}`);
    }
    expect(calls).toContain('aster_runtime.run_tenant_maintenance');
    expect(calls).toContain('aster_runtime.mint_tenant_binding');
    expect(sql).toContain("'phase1-invariant-cross-a'");
    expect(sql).toContain("'phase1-invariant-cross-b'");
    expect(sql).toContain("'sentinel-a'");
    expect(sql).toContain("'sentinel-b'");
    expect(sql).toContain('forbidden-cross-tenant-parent');
    expect(sql).toContain('parent_item_id');
    expect(sql).toContain('aster_runtime.bound_tenant_id(NULL)');
    expect(sql).toContain("'project-cross-tenant'");
    expect(sql).toContain("'cleanup-cross-tenant'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed and cleans when a cross-tenant row becomes visible', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(crossTenantInvariantId), {
        env: { ...fake.env, CROSS_PROBE_OUTPUT: 'tenant-a|sentinel-a|1' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain('--set=action=cleanup-cross-tenant');
  });

  it('binds one admin capability to one tenant and operation class', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(adminBindingInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(adminBindingOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    for (const role of ['aster_maintainer', 'aster_admin']) {
      expect(calls).toContain(`--username ${role}`);
    }
    expect(calls).toContain('aster_runtime.run_tenant_maintenance');
    expect(calls).toContain('aster_runtime.mint_admin_tenant_binding');
    expect(sql).toContain('aster_runtime.probe_admin_provision_write');
    expect(sql).toContain('aster_runtime.create_inactive_tenant');
    expect(sql).toContain('aster_runtime.probe_admin_rewrap_write');
    expect(sql).toContain('ROLLBACK TO SAVEPOINT');
    expect(sql).toContain("'project-admin-binding'");
    expect(sql).toContain("'cleanup-admin-binding'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed and cleans when an admin denial is broadened', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(adminBindingInvariantId), {
        env: { ...fake.env, ADMIN_PROBE_OUTPUT: '00000|42501' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain('--set=action=cleanup-admin-binding');
  });

  it('projects the exact admin status and operation matrix with epoch fencing', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(adminMatrixInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(adminMatrixOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    expect(calls).toContain('--username aster_maintainer');
    expect(calls).toContain('--username aster_admin');
    for (const operation of ['provision', 'key_lifecycle', 'rewrap', 'key_audit']) {
      expect(calls).toContain(`'${operation}'`);
    }
    for (const status of ['inactive', 'active', 'suspended', 'deleted']) {
      expect(calls).toContain(`phase1-invariant-matrix-${status}`);
    }
    expect(sql).toContain('matrix-function-narrowing');
    expect(sql).toContain('aster_runtime.probe_admin_rewrap_write');
    expect(sql).toContain("'advance-admin-matrix-epochs'");
    expect(sql).toContain("'project-admin-matrix'");
    expect(sql).toContain("'cleanup-admin-matrix'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed and cleans when a forbidden matrix pair is accepted', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(adminMatrixInvariantId), {
        env: { ...fake.env, MATRIX_FORBIDDEN_ALLOWED: '1' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain('--set=action=cleanup-admin-matrix');
  });

  it('reaps overdue request and worker transactions without projecting sentinels', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(reaperActivityInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(reaperActivityOutput));
    expect(stdout).not.toMatch(/phase1-reaper-(?:request|worker)-sentinel/u);
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    for (const role of ['aster_request', 'aster_worker', 'aster_maintainer']) {
      expect(calls).toContain(`--username ${role}`);
    }
    expect(calls).toContain('PGAPPNAME=phase1-invariant-reaper-request');
    expect(calls).toContain('PGAPPNAME=phase1-invariant-reaper-worker');
    expect(calls).toContain('aster_runtime.run_tenant_maintenance');
    expect(calls).toContain('pg_stat_activity');
    expect(sql).toContain('phase1-reaper-request-sentinel');
    expect(sql).toContain('phase1-reaper-worker-sentinel');
    expect(sql).toContain("'reaper.activity-visibility-redaction'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed and reaps fixture processes when the maintainer misses one backend', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(reaperActivityInvariantId), {
        env: { ...fake.env, REAPER_RESULT: '1|0' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain('pg_terminate_backend');
  });

  it('proves request and worker object audit is disabled across every configured sink', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(reaperAuditInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(reaperAuditOutput));
    expect(stdout).not.toMatch(/phase1-audit-(?:request|worker)-sentinel/u);
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    expect(calls).toContain('com.docker.compose.service=candidate-primary-core');
    expect(calls).toContain('candidate-primary-core');
    expect(calls).toContain('logs');
    for (const role of ['aster_request', 'aster_worker']) {
      expect(calls).toContain(`--username ${role}`);
    }
    expect(calls).toContain('PGAPPNAME=phase1-invariant-audit-request');
    expect(calls).toContain('PGAPPNAME=phase1-invariant-audit-worker');
    expect(calls).toContain('pg_db_role_setting');
    expect(calls).toContain('pg_terminate_backend');
    expect(sql).toContain('phase1-audit-request-sentinel');
    expect(sql).toContain('phase1-audit-worker-sentinel');
    expect(sql).toContain("'reaper.object-audit-disabled'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed and cleans when a complete log artifact contains a sentinel', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(reaperAuditInvariantId), {
        env: { ...fake.env, AUDIT_LOG_SENTINEL: '1' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain('pg_terminate_backend');
  });

  it('enforces required subset loaded subset live for key-runtime leases', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(requiredReadableInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(requiredReadableOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    expect(calls).toContain('--username postgres');
    expect(sql).toContain('SET SESSION AUTHORIZATION aster_key_runtime');
    expect(sql).toContain('aster_runtime.upsert_own_writer_lease');
    expect(sql).toContain('aster_runtime.read_key_runtime_state');
    expect(sql).toContain('phase1-required-old-referenced');
    expect(sql).toContain('phase1-required-rollback-retained');
    expect(sql).toContain('phase1-required-staged-optional');
    expect(sql).toContain('phase1-required-removable-optional');
    expect(sql).toContain('ROLLBACK;');
    expect(sql).toContain("'keystore.required-readable-key-set'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed when a required-readable negative category is accepted', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(requiredReadableInvariantId), {
        env: { ...fake.env, REQUIRED_READABLE_TOKEN: '15000|00000|42501|42501|42501|true' },
      })
    ).rejects.toThrow();
  });

  it('rejects a stale replica until a full generation and key-set reload', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(staleKeyringInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(staleKeyringOutput));
    const sql = await readFile(fake.stdin, 'utf8');

    expect(sql).toContain('phase1-stale-keyring-pre-reload');
    expect(sql).toContain('phase1-stale-keyring-post-reload');
    expect(sql).toContain('aster_runtime.upsert_own_writer_lease');
    expect(sql).toContain('minimum_keyring_generation = 2');
    expect(sql).toContain('SET SESSION AUTHORIZATION aster_key_runtime');
    expect(sql).toContain('ROLLBACK;');
    expect(sql).toContain("'keystore.stale-keyring-rejoin-rejected'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed when a stale generation heartbeat is accepted', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(staleKeyringInvariantId), {
        env: { ...fake.env, STALE_KEYRING_TOKEN: '15000|15000|42501|42501|true' },
      })
    ).rejects.toThrow();
  });

  it('keeps owner-definer key access capability-bound under forced RLS', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(forcedRlsInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(forcedRlsOutput));
    const sql = await readFile(fake.stdin, 'utf8');

    expect(sql).toContain('phase1-key-owner-probe');
    expect(sql).toContain('aster_runtime.provision_signing_key');
    expect(sql).toContain('aster_runtime.provision_cookie_key');
    expect(sql).toContain('aster_runtime.activate_tenant_binding');
    expect(sql).toContain('aster_runtime.phase1_key_owner_probe');
    expect(sql).toContain('relforcerowsecurity');
    expect(sql).toContain('pg_catalog.pg_policy');
    expect(sql).toContain('ROLLBACK;');
    expect(sql).toContain("'keystore.forced-rls-owner-boundary'");
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
  });

  it('fails closed when owner-definer key mutation crosses tenants', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(forcedRlsInvariantId), {
        env: { ...fake.env, FORCED_RLS_TOKEN: '1|1|00000|true|true' },
      })
    ).rejects.toThrow();
  });

  it('allows only database-timed signing and sealing metadata updates', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(metadataDmlInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(metadataDmlOutput));
    const sql = await readFile(fake.stdin, 'utf8');

    expect(sql).toContain('phase1-metadata-dml-probe');
    expect(sql).toContain('aster_runtime.provision_signing_key');
    expect(sql).toContain('aster_runtime.provision_cookie_key');
    expect(sql).toContain('aster_runtime.record_signing_use');
    expect(sql).toContain('aster_runtime.record_cookie_seal');
    for (const operation of [
      'caller_time_state',
      'lifecycle_state',
      'generation_state',
      'tenant_state',
      'material_state',
      'public_metadata_state',
    ]) {
      expect(sql).toContain(operation);
    }
    expect(sql).toContain('ROLLBACK;');
    expect(sql).toContain("'keystore.metadata-dml-boundary'");
    expect(sql).not.toMatch(/password|secret|private_key/iu);
  });

  it('fails closed when caller-supplied metadata time is accepted', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(metadataDmlInvariantId), {
        env: { ...fake.env, METADATA_DML_TOKEN: '00000|42501|42501|42501|42501|42501|true' },
      })
    ).rejects.toThrow();
  });

  it('keeps the wrapping reference ledger equal to all material rows', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(referenceLedgerInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(referenceLedgerOutput));
    const sql = await readFile(fake.stdin, 'utf8');

    expect(sql).toContain('phase1-reference-ledger-probe');
    expect(sql).toContain('aster_runtime.provision_signing_key');
    expect(sql).toContain('aster_runtime.provision_cookie_key');
    expect(sql).toContain('aster_runtime.rewrap_signing_key_material');
    expect(sql).toContain('aster_runtime.phase1_reference_delete_probe');
    expect(sql).toContain('reference_count');
    expect(sql).toContain('UNION ALL');
    expect(sql).toContain('ROLLBACK TO SAVEPOINT');
    expect(sql).toContain("'keystore.reference-count-ledger'");
    expect(sql).not.toMatch(/password|secret|private_key/iu);
  });

  it('fails closed when the reference ledger does not match material population', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(referenceLedgerInvariantId), {
        env: { ...fake.env, REFERENCE_LEDGER_TOKEN: 'false|1|true' },
      })
    ).rejects.toThrow();
  });

  it('enforces the 32-row live ledger and immutable key-id tombstones', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(liveLedgerInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(liveLedgerOutput));
    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    expect(calls).toContain('aster_runtime.stage_wrapping_key');
    expect(calls).toContain('aster-mk-400000000000ff01');
    expect(calls).toContain('aster-mk-400000000000ff02');
    expect(calls).toContain('aster-mk-4000000000000002');
    expect(calls).toContain('DELETE FROM aster_control.wrapping_key_registry');
    expect(calls).toContain('generate_series(1, 31)');
    expect(calls).toContain('wrapping_key_history');
    expect(sql).toContain("'keystore.live-ledger-limit-and-tombstone'");
    expect(sql).not.toMatch(/password|secret|private_key/iu);
  });

  it('fails closed and cleans when row 33 enters the live registry', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(liveLedgerInvariantId), {
        env: { ...fake.env, LIVE_LEDGER_ROW33_ALLOWED: '1' },
      })
    ).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');

    expect(calls).toContain("key_id LIKE 'aster-mk-4%'");
  });

  it('rejects a late old-key material write after the wrapping fence completes', async () => {
    const fake = await fakeDocker();
    const { stdout, stderr } = await executeFile(driver, args(wrappingFenceInvariantId), {
      env: fake.env,
    });

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(wrappingFenceOutput));
    const sql = await readFile(fake.stdin, 'utf8');

    expect(sql).toContain('phase1-wrapping-fence-late-probe');
    expect(sql).toContain('aster_runtime.provision_signing_key');
    expect(sql).toContain('write_fenced = true');
    expect(sql).toContain('aster-mk-5000000000000001');
    expect(sql).toContain('aster-mk-5000000000000002');
    expect(sql).toContain('old_key.reference_count');
    expect(sql).toContain('new_key.reference_count');
    expect(sql).toContain('ROLLBACK TO SAVEPOINT');
    expect(sql).toContain("'keystore.wrapping-fence-late-commit'");
    expect(sql).not.toMatch(/password|secret|private_key/iu);
  });

  it('fails closed when a late old-key write is accepted', async () => {
    const fake = await fakeDocker();

    await expect(
      executeFile(driver, args(wrappingFenceInvariantId), {
        env: { ...fake.env, WRAPPING_FENCE_TOKEN: '00000|true' },
      })
    ).rejects.toThrow();
  });

  it.each([
    ['unknown invariant', args('tenant.unknown-invariant')],
    ['extra argument', [...args(), '--extra']],
    ['wrong project', args().map((value) => (value === projectName ? 'wrong' : value))],
  ] as const)('rejects %s before docker exec', async (_name, invocation) => {
    const fake = await fakeDocker();

    await expect(executeFile(driver, [...invocation], { env: fake.env })).rejects.toThrow();
    await expect(readFile(fake.calls, 'utf8')).rejects.toThrow();
  });

  it.each([
    ['wrong primary service', 'candidate-primary-core', 'candidate-foreign-postgres', projectName],
    [
      'wrong foreign service',
      'candidate-primary-postgres',
      'candidate-primary-postgres',
      projectName,
    ],
    [
      'wrong compose project',
      'candidate-primary-postgres',
      'candidate-foreign-postgres',
      'aster-phase1-fedcba9876543210',
    ],
  ] as const)('rejects %s', async (_name, primary, foreign, project) => {
    const fake = await fakeDocker(primary, foreign, project);

    await expect(executeFile(driver, args(), { env: fake.env })).rejects.toThrow();
    const calls = await readFile(fake.calls, 'utf8');
    expect(calls).not.toContain('exec --interactive');
  });
});

/* eslint-enable max-lines */
