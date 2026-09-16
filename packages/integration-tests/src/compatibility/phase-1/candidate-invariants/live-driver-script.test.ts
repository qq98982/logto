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
const projection = (invariantId: string) =>
  candidateInvariantContracts.find(({ id }) => id === invariantId)?.positiveControl
    .expectedProjection;
const ownerRoleProjection = projection(ownerRoleInvariantId);
const suspendedEpochProjection = projection(suspendedEpochInvariantId);
const crossTenantProjection = projection(crossTenantInvariantId);
const adminBindingProjection = projection(adminBindingInvariantId);
const adminMatrixProjection = projection(adminMatrixInvariantId);

if (
  !ownerRoleProjection ||
  !suspendedEpochProjection ||
  !crossTenantProjection ||
  !adminBindingProjection ||
  !adminMatrixProjection
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
if [[ "$1" == inspect ]]; then
  if [[ "${'$'}{*: -1}" == "$PRIMARY_ID" ]]; then printf '%s|%s' "$PRIMARY_SERVICE" "$PROJECT"; exit 0; fi
  if [[ "${'$'}{*: -1}" == "$FOREIGN_ID" ]]; then printf '%s|%s' "$FOREIGN_SERVICE" "$PROJECT"; exit 0; fi
  exit 1
fi
if [[ "$1" == exec ]]; then
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
  if [[ "$*" == *'--username aster_maintainer'* || "$*" == *'--username aster_control_resolver'* || "$*" == *'--username aster_admin'* ]]; then exit 0; fi
  cat >>"$STDIN"
  [[ "${'$'}{FINAL_STATUS:-0}" == 0 ]] || exit "$FINAL_STATUS"
  printf '%s' "$OWNER_OUTPUT"
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
    expect(sql).not.toMatch(/password|secret|ciphertext|private_key/iu);
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
