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
const invariantId = 'database.owner-role-membership-boundary';
const projection = candidateInvariantContracts.find(({ id }) => id === invariantId)?.positiveControl
  .expectedProjection;

if (!projection) {
  throw new Error('missing owner-role invariant projection');
}

const output = JSON.stringify({
  schemaVersion: 1,
  kind: 'phase1-candidate-invariant-terminal',
  invariantId,
  projection,
});

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
  if [[ "$*" == *'--username aster_migrator'* ]]; then exit 0; fi
  if [[ "$*" == *'--username aster_'* && "$*" != *'--username postgres'* ]]; then exit 1; fi
  cat >"$STDIN"
  [[ "${'$'}{FINAL_STATUS:-0}" == 0 ]] || exit "$FINAL_STATUS"
  printf '%s' "$OUTPUT"
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
      OUTPUT: output,
    },
  };
};

const args = (id = invariantId) => [
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
    expect(JSON.parse(stdout)).toEqual(JSON.parse(output));
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

  it.each([
    ['unknown invariant', args('tenant.cross-tenant-read-rejected')],
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
