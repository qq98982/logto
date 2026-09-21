/* eslint-disable no-await-in-loop -- Each hostile invocation owns a separate fake Docker directory and must finish before its cleanup assertion. */
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const driver = path.join(repositoryRoot, '.scripts/compatibility/phase1-candidate-state-driver.sh');
const roots = new Set<string>();
const projectName = 'aster-phase1-0123456789abcdef';
const safeOutput = JSON.stringify({
  schemaVersion: 1,
  scenarioId: 'token.authorization-code',
  stepId: 'state',
  models: [],
  extensions: [],
  users: [],
  verificationRecords: [],
});

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const fakeDocker = async (service = 'candidate-primary-postgres', project = projectName) => {
  const root = await mkdtemp('/var/tmp/henry-build/candidate-state-driver-');
  roots.add(root);
  const binary = path.join(root, 'docker');
  const calls = path.join(root, 'calls');
  const stdin = path.join(root, 'stdin.sql');
  await writeFile(
    binary,
    `#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' "$*" >>"$CALLS"\nif [[ "$1" == inspect ]]; then printf '%s|%s\\n' "$SERVICE" "$PROJECT"; exit 0; fi\nif [[ "$1" == exec ]]; then cat >"$STDIN"; printf '%s\\n' "$OUTPUT"; exit 0; fi\nexit 1\n`,
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
      SERVICE: service,
      PROJECT: project,
      OUTPUT: safeOutput,
    },
  };
};

describe('Phase 1 candidate state driver', () => {
  it.each([
    ['candidate-primary-postgres', 'aster_phase1_candidate_primary'],
    ['candidate-foreign-postgres', 'aster_phase1_candidate_foreign'],
  ] as const)('binds %s to its fixed Aster database', async (service, database) => {
    const fake = await fakeDocker(service);
    const { stdout, stderr } = await executeFile(
      driver,
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        projectName,
        '--expected-service',
        service,
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'state',
      ],
      { env: fake.env }
    );
    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(safeOutput));
    const calls = await readFile(fake.calls, 'utf8');
    expect(calls).toContain(`--dbname ${database}`);
    expect(calls).toContain('exec --interactive --user postgres');
  });

  it('locks the isolated superuser projection inside one read-only transaction', async () => {
    const fake = await fakeDocker();

    await executeFile(
      driver,
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        projectName,
        '--expected-service',
        'candidate-primary-postgres',
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'state',
      ],
      { env: fake.env }
    );

    const calls = await readFile(fake.calls, 'utf8');
    const sql = await readFile(fake.stdin, 'utf8');

    expect(calls).toContain('--single-transaction');
    expect(sql.startsWith('SET TRANSACTION READ ONLY;\n')).toBe(true);
    expect(sql).toContain("SET LOCAL statement_timeout = '20s';");
    expect(sql).toContain("SET LOCAL lock_timeout = '5s';");
    expect(sql).toContain("SET LOCAL idle_in_transaction_session_timeout = '20s';");
    expect(sql).toContain('SET LOCAL search_path = pg_catalog;');
    expect(sql).not.toMatch(
      /^\s*(?:insert|update|delete|create|alter|drop|truncate|grant|revoke)\b/imu
    );
  });

  it('pins the Aster-only read model and excludes raw credential material', async () => {
    const source = await readFile(driver, 'utf8');
    for (const table of [
      'aster_tenant.interactions',
      'aster_tenant.sessions',
      'aster_tenant.grants',
      'aster_tenant.authorization_codes',
      'aster_tenant.token_families',
      'aster_tenant.refresh_tokens',
      'aster_tenant.users',
    ]) {
      expect(source).toContain(table);
    }
    for (const forbidden of ['password_hash', 'code_context', 'ciphertext', 'private_key']) {
      expect(source).not.toContain(forbidden);
    }
    expect(source).toContain("encode(code_digest,'hex')");
    expect(source).toContain('encode(token.refresh_digest');
    expect(source).toContain("'phase1-family:'||family.grant_id");
    expect(source).not.toContain("'phase1-family:'||family.family_id");
    expect(source).toContain("nullif(authorization_entry.value->>'grant_id','') is not null");
  });

  it('rejects wrong services, projects, steps, and extra flags before docker exec', async () => {
    const cases = [
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        projectName,
        '--expected-service',
        'oracle-primary-postgres',
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'state',
      ],
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        'wrong',
        '--expected-service',
        'candidate-primary-postgres',
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'state',
      ],
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        projectName,
        '--expected-service',
        'candidate-primary-postgres',
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'wrong',
      ],
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        projectName,
        '--expected-service',
        'candidate-primary-postgres',
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'state',
        '--extra',
      ],
    ];
    for (const args of cases) {
      const fake = await fakeDocker();
      await expect(executeFile(driver, args, { env: fake.env })).rejects.toThrow();
      await expect(readFile(fake.calls, 'utf8')).rejects.toThrow();
    }
  });

  it.each([
    ['a container outside the candidate Postgres services', 'candidate-primary-core', projectName],
    [
      'a correctly named service from another Compose project',
      'candidate-primary-postgres',
      'aster-phase1-fedcba9876543210',
    ],
  ] as const)('rejects %s', async (_name, actualService, actualProject) => {
    const fake = await fakeDocker(actualService, actualProject);

    await expect(
      executeFile(
        driver,
        [
          '--container-id',
          '1'.repeat(64),
          '--project-name',
          projectName,
          '--expected-service',
          'candidate-primary-postgres',
          '--scenario-id',
          'token.authorization-code',
          '--step-id',
          'state',
        ],
        { env: fake.env }
      )
    ).rejects.toThrow();
    expect(await readFile(fake.calls, 'utf8')).not.toContain('exec --interactive');
  });
});

/* eslint-enable no-await-in-loop */
