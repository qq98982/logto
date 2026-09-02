import { execFile } from 'node:child_process';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const roots = new Set<string>();
const repositoryRoot = path.resolve(process.cwd(), '../..');
const driver = path.join(repositoryRoot, '.scripts/compatibility/phase1-reference-state-driver.sh');

const createRoot = async () => {
  const root = path.join(
    '/var/tmp/henry-build',
    `phase1-state-driver-${process.pid}-${Date.now()}`
  );
  await mkdir(root, { recursive: true, mode: 0o700 });
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const safeOutput = JSON.stringify({
  schemaVersion: 1,
  scenarioId: 'token.authorization-code',
  stepId: 'state',
  models: [],
  extensions: [],
  users: [],
  verificationRecords: [],
});
const projectName = 'aster-phase1-0123456789abcdef';

const createFakeDocker = async (
  root: string,
  service = 'oracle-primary-postgres',
  project = projectName
) => {
  const binary = path.join(root, 'docker');
  const calls = path.join(root, 'calls');
  await writeFile(
    binary,
    `#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' "$*" >>"$PHASE1_FAKE_CALLS"\nif [[ "$1" == inspect ]]; then\n  printf '%s|%s\\n' "$PHASE1_FAKE_SERVICE" "$PHASE1_FAKE_PROJECT"\n  exit 0\nfi\nif [[ "$1" == exec ]]; then\n  cat >/dev/null\n  printf '%s\\n' "$PHASE1_FAKE_OUTPUT"\n  exit 0\nfi\nexit 1\n`,
    { mode: 0o700 }
  );
  await chmod(binary, 0o700);

  return {
    calls,
    environment: {
      PATH: `${root}:/usr/bin:/bin`,
      PHASE1_FAKE_CALLS: calls,
      PHASE1_FAKE_SERVICE: service,
      PHASE1_FAKE_PROJECT: project,
      PHASE1_FAKE_OUTPUT: safeOutput,
    },
  };
};

describe('Phase 1 reference state driver', () => {
  it('accepts only a closed scenario step and a labeled Postgres container', async () => {
    const root = await createRoot();
    const fake = await createFakeDocker(root);
    const { stdout, stderr } = await executeFile(
      driver,
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
      { env: fake.environment }
    );

    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toEqual(JSON.parse(safeOutput));
    expect(await readFile(fake.calls, 'utf8')).toContain('exec --interactive');
  });

  it.each([
    [
      'invalid container',
      [
        '--container-id',
        '../postgres',
        '--project-name',
        projectName,
        '--expected-service',
        'oracle-primary-postgres',
        '--scenario-id',
        'token.authorization-code',
        '--step-id',
        'state',
      ],
    ],
    [
      'unknown scenario',
      [
        '--container-id',
        '1'.repeat(64),
        '--project-name',
        projectName,
        '--expected-service',
        'oracle-primary-postgres',
        '--scenario-id',
        'unknown',
        '--step-id',
        'state',
      ],
    ],
    [
      'wrong step',
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
        'authorize',
      ],
    ],
    [
      'extra flag',
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
        '--extra',
      ],
    ],
  ] as const)('fails closed for %s', async (_name, arguments_) => {
    const root = await createRoot();
    const fake = await createFakeDocker(root);

    await expect(executeFile(driver, [...arguments_], { env: fake.environment })).rejects.toThrow();
    await expect(readFile(fake.calls, 'utf8')).rejects.toThrow();
  });

  it('rejects a container outside the four isolated Postgres services', async () => {
    const root = await createRoot();
    const fake = await createFakeDocker(root, 'candidate-primary-core');

    await expect(
      executeFile(
        driver,
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
        { env: fake.environment }
      )
    ).rejects.toThrow();
    expect(await readFile(fake.calls, 'utf8')).not.toContain('exec --interactive');
  });

  it('rejects a correctly named service from another Compose project', async () => {
    const root = await createRoot();
    const fake = await createFakeDocker(
      root,
      'oracle-primary-postgres',
      'aster-phase1-fedcba9876543210'
    );

    await expect(
      executeFile(
        driver,
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
        { env: fake.environment }
      )
    ).rejects.toThrow();
    expect(await readFile(fake.calls, 'utf8')).not.toContain('exec --interactive');
  });
});
