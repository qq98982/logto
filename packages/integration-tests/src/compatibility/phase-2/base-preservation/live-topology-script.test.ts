/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The source-contract assertions reuse one mutable private test root across the fixture lifecycle. */
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const runnerPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase2-base-preservation.sh'
);
const acceptedPhase1Runner = '.scripts/compatibility/run-phase1-runtime-candidate.sh';
let source = '';
let temporaryRoot = '';

describe('Phase 2 base-preservation live runner', () => {
  beforeAll(async () => {
    source = await readFile(runnerPath, 'utf8');
    temporaryRoot = await mkdtemp('/var/tmp/henry-build/phase2-base-runner-test-');
  });

  afterAll(async () => {
    await rm(temporaryRoot, { force: true, recursive: true });
  });

  it('derives the topology runner only from the exact accepted Phase 1 blob', () => {
    expect(source).toContain('83d08f0821345d1bdc01491152949cc6f044ecfb');
    expect(source).toContain(acceptedPhase1Runner);
    expect(source).toContain('rev-parse "$ACCEPTED_H_COMMIT:$PHASE1_RUNNER_RELATIVE"');
    expect(source).toContain('hash-object --no-filters -- "$PHASE1_RUNNER"');
    expect(source).toContain('transform_phase1_runner');
    expect(source).not.toContain('docker-compose.phase1-runtime-candidate-differential.yml');
  });

  it('runs the raw accepted gate as a rejection control before the separate base CLI', () => {
    const raw = source.indexOf('raw-phase1-negative-control');
    const base = source.indexOf('compatibility/phase-2/base-preservation/launcher.mjs');

    expect(raw).toBeGreaterThan(0);
    expect(base).toBeGreaterThan(raw);
    expect(source).toContain('raw_status');
    expect(source).toContain("'Phase 1 run failed.'");
    expect(source).toContain(".replaceAll('\\\\${', '${')");
    expect(source).toContain('phase-2-base-preservation.json');
    expect(source).not.toContain('Phase 1 differential gate passed');
  });

  it('publishes only after the accepted child runner has completed cleanup', () => {
    const child = source.lastIndexOf('run_transformed_topology "$generated"');
    const publication = source.lastIndexOf('publish_verified_result "$staging"');

    expect(child).toBeGreaterThan(0);
    expect(publication).toBeGreaterThan(child);
    expect(source).toContain('--no-clobber --no-target-directory');
    expect(source).toContain('aster-phase2-base-preservation-results');
    expect(source).toContain('trap cleanup EXIT');
  });

  it('keeps secrets out of arguments, logs, evidence and shared memory', () => {
    expect(source).not.toContain('/dev/shm');
    expect(source).not.toMatch(/set\s+-x/u);
    expect(source).not.toMatch(/(?:PASSWORD|SECRET_VAULT_KEK|STATUS_API_KEY).*printf/u);
    expect(source).toContain('>/dev/null 2>&1');
    expect(source).toContain('umask 077');
  });

  it('rejects publication unless the staging directory has one private fixed artifact', async () => {
    const stagingRoot = path.join(temporaryRoot, 'staging');
    const resultRoot = path.join(temporaryRoot, 'results');
    const staging = path.join(stagingRoot, 'result.test');
    const harness = path.join(temporaryRoot, 'publish-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    await mkdir(resultRoot, { mode: 0o700 });
    await writeFile(path.join(staging, 'wrong.json'), '{}', { mode: 0o600 });
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(runnerPath)}\nRESULT_ROOT=${JSON.stringify(
        resultRoot
      )}\nSTAGING_ROOT=${JSON.stringify(stagingRoot)}\nif publish_verified_result ${JSON.stringify(
        staging
      )} >/dev/null 2>&1; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
