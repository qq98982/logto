import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

const execute = promisify(execFile);
const script = new URL('./phase1-candidate-postgres-init.sh', import.meta.url).pathname;
const run = async (h5, password) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'aster-h5-hba-'));
  try {
    await writeFile(`${root}/pg_hba.conf`, 'initial\n', { mode: 0o600 });
    let code = 0;
    try {
      await execute(script, [], {
        env: {
          PATH: '/usr/bin:/bin', PGDATA: root,
          ASTER_PHASE1_INIT_CIDR: '172.30.241.11/32',
          ASTER_PHASE1_CORE_CIDR: '172.30.241.12/32',
          ASTER_PHASE1_COORDINATOR_CIDR: '172.30.241.13/32',
          ...(h5 === undefined ? {} : { ASTER_PHASE1_H5_CORE_CIDR: h5 }),
          ...(password === undefined ? {} : { ASTER_PHASE1_PASSWORD_CORE_CIDR: password }),
        },
      });
    } catch (error) {
      code = Number(error?.code ?? 1);
    }
    return { code, hba: await readFile(`${root}/pg_hba.conf`, 'utf8') };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

test('admits only the exact optional H5 core address for runtime database roles', async () => {
  const { code, hba } = await run('172.30.241.14/32');
  assert.equal(code, 0);
  const rows = hba.split('\n').filter((row) => row.includes('172.30.241.14/32'));
  assert.deepEqual(rows, ['host all aster_control_resolver,aster_request,aster_key_runtime,aster_maintainer 172.30.241.14/32 trust']);
  assert.doesNotMatch(hba, /172\.30\.241\.0\/24/u);
});

test('keeps the existing HBA unchanged when no H5 core is configured', async () => {
  const { code, hba } = await run(undefined);
  assert.equal(code, 0);
  assert.doesNotMatch(hba, /172\.30\.241\.14\/32/u);
  assert.match(hba, /host all aster_control_resolver,aster_request,aster_key_runtime,aster_maintainer 172\.30\.241\.12\/32 trust/u);
});

test('admits distinct H5 and password cores without broadening either database role', async () => {
  const { code, hba } = await run('172.30.241.14/32', '172.30.241.15/32');
  assert.equal(code, 0);
  assert.equal(hba.split('\n').filter((row) => row.includes('172.30.241.14/32')).length, 1);
  assert.equal(hba.split('\n').filter((row) => row.includes('172.30.241.15/32')).length, 1);
  assert.doesNotMatch(hba, /172\.30\.241\.0\/24/u);
});

test('rejects a password core address reused by another fixture role', async () => {
  for (const value of ['172.30.241.11/32', '172.30.241.12/32', '172.30.241.13/32', '172.30.241.14/32']) {
    const { code, hba } = await run('172.30.241.14/32', value);
    assert.notEqual(code, 0);
    assert.equal(hba, 'initial\n');
  }
});

test('rejects empty, subnet, and existing fixture addresses without replacing the HBA', async () => {
  for (const value of ['', '172.30.241.0/24', '172.30.241.11/32', '172.30.241.12/32', '172.30.241.13/32']) {
    const { code, hba } = await run(value);
    assert.notEqual(code, 0);
    assert.equal(hba, 'initial\n');
  }
});
