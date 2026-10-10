import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { createSmsProviderRuntime, clearSmsProviderRuntime } from './phase2-sms-provider-runtime.mjs';
const owned = async (use) => {
  const parent = await mkdtemp('/var/tmp/henry-build/sms-runtime-'); await chmod(parent, 0o700);
  try { await use(path.join(parent, 's')); } finally { await rm(parent, { recursive: true, force: true }); }
};
test('creates separate private per-target credentials and clears only stopped fixture material', async () => {
  await owned(async (root) => {
    const roles = await createSmsProviderRuntime(root);
    const configurations = [];
    for (const role of ['oracle', 'candidate']) {
      const data = JSON.parse(await readFile(roles[role].configurationFile, 'utf8')); configurations.push(data);
      assert.equal((await lstat(roles[role].configurationFile)).mode & 0o777, 0o600);
      assert.deepEqual(JSON.parse(await readFile(roles[role].inputFile, 'utf8')),
        { schemaVersion: 1, configurationFile: roles[role].configurationFile, controlSocket: roles[role].controlSocket });
    }
    assert.notEqual(configurations[0].accessKeySecret, configurations[1].accessKeySecret);
    assert.notEqual(configurations[0].controlCapability, configurations[1].controlCapability);
    await clearSmsProviderRuntime(root);
    for (const role of ['oracle', 'candidate']) for (const name of ['configurationFile', 'receiptFile', 'inputFile'])
      assert.equal((await lstat(roles[role][name])).size, 0);
  });
});
test('preserves credentials while an owned control socket is active', async () => {
  await owned(async (root) => {
    const roles = await createSmsProviderRuntime(root), server = createServer();
    await new Promise((resolve) => server.listen(roles.oracle.controlSocket, resolve));
    try {
      await assert.rejects(clearSmsProviderRuntime(root), /Invalid Phase 2 SMS provider runtime/u);
      assert.ok((await lstat(roles.oracle.configurationFile)).size > 0);
    } finally { await new Promise((resolve) => server.close(resolve)); }
  });
});
test('refuses existing roots and altered file permissions without clearing admitted peer files', async () => {
  await owned(async (root) => {
    const roles = await createSmsProviderRuntime(root);
    await assert.rejects(createSmsProviderRuntime(root));
    await chmod(roles.candidate.inputFile, 0o644);
    await assert.rejects(clearSmsProviderRuntime(root));
    assert.ok((await lstat(roles.oracle.configurationFile)).size > 0);
  });
});
