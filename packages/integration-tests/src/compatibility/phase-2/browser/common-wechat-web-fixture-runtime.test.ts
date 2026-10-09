/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Lease tests retain one scoped credential handle to prove closure. */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { readCommonWechatWebFixtureRuntime } from './common-wechat-web-fixture-runtime.js';

const row = Object.freeze({
  schemaVersion: 1,
  container: 'oracle-wechat-provider-1',
  project: 'oracle-project',
  service: 'oracle-wechat-provider',
  image: `sha256:${'a'.repeat(64)}`,
  configFile: '/private/wechat/configuration.json',
  receiptFile: '/private/wechat/receipt.json',
  healthDiagnosticFile: '/private/wechat/health.json',
  dockerHome: '/private/docker-home',
  apiVersion: '5.0.0',
  wechatSubject: 'common-wechat-web-union',
  originalOwnerEmail: 'owner@example.invalid',
  unionId: 'common-wechat-web-union',
  channel: 'web',
  clientId: 'private-client-id',
  clientSecret: 'private-client-secret',
});

const createInput = async (value: unknown = row) => {
  const root = await mkdtemp('/var/tmp/henry-build/wechat-web-fixture-runtime.');
  const file = path.join(root, 'provider-input.json');
  await writeFile(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return { root, file };
};

test('binds the canonical UnionID subject and closes the credential lease', async () => {
  const input = await createInput();
  try {
    const runtime = await readCommonWechatWebFixtureRuntime(input.file, '/private/podman.sock');
    expect(runtime.provider).toEqual({
      wechatSubject: row.unionId,
      originalOwnerEmail: row.originalOwnerEmail,
    });
    let retained: { getClientId(): string } | undefined;
    await expect(
      runtime.withProviderCredentialLease(async (lease) => {
        retained = lease;
        expect(lease.getClientId()).toBe(row.clientId);
        expect(lease.getClientSecret()).toBe(row.clientSecret);
        expect(() => JSON.stringify(lease)).toThrow('Invalid Common WeChat Web fixture runtime');
        return 'complete';
      })
    ).resolves.toBe('complete');
    expect(() => retained?.getClientId()).toThrow('Invalid Common WeChat Web fixture runtime');
    await expect(
      runtime.prepareProvider({
        connectorId: 'wechat-main',
        clientId: row.clientId,
        clientSecret: row.clientSecret,
        targetOrigin: 'https://core.example/',
        role: 'oracle',
        subject: 'different-union-id',
      })
    ).rejects.toThrow('Invalid Common WeChat Web fixture runtime');
  } finally {
    await rm(input.root, { recursive: true, force: true });
  }
});

test('rejects a provider descriptor whose connector subject differs from UnionID', async () => {
  const input = await createInput({ ...row, wechatSubject: 'different-subject' });
  try {
    await expect(
      readCommonWechatWebFixtureRuntime(input.file, '/private/podman.sock')
    ).rejects.toThrow('Invalid Common WeChat Web fixture runtime');
  } finally {
    await rm(input.root, { recursive: true, force: true });
  }
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
