/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Each mutation owns and removes one isolated provider lifecycle before the next begins. */
import { chmod, mkdtemp, open, readFile, rename, rm, writeFile } from 'node:fs/promises';

import {
  prepareWechatWebProviderLease,
  type WechatWebProviderControl,
  wechatWebProviderLeaseFailureStage,
} from './wechat-web-provider-lease.js';

const containerId = 'a'.repeat(64);
const image = `sha256:${'b'.repeat(64)}`;

test.each([
  'docker-environment',
  'admission',
  'configuration-file',
  'receipt-file',
  'container-admission',
  'configuration-write',
  'start',
  'health',
  'compensation',
  'stop-state',
  'stop-config-identity',
  'stop-receipt-identity',
  'unknown',
] as const)('reads the owned WechatWeb lease stage %s', (stage) => {
  class SyntheticLeaseError extends TypeError {
    readonly leaseStage = stage;
    constructor() {
      super('Invalid WechatWeb provider lease');
    }
  }
  const error = new SyntheticLeaseError();
  expect(wechatWebProviderLeaseFailureStage(error)).toBe(stage);
});

const createLease = async () => {
  const root = await mkdtemp('/var/tmp/henry-build/wechat-provider-lease.');
  await chmod(root, 0o700);
  const configFile = `${root}/configuration.json`;
  const receiptFile = `${root}/receipt.json`;
  const healthDiagnosticFile = `${root}/health.json`;
  await Promise.all(
    [configFile, receiptFile, healthDiagnosticFile].map(async (file) => {
      const handle = await open(file, 'wx', 0o600);
      await handle.close();
    })
  );
  let started = false;
  let stoppedCleanly = false;
  const control: WechatWebProviderControl = {
    run: async (args) => {
      if (args[0] === 'start') {
        started = true;
        stoppedCleanly = false;
        return '';
      }
      if (args[0] === 'stop') {
        started = false;
        stoppedCleanly = true;
        return '';
      }
      if (args[0] === 'inspect' && args[2] === '{{json .State}}') {
        return JSON.stringify(
          started
            ? { Status: 'running', Running: true, ExitCode: 0, Health: { Status: 'healthy' } }
            : { Status: stoppedCleanly ? 'exited' : 'created', Running: false, ExitCode: 0 }
        );
      }
      if (args[0] === 'inspect') {
        return JSON.stringify({
          Id: containerId,
          Name: '/oracle-wechat-provider-1',
          Image: image,
          Config: {
            Image: image,
            Labels: {
              'com.docker.compose.project': 'oracle-project',
              'com.docker.compose.service': 'oracle-wechat-provider',
            },
          },
          State: {
            Status: stoppedCleanly ? 'exited' : 'created',
            Running: false,
            ExitCode: 0,
          },
        });
      }
      throw new TypeError('Unexpected provider control command');
    },
  };
  const prepare = async () =>
    prepareWechatWebProviderLease({
      control,
      container: 'oracle-wechat-provider-1',
      project: 'oracle-project',
      service: 'oracle-wechat-provider',
      image,
      configFile,
      receiptFile,
      healthDiagnosticFile,
      role: 'oracle',
      targetOrigin: 'https://core.example/',
      connectorId: 'wechat-main',
      clientId: 'owned-client',
      clientSecret: 'private-secret',
      subject: 'stable-union-id',
    });
  const lease = await prepare();
  return { root, configFile, receiptFile, lease, prepare };
};

test('resets owned files and reuses a cleanly exited provider container', async () => {
  const { root, configFile, receiptFile, lease, prepare } = await createLease();
  try {
    await lease.stop();
    const [configBytes, receiptBytes] = await Promise.all([
      readFile(configFile),
      readFile(receiptFile),
    ]);
    expect(configBytes.byteLength).toBe(0);
    expect(receiptBytes.byteLength).toBe(0);
    const second = await prepare();
    await second.stop();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

const validReceipt = Object.freeze({
  schemaVersion: 1,
  facts: [
    { kind: 'token', phase: 'setup', method: 'GET', exact: true },
    {
      kind: 'userinfo',
      phase: 'setup',
      method: 'GET',
      exact: true,
      unionIdPresent: true,
      unionIdMatches: true,
    },
    { kind: 'token', phase: 'browser', method: 'GET', exact: true },
    {
      kind: 'userinfo',
      phase: 'browser',
      method: 'GET',
      exact: true,
      unionIdPresent: true,
      unionIdMatches: true,
    },
  ],
});

test('derives request phases and stable UnionID only from an identity-checked receipt', async () => {
  const fixture = await createLease();
  try {
    await writeFile(fixture.receiptFile, `${JSON.stringify(validReceipt)}\n`, { mode: 0o600 });
    await expect(fixture.lease.observation()).resolves.toEqual({
      setupRequests: 1,
      browserRequests: 1,
      tokenExact: true,
      userinfoExact: true,
      unionIdStable: true,
    });
    const original = `${fixture.root}/original-receipt.json`;
    await rename(fixture.receiptFile, original);
    await writeFile(fixture.receiptFile, `${JSON.stringify(validReceipt)}\n`, { mode: 0o600 });
    await expect(fixture.lease.observation()).rejects.toThrow('Invalid WechatWeb provider lease');
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('rejects missing phase or unproven UnionID equality', async () => {
  for (const mutate of [
    (value: typeof validReceipt) => ({
      ...value,
      facts: value.facts.map((fact) => {
        const { phase: _phase, ...rest } = fact;
        return rest;
      }),
    }),
    (value: typeof validReceipt) => ({
      ...value,
      facts: value.facts.map((fact) =>
        fact.kind === 'userinfo' ? { ...fact, unionIdMatches: false } : fact
      ),
    }),
  ]) {
    const fixture = await createLease();
    try {
      await writeFile(fixture.receiptFile, `${JSON.stringify(mutate(validReceipt))}\n`, {
        mode: 0o600,
      });
      await expect(fixture.lease.observation()).rejects.toThrow('Invalid WechatWeb provider lease');
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
