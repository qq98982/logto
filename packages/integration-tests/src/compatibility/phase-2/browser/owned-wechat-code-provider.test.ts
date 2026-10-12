/* eslint-disable no-bitwise, unicorn/no-await-expression-member, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful fake models one owned container lifecycle. */
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  prepareOwnedWechatMiniProvider,
  prepareOwnedWechatNativeProvider,
} from './owned-wechat-code-provider.js';
import type { WechatBrowserProviderControl } from './wechat-browser-provider-lease.js';

const id = 'a'.repeat(64);
const image = `sha256:${'b'.repeat(64)}`;
const container = 'owned-wechat-provider';
const project = 'owned-project';
const service = 'wechat-provider';

const files = async () => {
  const root = await mkdtemp('/var/tmp/henry-build/owned-wechat-code-provider-');
  const configFile = path.join(root, 'config.json');
  const receiptFile = path.join(root, 'receipt.ndjson');
  await writeFile(configFile, '', { mode: 0o600 });
  await writeFile(receiptFile, '', { mode: 0o600 });
  return { root, configFile, receiptFile };
};

const controlled = (stopRunning = false) => {
  let state: Record<string, unknown> = { Status: 'created', Running: false, ExitCode: 0 };
  const calls: string[][] = [];
  const control: WechatBrowserProviderControl = {
    run: async (args) => {
      calls.push([...args]);
      if (args[0] === 'start') {
        state = {
          Status: 'running',
          Running: true,
          ExitCode: 0,
          Health: { Status: 'healthy' },
        };
        return id;
      }
      if (args[0] === 'stop') {
        state = stopRunning
          ? { Status: 'running', Running: true, ExitCode: 0, Health: { Status: 'healthy' } }
          : { Status: 'exited', Running: false, ExitCode: 0 };
        return id;
      }
      if (args[2] === '{{json .State}}') {
        return JSON.stringify(state);
      }
      return JSON.stringify({
        Id: id,
        Name: `/${container}`,
        Image: image,
        Config: {
          Image: image,
          Labels: {
            'com.docker.compose.project': project,
            'com.docker.compose.service': service,
          },
        },
        State: state,
      });
    },
  };
  return { control, calls };
};

const input = (
  control: WechatBrowserProviderControl,
  fixture: Awaited<ReturnType<typeof files>>
) => ({
  control,
  container,
  project,
  service,
  image,
  configFile: fixture.configFile,
  receiptFile: fixture.receiptFile,
  clientId: 'owned-client',
  clientSecret: 'owned-secret',
  wechatSubject: 'owned-subject',
  collisionWechatSubject: 'collision-subject',
  phone: '+819012345678',
  takePhoneCode: async (recipient: string) => (recipient === '+819012345678' ? '123456' : ''),
});

const miniReceipts = [
  ['setup', true],
  ['positive', true],
  ['noUnionId', true],
  ['invalidCode', false],
  ['malformedProvider', true],
  ['replay', true],
  ['replay', false],
].map(([kind, accepted]) => ({
  channel: 'mini',
  step: 'session',
  kind,
  methodGet: true,
  exactQuery: true,
  accepted,
}));

test('refuses a pre-populated configuration before inspecting or starting the container', async () => {
  const fixture = await files();
  try {
    await writeFile(fixture.configFile, '{"foreign":true}\n', { mode: 0o600 });
    const { control, calls } = controlled();
    await expect(prepareOwnedWechatMiniProvider(input(control, fixture))).rejects.toThrow(
      'Invalid owned WeChat code provider'
    );
    expect(calls).toEqual([]);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('Mini lease writes all distinct private codes, binds SMS, proves receipts, and stops owned container', async () => {
  const fixture = await files();
  try {
    const { control, calls } = controlled();
    const lease = await prepareOwnedWechatMiniProvider(input(control, fixture));
    const config = JSON.parse(await readFile(fixture.configFile, 'utf8')) as {
      appSecret: string;
      codes: Record<string, string>;
    };
    expect((await lstat(fixture.configFile)).mode & 0o777).toBe(0o600);
    expect(config.appSecret).toBe('owned-secret');
    expect(Object.keys(config.codes)).toHaveLength(17);
    expect(new Set(Object.values(config.codes)).size).toBe(17);
    expect(lease.associationData.code).toBe(config.codes.miniSetup);
    await expect(lease.takeCode()).resolves.toBe(config.codes.miniPositive);
    await expect(lease.takeCode()).rejects.toThrow('Invalid owned WeChat code provider');
    await expect(lease.takePhoneCode?.('+819012345678')).resolves.toBe('123456');
    await expect(lease.takePhoneCode?.('+819099999999')).rejects.toThrow(
      'Invalid owned WeChat code provider'
    );
    const replay = await lease.takeControlCode?.('replay');
    await expect(lease.takeControlCode?.('replay')).resolves.toBe(replay);
    await writeFile(
      fixture.receiptFile,
      `${miniReceipts.map((value) => JSON.stringify(value)).join('\n')}\n`,
      { mode: 0o600 }
    );
    expect(lease.observation()).toMatchObject({ authorizationExact: true, unionIdStable: true });
    await lease.stop();
    expect(calls.some((value) => value[0] === 'stop' && value[3] === id)).toBe(true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('Native lease rejects Mini receipts and reports an owned-container cleanup failure', async () => {
  const fixture = await files();
  try {
    const { control } = controlled(true);
    const lease = await prepareOwnedWechatNativeProvider(input(control, fixture));
    await writeFile(fixture.receiptFile, `${JSON.stringify(miniReceipts[0])}\n`, { mode: 0o600 });
    await expect(lease.observation()).rejects.toThrow('Invalid owned WeChat code provider');
    await expect(lease.stop()).rejects.toThrow('Invalid owned WeChat code provider');
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});
/* eslint-enable no-bitwise, unicorn/no-await-expression-member, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
