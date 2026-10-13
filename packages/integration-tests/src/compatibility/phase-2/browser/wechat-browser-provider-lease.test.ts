/* eslint-disable complexity, max-lines, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful fake records one provider lifecycle and its closed health evidence. */
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';

import {
  createDockerWechatBrowserProviderControl,
  wechatBrowserProviderLeaseFailureStage,
  type WechatBrowserProviderControl,
  type WechatBrowserProviderHealthTiming,
  prepareWechatBrowserProviderLease,
} from './wechat-browser-provider-lease.js';

const id = 'a'.repeat(64);
const image = `sha256:${'b'.repeat(64)}`;
const name = 'owned-wechatBrowser-provider';
const project = 'owned-project';
const service = 'wechatBrowser-provider';
type ProviderState = {
  Status: string;
  Running: boolean;
  ExitCode: number;
  Health?: { Status: string };
};

const validReceipt = {
  schemaVersion: 1,
  facts: [
    { kind: 'token', method: 'GET', exact: true },
    { kind: 'userinfo', method: 'GET', exact: true },
    { kind: 'token', method: 'GET', exact: true },
    { kind: 'userinfo', method: 'GET', exact: true },
  ],
};

const h5ExternalSmsReceipt = {
  schemaVersion: 1,
  facts: [
    { kind: 'token', method: 'GET', exact: true },
    { kind: 'userinfo', method: 'GET', exact: true },
  ],
};

const h5ReceiptWithForeignSmsFact = {
  schemaVersion: 1,
  facts: [
    ...h5ExternalSmsReceipt.facts,
    { kind: 'sms', recipientBound: true, signatureValid: true },
  ],
};

const containerRow = (state: ProviderState, override: Record<string, unknown> = {}) => ({
  Id: id,
  Name: `/${name}`,
  Image: image,
  Config: {
    Image: image,
    Labels: {
      'com.docker.compose.project': project,
      'com.docker.compose.service': service,
    },
  },
  State: state,
  ...override,
});

const createControl = (
  input: Readonly<{
    health?: readonly string[];
    onHealthInspect?: () => void | Promise<void>;
    startError?: boolean;
    stopError?: boolean;
    stopExitCode?: number;
    terminalState?: 'dead' | 'exited';
    wrongIdentity?: boolean;
    configuredImage?: string;
    providerLog?: string;
  }> = {}
) => {
  let state: ProviderState = { Status: 'created', Running: false, ExitCode: 0 };
  let healthInspection = 0;
  const calls: string[][] = [];
  const timeouts: Array<number | undefined> = [];
  const control: WechatBrowserProviderControl = {
    run: async (args, timeoutMilliseconds) => {
      calls.push([...args]);
      timeouts.push(timeoutMilliseconds);
      if (args[0] === 'start') {
        state = {
          Status: 'running',
          Running: true,
          ExitCode: 0,
          Health: { Status: input.health?.[0] ?? 'healthy' },
        };
        if (input.startError) {
          throw new Error('private-start-transport');
        }
        return id;
      }
      if (args[0] === 'stop') {
        if (input.stopError) {
          throw new Error('private-stop-transport');
        }
        state = { Status: 'exited', Running: false, ExitCode: input.stopExitCode ?? 0 };
        return id;
      }
      if (args[0] === 'logs') {
        return input.providerLog ?? '';
      }
      if (args[2] === '{{json .State}}') {
        if (state.Running) {
          await input.onHealthInspect?.();
        }
        if (state.Running && input.terminalState) {
          state = { Status: input.terminalState, Running: false, ExitCode: 1 };
        }
        if (state.Running && input.health) {
          state.Health = {
            Status:
              input.health[Math.min(healthInspection, input.health.length - 1)] ?? 'unhealthy',
          };
          healthInspection += 1;
        }
        return JSON.stringify(state);
      }
      const row = containerRow(state, input.wrongIdentity ? { Name: '/foreign-provider' } : {});
      return JSON.stringify(
        input.configuredImage
          ? { ...row, Config: { ...row.Config, Image: input.configuredImage } }
          : row
      );
    },
  };
  return { control, calls, timeouts };
};

const createFiles = async () => {
  const root = await mkdtemp('/var/tmp/henry-build/wechat-browser-provider-lease-');
  const configFile = path.join(root, 'config.json');
  const receiptFile = path.join(root, 'receipt.json');
  const healthDiagnosticFile = path.join(root, 'health-diagnostic.json');
  await writeFile(configFile, '', { mode: 0o600 });
  await writeFile(receiptFile, '', { mode: 0o600 });
  await writeFile(healthDiagnosticFile, '', { mode: 0o600 });
  return { root, configFile, receiptFile, healthDiagnosticFile };
};

const prepare = async (
  control: WechatBrowserProviderControl,
  files: Awaited<ReturnType<typeof createFiles>>,
  input: Readonly<{ healthTiming?: WechatBrowserProviderHealthTiming; targetOrigin?: string }> = {}
) =>
  prepareWechatBrowserProviderLease({
    control,
    container: name,
    project,
    service,
    image,
    configFile: files.configFile,
    receiptFile: files.receiptFile,
    healthDiagnosticFile: files.healthDiagnosticFile,
    role: 'oracle',
    targetOrigin: input.targetOrigin ?? 'http://localhost:3321/',
    connectorId: 'wechatBrowser-instance',
    clientId: 'client',
    clientSecret: 'private-client-secret',
    subject: 'wechat-subject',
    channel: 'web',
    ...(input.healthTiming && { healthTiming: input.healthTiming }),
  });

test('starts the exact owned provider, proves its receipt, and stops it idempotently', async () => {
  const files = await createFiles();
  const { control, calls } = createControl();
  const lease = await prepare(control, files);
  const configState = await lstat(files.configFile);
  const config = JSON.parse(await readFile(files.configFile, 'utf8')) as Record<string, unknown>;
  expect(configState.mode & 0o777).toBe(0o600);
  expect(config).toMatchObject({
    schemaVersion: 1,
    appId: 'client',
    appSecret: 'private-client-secret',
    unionId: 'wechat-subject',
  });
  expect(lease.associationData).toMatchObject({
    redirectUri: 'http://localhost:3321/callback/wechatBrowser-instance',
  });
  await expect(lease.takeBrowserCode()).resolves.toMatch(/^[a-f0-9]{48}$/u);
  await expect(lease.takeBrowserCode()).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(calls.slice(0, 3)).toEqual([
    ['inspect', '--format', '{{json .}}', name],
    ['start', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await writeFile(files.receiptFile, JSON.stringify(validReceipt), { mode: 0o600 });
  expect(lease.observation()).toMatchObject({ setupRequests: 1, browserRequests: 1 });
  await lease.stop();
  await lease.stop();
  expect(calls.slice(-4)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test('writes the exact provider schema and keeps H5 SMS evidence in its external lease', async () => {
  const externalFiles = await createFiles();
  const externalControl = createControl();
  const externalLease = await prepareWechatBrowserProviderLease({
    control: externalControl.control,
    container: name,
    project,
    service,
    image,
    configFile: externalFiles.configFile,
    receiptFile: externalFiles.receiptFile,
    healthDiagnosticFile: externalFiles.healthDiagnosticFile,
    role: 'oracle',
    targetOrigin: 'http://localhost:3321/',
    connectorId: 'wechatBrowser-instance',
    clientId: 'client',
    clientSecret: 'private-client-secret',
    subject: 'wechat-subject',
    channel: 'h5',
    smsAccessSecret: 'private-sms-secret',
  });
  const configuration = JSON.parse(await readFile(externalFiles.configFile, 'utf8')) as Record<
    string,
    unknown
  >;
  expect(new Set(Object.keys(configuration))).toEqual(
    new Set(['appId', 'appSecret', 'codes', 'schemaVersion', 'unionId'])
  );
  const codes = configuration.codes as Record<string, unknown>;
  expect(new Set(Object.keys(codes))).toEqual(
    new Set([
      'account',
      'browser',
      'foreignAccount',
      'invalidCode',
      'malformedProvider',
      'noUnionId',
      'replay',
      'setup',
    ])
  );
  expect(new Set(Object.values(codes)).size).toBe(8);
  await writeFile(externalFiles.receiptFile, JSON.stringify(h5ExternalSmsReceipt), { mode: 0o600 });
  expect(externalLease.observation()).toMatchObject({ setupRequests: 0, browserRequests: 1 });
  await writeFile(externalFiles.receiptFile, JSON.stringify(h5ReceiptWithForeignSmsFact), {
    mode: 0o600,
  });
  expect(() => externalLease.observation()).toThrow('Invalid WechatBrowser provider lease');
  await externalLease.stop();
  await rm(externalFiles.root, { recursive: true, force: true });
});

test('refuses a replaced receipt inode before publishing provider observation', async () => {
  const fixture = await createFiles();
  const { control } = createControl();
  const lease = await prepare(control, fixture);
  const replacement = path.join(fixture.root, 'replacement.json');
  await writeFile(replacement, JSON.stringify(validReceipt), { mode: 0o600 });
  await rename(replacement, fixture.receiptFile);
  expect(() => lease.observation()).toThrow('Invalid WechatBrowser provider lease');
  await expect(lease.stop()).rejects.toThrow('Invalid WechatBrowser provider lease');
  await rm(fixture.root, { recursive: true, force: true });
});

test('accepts a signal-derived exit code after stopping the exact owned provider', async () => {
  const files = await createFiles();
  const { control } = createControl({ stopExitCode: 143 });
  const lease = await prepare(control, files);
  await expect(lease.stop()).resolves.toBeUndefined();
  await rm(files.root, { recursive: true, force: true });
});

test('rejects foreign ownership before start without retaining private error text', async () => {
  const files = await createFiles();
  const { control, calls } = createControl({ wrongIdentity: true });
  const failure = await prepare(control, files).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(TypeError);
  expect(wechatBrowserProviderLeaseFailureStage(failure)).toBe('container-admission');
  expect(calls).toEqual([['inspect', '--format', '{{json .}}', name]]);
  expect(JSON.stringify(calls)).not.toContain('private-client-secret');
  expect(await readFile(files.configFile, 'utf8')).toBe('');
  expect(await readFile(files.receiptFile, 'utf8')).toBe('');
  await rm(files.root, { recursive: true, force: true });
});

test('accepts the exact configured image ID without its optional sha256 prefix', async () => {
  const bareFiles = await createFiles();
  const bare = createControl({ configuredImage: image.slice('sha256:'.length) });
  const lease = await prepare(bare.control, bareFiles);
  await lease.stop();
  await rm(bareFiles.root, { recursive: true, force: true });
});

test.each([`sha256:${'c'.repeat(64)}`, `example.invalid/provider@${image}`])(
  'rejects the foreign configured image %s before config write or start',
  async (configuredImage) => {
    const files = await createFiles();
    const { control, calls } = createControl({ configuredImage });
    await expect(prepare(control, files)).rejects.toThrow('Invalid WechatBrowser provider lease');
    expect(calls).toEqual([['inspect', '--format', '{{json .}}', name]]);
    expect(await readFile(files.configFile, 'utf8')).toBe('');
    await rm(files.root, { recursive: true, force: true });
  }
);

test('waits through starting health before returning the owned provider', async () => {
  const files = await createFiles();
  const { control, calls, timeouts } = createControl({ health: ['starting', 'healthy'] });
  let now = 0;
  const waits: number[] = [];
  const lease = await prepare(control, files, {
    healthTiming: {
      now: () => now,
      wait: async (milliseconds) => {
        waits.push(milliseconds);
        now += milliseconds;
      },
    },
  });
  expect(waits).toEqual([250]);
  expect(calls).toContainEqual(['healthcheck', id]);
  expect([timeouts[2], timeouts[4]]).toEqual([60_000, 59_750]);
  await lease.stop();
  await expect(lease.takeBrowserCode()).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(calls.slice(-2)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test('rejects a healthy result returned after the real health deadline and quiesces', async () => {
  const files = await createFiles();
  let now = 0;
  let waitCalled = false;
  const { control, calls, timeouts } = createControl({
    health: ['healthy'],
    onHealthInspect: () => {
      now = 60_000;
    },
  });
  await expect(
    prepare(control, files, {
      healthTiming: {
        now: () => now,
        wait: async () => {
          waitCalled = true;
        },
      },
    })
  ).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(waitCalled).toBe(false);
  expect(timeouts[2]).toBe(60_000);
  expect(calls.slice(-2)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test('rejects persistent starting health at the deadline and quiesces the provider', async () => {
  const files = await createFiles();
  const { control, calls } = createControl({ health: ['starting'] });
  let now = 0;
  const waits: number[] = [];
  await expect(
    prepare(control, files, {
      healthTiming: {
        now: () => now,
        wait: async (milliseconds) => {
          waits.push(milliseconds);
          now += 30_000;
        },
      },
    })
  ).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(waits).toEqual([250, 250]);
  expect(calls.slice(-2)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test.each([
  ['unhealthy', { health: ['unhealthy'] }],
  ['exited', { terminalState: 'exited' }],
  ['dead', { terminalState: 'dead' }],
] as const)('rejects %s provider state and quiesces the owned container', async (_label, state) => {
  const files = await createFiles();
  const { control, calls } = createControl(state);
  await expect(prepare(control, files)).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(calls.slice(-2)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test('writes one closed health diagnostic and discards unmatched private logs', async () => {
  const files = await createFiles();
  const { control } = createControl({
    health: ['unhealthy'],
    providerLog:
      'private-token-line\nAster Phase 2 WechatBrowser provider fixture failed (config-read-file-permission)\n',
  });
  const failure = await prepare(control, files).catch((error: unknown) => error);
  expect(wechatBrowserProviderLeaseFailureStage(failure)).toBe('health');
  const raw = await readFile(files.healthDiagnosticFile, 'utf8');
  expect(raw).not.toContain('private-token-line');
  expect(JSON.parse(raw)).toEqual({
    schemaVersion: 1,
    complete: false,
    role: 'oracle',
    stateReadable: true,
    status: 'running',
    exitCode: 0,
    oomKilled: null,
    healthPresent: true,
    healthStatus: 'unhealthy',
    startupFailure: 'config-read-file-permission',
  });
  await rm(files.root, { recursive: true, force: true });
});

test.each(['mode', 'replaced'] as const)(
  'still quiesces with the original health stage when diagnostic file is %s',
  async (kind) => {
    const files = await createFiles();
    let changed = false;
    const { control, calls } = createControl({
      health: ['unhealthy'],
      onHealthInspect: async () => {
        if (changed) {
          return;
        }
        changed = true;
        if (kind === 'mode') {
          await chmod(files.healthDiagnosticFile, 0o644);
        } else {
          const replacement = path.join(files.root, 'replacement-health-diagnostic');
          await writeFile(replacement, '', { mode: 0o600 });
          await rename(replacement, files.healthDiagnosticFile);
        }
      },
    });
    const failure = await prepare(control, files).catch((error: unknown) => error);
    expect(wechatBrowserProviderLeaseFailureStage(failure)).toBe('health');
    expect(calls.slice(-2)).toEqual([
      ['stop', '--time', '5', id],
      ['inspect', '--format', '{{json .State}}', id],
    ]);
    await rm(files.root, { recursive: true, force: true });
  }
);

test('reports compensation when health cleanup cannot quiesce the owned provider', async () => {
  const files = await createFiles();
  const { control } = createControl({ health: ['unhealthy'], stopError: true });
  const failure = await prepare(control, files).catch((error: unknown) => error);
  expect(wechatBrowserProviderLeaseFailureStage(failure)).toBe('compensation');
  await rm(files.root, { recursive: true, force: true });
});

test('rejects non-loopback HTTP origins before writing config or starting a container', async () => {
  const files = await createFiles();
  const { control, calls } = createControl();
  await expect(
    prepare(control, files, { targetOrigin: 'http://core.example:3321/' })
  ).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(calls).toEqual([]);
  expect(await readFile(files.configFile, 'utf8')).toBe('');
  await rm(files.root, { recursive: true, force: true });
});

test('redacts a start transport error and compensates the possibly started provider', async () => {
  const files = await createFiles();
  const { control, calls } = createControl({ startError: true });
  await expect(prepare(control, files)).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(calls.slice(-2)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test('quiesces the provider before rejecting a replaced receipt inode', async () => {
  const files = await createFiles();
  const { control, calls } = createControl();
  const lease = await prepare(control, files);
  const replacement = path.join(files.root, 'replacement-receipt');
  await writeFile(replacement, '', { mode: 0o600 });
  await rename(replacement, files.receiptFile);
  await expect(lease.stop()).rejects.toThrow('Invalid WechatBrowser provider lease');
  expect(calls.slice(-2)).toEqual([
    ['stop', '--time', '5', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test.each(['mode', 'symlink', 'hardlink'] as const)(
  'rejects a non-private config %s before container inspection',
  async (kind) => {
    const files = await createFiles();
    const { control, calls } = createControl();
    if (kind === 'mode') {
      await chmod(files.configFile, 0o644);
    }
    if (kind === 'symlink') {
      const target = path.join(files.root, 'target');
      await writeFile(target, '', { mode: 0o600 });
      await rm(files.configFile);
      await symlink(target, files.configFile);
    }
    if (kind === 'hardlink') {
      await link(files.configFile, path.join(files.root, 'second-link'));
    }
    await expect(prepare(control, files)).rejects.toThrow('Invalid WechatBrowser provider lease');
    expect(calls).toEqual([]);
    await rm(files.root, { recursive: true, force: true });
  }
);

test('runs Docker with a private socket, closed environment, bounds, and exact commands', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/wechatBrowser-provider-control-');
  const home = path.join(root, 'home');
  const socket = path.join(root, 'engine.sock');
  await mkdir(home, { mode: 0o700 });
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socket, resolve);
  });
  await chmod(socket, 0o600);
  const executions: unknown[][] = [];
  const control = createDockerWechatBrowserProviderControl(
    { socket, home, apiVersion: '5.5.2' },
    async (...args) => {
      executions.push(args);
      return { stdout: '{}' };
    }
  );
  await expect(control.run(['inspect', '--format', '{{json .}}', name])).resolves.toBe('{}');
  const [binary, args, options] = executions[0] as [
    string,
    string[],
    { env: Record<string, string>; timeout: number; maxBuffer: number },
  ];
  expect(binary).toBe('/usr/bin/docker');
  expect(args).toEqual(['inspect', '--format', '{{json .}}', name]);
  expect(options).toEqual({
    env: { PATH: '/usr/bin:/bin', HOME: home, DOCKER_HOST: `unix://${socket}` },
    timeout: 180_000,
    maxBuffer: 65_536,
  });
  await expect(control.run(['healthcheck', id], 2500)).resolves.toBe('{}');
  const [healthBinary, healthArgs, healthOptions] = executions[1] as [
    string,
    string[],
    { env: Record<string, string>; timeout: number; maxBuffer: number },
  ];
  expect(healthBinary).toBe('/usr/bin/curl');
  expect(healthArgs).toEqual([
    '--silent',
    '--show-error',
    '--connect-timeout',
    '3',
    '--max-time',
    '3',
    '--output',
    '/dev/null',
    '--unix-socket',
    socket,
    `http://localhost/v5.5.2/libpod/containers/${id}/healthcheck`,
  ]);
  expect(healthOptions).toMatchObject({ timeout: 2500, maxBuffer: 65_536 });
  await expect(control.run(['rm', '-f', name])).rejects.toThrow(
    'Invalid WechatBrowser provider lease'
  );
  expect(executions).toHaveLength(2);
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
  await rm(root, { recursive: true, force: true });
});
/* eslint-enable complexity, max-lines, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
