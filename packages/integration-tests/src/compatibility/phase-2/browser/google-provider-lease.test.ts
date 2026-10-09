/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful fake records sequential provider lifecycles and their closed health evidence. */
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
  createDockerGoogleProviderControl,
  googleProviderLeaseFailureStage,
  type GoogleProviderControl,
  type GoogleProviderHealthTiming,
  prepareGoogleProviderLease,
} from './google-provider-lease.js';

const id = 'a'.repeat(64);
const image = `sha256:${'b'.repeat(64)}`;
const name = 'owned-google-provider';
const project = 'owned-project';
const service = 'google-provider';
type ProviderState = {
  Status: string;
  Running: boolean;
  ExitCode: number;
  Health?: { Status: string };
};

const validReceipt = {
  tokenRequestCount: 2,
  userinfoRequestCount: 2,
  userinfoGetObserved: true,
  userinfoPostObserved: false,
  grantTypeExact: true,
  callbackUriExact: true,
  clientAuthenticationExact: true,
  issuedBearerObserved: true,
  stableSubjectCaseConsumed: true,
  changedEmailCaseConsumed: true,
  wrongStateControlCodeConsumed: false,
  unverifiedEmailControlConsumed: false,
  occupiedEmailControlConsumed: false,
  replayRejected: false,
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
    terminalState?: 'dead' | 'exited';
    wrongIdentity?: boolean;
    configuredImage?: string;
    providerLog?: string;
    initialState?: ProviderState;
  }> = {}
) => {
  let state: ProviderState = input.initialState ?? {
    Status: 'created',
    Running: false,
    ExitCode: 0,
  };
  let healthInspection = 0;
  const calls: string[][] = [];
  const timeouts: Array<number | undefined> = [];
  const admissions: Array<Readonly<{ id: string; status: string; running: boolean }>> = [];
  const control: GoogleProviderControl = {
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
        state = { Status: 'exited', Running: false, ExitCode: 0 };
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
      admissions.push({ id: row.Id, status: state.Status, running: state.Running });
      return JSON.stringify(
        input.configuredImage
          ? { ...row, Config: { ...row.Config, Image: input.configuredImage } }
          : row
      );
    },
  };
  return { control, calls, timeouts, admissions };
};

const createFiles = async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-provider-lease-');
  const configFile = path.join(root, 'config.json');
  const receiptFile = path.join(root, 'receipt.json');
  const healthDiagnosticFile = path.join(root, 'health-diagnostic.json');
  await writeFile(configFile, '', { mode: 0o600 });
  await writeFile(receiptFile, '', { mode: 0o600 });
  await writeFile(healthDiagnosticFile, '', { mode: 0o600 });
  return { root, configFile, receiptFile, healthDiagnosticFile };
};

const prepare = async (
  control: GoogleProviderControl,
  files: Awaited<ReturnType<typeof createFiles>>,
  input: Readonly<{
    healthTiming?: GoogleProviderHealthTiming;
    targetOrigin?: string;
    resetPrivateFilesOnStop?: true;
  }> = {}
) =>
  prepareGoogleProviderLease({
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
    connectorId: 'google-instance',
    clientId: 'client',
    clientSecret: 'private-client-secret',
    googleSubject: 'google-subject',
    originalEmail: 'owner@example.invalid',
    changedEmail: 'changed@example.invalid',
    expectedUserinfoMethod: 'GET',
    ...(input.healthTiming && { healthTiming: input.healthTiming }),
    ...(input.resetPrivateFilesOnStop && { resetPrivateFilesOnStop: true }),
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
    clientId: 'client',
    clientSecret: 'private-client-secret',
    targetOrigin: 'http://localhost:3321',
    connectorId: 'google-instance',
    callbackUri: 'http://localhost:3321/callback/google-instance',
  });
  expect(lease.associationData).toMatchObject({
    redirectUri: 'http://localhost:3321/callback/google-instance',
  });
  const associationCode = Reflect.get(lease.associationData, 'code');
  const browserCode = await lease.takeBrowserCode();
  const controlCode = await lease.takeWrongStateControlCode();
  expect([associationCode, browserCode, controlCode]).toHaveLength(3);
  expect(new Set([associationCode, browserCode, controlCode]).size).toBe(3);
  expect(browserCode).toMatch(/^[a-f0-9]{48}$/u);
  expect(controlCode).toMatch(/^[a-f0-9]{48}$/u);
  await expect(lease.takeBrowserCode()).rejects.toThrow('Invalid Google provider lease');
  await expect(lease.takeWrongStateControlCode()).rejects.toThrow('Invalid Google provider lease');
  expect(calls.slice(0, 3)).toEqual([
    ['inspect', '--format', '{{json .}}', name],
    ['start', id],
    ['inspect', '--format', '{{json .State}}', id],
  ]);
  await writeFile(files.receiptFile, JSON.stringify(validReceipt), { mode: 0o600 });
  await expect(lease.assertChangedEmailProviderCase()).resolves.toBeUndefined();
  await expect(lease.assertChangedEmailProviderCase('replay')).resolves.toBeUndefined();
  await writeFile(
    files.receiptFile,
    JSON.stringify({ ...validReceipt, tokenRequestCount: 3, replayRejected: true }),
    { mode: 0o600 }
  );
  await expect(lease.assertChangedEmailProviderCase('replay')).resolves.toBeUndefined();
  await expect(lease.assertChangedEmailProviderCase()).rejects.toThrow(
    'Invalid Google provider lease'
  );
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

test('reuses the same owned container across three compensated provider controls', async () => {
  const files = await createFiles();
  const shared = createControl();
  for (let cycle = 0; cycle < 3; cycle += 1) {
    const lease = await prepare(shared.control, files, { resetPrivateFilesOnStop: true });
    await lease.stop();
    expect(await readFile(files.configFile, 'utf8')).toBe('');
    expect(await readFile(files.receiptFile, 'utf8')).toBe('');
  }
  expect(shared.admissions).toEqual([
    { id, status: 'created', running: false },
    { id, status: 'exited', running: false },
    { id, status: 'exited', running: false },
  ]);
  expect(shared.calls.filter(([command]) => command === 'start')).toEqual([
    ['start', id],
    ['start', id],
    ['start', id],
  ]);
  await rm(files.root, { recursive: true, force: true });
});

test.each([
  ['running', { Status: 'running', Running: true, ExitCode: 0 }],
  ['stopping', { Status: 'stopping', Running: true, ExitCode: 0 }],
  ['dead', { Status: 'dead', Running: false, ExitCode: 1 }],
  ['failed exit', { Status: 'exited', Running: false, ExitCode: 1 }],
] as const)(
  'rejects a pre-existing %s container before config write or start',
  async (_name, state) => {
    const files = await createFiles();
    const provider = createControl({ initialState: state });
    await expect(prepare(provider.control, files)).rejects.toThrow('Invalid Google provider lease');
    expect(provider.calls).toEqual([['inspect', '--format', '{{json .}}', name]]);
    expect(await readFile(files.configFile, 'utf8')).toBe('');
    expect(await readFile(files.receiptFile, 'utf8')).toBe('');
    await rm(files.root, { recursive: true, force: true });
  }
);

test('rejects foreign ownership before start without retaining private error text', async () => {
  const files = await createFiles();
  const { control, calls } = createControl({ wrongIdentity: true });
  const failure = await prepare(control, files).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(TypeError);
  expect(googleProviderLeaseFailureStage(failure)).toBe('container-admission');
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
    await expect(prepare(control, files)).rejects.toThrow('Invalid Google provider lease');
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
  await expect(lease.takeBrowserCode()).rejects.toThrow('Invalid Google provider lease');
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
  ).rejects.toThrow('Invalid Google provider lease');
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
  ).rejects.toThrow('Invalid Google provider lease');
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
  await expect(prepare(control, files)).rejects.toThrow('Invalid Google provider lease');
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
      'private-token-line\nAster Phase 2 Google provider fixture failed (config-read-file-permission)\n',
  });
  const failure = await prepare(control, files).catch((error: unknown) => error);
  expect(googleProviderLeaseFailureStage(failure)).toBe('health');
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
    expect(googleProviderLeaseFailureStage(failure)).toBe('health');
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
  expect(googleProviderLeaseFailureStage(failure)).toBe('compensation');
  await rm(files.root, { recursive: true, force: true });
});

test('rejects non-loopback HTTP origins before writing config or starting a container', async () => {
  const files = await createFiles();
  const { control, calls } = createControl();
  await expect(
    prepare(control, files, { targetOrigin: 'http://core.example:3321/' })
  ).rejects.toThrow('Invalid Google provider lease');
  expect(calls).toEqual([]);
  expect(await readFile(files.configFile, 'utf8')).toBe('');
  await rm(files.root, { recursive: true, force: true });
});

test('redacts a start transport error and compensates the possibly started provider', async () => {
  const files = await createFiles();
  const { control, calls } = createControl({ startError: true });
  await expect(prepare(control, files)).rejects.toThrow('Invalid Google provider lease');
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
  await expect(lease.stop()).rejects.toThrow('Invalid Google provider lease');
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
    await expect(prepare(control, files)).rejects.toThrow('Invalid Google provider lease');
    expect(calls).toEqual([]);
    await rm(files.root, { recursive: true, force: true });
  }
);

test('runs Docker with a private socket, closed environment, bounds, and exact commands', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-provider-control-');
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
  const control = createDockerGoogleProviderControl(
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
  await expect(control.run(['rm', '-f', name])).rejects.toThrow('Invalid Google provider lease');
  expect(executions).toHaveLength(2);
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
  await rm(root, { recursive: true, force: true });
});
/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
