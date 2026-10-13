/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One lease owns a private file pair and one precreated provider container lifecycle, including a bounded sequential health poll. */
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import type { WechatProviderObservation } from './common-wechat-web-h5.js';
import type { SelectedWechatProviderLease } from './selected-wechat-connector-fixture.js';

const execute = promisify(execFile);
const failure = 'Invalid WechatBrowser provider lease';
const leaseStages = new Set([
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
]);
export type WechatBrowserProviderLeaseFailureStage =
  | 'docker-environment'
  | 'admission'
  | 'configuration-file'
  | 'receipt-file'
  | 'container-admission'
  | 'configuration-write'
  | 'start'
  | 'health'
  | 'compensation'
  | 'stop-state'
  | 'stop-config-identity'
  | 'stop-receipt-identity'
  | 'unknown';
const isLeaseStage = (value: unknown): value is WechatBrowserProviderLeaseFailureStage =>
  typeof value === 'string' && leaseStages.has(value);
const maximumFileBytes = 65_536;
const healthDeadlineMilliseconds = 60_000;
const healthPollMilliseconds = 250;
const safeName = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const imageId = /^sha256:[a-f0-9]{64}$/u;
const containerId = /^[a-f0-9]{64}$/u;
const apiVersion = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/u;
const fail = (): never => {
  throw new TypeError(failure);
};
class WechatBrowserProviderLeaseError extends TypeError {
  readonly leaseStage: WechatBrowserProviderLeaseFailureStage;

  constructor(stage: WechatBrowserProviderLeaseFailureStage) {
    super(failure);
    this.leaseStage = stage;
  }
}
const stagedFail = (stage: WechatBrowserProviderLeaseFailureStage): never => {
  throw new WechatBrowserProviderLeaseError(stage);
};
export const wechatBrowserProviderLeaseFailureStage = (
  error: unknown
): WechatBrowserProviderLeaseFailureStage | undefined => {
  const message =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'message') : undefined;
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'leaseStage') : undefined;
  const value: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  return message &&
    Object.hasOwn(message, 'value') &&
    message.value === failure &&
    isLeaseStage(value)
    ? value
    : undefined;
};

type FileIdentity = Readonly<{ dev: number; ino: number }>;
type DockerExecution = (
  file: string,
  args: readonly string[],
  options: Readonly<{
    env: Readonly<Record<string, string>>;
    timeout: number;
    maxBuffer: number;
  }>
) => Promise<Readonly<{ stdout: string | Uint8Array; stderr?: string | Uint8Array }>>;

export type WechatBrowserProviderControl = Readonly<{
  run(args: readonly string[], timeoutMilliseconds?: number): Promise<string>;
}>;
export type WechatBrowserProviderHealthTiming = Readonly<{
  now(): number;
  wait(milliseconds: number): Promise<void>;
}>;
export type WechatBrowserProviderLease = SelectedWechatProviderLease &
  Readonly<{
    takeBrowserCode(): Promise<string>;
    takeAccountCode(): Promise<string>;
    takeForeignAccountCode(): Promise<string>;
  }>;

const defaultHealthTiming: WechatBrowserProviderHealthTiming = Object.freeze({
  now: () => Date.now(),
  wait: async (milliseconds) =>
    new Promise<void>((resolve) => {
      setTimeout(resolve, milliseconds);
    }),
});

const readProviderObservation = (
  receiptFile: string,
  channel: 'web' | 'h5',
  identity: FileIdentity
): WechatProviderObservation => {
  const before = lstatSync(receiptFile);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== currentUid() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o600 ||
    before.size > maximumFileBytes ||
    before.dev !== identity.dev ||
    before.ino !== identity.ino ||
    realpathSync(receiptFile) !== receiptFile
  ) {
    return fail();
  }
  const descriptor = openSync(receiptFile, constants.O_RDONLY | constants.O_NOFOLLOW);
  let text: string;
  try {
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== identity.dev ||
      opened.ino !== identity.ino ||
      opened.uid !== currentUid() ||
      opened.nlink !== 1 ||
      (opened.mode & 0o777) !== 0o600 ||
      opened.size !== before.size
    ) {
      return fail();
    }
    text = readFileSync(descriptor, 'utf8');
    const after = fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size) {
      return fail();
    }
  } finally {
    closeSync(descriptor);
  }
  const receipt = parsedRecord(text);
  const { facts } = receipt;
  if (!Array.isArray(facts)) {
    return fail();
  }
  const entries: unknown[] = facts.map((value: unknown) => value);
  const token = entries.filter((value) => plainRecord(value).kind === 'token');
  const userinfo = entries.filter((value) => plainRecord(value).kind === 'userinfo');
  const sms = entries.filter((value) => plainRecord(value).kind === 'sms');
  const expectedProviderRequests = channel === 'web' ? 2 : 1;
  if (
    token.length !== expectedProviderRequests ||
    userinfo.length !== expectedProviderRequests ||
    sms.length > 0 ||
    [...token, ...userinfo].some((value) => plainRecord(value).exact !== true) ||
    sms.some(
      (value) =>
        plainRecord(value).recipientBound !== true || plainRecord(value).signatureValid !== true
    )
  ) {
    return fail();
  }
  return Object.freeze({
    setupRequests: channel === 'web' ? 1 : 0,
    browserRequests: 1,
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });
};

const currentUid = (): number => process.getuid?.() ?? fail();
const plainRecord = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
const parsedRecord = (text: string): Record<string, unknown> => {
  try {
    return plainRecord(JSON.parse(text));
  } catch {
    return fail();
  }
};
const fixedString = (value: string, maximum = 512): string => {
  const hasControlCharacter = [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || code === 127;
  });
  return value.length > 0 && value.length <= maximum && !hasControlCharacter ? value : fail();
};
const exactAbsolutePath = (value: string): string =>
  path.isAbsolute(value) && path.normalize(value) === value ? value : fail();

const inspectPrivateMutableFile = async (
  filePath: string,
  requireEmpty = false
): Promise<FileIdentity> => {
  try {
    exactAbsolutePath(filePath);
    const [state, resolved] = await Promise.all([lstat(filePath), realpath(filePath)]);
    if (
      !state.isFile() ||
      state.isSymbolicLink() ||
      state.uid !== currentUid() ||
      state.nlink !== 1 ||
      (state.mode & 0o777) !== 0o600 ||
      state.size > maximumFileBytes ||
      (requireEmpty && state.size > 0) ||
      resolved !== filePath
    ) {
      return fail();
    }
    return { dev: state.dev, ino: state.ino };
  } catch {
    return fail();
  }
};

const samePrivateMutableFile = async (filePath: string, expected: FileIdentity): Promise<void> => {
  const current = await inspectPrivateMutableFile(filePath);
  if (current.dev !== expected.dev || current.ino !== expected.ino) {
    return fail();
  }
};

const writePrivateConfig = async (
  filePath: string,
  expected: FileIdentity,
  value: unknown
): Promise<void> => {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (bytes.byteLength > maximumFileBytes) {
    return fail();
  }
  const handle = await open(filePath, constants.O_RDWR | constants.O_NOFOLLOW).catch(fail);
  try {
    const opened = await handle.stat();
    if (
      opened.dev !== expected.dev ||
      opened.ino !== expected.ino ||
      opened.uid !== currentUid() ||
      opened.nlink !== 1 ||
      (opened.mode & 0o777) !== 0o600
    ) {
      return fail();
    }
    await handle.truncate(bytes.byteLength);
    const written = await handle.write(bytes, 0, bytes.byteLength, 0);
    if (written.bytesWritten !== bytes.byteLength) {
      return fail();
    }
    await handle.sync();
    const after = await handle.stat();
    if (
      after.dev !== expected.dev ||
      after.ino !== expected.ino ||
      after.size !== bytes.byteLength
    ) {
      return fail();
    }
  } finally {
    await handle.close();
  }
  await samePrivateMutableFile(filePath, expected);
};

const validateDockerEnvironment = async (input: Readonly<{ socket: string; home: string }>) => {
  try {
    exactAbsolutePath(input.socket);
    exactAbsolutePath(input.home);
    const [socketState, socketPath, homeState, homePath] = await Promise.all([
      lstat(input.socket),
      realpath(input.socket),
      lstat(input.home),
      realpath(input.home),
    ]);
    if (
      !socketState.isSocket() ||
      socketState.uid !== currentUid() ||
      socketState.nlink !== 1 ||
      (socketState.mode & 0o077) !== 0 ||
      socketPath !== input.socket ||
      !homeState.isDirectory() ||
      homeState.uid !== currentUid() ||
      (homeState.mode & 0o777) !== 0o700 ||
      homePath !== input.home
    ) {
      return fail();
    }
  } catch {
    return fail();
  }
};

const allowedDockerCommand = (args: readonly string[]): boolean =>
  (args.length === 4 &&
    args[0] === 'inspect' &&
    args[1] === '--format' &&
    (args[2] === '{{json .}}' || args[2] === '{{json .State}}') &&
    (safeName.test(args[3] ?? '') || containerId.test(args[3] ?? ''))) ||
  (args.length === 2 && args[0] === 'start' && containerId.test(args[1] ?? '')) ||
  (args.length === 2 && args[0] === 'healthcheck' && containerId.test(args[1] ?? '')) ||
  (args.length === 4 &&
    args[0] === 'logs' &&
    args[1] === '--tail' &&
    args[2] === '8' &&
    containerId.test(args[3] ?? '')) ||
  (args.length === 4 &&
    args[0] === 'stop' &&
    args[1] === '--time' &&
    args[2] === '5' &&
    containerId.test(args[3] ?? ''));

export const createDockerWechatBrowserProviderControl = (
  input: Readonly<{ socket: string; home: string; apiVersion: string }>,
  executeCommand: DockerExecution = execute
): WechatBrowserProviderControl => ({
  run: async (args, timeoutMilliseconds = 180_000) => {
    if (
      !allowedDockerCommand(args) ||
      !Number.isInteger(timeoutMilliseconds) ||
      timeoutMilliseconds < 1 ||
      timeoutMilliseconds > 180_000
    ) {
      return fail();
    }
    try {
      await validateDockerEnvironment(input);
    } catch {
      return stagedFail('docker-environment');
    }
    try {
      const healthcheck = args[0] === 'healthcheck';
      if (!apiVersion.test(input.apiVersion)) {
        return stagedFail('docker-environment');
      }
      const command = healthcheck
        ? [
            '--silent',
            '--show-error',
            '--connect-timeout',
            '3',
            '--max-time',
            '3',
            '--output',
            '/dev/null',
            '--unix-socket',
            input.socket,
            `http://localhost/v${input.apiVersion}/libpod/containers/${args[1]}/healthcheck`,
          ]
        : args;
      const result = await executeCommand(
        healthcheck ? '/usr/bin/curl' : '/usr/bin/docker',
        command,
        {
          env: { PATH: '/usr/bin:/bin', HOME: input.home, DOCKER_HOST: `unix://${input.socket}` },
          timeout: timeoutMilliseconds,
          maxBuffer: maximumFileBytes,
        }
      );
      const stdout = typeof result.stdout === 'string' ? result.stdout : result.stdout.toString();
      const stderr =
        typeof result.stderr === 'string' ? result.stderr : (result.stderr?.toString() ?? '');
      const output = args[0] === 'logs' ? `${stdout}${stderr}` : stdout;
      return Buffer.byteLength(output) <= maximumFileBytes ? output : fail();
    } catch {
      return fail();
    }
  },
});

type ContainerIdentity = Readonly<{ id: string }>;
type OwnedContainer = Readonly<{
  control: WechatBrowserProviderControl;
  container: string;
  project: string;
  service: string;
  image: string;
}>;

const inspectOwnedContainer = async (input: OwnedContainer): Promise<ContainerIdentity> => {
  const row = parsedRecord(
    await input.control.run(['inspect', '--format', '{{json .}}', input.container])
  );
  const config = plainRecord(row.Config);
  const labels = plainRecord(config.Labels);
  const state = plainRecord(row.State);
  if (
    typeof row.Id !== 'string' ||
    !containerId.test(row.Id) ||
    row.Name !== `/${input.container}` ||
    row.Image !== input.image ||
    (config.Image !== input.image && config.Image !== input.image.slice('sha256:'.length)) ||
    labels['com.docker.compose.project'] !== input.project ||
    labels['com.docker.compose.service'] !== input.service ||
    state.Status !== 'created' ||
    state.Running !== false
  ) {
    return fail();
  }
  return { id: row.Id };
};

const inspectState = async (
  control: WechatBrowserProviderControl,
  id: string,
  timeoutMilliseconds?: number
): Promise<Record<string, unknown>> =>
  parsedRecord(
    await control.run(['inspect', '--format', '{{json .State}}', id], timeoutMilliseconds)
  );

const waitUntilHealthy = async (
  control: WechatBrowserProviderControl,
  id: string,
  timing: WechatBrowserProviderHealthTiming
): Promise<void> => {
  const startedAt = timing.now();
  if (!Number.isFinite(startedAt)) {
    return fail();
  }
  const deadline = startedAt + healthDeadlineMilliseconds;
  let previous = startedAt;
  for (let attempt = 0; attempt <= healthDeadlineMilliseconds / healthPollMilliseconds; attempt++) {
    const beforeInspect = timing.now();
    if (!Number.isFinite(beforeInspect) || beforeInspect < previous || beforeInspect >= deadline) {
      return fail();
    }
    previous = beforeInspect;
    const state = await inspectState(control, id, Math.ceil(deadline - beforeInspect));
    const afterInspect = timing.now();
    if (!Number.isFinite(afterInspect) || afterInspect < previous || afterInspect >= deadline) {
      return fail();
    }
    previous = afterInspect;
    const health = plainRecord(state.Health);
    if (
      state.Status !== 'running' ||
      state.Running !== true ||
      state.ExitCode !== 0 ||
      (health.Status !== 'starting' && health.Status !== 'healthy')
    ) {
      return fail();
    }
    if (health.Status === 'healthy') {
      return;
    }
    await control
      .run(['healthcheck', id], Math.max(1, Math.ceil(Math.min(3000, deadline - afterInspect))))
      .catch(() => null);
    await timing.wait(Math.min(healthPollMilliseconds, deadline - afterInspect));
  }
  return fail();
};

const quiesceOwnedContainer = async (
  control: WechatBrowserProviderControl,
  id: string,
  requireCleanExit: boolean
): Promise<void> => {
  await control.run(['stop', '--time', '5', id]).catch(() => null);
  const state = await inspectState(control, id);
  if (
    state.Running !== false ||
    (state.Status !== 'created' && state.Status !== 'exited') ||
    (requireCleanExit && state.ExitCode !== 0)
  ) {
    return fail();
  }
};

const providerStartupPattern =
  /^Aster Phase 2 WechatBrowser provider fixture failed \((certificate-read|key-read|config-read|config-validate|receipt-read-or-write|server-create|listen)-(input|file-missing|file-permission|bind|tls|unknown)\)$/u;
const healthFailureEvidence = async (
  input: Readonly<{
    control: WechatBrowserProviderControl;
    id: string;
    role: 'oracle' | 'candidate';
  }>
) => {
  let state: Record<string, unknown> = {};
  try {
    state = await inspectState(input.control, input.id);
  } catch {
    state = {};
  }
  let startupFailure = 'absent';
  try {
    const logs = await input.control.run(['logs', '--tail', '8', input.id]);
    const matched = logs
      .split('\n')
      .map((line) => providerStartupPattern.exec(line)?.slice(1).join('-'))
      .filter((value): value is string => value !== undefined);
    if (matched.length === 1) {
      startupFailure = matched[0] ?? 'absent';
    }
  } catch {
    startupFailure = 'absent';
  }
  const status = ['created', 'running', 'exited', 'dead'].includes(String(state.Status))
    ? String(state.Status)
    : 'unknown';
  const exitCode =
    Number.isInteger(state.ExitCode) && Number(state.ExitCode) >= 0 && Number(state.ExitCode) <= 255
      ? Number(state.ExitCode)
      : -1;
  const health =
    typeof state.Health === 'object' && state.Health !== null
      ? plainRecord(state.Health)
      : undefined;
  const healthStatus = ['starting', 'healthy', 'unhealthy'].includes(String(health?.Status))
    ? String(health?.Status)
    : health
      ? 'unknown'
      : 'absent';
  return Object.freeze({
    schemaVersion: 1,
    complete: false,
    role: input.role,
    stateReadable: Object.keys(state).length > 0,
    status,
    exitCode,
    oomKilled: typeof state.OOMKilled === 'boolean' ? state.OOMKilled : null,
    healthPresent: health !== undefined,
    healthStatus,
    startupFailure,
  });
};

export const prepareWechatBrowserProviderLease = async (
  input: Readonly<{
    control: WechatBrowserProviderControl;
    container: string;
    project: string;
    service: string;
    image: string;
    configFile: string;
    receiptFile: string;
    healthDiagnosticFile: string;
    role: 'oracle' | 'candidate';
    targetOrigin: string;
    connectorId: string;
    clientId: string;
    clientSecret: string;
    subject: string;
    channel: 'web' | 'h5';
    smsAccessSecret?: string;
    healthTiming?: WechatBrowserProviderHealthTiming;
  }>
): Promise<WechatBrowserProviderLease> => {
  let stage: WechatBrowserProviderLeaseFailureStage = 'admission';
  try {
    if (
      !safeName.test(input.container) ||
      !safeName.test(input.project) ||
      !safeName.test(input.service) ||
      !imageId.test(input.image) ||
      !/^[A-Za-z0-9._~-]+$/u.test(input.connectorId)
    ) {
      return fail();
    }
    for (const value of [input.clientId, input.clientSecret, input.subject]) {
      fixedString(value, 1024);
    }
    if (input.channel === 'h5') {
      fixedString(input.smsAccessSecret ?? '', 1024);
    }
    const origin = new URL(input.targetOrigin);
    const loopbackHttp =
      origin.protocol === 'http:' &&
      origin.port !== '' &&
      (origin.hostname === 'localhost' ||
        origin.hostname === '127.0.0.1' ||
        origin.hostname === '[::1]');
    if (
      (origin.protocol !== 'https:' && !loopbackHttp) ||
      origin.username !== '' ||
      origin.password !== '' ||
      origin.pathname !== '/' ||
      origin.search !== '' ||
      origin.hash !== ''
    ) {
      return fail();
    }
    const codes = Object.freeze({
      setup: randomBytes(24).toString('hex'),
      browser: randomBytes(24).toString('hex'),
      account: randomBytes(24).toString('hex'),
      foreignAccount: randomBytes(24).toString('hex'),
      noUnionId: randomBytes(24).toString('hex'),
      invalidCode: randomBytes(24).toString('hex'),
      replay: randomBytes(24).toString('hex'),
      malformedProvider: randomBytes(24).toString('hex'),
    });
    const setupCode = codes.setup;
    const browserCode = codes.browser;
    const callbackUri = new URL(`/callback/${encodeURIComponent(input.connectorId)}`, origin).href;
    const config = {
      schemaVersion: 1,
      appId: input.clientId,
      appSecret: input.clientSecret,
      unionId: input.subject,
      codes,
    };
    stage = 'configuration-file';
    const configIdentity = await inspectPrivateMutableFile(input.configFile, true);
    stage = 'receipt-file';
    const receiptIdentity = await inspectPrivateMutableFile(input.receiptFile, true);
    const healthDiagnosticIdentity = await inspectPrivateMutableFile(
      input.healthDiagnosticFile,
      true
    );
    const owned = {
      control: input.control,
      container: input.container,
      project: input.project,
      service: input.service,
      image: input.image,
    };
    stage = 'container-admission';
    const identity = await inspectOwnedContainer(owned);
    stage = 'configuration-write';
    await writePrivateConfig(input.configFile, configIdentity, config);
    try {
      stage = 'start';
      await input.control.run(['start', identity.id]);
      stage = 'health';
      await waitUntilHealthy(input.control, identity.id, input.healthTiming ?? defaultHealthTiming);
    } catch (error: unknown) {
      const failedStage = wechatBrowserProviderLeaseFailureStage(error) ?? stage;
      if (failedStage === 'health') {
        try {
          const evidence = await healthFailureEvidence({
            control: input.control,
            id: identity.id,
            role: input.role,
          });
          await writePrivateConfig(input.healthDiagnosticFile, healthDiagnosticIdentity, evidence);
        } catch {
          // Diagnostic availability never changes provider compensation.
        }
      }
      try {
        await quiesceOwnedContainer(input.control, identity.id, false);
      } catch {
        return stagedFail('compensation');
      }
      return stagedFail(failedStage);
    }
    let accountCodeTaken = false;
    let foreignAccountCodeTaken = false;
    let browserCodeTaken = false;
    let stopped = false;
    return Object.freeze({
      associationData: { code: setupCode, redirectUri: callbackUri },
      takeAccountCode: async () => {
        if (accountCodeTaken || stopped) {
          return fail();
        }
        accountCodeTaken = true;
        return codes.account;
      },
      takeForeignAccountCode: async () => {
        if (foreignAccountCodeTaken || stopped) {
          return fail();
        }
        foreignAccountCodeTaken = true;
        return codes.foreignAccount;
      },
      takeBrowserCode: async () => {
        if (browserCodeTaken || stopped) {
          return fail();
        }
        browserCodeTaken = true;
        return browserCode;
      },
      observation: () => readProviderObservation(input.receiptFile, input.channel, receiptIdentity),
      stop: async () => {
        stopped = true;
        try {
          await quiesceOwnedContainer(input.control, identity.id, false);
        } catch {
          return stagedFail('stop-state');
        }
        try {
          await samePrivateMutableFile(input.configFile, configIdentity);
        } catch {
          return stagedFail('stop-config-identity');
        }
        try {
          await samePrivateMutableFile(input.receiptFile, receiptIdentity);
        } catch {
          return stagedFail('stop-receipt-identity');
        }
      },
    });
  } catch (error: unknown) {
    return stagedFail(wechatBrowserProviderLeaseFailureStage(error) ?? stage);
  }
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
