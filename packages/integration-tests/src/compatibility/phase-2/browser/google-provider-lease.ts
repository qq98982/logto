/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One lease owns a private file pair and one precreated provider container lifecycle, including a bounded sequential health poll. */
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  assertGoogleChangedEmailProviderReceipt,
  assertGooglePrimaryRegistrationProviderReceipt,
  assertGoogleReplayProviderReceipt,
  assertGoogleWrongStateProviderReceipt,
} from './google-provider-case-proof.js';
import type { SelectedGoogleProviderLease } from './selected-google-connector-fixture.js';

const execute = promisify(execFile);
const failure = 'Invalid Google provider lease';
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
  'unknown',
]);
export type GoogleProviderLeaseFailureStage =
  | 'docker-environment'
  | 'admission'
  | 'configuration-file'
  | 'receipt-file'
  | 'container-admission'
  | 'configuration-write'
  | 'start'
  | 'health'
  | 'compensation'
  | 'unknown';
const isLeaseStage = (value: unknown): value is GoogleProviderLeaseFailureStage =>
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
class GoogleProviderLeaseError extends TypeError {
  readonly leaseStage: GoogleProviderLeaseFailureStage;

  constructor(stage: GoogleProviderLeaseFailureStage) {
    super(failure);
    this.leaseStage = stage;
  }
}
const stagedFail = (stage: GoogleProviderLeaseFailureStage): never => {
  throw new GoogleProviderLeaseError(stage);
};
export const googleProviderLeaseFailureStage = (
  error: unknown
): GoogleProviderLeaseFailureStage | undefined => {
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

export type GoogleProviderControl = Readonly<{
  run(args: readonly string[], timeoutMilliseconds?: number): Promise<string>;
}>;
export type GoogleProviderHealthTiming = Readonly<{
  now(): number;
  wait(milliseconds: number): Promise<void>;
}>;
export type GoogleProviderLease = SelectedGoogleProviderLease &
  Readonly<{
    takeBrowserCode(): Promise<string>;
    takeWrongStateControlCode(): Promise<string>;
    takePrimaryRegistrationCode(): Promise<string>;
    takeUnverifiedEmailControlCode(): Promise<string>;
    takeOccupiedEmailControlCode(): Promise<string>;
    assertPrimaryRegistrationProviderCase(): Promise<void>;
  }>;

const defaultHealthTiming: GoogleProviderHealthTiming = Object.freeze({
  now: () => Date.now(),
  wait: async (milliseconds) =>
    new Promise<void>((resolve) => {
      setTimeout(resolve, milliseconds);
    }),
});

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

const clearPrivateFile = async (filePath: string, expected: FileIdentity): Promise<void> => {
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
    await handle.truncate(0);
    await handle.sync();
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

export const createDockerGoogleProviderControl = (
  input: Readonly<{ socket: string; home: string; apiVersion: string }>,
  executeCommand: DockerExecution = execute
): GoogleProviderControl => ({
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
  control: GoogleProviderControl;
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
    (state.Status !== 'created' && state.Status !== 'exited') ||
    state.Running !== false ||
    state.ExitCode !== 0
  ) {
    return fail();
  }
  return { id: row.Id };
};

const inspectState = async (
  control: GoogleProviderControl,
  id: string,
  timeoutMilliseconds?: number
): Promise<Record<string, unknown>> =>
  parsedRecord(
    await control.run(['inspect', '--format', '{{json .State}}', id], timeoutMilliseconds)
  );

const waitUntilHealthy = async (
  control: GoogleProviderControl,
  id: string,
  timing: GoogleProviderHealthTiming
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
  control: GoogleProviderControl,
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
  /^Aster Phase 2 Google provider fixture failed \((certificate-read|key-read|config-read|config-validate|receipt-read-or-write|server-create|listen)-(input|file-missing|file-permission|bind|tls|unknown)\)$/u;
const healthFailureEvidence = async (
  input: Readonly<{
    control: GoogleProviderControl;
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

export const prepareGoogleProviderLease = async (
  input: Readonly<{
    control: GoogleProviderControl;
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
    googleSubject: string;
    originalEmail: string;
    changedEmail: string;
    expectedUserinfoMethod: 'GET' | 'POST';
    resetPrivateFilesOnStop?: true;
    healthTiming?: GoogleProviderHealthTiming;
  }>
): Promise<GoogleProviderLease> => {
  let stage: GoogleProviderLeaseFailureStage = 'admission';
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
    for (const value of [
      input.clientId,
      input.clientSecret,
      input.googleSubject,
      input.originalEmail,
      input.changedEmail,
    ]) {
      fixedString(value, 1024);
    }
    if (input.originalEmail === input.changedEmail) {
      return fail();
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
    const stableCode = randomBytes(24).toString('hex');
    const changedCode = randomBytes(24).toString('hex');
    const wrongStateControlCode = randomBytes(24).toString('hex');
    const unverifiedEmailControlCode = randomBytes(24).toString('hex');
    const occupiedEmailControlCode = randomBytes(24).toString('hex');
    const callbackUri = new URL(`/callback/${encodeURIComponent(input.connectorId)}`, origin).href;
    const config = {
      schemaVersion: 1,
      clientId: input.clientId,
      clientSecret: input.clientSecret,
      targetOrigin: origin.origin,
      connectorId: input.connectorId,
      callbackUri,
      stable: {
        code: stableCode,
        accessToken: randomBytes(24).toString('hex'),
        profile: { sub: input.googleSubject, email: input.originalEmail, emailVerified: true },
      },
      changedEmail: {
        code: changedCode,
        accessToken: randomBytes(24).toString('hex'),
        profile: { sub: input.googleSubject, email: input.changedEmail, emailVerified: true },
      },
      wrongStateControl: {
        code: wrongStateControlCode,
        accessToken: randomBytes(24).toString('hex'),
        profile: { sub: input.googleSubject, email: input.changedEmail, emailVerified: true },
      },
      unverifiedEmailControl: {
        code: unverifiedEmailControlCode,
        accessToken: randomBytes(24).toString('hex'),
        profile: {
          sub: `${input.googleSubject}-unverified`,
          email: input.changedEmail,
          emailVerified: false,
        },
      },
      occupiedEmailControl: {
        code: occupiedEmailControlCode,
        accessToken: randomBytes(24).toString('hex'),
        profile: {
          sub: `${input.googleSubject}-occupied`,
          email: input.originalEmail,
          emailVerified: true,
        },
      },
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
      const failedStage = googleProviderLeaseFailureStage(error) ?? stage;
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
    let browserCodeTaken = false;
    let wrongStateControlCodeTaken = false;
    let unverifiedEmailControlCodeTaken = false;
    let occupiedEmailControlCodeTaken = false;
    let stopped = false;
    return Object.freeze({
      associationData: { code: stableCode, redirectUri: callbackUri },
      takeBrowserCode: async () => {
        if (browserCodeTaken || stopped) {
          return fail();
        }
        browserCodeTaken = true;
        return changedCode;
      },
      takeWrongStateControlCode: async () => {
        if (wrongStateControlCodeTaken || stopped) {
          return fail();
        }
        wrongStateControlCodeTaken = true;
        return wrongStateControlCode;
      },
      takePrimaryRegistrationCode: async () => {
        if (browserCodeTaken || stopped) {
          return fail();
        }
        browserCodeTaken = true;
        return stableCode;
      },
      takeUnverifiedEmailControlCode: async () => {
        if (unverifiedEmailControlCodeTaken || stopped) {
          return fail();
        }
        unverifiedEmailControlCodeTaken = true;
        return unverifiedEmailControlCode;
      },
      takeOccupiedEmailControlCode: async () => {
        if (occupiedEmailControlCodeTaken || stopped) {
          return fail();
        }
        occupiedEmailControlCodeTaken = true;
        return occupiedEmailControlCode;
      },
      assertChangedEmailProviderCase: async (mode = 'positive') => {
        try {
          if (mode !== 'positive' && mode !== 'replay') {
            return fail();
          }
          await samePrivateMutableFile(input.configFile, configIdentity);
          await samePrivateMutableFile(input.receiptFile, receiptIdentity);
          const assertReceipt =
            mode === 'replay'
              ? assertGoogleReplayProviderReceipt
              : assertGoogleChangedEmailProviderReceipt;
          await assertReceipt(input.receiptFile, input.expectedUserinfoMethod);
        } catch {
          return fail();
        }
      },
      assertWrongStateProviderCase: async () => {
        try {
          await samePrivateMutableFile(input.configFile, configIdentity);
          await samePrivateMutableFile(input.receiptFile, receiptIdentity);
          await assertGoogleWrongStateProviderReceipt(
            input.receiptFile,
            input.expectedUserinfoMethod
          );
        } catch {
          return fail();
        }
      },
      assertPrimaryRegistrationProviderCase: async () => {
        try {
          await samePrivateMutableFile(input.configFile, configIdentity);
          await samePrivateMutableFile(input.receiptFile, receiptIdentity);
          await assertGooglePrimaryRegistrationProviderReceipt(
            input.receiptFile,
            input.expectedUserinfoMethod
          );
        } catch {
          return fail();
        }
      },
      stop: async () => {
        stopped = true;
        try {
          await quiesceOwnedContainer(input.control, identity.id, true);
          await samePrivateMutableFile(input.configFile, configIdentity);
          await samePrivateMutableFile(input.receiptFile, receiptIdentity);
          await samePrivateMutableFile(input.healthDiagnosticFile, healthDiagnosticIdentity);
          if (input.resetPrivateFilesOnStop) {
            await clearPrivateFile(input.configFile, configIdentity);
            await clearPrivateFile(input.receiptFile, receiptIdentity);
            await clearPrivateFile(input.healthDiagnosticFile, healthDiagnosticIdentity);
          }
        } catch {
          return fail();
        }
      },
    });
  } catch (error: unknown) {
    return stagedFail(googleProviderLeaseFailureStage(error) ?? stage);
  }
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
