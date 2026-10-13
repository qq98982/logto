/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, no-restricted-syntax, no-unsafe-finally, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal -- Private files and exact owned containers form bounded attempt leases. */
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import { consumeOwnedBackchannelNotification } from '../clients/backchannel-receiver.js';

import type { PasswordCompromiseFixture } from './common-password-policy.js';
import type { GoogleProviderControl } from './google-provider-lease.js';

const fail = (): never => {
  throw new TypeError('Invalid owned policy/logout fixture');
};
const safeName = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const imageId = /^sha256:[a-f0-9]{64}$/u;
const containerId = /^[a-f0-9]{64}$/u;
const maximumFileBytes = 65_536;
const parsedRecord = (text: string): Record<string, unknown> => {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? Object.fromEntries(Object.entries(value))
      : fail();
  } catch {
    return fail();
  }
};

export type OwnedPrivateService = Readonly<{
  control: GoogleProviderControl;
  container: string;
  project: string;
  service: string;
  image: string;
  receiptFile: string;
  configFile?: string;
  socketFile?: string;
}>;

type FileIdentity = Readonly<{ dev: number; ino: number }>;
const inspectPrivateFile = async (
  filePath: string,
  expectedMode: 0o600,
  requireEmpty: boolean
): Promise<FileIdentity> => {
  if (!path.isAbsolute(filePath) || path.normalize(filePath) !== filePath) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(filePath), realpath(filePath)]);
  if (
    resolved !== filePath ||
    !state.isFile() ||
    state.isSymbolicLink() ||
    state.uid !== process.getuid?.() ||
    state.nlink !== 1 ||
    (state.mode & 0o777) !== expectedMode ||
    state.size > maximumFileBytes ||
    (requireEmpty && state.size > 0)
  ) {
    return fail();
  }
  return { dev: state.dev, ino: state.ino };
};
const writePrivateFile = async (
  filePath: string,
  identity: FileIdentity,
  body: string
): Promise<void> => {
  if (Buffer.byteLength(body) > maximumFileBytes) {
    return fail();
  }
  const handle = await open(filePath, constants.O_RDWR | constants.O_NOFOLLOW);
  try {
    const state = await handle.stat();
    if (
      !state.isFile() ||
      state.dev !== identity.dev ||
      state.ino !== identity.ino ||
      state.nlink !== 1 ||
      state.uid !== process.getuid?.() ||
      (state.mode & 0o777) !== 0o600
    ) {
      return fail();
    }
    await handle.truncate(0);
    if (body) {
      await handle.writeFile(body, 'utf8');
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
};
const readPrivateReceipt = async (
  filePath: string,
  identity: FileIdentity
): Promise<Record<string, unknown>> => {
  const handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const state = await handle.stat();
    if (
      !state.isFile() ||
      state.dev !== identity.dev ||
      state.ino !== identity.ino ||
      state.nlink !== 1 ||
      state.uid !== process.getuid?.() ||
      (state.mode & 0o777) !== 0o600 ||
      state.size < 3 ||
      state.size > maximumFileBytes
    ) {
      return fail();
    }
    const text = await handle.readFile('utf8');
    if (!text.endsWith('\n') || text.trimEnd().includes('\n')) {
      return fail();
    }
    return parsedRecord(text);
  } finally {
    await handle.close();
  }
};
const ownedContainer = async (input: OwnedPrivateService): Promise<string> => {
  if (
    !safeName.test(input.container) ||
    !safeName.test(input.project) ||
    !safeName.test(input.service) ||
    !imageId.test(input.image)
  ) {
    return fail();
  }
  const text = await input.control.run(['inspect', '--format', '{{json .}}', input.container]);
  const row = parsedRecord(text);
  const configValue: unknown = row.Config;
  const config =
    typeof configValue === 'object' && configValue !== null
      ? Object.fromEntries(Object.entries(configValue))
      : fail();
  const labelsValue: unknown = config.Labels;
  const labels =
    typeof labelsValue === 'object' && labelsValue !== null
      ? Object.fromEntries(Object.entries(labelsValue))
      : fail();
  const stateValue: unknown = row.State;
  const state =
    typeof stateValue === 'object' && stateValue !== null
      ? Object.fromEntries(Object.entries(stateValue))
      : fail();
  if (
    typeof row.Id !== 'string' ||
    !containerId.test(row.Id) ||
    row.Name !== `/${input.container}` ||
    row.Image !== input.image ||
    (config.Image !== input.image && config.Image !== input.image.slice(7)) ||
    labels['com.docker.compose.project'] !== input.project ||
    labels['com.docker.compose.service'] !== input.service ||
    !['created', 'exited'].includes(String(state.Status)) ||
    state.Running !== false
  ) {
    return fail();
  }
  return row.Id;
};
const state = async (input: OwnedPrivateService, id: string) => {
  return parsedRecord(await input.control.run(['inspect', '--format', '{{json .State}}', id]));
};
const startOwned = async (input: OwnedPrivateService, id: string): Promise<void> => {
  await input.control.run(['start', id]);
  const deadline = Date.now() + 60_000;
  while (Date.now() <= deadline) {
    const current = await state(input, id);
    if (
      current.Running === true &&
      Object.getOwnPropertyDescriptor(current, 'Health')?.value?.Status === 'healthy'
    ) {
      return;
    }
    await input.control.run(['healthcheck', id], 5000).catch(() => '');
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 250);
    });
  }
  return fail();
};
const stopOwned = async (input: OwnedPrivateService, id: string): Promise<void> => {
  await input.control.run(['stop', '--time', '5', id]);
  const stopped = await state(input, id);
  if (stopped.Running !== false || stopped.Status !== 'exited') {
    return fail();
  }
};
const attempt = async <Result>(
  service: OwnedPrivateService,
  configure: () => Promise<Readonly<{ receipt: FileIdentity; config?: FileIdentity }>>,
  use: () => Promise<Result>,
  verify: (receipt: Record<string, unknown>) => void
): Promise<Result> => {
  const files = await configure();
  let id: string | undefined;
  let primary: unknown;
  try {
    id = await ownedContainer(service);
    await startOwned(service, id);
    const result = await use();
    verify(await readPrivateReceipt(service.receiptFile, files.receipt));
    return result;
  } catch (error: unknown) {
    primary = error;
  } finally {
    const cleanup: unknown[] = [];
    if (id) {
      await stopOwned(service, id).catch((error: unknown) => cleanup.push(error));
    }
    if (service.socketFile) {
      const socketAbsent = await lstat(service.socketFile).then(
        () => false,
        (error: unknown) =>
          typeof error === 'object' &&
          error !== null &&
          Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ENOENT'
      );
      if (!socketAbsent) {
        cleanup.push(new TypeError('Owned backchannel socket remained after stop'));
      }
    }
    await writePrivateFile(service.receiptFile, files.receipt, '').catch((error: unknown) =>
      cleanup.push(error)
    );
    if (files.config && service.configFile) {
      await writePrivateFile(service.configFile, files.config, '').catch((error: unknown) =>
        cleanup.push(error)
      );
    }
    if (cleanup.length > 0) {
      throw new AggregateError(
        [...(primary === undefined ? [] : [primary]), ...cleanup],
        'Owned policy/logout fixture cleanup failed'
      );
    }
  }
  throw primary ?? new TypeError('Owned policy/logout fixture did not complete');
};

export const createOwnedPasswordCompromiseFixture = (
  services: Readonly<Record<'clear' | 'compromised' | 'unavailable', OwnedPrivateService>>,
  role: 'oracle' | 'candidate'
): PasswordCompromiseFixture => ({
  withAttempt: async ({ password, outcome }, use) => {
    const digest = createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);
    const service = services[outcome];
    const responseMode =
      outcome === 'clear'
        ? 'count-zero'
        : outcome === 'compromised'
          ? 'count-one'
          : 'transport-reset';
    return attempt(
      service,
      async () => {
        const configFile = service.configFile ?? fail();
        const [config, receipt] = await Promise.all([
          inspectPrivateFile(configFile, 0o600, false),
          inspectPrivateFile(service.receiptFile, 0o600, true),
        ]);
        await writePrivateFile(
          configFile,
          config,
          `${JSON.stringify({ prefix, suffix, responseMode })}\n`
        );
        return { config, receipt };
      },
      use,
      (receipt) => {
        const allowedAgent = new Set(['absent', 'aster', 'logto', 'undici', 'node', 'other']);
        if (
          receipt.methodGet !== true ||
          receipt.originMatches !== true ||
          receipt.pathShapeMatches !== true ||
          receipt.prefixMatches !== true ||
          receipt.addPaddingPresent !== (role === 'candidate') ||
          !allowedAgent.has(receipt.userAgentProduct as string) ||
          receipt.status !== (outcome === 'unavailable' ? 0 : 200) ||
          Reflect.ownKeys(receipt).length !== 7
        ) {
          fail();
        }
      }
    );
  },
});

export type OwnedBackchannelReceiver = Readonly<{
  consume(): Promise<string | undefined>;
  deliveryStatus(): Promise<number>;
}>;
export const withOwnedBackchannelReceiver = async <Result>(
  input: Readonly<{
    delivery: 'accepted' | 'rejected';
    services: Readonly<Record<'accepted' | 'rejected', OwnedPrivateService>>;
    signal?: AbortSignal;
  }>,
  use: (receiver: OwnedBackchannelReceiver) => Promise<Result>
): Promise<Result> => {
  const service = input.services[input.delivery];
  const expected = input.delivery === 'accepted' ? 204 : 503;
  let receiptIdentity: FileIdentity | undefined;
  const verify = (receipt: Record<string, unknown>) => {
    if (
      receipt.methodPost !== true ||
      receipt.pathMatches !== true ||
      receipt.contentTypeMatches !== true ||
      receipt.originMatches !== true ||
      receipt.bodyWithinLimit !== true ||
      receipt.exactForm !== true ||
      receipt.tokenPresent !== true ||
      receipt.configuredResponseStatus !== expected ||
      receipt.status !== expected ||
      Reflect.ownKeys(receipt).length !== 9
    ) {
      fail();
    }
  };
  return attempt(
    service,
    async () => {
      receiptIdentity = await inspectPrivateFile(service.receiptFile, 0o600, true);
      return { receipt: receiptIdentity };
    },
    async () =>
      use(
        Object.freeze({
          consume: async () =>
            consumeOwnedBackchannelNotification(service.socketFile ?? fail(), input.signal),
          deliveryStatus: async () => {
            const identity = receiptIdentity ?? fail();
            verify(await readPrivateReceipt(service.receiptFile, identity));
            return expected;
          },
        })
      ),
    verify
  );
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, no-restricted-syntax, no-unsafe-finally, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal */
