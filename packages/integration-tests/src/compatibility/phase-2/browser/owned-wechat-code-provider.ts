/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, no-control-regex, no-restricted-syntax, unicorn/no-array-callback-reference, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function -- One lease validates and owns a precreated private provider container. */
import { randomBytes } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import type { WechatNativeProviderLease } from '../scenarios/common-wechat-native.js';

import type { SelectedWechatProviderLease } from './selected-wechat-connector-fixture.js';
import type {
  WechatBrowserProviderControl,
  WechatBrowserProviderHealthTiming,
} from './wechat-browser-provider-lease.js';

const failure = 'Invalid owned WeChat code provider';
const maximumFileBytes = 65_536;
const safeName = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const imageId = /^sha256:[a-f0-9]{64}$/u;
const containerId = /^[a-f0-9]{64}$/u;
const secretText = /^[^\u0000-\u001F\u007F]{1,1024}$/u;
const fail = (): never => {
  throw new TypeError(failure);
};
const defaultTiming: WechatBrowserProviderHealthTiming = Object.freeze({
  now: () => Date.now(),
  wait: async (milliseconds) =>
    new Promise<void>((resolve) => {
      setTimeout(resolve, milliseconds);
    }),
});

type FileIdentity = Readonly<{ dev: number; ino: number }>;
type Receipt = Readonly<{
  channel: unknown;
  step: unknown;
  kind: unknown;
  methodGet: unknown;
  exactQuery: unknown;
  accepted?: unknown;
  unionIdPresent?: unknown;
}>;
type Input = Readonly<{
  control: WechatBrowserProviderControl;
  container: string;
  project: string;
  service: string;
  image: string;
  configFile: string;
  receiptFile: string;
  clientId: string;
  clientSecret: string;
  wechatSubject: string;
  collisionWechatSubject: string;
  phone: string;
  healthTiming?: WechatBrowserProviderHealthTiming;
  takePhoneCode(recipient: string): Promise<string>;
}>;

const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
const parsed = (text: string): Record<string, unknown> => {
  try {
    return record(JSON.parse(text));
  } catch {
    return fail();
  }
};
const absolutePath = (value: string) =>
  path.isAbsolute(value) && path.normalize(value) === value ? value : fail();
const currentUid = () => process.getuid?.() ?? fail();
const privateFile = async (file: string, empty: boolean): Promise<FileIdentity> => {
  absolutePath(file);
  const [state, resolved] = await Promise.all([lstat(file), realpath(file)]).catch(fail);
  if (
    !state.isFile() ||
    state.isSymbolicLink() ||
    state.uid !== currentUid() ||
    state.nlink !== 1 ||
    (state.mode & 0o777) !== 0o600 ||
    state.size > maximumFileBytes ||
    (empty && state.size > 0) ||
    resolved !== file
  ) {
    return fail();
  }
  return { dev: state.dev, ino: state.ino };
};
const sameFile = async (file: string, identity: FileIdentity) => {
  const current = await privateFile(file, false);
  if (current.dev !== identity.dev || current.ino !== identity.ino) {
    return fail();
  }
};
const writeConfig = async (file: string, identity: FileIdentity, value: unknown) => {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (bytes.byteLength > maximumFileBytes) {
    return fail();
  }
  const handle = await open(file, constants.O_RDWR | constants.O_NOFOLLOW).catch(fail);
  try {
    const state = await handle.stat();
    if (
      state.dev !== identity.dev ||
      state.ino !== identity.ino ||
      state.uid !== currentUid() ||
      state.nlink !== 1 ||
      (state.mode & 0o777) !== 0o600
    ) {
      return fail();
    }
    await handle.truncate(bytes.byteLength);
    const written = await handle.write(bytes, 0, bytes.byteLength, 0);
    if (written.bytesWritten !== bytes.byteLength) {
      return fail();
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
  await sameFile(file, identity);
};

const inspectContainer = async (input: Input) => {
  if (
    !safeName.test(input.container) ||
    !safeName.test(input.project) ||
    !safeName.test(input.service) ||
    !imageId.test(input.image)
  ) {
    return fail();
  }
  const row = parsed(
    await input.control.run(['inspect', '--format', '{{json .}}', input.container])
  );
  const config = record(row.Config);
  const labels = record(config.Labels);
  const state = record(row.State);
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
  return row.Id;
};
const inspectState = async (input: Input, id: string) =>
  parsed(await input.control.run(['inspect', '--format', '{{json .State}}', id]));
const waitHealthy = async (input: Input, id: string) => {
  const timing = input.healthTiming ?? defaultTiming;
  const start = timing.now();
  if (!Number.isFinite(start)) {
    return fail();
  }
  const deadline = start + 60_000;
  for (let attempt = 0; attempt <= 240; attempt++) {
    const now = timing.now();
    if (!Number.isFinite(now) || now < start || now >= deadline) {
      return fail();
    }
    const state = await inspectState(input, id);
    const health = record(state.Health);
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
    await input.control.run(['healthcheck', id], 3000).catch(() => '');
    await timing.wait(250);
  }
  return fail();
};
const stopContainer = async (input: Input, id: string) => {
  await input.control.run(['stop', '--time', '5', id]).catch(() => '');
  const state = await inspectState(input, id);
  if (state.Running !== false || (state.Status !== 'created' && state.Status !== 'exited')) {
    return fail();
  }
};

const receipts = (file: string): Receipt[] => {
  const text = readFileSync(file, 'utf8');
  if (Buffer.byteLength(text) > maximumFileBytes) {
    return fail();
  }
  const lines = text.split('\n').filter(Boolean);
  if (lines.length === 0 || lines.length > 32) {
    return fail();
  }
  return lines.map((line) => record(JSON.parse(line)) as Receipt);
};
const exactBase = (entry: Receipt, channel: 'mini' | 'native', step: string) =>
  entry.channel === channel &&
  entry.step === step &&
  entry.methodGet === true &&
  entry.exactQuery === true;
const exactly = (
  values: readonly Receipt[],
  predicate: (value: Receipt) => boolean,
  count: number
) => values.filter(predicate).length === count;
const assertMiniReceipts = (file: string) => {
  const values = receipts(file);
  if (
    values.some((value) => !exactBase(value, 'mini', 'session')) ||
    !exactly(values, (value) => value.kind === 'setup' && value.accepted === true, 1) ||
    !exactly(values, (value) => value.kind === 'positive' && value.accepted === true, 1) ||
    !exactly(values, (value) => value.kind === 'noUnionId' && value.accepted === true, 1) ||
    !exactly(values, (value) => value.kind === 'invalidCode' && value.accepted === false, 1) ||
    !exactly(values, (value) => value.kind === 'malformedProvider' && value.accepted === true, 1) ||
    !exactly(values, (value) => value.kind === 'replay' && value.accepted === true, 1) ||
    !exactly(values, (value) => value.kind === 'replay' && value.accepted === false, 1) ||
    values.some(
      (value) =>
        ![
          'setup',
          'positive',
          'collision',
          'noUnionId',
          'invalidCode',
          'replay',
          'malformedProvider',
        ].includes(String(value.kind))
    )
  ) {
    return fail();
  }
  const collisions = values.filter((value) => value.kind === 'collision');
  if (collisions.length > 1 || collisions.some((value) => value.accepted !== true)) {
    return fail();
  }
  return Object.freeze({
    setupRequests: 1,
    browserRequests: 1,
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });
};
const assertNativeReceipts = (file: string) => {
  const values = receipts(file);
  const tokens = values.filter((value) => value.step === 'token');
  const users = values.filter((value) => value.step === 'userinfo');
  if (
    values.some(
      (value) => !exactBase(value, 'native', value.step === 'token' ? 'token' : 'userinfo')
    ) ||
    !exactly(tokens, (value) => value.kind === 'setup' && value.accepted === true, 1) ||
    !exactly(users, (value) => value.kind === 'setup' && value.unionIdPresent === true, 1) ||
    !exactly(tokens, (value) => value.kind === 'positive' && value.accepted === true, 1) ||
    !exactly(users, (value) => value.kind === 'positive' && value.unionIdPresent === true, 1) ||
    !exactly(tokens, (value) => value.kind === 'noUnionId' && value.accepted === true, 1) ||
    !exactly(users, (value) => value.kind === 'noUnionId' && value.unionIdPresent === false, 1) ||
    !exactly(tokens, (value) => value.kind === 'invalidCode' && value.accepted === false, 1) ||
    !exactly(tokens, (value) => value.kind === 'malformedProvider' && value.accepted === true, 1) ||
    !exactly(tokens, (value) => value.kind === 'replay' && value.accepted === true, 1) ||
    !exactly(tokens, (value) => value.kind === 'replay' && value.accepted === false, 1) ||
    !exactly(users, (value) => value.kind === 'replay' && value.unionIdPresent === true, 1)
  ) {
    return fail();
  }
  return Object.freeze({
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  } as const);
};

const prepare = async (input: Input, channel: 'mini' | 'native') => {
  for (const value of [
    input.clientId,
    input.clientSecret,
    input.wechatSubject,
    input.collisionWechatSubject,
  ]) {
    if (!secretText.test(value)) {
      return fail();
    }
  }
  if (input.wechatSubject === input.collisionWechatSubject || !/^\+?\d{8,15}$/u.test(input.phone)) {
    return fail();
  }
  const configIdentity = await privateFile(input.configFile, true);
  const receiptIdentity = await privateFile(input.receiptFile, true);
  const id = await inspectContainer(input);
  const code = () => randomBytes(24).toString('hex');
  const codes = Object.fromEntries(
    [
      'setup',
      'browser',
      'account',
      'foreignAccount',
      'miniSetup',
      'miniPositive',
      'miniCollision',
      'miniNoUnionId',
      'miniInvalidCode',
      'miniReplay',
      'miniMalformedProvider',
      'nativeSetup',
      'nativePositive',
      'nativeNoUnionId',
      'nativeInvalidCode',
      'nativeReplay',
      'nativeMalformedProvider',
    ].map((name) => [name, code()])
  ) as Record<string, string>;
  await writeConfig(input.configFile, configIdentity, {
    schemaVersion: 1,
    appId: input.clientId,
    appSecret: input.clientSecret,
    unionId: input.wechatSubject,
    collisionUnionId: input.collisionWechatSubject,
    codes,
  });
  try {
    await input.control.run(['start', id]);
    await waitHealthy(input, id);
  } catch {
    await stopContainer(input, id).catch(() => {});
    return fail();
  }
  let stopped = false;
  const taken = new Set<string>();
  const takeOnce = async (name: string) => {
    if (stopped || taken.has(name)) {
      return fail();
    }
    taken.add(name);
    return codes[name] ?? fail();
  };
  const replay = channel === 'mini' ? 'miniReplay' : 'nativeReplay';
  const finish = async () => {
    stopped = true;
    await stopContainer(input, id);
    await Promise.all([
      sameFile(input.configFile, configIdentity),
      sameFile(input.receiptFile, receiptIdentity),
    ]);
  };
  return { codes, takeOnce, replay, finish, stopped: () => stopped };
};

export const prepareOwnedWechatMiniProvider = async (
  input: Input
): Promise<SelectedWechatProviderLease & Readonly<{ takeCode(): Promise<string> }>> => {
  const lease = await prepare(input, 'mini');
  return Object.freeze({
    associationData: { code: lease.codes.miniSetup ?? fail() },
    takeCode: async () => lease.takeOnce('miniPositive'),
    takeCollisionCode: async () => lease.takeOnce('miniCollision'),
    takeControlCode: async (kind: 'noUnionId' | 'invalidCode' | 'replay' | 'malformedProvider') =>
      kind === 'replay'
        ? lease.stopped()
          ? fail()
          : (lease.codes[lease.replay] ?? fail())
        : lease.takeOnce(`mini${kind[0]?.toUpperCase() ?? ''}${kind.slice(1)}`),
    takePhoneCode: async (recipient: string) => {
      if (lease.stopped() || recipient !== input.phone) {
        return fail();
      }
      const value = await input.takePhoneCode(recipient);
      return /^\d{6}$/u.test(value) ? value : fail();
    },
    observation: () => assertMiniReceipts(input.receiptFile),
    stop: lease.finish,
  });
};

export const prepareOwnedWechatNativeProvider = async (
  input: Input
): Promise<WechatNativeProviderLease> => {
  const lease = await prepare(input, 'native');
  return Object.freeze({
    associationData: { code: lease.codes.nativeSetup ?? fail() },
    takeCode: async () => lease.takeOnce('nativePositive'),
    takeControlCode: async (kind) =>
      kind === 'replay'
        ? lease.stopped()
          ? fail()
          : (lease.codes[lease.replay] ?? fail())
        : lease.takeOnce(`native${kind[0]?.toUpperCase() ?? ''}${kind.slice(1)}`),
    observation: async () => assertNativeReceipts(input.receiptFile),
    stop: lease.finish,
  });
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, no-control-regex, no-restricted-syntax, unicorn/no-array-callback-reference, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function */
