/* eslint-disable max-lines, complexity, no-restricted-syntax, no-constant-condition, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/no-loop-func, @typescript-eslint/no-unnecessary-condition -- This runtime owns bounded public metadata reads, short-lived filesystem mutation watchers, and the closed JSON protocol requires explicit nulls for absent finish facts. */
import { createHash } from 'node:crypto';
import { constants as fsConstants, watch, type FSWatcher } from 'node:fs';
import { access, chmod, lstat, mkdir, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { types as nodeTypes } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../model.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../phase-1/clients/command-provisioner.js';

import type { SanitizedTokenObservation } from './clients/client-credentials.js';
import { phase2StateRequestKind, phase2StateTerminalKind } from './driver-protocol.js';
import type { ProvisionedPhase2Fixture } from './fixtures.js';
import type { Phase2DifferentialScenarioId } from './profile.js';
import type {
  Phase2EffectiveAuthorityFacts,
  Phase2SideEffectFacts,
  Phase2SigningUseFacts,
} from './projections/client-credentials.js';
import type {
  Phase2ArtifactIdentity,
  Phase2SocketIdentity,
  Phase2TopologyIdentity,
} from './provenance.js';
import type {
  AccountPasswordProofScenarioId,
  AccountPasswordProofStateDriver,
  AccountPasswordProofStateHandle,
} from './scenarios/account-password-proof-expiry.js';
import type {
  Phase2ScenarioStateDriver,
  Phase2ScenarioStateObservation,
} from './scenarios/client-credentials.js';
import type {
  DeviceAuthorizationScenarioId,
  DeviceScenarioHandle,
  DeviceScenarioStateAction,
  DeviceScenarioStateDriver,
} from './scenarios/device-authorization.js';

export type Phase2RuntimeDriver = Readonly<{
  path: string;
  sha256: string;
  controlSocket: string;
}>;

export type Phase2TargetDescriptor = Readonly<{
  schemaVersion: 1;
  kind: 'oracle' | 'candidate';
  sourceCommit: string;
  imageDigest: string;
  projectName: string;
  primaryContainerId: string;
  foreignContainerId: string;
  target: TargetConfig;
  foreignTarget: TargetConfig;
  stateDriver: Phase2RuntimeDriver;
  fixtureExecutable?: Readonly<{ path: string; sha256: string }>;
  fixtureSocket?: string;
  invariantDriver?: Phase2RuntimeDriver;
  fetchObserverReceiptFile: string;
}>;

export type Phase2MutableFileIdentity = Readonly<{
  path: string;
  dev: string;
  ino: string;
  uid: number;
  mode: number;
  nlink: number;
}>;

export type VerifiedPhase2Target = Readonly<{
  descriptor: Phase2TargetDescriptor;
  topology: Phase2TopologyIdentity;
  fixtureExecutable?: Phase2ArtifactIdentity;
  stateDriver: Phase2ArtifactIdentity;
  invariantDriver?: Phase2ArtifactIdentity;
  fixtureSocket?: Phase2SocketIdentity;
  stateControlSocket: Phase2SocketIdentity;
  invariantControlSocket?: Phase2SocketIdentity;
  fetchObserverReceiptFile: Phase2MutableFileIdentity;
}>;

export type Phase2InvocationFence = Readonly<{
  run<Result>(operation: () => Promise<Result>): Promise<Result>;
  assertStable(): Promise<void>;
}>;

export type PreparedPhase2Target = Readonly<{
  descriptor: Phase2TargetDescriptor;
  topology: Phase2TopologyIdentity;
  fence: Phase2InvocationFence;
  fetchObserverReceiptFile: Phase2MutableFileIdentity;
}>;

type StateDriverOptions = Readonly<{
  descriptor: Phase2TargetDescriptor;
  identityFence?: Phase2InvocationFence;
  runner?: (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;
}>;

const diagnostic = 'Invalid Phase 2 runtime';
const maximumHttpBytes = 1024 * 1024;
const maximumProcessBytes = 65_536;
const processTimeoutMs = 120_000;
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const handlePattern = /^[0-9a-f]{32}$/u;
const accountIdPattern = /^[A-Za-z0-9._~-]{1,128}$/u;
const signingKeyIdPattern = /^[A-Za-z0-9._~-]{1,256}$/u;
const commitPattern = /^[0-9a-f]{40}$/u;
const imagePattern = /^sha256:[0-9a-f]{64}$/u;
const containerPattern = /^[0-9a-f]{64}$/u;
const projectPattern = /^aster-phase2-client-credentials-[0-9a-f]{16}$/u;
const shaPattern = /^[0-9a-f]{64}$/u;
const preparedTargetCapabilities = new WeakSet<object>();

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.prototype.toString.call(value) !== '[object Object]'
  ) {
    return fail();
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      return fail();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }
  }
  return value as Record<string, unknown>;
};

const exactRecord = (
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = []
): Record<string, unknown> => {
  const result = record(value);
  const keys = Object.keys(result);
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !keys.includes(key)) ||
    keys.some((key) => !allowed.has(key)) ||
    keys.length > required.length + optional.length
  ) {
    return fail();
  }
  return result;
};

const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const validateAbsolutePath = (value: unknown): string =>
  typeof value === 'string' &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/\p{Cc}/u.test(value) &&
  Buffer.byteLength(value) <= 4096
    ? value
    : fail();

const validateDriver = (value: unknown): Phase2RuntimeDriver => {
  const driver = exactRecord(value, ['path', 'sha256', 'controlSocket']);
  const sha256 = own(driver, 'sha256');
  return Object.freeze({
    path: validateAbsolutePath(own(driver, 'path')),
    sha256: typeof sha256 === 'string' && shaPattern.test(sha256) ? sha256 : fail(),
    controlSocket: validateAbsolutePath(own(driver, 'controlSocket')),
  });
};

const validateTarget = (value: unknown, label: TargetConfig['label']): TargetConfig => {
  const target = exactRecord(value, ['label', 'coreUrl', 'adminUrl']);
  if (own(target, 'label') !== label) {
    return fail();
  }
  const coreUrl = own(target, 'coreUrl');
  const adminUrl = own(target, 'adminUrl');
  if (typeof coreUrl !== 'string' || typeof adminUrl !== 'string') {
    return fail();
  }
  for (const raw of [coreUrl, adminUrl]) {
    const url = new URL(raw);
    if (
      (url.protocol !== 'http:' && url.protocol !== 'https:') ||
      url.username !== '' ||
      url.password !== '' ||
      url.pathname !== '/' ||
      url.search !== '' ||
      url.hash !== ''
    ) {
      return fail();
    }
  }
  return Object.freeze({ label, coreUrl, adminUrl });
};

const readBoundedResponseBody = async (
  response: Response,
  maximumBytes: number
): Promise<Uint8Array> => {
  const contentLength = response.headers.get('content-length');
  if (
    contentLength !== null &&
    (!/^(?:0|[1-9]\d*)$/u.test(contentLength) || Number(contentLength) > maximumBytes)
  ) {
    await response.body?.cancel().catch(() => false);
    return fail();
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel().catch(() => false);
        return fail();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
};

export const validatePhase2TargetDescriptor = (value: unknown): Phase2TargetDescriptor => {
  const source = exactRecord(
    value,
    [
      'schemaVersion',
      'kind',
      'sourceCommit',
      'imageDigest',
      'projectName',
      'primaryContainerId',
      'foreignContainerId',
      'target',
      'foreignTarget',
      'stateDriver',
      'fetchObserverReceiptFile',
    ],
    ['fixtureExecutable', 'fixtureSocket', 'invariantDriver']
  );
  const kind = own(source, 'kind');
  if (own(source, 'schemaVersion') !== 1 || (kind !== 'oracle' && kind !== 'candidate')) {
    return fail();
  }
  const label = kind === 'oracle' ? 'oracle' : 'candidate';
  const target = validateTarget(own(source, 'target'), label);
  const foreignTarget = validateTarget(own(source, 'foreignTarget'), label);
  if (target.coreUrl === foreignTarget.coreUrl || target.adminUrl === foreignTarget.adminUrl) {
    return fail();
  }
  const fixtureSocket = own(source, 'fixtureSocket');
  const fixtureExecutable = own(source, 'fixtureExecutable');
  const invariantDriver = own(source, 'invariantDriver');
  if (
    (kind === 'candidate' &&
      (fixtureSocket === undefined ||
        fixtureExecutable === undefined ||
        invariantDriver === undefined)) ||
    (kind === 'oracle' &&
      (fixtureSocket !== undefined ||
        fixtureExecutable !== undefined ||
        invariantDriver !== undefined))
  ) {
    return fail();
  }
  const sourceCommit = own(source, 'sourceCommit');
  const imageDigest = own(source, 'imageDigest');
  const projectName = own(source, 'projectName');
  const primaryContainerId = own(source, 'primaryContainerId');
  const foreignContainerId = own(source, 'foreignContainerId');
  const expected =
    kind === 'oracle'
      ? [
          'http://localhost:3311/',
          'http://localhost:3411/',
          'http://localhost:3312/',
          'http://localhost:3412/',
        ]
      : [
          'http://localhost:3321/',
          'http://localhost:3421/',
          'http://localhost:3322/',
          'http://localhost:3422/',
        ];
  if (
    !commitPattern.test(String(sourceCommit)) ||
    !imagePattern.test(String(imageDigest)) ||
    !projectPattern.test(String(projectName)) ||
    !containerPattern.test(String(primaryContainerId)) ||
    !containerPattern.test(String(foreignContainerId)) ||
    primaryContainerId === foreignContainerId ||
    [target.coreUrl, target.adminUrl, foreignTarget.coreUrl, foreignTarget.adminUrl].some(
      (entry, index) => entry !== expected[index]
    )
  ) {
    return fail();
  }
  return Object.freeze({
    schemaVersion: 1,
    kind,
    sourceCommit: sourceCommit as string,
    imageDigest: imageDigest as string,
    projectName: projectName as string,
    primaryContainerId: primaryContainerId as string,
    foreignContainerId: foreignContainerId as string,
    target,
    foreignTarget,
    stateDriver: validateDriver(own(source, 'stateDriver')),
    fetchObserverReceiptFile: validateAbsolutePath(own(source, 'fetchObserverReceiptFile')),
    ...(fixtureExecutable === undefined
      ? {}
      : { fixtureExecutable: validateExecutableDescriptor(fixtureExecutable) }),
    ...(fixtureSocket === undefined ? {} : { fixtureSocket: validateAbsolutePath(fixtureSocket) }),
    ...(invariantDriver === undefined ? {} : { invariantDriver: validateDriver(invariantDriver) }),
  });
};

const validateExecutableDescriptor = (
  value: unknown
): Readonly<{ path: string; sha256: string }> => {
  const recordValue = exactRecord(value, ['path', 'sha256']);
  const sha256 = own(recordValue, 'sha256');
  return Object.freeze({
    path: validateAbsolutePath(own(recordValue, 'path')),
    sha256: typeof sha256 === 'string' && shaPattern.test(sha256) ? sha256 : fail(),
  });
};

const currentUid = (): number => process.getuid?.() ?? fail();
const privateParent = async (filePath: string): Promise<void> => {
  const parent = path.dirname(filePath);
  const state = await lstat(parent).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.uid !== currentUid() ||
    (state.mode & 0o777) !== 0o700 ||
    (await realpath(parent)) !== parent
  ) {
    fail();
  }
};
const verifyArtifact = async (
  descriptor: Readonly<{ path: string; sha256: string }>
): Promise<Phase2ArtifactIdentity> => {
  await privateParent(descriptor.path);
  const handle = await open(descriptor.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(
    fail
  );
  try {
    const state = await handle.stat();
    const mode = state.mode & 0o777;
    if (
      !state.isFile() ||
      state.uid !== currentUid() ||
      (mode !== 0o500 && mode !== 0o700) ||
      state.nlink !== 1 ||
      state.size <= 0 ||
      state.size > 16 * 1024 * 1024
    ) {
      fail();
    }
    const bytes = new Uint8Array(state.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead <= 0) {
        fail();
      }
      offset += bytesRead;
    }
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const after = await handle.stat();
    const pathAfter = await lstat(descriptor.path);
    if (
      sha256 !== descriptor.sha256 ||
      !after.isFile() ||
      after.dev !== state.dev ||
      after.ino !== state.ino ||
      after.uid !== state.uid ||
      after.mode !== state.mode ||
      after.nlink !== state.nlink ||
      after.size !== state.size ||
      after.mtimeMs !== state.mtimeMs ||
      after.ctimeMs !== state.ctimeMs ||
      pathAfter.isSymbolicLink() ||
      !pathAfter.isFile() ||
      pathAfter.dev !== state.dev ||
      pathAfter.ino !== state.ino ||
      pathAfter.uid !== state.uid ||
      pathAfter.mode !== state.mode ||
      pathAfter.nlink !== state.nlink ||
      pathAfter.size !== state.size ||
      pathAfter.mtimeMs !== state.mtimeMs ||
      pathAfter.ctimeMs !== state.ctimeMs
    ) {
      fail();
    }
    return Object.freeze({
      path: descriptor.path,
      sha256,
      dev: String(state.dev),
      ino: String(state.ino),
      uid: state.uid,
      mode: state.mode & 0o777,
      nlink: state.nlink,
    });
  } finally {
    await handle.close();
  }
};
const verifySocket = async (socketPath: string): Promise<Phase2SocketIdentity> => {
  await privateParent(socketPath);
  const state = await lstat(socketPath).catch(fail);
  if (
    !state.isSocket() ||
    state.uid !== currentUid() ||
    state.nlink !== 1 ||
    (state.mode & 0o077) !== 0
  ) {
    fail();
  }
  return Object.freeze({
    path: socketPath,
    dev: String(state.dev),
    ino: String(state.ino),
    uid: state.uid,
    mode: state.mode & 0o777,
    nlink: state.nlink,
    type: 'unix-socket',
  });
};

const verifyMutableReceiptFile = async (filePath: string): Promise<Phase2MutableFileIdentity> => {
  await privateParent(filePath);
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const state = await handle.stat();
    const pathState = await lstat(filePath).catch(fail);
    if (
      !state.isFile() ||
      state.uid !== currentUid() ||
      (state.mode & 0o777) !== 0o600 ||
      state.nlink !== 1 ||
      state.size > 16 * 1024 ||
      pathState.isSymbolicLink() ||
      !pathState.isFile() ||
      pathState.dev !== state.dev ||
      pathState.ino !== state.ino ||
      pathState.uid !== state.uid ||
      pathState.mode !== state.mode ||
      pathState.nlink !== state.nlink
    ) {
      return fail();
    }
    return Object.freeze({
      path: filePath,
      dev: String(state.dev),
      ino: String(state.ino),
      uid: state.uid,
      mode: state.mode & 0o777,
      nlink: state.nlink,
    });
  } finally {
    await handle.close();
  }
};

const sameArtifactIdentity = (
  left: Phase2ArtifactIdentity | undefined,
  right: Phase2ArtifactIdentity | undefined
): boolean => JSON.stringify(left) === JSON.stringify(right);

const sameSocketIdentity = (
  left: Phase2SocketIdentity | undefined,
  right: Phase2SocketIdentity | undefined
): boolean => JSON.stringify(left) === JSON.stringify(right);
const sameMutableFileIdentity = (
  left: Phase2MutableFileIdentity,
  right: Phase2MutableFileIdentity
): boolean => JSON.stringify(left) === JSON.stringify(right);

const assertVerifiedTargetStable = async (verified: VerifiedPhase2Target): Promise<void> => {
  const { descriptor } = verified;
  const [
    stateDriver,
    stateSocket,
    fixtureExecutable,
    fixtureSocket,
    invariantDriver,
    invariantSocket,
    receiptFile,
  ] = await Promise.all([
    verifyArtifact(descriptor.stateDriver),
    verifySocket(descriptor.stateDriver.controlSocket),
    descriptor.fixtureExecutable ? verifyArtifact(descriptor.fixtureExecutable) : undefined,
    descriptor.fixtureSocket ? verifySocket(descriptor.fixtureSocket) : undefined,
    descriptor.invariantDriver ? verifyArtifact(descriptor.invariantDriver) : undefined,
    descriptor.invariantDriver ? verifySocket(descriptor.invariantDriver.controlSocket) : undefined,
    verifyMutableReceiptFile(descriptor.fetchObserverReceiptFile),
  ]);
  if (
    !sameArtifactIdentity(stateDriver, verified.stateDriver) ||
    !sameSocketIdentity(stateSocket, verified.stateControlSocket) ||
    !sameArtifactIdentity(fixtureExecutable, verified.fixtureExecutable) ||
    !sameSocketIdentity(fixtureSocket, verified.fixtureSocket) ||
    !sameArtifactIdentity(invariantDriver, verified.invariantDriver) ||
    !sameSocketIdentity(invariantSocket, verified.invariantControlSocket) ||
    !sameMutableFileIdentity(receiptFile, verified.fetchObserverReceiptFile)
  ) {
    fail();
  }
};

const mutationWatchers = (
  paths: readonly string[]
): Readonly<{ changed: () => boolean; close: () => void }> => {
  let changed = false;
  const grouped = new Map<string, Set<string>>();
  for (const filePath of paths) {
    let current = filePath;
    while (true) {
      const parent = path.dirname(current);
      if (parent === current) {
        break;
      }
      const names = grouped.get(parent) ?? new Set<string>();
      names.add(path.basename(current));
      grouped.set(parent, names);
      current = parent;
    }
  }
  const watchers: FSWatcher[] = [];
  try {
    for (const [parent, names] of grouped) {
      watchers.push(
        watch(parent, { persistent: false }, (_event, filename) => {
          if (filename === null || names.has(filename.toString())) {
            changed = true;
          }
        })
      );
    }
  } catch {
    for (const watcher of watchers) {
      watcher.close();
    }
    return fail();
  }
  return Object.freeze({
    changed: () => changed,
    close: () => {
      for (const watcher of watchers) {
        watcher.close();
      }
    },
  });
};

const drainMutationEvents = async (): Promise<void> => {
  await new Promise<void>((resolve) => {
    setImmediate(resolve);
  });
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
  await new Promise<void>((resolve) => {
    setImmediate(resolve);
  });
};

const createInvocationFence = (verified: VerifiedPhase2Target): Phase2InvocationFence => {
  const watchedPaths = Object.freeze([
    verified.stateDriver.path,
    verified.stateControlSocket.path,
    ...(verified.fixtureExecutable ? [verified.fixtureExecutable.path] : []),
    ...(verified.fixtureSocket ? [verified.fixtureSocket.path] : []),
    ...(verified.invariantDriver ? [verified.invariantDriver.path] : []),
    ...(verified.invariantControlSocket ? [verified.invariantControlSocket.path] : []),
  ]);
  const assertStable = async (): Promise<void> => assertVerifiedTargetStable(verified);
  return Object.freeze({
    assertStable,
    run: async <Result>(operation: () => Promise<Result>): Promise<Result> => {
      const watchers = mutationWatchers(watchedPaths);
      try {
        let result: Result | undefined;
        let operationError: unknown;
        try {
          await assertStable();
          result = await operation();
        } catch (error: unknown) {
          operationError = error;
        }
        await drainMutationEvents();
        let stabilityError: unknown;
        try {
          if (watchers.changed()) {
            fail();
          }
          await assertStable();
          if (watchers.changed()) {
            fail();
          }
        } catch (error: unknown) {
          stabilityError = error;
        }
        if (operationError !== undefined || stabilityError !== undefined) {
          if (operationError !== undefined && stabilityError !== undefined) {
            throw new AggregateError([operationError, stabilityError], diagnostic);
          }
          throw operationError ?? stabilityError;
        }
        return result as Result;
      } finally {
        watchers.close();
      }
    },
  });
};

const materializeArtifact = async (
  source: Phase2ArtifactIdentity,
  destination: string
): Promise<void> => {
  const sourceHandle = await open(source.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(
    fail
  );
  let destinationHandle;
  try {
    const sourceState = await sourceHandle.stat();
    if (
      String(sourceState.dev) !== source.dev ||
      String(sourceState.ino) !== source.ino ||
      sourceState.uid !== source.uid ||
      sourceState.nlink !== source.nlink
    ) {
      return fail();
    }
    const bytes = await sourceHandle.readFile();
    if (createHash('sha256').update(bytes).digest('hex') !== source.sha256) {
      return fail();
    }
    destinationHandle = await open(
      destination,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o700
    ).catch(fail);
    await destinationHandle.writeFile(bytes);
    await destinationHandle.sync();
    await destinationHandle.chmod(0o700);
    const destinationState = await destinationHandle.stat();
    if (
      !destinationState.isFile() ||
      destinationState.uid !== currentUid() ||
      destinationState.nlink !== 1 ||
      (destinationState.mode & 0o777) !== 0o700 ||
      destinationState.size !== bytes.byteLength
    ) {
      return fail();
    }
  } finally {
    await destinationHandle?.close().catch(() => {
      // The primary materialization failure remains authoritative.
    });
    await sourceHandle.close().catch(() => {
      // The primary materialization failure remains authoritative.
    });
  }
};

export const preparePhase2TargetForExecution = async (
  verified: VerifiedPhase2Target,
  sessionRoot: string,
  namespace: 'oracle' | 'candidate'
): Promise<PreparedPhase2Target> => {
  const rootState = await lstat(sessionRoot).catch(fail);
  if (
    rootState.isSymbolicLink() ||
    !rootState.isDirectory() ||
    rootState.uid !== currentUid() ||
    (rootState.mode & 0o777) !== 0o700 ||
    (await realpath(sessionRoot)) !== sessionRoot
  ) {
    return fail();
  }
  const executionRoot = path.join(sessionRoot, `${namespace}-executables`);
  await mkdir(executionRoot, { mode: 0o700 }).catch(fail);
  await chmod(executionRoot, 0o700);
  const originalFence = createInvocationFence(verified);
  const statePath = path.join(executionRoot, 'state-driver');
  const fixturePath = verified.fixtureExecutable
    ? path.join(executionRoot, 'fixture-executable')
    : undefined;
  const invariantPath = verified.invariantDriver
    ? path.join(executionRoot, 'invariant-driver')
    : undefined;
  await originalFence.run(async () => {
    await materializeArtifact(verified.stateDriver, statePath);
    if (verified.fixtureExecutable && fixturePath) {
      await materializeArtifact(verified.fixtureExecutable, fixturePath);
    }
    if (verified.invariantDriver && invariantPath) {
      await materializeArtifact(verified.invariantDriver, invariantPath);
    }
  });
  const descriptor = Object.freeze({
    ...verified.descriptor,
    stateDriver: Object.freeze({ ...verified.descriptor.stateDriver, path: statePath }),
    ...(verified.descriptor.fixtureExecutable && fixturePath
      ? {
          fixtureExecutable: Object.freeze({
            ...verified.descriptor.fixtureExecutable,
            path: fixturePath,
          }),
        }
      : {}),
    ...(verified.descriptor.invariantDriver && invariantPath
      ? {
          invariantDriver: Object.freeze({
            ...verified.descriptor.invariantDriver,
            path: invariantPath,
          }),
        }
      : {}),
  });
  const copied = await verifyPhase2Target(descriptor);
  const copiedFence = createInvocationFence(copied);
  const fence: Phase2InvocationFence = Object.freeze({
    assertStable: async () => {
      await originalFence.assertStable();
      await copiedFence.assertStable();
    },
    run: async <Result>(operation: () => Promise<Result>): Promise<Result> =>
      originalFence.run(async () => copiedFence.run(operation)),
  });
  await fence.assertStable();
  const prepared = Object.freeze({
    descriptor,
    topology: verified.topology,
    fence,
    fetchObserverReceiptFile: copied.fetchObserverReceiptFile,
  });
  preparedTargetCapabilities.add(prepared);
  return prepared;
};

export const assertPreparedPhase2TargetCapability = (
  value: PreparedPhase2Target
): PreparedPhase2Target => (preparedTargetCapabilities.has(value) ? value : fail());

export const verifyPhase2Target = async (
  descriptor: Phase2TargetDescriptor
): Promise<VerifiedPhase2Target> => {
  const [
    stateDriver,
    stateControlSocket,
    fixtureExecutable,
    fixtureSocket,
    invariantDriver,
    invariantControlSocket,
    fetchObserverReceiptFile,
  ] = await Promise.all([
    verifyArtifact(descriptor.stateDriver),
    verifySocket(descriptor.stateDriver.controlSocket),
    descriptor.fixtureExecutable ? verifyArtifact(descriptor.fixtureExecutable) : undefined,
    descriptor.fixtureSocket ? verifySocket(descriptor.fixtureSocket) : undefined,
    descriptor.invariantDriver ? verifyArtifact(descriptor.invariantDriver) : undefined,
    descriptor.invariantDriver ? verifySocket(descriptor.invariantDriver.controlSocket) : undefined,
    verifyMutableReceiptFile(descriptor.fetchObserverReceiptFile),
  ]);
  const topology = Object.freeze({
    projectName: descriptor.projectName,
    primary: Object.freeze({
      containerId: descriptor.primaryContainerId,
      service: `${descriptor.kind}-primary-core`,
      imageDigest: descriptor.imageDigest,
    }),
    foreign: Object.freeze({
      containerId: descriptor.foreignContainerId,
      service: `${descriptor.kind}-foreign-core`,
      imageDigest: descriptor.imageDigest,
    }),
  });
  return Object.freeze({
    descriptor,
    topology,
    stateDriver,
    stateControlSocket,
    ...(fixtureExecutable && { fixtureExecutable }),
    ...(fixtureSocket && { fixtureSocket }),
    ...(invariantDriver && { invariantDriver }),
    ...(invariantControlSocket && { invariantControlSocket }),
    fetchObserverReceiptFile,
  });
};

export const readAndResetPhase2FetchReceipts = async (
  target: PreparedPhase2Target,
  accept: (value: unknown) => void
): Promise<void> => {
  if (typeof accept !== 'function') {
    return fail();
  }
  const expected = target.fetchObserverReceiptFile;
  const current = await verifyMutableReceiptFile(expected.path);
  if (!sameMutableFileIdentity(current, expected)) {
    return fail();
  }
  const handle = await open(expected.path, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const before = await handle.stat();
    if (
      String(before.dev) !== expected.dev ||
      String(before.ino) !== expected.ino ||
      before.uid !== expected.uid ||
      (before.mode & 0o777) !== expected.mode ||
      before.nlink !== expected.nlink ||
      before.size > 16 * 1024
    ) {
      return fail();
    }
    const bytes = new Uint8Array(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead < 1) {
        return fail();
      }
      offset += bytesRead;
    }
    const afterRead = await handle.stat();
    const pathAfterRead = await lstat(expected.path).catch(fail);
    if (
      afterRead.dev !== before.dev ||
      afterRead.ino !== before.ino ||
      afterRead.uid !== before.uid ||
      afterRead.mode !== before.mode ||
      afterRead.nlink !== before.nlink ||
      afterRead.size !== before.size ||
      pathAfterRead.isSymbolicLink() ||
      pathAfterRead.dev !== before.dev ||
      pathAfterRead.ino !== before.ino
    ) {
      return fail();
    }
    const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    const lines =
      text.length === 0 ? [] : text.endsWith('\n') ? text.slice(0, -1).split('\n') : fail();
    if (lines.length > 64 || lines.some((line) => line.length === 0)) {
      return fail();
    }
    const parsed = lines.map((line) => JSON.parse(line) as unknown);
    accept(parsed);
    await handle.truncate(0);
    await handle.sync();
    const afterReset = await handle.stat();
    const pathAfterReset = await lstat(expected.path).catch(fail);
    if (
      afterReset.dev !== before.dev ||
      afterReset.ino !== before.ino ||
      afterReset.uid !== before.uid ||
      afterReset.mode !== before.mode ||
      afterReset.nlink !== before.nlink ||
      afterReset.size > 0 ||
      pathAfterReset.isSymbolicLink() ||
      pathAfterReset.dev !== before.dev ||
      pathAfterReset.ino !== before.ino
    ) {
      return fail();
    }
  } catch {
    return fail();
  } finally {
    await handle.close();
  }
};

const readJsonResponse = async (url: URL, requestFetch: typeof fetch): Promise<unknown> => {
  const response = await requestFetch(url, {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  if (response.status !== 200 || response.redirected) {
    return fail();
  }
  const bytes = await readBoundedResponseBody(response, maximumHttpBytes);
  try {
    return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return fail();
  }
};

export const requestPhase2Json = async (
  input: Readonly<{
    url: URL;
    method: 'GET' | 'PUT' | 'PATCH' | 'POST' | 'DELETE';
    headers?: HeadersInit;
    body?: BodyInit;
    signal: AbortSignal;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<
  Readonly<{ status: number; headers: Readonly<Record<string, string>>; body: unknown }>
> => {
  const response = await requestFetch(input.url, {
    method: input.method,
    headers: input.headers,
    body: input.body,
    redirect: 'manual',
    signal: input.signal,
  });
  if (response.redirected) {
    return fail();
  }
  const bytes = await readBoundedResponseBody(response, maximumHttpBytes);
  const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  let body: unknown = null;
  if (text.length > 0) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      return fail();
    }
  }
  return Object.freeze({
    status: response.status,
    headers: Object.freeze(Object.fromEntries(response.headers.entries())),
    body,
  });
};

export const fetchPhase2PublicJwks = async (
  target: TargetConfig,
  requestFetch: typeof fetch = fetch
): Promise<Readonly<JSONWebKeySet>> => {
  const document = exactRecord(
    await readJsonResponse(new URL('/oidc/jwks', target.coreUrl), requestFetch),
    ['keys']
  );
  const keys = own(document, 'keys');
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 32) {
    return fail();
  }
  for (const key of keys) {
    const candidate = record(key);
    if (
      Object.keys(candidate).some((member) => privateJwkMembers.has(member)) ||
      typeof candidate.kty !== 'string' ||
      typeof candidate.kid !== 'string'
    ) {
      return fail();
    }
  }
  return Object.freeze({
    keys: keys.map((key) => Object.freeze({ ...record(key) })) as JSONWebKeySet['keys'],
  });
};

export const fetchPhase2Discovery = async (
  target: TargetConfig,
  requestFetch: typeof fetch = fetch
): Promise<Readonly<Record<string, unknown>>> => {
  const document = record(
    await readJsonResponse(
      new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
      requestFetch
    )
  );
  return Object.freeze({ ...document });
};

const validateExecutable = async (value: string): Promise<string> => {
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (state.isSymbolicLink() || !state.isFile() || resolved !== value) {
    return fail();
  }
  await access(value, fsConstants.X_OK).catch(fail);
  return value;
};

const requireResult = (value: unknown): CommandRunnerResult => {
  const result = exactRecord(value, [
    'exitCode',
    'signal',
    'stdout',
    'stderr',
    'timedOut',
    'killed',
    'reaped',
  ]);
  const stdout = own(result, 'stdout');
  const stderr = own(result, 'stderr');
  if (
    own(result, 'exitCode') !== 0 ||
    own(result, 'signal') !== null ||
    typeof stdout !== 'string' ||
    typeof stderr !== 'string' ||
    stderr !== '' ||
    Buffer.byteLength(stdout) > maximumProcessBytes ||
    own(result, 'timedOut') !== false ||
    own(result, 'killed') !== false ||
    own(result, 'reaped') !== true
  ) {
    return fail();
  }
  return value as CommandRunnerResult;
};

const parseTerminal = (
  stdout: string,
  operation:
    | 'begin'
    | 'finish'
    | 'abort'
    | 'set-default-resource'
    | 'device-begin'
    | 'device-capture'
    | 'device-transition'
    | 'device-abort'
    | 'account-proof-begin'
    | 'account-proof-capture'
    | 'account-proof-expire'
    | 'account-proof-abort',
  scenarioId: Phase2DifferentialScenarioId | AccountPasswordProofScenarioId,
  topology: Phase2TopologyIdentity
): Record<string, unknown> => {
  if (stdout.length === 0 || /[\r\n]/u.test(stdout)) {
    return fail();
  }
  const expectedKeys =
    operation === 'begin' || operation === 'device-begin' || operation === 'account-proof-begin'
      ? ['schemaVersion', 'kind', 'operation', 'scenarioId', 'handle', 'attestation']
      : operation === 'finish'
        ? [
            'schemaVersion',
            'kind',
            'operation',
            'scenarioId',
            'handle',
            'authority',
            'signingUse',
            'sideEffects',
            'attestation',
          ]
        : ['schemaVersion', 'kind', 'operation', 'scenarioId', 'ok', 'attestation'];
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout) as unknown;
  } catch {
    return fail();
  }
  const terminal = exactRecord(parsed, expectedKeys);
  if (
    own(terminal, 'schemaVersion') !== 1 ||
    own(terminal, 'kind') !== phase2StateTerminalKind ||
    own(terminal, 'operation') !== operation ||
    own(terminal, 'scenarioId') !== scenarioId ||
    JSON.stringify(own(terminal, 'attestation')) !== JSON.stringify(topology)
  ) {
    return fail();
  }
  return terminal;
};

const parseAuthority = (value: unknown): Phase2EffectiveAuthorityFacts => {
  const authority = exactRecord(value, [
    'decision',
    'targetKind',
    'target',
    'availableScopes',
    'effectiveScopes',
  ]);
  const decision = own(authority, 'decision');
  const targetKind = own(authority, 'targetKind');
  const target = own(authority, 'target');
  const availableScopes = own(authority, 'availableScopes');
  const effectiveScopes = own(authority, 'effectiveScopes');
  if (
    ![
      'authorized',
      'unauthorized-client',
      'invalid-target',
      'access-denied',
      'invalid-request',
    ].includes(String(decision)) ||
    !['resource', 'organization', 'none'].includes(String(targetKind)) ||
    (target !== null && typeof target !== 'string') ||
    !Array.isArray(availableScopes) ||
    !Array.isArray(effectiveScopes) ||
    availableScopes.some((entry) => typeof entry !== 'string') ||
    effectiveScopes.some((entry) => typeof entry !== 'string')
  ) {
    return fail();
  }
  return Object.freeze({
    decision: decision as Phase2EffectiveAuthorityFacts['decision'],
    targetKind: targetKind as Phase2EffectiveAuthorityFacts['targetKind'],
    target,
    availableScopes: Object.freeze((availableScopes as unknown[]).map((entry) => entry as string)),
    effectiveScopes: Object.freeze((effectiveScopes as unknown[]).map((entry) => entry as string)),
  });
};

const clientCredentialsResponseErrors = new Set([
  'invalid_client',
  'invalid_target',
  'access_denied',
  'invalid_request',
]);

type FinishResponseFacts = Readonly<{
  responseError: string | null;
  signingKeyId: string | null;
}>;

const finishResponseFacts = (response: SanitizedTokenObservation): FinishResponseFacts => {
  const body = record(response.body);
  const responseError = own(body, 'error');
  if (response.jwt !== undefined) {
    const header = exactRecord(response.jwt.header, ['alg', 'kid', 'typ']);
    const signingKeyId = own(header, 'kid');
    if (
      response.status !== 200 ||
      responseError !== undefined ||
      typeof signingKeyId !== 'string' ||
      !signingKeyIdPattern.test(signingKeyId)
    ) {
      return fail();
    }
    return Object.freeze({ responseError: null, signingKeyId });
  }
  if (typeof responseError !== 'string' || !clientCredentialsResponseErrors.has(responseError)) {
    return fail();
  }
  return Object.freeze({ responseError, signingKeyId: null });
};

const parseSigning = (value: unknown): Phase2SigningUseFacts => {
  const signing = exactRecord(value, ['generalKeyUse', 'oidcIdTokenKeyUse']);
  if (
    !['verified', 'unchanged'].includes(String(own(signing, 'generalKeyUse'))) ||
    own(signing, 'oidcIdTokenKeyUse') !== 'unchanged'
  ) {
    return fail();
  }
  return Object.freeze({
    generalKeyUse: own(signing, 'generalKeyUse') as Phase2SigningUseFacts['generalKeyUse'],
    oidcIdTokenKeyUse: 'unchanged',
  });
};

const parseSideEffects = (value: unknown): Phase2SideEffectFacts => {
  const effects = exactRecord(value, [
    'users',
    'sessions',
    'grants',
    'authorizationCodes',
    'interactions',
    'refreshTokens',
    'tokenFamilies',
  ]);
  if (Object.values(effects).some((entry) => entry !== 0)) {
    return fail();
  }
  return Object.freeze({
    users: 0,
    sessions: 0,
    grants: 0,
    authorizationCodes: 0,
    interactions: 0,
    refreshTokens: 0,
    tokenFamilies: 0,
  });
};

export const createCommandPhase2ScenarioStateDriver = async (
  options: StateDriverOptions
): Promise<
  Phase2ScenarioStateDriver & DeviceScenarioStateDriver & AccountPasswordProofStateDriver
> => {
  const verified = await verifyPhase2Target(options.descriptor);
  const executable = verified.stateDriver.path;
  const runner = options.runner ?? runPhase1FixtureCommand;
  const env = Object.freeze({
    ASTER_PHASE2_CONTROL_SOCKET: options.descriptor.stateDriver.controlSocket,
    LC_ALL: 'C',
  });
  const run = async (
    operation:
      | 'begin'
      | 'finish'
      | 'abort'
      | 'set-default-resource'
      | 'device-begin'
      | 'device-capture'
      | 'device-transition'
      | 'device-abort'
      | 'account-proof-begin'
      | 'account-proof-capture'
      | 'account-proof-expire'
      | 'account-proof-abort',
    scenarioId: Phase2DifferentialScenarioId | AccountPasswordProofScenarioId,
    fixture: ProvisionedPhase2Fixture,
    extra: Readonly<Record<string, unknown>> = {}
  ): Promise<Record<string, unknown>> => {
    const descriptor = Object.freeze({
      schemaVersion: 1,
      kind: phase2StateRequestKind,
      operation,
      scenarioId,
      target: options.descriptor.target,
      foreignTarget: options.descriptor.foreignTarget,
      fixture: fixture.public,
      ...extra,
    });
    const invoke = async () =>
      requireResult(
        await runner({
          command: executable,
          args: Object.freeze([]),
          stdin: JSON.stringify(descriptor),
          env,
          timeoutMs: processTimeoutMs,
          maxStdoutBytes: maximumProcessBytes,
          maxStderrBytes: maximumProcessBytes,
          shell: false,
        })
      );
    const result = options.identityFence ? await options.identityFence.run(invoke) : await invoke();
    const after = await verifyArtifact(options.descriptor.stateDriver);
    if (JSON.stringify(after) !== JSON.stringify(verified.stateDriver)) {
      return fail();
    }
    return parseTerminal(result.stdout, operation, scenarioId, verified.topology);
  };

  const abort = async (
    scenarioId: Phase2DifferentialScenarioId,
    fixture: ProvisionedPhase2Fixture,
    handle: string | undefined
  ): Promise<void> => {
    const terminal = await run('abort', scenarioId, fixture, { handle: handle ?? null });
    if (own(terminal, 'ok') !== true) {
      fail();
    }
  };

  return Object.freeze({
    observe: async (
      scenarioId: Phase2DifferentialScenarioId,
      fixture: ProvisionedPhase2Fixture,
      execute: () => Promise<SanitizedTokenObservation>
    ): Promise<Phase2ScenarioStateObservation> => {
      let handle: string | undefined;
      let response: SanitizedTokenObservation;
      try {
        const begin = await run('begin', scenarioId, fixture);
        const rawHandle = own(begin, 'handle');
        handle = typeof rawHandle === 'string' && rawHandle.length <= 128 ? rawHandle : undefined;
        if (handle === undefined || !handlePattern.test(handle)) {
          throw new TypeError(diagnostic);
        }
        response = await execute();
        const { responseError, signingKeyId } = finishResponseFacts(response);
        const finish = await run('finish', scenarioId, fixture, {
          handle,
          responseStatus: response.status,
          tokenIssued: response.jwt !== undefined,
          responseError,
          signingKeyId,
        });
        if (own(finish, 'handle') !== handle) {
          throw new TypeError(diagnostic);
        }
        const signingUse = parseSigning(own(finish, 'signingUse'));
        if (
          (response.jwt === undefined && signingUse.generalKeyUse !== 'unchanged') ||
          (response.jwt !== undefined && signingUse.generalKeyUse !== 'verified')
        ) {
          throw new TypeError(diagnostic);
        }
        return Object.freeze({
          response,
          authority: parseAuthority(own(finish, 'authority')),
          signingUse,
          sideEffects: parseSideEffects(own(finish, 'sideEffects')),
        });
      } catch (error: unknown) {
        try {
          await abort(scenarioId, fixture, handle);
        } catch (cleanupError: unknown) {
          throw new AggregateError([error, cleanupError], diagnostic);
        }
        throw error;
      }
    },
    setDefaultResource: async (
      fixture: ProvisionedPhase2Fixture,
      enabled: boolean
    ): Promise<void> => {
      const scenarioId = 'client-credentials.missing-target';
      const terminal = await run('set-default-resource', scenarioId, fixture, { enabled });
      if (own(terminal, 'ok') !== true) {
        return fail();
      }
    },
    withDeviceHandle: async <Result>(
      scenarioId: DeviceAuthorizationScenarioId,
      fixture: ProvisionedPhase2Fixture,
      use: (handle: DeviceScenarioHandle) => Result | Promise<Result>
    ): Promise<Result> => {
      let handle: string | undefined;
      let outcome: Result | undefined;
      let callbackError: unknown;
      let callbackFailed = false;
      try {
        const begin = await run('device-begin', scenarioId, fixture);
        const rawHandle = own(begin, 'handle');
        handle =
          typeof rawHandle === 'string' && handlePattern.test(rawHandle) ? rawHandle : fail();
        const controls: DeviceScenarioHandle = Object.freeze({
          capture: async () => {
            const terminal = await run('device-capture', scenarioId, fixture, { handle });
            if (own(terminal, 'ok') !== true) {
              fail();
            }
          },
          transition: async (action: DeviceScenarioStateAction) => {
            const terminal = await run('device-transition', scenarioId, fixture, {
              handle,
              action,
            });
            if (own(terminal, 'ok') !== true) {
              fail();
            }
          },
        });
        outcome = await use(controls);
      } catch (error: unknown) {
        callbackFailed = true;
        callbackError = error;
      }
      let cleanupError: unknown;
      let cleanupFailed = false;
      try {
        const terminal = await run('device-abort', scenarioId, fixture, {
          handle: handle ?? null,
        });
        if (own(terminal, 'ok') !== true) {
          fail();
        }
      } catch (error: unknown) {
        cleanupFailed = true;
        cleanupError = error;
      }
      if (callbackFailed && cleanupFailed) {
        throw new AggregateError([callbackError, cleanupError], diagnostic);
      }
      if (callbackFailed) {
        throw callbackError;
      }
      if (cleanupFailed) {
        throw cleanupError;
      }
      return outcome as Result;
    },
    withAccountPasswordProofHandle: async <Result>(
      scenarioId: AccountPasswordProofScenarioId,
      fixture: ProvisionedPhase2Fixture,
      userId: string,
      use: (handle: AccountPasswordProofStateHandle) => Result | Promise<Result>
    ): Promise<Result> => {
      if (!accountIdPattern.test(userId)) {
        return fail();
      }
      let handle: string | undefined;
      let outcome: Result | undefined;
      let callbackError: unknown;
      let callbackFailed = false;
      try {
        const begin = await run('account-proof-begin', scenarioId, fixture, { userId });
        const rawHandle = own(begin, 'handle');
        handle =
          typeof rawHandle === 'string' && handlePattern.test(rawHandle) ? rawHandle : fail();
        const controls: AccountPasswordProofStateHandle = Object.freeze({
          capture: async () => {
            const terminal = await run('account-proof-capture', scenarioId, fixture, { handle });
            if (own(terminal, 'ok') !== true) {
              fail();
            }
          },
          expire: async () => {
            const terminal = await run('account-proof-expire', scenarioId, fixture, { handle });
            if (own(terminal, 'ok') !== true) {
              fail();
            }
          },
        });
        outcome = await use(controls);
      } catch (error: unknown) {
        callbackFailed = true;
        callbackError = error;
      }
      let cleanupError: unknown;
      let cleanupFailed = false;
      try {
        const terminal = await run('account-proof-abort', scenarioId, fixture, {
          handle: handle ?? null,
        });
        if (own(terminal, 'ok') !== true) {
          fail();
        }
      } catch (error: unknown) {
        cleanupFailed = true;
        cleanupError = error;
      }
      if (callbackFailed && cleanupFailed) {
        throw new AggregateError([callbackError, cleanupError], diagnostic);
      }
      if (callbackFailed) {
        throw callbackError;
      }
      if (cleanupFailed) {
        throw cleanupError;
      }
      return outcome as Result;
    },
  });
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, no-constant-condition, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/no-loop-func, @typescript-eslint/no-unnecessary-condition */
