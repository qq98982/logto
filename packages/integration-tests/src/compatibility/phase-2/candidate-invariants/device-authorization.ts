/* eslint-disable max-lines, complexity, no-restricted-syntax, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- This candidate-only registry owns eight closed projections, ordered live probes, secret leases, and deliberate mutation controls. */
import { constants as fsConstants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import {
  createDeviceAuthorizationTransportLease,
  type DeviceAuthorizationProjection,
  type DeviceAuthorizationTransportLease,
} from '../clients/device-authorization.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2CandidateInvariantId, Phase2ProfileRegistries } from '../profile.js';
import { assertDeviceAuthorizationEvidenceIsSanitized } from '../projections/device-authorization.js';
import type { Phase2TopologyIdentity } from '../provenance.js';
import type { Phase2InvocationFence } from '../runtime.js';
import {
  completeDeviceApproval,
  executeDeviceConcurrencyTrial,
  startDeviceAuthorization,
  type DeviceAuthorizationScenarioRuntime,
  type DeviceScenarioStateDriver,
} from '../scenarios/device-authorization.js';

export const deviceCandidateInvariantIds = Object.freeze([
  'device-authorization.forced-rls-isolation',
  'device-authorization.credentials-digest-only',
  'device-authorization.cross-tenant-lookup-rejected',
  'device-authorization.transition-failure-rolls-back',
  'device-token.concurrent-poll-one-winner',
  'device-token.consumed-replay-revokes-grant',
  'device-authorization.expired-cleanup-bounded',
  'device-evidence.secret-material-absent',
] as const satisfies readonly Phase2CandidateInvariantId[]);

export type DeviceCandidateInvariantId = (typeof deviceCandidateInvariantIds)[number];

export type DeviceCandidateInvariantProjection =
  | Readonly<{
      invariant: 'forced-rls-isolation';
      catalog: Readonly<{ rowSecurity: true; forcedRowSecurity: true }>;
      privileges: Readonly<{
        request: 'select-insert-update-delete';
        admin: 'none';
        worker: 'none';
      }>;
      requestRole: Readonly<{
        primaryVisible: true;
        foreignVisible: false;
        foreignUpdate: 'rejected';
      }>;
      adminRole: 'rejected';
      workerRole: 'rejected';
    }>
  | Readonly<{
      invariant: 'credentials-digest-only';
      schemaClearColumns: 'absent';
      row: Readonly<{
        deviceDigestBytes: 32;
        userDigestBytes: 32;
        clearMaterial: 'absent';
        structuredContextClearMaterial: 'absent';
      }>;
    }>
  | Readonly<{
      invariant: 'cross-tenant-lookup-rejected';
      foreignPoll: Readonly<{ status: 400; error: 'invalid_grant' }>;
      foreignRow: 'not-visible';
      primaryState: 'unchanged';
    }>
  | Readonly<{
      invariant: 'transition-failure-rolls-back';
      injectedFailure: 'observed';
      rollback: Readonly<{
        deviceState: 'approved';
        interaction: 'unchanged';
        grant: 'unchanged';
        session: 'unchanged';
      }>;
      retry: 'issued';
    }>
  | Readonly<{
      invariant: 'concurrent-poll-one-winner';
      trials: readonly [
        Readonly<{ winnerCount: 1; loserError: 'invalid_grant' }>,
        Readonly<{ winnerCount: 1; loserError: 'invalid_grant' }>,
        Readonly<{ winnerCount: 1; loserError: 'invalid_grant' }>,
      ];
    }>
  | Readonly<{
      invariant: 'consumed-replay-revokes-grant';
      replay: Readonly<{ status: 400; error: 'invalid_grant' }>;
      authority: Readonly<{
        device: 'removed';
        grant: 'revoked';
        family: 'inactive';
        access: 'inactive';
        refresh: 'inactive';
      }>;
    }>
  | Readonly<{
      invariant: 'expired-cleanup-bounded';
      cleanup: Readonly<{
        seededExpired: 65;
        deletedExpired: 64;
        remainingExpired: 1;
        sentinel: 'preserved';
        foreignTenant: 'unchanged';
        newAuthorization: 'published';
      }>;
    }>
  | Readonly<{
      invariant: 'secret-material-absent';
      database: 'clear-material-absent';
      schema: 'closed';
      evidence: 'sanitized';
      driverOutput: 'sanitized';
    }>;

export type DeviceCandidateInvariantControlEvidence = Readonly<{
  id: DeviceCandidateInvariantId;
  candidate: DeviceCandidateInvariantProjection;
  positiveControl: Readonly<{ detected: true }>;
  negativeControl: Readonly<{ detected: true; pointer: string }>;
}>;

export type DeviceCandidateInvariant = Readonly<{
  id: DeviceCandidateInvariantId;
  expected: DeviceCandidateInvariantProjection;
}>;

export type DeviceCandidateInvariantExecutor = Readonly<{
  execute(id: DeviceCandidateInvariantId): Promise<DeviceCandidateInvariantProjection>;
}>;

const diagnostic = 'Invalid Phase 2 device candidate invariant';
const fail = (): never => {
  throw new TypeError(diagnostic);
};

type OneWinnerTrial = Readonly<{ winnerCount: 1; loserError: 'invalid_grant' }>;
const oneWinnerTrial = (): OneWinnerTrial =>
  Object.freeze({ winnerCount: 1 as const, loserError: 'invalid_grant' as const });
const expected: Readonly<Record<DeviceCandidateInvariantId, DeviceCandidateInvariantProjection>> =
  Object.freeze({
    'device-authorization.forced-rls-isolation': Object.freeze({
      invariant: 'forced-rls-isolation',
      catalog: Object.freeze({ rowSecurity: true, forcedRowSecurity: true }),
      privileges: Object.freeze({
        request: 'select-insert-update-delete',
        admin: 'none',
        worker: 'none',
      }),
      requestRole: Object.freeze({
        primaryVisible: true,
        foreignVisible: false,
        foreignUpdate: 'rejected',
      }),
      adminRole: 'rejected',
      workerRole: 'rejected',
    }),
    'device-authorization.credentials-digest-only': Object.freeze({
      invariant: 'credentials-digest-only',
      schemaClearColumns: 'absent',
      row: Object.freeze({
        deviceDigestBytes: 32,
        userDigestBytes: 32,
        clearMaterial: 'absent',
        structuredContextClearMaterial: 'absent',
      }),
    }),
    'device-authorization.cross-tenant-lookup-rejected': Object.freeze({
      invariant: 'cross-tenant-lookup-rejected',
      foreignPoll: Object.freeze({ status: 400, error: 'invalid_grant' }),
      foreignRow: 'not-visible',
      primaryState: 'unchanged',
    }),
    'device-authorization.transition-failure-rolls-back': Object.freeze({
      invariant: 'transition-failure-rolls-back',
      injectedFailure: 'observed',
      rollback: Object.freeze({
        deviceState: 'approved',
        interaction: 'unchanged',
        grant: 'unchanged',
        session: 'unchanged',
      }),
      retry: 'issued',
    }),
    'device-token.concurrent-poll-one-winner': Object.freeze({
      invariant: 'concurrent-poll-one-winner',
      trials: Object.freeze([oneWinnerTrial(), oneWinnerTrial(), oneWinnerTrial()]) as readonly [
        OneWinnerTrial,
        OneWinnerTrial,
        OneWinnerTrial,
      ],
    }),
    'device-token.consumed-replay-revokes-grant': Object.freeze({
      invariant: 'consumed-replay-revokes-grant',
      replay: Object.freeze({ status: 400, error: 'invalid_grant' }),
      authority: Object.freeze({
        device: 'removed',
        grant: 'revoked',
        family: 'inactive',
        access: 'inactive',
        refresh: 'inactive',
      }),
    }),
    'device-authorization.expired-cleanup-bounded': Object.freeze({
      invariant: 'expired-cleanup-bounded',
      cleanup: Object.freeze({
        seededExpired: 65,
        deletedExpired: 64,
        remainingExpired: 1,
        sentinel: 'preserved',
        foreignTenant: 'unchanged',
        newAuthorization: 'published',
      }),
    }),
    'device-evidence.secret-material-absent': Object.freeze({
      invariant: 'secret-material-absent',
      database: 'clear-material-absent',
      schema: 'closed',
      evidence: 'sanitized',
      driverOutput: 'sanitized',
    }),
  });

const negativePointers: Readonly<Record<DeviceCandidateInvariantId, string>> = Object.freeze({
  'device-authorization.forced-rls-isolation': '/catalog/forcedRowSecurity',
  'device-authorization.credentials-digest-only': '/row/deviceDigestBytes',
  'device-authorization.cross-tenant-lookup-rejected': '/foreignPoll/error',
  'device-authorization.transition-failure-rolls-back': '/rollback/deviceState',
  'device-token.concurrent-poll-one-winner': '/trials/0/winnerCount',
  'device-token.consumed-replay-revokes-grant': '/authority/grant',
  'device-authorization.expired-cleanup-bounded': '/cleanup/deletedExpired',
  'device-evidence.secret-material-absent': '/evidence',
});

const plainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  !nodeTypes.isProxy(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(
      descriptor &&
        Object.hasOwn(descriptor, 'value') &&
        descriptor.enumerable &&
        descriptor.get === undefined &&
        descriptor.set === undefined
    );
  });

const assertClosed = (value: unknown, reference: unknown): void => {
  if (Array.isArray(reference)) {
    if (!Array.isArray(value) || value.length !== reference.length) {
      return fail();
    }
    for (const [index, entry] of reference.entries()) {
      assertClosed(value[index], entry);
    }
    return;
  }
  if (plainRecord(reference)) {
    if (!plainRecord(value) || !isDeepStrictEqual(Object.keys(value), Object.keys(reference))) {
      return fail();
    }
    for (const key of Object.keys(reference)) {
      assertClosed(value[key], reference[key]);
    }
    return;
  }
  if (!isDeepStrictEqual(value, reference)) {
    fail();
  }
};

const mutate = (id: DeviceCandidateInvariantId): unknown => {
  const copy = JSON.parse(JSON.stringify(expected[id])) as Record<string, unknown>;
  switch (id) {
    case 'device-authorization.forced-rls-isolation': {
      (copy.catalog as Record<string, unknown>).forcedRowSecurity = false;
      break;
    }
    case 'device-authorization.credentials-digest-only': {
      (copy.row as Record<string, unknown>).deviceDigestBytes = 31;
      break;
    }
    case 'device-authorization.cross-tenant-lookup-rejected': {
      (copy.foreignPoll as Record<string, unknown>).error = 'authorization_pending';
      break;
    }
    case 'device-authorization.transition-failure-rolls-back': {
      (copy.rollback as Record<string, unknown>).deviceState = 'consumed';
      break;
    }
    case 'device-token.concurrent-poll-one-winner': {
      const first = (copy.trials as Array<Record<string, unknown>>)[0] ?? fail();
      first.winnerCount = 2;
      break;
    }
    case 'device-token.consumed-replay-revokes-grant': {
      (copy.authority as Record<string, unknown>).grant = 'active';
      break;
    }
    case 'device-authorization.expired-cleanup-bounded': {
      (copy.cleanup as Record<string, unknown>).deletedExpired = 65;
      break;
    }
    case 'device-evidence.secret-material-absent': {
      copy.evidence = 'leaked';
      break;
    }
  }
  return copy;
};

const differencePointer = (left: unknown, right: unknown, pointer = ''): string | undefined => {
  if (isDeepStrictEqual(left, right)) {
    return undefined;
  }
  if (Array.isArray(left) && Array.isArray(right)) {
    for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
      const nested = differencePointer(left[index], right[index], `${pointer}/${index}`);
      if (nested) {
        return nested;
      }
    }
  } else if (plainRecord(left) && plainRecord(right)) {
    for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])].toSorted()) {
      const escaped = key.replaceAll('~', '~0').replaceAll('/', '~1');
      const nested = differencePointer(left[key], right[key], `${pointer}/${escaped}`);
      if (nested) {
        return nested;
      }
    }
  }
  return pointer || '/';
};

export const deviceCandidateInvariantExpectedProjection = (
  id: DeviceCandidateInvariantId
): DeviceCandidateInvariantProjection => expected[id];

export const createDeviceCandidateInvariantRegistry = (
  profile: Phase2ProfileRegistries
): readonly DeviceCandidateInvariant[] => {
  const all = profile.candidateInvariantScenarios;
  const expectedCount = 5 + deviceCandidateInvariantIds.length;
  const suffix = all.slice(5);
  if (
    all.length !== expectedCount ||
    suffix.length !== deviceCandidateInvariantIds.length ||
    suffix.some((id, index) => id !== deviceCandidateInvariantIds[index])
  ) {
    return fail();
  }
  return Object.freeze(
    deviceCandidateInvariantIds.map((id) => Object.freeze({ id, expected: expected[id] }))
  );
};

export const runDeviceCandidateInvariantControls = (
  id: DeviceCandidateInvariantId,
  candidate: DeviceCandidateInvariantProjection
): DeviceCandidateInvariantControlEvidence => {
  assertClosed(candidate, expected[id]);
  const pointer = differencePointer(expected[id], mutate(id));
  if (pointer !== negativePointers[id]) {
    return fail();
  }
  return Object.freeze({
    id,
    candidate,
    positiveControl: Object.freeze({ detected: true as const }),
    negativeControl: Object.freeze({ detected: true as const, pointer }),
  });
};

export const runDeviceCandidateInvariants = async (
  profile: Phase2ProfileRegistries,
  executor: DeviceCandidateInvariantExecutor
): Promise<readonly DeviceCandidateInvariantControlEvidence[]> => {
  const registry = createDeviceCandidateInvariantRegistry(profile);
  if (!plainRecord(executor) || typeof executor.execute !== 'function') {
    return fail();
  }
  const evidence: DeviceCandidateInvariantControlEvidence[] = [];
  for (const [index, invariant] of registry.entries()) {
    try {
      const projection = await executor.execute(invariant.id);
      evidence.push(runDeviceCandidateInvariantControls(invariant.id, projection));
    } catch (error: unknown) {
      if (
        (index === 1 && error instanceof DeviceDigestDriverError) ||
        (index === 2 && error instanceof DeviceCrossTenantDriverError) ||
        (index === 7 && error instanceof DeviceEvidenceDriverError)
      ) {
        throw error;
      }
      throw new Error(`Phase 2 stage failed: candidate-invariant-device-${index}`);
    }
  }
  return Object.freeze(evidence);
};

export type LiveDeviceCandidateInvariantOptions = Readonly<{
  profile: Phase2ProfileRegistries;
  target: TargetConfig;
  foreignTarget: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  driverPath: string;
  controlSocket: string;
  topology: Phase2TopologyIdentity;
  state: DeviceScenarioStateDriver;
  jwks: Readonly<JSONWebKeySet>;
  fetch?: typeof fetch;
  createTransport?: typeof createDeviceAuthorizationTransportLease;
  identityFence?: Phase2InvocationFence;
  runner?: (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;
}>;

type DriverOperation = 'probe' | 'arm' | 'restore' | 'finish' | 'abort';
type PrivateDriverValues = Readonly<Record<string, unknown>>;
type DriverObservation = Readonly<Record<string, unknown>>;
type DriverControl = Readonly<{ handle?: string; ok?: true }>;

const driverControlKind = 'phase2-device-candidate-invariant-control';
const invariantTerminalKind = 'phase2-client-credentials-candidate-invariant';
const maximumDriverBytes = 65_536;
const driverTimeoutMs = 120_000;
const handlePattern = /^[0-9a-f]{32}$/u;
const deviceDigestDriverFailurePattern =
  /^Phase 2 client credentials invariant driver failed \(device-1-(private-code-extraction|row-sql|row-missing|row-facts|schema-query|schema-clear-columns)\)\.\n$/u;
type DeviceDigestFailureStage =
  | 'private-code-extraction'
  | 'row-sql'
  | 'row-missing'
  | 'row-facts'
  | 'schema-query'
  | 'schema-clear-columns';
class DeviceDigestDriverError extends Error {
  constructor(readonly stage: DeviceDigestFailureStage) {
    super(`Phase 2 stage failed: candidate-invariant-device-1-${stage}`);
  }
}

const deviceEvidenceDriverFailurePattern =
  /^Phase 2 client credentials invariant driver failed \(device-7-(private-extraction|row-sql|row-facts|schema-query|schema-clear-columns|scan-input|scan-query|scan-match|normalized-input|normalized-query|normalized-match)\)\.\n$/u;
type DeviceEvidenceFailureStage =
  | 'private-extraction'
  | 'row-sql'
  | 'row-facts'
  | 'schema-query'
  | 'schema-clear-columns'
  | 'scan-input'
  | 'scan-query'
  | 'scan-match'
  | 'normalized-input'
  | 'normalized-query'
  | 'normalized-match';
class DeviceEvidenceDriverError extends Error {
  constructor(readonly stage: DeviceEvidenceFailureStage) {
    super(`Phase 2 stage failed: candidate-invariant-device-7-${stage}`);
  }
}

type DeviceCrossTenantFailureStage =
  | 'arm'
  | 'abort'
  | 'foreign-poll-error'
  | 'foreign-poll-invalid-client'
  | 'foreign-poll-authorization-pending'
  | 'foreign-poll-status'
  | 'response'
  | 'finish';
class DeviceCrossTenantDriverError extends Error {
  constructor(readonly stage: DeviceCrossTenantFailureStage) {
    super(`Phase 2 stage failed: candidate-invariant-device-2-${stage}`);
  }
}

export const deviceDigestFailureStage = (value: unknown): DeviceDigestFailureStage | undefined => {
  if (!plainRecord(value)) {
    return undefined;
  }
  if (
    !isDeepStrictEqual(Object.keys(value), [
      'exitCode',
      'signal',
      'stdout',
      'stderr',
      'timedOut',
      'killed',
      'reaped',
    ]) ||
    value.exitCode !== 41 ||
    value.signal !== null ||
    value.stdout !== '' ||
    typeof value.stderr !== 'string' ||
    value.timedOut !== false ||
    value.killed !== false ||
    value.reaped !== true
  ) {
    return undefined;
  }
  return deviceDigestDriverFailurePattern.exec(value.stderr)?.[1] as
    | DeviceDigestFailureStage
    | undefined;
};

export const deviceEvidenceFailureStage = (
  value: unknown
): DeviceEvidenceFailureStage | undefined => {
  if (!plainRecord(value)) {
    return undefined;
  }
  if (
    !isDeepStrictEqual(Object.keys(value), [
      'exitCode',
      'signal',
      'stdout',
      'stderr',
      'timedOut',
      'killed',
      'reaped',
    ]) ||
    value.exitCode !== 42 ||
    value.signal !== null ||
    value.stdout !== '' ||
    typeof value.stderr !== 'string' ||
    value.timedOut !== false ||
    value.killed !== false ||
    value.reaped !== true
  ) {
    return undefined;
  }
  return deviceEvidenceDriverFailurePattern.exec(value.stderr)?.[1] as
    | DeviceEvidenceFailureStage
    | undefined;
};

const sensitiveStrings = (value: unknown): readonly string[] => {
  const output: string[] = [];
  const inspect = (current: unknown): void => {
    if (typeof current === 'string') {
      if (current.length > 0) {
        output.push(current);
      }
    } else if (Array.isArray(current)) {
      for (const entry of current) {
        inspect(entry);
      }
    } else if (plainRecord(current)) {
      for (const entry of Object.values(current)) {
        inspect(entry);
      }
    }
  };
  inspect(value);
  return Object.freeze(output);
};

const assertNoSecretReflection = (value: unknown, secrets: readonly string[]): void => {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) {
    const variants = [
      secret,
      encodeURIComponent(secret),
      new URLSearchParams([['value', secret]]).toString().slice('value='.length),
      Buffer.from(secret, 'utf8').toString('base64'),
      Buffer.from(secret, 'utf8').toString('base64url'),
    ];
    if (variants.some((variant) => variant.length > 0 && serialized.includes(variant))) {
      fail();
    }
  }
  assertDeviceAuthorizationEvidenceIsSanitized(value);
};

const requireDriverResult = (value: unknown): CommandRunnerResult => {
  if (!plainRecord(value)) {
    return fail();
  }
  const keys = ['exitCode', 'signal', 'stdout', 'stderr', 'timedOut', 'killed', 'reaped'];
  if (
    !isDeepStrictEqual(Object.keys(value), keys) ||
    value.exitCode !== 0 ||
    value.signal !== null ||
    typeof value.stdout !== 'string' ||
    typeof value.stderr !== 'string' ||
    value.stderr !== '' ||
    Buffer.byteLength(value.stdout) > maximumDriverBytes ||
    value.timedOut !== false ||
    value.killed !== false ||
    value.reaped !== true
  ) {
    return fail();
  }
  return value as CommandRunnerResult;
};

const exactJson = (value: string): Record<string, unknown> => {
  if (value.length === 0 || /[\r\n]/u.test(value)) {
    return fail();
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return plainRecord(parsed) ? parsed : fail();
  } catch {
    return fail();
  }
};

const validateExecutable = async (value: string): Promise<string> => {
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (state.isSymbolicLink() || !state.isFile() || resolved !== value) {
    return fail();
  }
  await access(value, fsConstants.X_OK).catch(fail);
  return value;
};

const validateControlSocket = (value: string): string =>
  path.isAbsolute(value) && path.normalize(value) === value && Buffer.byteLength(value) <= 4096
    ? value
    : fail();

const createDriver = async (options: LiveDeviceCandidateInvariantOptions) => {
  const executable = await validateExecutable(options.driverPath);
  const socket = validateControlSocket(options.controlSocket);
  const runner = options.runner ?? runPhase1FixtureCommand;
  const environment = Object.freeze({
    ASTER_PHASE2_CONTROL_SOCKET: socket,
    ASTER_CORE_URL: options.target.coreUrl,
    ASTER_ADMIN_URL: options.target.adminUrl,
    ASTER_FOREIGN_CORE_URL: options.foreignTarget.coreUrl,
    ASTER_FOREIGN_ADMIN_URL: options.foreignTarget.adminUrl,
    LC_ALL: 'C',
  });
  return async (
    id: DeviceCandidateInvariantId,
    operation: DriverOperation,
    privateValues: PrivateDriverValues = {},
    handle?: string,
    observation: DriverObservation = {}
  ): Promise<DeviceCandidateInvariantProjection | DriverControl> => {
    if ((handle !== undefined && !handlePattern.test(handle)) || !plainRecord(privateValues)) {
      return fail();
    }
    const descriptor = Object.freeze({
      schemaVersion: 1,
      kind: 'phase2-client-credentials-candidate-invariant-request',
      invariantId: id,
      operation,
      target: Object.freeze({ primary: options.target, foreign: options.foreignTarget }),
      fixture: options.fixture.public,
      ...(handle === undefined ? {} : { handle }),
      private: privateValues,
      observation,
    });
    const secrets = sensitiveStrings(privateValues);
    const invoke = async () => {
      const rawResult = await runner({
        command: executable,
        args: Object.freeze([]),
        stdin: JSON.stringify(descriptor),
        env: environment,
        timeoutMs: driverTimeoutMs,
        maxStdoutBytes: maximumDriverBytes,
        maxStderrBytes: maximumDriverBytes,
        shell: false,
      });
      if (id === 'device-authorization.credentials-digest-only') {
        const substage = deviceDigestFailureStage(rawResult);
        if (substage !== undefined) {
          throw new DeviceDigestDriverError(substage);
        }
      }
      if (id === 'device-evidence.secret-material-absent') {
        const substage = deviceEvidenceFailureStage(rawResult);
        if (substage !== undefined) {
          throw new DeviceEvidenceDriverError(substage);
        }
      }
      return requireDriverResult(rawResult);
    };
    const result = options.identityFence ? await options.identityFence.run(invoke) : await invoke();
    assertNoSecretReflection({ stdout: result.stdout, stderr: result.stderr }, secrets);
    const terminal = exactJson(result.stdout);
    if (
      terminal.schemaVersion !== 1 ||
      terminal.invariantId !== id ||
      !isDeepStrictEqual(terminal.attestation, options.topology)
    ) {
      return fail();
    }
    if (operation === 'probe' || operation === 'finish') {
      if (
        !isDeepStrictEqual(Object.keys(terminal), [
          'schemaVersion',
          'kind',
          'invariantId',
          'projection',
          'attestation',
        ]) ||
        terminal.kind !== invariantTerminalKind
      ) {
        return fail();
      }
      assertNoSecretReflection(terminal.projection, secrets);
      const projection = terminal.projection as DeviceCandidateInvariantProjection;
      assertClosed(projection, expected[id]);
      return projection;
    }
    if (
      terminal.kind !== driverControlKind ||
      terminal.operation !== operation ||
      !isDeepStrictEqual(
        Object.keys(terminal),
        operation === 'arm'
          ? ['schemaVersion', 'kind', 'invariantId', 'operation', 'handle', 'attestation']
          : ['schemaVersion', 'kind', 'invariantId', 'operation', 'ok', 'attestation']
      )
    ) {
      return fail();
    }
    if (operation === 'arm') {
      return typeof terminal.handle === 'string' && handlePattern.test(terminal.handle)
        ? Object.freeze({ handle: terminal.handle })
        : fail();
    }
    return terminal.ok === true ? Object.freeze({ ok: true as const }) : fail();
  };
};

const oauthCategory = (projection: DeviceAuthorizationProjection): string | undefined =>
  projection.oauthError.category;

type ConsumedReplayObservation = Readonly<{
  replayStatus: 400;
  replayError: 'invalid_grant';
  accessActive: false;
  refreshActive: false;
  refreshStatus: 400;
  refreshError: 'invalid_grant';
}>;

export const observeConsumedReplayRevocation = async (
  lease: DeviceAuthorizationTransportLease,
  clientId: string,
  expectedSubjectId: string
): Promise<ConsumedReplayObservation> => {
  const proof = { method: 'public' as const, clientId };
  const replay = await lease.pollToken({ proof });
  const access = await lease.requestLifecycle({
    kind: 'introspection',
    method: 'POST',
    proof,
    token: 'access',
    expectedSubjectId,
    expectedClientId: clientId,
  });
  const refresh = await lease.requestLifecycle({
    kind: 'introspection',
    method: 'POST',
    proof,
    token: 'refresh',
    expectedSubjectId,
    expectedClientId: clientId,
  });
  const refreshAttempt = await lease.requestLifecycle({
    kind: 'refresh',
    method: 'POST',
    proof,
  });
  const accessActive =
    access.kind === 'introspection' &&
    access.facts.marker === 'introspection' &&
    access.facts.active;
  const refreshActive =
    refresh.kind === 'introspection' &&
    refresh.facts.marker === 'introspection' &&
    refresh.facts.active;
  if (
    replay.status !== 400 ||
    oauthCategory(replay) !== 'invalid_grant' ||
    access.status !== 200 ||
    refresh.status !== 200 ||
    accessActive ||
    refreshActive ||
    refreshAttempt.status !== 400 ||
    refreshAttempt.oauthError.category !== 'invalid_grant'
  ) {
    return fail();
  }
  return Object.freeze({
    replayStatus: 400,
    replayError: 'invalid_grant',
    accessActive: false,
    refreshActive: false,
    refreshStatus: 400,
    refreshError: 'invalid_grant',
  });
};

export const projectDeviceConcurrencyInvariant = async (
  runTrial: () => Promise<
    Readonly<{
      winnerCount: number;
      responses: readonly [DeviceAuthorizationProjection, DeviceAuthorizationProjection];
    }>
  >
): Promise<DeviceCandidateInvariantProjection> => {
  const trials: OneWinnerTrial[] = [];
  for (let index = 0; index < 3; index += 1) {
    const observed = await runTrial();
    const loser = observed.responses.find(({ status }) => status !== 200);
    if (
      observed.winnerCount !== 1 ||
      loser?.status !== 400 ||
      oauthCategory(loser) !== 'invalid_grant'
    ) {
      return fail();
    }
    trials.push(oneWinnerTrial());
  }
  const projection = Object.freeze({
    invariant: 'concurrent-poll-one-winner' as const,
    trials: Object.freeze(trials) as unknown as readonly [
      OneWinnerTrial,
      OneWinnerTrial,
      OneWinnerTrial,
    ],
  }) satisfies DeviceCandidateInvariantProjection;
  assertClosed(projection, expected['device-token.concurrent-poll-one-winner']);
  return projection;
};

const expectAuthorizationIssued = (projection: DeviceAuthorizationProjection): void => {
  if (projection.status !== 200 || projection.deviceCodeShape === undefined) {
    fail();
  }
};

const prepareAuthorizationSecrets = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime
): Promise<void> => {
  expectAuthorizationIssued(
    await startDeviceAuthorization(lease, runtime, {
      client: 'firstParty',
      scope: 'openid offline_access profile',
    })
  );
  await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
};

const withAuthorizationSecrets = async <Result>(
  lease: DeviceAuthorizationTransportLease,
  use: (values: Readonly<{ deviceCode: string; userCode: string; xsrf: string }>) => Promise<Result>
): Promise<Result> =>
  (lease.withAuthorizationSecretLease ?? fail())(async (secrets) =>
    use(
      Object.freeze({
        deviceCode: secrets.getDeviceCode(),
        userCode: secrets.getUserCode(),
        xsrf: secrets.getXsrf(),
      })
    )
  );

const withDeviceCode = async <Result>(
  lease: DeviceAuthorizationTransportLease,
  use: (values: Readonly<{ deviceCode: string }>) => Promise<Result>
): Promise<Result> =>
  lease.withDeviceCodeLease(async (secret) =>
    use(Object.freeze({ deviceCode: secret.getDeviceCode() }))
  );

export const createLiveDeviceCandidateInvariantExecutor = async (
  options: LiveDeviceCandidateInvariantOptions
): Promise<DeviceCandidateInvariantExecutor> => {
  createDeviceCandidateInvariantRegistry(options.profile);
  if (
    options.target.label !== 'candidate' ||
    options.foreignTarget.label !== 'candidate' ||
    options.target.coreUrl === options.foreignTarget.coreUrl
  ) {
    return fail();
  }
  const driver = await createDriver(options);
  const createTransport = options.createTransport ?? createDeviceAuthorizationTransportLease;
  const runtime: DeviceAuthorizationScenarioRuntime = Object.freeze({
    target: options.target,
    fixture: options.fixture,
    jwks: options.jwks,
    state: options.state,
    fetch: options.fetch,
    createTransport,
  });

  const executeWithLease = async (
    operation: (
      lease: DeviceAuthorizationTransportLease
    ) => Promise<DeviceCandidateInvariantProjection>
  ) => {
    const lease = createTransport({ target: options.target, fetch: options.fetch });
    try {
      return await operation(lease);
    } finally {
      lease.clear();
    }
  };

  return Object.freeze({
    execute: async (
      id: DeviceCandidateInvariantId
    ): Promise<DeviceCandidateInvariantProjection> => {
      switch (id) {
        case 'device-authorization.forced-rls-isolation': {
          return driver(id, 'probe') as Promise<DeviceCandidateInvariantProjection>;
        }
        case 'device-authorization.credentials-digest-only': {
          return executeWithLease(async (lease) => {
            await prepareAuthorizationSecrets(lease, runtime);
            const outcome = await withAuthorizationSecrets(lease, async (codes) => {
              try {
                const projection = (await driver(
                  id,
                  'probe',
                  codes
                )) as DeviceCandidateInvariantProjection;
                return Object.freeze({ kind: 'projection' as const, projection });
              } catch (error: unknown) {
                if (error instanceof DeviceDigestDriverError) {
                  return Object.freeze({ kind: 'digest-failure' as const, stage: error.stage });
                }
                throw error;
              }
            });
            if (outcome.kind === 'digest-failure') {
              throw new DeviceDigestDriverError(outcome.stage);
            }
            return outcome.projection;
          });
        }
        case 'device-authorization.cross-tenant-lookup-rejected': {
          return executeWithLease(async (lease) => {
            await prepareAuthorizationSecrets(lease, runtime);
            const outcome = await withAuthorizationSecrets(lease, async (codes) => {
              let armed: DriverControl;
              try {
                armed = (await driver(id, 'arm', codes)) as DriverControl;
              } catch {
                return Object.freeze({ kind: 'failure' as const, stage: 'arm' as const });
              }
              const { handle } = armed;
              if (handle === undefined) {
                return Object.freeze({ kind: 'failure' as const, stage: 'arm' as const });
              }
              const foreign = createTransport({
                target: options.foreignTarget,
                fetch: options.fetch,
              });
              const abort = async (): Promise<DeviceCrossTenantFailureStage | undefined> => {
                try {
                  await driver(id, 'abort', {}, handle);
                } catch {
                  return 'abort';
                }
              };
              try {
                let response: DeviceAuthorizationProjection;
                try {
                  response = await foreign.pollToken({
                    proof: {
                      method: 'public',
                      clientId: options.fixture.public.deviceClients.firstParty.id,
                    },
                    deviceCode: codes.deviceCode,
                  });
                } catch {
                  const abortStage = await abort();
                  return Object.freeze({
                    kind: 'failure' as const,
                    stage: abortStage ?? ('foreign-poll-error' as const),
                  });
                }
                const category = oauthCategory(response);
                if (response.status !== 400 || category !== 'invalid_grant') {
                  const abortStage = await abort();
                  const stage =
                    category === 'invalid_client'
                      ? 'foreign-poll-invalid-client'
                      : category === 'authorization_pending'
                        ? 'foreign-poll-authorization-pending'
                        : response.status === 400
                          ? 'response'
                          : 'foreign-poll-status';
                  return Object.freeze({ kind: 'failure' as const, stage: abortStage ?? stage });
                }
                try {
                  const projection = await (driver(id, 'finish', {}, handle, {
                    foreignStatus: response.status,
                    foreignError: category,
                  }) as Promise<DeviceCandidateInvariantProjection>);
                  return Object.freeze({ kind: 'projection' as const, projection });
                } catch {
                  const abortStage = await abort();
                  return Object.freeze({
                    kind: 'failure' as const,
                    stage: abortStage ?? ('finish' as const),
                  });
                }
              } catch (error: unknown) {
                const abortStage = await abort();
                if (abortStage !== undefined) {
                  return Object.freeze({ kind: 'failure' as const, stage: abortStage });
                }
                throw error;
              } finally {
                foreign.clear();
              }
            });
            if (outcome.kind === 'failure') {
              throw new DeviceCrossTenantDriverError(outcome.stage);
            }
            return outcome.projection;
          });
        }
        case 'device-authorization.transition-failure-rolls-back': {
          return executeWithLease(async (lease) => {
            await prepareAuthorizationSecrets(lease, runtime);
            await completeDeviceApproval(lease, runtime);
            const armed = await withDeviceCode(lease, async (codes) => driver(id, 'arm', codes));
            const handle = (armed as DriverControl).handle ?? fail();
            try {
              const failed = await lease.pollToken({
                proof: {
                  method: 'public',
                  clientId: options.fixture.public.deviceClients.firstParty.id,
                },
              });
              if (failed.status < 500 || failed.status > 599) {
                return fail();
              }
              const restored = (await driver(id, 'restore', {}, handle, {
                failureStatus: failed.status,
                tokenPublished: false,
              })) as DriverControl;
              if (!restored.ok) {
                return fail();
              }
              const retried = await lease.pollToken({
                proof: {
                  method: 'public',
                  clientId: options.fixture.public.deviceClients.firstParty.id,
                },
              });
              if (retried.status !== 200) {
                return fail();
              }
              return await (driver(id, 'finish', {}, handle, {
                retryStatus: retried.status,
              }) as Promise<DeviceCandidateInvariantProjection>);
            } catch (error: unknown) {
              await driver(id, 'abort', {}, handle).catch(() => {});
              throw error;
            }
          });
        }
        case 'device-token.concurrent-poll-one-winner': {
          return projectDeviceConcurrencyInvariant(async () =>
            executeDeviceConcurrencyTrial(runtime, createTransport)
          );
        }
        case 'device-token.consumed-replay-revokes-grant': {
          return executeWithLease(async (lease) => {
            await prepareAuthorizationSecrets(lease, runtime);
            await completeDeviceApproval(lease, runtime);
            const issued = await lease.pollToken({
              proof: {
                method: 'public',
                clientId: options.fixture.public.deviceClients.firstParty.id,
              },
            });
            if (issued.status !== 200) {
              return fail();
            }
            const armed = await withDeviceCode(lease, async (codes) =>
              driver(id, 'arm', codes, undefined, { issuedStatus: issued.status })
            );
            const handle = (armed as DriverControl).handle ?? fail();
            try {
              const observation = await observeConsumedReplayRevocation(
                lease,
                options.fixture.public.deviceClients.firstParty.id,
                options.fixture.status?.user.id ?? fail()
              );
              return await (driver(
                id,
                'finish',
                {},
                handle,
                observation
              ) as Promise<DeviceCandidateInvariantProjection>);
            } catch (error: unknown) {
              await driver(id, 'abort', {}, handle).catch(() => {});
              throw error;
            }
          });
        }
        case 'device-authorization.expired-cleanup-bounded': {
          const armed = (await driver(id, 'arm')) as DriverControl;
          const handle = armed.handle ?? fail();
          try {
            return await executeWithLease(async (lease) => {
              await prepareAuthorizationSecrets(lease, runtime);
              return withAuthorizationSecrets(
                lease,
                async (codes) =>
                  driver(id, 'finish', codes, handle, {
                    authorizationStatus: 200,
                  }) as Promise<DeviceCandidateInvariantProjection>
              );
            });
          } catch (error: unknown) {
            await driver(id, 'abort', {}, handle).catch(() => {});
            throw error;
          }
        }
        case 'device-evidence.secret-material-absent': {
          return executeWithLease(async (lease) => {
            await prepareAuthorizationSecrets(lease, runtime);
            await completeDeviceApproval(lease, runtime);
            const issued = await lease.pollToken({
              proof: {
                method: 'public',
                clientId: options.fixture.public.deviceClients.firstParty.id,
              },
            });
            if (issued.status !== 200) {
              return fail();
            }
            const withEvidence = lease.withEvidenceSecretLease ?? fail();
            const outcome = await options.fixture.withSecretLease(async (fixtureSecrets) =>
              withEvidence(async (secrets) => {
                const privateValues = Object.freeze({
                  deviceCode: secrets.getDeviceCode(),
                  userCode: secrets.getUserCode(),
                  xsrf: secrets.getAuditXsrf(),
                  password: fixtureSecrets.getSubjectPassword?.() ?? fail(),
                  clientSecrets: Object.freeze([
                    fixtureSecrets.getClientSecret('basic'),
                    fixtureSecrets.getClientSecret('post'),
                    fixtureSecrets.getStatusClientSecret(),
                  ]),
                  tokens: Object.freeze(
                    [
                      secrets.getAccessToken(),
                      secrets.getRefreshToken(),
                      secrets.getIdToken(),
                    ].filter((value): value is string => typeof value === 'string')
                  ),
                });
                try {
                  const projection = (await driver(id, 'probe', privateValues, undefined, {
                    issuedStatus: issued.status,
                  })) as DeviceCandidateInvariantProjection;
                  return Object.freeze({ kind: 'projection' as const, projection });
                } catch (error: unknown) {
                  if (error instanceof DeviceEvidenceDriverError) {
                    return Object.freeze({
                      kind: 'evidence-failure' as const,
                      stage: error.stage,
                    });
                  }
                  throw error;
                }
              })
            );
            if (outcome.kind === 'evidence-failure') {
              throw new DeviceEvidenceDriverError(outcome.stage);
            }
            return outcome.projection;
          });
        }
      }
    },
  });
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
