/* eslint-disable max-lines, max-params, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This candidate-only boundary owns a closed private driver protocol and deliberate mutation controls. */
import { constants as fsConstants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import { phase2InvariantRequestKind, phase2InvariantTerminalKind } from '../driver-protocol.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2TopologyIdentity } from '../provenance.js';
import type { Phase2InvocationFence } from '../runtime.js';

export const customJwtCandidateInvariantIds = Object.freeze([
  'custom-jwt.storage-confidential-forced-rls',
  'custom-jwt.blocking-refresh-rolls-back',
] as const);

export type CustomJwtCandidateInvariantId = (typeof customJwtCandidateInvariantIds)[number];

export type CustomJwtCandidateInvariantProjection =
  | Readonly<{
      invariant: 'storage-canary-absent-forced-rls';
      catalog: Readonly<{ rowSecurity: true; forcedRowSecurity: true }>;
      schema: Readonly<{ plaintextColumns: 'absent'; envelopeColumns: 'closed' }>;
      envelope: Readonly<{
        ciphertext: 'present';
        nonceBytes: 24;
        revision: 'positive';
        canaryBytes: 'absent';
      }>;
      managementRoundTrip: 'matched';
      requestRole: Readonly<{
        primaryVisible: true;
        foreignVisible: false;
        foreignUpdate: 'rejected';
      }>;
      adminRole: 'rejected';
      workerRole: 'rejected';
    }>
  | Readonly<{
      invariant: 'blocking-refresh-rolls-back';
      blocked: Readonly<{ status: 400; error: 'invalid_request'; tokenPublished: false }>;
      rollback: Readonly<{
        refreshAuthority: 'unchanged';
        tokenFamily: 'unchanged';
        accessAuthority: 'unchanged';
      }>;
      correctedRetry: Readonly<{ status: 200; tokenPublished: true }>;
    }>;

export type CustomJwtCandidateInvariantControlEvidence = Readonly<{
  id: CustomJwtCandidateInvariantId;
  candidate: CustomJwtCandidateInvariantProjection;
  positiveControl: Readonly<{ detected: true }>;
  negativeControl: Readonly<{ detected: true; pointer: string }>;
}>;

export type CustomJwtRefreshObservation = Readonly<{
  status: number;
  error?: string;
  tokenPublished: boolean;
}>;

export type CustomJwtCandidateWorkflow = Readonly<{
  withStorageCanary<Result>(
    use: (canary: string, semanticRoundTrip: true) => Promise<Result>
  ): Promise<Result>;
  withRefreshCredential<Result>(
    use: (refreshCredential: string) => Promise<Result>
  ): Promise<Result>;
  withBlockingCustomizer<Result>(use: () => Promise<Result>): Promise<Result>;
  installCorrectedCustomizer(): Promise<void>;
  exchangeRefresh(refreshCredential: string): Promise<CustomJwtRefreshObservation>;
}>;

export type CustomJwtCandidateInvariantOptions = Readonly<{
  target: TargetConfig;
  foreignTarget: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  driverPath: string;
  controlSocket: string;
  topology: Phase2TopologyIdentity;
  workflow: CustomJwtCandidateWorkflow;
  identityFence?: Phase2InvocationFence;
  runner?: (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;
}>;

const diagnostic = 'Invalid Phase 2 custom JWT candidate invariant';
const maximumDriverBytes = 65_536;
const driverTimeoutMs = 120_000;
const handlePattern = /^[0-9a-f]{32}$/u;
const controlTerminalKind = 'phase2-custom-jwt-candidate-invariant-control';
const terminalKeys = Object.freeze([
  'schemaVersion',
  'kind',
  'invariantId',
  'projection',
  'attestation',
]);
const fail = (): never => {
  throw new TypeError(diagnostic);
};

const expected: Readonly<
  Record<CustomJwtCandidateInvariantId, CustomJwtCandidateInvariantProjection>
> = Object.freeze({
  'custom-jwt.storage-confidential-forced-rls': Object.freeze({
    invariant: 'storage-canary-absent-forced-rls',
    catalog: Object.freeze({ rowSecurity: true, forcedRowSecurity: true }),
    schema: Object.freeze({ plaintextColumns: 'absent', envelopeColumns: 'closed' }),
    envelope: Object.freeze({
      ciphertext: 'present',
      nonceBytes: 24,
      revision: 'positive',
      canaryBytes: 'absent',
    }),
    managementRoundTrip: 'matched',
    requestRole: Object.freeze({
      primaryVisible: true,
      foreignVisible: false,
      foreignUpdate: 'rejected',
    }),
    adminRole: 'rejected',
    workerRole: 'rejected',
  }),
  'custom-jwt.blocking-refresh-rolls-back': Object.freeze({
    invariant: 'blocking-refresh-rolls-back',
    blocked: Object.freeze({ status: 400, error: 'invalid_request', tokenPublished: false }),
    rollback: Object.freeze({
      refreshAuthority: 'unchanged',
      tokenFamily: 'unchanged',
      accessAuthority: 'unchanged',
    }),
    correctedRetry: Object.freeze({ status: 200, tokenPublished: true }),
  }),
});

const negativePointers: Readonly<Record<CustomJwtCandidateInvariantId, string>> = Object.freeze({
  'custom-jwt.storage-confidential-forced-rls': '/envelope/canaryBytes',
  'custom-jwt.blocking-refresh-rolls-back': '/rollback/refreshAuthority',
});

const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor =
      typeof key === 'string' ? Object.getOwnPropertyDescriptor(value, key) : undefined;
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      return fail();
    }
  }
  return value as Record<string, unknown>;
};

const exactRecord = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
  const result = record(value);
  return isDeepStrictEqual(Object.keys(result), keys) ? result : fail();
};

const assertSafe = (value: unknown, secrets: readonly string[]): void => {
  const serialized = JSON.stringify(value);
  if (
    secrets.some((secret) => secret.length > 0 && serialized.includes(secret)) ||
    /(?:access_token|refresh_token|authorization|cookie|private_key|client_secret|script|environmentVariables)/iu.test(
      serialized
    ) ||
    /\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/-]+=*/u.test(serialized)
  ) {
    fail();
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

const validateOptions = (options: CustomJwtCandidateInvariantOptions): void => {
  if (
    options.target.label !== 'candidate' ||
    options.foreignTarget.label !== 'candidate' ||
    options.target.coreUrl === options.foreignTarget.coreUrl ||
    options.target.adminUrl === options.foreignTarget.adminUrl ||
    !path.isAbsolute(options.controlSocket) ||
    path.normalize(options.controlSocket) !== options.controlSocket ||
    Buffer.byteLength(options.controlSocket) > 4096
  ) {
    fail();
  }
};

const requireResult = (value: CommandRunnerResult): CommandRunnerResult => {
  if (
    value.exitCode !== 0 ||
    value.signal !== null ||
    value.stderr !== '' ||
    value.timedOut ||
    value.killed ||
    !value.reaped ||
    Buffer.byteLength(value.stdout) > maximumDriverBytes
  ) {
    return fail();
  }
  return value;
};

const mutation = (
  id: CustomJwtCandidateInvariantId,
  projection: CustomJwtCandidateInvariantProjection
): unknown => {
  const copy = JSON.parse(JSON.stringify(projection)) as Record<string, unknown>;
  if (id === 'custom-jwt.storage-confidential-forced-rls') {
    (copy.envelope as Record<string, unknown>).canaryBytes = 'present';
  } else {
    (copy.rollback as Record<string, unknown>).refreshAuthority = 'changed';
  }
  return copy;
};

const differencePointer = (
  expectedValue: unknown,
  actual: unknown,
  pointer = ''
): string | undefined => {
  if (isDeepStrictEqual(expectedValue, actual)) {
    return undefined;
  }
  if (
    typeof expectedValue === 'object' &&
    expectedValue !== null &&
    !Array.isArray(expectedValue) &&
    typeof actual === 'object' &&
    actual !== null &&
    !Array.isArray(actual)
  ) {
    const left = expectedValue as Record<string, unknown>;
    const right = actual as Record<string, unknown>;
    for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])].toSorted()) {
      const nested = differencePointer(
        left[key],
        right[key],
        `${pointer}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`
      );
      if (nested) {
        return nested;
      }
    }
  }
  return pointer || '/';
};

export const runCustomJwtCandidateInvariantControls = (
  id: CustomJwtCandidateInvariantId,
  candidate: CustomJwtCandidateInvariantProjection
): CustomJwtCandidateInvariantControlEvidence => {
  if (!isDeepStrictEqual(candidate, expected[id])) {
    return fail();
  }
  const pointer = differencePointer(expected[id], mutation(id, expected[id]));
  if (pointer !== negativePointers[id]) {
    return fail();
  }
  const evidence = Object.freeze({
    id,
    candidate,
    positiveControl: Object.freeze({ detected: true as const }),
    negativeControl: Object.freeze({ detected: true as const, pointer }),
  });
  assertSafe(evidence, []);
  return evidence;
};

export const createCustomJwtCandidateInvariantExecutor = async (
  options: CustomJwtCandidateInvariantOptions
): Promise<
  Readonly<{
    execute(id: CustomJwtCandidateInvariantId): Promise<CustomJwtCandidateInvariantProjection>;
  }>
> => {
  validateOptions(options);
  const executable = await validateExecutable(options.driverPath);
  const runner = options.runner ?? runPhase1FixtureCommand;
  const environment = Object.freeze({
    ASTER_PHASE2_CONTROL_SOCKET: options.controlSocket,
    ASTER_CORE_URL: options.target.coreUrl,
    ASTER_ADMIN_URL: options.target.adminUrl,
    ASTER_FOREIGN_CORE_URL: options.foreignTarget.coreUrl,
    ASTER_FOREIGN_ADMIN_URL: options.foreignTarget.adminUrl,
    LC_ALL: 'C',
  });

  const invoke = async (
    id: CustomJwtCandidateInvariantId,
    operation: 'probe' | 'arm' | 'restore' | 'finish' | 'abort',
    privateValues: Readonly<Record<string, string>> = {},
    observation: Readonly<Record<string, unknown>> = {},
    handle?: string
  ): Promise<Record<string, unknown>> => {
    if (handle !== undefined && !handlePattern.test(handle)) {
      return fail();
    }
    const descriptor = Object.freeze({
      schemaVersion: 1,
      kind: phase2InvariantRequestKind,
      invariantId: id,
      operation,
      target: Object.freeze({ primary: options.target, foreign: options.foreignTarget }),
      fixture: options.fixture.public,
      ...(handle === undefined ? {} : { handle }),
      private: privateValues,
      observation,
    });
    const secrets = Object.freeze(Object.values(privateValues));
    const run = async () =>
      requireResult(
        await runner({
          command: executable,
          args: Object.freeze([]),
          stdin: JSON.stringify(descriptor),
          env: environment,
          timeoutMs: driverTimeoutMs,
          maxStdoutBytes: maximumDriverBytes,
          maxStderrBytes: maximumDriverBytes,
          shell: false,
        })
      );
    const result = options.identityFence ? await options.identityFence.run(run) : await run();
    assertSafe({ stdout: result.stdout, stderr: result.stderr }, secrets);
    if (result.stdout.length === 0 || /[\r\n]/u.test(result.stdout)) {
      return fail();
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout) as unknown;
    } catch {
      return fail();
    }
    const terminal = record(parsed);
    if (
      terminal.schemaVersion !== 1 ||
      terminal.invariantId !== id ||
      !isDeepStrictEqual(terminal.attestation, options.topology)
    ) {
      return fail();
    }
    return terminal;
  };

  const projection = async (
    id: CustomJwtCandidateInvariantId,
    operation: 'probe' | 'finish',
    privateValues: Readonly<Record<string, string>> = {},
    observation: Readonly<Record<string, unknown>> = {},
    handle?: string
  ): Promise<CustomJwtCandidateInvariantProjection> => {
    const terminal = exactRecord(
      await invoke(id, operation, privateValues, observation, handle),
      terminalKeys
    );
    if (terminal.kind !== phase2InvariantTerminalKind) {
      return fail();
    }
    const value = terminal.projection;
    assertSafe(value, Object.values(privateValues));
    if (!isDeepStrictEqual(value, expected[id])) {
      return fail();
    }
    return value as CustomJwtCandidateInvariantProjection;
  };

  return Object.freeze({
    execute: async (id: CustomJwtCandidateInvariantId) => {
      if (id === 'custom-jwt.storage-confidential-forced-rls') {
        return options.workflow.withStorageCanary(async (canary, semanticRoundTrip) =>
          projection(id, 'probe', { canary }, { semanticRoundTrip })
        );
      }
      return options.workflow.withRefreshCredential(async (refreshCredential) => {
        return options.workflow.withBlockingCustomizer(async () => {
          let handle: string | undefined;
          try {
            const armed = await invoke(id, 'arm', { refreshCredential });
            const candidateHandle = armed.handle;
            if (
              armed.kind !== controlTerminalKind ||
              armed.operation !== 'arm' ||
              typeof candidateHandle !== 'string' ||
              !handlePattern.test(candidateHandle)
            ) {
              return fail();
            }
            handle = candidateHandle;
            const blocked = await options.workflow.exchangeRefresh(refreshCredential);
            await invoke(id, 'restore', {}, blocked, handle);
            await options.workflow.installCorrectedCustomizer();
            const retried = await options.workflow.exchangeRefresh(refreshCredential);
            return await projection(id, 'finish', {}, retried, handle);
          } catch (error: unknown) {
            if (handle !== undefined) {
              await invoke(id, 'abort', {}, {}, handle).catch(() => null);
            }
            throw error;
          }
        });
      });
    },
  });
};

export const customJwtCandidateInvariantExpectedProjection = (
  id: CustomJwtCandidateInvariantId
): CustomJwtCandidateInvariantProjection => expected[id];

/* eslint-enable max-lines, max-params, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
