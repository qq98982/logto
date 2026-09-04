/* eslint-disable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods, import/order, @typescript-eslint/ban-types, no-control-regex, unicorn/escape-case, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-unnecessary-condition, no-await-in-loop -- The command boundary owns bounded mutable process I/O state, exact descriptors, closed result parsing, process-group termination, condition polling, and partial-apply cleanup. */
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import {
  parsePhase1UserActivityState,
  resolvePhase1FixtureUserActivityTarget,
  type Phase1BrowserFixtureProvisioner,
} from '../browser/activity-reader.js';
import { snapshotClosedDataGraph } from '../model.js';
import type { Phase1Profile } from '../profile-types.js';
import {
  assertPhase1RuntimeCredentialGraphIsSanitized,
  createProvisionedPhase1Fixture,
  phase1TargetOriginsArePairwiseDisjoint,
  revokeProvisionedPhase1Fixture,
  type ProvisionedPhase1Fixture,
  type SemanticStateProjection,
} from '../fixtures.js';
import {
  assertPhase1FixtureMapEntityKeys,
  createPhase1FixtureMap,
  createPhase1FixtureStateProjection,
  getExpectedPhase1FixtureEntityKeys,
  phase1FixtureRecipeDefinitions,
} from '../fixture-map.js';
import type { Phase1FixtureRecipe } from '../model.js';

type CommandEnvironment = Readonly<Record<string, string | undefined>>;

export type CommandRunnerRequest = Readonly<{
  command: string;
  args: readonly string[];
  stdin: string;
  env: Readonly<Record<string, string>>;
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  shell: false;
}>;

export type CommandRunnerResult = Readonly<{
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  killed: boolean;
  reaped: boolean;
}>;

type CommandRunner = (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;

type CommandProvisionerOptions = Readonly<{
  profile: Pick<Phase1Profile, 'fixtures'>;
  target: TargetConfig;
  foreignTarget?: TargetConfig;
  runner?: CommandRunner;
  environment?: CommandEnvironment;
  createAllocationId?: () => string;
  createSecret?: () => string;
}>;

type CommandFixtureState = {
  recipe: Phase1FixtureRecipe;
  allocationId: string;
  allocationOwner: symbol;
  secretValues: readonly string[];
  publicAllocationIds?: readonly string[];
  recoveryFixture?: ProvisionedPhase1Fixture;
  cleanupPromise?: Promise<void>;
  completed: boolean;
};

const command = 'aster-admin';
const args = Object.freeze(['fixture', 'apply'] as const);
const timeoutMs = 30_000;
const maxStdoutBytes = 262_144;
const maxStderrBytes = 65_536;
const killGraceMs = 100;
const groupReapTimeoutMs = 2000;
const groupPollMs = 10;
const commandFailure = 'Candidate fixture command failed';
const cleanupFailure = 'Candidate fixture cleanup command failed';
const safeTextPattern = /^[^\u0000-\u001f\u007f]+$/u;

const safeText = (value: unknown, minimumLength = 1): string => {
  if (
    typeof value !== 'string' ||
    value.length < minimumLength ||
    value.length > 1024 ||
    !safeTextPattern.test(value)
  ) {
    throw new TypeError(commandFailure);
  }

  return value;
};

const exactRecord = (
  value: unknown,
  keys: readonly string[],
  failureMessage = commandFailure
): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(failureMessage);
  }
  const ownKeys = Reflect.ownKeys(value);

  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    throw new Error(failureMessage);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new Error(failureMessage);
    }
  }

  return value as Record<string, unknown>;
};

const ownValue = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const outputBytes = (value: string): number => Buffer.byteLength(value, 'utf8');

const validateRunnerResult = (value: unknown, failureMessage: string): CommandRunnerResult => {
  const result = exactRecord(
    value,
    ['exitCode', 'signal', 'stdout', 'stderr', 'timedOut', 'killed', 'reaped'],
    failureMessage
  );
  const exitCode = ownValue(result, 'exitCode');
  const signal = ownValue(result, 'signal');
  const stdout = ownValue(result, 'stdout');
  const stderr = ownValue(result, 'stderr');
  const timedOut = ownValue(result, 'timedOut');
  const killed = ownValue(result, 'killed');
  const reaped = ownValue(result, 'reaped');

  if (
    (exitCode !== null && (!Number.isSafeInteger(exitCode) || (exitCode as number) < 0)) ||
    (signal !== null && typeof signal !== 'string') ||
    typeof stdout !== 'string' ||
    typeof stderr !== 'string' ||
    typeof timedOut !== 'boolean' ||
    typeof killed !== 'boolean' ||
    typeof reaped !== 'boolean' ||
    outputBytes(stdout) > maxStdoutBytes ||
    outputBytes(stderr) > maxStderrBytes ||
    exitCode !== 0 ||
    signal !== null ||
    timedOut ||
    killed ||
    !reaped
  ) {
    throw new Error(failureMessage);
  }

  return result as CommandRunnerResult;
};

const parseOutputRecord = (
  stdout: string,
  expectedOperation: string,
  keys: readonly string[],
  failureMessage: string
): Record<string, unknown> => {
  try {
    const parsed: unknown = JSON.parse(stdout);
    const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(parsed);
    const result = exactRecord(snapshot, keys, failureMessage);

    if (
      ownValue(result, 'schemaVersion') !== 1 ||
      ownValue(result, 'operation') !== expectedOperation
    ) {
      throw new Error(failureMessage);
    }

    return result;
  } catch {
    throw new Error(failureMessage);
  }
};

const signalGroup = (pid: number | undefined, signal: NodeJS.Signals): void => {
  if (pid === undefined || pid <= 0) {
    return;
  }
  try {
    process.kill(-pid, signal);
  } catch {
    // The owned process group may already be reaped.
  }
};

const groupExists = (pid: number | undefined): boolean => {
  if (pid === undefined || pid <= 0) {
    return false;
  }
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error: unknown) {
    return !(
      typeof error === 'object' &&
      error !== null &&
      Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ESRCH'
    );
  }
};

const delay = async (milliseconds: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });

const waitForGroupExit = async (pid: number | undefined): Promise<boolean> => {
  const deadline = Date.now() + groupReapTimeoutMs;

  while (groupExists(pid) && Date.now() < deadline) {
    await delay(groupPollMs);
  }

  return !groupExists(pid);
};

const fenceOwnedGroup = async (pid: number | undefined, force: boolean): Promise<boolean> => {
  if (!groupExists(pid)) {
    return true;
  }
  if (!force) {
    signalGroup(pid, 'SIGTERM');
    await delay(killGraceMs);
  }
  if (groupExists(pid)) {
    signalGroup(pid, 'SIGKILL');
  }

  return waitForGroupExit(pid);
};

export const runPhase1FixtureCommand: CommandRunner = async (request) =>
  new Promise((resolve) => {
    const child = spawn(request.command, [...request.args], {
      detached: true,
      env: { ...request.env },
      shell: request.shell,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let killed = false;
    let settled = false;
    let forceKillTimer: NodeJS.Timeout | undefined;
    let terminationStarted = false;

    const terminate = (dueToTimeout: boolean) => {
      timedOut ||= dueToTimeout;
      killed = true;
      if (terminationStarted) {
        return;
      }
      terminationStarted = true;
      signalGroup(child.pid, 'SIGTERM');
      forceKillTimer = setTimeout(() => {
        signalGroup(child.pid, 'SIGKILL');
      }, killGraceMs);
    };
    const append = (stream: 'stdout' | 'stderr', chunk: Buffer | string) => {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      const chunks = stream === 'stdout' ? stdoutChunks : stderrChunks;
      const currentBytes = stream === 'stdout' ? stdoutBytes : stderrBytes;
      const maximumBytes = stream === 'stdout' ? request.maxStdoutBytes : request.maxStderrBytes;
      const remaining = Math.max(0, maximumBytes + 1 - currentBytes);

      if (remaining > 0) {
        chunks.push(bytes.subarray(0, remaining));
      }
      if (stream === 'stdout') {
        stdoutBytes += bytes.byteLength;
      } else {
        stderrBytes += bytes.byteLength;
      }
      if (currentBytes + bytes.byteLength > maximumBytes) {
        terminate(false);
      }
    };
    child.stdout.on('data', (chunk: Buffer | string) => append('stdout', chunk));
    child.stderr.on('data', (chunk: Buffer | string) => append('stderr', chunk));
    child.stdout.once('error', () => terminate(false));
    child.stderr.once('error', () => terminate(false));
    const timer = setTimeout(() => terminate(true), request.timeoutMs);
    child.once('error', () => terminate(false));
    const finalize = async (exitCode: number | null, signal: NodeJS.Signals | null) => {
      const reaped = await fenceOwnedGroup(child.pid, killed);
      resolve({
        exitCode,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        killed: killed || !reaped,
        reaped,
      });
    };
    child.once('close', (exitCode, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (forceKillTimer) {
        clearTimeout(forceKillTimer);
      }
      void finalize(exitCode, signal);
    });
    child.stdin.on('error', () => terminate(false));
    try {
      child.stdin.end(request.stdin);
    } catch {
      terminate(false);
    }
  });

const allowlistedEnvironment = (
  target: TargetConfig,
  foreignTarget: TargetConfig | undefined,
  environment: CommandEnvironment | undefined
): Readonly<Record<string, string>> => {
  let path = '/usr/bin:/bin';

  if (environment !== undefined) {
    if (
      typeof environment !== 'object' ||
      environment === null ||
      Array.isArray(environment) ||
      nodeTypes.isProxy(environment)
    ) {
      throw new TypeError(commandFailure);
    }
    const descriptor = Object.getOwnPropertyDescriptor(environment, 'PATH');

    if (descriptor && Object.hasOwn(descriptor, 'value') && descriptor.value !== undefined) {
      path = safeText(descriptor.value);
    }
  }

  return Object.freeze({
    PATH: path,
    ASTER_TARGET_LABEL: target.label,
    ASTER_CORE_URL: target.coreUrl,
    ASTER_ADMIN_URL: target.adminUrl,
    ...(foreignTarget && {
      ASTER_FOREIGN_CORE_URL: foreignTarget.coreUrl,
      ASTER_FOREIGN_ADMIN_URL: foreignTarget.adminUrl,
    }),
  });
};

const seedLogicalIds = (
  recipe: Phase1FixtureRecipe,
  profile: Pick<Phase1Profile, 'fixtures'>
): readonly string[] => {
  const ids: string[] = [];

  if (
    recipe === 'dataProtocol' ||
    recipe === 'fullPhase1' ||
    recipe === 'corsBoundary' ||
    recipe === 'consentBoundary'
  ) {
    ids.push(profile.fixtures.dataTenant.subject.id);
  }
  if (recipe === 'adminConsole' || recipe === 'fullPhase1' || recipe === 'corsBoundary') {
    ids.push(profile.fixtures.adminTenant.operator.id);
  }
  if (recipe === 'consentBoundary') {
    ids.push('consent.primary.user-b', 'consent.foreign.user-b');
  }

  return Object.freeze(ids);
};

export const createCommandPhase1FixtureProvisioner = (
  options: CommandProvisionerOptions
): Phase1BrowserFixtureProvisioner => {
  const target = validateTargetConfig(options.target);
  const foreignTarget = options.foreignTarget
    ? validateTargetConfig(options.foreignTarget)
    : undefined;

  if (!phase1TargetOriginsArePairwiseDisjoint(target, foreignTarget)) {
    throw new TypeError(commandFailure);
  }
  try {
    assertPhase1RuntimeCredentialGraphIsSanitized({ target, foreignTarget: foreignTarget ?? null });
  } catch {
    throw new TypeError(commandFailure);
  }
  const runner = options.runner ?? runPhase1FixtureCommand;
  const environment = allowlistedEnvironment(target, foreignTarget, options.environment);
  const createAllocationId = options.createAllocationId ?? randomUUID;
  const createSecret = options.createSecret ?? (() => randomBytes(32).toString('base64url'));
  const states = new WeakMap<object, CommandFixtureState>();
  const allocationOwners = new Map<string, symbol>();
  const pendingProvisioningCleanups = new Set<CommandFixtureState>();
  let pendingProvisioningRecovery: Promise<void> | undefined;
  const releaseAllocationId = (allocationId: string, owner: symbol): void => {
    if (allocationOwners.get(allocationId) === owner) {
      allocationOwners.delete(allocationId);
    }
  };

  const runDescriptor = async (
    descriptor: Readonly<Record<string, unknown>>,
    expectedOperation: 'provision' | 'projectState' | 'readUserActivityState' | 'cleanup',
    failureMessage: string,
    secretValues: readonly string[]
  ): Promise<Record<string, unknown>> => {
    let stdin: string;
    try {
      stdin = JSON.stringify(descriptor);
    } catch {
      throw new Error(failureMessage);
    }
    const rawResult = await runner({
      command,
      args,
      stdin,
      env: environment,
      timeoutMs,
      maxStdoutBytes,
      maxStderrBytes,
      shell: false,
    }).catch(() => {
      throw new Error(failureMessage);
    });
    const result = validateRunnerResult(rawResult, failureMessage);
    try {
      assertPhase1RuntimeCredentialGraphIsSanitized(
        { stdout: result.stdout, stderr: result.stderr },
        secretValues
      );
    } catch {
      throw new Error(failureMessage);
    }
    const resultKeys =
      expectedOperation === 'provision'
        ? ['schemaVersion', 'operation', 'public']
        : expectedOperation === 'projectState'
          ? ['schemaVersion', 'operation', 'projection']
          : expectedOperation === 'readUserActivityState'
            ? ['schemaVersion', 'operation', 'activity']
            : ['schemaVersion', 'operation', 'ok'];

    const parsed = parseOutputRecord(result.stdout, expectedOperation, resultKeys, failureMessage);
    try {
      assertPhase1RuntimeCredentialGraphIsSanitized(parsed, secretValues);
    } catch {
      throw new Error(failureMessage);
    }

    return parsed;
  };

  const cleanupDescriptor = (state: CommandFixtureState, fixture?: ProvisionedPhase1Fixture) =>
    Object.freeze({
      schemaVersion: 1,
      operation: 'cleanup',
      recipe: state.recipe,
      allocationId: state.allocationId,
      ...(fixture && { public: fixture.public }),
    });

  const applyCleanupDescriptor = async (
    state: CommandFixtureState,
    fixture?: ProvisionedPhase1Fixture
  ): Promise<void> => {
    try {
      const result = await runDescriptor(
        cleanupDescriptor(state, fixture),
        'cleanup',
        cleanupFailure,
        state.secretValues
      );
      if (ownValue(result, 'ok') !== true) {
        throw new Error(cleanupFailure);
      }
    } catch {
      throw new Error(cleanupFailure);
    }
  };

  const releaseStateAllocationIds = (state: CommandFixtureState): void => {
    releaseAllocationId(state.allocationId, state.allocationOwner);
    for (const allocationId of state.publicAllocationIds ?? []) {
      releaseAllocationId(allocationId, state.allocationOwner);
    }
  };

  const cleanupState = async (
    state: CommandFixtureState,
    fixture = state.recoveryFixture
  ): Promise<void> => {
    if (fixture) {
      state.recoveryFixture = fixture;
      revokeProvisionedPhase1Fixture(fixture);
    }
    if (state.completed) {
      pendingProvisioningCleanups.delete(state);
      state.recoveryFixture = undefined;
      return;
    }
    if (state.cleanupPromise) {
      return state.cleanupPromise;
    }
    const cleanupPromise = (async () => {
      await applyCleanupDescriptor(state, state.recoveryFixture);
      state.completed = true;
      releaseStateAllocationIds(state);
      pendingProvisioningCleanups.delete(state);
      state.recoveryFixture = undefined;
    })();
    state.cleanupPromise = cleanupPromise;

    try {
      await cleanupPromise;
    } catch (error: unknown) {
      pendingProvisioningCleanups.add(state);
      throw error;
    } finally {
      state.cleanupPromise = undefined;
    }
  };

  const recoverPendingProvisioningCleanups = async (): Promise<void> => {
    if (pendingProvisioningCleanups.size === 0) {
      return;
    }
    if (pendingProvisioningRecovery) {
      return pendingProvisioningRecovery;
    }
    const recovery = (async () => {
      const failures: unknown[] = [];

      for (const state of pendingProvisioningCleanups) {
        try {
          await cleanupState(state);
        } catch (error: unknown) {
          failures.push(error);
        }
      }
      if (failures.length > 0) {
        throw new AggregateError(failures, 'Candidate pending fixture cleanup failed');
      }
    })();
    pendingProvisioningRecovery = recovery;

    try {
      await recovery;
    } finally {
      pendingProvisioningRecovery = undefined;
    }
  };

  return Object.freeze({
    provision: async (recipe: Phase1FixtureRecipe): Promise<ProvisionedPhase1Fixture> => {
      if (!Object.hasOwn(phase1FixtureRecipeDefinitions, recipe)) {
        throw new TypeError(commandFailure);
      }
      if ((recipe === 'corsBoundary' || recipe === 'consentBoundary') && !foreignTarget) {
        throw new TypeError(commandFailure);
      }
      await recoverPendingProvisioningCleanups();
      const allocationId = safeText(createAllocationId());
      const allocationOwner = Symbol('Phase 1 command fixture allocation');
      const passwords = seedLogicalIds(recipe, options.profile).map((logicalId) => ({
        logicalId,
        value: safeText(createSecret(), 12),
      }));

      if (allocationOwners.has(allocationId)) {
        throw new Error(commandFailure);
      }
      allocationOwners.set(allocationId, allocationOwner);
      const state: CommandFixtureState = {
        recipe,
        allocationId,
        allocationOwner,
        secretValues: Object.freeze(passwords.map(({ value }) => value)),
        completed: false,
      };
      const descriptor = Object.freeze({
        schemaVersion: 1,
        operation: 'provision',
        recipe,
        allocationId,
        profile: Object.freeze({ fixtures: options.profile.fixtures }),
        seeds: Object.freeze({ passwords, clientSecrets: Object.freeze([]) }),
      });

      try {
        const result = await runDescriptor(
          descriptor,
          'provision',
          commandFailure,
          state.secretValues
        );
        const publicMap = createPhase1FixtureMap(ownValue(result, 'public'));

        if (publicMap.recipe !== recipe) {
          throw new Error(commandFailure);
        }
        assertPhase1FixtureMapEntityKeys(
          publicMap,
          getExpectedPhase1FixtureEntityKeys(options.profile, recipe)
        );
        if (
          publicMap.allocations.some(
            ({ allocationId: publicAllocationId }) =>
              allocationOwners.has(publicAllocationId) &&
              allocationOwners.get(publicAllocationId) !== allocationOwner
          )
        ) {
          throw new Error(commandFailure);
        }
        state.publicAllocationIds = Object.freeze(
          publicMap.allocations.map(({ allocationId: publicAllocationId }) => publicAllocationId)
        );
        for (const publicAllocationId of state.publicAllocationIds) {
          allocationOwners.set(publicAllocationId, allocationOwner);
        }
        const fixture = createProvisionedPhase1Fixture({
          public: publicMap,
          ...((recipe === 'corsBoundary' || recipe === 'consentBoundary') && { foreignTarget }),
          passwords,
          clientSecrets: [],
        });
        states.set(fixture as object, state);

        return fixture;
      } catch (error: unknown) {
        const primary =
          error instanceof Error && error.message === commandFailure
            ? error
            : new Error(commandFailure);
        let cleanupError: unknown;
        try {
          await cleanupState(state);
        } catch {
          cleanupError = new Error(cleanupFailure);
        }

        if (cleanupError) {
          throw new AggregateError(
            [primary, cleanupError],
            'Candidate fixture provisioning and cleanup failed',
            { cause: primary }
          );
        }
        releaseStateAllocationIds(state);
        throw primary;
      }
    },

    projectState: async (fixture: ProvisionedPhase1Fixture): Promise<SemanticStateProjection> => {
      const state = states.get(fixture as object);

      if (!state) {
        throw new TypeError(commandFailure);
      }
      const result = await runDescriptor(
        Object.freeze({
          schemaVersion: 1,
          operation: 'projectState',
          recipe: state.recipe,
          allocationId: state.allocationId,
          public: fixture.public,
        }),
        'projectState',
        commandFailure,
        state.secretValues
      );
      let projection: SemanticStateProjection;
      try {
        projection = createPhase1FixtureStateProjection(
          ownValue(result, 'projection'),
          fixture.public,
          options.profile
        );
        assertPhase1RuntimeCredentialGraphIsSanitized(projection, state.secretValues);
      } catch {
        throw new Error(commandFailure);
      }

      return projection;
    },

    readUserActivityState: async (fixture: ProvisionedPhase1Fixture, logicalUserId: string) => {
      const state = states.get(fixture as object);

      if (!state) {
        throw new TypeError(commandFailure);
      }
      try {
        resolvePhase1FixtureUserActivityTarget(fixture, logicalUserId);
      } catch {
        throw new TypeError(commandFailure);
      }
      const result = await runDescriptor(
        Object.freeze({
          schemaVersion: 1,
          operation: 'readUserActivityState',
          recipe: state.recipe,
          allocationId: state.allocationId,
          public: fixture.public,
          logicalUserId,
        }),
        'readUserActivityState',
        commandFailure,
        state.secretValues
      );
      try {
        const activity = parsePhase1UserActivityState(ownValue(result, 'activity'));
        assertPhase1RuntimeCredentialGraphIsSanitized(activity, state.secretValues);

        return activity;
      } catch {
        throw new Error(commandFailure);
      }
    },

    cleanup: async (fixture: ProvisionedPhase1Fixture): Promise<void> => {
      const state = states.get(fixture as object);

      if (!state) {
        throw new TypeError(cleanupFailure);
      }
      await cleanupState(state, fixture);
    },
  });
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods, import/order, @typescript-eslint/ban-types, no-control-regex, unicorn/escape-case, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-unnecessary-condition, no-await-in-loop */
