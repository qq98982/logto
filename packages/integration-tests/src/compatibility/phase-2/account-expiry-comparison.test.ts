/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Jest's ESM module mock API is untyped here; this test owns temporary prepared-target capabilities and mock call state. */
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:net';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';

import type { ProvisionedPhase2Fixture } from './fixtures.js';
import {
  preparePhase2TargetForExecution,
  validatePhase2TargetDescriptor,
  verifyPhase2Target,
  type Phase2TargetDescriptor,
} from './runtime.js';
import type { runAccountPasswordProofExpiryForTarget } from './scenarios/account-password-proof-expiry-target-driver.js';
import { accountPasswordProofExpiryExpectedProjection } from './scenarios/account-password-proof-expiry.js';

type TargetDriverInput = Parameters<typeof runAccountPasswordProofExpiryForTarget>[0];
const isJestRuntime = (value: unknown): value is typeof jest =>
  typeof value === 'object' && value !== null && typeof Reflect.get(value, 'fn') === 'function';
const jestRuntime: unknown = Reflect.get(import.meta, 'jest');
if (!isJestRuntime(jestRuntime)) {
  throw new TypeError('Jest ESM runtime is unavailable');
}
const runTarget = jestRuntime.fn<
  ReturnType<typeof runAccountPasswordProofExpiryForTarget>,
  Parameters<typeof runAccountPasswordProofExpiryForTarget>
>();
const unstableMockModule: unknown = Reflect.get(jestRuntime, 'unstable_mockModule');
if (typeof unstableMockModule !== 'function') {
  throw new TypeError('Jest ESM module mocking is unavailable');
}
Reflect.apply(unstableMockModule, jestRuntime, [
  './scenarios/account-password-proof-expiry-target-driver.js',
  () => ({ runAccountPasswordProofExpiryForTarget: runTarget }),
]);

const {
  createAccountExpiryComparisonTarget,
  runAccountExpiryComparison,
  runBoundAccountExpiryComparisonTargets,
} = await import('./account-expiry-comparison.js');

const rootPrefix = '/var/tmp/henry-build/account-expiry-comparison-';
const unavailableRelease = (): never => {
  throw new TypeError('Deferred release unavailable');
};
let root = '';
let driverPath = '';
let receiptPath = '';
let servers: Server[] = [];

const fixture = Object.freeze({
  public: Object.freeze({
    allocationId: 'account-expiry-test',
    clients: Object.freeze({
      basic: Object.freeze({ id: 'basic', method: 'client_secret_basic' }),
      post: Object.freeze({ id: 'post', method: 'client_secret_post' }),
    }),
    deviceClients: Object.freeze({
      firstParty: Object.freeze({
        id: 'first',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      }),
      thirdParty: Object.freeze({
        id: 'third',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      }),
      missingGrant: Object.freeze({
        id: 'missing',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
      ineligibleWeb: Object.freeze({
        id: 'web',
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({ id: 'primary', indicator: 'https://example.invalid/primary' }),
      default: Object.freeze({ id: 'default', indicator: 'https://example.invalid/default' }),
    }),
    organization: Object.freeze({ id: 'organization', scopeName: 'organization:read' }),
    scopes: Object.freeze({
      read: Object.freeze({ id: 'read', name: 'read' }),
      write: Object.freeze({ id: 'write', name: 'write' }),
      unassigned: Object.freeze({ id: 'unassigned', name: 'unassigned' }),
    }),
    boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
  }),
  withSecretLease: async () => {
    throw new Error('target driver is mocked at its public boundary');
  },
}) satisfies ProvisionedPhase2Fixture;

const listen = async (socketPath: string): Promise<Server> =>
  new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.removeListener('error', reject);
      servers.push(server);
      resolve(server);
    });
  });

const closeServer = async (server: Server): Promise<void> =>
  new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
  });

const descriptor = (
  kind: 'oracle' | 'candidate',
  socketPath: string,
  driverSha256: string
): Phase2TargetDescriptor =>
  validatePhase2TargetDescriptor({
    schemaVersion: 1,
    kind,
    sourceCommit: kind === 'oracle' ? '6'.repeat(40) : 'a'.repeat(40),
    imageDigest: `sha256:${kind === 'oracle' ? '7'.repeat(64) : 'b'.repeat(64)}`,
    projectName: 'aster-phase2-client-credentials-0123456789abcdef',
    primaryContainerId: kind === 'oracle' ? '1'.repeat(64) : '3'.repeat(64),
    foreignContainerId: kind === 'oracle' ? '2'.repeat(64) : '4'.repeat(64),
    target: {
      label: kind,
      coreUrl: kind === 'oracle' ? 'http://localhost:3311/' : 'http://localhost:3321/',
      adminUrl: kind === 'oracle' ? 'http://localhost:3411/' : 'http://localhost:3421/',
    },
    foreignTarget: {
      label: kind,
      coreUrl: kind === 'oracle' ? 'http://localhost:3312/' : 'http://localhost:3322/',
      adminUrl: kind === 'oracle' ? 'http://localhost:3412/' : 'http://localhost:3422/',
    },
    stateDriver: { path: driverPath, sha256: driverSha256, controlSocket: socketPath },
    fetchObserverReceiptFile: receiptPath,
    ...(kind === 'candidate'
      ? {
          fixtureExecutable: { path: driverPath, sha256: driverSha256 },
          fixtureSocket: path.join(root, 'candidate-fixture.sock'),
          invariantDriver: {
            path: driverPath,
            sha256: driverSha256,
            controlSocket: path.join(root, 'candidate-invariant.sock'),
          },
        }
      : {}),
  });

beforeAll(async () => {
  root = await mkdtemp(rootPrefix);
  await chmod(root, 0o700);
  driverPath = path.join(root, 'state-driver');
  receiptPath = path.join(root, 'receipts.ndjson');
  await Promise.all([
    writeFile(driverPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 }),
    writeFile(receiptPath, '', { mode: 0o600 }),
  ]);
  await Promise.all([
    listen(path.join(root, 'oracle.sock')),
    listen(path.join(root, 'candidate.sock')),
    listen(path.join(root, 'candidate-fixture.sock')),
    listen(path.join(root, 'candidate-invariant.sock')),
  ]);
  await Promise.all([
    chmod(path.join(root, 'oracle.sock'), 0o600),
    chmod(path.join(root, 'candidate.sock'), 0o600),
    chmod(path.join(root, 'candidate-fixture.sock'), 0o600),
    chmod(path.join(root, 'candidate-invariant.sock'), 0o600),
  ]);
});

afterAll(async () => {
  await Promise.all(servers.map(async (server) => closeServer(server)));
  servers = [];
  await rm(root, { force: true, recursive: true });
});

const prepareTarget = async (kind: 'oracle' | 'candidate') => {
  const driverSha256 = createHash('sha256')
    .update(await readFile(driverPath))
    .digest('hex');
  const source = descriptor(kind, path.join(root, `${kind}.sock`), driverSha256);
  const verified = await verifyPhase2Target(source);
  const sessionRoot = await mkdtemp(path.join(root, `${kind}-session-`));
  await chmod(sessionRoot, 0o700);
  const prepared = await preparePhase2TargetForExecution(verified, sessionRoot, kind);
  return createAccountExpiryComparisonTarget(prepared, fixture);
};

beforeEach(() => {
  runTarget.mockReset();
  runTarget.mockImplementation(async () => accountPasswordProofExpiryExpectedProjection);
});

it('runs the target-driver boundary for both bound prepared targets', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const executions = await runBoundAccountExpiryComparisonTargets(
    { oracle, candidate, signal: new AbortController().signal },
    runTarget
  );
  expect(runTarget).toHaveBeenCalledTimes(2);
  expect(runTarget.mock.calls.map(([input]: [TargetDriverInput]) => input.target.label)).toEqual([
    'oracle',
    'candidate',
  ]);
  expect(executions.map(({ target }) => target)).toEqual([oracle, candidate]);
  expect(executions.map(({ projection }) => projection)).toEqual([
    accountPasswordProofExpiryExpectedProjection,
    accountPasswordProofExpiryExpectedProjection,
  ]);
});

it('waits for the sibling target before preserving one target failure', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const oracleError = new Error('oracle failed');
  let releaseCandidate: () => void = unavailableRelease;
  const candidateGate = new Promise<void>((resolve) => {
    releaseCandidate = resolve;
  });
  let candidateStarted = false;
  let candidateFinished = false;
  let comparisonSettled = false;
  runTarget.mockImplementation(async ({ target }: TargetDriverInput) => {
    if (target.label === 'oracle') {
      throw oracleError;
    }
    candidateStarted = true;
    await candidateGate;
    candidateFinished = true;
    return accountPasswordProofExpiryExpectedProjection;
  });
  const comparison = runBoundAccountExpiryComparisonTargets(
    { oracle, candidate, signal: new AbortController().signal },
    runTarget
  );
  void (async () => {
    try {
      await comparison;
    } catch {
      comparisonSettled = true;
      return;
    }
    comparisonSettled = true;
  })();
  try {
    await setImmediate();
    expect(candidateStarted).toBe(true);
    expect(candidateFinished).toBe(false);
    expect(comparisonSettled).toBe(false);
  } finally {
    releaseCandidate();
  }
  await expect(comparison).rejects.toBe(oracleError);
  expect(candidateFinished).toBe(true);
});

it('preserves two target failures in oracle and candidate order', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const oracleError = new Error('oracle failed');
  const candidateError = new Error('candidate failed');
  runTarget.mockImplementation(async ({ target }: TargetDriverInput) => {
    throw target.label === 'oracle' ? oracleError : candidateError;
  });
  let caught: unknown;
  try {
    await runBoundAccountExpiryComparisonTargets(
      { oracle, candidate, signal: new AbortController().signal },
      runTarget
    );
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors).toEqual([oracleError, candidateError]);
});

it('rejects a forged descriptor/state cross-pair before target execution', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const crossPaired = Object.freeze({ ...oracle, state: candidate.state });
  await expect(
    runAccountExpiryComparison({
      oracle: crossPaired,
      candidate,
      signal: new AbortController().signal,
    })
  ).rejects.toThrow('Invalid Account expiry supplemental comparison');
  expect(runTarget).not.toHaveBeenCalled();
});

it('rejects a transport override at the authoritative evidence boundary', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const input: Parameters<typeof runAccountExpiryComparison>[0] & { fetch: typeof fetch } = {
    oracle,
    candidate,
    signal: new AbortController().signal,
    fetch: jestRuntime.fn(),
  };
  await expect(runAccountExpiryComparison(input)).rejects.toThrow(
    'Invalid Account expiry supplemental comparison'
  );
  expect(runTarget).not.toHaveBeenCalled();
});

it('snapshots each authoritative input capability exactly once', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const reads = { oracle: 0, candidate: 0, signal: 0 };
  const signal = AbortSignal.abort();
  const input = Object.defineProperties(
    {},
    {
      oracle: {
        enumerable: true,
        get: () => {
          reads.oracle += 1;
          return oracle;
        },
      },
      candidate: {
        enumerable: true,
        get: () => {
          reads.candidate += 1;
          return candidate;
        },
      },
      signal: {
        enumerable: true,
        get: () => {
          reads.signal += 1;
          return signal;
        },
      },
    }
  ) as Parameters<typeof runAccountExpiryComparison>[0];
  await expect(runAccountExpiryComparison(input)).rejects.toThrow(
    'Invalid Account expiry supplemental comparison'
  );
  expect(reads).toEqual({ oracle: 1, candidate: 1, signal: 1 });
});

it('returns a divergent security outcome without normalizing it', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  runTarget.mockImplementation(async ({ target }: TargetDriverInput) =>
    target.label === 'oracle'
      ? accountPasswordProofExpiryExpectedProjection
      : {
          ...accountPasswordProofExpiryExpectedProjection,
          mutation: { status: 204, error: 'none' },
        }
  );
  const executions = await runBoundAccountExpiryComparisonTargets(
    { oracle, candidate, signal: new AbortController().signal },
    runTarget
  );
  expect(executions[0].projection.mutation).toEqual({
    status: 401,
    error: 'verification_record.permission_denied',
  });
  expect(executions[1].projection.mutation).toEqual({ status: 204, error: 'none' });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
