import { isDeepStrictEqual } from 'node:util';

import type { ProvisionedPhase2Fixture } from './fixtures.js';
import {
  assertPreparedPhase2TargetCapability,
  createCommandPhase2ScenarioStateDriver,
  type Phase2TargetDescriptor,
  type PreparedPhase2Target,
} from './runtime.js';
import { runAccountPasswordProofExpiryForTarget } from './scenarios/account-password-proof-expiry-target-driver.js';
import {
  accountPasswordProofExpiryScenarioId,
  assertAccountPasswordProofExpiryProjection,
  compareAccountPasswordProofExpiryProjections,
  type AccountPasswordProofExpiryProjection,
  type AccountPasswordProofStateDriver,
} from './scenarios/account-password-proof-expiry.js';

export type AccountExpiryComparisonTarget = Readonly<{
  descriptor: Phase2TargetDescriptor;
  fixture: ProvisionedPhase2Fixture;
  state: AccountPasswordProofStateDriver;
}>;
const accountExpiryComparisonTargets = new WeakSet<Record<string, unknown>>();

type AccountExpirySourceBinding = Readonly<{
  sourceCommit: string;
  imageDigest: string;
  stateDriverSha256: string;
}>;

export type AccountExpiryComparisonEvidence = Readonly<{
  schemaVersion: 1;
  kind: 'aster-account-expiry-supplemental-comparison';
  scenarioId: typeof accountPasswordProofExpiryScenarioId;
  oracle: Readonly<{
    binding: AccountExpirySourceBinding;
    projection: AccountPasswordProofExpiryProjection;
  }>;
  candidate: Readonly<{
    binding: AccountExpirySourceBinding;
    projection: AccountPasswordProofExpiryProjection;
  }>;
  differences: readonly never[];
}>;

const fail = (): never => {
  throw new TypeError('Invalid Account expiry supplemental comparison');
};

const binding = (descriptor: Phase2TargetDescriptor): AccountExpirySourceBinding =>
  Object.freeze({
    sourceCommit: descriptor.sourceCommit,
    imageDigest: descriptor.imageDigest,
    stateDriverSha256: descriptor.stateDriver.sha256,
  });

export const createAccountExpiryComparisonTarget = async (
  preparedInput: PreparedPhase2Target,
  fixture: ProvisionedPhase2Fixture
): Promise<AccountExpiryComparisonTarget> => {
  const prepared = assertPreparedPhase2TargetCapability(preparedInput);
  const state = await createCommandPhase2ScenarioStateDriver({
    descriptor: prepared.descriptor,
    identityFence: prepared.fence,
  });
  const target = Object.freeze({ descriptor: prepared.descriptor, fixture, state });
  accountExpiryComparisonTargets.add(target);
  return target;
};

type AccountExpiryTargetExecutor = typeof runAccountPasswordProofExpiryForTarget;

export const runBoundAccountExpiryComparisonTargets = async (
  input: Readonly<{
    oracle: AccountExpiryComparisonTarget;
    candidate: AccountExpiryComparisonTarget;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>,
  executeTarget: AccountExpiryTargetExecutor
): Promise<
  readonly [
    Readonly<{
      target: AccountExpiryComparisonTarget;
      projection: AccountPasswordProofExpiryProjection;
    }>,
    Readonly<{
      target: AccountExpiryComparisonTarget;
      projection: AccountPasswordProofExpiryProjection;
    }>,
  ]
> => {
  const { oracle, candidate, signal, fetch: requestFetch } = input;
  if (
    signal.aborted ||
    !accountExpiryComparisonTargets.has(oracle) ||
    !accountExpiryComparisonTargets.has(candidate) ||
    oracle.descriptor.kind !== 'oracle' ||
    candidate.descriptor.kind !== 'candidate'
  ) {
    return fail();
  }
  const [oracleResult, candidateResult] = await Promise.allSettled([
    executeTarget({
      target: oracle.descriptor.target,
      fixture: oracle.fixture,
      state: oracle.state,
      signal,
      fetch: requestFetch,
    }),
    executeTarget({
      target: candidate.descriptor.target,
      fixture: candidate.fixture,
      state: candidate.state,
      signal,
      fetch: requestFetch,
    }),
  ]);
  if (oracleResult.status === 'rejected' && candidateResult.status === 'rejected') {
    throw new AggregateError(
      [oracleResult.reason, candidateResult.reason],
      'Account expiry comparison targets failed'
    );
  }
  if (oracleResult.status === 'rejected') {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Preserve the executor's original rejection reason.
    throw oracleResult.reason;
  }
  if (candidateResult.status === 'rejected') {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Preserve the executor's original rejection reason.
    throw candidateResult.reason;
  }
  const oracleProjection = oracleResult.value;
  const candidateProjection = candidateResult.value;
  return [
    Object.freeze({ target: oracle, projection: oracleProjection }),
    Object.freeze({ target: candidate, projection: candidateProjection }),
  ];
};

export const runAccountExpiryComparison = async (
  input: Readonly<{
    oracle: AccountExpiryComparisonTarget;
    candidate: AccountExpiryComparisonTarget;
    signal: AbortSignal;
  }>
): Promise<AccountExpiryComparisonEvidence> => {
  if (
    Object.keys(input).length !== 3 ||
    !Object.hasOwn(input, 'oracle') ||
    !Object.hasOwn(input, 'candidate') ||
    !Object.hasOwn(input, 'signal')
  ) {
    return fail();
  }
  const { oracle: oracleTarget, candidate: candidateTarget, signal } = input;
  const [oracleExecution, candidateExecution] = await runBoundAccountExpiryComparisonTargets(
    { oracle: oracleTarget, candidate: candidateTarget, signal },
    runAccountPasswordProofExpiryForTarget
  );
  const oracle = assertAccountPasswordProofExpiryProjection(oracleExecution.projection);
  const candidate = assertAccountPasswordProofExpiryProjection(candidateExecution.projection);
  const differences = compareAccountPasswordProofExpiryProjections(oracle, candidate);
  if (differences.length > 0 || !isDeepStrictEqual(oracle, candidate)) {
    return fail();
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'aster-account-expiry-supplemental-comparison',
    scenarioId: accountPasswordProofExpiryScenarioId,
    oracle: Object.freeze({
      binding: binding(oracleExecution.target.descriptor),
      projection: oracle,
    }),
    candidate: Object.freeze({
      binding: binding(candidateExecution.target.descriptor),
      projection: candidate,
    }),
    differences: Object.freeze([] as const),
  });
};
