/* eslint-disable max-lines, complexity, no-await-in-loop, @silverhand/fp/no-mutating-methods -- The candidate-control runtime serializes eighteen stateful live probes and closes seven comparator mutations into one exact artifact; Task 2 moves the process driver behind this boundary. */
import { isDeepStrictEqual } from 'node:util';

import { compareJson } from '../../compare.js';
import type { Difference, Observation } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import { assertPhase1PublicArtifactValue } from '../artifact-contract.js';
import {
  createPhase1EvidenceProvenance,
  createPhase1ProjectionEnvelope,
  type Phase1EvidenceProvenance,
  type Phase1ProjectionEnvelope,
} from '../evidence-envelope.js';
import { assertPhase1EvidenceIsSanitized, runObservationNegativeControl } from '../evidence.js';
import {
  candidateInvariantScenarioIds,
  cloneAndDeepFreeze,
  phase1ObservationKinds,
  type CandidateInvariantScenarioId,
} from '../model.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import { assertCandidateInvariantProjectionIsSanitized } from './evidence.js';
import {
  runAllCandidateInvariantFakeControls,
  runCandidateInvariantFakeControls,
} from './fake-controls.js';
import { candidateInvariantContracts } from './index.js';

type CandidateControlEnvelope = Phase1ProjectionEnvelope<
  | 'candidate-only'
  | 'positive-control'
  | 'negative-control'
  | 'negative-observation'
  | 'discovery-extra-control'
>;

export type Phase1CandidateControlOutcome = Readonly<{
  id: (typeof candidateInvariantScenarioIds)[number];
  detected: true;
  candidate: CandidateControlEnvelope;
  positiveControl: Readonly<{ detected: true; result: CandidateControlEnvelope }>;
  negativeControl: Readonly<{
    detected: true;
    pointer: string;
    result: CandidateControlEnvelope;
  }>;
}>;

export type Phase1CandidateObservationControl = Readonly<{
  kind: (typeof phase1ObservationKinds)[number];
  pointer: string;
  detected: true;
  observation: CandidateControlEnvelope;
}>;

export type Phase1CandidateControlsEvidence = Readonly<{
  schemaVersion: 1;
  mode: 'review-candidate' | 'mirror-control' | 'runtime-candidate';
  provenance: Phase1EvidenceProvenance;
  sanitizerSuccess: true;
  outcomes: readonly Phase1CandidateControlOutcome[];
  observationNegativeControls: readonly Phase1CandidateObservationControl[];
  discoveryExtraControl: Readonly<{
    pointer: '/value/__unexpected';
    detected: true;
    observation: CandidateControlEnvelope;
  }>;
}>;

export type Phase1LiveCandidateInvariantResult = Readonly<{
  id: CandidateInvariantScenarioId;
  projection: JsonValue;
}>;

export type Phase1CandidateInvariantRuntimeDependencies = Readonly<{
  runLiveInvariant(
    id: CandidateInvariantScenarioId,
    context: Phase1EvidenceRuntimeContext
  ): Promise<Phase1LiveCandidateInvariantResult>;
}>;

const diagnostic = 'Invalid phase 1 candidate control runtime';
const runtimeUnavailable = 'Phase 1 candidate invariant runtime is unavailable';
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;
const allowedModes: ReadonlySet<unknown> = new Set([
  'review-candidate',
  'mirror-control',
  'runtime-candidate',
]);
const observationRoot = '/observations/0';
const discoveryPointer = '/value/__unexpected';

const bytewiseCompare = (left: string, right: string): number =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

const observationFixtures = Object.freeze([
  Object.freeze({ kind: 'http' as const, pointer: '/value/status', value: { status: 200 } }),
  Object.freeze({
    kind: 'redirect' as const,
    pointer: '/value/path',
    value: { path: '/callback' },
  }),
  Object.freeze({
    kind: 'cookie-metadata' as const,
    pointer: '/value/sameSite',
    value: { sameSite: 'Lax' },
  }),
  Object.freeze({ kind: 'jwt-header' as const, pointer: '/value/alg', value: { alg: 'RS256' } }),
  Object.freeze({
    kind: 'jwt-claims' as const,
    pointer: '/value/aud',
    value: { aud: 'urn:aster:phase1-control' },
  }),
  Object.freeze({
    kind: 'semantic-state' as const,
    pointer: '/value/grants/0/scopes/0',
    value: { grants: [{ scopes: ['read'] }] },
  }),
]);

const differenceValue = (value: unknown): JsonValue => {
  if (value === undefined) {
    return '<absent>';
  }
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => differenceValue(item));
  }
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, differenceValue(nested)])
    );
  }

  throw new TypeError(diagnostic);
};

const controlProjection = (
  kind: string,
  pointer: string,
  difference: Difference
): Readonly<JsonObject> => {
  const result = cloneAndDeepFreeze({
    kind,
    pointer,
    baseline: differenceValue(difference.oracle),
    injected: differenceValue(difference.candidate),
  });

  assertCandidateInvariantProjectionIsSanitized(result);

  return result;
};

const envelope = <Label extends CandidateControlEnvelope['label']>(
  label: Label,
  value: unknown
): Phase1ProjectionEnvelope<Label> => {
  assertCandidateInvariantProjectionIsSanitized(value);

  return createPhase1ProjectionEnvelope(label, value);
};

const requireAuthorization = (
  context: Phase1EvidenceRuntimeContext
): 'review-candidate' | 'mirror-control' | 'runtime-candidate' => {
  const { authorization } = context;
  const { mode, profile, provenance, protectedExecution, controls } = authorization;

  if (
    !allowedModes.has(mode) ||
    profile.phase1Harness.commit !== provenance.harnessCommit ||
    !isDeepStrictEqual(profile.candidateInvariantScenarios, candidateInvariantScenarioIds) ||
    !controls.observationControls ||
    !controls.discoveryExtraControl ||
    !controls.candidateInvariantControls ||
    !imageDigestPattern.test(context.oracleImageDigest) ||
    !imageDigestPattern.test(context.candidateImageDigest) ||
    (mode === 'mirror-control' && context.oracleImageDigest !== context.candidateImageDigest) ||
    (mode === 'runtime-candidate' && context.oracleImageDigest === context.candidateImageDigest) ||
    (mode === 'review-candidate'
      ? provenance.kind !== 'review-candidate' || protectedExecution !== undefined
      : provenance.kind !== 'accepted-harness' ||
        protectedExecution?.mode !== mode ||
        protectedExecution.provenance !== provenance)
  ) {
    throw new TypeError(diagnostic);
  }

  return mode;
};

const createFakeOutcomes = (): readonly Phase1CandidateControlOutcome[] => {
  const evidence = runAllCandidateInvariantFakeControls();

  if (evidence.length !== candidateInvariantContracts.length) {
    throw new TypeError(diagnostic);
  }
  const outcomes = evidence.map((result, index): Phase1CandidateControlOutcome => {
    const contract = candidateInvariantContracts[index];
    const difference = result.negativeControl.differences[0];

    if (
      !contract ||
      result.scenarioId !== contract.id ||
      result.positiveControl.differences.length > 0 ||
      result.negativeControl.differences.length !== 1 ||
      !difference ||
      difference.path !== contract.negativeControl.expectedDifferencePointer
    ) {
      throw new TypeError(diagnostic);
    }

    return cloneAndDeepFreeze({
      id: contract.id,
      detected: true as const,
      candidate: envelope('candidate-only', result.candidate.outcome),
      positiveControl: {
        detected: true as const,
        result: envelope('positive-control', contract.positiveControl.expectedProjection),
      },
      negativeControl: {
        detected: true as const,
        pointer: difference.path,
        result: envelope('negative-control', contract.negativeControl.expectedProjection),
      },
    });
  });

  return Object.freeze(outcomes.toSorted((left, right) => bytewiseCompare(left.id, right.id)));
};

const liveOutcome = (
  contract: (typeof candidateInvariantContracts)[number],
  projection: JsonValue
): Phase1CandidateControlOutcome => {
  const snapshot = cloneAndDeepFreeze(projection);

  assertCandidateInvariantProjectionIsSanitized(snapshot);
  if (!isDeepStrictEqual(snapshot, contract.positiveControl.expectedProjection)) {
    throw new TypeError(diagnostic);
  }
  const control = runCandidateInvariantFakeControls(contract.id);
  const difference = control.negativeControl.differences[0];

  if (
    control.positiveControl.differences.length > 0 ||
    control.negativeControl.differences.length !== 1 ||
    !difference ||
    difference.path !== contract.negativeControl.expectedDifferencePointer
  ) {
    throw new TypeError(diagnostic);
  }

  return cloneAndDeepFreeze({
    id: contract.id,
    detected: true as const,
    candidate: envelope('candidate-only', snapshot),
    positiveControl: {
      detected: true as const,
      result: envelope('positive-control', snapshot),
    },
    negativeControl: {
      detected: true as const,
      pointer: difference.path,
      result: envelope('negative-control', contract.negativeControl.expectedProjection),
    },
  });
};

const createLiveOutcomes = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies: Phase1CandidateInvariantRuntimeDependencies
): Promise<readonly Phase1CandidateControlOutcome[]> => {
  const outcomes: Phase1CandidateControlOutcome[] = [];

  for (const contract of candidateInvariantContracts) {
    const result = await dependencies.runLiveInvariant(contract.id, context);

    if (result.id !== contract.id) {
      throw new TypeError(diagnostic);
    }
    outcomes.push(liveOutcome(contract, result.projection));
  }

  return Object.freeze(outcomes.toSorted((left, right) => bytewiseCompare(left.id, right.id)));
};

const requireLiveDependencies = (
  dependencies: Phase1CandidateInvariantRuntimeDependencies | undefined
): Phase1CandidateInvariantRuntimeDependencies => {
  if (!dependencies) {
    throw new TypeError(diagnostic);
  }

  return dependencies;
};

const createObservationControls = (): readonly Phase1CandidateObservationControl[] =>
  Object.freeze(
    observationFixtures.map((fixture, index): Phase1CandidateObservationControl => {
      if (fixture.kind !== phase1ObservationKinds[index]) {
        throw new TypeError(diagnostic);
      }
      const result = runObservationNegativeControl({
        stepId: 'phase1-negative-control',
        kind: fixture.kind,
        value: fixture.value,
      });
      const difference = result.differences[0];

      if (
        result.differences.length !== 1 ||
        !difference ||
        result.differencePath !== `${observationRoot}${fixture.pointer}`
      ) {
        throw new TypeError(diagnostic);
      }

      return cloneAndDeepFreeze({
        kind: fixture.kind,
        pointer: fixture.pointer,
        detected: true as const,
        observation: envelope(
          'negative-observation',
          controlProjection(fixture.kind, fixture.pointer, difference)
        ),
      });
    })
  );

const createDiscoveryExtraControl =
  (): Phase1CandidateControlsEvidence['discoveryExtraControl'] => {
    const original: Observation = Object.freeze({
      stepId: 'phase1-discovery-extra-control',
      kind: 'http',
      value: Object.freeze({ status: 200 }),
    });
    const mutated: Observation = Object.freeze({
      ...original,
      value: Object.freeze({ status: 200, __unexpected: true }),
    });
    const differences = compareJson({ observations: [original] }, { observations: [mutated] });
    const difference = differences[0];

    if (
      differences.length !== 1 ||
      !difference ||
      difference.path !== `${observationRoot}${discoveryPointer}`
    ) {
      throw new TypeError(diagnostic);
    }

    return cloneAndDeepFreeze({
      pointer: discoveryPointer,
      detected: true as const,
      observation: envelope(
        'discovery-extra-control',
        controlProjection('discovery-extra-field', discoveryPointer, difference)
      ),
    });
  };

const executeCandidateControlRuntime = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies?: Phase1CandidateInvariantRuntimeDependencies
): Promise<Phase1CandidateControlsEvidence> => {
  if (context.authorization.mode === 'runtime-candidate' && !dependencies) {
    throw new TypeError(runtimeUnavailable);
  }

  try {
    const mode = requireAuthorization(context);
    const harnessCommit = context.authorization.profile.phase1Harness.commit;

    if (typeof harnessCommit !== 'string') {
      throw new TypeError(diagnostic);
    }
    const outcomes =
      mode === 'runtime-candidate'
        ? await createLiveOutcomes(context, requireLiveDependencies(dependencies))
        : createFakeOutcomes();
    const result = cloneAndDeepFreeze({
      schemaVersion: 1 as const,
      mode,
      provenance: createPhase1EvidenceProvenance({
        harnessCommit,
        profileSha256: context.authorization.profileSha256,
        schemaSha256: context.authorization.schemaSha256,
        imageDigest:
          mode === 'runtime-candidate' ? context.candidateImageDigest : context.oracleImageDigest,
      }),
      sanitizerSuccess: true as const,
      outcomes,
      observationNegativeControls: createObservationControls(),
      discoveryExtraControl: createDiscoveryExtraControl(),
    });

    assertPhase1EvidenceIsSanitized(result);
    assertPhase1PublicArtifactValue(result);

    return result;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runPhase1CandidateControlRuntime = async (
  context: Phase1EvidenceRuntimeContext
): Promise<Phase1CandidateControlsEvidence> => executeCandidateControlRuntime(context);

export const runPhase1CandidateControlRuntimeForTesting = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies: Phase1CandidateInvariantRuntimeDependencies
): Promise<Phase1CandidateControlsEvidence> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }

  return executeCandidateControlRuntime(context, dependencies);
};

/* eslint-enable max-lines, complexity, no-await-in-loop, @silverhand/fp/no-mutating-methods */
