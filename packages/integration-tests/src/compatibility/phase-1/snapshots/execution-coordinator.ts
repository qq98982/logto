/* eslint-disable max-lines, max-params, complexity, no-restricted-syntax, no-await-in-loop, no-use-extend-native/no-use-extend-native, unicorn/no-await-expression-member, @typescript-eslint/no-empty-function, @typescript-eslint/no-non-null-assertion, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This closed composition root validates heterogeneous registries, ordered artifacts, transactional publication, and snapshot authority in one auditable boundary. */
import { lstat, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { compareJson } from '../../compare.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import {
  assertPhase1PublicArtifactValue,
  bytewiseCompare,
  canonicalPhase1ArtifactBytes,
  exactArtifactKeys,
  isArtifactRecord,
  phase1ArtifactMaximumBytes,
  phase1EvidenceFileNames,
  type Phase1EvidenceFileName,
} from '../artifact-contract.js';
import { runPhase1BrowserRuntime } from '../browser/runtime.js';
import { assertCandidateInvariantProjectionIsSanitized } from '../candidate-invariants/evidence.js';
import { candidateInvariantContracts } from '../candidate-invariants/index.js';
import { runPhase1CandidateControlRuntime } from '../candidate-invariants/runtime.js';
import { phase1ConformanceAdapterControlIds } from '../conformance/runner.js';
import { runPhase1ConformanceRuntime } from '../conformance/runtime.js';
import { runPhase1DifferentialRuntime } from '../differential/runtime.js';
import { hashCanonicalPhase1Json } from '../evidence-envelope.js';
import { oracleCommit, phase1ObservationKinds } from '../model.js';
import type { Phase1RunAuthorization } from '../run-authorization.js';
import { phase1ScenarioContracts } from '../scenario-contracts.js';
import {
  createSecureEvidenceSink,
  type SecureEvidenceInputAuthority,
  type SecureEvidenceSink,
} from '../secure-evidence-sink.js';

import { createOracleSnapshotSet } from './oracle.js';
import {
  assertValidatedPhase1EvidenceRuntimeContext,
  createPhase1EvidenceRuntimeContext,
  type Phase1EvidenceRuntimeContext,
  type Phase1RuntimeIsolationAttestations,
} from './runtime-context.js';
import {
  loadImmutableOracleSnapshotSet,
  rollbackImmutableOracleSnapshotSet,
  writeImmutableOracleSnapshotSet,
} from './store.js';

export type Phase1EvidenceExecutionPorts = Readonly<{
  differential(context: Phase1EvidenceRuntimeContext): Promise<unknown>;
  browser(context: Phase1EvidenceRuntimeContext): Promise<unknown>;
  candidateControls(context: Phase1EvidenceRuntimeContext): Promise<unknown>;
  conformance(context: Phase1EvidenceRuntimeContext): Promise<unknown>;
}>;

type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;
type Phase1ExecutionCoordinatorDependencies = Readonly<{
  createSink(
    root: string,
    allowlist: readonly string[],
    authority: SecureEvidenceInputAuthority
  ): Promise<SecureEvidenceSink>;
}>;

const diagnostic = 'Phase 1 evidence execution failed.';
const directCliDiagnostic = 'Direct Phase 1 coordinator execution is unavailable.';
const sha256Pattern = /^[0-9a-f]{64}$/u;
const containerIdPattern = /^[0-9a-f]{12,64}$/u;
const resultIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const topologyIdPattern = /^aster-phase1-[0-9a-f]{16}$/u;
const observationPointers = Object.freeze({
  http: '/value/status',
  redirect: '/value/path',
  'cookie-metadata': '/value/sameSite',
  'jwt-header': '/value/alg',
  'jwt-claims': '/value/aud',
  'semantic-state': '/value/grants/0/scopes/0',
} as const);
const observationControlValues = Object.freeze({
  http: Object.freeze({ baseline: 200, injected: 201 }),
  redirect: Object.freeze({ baseline: '/callback', injected: '/callback-control' }),
  'cookie-metadata': Object.freeze({ baseline: 'Lax', injected: 'Strict' }),
  'jwt-header': Object.freeze({ baseline: 'RS256', injected: 'ES256' }),
  'jwt-claims': Object.freeze({
    baseline: 'urn:aster:phase1-control',
    injected: 'urn:aster:phase1-control-control',
  }),
  'semantic-state': Object.freeze({ baseline: 'read', injected: 'read-control' }),
} as const);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const exactRecord = (value: unknown, keys: readonly string[]) => {
  if (!isArtifactRecord(value) || !exactArtifactKeys(value, keys)) {
    return fail();
  }

  return value;
};

const exactArray = (value: unknown): readonly unknown[] => (Array.isArray(value) ? value : fail());

const requireCommonArtifact = (
  value: unknown,
  context: Phase1EvidenceRuntimeContext,
  detailKeys: readonly string[]
) => {
  assertPhase1PublicArtifactValue(value);
  const root = exactRecord(value, [
    'schemaVersion',
    'mode',
    'provenance',
    'sanitizerSuccess',
    ...detailKeys,
  ]);
  const harnessCommit = context.authorization.profile.phase1Harness.commit;
  const provenance = exactRecord(root.provenance, [
    'harnessCommit',
    'profileSha256',
    'schemaSha256',
    'imageDigest',
  ]);

  if (
    root.schemaVersion !== 1 ||
    root.mode !== context.authorization.mode ||
    root.sanitizerSuccess !== true ||
    typeof harnessCommit !== 'string' ||
    provenance.harnessCommit !== harnessCommit ||
    provenance.profileSha256 !== context.authorization.profileSha256 ||
    provenance.schemaSha256 !== context.authorization.schemaSha256 ||
    provenance.imageDigest !== context.oracleImageDigest
  ) {
    return fail();
  }

  if (canonicalPhase1ArtifactBytes(value).byteLength > phase1ArtifactMaximumBytes) {
    return fail();
  }

  return root;
};

const requireEnvelope = (value: unknown, label: string) => {
  const envelope = exactRecord(value, ['label', 'projectionSha256', 'value']);

  if (!isArtifactRecord(envelope.value)) {
    return fail();
  }
  const projection = envelope.value;

  if (
    envelope.label !== label ||
    typeof envelope.projectionSha256 !== 'string' ||
    !sha256Pattern.test(envelope.projectionSha256) ||
    envelope.projectionSha256 !== hashCanonicalPhase1Json(projection)
  ) {
    return fail();
  }
  return envelope as Readonly<{
    label: string;
    projectionSha256: string;
    value: Readonly<JsonObject>;
  }>;
};

const requireCandidateControlProjection = (
  envelope: ReturnType<typeof requireEnvelope>,
  expected: Readonly<{ kind: string; pointer: string; baseline: unknown; injected: unknown }>
): void => {
  const projection = exactRecord(envelope.value, ['kind', 'pointer', 'baseline', 'injected']);

  assertCandidateInvariantProjectionIsSanitized(projection);
  if (!isDeepStrictEqual(projection, expected)) {
    return fail();
  }
};

const requireSortedExactIds = (items: readonly unknown[], expectedIds: readonly string[]): void => {
  const ids = items.map((item) => {
    if (!isArtifactRecord(item) || typeof item.id !== 'string') {
      return fail();
    }

    return item.id;
  });

  if (!isDeepStrictEqual(ids, expectedIds)) {
    return fail();
  }
};

const scenarioStepProjectionKeys = Object.freeze([
  'status',
  'mediaType',
  'error',
  'headers',
  'body',
  'redirect',
  'cookies',
  'urls',
  'tokens',
  'generatedIds',
  'persistedState',
  'semanticState',
  'sideEffects',
  'outcomes',
] as const);

const requireScenarioProjection = (
  envelope: ReturnType<typeof requireEnvelope>,
  expectedStepIds: readonly string[]
): void => {
  const projection = exactRecord(envelope.value, ['steps']);
  const steps = exactRecord(projection.steps, expectedStepIds);

  if (JSON.stringify(Object.keys(steps)) !== JSON.stringify(expectedStepIds)) {
    return fail();
  }
  for (const stepId of expectedStepIds) {
    const step = exactRecord(steps[stepId], ['value']);

    exactRecord(step.value, scenarioStepProjectionKeys);
  }
};

const requireComparableEntry = (
  value: unknown,
  id: string,
  oracleLabel: string,
  candidateLabel: string,
  expectedStepIds?: readonly string[]
): void => {
  const entry = exactRecord(value, ['id', 'oracle', 'candidate', 'differences']);
  const oracle = requireEnvelope(entry.oracle, oracleLabel);
  const candidate = requireEnvelope(entry.candidate, candidateLabel);
  const differences = exactArray(entry.differences);
  const expectedDifferences = compareJson(
    oracle.value as unknown as JsonValue,
    candidate.value as unknown as JsonValue
  );

  if (expectedStepIds) {
    requireScenarioProjection(oracle, expectedStepIds);
    requireScenarioProjection(candidate, expectedStepIds);
  }

  if (
    entry.id !== id ||
    differences.length > 0 ||
    !isDeepStrictEqual(differences, expectedDifferences)
  ) {
    return fail();
  }
};

const validateDifferential = (value: unknown, context: Phase1EvidenceRuntimeContext): JsonValue => {
  const root = requireCommonArtifact(value, context, ['scenarios']);
  const scenarios = exactArray(root.scenarios);
  const expectedIds = [...context.authorization.profile.differentialScenarios].toSorted(
    bytewiseCompare
  );
  const contractById = new Map<string, (typeof phase1ScenarioContracts)[number]>(
    phase1ScenarioContracts.map((contract) => [contract.id, contract])
  );

  requireSortedExactIds(scenarios, expectedIds);
  for (const [index, scenario] of scenarios.entries()) {
    const id = expectedIds[index] ?? fail();
    const contract = contractById.get(id) ?? fail();
    requireComparableEntry(
      scenario,
      id,
      'oracle',
      'candidate',
      contract.orderedSteps.map(({ id: stepId }) => stepId)
    );
  }

  return value as JsonValue;
};

const validateBrowser = (value: unknown, context: Phase1EvidenceRuntimeContext): JsonValue => {
  const root = requireCommonArtifact(value, context, ['flows']);
  const flows = exactArray(root.flows);
  const expectedIds = context.authorization.profile.browserFlows
    .map(({ id }) => id)
    .toSorted(bytewiseCompare);

  requireSortedExactIds(flows, expectedIds);
  for (const [index, flow] of flows.entries()) {
    requireComparableEntry(
      flow,
      expectedIds[index] ?? fail(),
      'oracle-browser',
      'candidate-browser'
    );
  }

  return value as JsonValue;
};

const validateCandidateControls = (
  value: unknown,
  context: Phase1EvidenceRuntimeContext
): JsonValue => {
  const root = requireCommonArtifact(value, context, [
    'outcomes',
    'observationNegativeControls',
    'discoveryExtraControl',
  ]);
  const outcomes = exactArray(root.outcomes);
  const expectedIds = [...context.authorization.profile.candidateInvariantScenarios].toSorted(
    bytewiseCompare
  );
  const contracts = new Map<string, (typeof candidateInvariantContracts)[number]>(
    candidateInvariantContracts.map((contract) => [contract.id, contract])
  );

  requireSortedExactIds(outcomes, expectedIds);
  for (const [index, candidate] of outcomes.entries()) {
    const outcome = exactRecord(candidate, [
      'id',
      'detected',
      'candidate',
      'positiveControl',
      'negativeControl',
    ]);
    const id = expectedIds[index] ?? fail();
    const contract = contracts.get(id) ?? fail();
    const candidateEnvelope = requireEnvelope(outcome.candidate, 'candidate-only');
    const positive = exactRecord(outcome.positiveControl, ['detected', 'result']);
    const negative = exactRecord(outcome.negativeControl, ['detected', 'pointer', 'result']);
    const positiveEnvelope = requireEnvelope(positive.result, 'positive-control');
    const negativeEnvelope = requireEnvelope(negative.result, 'negative-control');

    assertCandidateInvariantProjectionIsSanitized(candidateEnvelope.value);
    assertCandidateInvariantProjectionIsSanitized(positiveEnvelope.value);
    assertCandidateInvariantProjectionIsSanitized(negativeEnvelope.value);

    if (
      outcome.id !== id ||
      outcome.detected !== true ||
      positive.detected !== true ||
      negative.detected !== true ||
      negative.pointer !== contract.negativeControl.expectedDifferencePointer ||
      !isDeepStrictEqual(candidateEnvelope.value, contract.positiveControl.expectedProjection) ||
      !isDeepStrictEqual(positiveEnvelope.value, contract.positiveControl.expectedProjection) ||
      !isDeepStrictEqual(negativeEnvelope.value, contract.negativeControl.expectedProjection)
    ) {
      fail();
    }
  }

  const observations = exactArray(root.observationNegativeControls);

  if (observations.length !== phase1ObservationKinds.length) {
    return fail();
  }
  for (const [index, candidate] of observations.entries()) {
    const control = exactRecord(candidate, ['kind', 'pointer', 'detected', 'observation']);
    const kind = phase1ObservationKinds[index] ?? fail();
    const observation = requireEnvelope(control.observation, 'negative-observation');
    const values = observationControlValues[kind];

    if (
      control.kind !== kind ||
      control.pointer !== observationPointers[kind] ||
      control.detected !== true ||
      observation.value.kind !== kind ||
      observation.value.pointer !== observationPointers[kind]
    ) {
      fail();
    }
    requireCandidateControlProjection(observation, {
      kind,
      pointer: observationPointers[kind],
      baseline: values.baseline,
      injected: values.injected,
    });
  }

  const discovery = exactRecord(root.discoveryExtraControl, ['pointer', 'detected', 'observation']);
  const discoveryEnvelope = requireEnvelope(discovery.observation, 'discovery-extra-control');

  if (
    discovery.pointer !== '/value/__unexpected' ||
    discovery.detected !== true ||
    discoveryEnvelope.value.pointer !== '/value/__unexpected'
  ) {
    return fail();
  }
  requireCandidateControlProjection(discoveryEnvelope, {
    kind: 'discovery-extra-field',
    pointer: '/value/__unexpected',
    baseline: '<absent>',
    injected: true,
  });

  return value as JsonValue;
};

const validateConformance = (value: unknown, context: Phase1EvidenceRuntimeContext): JsonValue => {
  const root = requireCommonArtifact(value, context, [
    'adapterControls',
    'officialResultIds',
    'planResults',
  ]);
  const controls = exactArray(root.adapterControls);
  const expectedIds = [...phase1ConformanceAdapterControlIds];

  requireSortedExactIds(controls, expectedIds);
  for (const [index, candidate] of controls.entries()) {
    const control = exactRecord(candidate, ['id', 'detected', 'result']);
    const result = requireEnvelope(control.result, 'adapter-control');
    if (
      control.id !== expectedIds[index] ||
      control.detected !== true ||
      !isDeepStrictEqual(result.value, { configured: true, redirectUriMatches: true })
    ) {
      fail();
    }
  }

  const officialResultIds = exactArray(root.officialResultIds);
  const planResults = exactArray(root.planResults);

  if (context.authorization.mode !== 'runtime-candidate') {
    if (officialResultIds.length > 0 || planResults.length > 0) {
      return fail();
    }
    return value as JsonValue;
  }

  const expectedPlanIds = context.authorization.profile.conformance.plans
    .map(({ testPlanName }) => testPlanName)
    .toSorted(bytewiseCompare);
  const expectedPlanIdSet = new Set<string>(expectedPlanIds);

  const officialIds = officialResultIds.filter(
    (id): id is string => typeof id === 'string' && resultIdPattern.test(id)
  );

  if (
    officialResultIds.length !== expectedPlanIds.length ||
    officialIds.length !== officialResultIds.length ||
    officialIds.some(
      (id, index) =>
        expectedPlanIdSet.has(id) ||
        (index > 0 && bytewiseCompare(officialIds[index - 1]!, id) >= 0)
    ) ||
    planResults.length !== expectedPlanIds.length
  ) {
    return fail();
  }
  const observedResultIds: string[] = [];
  for (const [index, candidate] of planResults.entries()) {
    const result = exactRecord(candidate, ['planId', 'resultId', 'resultSha256', 'result']);
    const envelope = requireEnvelope(result.result, 'official-plan-result');
    const resultId = typeof result.resultId === 'string' ? result.resultId : fail();
    if (
      result.planId !== expectedPlanIds[index] ||
      !officialIds.includes(resultId) ||
      result.resultSha256 !== envelope.projectionSha256
    ) {
      fail();
    }
    observedResultIds.push(resultId);
  }
  if (!isDeepStrictEqual(observedResultIds.toSorted(bytewiseCompare), officialIds)) {
    return fail();
  }

  return value as JsonValue;
};

export const validatePhase1EvidenceArtifactForTesting = (
  name: Phase1EvidenceFileName,
  value: unknown,
  context: Phase1EvidenceRuntimeContext
): JsonValue => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  if (name === 'phase-1-differential.json') {
    return validateDifferential(value, context);
  }
  if (name === 'phase-1-browser.json') {
    return validateBrowser(value, context);
  }
  if (name === 'phase-1-candidate-invariants.json') {
    return validateCandidateControls(value, context);
  }

  return validateConformance(value, context);
};

const assertPrivateEmptyDirectory = async (directory: string): Promise<void> => {
  const state = await lstat(directory);

  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.mode % 0o1000 !== 0o700 ||
    (typeof process.getuid === 'function' && state.uid !== process.getuid()) ||
    (await realpath(directory)) !== directory ||
    (await readdir(directory)).length > 0
  ) {
    return fail();
  }
};

const createCurrentOracleSnapshotSet = (
  context: Phase1EvidenceRuntimeContext,
  results: Readonly<Record<Phase1EvidenceFileName, JsonValue>>
) => {
  const differential = exactRecord(results['phase-1-differential.json'], [
    'schemaVersion',
    'mode',
    'provenance',
    'sanitizerSuccess',
    'scenarios',
  ]);
  const browser = exactRecord(results['phase-1-browser.json'], [
    'schemaVersion',
    'mode',
    'provenance',
    'sanitizerSuccess',
    'flows',
  ]);
  const projections = [
    ...exactArray(differential.scenarios).map((candidate) => {
      const scenario = exactRecord(candidate, ['id', 'oracle', 'candidate', 'differences']);
      const id = typeof scenario.id === 'string' ? scenario.id : fail();

      return {
        id: `scenario:${id}`,
        value: requireEnvelope(scenario.oracle, 'oracle').value,
      };
    }),
    ...exactArray(browser.flows).map((candidate) => {
      const flow = exactRecord(candidate, ['id', 'oracle', 'candidate', 'differences']);
      const id = typeof flow.id === 'string' ? flow.id : fail();

      return {
        id: `browser:${id}`,
        value: requireEnvelope(flow.oracle, 'oracle-browser').value,
      };
    }),
  ];

  return createOracleSnapshotSet({
    recordOracle: true,
    referenceCommit: oracleCommit,
    imageDigest: context.oracleImageDigest,
    harnessClean: true,
    sanitizerSuccess: true,
    projections,
  });
};

const executeEvidence = async (
  context: Phase1EvidenceRuntimeContext,
  ports: Phase1EvidenceExecutionPorts,
  dependencies: Phase1ExecutionCoordinatorDependencies
): Promise<readonly string[]> => {
  let snapshotPublication: Awaited<ReturnType<typeof writeImmutableOracleSnapshotSet>> | undefined;

  try {
    assertValidatedPhase1EvidenceRuntimeContext(context);
    await assertPrivateEmptyDirectory(context.evidenceDirectory);
    const results: Readonly<Record<Phase1EvidenceFileName, JsonValue>> = {
      'phase-1-differential.json': validateDifferential(await ports.differential(context), context),
      'phase-1-browser.json': validateBrowser(await ports.browser(context), context),
      'phase-1-candidate-invariants.json': validateCandidateControls(
        await ports.candidateControls(context),
        context
      ),
      'phase-1-conformance.json': validateConformance(await ports.conformance(context), context),
    };
    const currentSnapshotSet = createCurrentOracleSnapshotSet(context, results);

    if (context.authorization.controls.recordOracle) {
      if (context.authorization.mode !== 'review-candidate') {
        return fail();
      }
      snapshotPublication = await writeImmutableOracleSnapshotSet(
        context.oracleSnapshotPath,
        currentSnapshotSet
      );
    } else {
      const expectedSnapshotSet = await loadImmutableOracleSnapshotSet(context.oracleSnapshotPath);

      if (!isDeepStrictEqual(expectedSnapshotSet, currentSnapshotSet)) {
        return fail();
      }
    }
    const trustedInputs = new WeakMap<
      Record<string, unknown>,
      Readonly<{ name: Phase1EvidenceFileName; serialized: string }>
    >(
      phase1EvidenceFileNames.map((name) => {
        const value = results[name];

        return [
          value as Record<string, unknown>,
          Object.freeze({
            name,
            serialized: Buffer.from(canonicalPhase1ArtifactBytes(value)).toString('utf8'),
          }),
        ];
      })
    );
    const authority: SecureEvidenceInputAuthority = Object.freeze({
      consume: ({ name, source, snapshot, serialized }) => {
        const expected =
          typeof source === 'object' && source !== null
            ? trustedInputs.get(source as Record<string, unknown>)
            : undefined;

        if (
          expected === undefined ||
          expected.name !== name ||
          expected.serialized !== serialized ||
          !isDeepStrictEqual(snapshot, source) ||
          Buffer.from(canonicalPhase1ArtifactBytes(snapshot)).toString('utf8') !== serialized ||
          !trustedInputs.delete(source as Record<string, unknown>)
        ) {
          throw new TypeError(diagnostic);
        }
      },
    });
    const sink = await dependencies.createSink(
      context.evidenceDirectory,
      phase1EvidenceFileNames,
      authority
    );
    const publications: string[] = [];
    const publishedNames: Phase1EvidenceFileName[] = [];

    try {
      for (const name of phase1EvidenceFileNames) {
        publications.push(await sink.write(name, results[name]));
        publishedNames.push(name);
      }
      const verified = await sink.scan();
      const expectedPaths = phase1EvidenceFileNames
        .map((name) => path.join(context.evidenceDirectory, name))
        .toSorted(bytewiseCompare);

      if (JSON.stringify(verified) !== JSON.stringify(expectedPaths)) {
        throw new TypeError(diagnostic);
      }
    } catch {
      let rollbackFailed = false;

      for (const name of publishedNames.toReversed()) {
        try {
          await sink.rollback(name);
        } catch {
          rollbackFailed = true;
        }
      }
      const remaining = await readdir(context.evidenceDirectory).catch(() => ['unreadable']);

      if (rollbackFailed || remaining.length > 0) {
        throw new TypeError(diagnostic);
      }
      throw new TypeError(diagnostic);
    }

    return Object.freeze(publications);
  } catch {
    if (snapshotPublication) {
      await rollbackImmutableOracleSnapshotSet(snapshotPublication).catch(() => {});
    }
    throw new TypeError(diagnostic);
  }
};

const differentialEvidenceName = 'phase-1-differential.json';

const executeDifferentialGate = async (
  context: Phase1EvidenceRuntimeContext,
  differential: Phase1EvidenceExecutionPorts['differential'],
  dependencies: Phase1ExecutionCoordinatorDependencies
): Promise<readonly string[]> => {
  try {
    assertValidatedPhase1EvidenceRuntimeContext(context);
    await assertPrivateEmptyDirectory(context.evidenceDirectory);
    const result = validateDifferential(await differential(context), context);
    const serialized = Buffer.from(canonicalPhase1ArtifactBytes(result)).toString('utf8');
    const trustedInputs = new WeakSet<Record<string, unknown>>([result as Record<string, unknown>]);
    const authority: SecureEvidenceInputAuthority = Object.freeze({
      consume: ({ name, source, snapshot, serialized: candidate }) => {
        if (
          name !== differentialEvidenceName ||
          source !== result ||
          candidate !== serialized ||
          !isDeepStrictEqual(snapshot, result) ||
          Buffer.from(canonicalPhase1ArtifactBytes(snapshot)).toString('utf8') !== serialized ||
          typeof source !== 'object' ||
          source === null ||
          !trustedInputs.delete(source as Record<string, unknown>)
        ) {
          throw new TypeError(diagnostic);
        }
      },
    });
    const sink = await dependencies.createSink(
      context.evidenceDirectory,
      Object.freeze([differentialEvidenceName]),
      authority
    );
    let published = false;

    try {
      const publication = await sink.write(differentialEvidenceName, result);
      published = true;
      const verified = await sink.scan();
      const expected = [path.join(context.evidenceDirectory, differentialEvidenceName)];

      if (
        trustedInputs.has(result as Record<string, unknown>) ||
        JSON.stringify(verified) !== JSON.stringify(expected)
      ) {
        throw new TypeError(diagnostic);
      }

      return Object.freeze([publication]);
    } catch {
      if (published) {
        await sink.rollback(differentialEvidenceName).catch(() => false);
      }
      const remaining = await readdir(context.evidenceDirectory).catch(() => ['unreadable']);

      if (remaining.length > 0) {
        throw new TypeError(diagnostic);
      }
      throw new TypeError(diagnostic);
    }
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const executePhase1EvidenceForTesting = async (
  context: Phase1EvidenceRuntimeContext,
  ports: Phase1EvidenceExecutionPorts,
  dependencies: Phase1ExecutionCoordinatorDependencies
): Promise<readonly string[]> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return executeEvidence(context, ports, dependencies);
};

export const executePhase1DifferentialGateForTesting = async (
  context: Phase1EvidenceRuntimeContext,
  differential: Phase1EvidenceExecutionPorts['differential'],
  dependencies: Phase1ExecutionCoordinatorDependencies
): Promise<readonly string[]> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return executeDifferentialGate(context, differential, dependencies);
};

const runtimePorts: Phase1EvidenceExecutionPorts = Object.freeze({
  differential: runPhase1DifferentialRuntime,
  browser: runPhase1BrowserRuntime,
  candidateControls: runPhase1CandidateControlRuntime,
  conformance: runPhase1ConformanceRuntime,
});

const requiredEnvironmentValue = (environment: RuntimeEnvironment, name: string): string => {
  const value = environment[name];

  return typeof value === 'string' && value.length > 0 ? value : fail();
};

export const loadPhase1RuntimeIsolationAttestations = (
  environment: RuntimeEnvironment
): Phase1RuntimeIsolationAttestations => {
  const container = (name: string) => {
    const value = requiredEnvironmentValue(environment, name);

    return containerIdPattern.test(value) ? `container:${value}` : fail();
  };
  const keySet = (name: string) => {
    const value = requiredEnvironmentValue(environment, name);

    return sha256Pattern.test(value) ? `sha256:${value}` : fail();
  };
  const implementation = (label: 'ORACLE' | 'CANDIDATE') => ({
    data: {
      persistenceId: container(`ASTER_PHASE1_${label}_PRIMARY_POSTGRES_CONTAINER_ID`),
      cookieKeyId: keySet(`ASTER_PHASE1_${label}_DATA_COOKIE_KEY_SET_SHA256`),
      signingKeyId: keySet(`ASTER_PHASE1_${label}_DATA_SIGNING_KEY_SET_SHA256`),
    },
    admin: {
      persistenceId: container(`ASTER_PHASE1_${label}_PRIMARY_POSTGRES_CONTAINER_ID`),
      cookieKeyId: keySet(`ASTER_PHASE1_${label}_ADMIN_COOKIE_KEY_SET_SHA256`),
      signingKeyId: keySet(`ASTER_PHASE1_${label}_ADMIN_SIGNING_KEY_SET_SHA256`),
    },
    foreign: {
      persistenceId: container(`ASTER_PHASE1_${label}_FOREIGN_POSTGRES_CONTAINER_ID`),
      cookieKeyId: keySet(`ASTER_PHASE1_${label}_FOREIGN_COOKIE_KEY_SET_SHA256`),
      signingKeyId: keySet(`ASTER_PHASE1_${label}_FOREIGN_SIGNING_KEY_SET_SHA256`),
    },
  });

  return Object.freeze({
    oracle: Object.freeze(implementation('ORACLE')),
    candidate: Object.freeze(implementation('CANDIDATE')),
  });
};

export const executeAuthorizedPhase1Run = async (
  authorization: Phase1RunAuthorization,
  repositoryRoot: string,
  environment: RuntimeEnvironment = process.env
): Promise<readonly string[]> => {
  try {
    if (
      authorization.differentialGate === true ||
      requiredEnvironmentValue(environment, 'ASTER_PHASE1_MODE') !== authorization.mode
    ) {
      return fail();
    }
    const context = createPhase1EvidenceRuntimeContext(
      {
        authorization,
        oracleImageDigest: requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_ORACLE_IMAGE_DIGEST'
        ),
        candidateImageDigest: requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST'
        ),
        evidenceDirectory: requiredEnvironmentValue(environment, 'ASTER_PHASE1_EVIDENCE_DIR'),
        oracleSnapshotPath: requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_ORACLE_SNAPSHOT_PATH'
        ),
        repositoryRoot,
        conformanceRoot: requiredEnvironmentValue(environment, 'ASTER_PHASE1_CONFORMANCE_ROOT'),
        isolationAttestations: loadPhase1RuntimeIsolationAttestations(environment),
      },
      environment
    );

    return await executeEvidence(context, runtimePorts, {
      createSink: async (root, allowlist, authority) =>
        createSecureEvidenceSink(root, allowlist, {}, authority),
    });
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const executeAuthorizedPhase1DifferentialGate = async (
  authorization: Phase1RunAuthorization,
  repositoryRoot: string,
  environment: RuntimeEnvironment = process.env
): Promise<readonly string[]> => {
  try {
    if (
      authorization.mode !== 'runtime-candidate' ||
      authorization.differentialGate !== true ||
      authorization.controls.recordOracle ||
      !authorization.controls.observationControls ||
      !authorization.controls.discoveryExtraControl ||
      !authorization.controls.candidateInvariantControls ||
      requiredEnvironmentValue(environment, 'ASTER_PHASE1_MODE') !== authorization.mode
    ) {
      return fail();
    }
    const context = createPhase1EvidenceRuntimeContext(
      {
        authorization,
        oracleImageDigest: requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_ORACLE_IMAGE_DIGEST'
        ),
        candidateImageDigest: requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST'
        ),
        evidenceDirectory: requiredEnvironmentValue(environment, 'ASTER_PHASE1_EVIDENCE_DIR'),
        oracleSnapshotPath: requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_ORACLE_SNAPSHOT_PATH'
        ),
        repositoryRoot,
        conformanceRoot: requiredEnvironmentValue(environment, 'ASTER_PHASE1_CONFORMANCE_ROOT'),
        isolationAttestations: loadPhase1RuntimeIsolationAttestations(environment),
      },
      environment
    );

    return await executeDifferentialGate(context, runPhase1DifferentialRuntime, {
      createSink: async (root, allowlist, authority) =>
        createSecureEvidenceSink(root, allowlist, {}, authority),
    });
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runPhase1ExecutionCoordinatorCli = async (): Promise<number> => {
  console.error(directCliDiagnostic);
  return 1;
};

if (
  process.argv[1]?.replaceAll('\\', '/').endsWith('/phase-1/snapshots/execution-coordinator.js') ===
  true
) {
  process.exitCode = await runPhase1ExecutionCoordinatorCli();
}

/* eslint-enable max-lines, max-params, complexity, no-restricted-syntax, no-await-in-loop, no-use-extend-native/no-use-extend-native, unicorn/no-await-expression-member, @typescript-eslint/no-empty-function, @typescript-eslint/no-non-null-assertion, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
