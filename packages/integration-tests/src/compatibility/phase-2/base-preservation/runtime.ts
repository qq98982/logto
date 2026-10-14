/* eslint-disable complexity, max-lines, no-await-in-loop, max-params, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition -- The Phase 2-owned composition deliberately mirrors accepted ports with explicit mutable fixture/projector journals and literal closed-contract checks. */
import { compareJson } from '../../compare.js';
import type { Difference } from '../../model.js';
import type { JsonObject } from '../../normalize.js';
import { bytewiseCompare } from '../../phase-1/artifact-contract.js';
import {
  createCommandPhase1FixtureProvisioner,
  runPhase1FixtureCommand,
} from '../../phase-1/clients/command-provisioner.js';
import { createReferencePhase1FixtureProvisioner } from '../../phase-1/clients/reference-provisioner.js';
import { projectPhase1HttpCompatibility } from '../../phase-1/differential/http-compatibility.js';
import {
  createReferenceScenarioStateProjector,
  type ReferenceScenarioStateProjector,
} from '../../phase-1/differential/reference-state.js';
import {
  loadPhase1ReferenceContainerGraph,
  type Phase1ReferenceContainerGraph,
} from '../../phase-1/differential/runtime.js';
import {
  createPhase1ProtocolSessionBinding,
  type Phase1ProtocolSessionBinding,
} from '../../phase-1/differential/session.js';
import {
  createPhase1EvidenceProvenance,
  createPhase1ProjectionEnvelope,
  type Phase1EvidenceProvenance,
  type Phase1ProjectionEnvelope,
} from '../../phase-1/evidence-envelope.js';
import {
  assertPhase1EvidenceIsSanitized,
  snapshotPhase1EvidencePreservingVerifiedTokens,
} from '../../phase-1/evidence.js';
import { runWithPhase1Fixture, type ProvisionedPhase1Fixture } from '../../phase-1/fixtures.js';
import type {
  Phase1DifferentialScenario,
  Phase1DifferentialScenarioId,
} from '../../phase-1/model.js';
import { assertCandidateNativeSurfaceArtifact } from '../../phase-1/native-surface-artifact.js';
import { projectPhase1ProfileForImplementation } from '../../phase-1/native-surface-profile.js';
import {
  runPhase1ScenarioForTarget,
  type Phase1TargetRuntime,
  type Phase1TargetStepEvidence,
} from '../../phase-1/scenario-runtime.js';
import {
  assertExactDifferentialScenarioRegistry,
  phase1DifferentialScenarios,
} from '../../phase-1/scenarios/index.js';
import type { Phase1EvidenceRuntimeContext } from '../../phase-1/snapshots/runtime-context.js';
import type { Phase2ProfileRegistries } from '../profile.js';

import {
  createPhase2BaseDiscoverySession,
  type Phase2BaseDiscoveryAppendProof,
  type Phase2BaseDiscoverySession,
} from './discovery.js';
import type { AcceptedPhase1SourceClosureManifest } from './source-closure.js';

export type Phase2BasePreservationScenario = Readonly<{
  id: Phase1DifferentialScenarioId;
  oracle: Phase1ProjectionEnvelope<'oracle'>;
  candidate: Phase1ProjectionEnvelope<'candidate'>;
  differences: readonly Difference[];
}>;

export type Phase2BasePreservationRuntimeResult = Readonly<{
  schemaVersion: 1;
  mode: 'phase-2-base-preservation';
  phase1Provenance: Phase1EvidenceProvenance;
  sourceClosure: AcceptedPhase1SourceClosureManifest;
  rawPhase1NegativeControl: Readonly<{
    scenarioId: 'discovery.config';
    detected: true;
    errorName: 'Error';
    error: 'Phase 1 candidate discovery contains unapproved metadata';
  }>;
  discoveryAppendProofs: readonly Phase2BaseDiscoveryAppendProof[];
  scenarios: readonly Phase2BasePreservationScenario[];
  sanitizerSuccess: true;
}>;

export type Phase2BaseScenarioStage =
  | 'oracle'
  | 'candidate'
  | 'artifact'
  | 'projection'
  | 'compare';

const phase2BaseScenarioFailures = new WeakSet<Error>();
const scenarioFailureMessage = 'Phase 2 base-preservation scenario failed';
const phase2BaseScenarioStages: readonly Phase2BaseScenarioStage[] = Object.freeze([
  'oracle',
  'candidate',
  'artifact',
  'projection',
  'compare',
]);

export type Phase2BaseScenarioFailure = Error &
  Readonly<{
    scenarioIndex: number;
    stage: Phase2BaseScenarioStage;
    stepIndex?: number;
    fieldIndex?: number;
    cookieFieldIndex?: number;
  }>;

class AuthenticPhase2BaseScenarioFailure extends Error implements Phase2BaseScenarioFailure {
  readonly scenarioIndex: number;
  readonly stage: Phase2BaseScenarioStage;
  readonly stepIndex?: number;
  readonly fieldIndex?: number;
  readonly cookieFieldIndex?: number;

  constructor(
    scenarioIndex: number,
    stage: Phase2BaseScenarioStage,
    stepIndex?: number,
    fieldIndex?: number,
    cookieFieldIndex?: number
  ) {
    super(scenarioFailureMessage);
    if (
      !Number.isInteger(scenarioIndex) ||
      scenarioIndex < 0 ||
      scenarioIndex > 21 ||
      !phase2BaseScenarioStages.includes(stage) ||
      (stepIndex !== undefined &&
        (scenarioIndex !== 1 ||
          stage !== 'compare' ||
          !Number.isInteger(stepIndex) ||
          stepIndex < 0 ||
          stepIndex > 9)) ||
      (fieldIndex !== undefined &&
        (scenarioIndex !== 1 ||
          stage !== 'compare' ||
          stepIndex !== 5 ||
          !Number.isInteger(fieldIndex) ||
          fieldIndex < 0 ||
          fieldIndex > 27)) ||
      (cookieFieldIndex !== undefined &&
        (scenarioIndex !== 11 ||
          stage !== 'compare' ||
          !Number.isInteger(cookieFieldIndex) ||
          cookieFieldIndex < 0 ||
          cookieFieldIndex > 29))
    ) {
      throw new TypeError(scenarioFailureMessage);
    }
    this.name = 'Phase2BaseScenarioFailure';
    this.scenarioIndex = scenarioIndex;
    this.stage = stage;
    if (stepIndex !== undefined) {
      this.stepIndex = stepIndex;
    }
    if (fieldIndex !== undefined) {
      this.fieldIndex = fieldIndex;
    }
    if (cookieFieldIndex !== undefined) {
      this.cookieFieldIndex = cookieFieldIndex;
    }
    phase2BaseScenarioFailures.add(this);
    Object.freeze(this);
  }
}

export const isPhase2BaseScenarioFailure = (error: unknown): error is Phase2BaseScenarioFailure =>
  error instanceof Error && phase2BaseScenarioFailures.has(error);

export type Phase2BasePreservationRuntimeDependencies = Readonly<{
  projectProfile: typeof projectPhase1ProfileForImplementation;
  createReferenceProvisioner: typeof createReferencePhase1FixtureProvisioner;
  createCandidateProvisioner: typeof createCommandPhase1FixtureProvisioner;
  runFixtureCommand: typeof runPhase1FixtureCommand;
  createSessionBinding: typeof createPhase1ProtocolSessionBinding;
  createReferenceProjector: typeof createReferenceScenarioStateProjector;
  loadContainerGraph: () => Phase1ReferenceContainerGraph;
  runScenario: typeof runPhase1ScenarioForTarget;
  runRawDiscoveryControl(
    scenario: Phase1DifferentialScenario,
    runtime: Phase1TargetRuntime
  ): Promise<Phase2BasePreservationRuntimeResult['rawPhase1NegativeControl']>;
  assertCandidateArtifact(value: unknown): void;
  projectHttpCompatibility(
    scenarioId: Phase1DifferentialScenarioId,
    oracle: Readonly<JsonObject>,
    candidate: Readonly<JsonObject>
  ): Readonly<{ oracle: Readonly<JsonObject>; candidate: Readonly<JsonObject> }>;
  compare(oracle: unknown, candidate: unknown): readonly Difference[];
  assertSanitized(value: unknown): void;
}>;

const diagnostic = 'Invalid Phase 2 base-preservation runtime';
const acceptedHarnessCommit = '83d08f0821345d1bdc01491152949cc6f044ecfb';
const scenarioTimeoutMs = 300_000;
const commitPattern = /^[0-9a-f]{40}$/u;
const scenarioOneStepIds: readonly string[] = Object.freeze([
  'authorize',
  'experience-bootstrap',
  'password',
  'identify',
  'submit',
  'consent-get',
  'consent-post',
  'resume',
  'callback',
  'state',
]);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const runScenarioStage = async <Value>(
  scenarioIndex: number,
  stage: Phase2BaseScenarioStage,
  operation: () => Value | Promise<Value>
): Promise<Value> => {
  try {
    return await operation();
  } catch (error: unknown) {
    if (isPhase2BaseScenarioFailure(error)) {
      throw error;
    }
    throw new AuthenticPhase2BaseScenarioFailure(scenarioIndex, stage);
  }
};

const decodeJsonPointerSegment = (segment: string): string | undefined => {
  if (/~(?:[^01]|$)/u.test(segment)) {
    return undefined;
  }

  return segment.replaceAll('~1', '/').replaceAll('~0', '~');
};

const scenarioOneDifferenceStepIndex = (difference: Difference | undefined): number | undefined => {
  if (!difference?.path.startsWith('/')) {
    return undefined;
  }
  const segments = difference.path
    .slice(1)
    .split('/')
    .map((segment) => decodeJsonPointerSegment(segment));

  if (
    segments.length < 3 ||
    segments.includes(undefined) ||
    segments[0] !== 'steps' ||
    segments[2] !== 'value'
  ) {
    return undefined;
  }
  const stepIndex = scenarioOneStepIds.indexOf(segments[1] ?? '');

  return stepIndex === -1 ? undefined : stepIndex;
};

const consentGetRootFields: readonly string[] = Object.freeze([
  'body',
  'cookies',
  'error',
  'generatedIds',
  'headers',
  'mediaType',
  'outcomes',
  'persistedState',
  'redirect',
  'semanticState',
  'sideEffects',
  'status',
  'tokens',
  'urls',
]);
const consentGetBodyFields: readonly string[] = Object.freeze([
  'application',
  'missingOIDCScope',
  'missingResourceScopes',
  'organizations',
  'redirectUri',
  'user',
]);
const consentGetHeaderFields: readonly string[] = Object.freeze([
  'cache-control',
  'etag',
  'content-length',
  'content-type',
  'vary',
  'set-cookie',
  'www-authenticate',
  'access-control-expose-headers',
]);
const consentGetValuePrefix = '/steps/consent-get/value/';

const scenarioOneConsentGetFieldIndex = (
  difference: Difference | undefined
): number | undefined => {
  if (!difference?.path.startsWith(consentGetValuePrefix)) {
    return undefined;
  }
  const segments = difference.path
    .slice(consentGetValuePrefix.length)
    .split('/')
    .map((segment) => decodeJsonPointerSegment(segment));
  if (segments.includes(undefined)) {
    return undefined;
  }
  const root = segments[0];

  if (root === undefined) {
    return undefined;
  }
  const rootIndex = consentGetRootFields.indexOf(root);

  if (rootIndex !== 0 && rootIndex !== 4) {
    return rootIndex === -1 ? undefined : rootIndex;
  }
  const child = segments[1];

  if (child === undefined) {
    return rootIndex;
  }
  const childFields = rootIndex === 0 ? consentGetBodyFields : consentGetHeaderFields;
  const childIndex = childFields.indexOf(child);

  return childIndex === -1
    ? rootIndex
    : consentGetRootFields.length +
        (rootIndex === 0 ? 0 : consentGetBodyFields.length) +
        childIndex;
};

const cookieScenarioStepIds = new Set([
  'admin-start',
  'data-start',
  'admin-finish',
  'data-finish',
  'data-start-reverse',
  'admin-start-reverse',
  'data-finish-reverse',
  'admin-finish-reverse',
  'state',
]);
const cookieRootFieldIndexes = new Map<string, number>([
  ['status', 0],
  ['mediaType', 1],
  ['error', 2],
  ['body', 10],
  ['redirect', 11],
  ['generatedIds', 22],
  ['persistedState', 23],
  ['semanticState', 24],
  ['sideEffects', 25],
  ['outcomes', 26],
  ['urls', 27],
  ['tokens', 28],
]);
const cookieHeaderFieldIndexes = new Map<string, number>([
  ['set-cookie', 3],
  ['cache-control', 4],
  ['etag', 5],
  ['content-length', 6],
  ['content-type', 7],
  ['location', 8],
]);
const cookieMetadataFieldIndexes = new Map<string, number>([
  ['name', 12],
  ['domain', 13],
  ['path', 14],
  ['sameSite', 15],
  ['secure', 16],
  ['httpOnly', 17],
  ['expires', 18],
  ['maxAge', 19],
  ['extensions', 20],
]);

const cookieScenarioDifferenceFieldIndex = (
  difference: Difference | undefined
): number | undefined => {
  if (!difference?.path.startsWith('/')) {
    return undefined;
  }
  const segments = difference.path
    .slice(1)
    .split('/')
    .map((segment) => decodeJsonPointerSegment(segment));

  if (
    segments.includes(undefined) ||
    segments[0] !== 'steps' ||
    !cookieScenarioStepIds.has(segments[1] ?? '') ||
    segments[2] !== 'value'
  ) {
    return undefined;
  }
  const rootField = segments[3];

  if (rootField === 'headers') {
    return cookieHeaderFieldIndexes.get(segments[4] ?? '') ?? 9;
  }
  if (rootField === 'cookies') {
    const metadataField = segments[5];

    return metadataField === undefined ? 12 : (cookieMetadataFieldIndexes.get(metadataField) ?? 21);
  }

  return rootField === undefined ? undefined : (cookieRootFieldIndexes.get(rootField) ?? 29);
};

const assertRawDiscoveryControl = (
  value: Phase2BasePreservationRuntimeResult['rawPhase1NegativeControl']
): void => {
  if (
    value.scenarioId !== 'discovery.config' ||
    !value.detected ||
    value.errorName !== 'Error' ||
    value.error !== 'Phase 1 candidate discovery contains unapproved metadata' ||
    Reflect.ownKeys(value).length !== 4
  ) {
    return fail();
  }
};

const runRawDiscoveryControl = async (
  scenario: Phase1DifferentialScenario,
  runtime: Phase1TargetRuntime
): Promise<Phase2BasePreservationRuntimeResult['rawPhase1NegativeControl']> =>
  runWithPhase1Fixture(
    runtime.provisioner,
    scenario.fixture,
    async (fixture, signal) => {
      const protocol = runtime.createProtocolSession({ target: runtime.target, fixture, signal });

      try {
        await scenario.run(
          Object.freeze({
            profile: runtime.profile,
            target: runtime.target,
            fixture,
            signal,
            protocol,
            projectFixtureState: async () => runtime.provisioner.projectState(fixture),
            projectScenarioState: async () => fail(),
          })
        );
      } catch (error: unknown) {
        if (
          error instanceof Error &&
          error.constructor === Error &&
          error.message === 'Phase 1 candidate discovery contains unapproved metadata'
        ) {
          return Object.freeze({
            scenarioId: 'discovery.config' as const,
            detected: true as const,
            errorName: 'Error' as const,
            error: 'Phase 1 candidate discovery contains unapproved metadata' as const,
          });
        }

        return fail();
      }

      return fail();
    },
    { timeoutMs: runtime.timeoutMs ?? scenarioTimeoutMs }
  );

const defaultDependencies: Phase2BasePreservationRuntimeDependencies = Object.freeze({
  projectProfile: projectPhase1ProfileForImplementation,
  createReferenceProvisioner: createReferencePhase1FixtureProvisioner,
  createCandidateProvisioner: createCommandPhase1FixtureProvisioner,
  runFixtureCommand: runPhase1FixtureCommand,
  createSessionBinding: createPhase1ProtocolSessionBinding,
  createReferenceProjector: createReferenceScenarioStateProjector,
  loadContainerGraph: loadPhase1ReferenceContainerGraph,
  runScenario: runPhase1ScenarioForTarget,
  runRawDiscoveryControl,
  assertCandidateArtifact: assertCandidateNativeSurfaceArtifact,
  projectHttpCompatibility: projectPhase1HttpCompatibility,
  compare: compareJson,
  assertSanitized: assertPhase1EvidenceIsSanitized,
});

export const phase2BasePreservationRunnerIdentities = Object.freeze(
  phase1DifferentialScenarios.map(({ run }) => run)
);

const keyedProjection = (
  scenario: Phase1DifferentialScenario,
  evidence: Phase1TargetStepEvidence
): Readonly<JsonObject> => {
  if (
    evidence.steps.length !== scenario.orderedSteps.length ||
    evidence.steps.some(({ stepId }, index) => stepId !== scenario.orderedSteps[index]?.id)
  ) {
    return fail();
  }
  const steps: Record<string, JsonObject> = {};

  for (const { stepId, value } of evidence.steps) {
    Object.defineProperty(steps, stepId, {
      configurable: false,
      enumerable: true,
      value: Object.freeze({ value }),
      writable: false,
    });
  }

  return snapshotPhase1EvidencePreservingVerifiedTokens<JsonObject>({ steps });
};

const provenanceFor = (context: Phase1EvidenceRuntimeContext): Phase1EvidenceProvenance =>
  createPhase1EvidenceProvenance({
    harnessCommit: context.authorization.profile.phase1Harness.commit ?? fail(),
    profileSha256: context.authorization.profileSha256,
    schemaSha256: context.authorization.schemaSha256,
    imageDigest: context.oracleImageDigest,
    candidateImageDigest: context.candidateImageDigest,
  });

const createOracleRuntime = (
  context: Phase1EvidenceRuntimeContext,
  containers: Phase1ReferenceContainerGraph['oracle'],
  projectName: string,
  dependencies: Phase2BasePreservationRuntimeDependencies
): Phase1TargetRuntime => {
  const target = context.targets.oracle.primary;
  const profile = dependencies.projectProfile(context.authorization.profile, 'oracle');
  const provisioner = dependencies.createReferenceProvisioner({
    profile,
    target,
    foreignTarget: context.targets.oracle.foreign,
    isolation: context.isolationAttestations.oracle,
  });
  const projectors = new WeakMap<ProvisionedPhase1Fixture, ReferenceScenarioStateProjector>();
  const driverPath = `${context.repositoryRoot}/.scripts/compatibility/phase1-reference-state-driver.sh`;

  return Object.freeze({
    profile,
    target,
    provisioner,
    timeoutMs: scenarioTimeoutMs,
    createProtocolSession: (input) => {
      const binding = dependencies.createSessionBinding(input);
      const projector = dependencies.createReferenceProjector({
        profile,
        primaryContainerId: containers.primary,
        foreignContainerId: containers.foreign,
        projectName,
        primaryService: 'oracle-primary-postgres',
        foreignService: 'oracle-foreign-postgres',
        symbols: binding.symbols,
        driverPath,
        environment: {
          PATH: process.env.PATH,
          ASTER_PHASE1_ENGINE_SOCKET: process.env.ASTER_PHASE1_ENGINE_SOCKET,
        },
      });
      projectors.set(input.fixture, projector);

      return binding.session;
    },
    projectScenarioState: async (input) => {
      const projector = projectors.get(input.fixture);

      return projector ? projector(input) : fail();
    },
  });
};

const createCandidateRuntime = (
  context: Phase1EvidenceRuntimeContext,
  containers: Phase1ReferenceContainerGraph['candidate'],
  projectName: string,
  scenario: Phase1DifferentialScenario,
  phase2Profile: Phase2ProfileRegistries,
  dependencies: Phase2BasePreservationRuntimeDependencies,
  adaptDiscovery: boolean,
  discoverySessions: Phase2BaseDiscoverySession[]
): Phase1TargetRuntime => {
  const target = context.targets.candidate.primary;
  const foreignTarget = context.targets.candidate.foreign;
  const profile = dependencies.projectProfile(context.authorization.profile, 'candidate');
  const fixtureSocket = process.env.ASTER_FIXTURE_SOCKET;
  const fixturePath = process.env.PATH ?? '/usr/bin:/bin';
  const provisioner = dependencies.createCandidateProvisioner({
    profile,
    target,
    foreignTarget,
    environment: { PATH: fixturePath, ASTER_FIXTURE_SOCKET: fixtureSocket },
    runner: async (request) =>
      dependencies.runFixtureCommand({
        ...request,
        env: Object.freeze({
          PATH: fixturePath,
          ...(fixtureSocket && { ASTER_FIXTURE_SOCKET: fixtureSocket }),
        }),
      }),
  });
  const projectors = new WeakMap<ProvisionedPhase1Fixture, ReferenceScenarioStateProjector>();
  const driverPath = `${context.repositoryRoot}/.scripts/compatibility/phase1-candidate-state-driver.sh`;

  return Object.freeze({
    profile,
    target,
    provisioner,
    timeoutMs: scenarioTimeoutMs,
    createProtocolSession: (input) => {
      const binding: Phase1ProtocolSessionBinding = dependencies.createSessionBinding(input);
      const projector = dependencies.createReferenceProjector({
        profile,
        primaryContainerId: containers.primary,
        foreignContainerId: containers.foreign,
        projectName,
        primaryService: 'candidate-primary-postgres',
        foreignService: 'candidate-foreign-postgres',
        symbols: binding.symbols,
        driverPath,
        environment: {
          PATH: process.env.PATH,
          ASTER_PHASE1_ENGINE_SOCKET: process.env.ASTER_PHASE1_ENGINE_SOCKET,
        },
      });
      projectors.set(input.fixture, projector);

      if (!adaptDiscovery) {
        return binding.session;
      }
      const wrapped = createPhase2BaseDiscoverySession({
        target,
        scenarioId: scenario.id,
        session: binding.session,
        acceptedGrantTypes: profile.oidc.grants,
        appendGrantTypes: phase2Profile.discovery.grantTypesSupportedAppend,
        endpointFieldsAppend: phase2Profile.discovery.endpointFieldsAppend,
        scopesSupportedAppend: phase2Profile.discovery.scopesSupportedAppend,
        stillAbsent: phase2Profile.discovery.stillAbsent,
        paths: Object.freeze({
          openid: profile.oidc.discoveryPath.slice(1),
          oauth: profile.oidc.oauthAuthorizationServerDiscoveryPath.slice(1),
          jwks: profile.oidc.jwksPath.slice(1),
        }),
      });
      discoverySessions.push(wrapped);

      return wrapped.session;
    },
    projectScenarioState: async (input) => {
      const projector = projectors.get(input.fixture);

      return projector ? projector(input) : fail();
    },
  });
};

export const runPhase2BasePreservationRuntime = async (
  context: Phase1EvidenceRuntimeContext,
  phase2Profile: Phase2ProfileRegistries,
  sourceClosure: AcceptedPhase1SourceClosureManifest,
  dependencies: Phase2BasePreservationRuntimeDependencies = defaultDependencies
): Promise<Phase2BasePreservationRuntimeResult> => {
  try {
    if (
      context.authorization.mode !== 'runtime-candidate' ||
      !commitPattern.test(context.authorization.profile.phase1Harness.commit ?? '') ||
      sourceClosure.acceptedCommit !== acceptedHarnessCommit ||
      phase2Profile.baseAcceptance.harnessCommit !== acceptedHarnessCommit ||
      context.oracleImageDigest === context.candidateImageDigest
    ) {
      return fail();
    }
    assertExactDifferentialScenarioRegistry(phase1DifferentialScenarios);
    if (
      phase2BasePreservationRunnerIdentities.length !== phase1DifferentialScenarios.length ||
      phase2BasePreservationRunnerIdentities.some(
        (runner, index) => runner !== phase1DifferentialScenarios[index]?.run
      )
    ) {
      return fail();
    }
    const containers = dependencies.loadContainerGraph();
    const ids = [
      containers.oracle.primary,
      containers.oracle.foreign,
      containers.candidate.primary,
      containers.candidate.foreign,
    ];

    if (new Set(ids).size !== ids.length) {
      return fail();
    }
    const oracleRuntime = createOracleRuntime(
      context,
      containers.oracle,
      containers.projectName,
      dependencies
    );
    const discoveryScenario = phase1DifferentialScenarios.find(
      ({ id }) => id === 'discovery.config'
    );

    if (!discoveryScenario) {
      return fail();
    }
    const scenarios: Phase2BasePreservationScenario[] = [];
    const discoverySessions: Phase2BaseDiscoverySession[] = [];

    for (const [scenarioIndex, scenario] of phase1DifferentialScenarios.entries()) {
      const candidateRuntime = await runScenarioStage(scenarioIndex, 'candidate', () =>
        createCandidateRuntime(
          context,
          containers.candidate,
          containers.projectName,
          scenario,
          phase2Profile,
          dependencies,
          scenario.id === 'discovery.config',
          discoverySessions
        )
      );
      const oracleEvidence = await runScenarioStage(scenarioIndex, 'oracle', async () =>
        dependencies.runScenario(scenario, oracleRuntime)
      );
      const candidateEvidence = await runScenarioStage(scenarioIndex, 'candidate', async () =>
        dependencies.runScenario(scenario, candidateRuntime)
      );
      const rawOracle = await runScenarioStage(scenarioIndex, 'projection', () =>
        keyedProjection(scenario, oracleEvidence)
      );
      const rawCandidate = await runScenarioStage(scenarioIndex, 'projection', () =>
        keyedProjection(scenario, candidateEvidence)
      );
      await runScenarioStage(scenarioIndex, 'artifact', () => {
        dependencies.assertCandidateArtifact(rawCandidate);
      });
      const { oracle, candidate } = await runScenarioStage(scenarioIndex, 'projection', () =>
        dependencies.projectHttpCompatibility(scenario.id, rawOracle, rawCandidate)
      );
      const differences = await runScenarioStage(scenarioIndex, 'compare', () => {
        const result = Object.freeze([...dependencies.compare(oracle, candidate)]);

        if (result.length > 0) {
          const stepIndex =
            scenarioIndex === 1 ? scenarioOneDifferenceStepIndex(result[0]) : undefined;
          throw new AuthenticPhase2BaseScenarioFailure(
            scenarioIndex,
            'compare',
            stepIndex,
            stepIndex === 5 ? scenarioOneConsentGetFieldIndex(result[0]) : undefined,
            scenarioIndex === 11 ? cookieScenarioDifferenceFieldIndex(result[0]) : undefined
          );
        }

        return result;
      });
      const projectedScenario = await runScenarioStage(scenarioIndex, 'projection', () =>
        snapshotPhase1EvidencePreservingVerifiedTokens<Phase2BasePreservationScenario>({
          id: scenario.id,
          oracle: createPhase1ProjectionEnvelope('oracle', oracle),
          candidate: createPhase1ProjectionEnvelope('candidate', candidate),
          differences,
        })
      );
      scenarios.push(projectedScenario);
    }
    if (discoverySessions.length !== 1) {
      return fail();
    }
    const rawPhase1NegativeControl = await dependencies.runRawDiscoveryControl(
      discoveryScenario,
      createCandidateRuntime(
        context,
        containers.candidate,
        containers.projectName,
        discoveryScenario,
        phase2Profile,
        dependencies,
        false,
        []
      )
    );
    assertRawDiscoveryControl(rawPhase1NegativeControl);
    const result =
      snapshotPhase1EvidencePreservingVerifiedTokens<Phase2BasePreservationRuntimeResult>({
        schemaVersion: 1 as const,
        mode: 'phase-2-base-preservation' as const,
        phase1Provenance: provenanceFor(context),
        sourceClosure,
        rawPhase1NegativeControl,
        discoveryAppendProofs: discoverySessions[0]?.proofs() ?? fail(),
        scenarios: Object.freeze(scenarios),
        sanitizerSuccess: true as const,
      });
    dependencies.assertSanitized(result);

    return result;
  } catch (error: unknown) {
    if (isPhase2BaseScenarioFailure(error)) {
      throw error;
    }
    if (error instanceof TypeError && error.message === diagnostic) {
      throw error;
    }

    throw new TypeError(diagnostic);
  }
};

export const sortedPhase2BasePreservationScenarioIds = Object.freeze(
  phase1DifferentialScenarios.map(({ id }) => id).toSorted(bytewiseCompare)
);

/* eslint-enable complexity, max-lines, no-await-in-loop, max-params, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition */
