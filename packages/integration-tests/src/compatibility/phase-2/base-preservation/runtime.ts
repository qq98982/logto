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

const fail = (): never => {
  throw new TypeError(diagnostic);
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

    for (const scenario of phase1DifferentialScenarios) {
      const candidateRuntime = createCandidateRuntime(
        context,
        containers.candidate,
        containers.projectName,
        scenario,
        phase2Profile,
        dependencies,
        scenario.id === 'discovery.config',
        discoverySessions
      );
      const rawOracle = keyedProjection(
        scenario,
        await dependencies.runScenario(scenario, oracleRuntime)
      );
      const rawCandidate = keyedProjection(
        scenario,
        await dependencies.runScenario(scenario, candidateRuntime)
      );
      dependencies.assertCandidateArtifact(rawCandidate);
      const { oracle, candidate } = dependencies.projectHttpCompatibility(
        scenario.id,
        rawOracle,
        rawCandidate
      );
      const differences = Object.freeze([...dependencies.compare(oracle, candidate)]);

      if (differences.length > 0) {
        return fail();
      }
      scenarios.push(
        snapshotPhase1EvidencePreservingVerifiedTokens<Phase2BasePreservationScenario>({
          id: scenario.id,
          oracle: createPhase1ProjectionEnvelope('oracle', oracle),
          candidate: createPhase1ProjectionEnvelope('candidate', candidate),
          differences,
        })
      );
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
