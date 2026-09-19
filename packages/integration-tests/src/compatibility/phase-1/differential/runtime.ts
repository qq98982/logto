/* eslint-disable no-await-in-loop, max-params, max-lines, @silverhand/fp/no-mutating-methods -- Differential scenarios deliberately run serially, and the private runtime factories keep their closed authorities explicit. */
import { compareJson } from '../../compare.js';
import type { Difference } from '../../model.js';
import type { JsonObject } from '../../normalize.js';
import { assertPhase1PublicArtifactValue, bytewiseCompare } from '../artifact-contract.js';
import {
  createCommandPhase1FixtureProvisioner,
  runPhase1FixtureCommand,
} from '../clients/command-provisioner.js';
import { createReferencePhase1FixtureProvisioner } from '../clients/reference-provisioner.js';
import {
  createPhase1EvidenceProvenance,
  createPhase1ProjectionEnvelope,
  type Phase1EvidenceProvenance,
  type Phase1ProjectionEnvelope,
} from '../evidence-envelope.js';
import {
  assertPhase1EvidenceIsSanitized,
  snapshotPhase1EvidencePreservingVerifiedTokens,
} from '../evidence.js';
import type { ProvisionedPhase1Fixture } from '../fixtures.js';
import type { Phase1DifferentialScenarioId } from '../model.js';
import { assertCandidateNativeSurfaceArtifact } from '../native-surface-artifact.js';
import { projectPhase1ProfileForImplementation } from '../native-surface-profile.js';
import {
  runPhase1ScenarioForTarget,
  type Phase1TargetRuntime,
  type Phase1TargetStepEvidence,
} from '../scenario-runtime.js';
import { phase1DifferentialScenarios } from '../scenarios/index.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import { projectPhase1HttpCompatibility } from './http-compatibility.js';
import {
  createReferenceScenarioStateProjector,
  type ReferenceScenarioStateProjector,
} from './reference-state.js';
import {
  createPhase1ProtocolSessionBinding,
  type Phase1ProtocolSessionBinding,
} from './session.js';

export type Phase1ReferenceContainerGraph = Readonly<{
  projectName: string;
  oracle: Readonly<{ primary: string; foreign: string }>;
  candidate: Readonly<{ primary: string; foreign: string }>;
}>;

export type Phase1DifferentialEvidenceScenario = Readonly<{
  id: Phase1DifferentialScenarioId;
  oracle: Phase1ProjectionEnvelope<'oracle'>;
  candidate: Phase1ProjectionEnvelope<'candidate'>;
  differences: readonly Difference[];
}>;

export type Phase1DifferentialEvidenceArtifact = Readonly<{
  schemaVersion: 1;
  mode: Phase1EvidenceRuntimeContext['authorization']['mode'];
  provenance: Phase1EvidenceProvenance;
  sanitizerSuccess: true;
  scenarios: readonly Phase1DifferentialEvidenceScenario[];
}>;

export type Phase1DifferentialRuntimeDependencies = Readonly<{
  projectProfile: typeof projectPhase1ProfileForImplementation;
  createReferenceProvisioner: typeof createReferencePhase1FixtureProvisioner;
  createCandidateProvisioner: typeof createCommandPhase1FixtureProvisioner;
  runFixtureCommand: typeof runPhase1FixtureCommand;
  createSessionBinding: typeof createPhase1ProtocolSessionBinding;
  createReferenceProjector: typeof createReferenceScenarioStateProjector;
  loadContainerGraph: () => Phase1ReferenceContainerGraph;
  runScenario: typeof runPhase1ScenarioForTarget;
}>;

const diagnostic = 'Invalid Phase 1 differential runtime';
const candidateAdapterUnavailable = 'Phase 1 candidate differential adapter is unavailable';
const containerIdPattern = /^[0-9a-f]{12,64}$/u;
const projectNamePattern = /^aster-phase1-[0-9a-f]{16}$/u;
const scenarioTimeoutMs = 300_000;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const loadContainerId = (
  environment: Readonly<Record<string, string | undefined>>,
  name: string
): string => {
  const value = environment[name];

  return value && containerIdPattern.test(value) ? value : fail();
};

export const loadPhase1ReferenceContainerGraph = (
  environment: Readonly<Record<string, string | undefined>> = process.env
): Phase1ReferenceContainerGraph => {
  const projectName = environment.ASTER_PHASE1_TOPOLOGY_ID;

  if (!projectName || !projectNamePattern.test(projectName)) {
    return fail();
  }

  return Object.freeze({
    projectName,
    oracle: Object.freeze({
      primary: loadContainerId(environment, 'ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_CONTAINER_ID'),
      foreign: loadContainerId(environment, 'ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_CONTAINER_ID'),
    }),
    candidate: Object.freeze({
      primary: loadContainerId(environment, 'ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID'),
      foreign: loadContainerId(environment, 'ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID'),
    }),
  });
};

const defaultDependencies: Phase1DifferentialRuntimeDependencies = Object.freeze({
  projectProfile: projectPhase1ProfileForImplementation,
  createReferenceProvisioner: createReferencePhase1FixtureProvisioner,
  createCandidateProvisioner: createCommandPhase1FixtureProvisioner,
  runFixtureCommand: runPhase1FixtureCommand,
  createSessionBinding: createPhase1ProtocolSessionBinding,
  createReferenceProjector: createReferenceScenarioStateProjector,
  loadContainerGraph: loadPhase1ReferenceContainerGraph,
  runScenario: runPhase1ScenarioForTarget,
});

// Mirror control runs the pinned oracle image under both target labels. Runtime-candidate uses this
// factory only for its oracle adapter, so every runtime created here consumes the oracle profile.
const createMirrorControlRuntime = (
  context: Phase1EvidenceRuntimeContext,
  implementation: 'oracle' | 'candidate',
  containers: Phase1ReferenceContainerGraph['oracle'],
  projectName: string,
  dependencies: Phase1DifferentialRuntimeDependencies
): Phase1TargetRuntime => {
  const target = context.targets[implementation].primary;
  const profile = dependencies.projectProfile(context.authorization.profile, 'oracle');
  const provisioner = dependencies.createReferenceProvisioner({
    profile,
    target,
    foreignTarget: context.targets[implementation].foreign,
    isolation: context.isolationAttestations[implementation],
  });
  const projectors = new WeakMap<ProvisionedPhase1Fixture, ReferenceScenarioStateProjector>();
  const driverPath = `${context.repositoryRoot}/.scripts/compatibility/phase1-reference-state-driver.sh`;

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
        primaryService: `${implementation}-primary-postgres`,
        foreignService: `${implementation}-foreign-postgres`,
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
  dependencies: Phase1DifferentialRuntimeDependencies
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

      return binding.session;
    },
    projectScenarioState: async (input) => {
      const projector = projectors.get(input.fixture);

      return projector ? projector(input) : fail();
    },
  });
};

const keyedProjection = (
  scenarioId: Phase1DifferentialEvidenceScenario['id'],
  evidence: Phase1TargetStepEvidence
): Readonly<JsonObject> => {
  const scenario = phase1DifferentialScenarios.find(({ id }) => id === scenarioId);

  if (
    !scenario ||
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

const provenanceFor = (context: Phase1EvidenceRuntimeContext): Phase1EvidenceProvenance => {
  const harnessCommit = context.authorization.profile.phase1Harness.commit;

  if (typeof harnessCommit !== 'string') {
    return fail();
  }

  return createPhase1EvidenceProvenance({
    harnessCommit,
    profileSha256: context.authorization.profileSha256,
    schemaSha256: context.authorization.schemaSha256,
    imageDigest: context.oracleImageDigest,
  });
};

const executePhase1DifferentialRuntime = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies: Phase1DifferentialRuntimeDependencies
): Promise<Phase1DifferentialEvidenceArtifact> => {
  if (
    context.authorization.mode !== 'runtime-candidate' &&
    context.oracleImageDigest !== context.candidateImageDigest
  ) {
    throw new TypeError(candidateAdapterUnavailable);
  }

  try {
    const containers = dependencies.loadContainerGraph();
    const containerIds = [
      containers.oracle.primary,
      containers.oracle.foreign,
      containers.candidate.primary,
      containers.candidate.foreign,
    ];

    if (new Set(containerIds).size !== containerIds.length) {
      return fail();
    }
    const oracleRuntime = createMirrorControlRuntime(
      context,
      'oracle',
      containers.oracle,
      containers.projectName,
      dependencies
    );
    const candidateRuntime =
      context.authorization.mode === 'runtime-candidate'
        ? createCandidateRuntime(
            context,
            containers.candidate,
            containers.projectName,
            dependencies
          )
        : createMirrorControlRuntime(
            context,
            'candidate',
            containers.candidate,
            containers.projectName,
            dependencies
          );
    const scenarios: Phase1DifferentialEvidenceScenario[] = [];

    for (const scenario of phase1DifferentialScenarios) {
      const rawOracle = keyedProjection(
        scenario.id,
        await dependencies.runScenario(scenario, oracleRuntime)
      );
      const rawCandidate = keyedProjection(
        scenario.id,
        await dependencies.runScenario(scenario, candidateRuntime)
      );
      assertCandidateNativeSurfaceArtifact(rawCandidate);
      const { oracle, candidate } = projectPhase1HttpCompatibility(
        scenario.id,
        rawOracle,
        rawCandidate
      );
      scenarios.push(
        snapshotPhase1EvidencePreservingVerifiedTokens<Phase1DifferentialEvidenceScenario>({
          id: scenario.id,
          oracle: createPhase1ProjectionEnvelope('oracle', oracle),
          candidate: createPhase1ProjectionEnvelope('candidate', candidate),
          differences: compareJson(oracle, candidate),
        })
      );
    }
    const artifact =
      snapshotPhase1EvidencePreservingVerifiedTokens<Phase1DifferentialEvidenceArtifact>({
        schemaVersion: 1 as const,
        mode: context.authorization.mode,
        provenance: provenanceFor(context),
        sanitizerSuccess: true as const,
        scenarios: scenarios.toSorted((left, right) => bytewiseCompare(left.id, right.id)),
      });

    assertPhase1EvidenceIsSanitized(artifact);
    assertPhase1PublicArtifactValue(artifact);

    return artifact;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runPhase1DifferentialRuntime = async (
  context: Phase1EvidenceRuntimeContext
): Promise<Phase1DifferentialEvidenceArtifact> =>
  executePhase1DifferentialRuntime(context, defaultDependencies);

/** Test-only dependency boundary. Production always uses live reference provisioners and state. */
export const runPhase1DifferentialRuntimeForTesting = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies: Phase1DifferentialRuntimeDependencies
): Promise<Phase1DifferentialEvidenceArtifact> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return executePhase1DifferentialRuntime(context, dependencies);
};

/* eslint-enable no-await-in-loop, max-params, max-lines, @silverhand/fp/no-mutating-methods */
