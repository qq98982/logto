/* eslint-disable no-restricted-syntax -- Playwright must load natively outside the tsup ESM bundle; the fixed shape assertion exposes only Chromium's launch capability. */
import { createRequire } from 'node:module';
import path from 'node:path';

import type { Browser, BrowserType } from '@playwright/test';

import { compareJson } from '../../compare.js';
import type { JsonObject } from '../../normalize.js';
import { assertPhase1PublicArtifactValue, bytewiseCompare } from '../artifact-contract.js';
import { createCommandPhase1FixtureProvisioner } from '../clients/command-provisioner.js';
import { createReferencePhase1FixtureProvisioner } from '../clients/reference-provisioner.js';
import {
  createPhase1EvidenceProvenance,
  createPhase1ProjectionEnvelope,
  type Phase1EvidenceProvenance,
  type Phase1ProjectionEnvelope,
} from '../evidence-envelope.js';
import { assertPhase1EvidenceIsSanitized } from '../evidence.js';
import { runWithPhase1Fixture } from '../fixtures.js';
import { cloneAndDeepFreeze } from '../model.js';
import {
  assertCandidateNativeSurfaceArtifact,
  projectNativeSurfaceArtifact,
} from '../native-surface-artifact.js';
import { projectPhase1ProfileForImplementation } from '../native-surface-profile.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import type {
  Phase1BrowserFlowId,
  Phase1BrowserGroupObserver,
  Phase1BrowserRunEvidence,
} from './contracts.js';
import { phase1BrowserFlowIds } from './contracts.js';
import { runPhase1BrowserFlows } from './index.js';
import { createPlaywrightBrowserGroupObserver } from './playwright-session.js';

export type Phase1BrowserEvidenceFlow = Readonly<{
  id: Phase1BrowserFlowId;
  oracle: Phase1ProjectionEnvelope<'oracle-browser'>;
  candidate: Phase1ProjectionEnvelope<'candidate-browser'>;
  differences: readonly never[];
}>;

export type Phase1BrowserEvidenceArtifact = Readonly<{
  schemaVersion: 1;
  mode: Phase1EvidenceRuntimeContext['authorization']['mode'];
  provenance: Phase1EvidenceProvenance;
  sanitizerSuccess: true;
  flows: readonly Phase1BrowserEvidenceFlow[];
}>;

export type Phase1BrowserRuntimeDependencies = Readonly<{
  environment: Readonly<Record<string, string | undefined>>;
  projectProfile: typeof projectPhase1ProfileForImplementation;
  projectArtifact: typeof projectNativeSurfaceArtifact;
  createObserver: () => Phase1BrowserGroupObserver;
  createCommandProvisioner: typeof createCommandPhase1FixtureProvisioner;
  createReferenceProvisioner: typeof createReferencePhase1FixtureProvisioner;
  runBrowserFlows: typeof runPhase1BrowserFlows;
}>;

const diagnostic = 'Invalid Phase 1 browser runtime';
const browserTimeoutMs = 300_000;
const maximumSocketPathLength = 4096;
const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

const defaultDependencies: Phase1BrowserRuntimeDependencies = Object.freeze({
  environment: process.env,
  projectProfile: projectPhase1ProfileForImplementation,
  projectArtifact: projectNativeSurfaceArtifact,
  createObserver: () => createPlaywrightBrowserGroupObserver(chromium),
  createCommandProvisioner: createCommandPhase1FixtureProvisioner,
  createReferenceProvisioner: createReferencePhase1FixtureProvisioner,
  runBrowserFlows: runPhase1BrowserFlows,
});

const commandEnvironment = (
  environment: Phase1BrowserRuntimeDependencies['environment']
): Readonly<Record<string, string | undefined>> => {
  const fixtureSocket = environment.ASTER_FIXTURE_SOCKET;

  if (
    typeof fixtureSocket !== 'string' ||
    fixtureSocket.length === 0 ||
    fixtureSocket.length > maximumSocketPathLength ||
    fixtureSocket.split('').some((character) => {
      const codePoint = character.codePointAt(0);

      return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
    }) ||
    !path.isAbsolute(fixtureSocket)
  ) {
    throw new TypeError(diagnostic);
  }

  return Object.freeze({
    PATH: environment.PATH,
    ASTER_FIXTURE_SOCKET: fixtureSocket,
  });
};

const flattenObservations = (
  evidence: Phase1BrowserRunEvidence
): ReadonlyMap<Phase1BrowserFlowId, Readonly<JsonObject>> => {
  const flows = evidence.groups.flatMap(({ flows: groupFlows }) => groupFlows);

  if (
    flows.length !== phase1BrowserFlowIds.length ||
    new Set(flows.map(({ id }) => id)).size !== phase1BrowserFlowIds.length ||
    phase1BrowserFlowIds.some((id) => !flows.some((flow) => flow.id === id))
  ) {
    throw new TypeError(diagnostic);
  }

  return new Map(flows.map(({ id, observation }) => [id, observation]));
};

const provenanceFor = (context: Phase1EvidenceRuntimeContext): Phase1EvidenceProvenance => {
  const harnessCommit = context.authorization.profile.phase1Harness.commit;

  if (typeof harnessCommit !== 'string') {
    throw new TypeError(diagnostic);
  }

  return createPhase1EvidenceProvenance({
    harnessCommit,
    profileSha256: context.authorization.profileSha256,
    schemaSha256: context.authorization.schemaSha256,
    imageDigest: context.oracleImageDigest,
  });
};

const executePhase1BrowserRuntime = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies: Phase1BrowserRuntimeDependencies
): Promise<Phase1BrowserEvidenceArtifact> => {
  try {
    const candidateEnvironment =
      context.authorization.mode === 'runtime-candidate'
        ? commandEnvironment(dependencies.environment)
        : undefined;
    const observer = dependencies.createObserver();
    const oracleProfile = dependencies.projectProfile(context.authorization.profile, 'oracle');
    const candidateImplementation =
      context.authorization.mode === 'runtime-candidate' ? 'candidate' : 'oracle';
    const candidateProfile = dependencies.projectProfile(
      context.authorization.profile,
      candidateImplementation
    );
    const oracleProvisioner = dependencies.createReferenceProvisioner({
      profile: oracleProfile,
      target: context.targets.oracle.primary,
      foreignTarget: context.targets.oracle.foreign,
      isolation: context.isolationAttestations.oracle,
      applicationRedirectUriMode: 'target',
      signInExperienceBrandingMode: 'clear',
    });
    const candidateProvisioner =
      context.authorization.mode === 'runtime-candidate'
        ? dependencies.createCommandProvisioner({
            profile: candidateProfile,
            target: context.targets.candidate.primary,
            foreignTarget: context.targets.candidate.foreign,
            environment: candidateEnvironment,
          })
        : dependencies.createReferenceProvisioner({
            profile: candidateProfile,
            target: context.targets.candidate.primary,
            foreignTarget: context.targets.candidate.foreign,
            isolation: context.isolationAttestations.candidate,
            applicationRedirectUriMode: 'target',
            signInExperienceBrandingMode: 'clear',
          });
    const controller = new AbortController();
    const oracle = await dependencies.runBrowserFlows({
      profile: oracleProfile,
      target: context.targets.oracle.primary,
      provisioner: oracleProvisioner,
      observer,
      signal: controller.signal,
      timeoutMs: browserTimeoutMs,
    });
    if (context.authorization.mode === 'runtime-candidate') {
      await runWithPhase1Fixture(candidateProvisioner, 'none', async () => null);
    }
    const candidate = await dependencies.runBrowserFlows({
      profile: candidateProfile,
      target: context.targets.candidate.primary,
      provisioner: candidateProvisioner,
      observer,
      signal: controller.signal,
      timeoutMs: browserTimeoutMs,
    });
    const oracleObservations = flattenObservations(oracle);
    const candidateObservations = flattenObservations(candidate);
    const flows = phase1BrowserFlowIds
      .map((id): Phase1BrowserEvidenceFlow => {
        const oracleObservation = oracleObservations.get(id);
        const candidateObservation = candidateObservations.get(id);

        if (!oracleObservation || !candidateObservation) {
          throw new TypeError(diagnostic);
        }
        const projectedOracle = dependencies.projectArtifact(oracleObservation, 'oracle');
        const projectedCandidate = dependencies.projectArtifact(
          candidateObservation,
          candidateImplementation
        );
        assertCandidateNativeSurfaceArtifact(projectedCandidate);

        if (compareJson(projectedOracle, projectedCandidate).length > 0) {
          throw new TypeError(diagnostic);
        }

        return cloneAndDeepFreeze({
          id,
          oracle: createPhase1ProjectionEnvelope('oracle-browser', projectedOracle),
          candidate: createPhase1ProjectionEnvelope('candidate-browser', projectedCandidate),
          differences: [] as const,
        });
      })
      .toSorted((left, right) => bytewiseCompare(left.id, right.id));
    const artifact = cloneAndDeepFreeze({
      schemaVersion: 1 as const,
      mode: context.authorization.mode,
      provenance: provenanceFor(context),
      sanitizerSuccess: true as const,
      flows,
    });

    assertPhase1EvidenceIsSanitized(artifact);
    assertPhase1PublicArtifactValue(artifact);

    return artifact;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runPhase1BrowserRuntime = async (
  context: Phase1EvidenceRuntimeContext
): Promise<Phase1BrowserEvidenceArtifact> =>
  executePhase1BrowserRuntime(context, defaultDependencies);

/** Test-only dependency boundary. Production execution uses the fixed Playwright/reference adapters. */
export const runPhase1BrowserRuntimeForTesting = async (
  context: Phase1EvidenceRuntimeContext,
  dependencies: Phase1BrowserRuntimeDependencies
): Promise<Phase1BrowserEvidenceArtifact> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }

  return executePhase1BrowserRuntime(context, dependencies);
};

/* eslint-enable no-restricted-syntax */
