/* eslint-disable complexity -- This adapter closes the runtime context into the exact credential-free conformance process contract. */
import path from 'node:path';

import { assertPhase1PublicArtifactValue } from '../artifact-contract.js';
import {
  asterPhase1BuildRootEnvironmentVariable,
  requireAsterPhase1BuildPath,
  resolveAsterPhase1BuildRoot,
  type AsterPhase1BuildRootEnvironment,
} from '../build-root.js';
import { createPhase1EvidenceProvenance } from '../evidence-envelope.js';
import { assertPhase1EvidenceIsSanitized } from '../evidence.js';

import { phase1ConformanceSuiteCommit } from './config.js';
import {
  assertValidatedPhase1ConformanceRuntimeContext,
  type Phase1ConformanceRuntimeContext,
} from './context.js';
import { createPhase1ConformanceEvidence, type Phase1ConformanceEvidence } from './evidence.js';
import { runPhase1Conformance, type Phase1ConformanceProcessRunner } from './runner.js';

export type Phase1ConformanceRuntimeEvidence = Phase1ConformanceEvidence;

export type Phase1ConformanceRuntimeDependencies = Readonly<{
  environment?: AsterPhase1BuildRootEnvironment;
  runner: Phase1ConformanceProcessRunner;
}>;

const diagnostic = 'Invalid phase 1 conformance runtime';
const runtimeUnavailable = 'Phase 1 official conformance plan runtime is unavailable';
const requireMode = (
  context: Phase1ConformanceRuntimeContext,
  environment: AsterPhase1BuildRootEnvironment
): 'review-candidate' | 'mirror-control' | 'runtime-candidate' => {
  const { authorization } = context;
  const { mode, profile, provenance, protectedExecution } = authorization;

  if (
    profile.phase1Harness.commit !== provenance.harnessCommit ||
    !path.isAbsolute(context.repositoryRoot) ||
    path.resolve(context.repositoryRoot) !== context.repositoryRoot ||
    (mode === 'mirror-control' && context.oracleImageDigest !== context.candidateImageDigest) ||
    (mode === 'review-candidate'
      ? provenance.kind !== 'review-candidate' || protectedExecution !== undefined
      : mode === 'runtime-candidate'
        ? authorization.conformanceGate !== true ||
          provenance.kind !== 'review-candidate' ||
          protectedExecution !== undefined
        : provenance.kind !== 'accepted-harness' ||
          protectedExecution?.mode !== mode ||
          protectedExecution.provenance !== provenance)
  ) {
    throw new TypeError(diagnostic);
  }
  requireAsterPhase1BuildPath(context.conformanceRoot, environment);

  return mode;
};

const executeRuntime = async (
  context: Phase1ConformanceRuntimeContext,
  dependencies?: Phase1ConformanceRuntimeDependencies
): Promise<Phase1ConformanceRuntimeEvidence> => {
  if (
    context.authorization.mode === 'runtime-candidate' &&
    context.authorization.conformanceGate !== true
  ) {
    throw new TypeError(runtimeUnavailable);
  }

  try {
    assertValidatedPhase1ConformanceRuntimeContext(context);
    const environment = dependencies?.environment ?? process.env;
    const buildRoot = resolveAsterPhase1BuildRoot(environment);
    const mode = requireMode(context, environment);
    const harnessCommit = context.authorization.profile.phase1Harness.commit;

    if (typeof harnessCommit !== 'string') {
      throw new TypeError(diagnostic);
    }
    const runResult = await runPhase1Conformance(context.authorization.profile, mode, {
      checkedOutSuiteCommit: phase1ConformanceSuiteCommit,
      repositoryRoot: context.repositoryRoot,
      scriptPath: path.join(
        context.repositoryRoot,
        '.scripts/compatibility/run-phase1-conformance.sh'
      ),
      workingDirectory: context.repositoryRoot,
      environment: {
        PATH: '/usr/bin:/bin',
        [asterPhase1BuildRootEnvironmentVariable]: buildRoot,
        ASTER_PHASE1_HARNESS_COMMIT: harnessCommit,
        ASTER_PHASE1_CONFORMANCE_ROOT: context.conformanceRoot,
        ASTER_PHASE1_CONFORMANCE_DRIVER: path.join(
          context.repositoryRoot,
          '.scripts/compatibility/phase1-conformance-driver.sh'
        ),
      },
      ...(dependencies === undefined ? {} : { runner: dependencies.runner }),
    });

    const imageDigest =
      mode === 'runtime-candidate' ? context.candidateImageDigest : context.oracleImageDigest;

    if (imageDigest === undefined) {
      throw new TypeError(diagnostic);
    }
    const evidence = createPhase1ConformanceEvidence(
      runResult,
      createPhase1EvidenceProvenance({
        harnessCommit,
        profileSha256: context.authorization.profileSha256,
        schemaSha256: context.authorization.schemaSha256,
        imageDigest,
      })
    );

    assertPhase1EvidenceIsSanitized(evidence);
    assertPhase1PublicArtifactValue(evidence);

    return evidence;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runPhase1ConformanceRuntime = async (
  context: Phase1ConformanceRuntimeContext
): Promise<Phase1ConformanceRuntimeEvidence> => executeRuntime(context);

export const runPhase1ConformanceRuntimeForTesting = async (
  context: Phase1ConformanceRuntimeContext,
  dependencies: Phase1ConformanceRuntimeDependencies
): Promise<Phase1ConformanceRuntimeEvidence> => {
  if (process.env.NODE_ENV !== 'test' || typeof dependencies.runner !== 'function') {
    throw new TypeError(diagnostic);
  }

  return executeRuntime(context, dependencies);
};

/* eslint-enable complexity */
