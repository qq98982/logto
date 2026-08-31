/* eslint-disable max-lines, unicorn/prevent-abbreviations -- The full source-evidence map retains the plan's public Phase1SourceEvidenceRef name and exact bounded registry checks. */
import {
  cloneAndDeepFreeze,
  defineDifferentialScenario,
  oracleCommit,
  phase0HarnessCommit,
  phase1DifferentialScenarioGuard,
  snapshotDensePlainArray,
  type Phase1DifferentialScenario,
  type Phase1FixtureRecipe,
  type Phase1SourceEvidenceRef,
} from '../model.js';
import { phase1ScenarioContracts } from '../scenario-contracts.js';

const oracle = (path: string): Phase1SourceEvidenceRef => ({ commit: oracleCommit, path });
const phase0 = (path: string): Phase1SourceEvidenceRef => ({ commit: phase0HarnessCommit, path });

type RegistryMetadata = Readonly<{
  fixture: Phase1FixtureRecipe;
  sourceEvidence: readonly Phase1SourceEvidenceRef[];
}>;

const registryMetadata: readonly RegistryMetadata[] = [
  {
    fixture: 'none',
    sourceEvidence: [
      phase0('packages/integration-tests/src/compatibility/scenarios/discovery.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/discovery.test.ts'),
      oracle('packages/core/src/oidc/init.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/client/index.ts'),
      oracle('packages/integration-tests/src/client/experience/index.ts'),
      oracle('packages/integration-tests/src/api/interaction.ts'),
      oracle('packages/integration-tests/src/tests/api/interaction/consent/happy-path.test.ts'),
      oracle('packages/core/src/routes/interaction/consent/index.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/client/index.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
      phase0('packages/integration-tests/src/compatibility/scenarios/password-code.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/tests/api/oidc/refresh-token-grant.test.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
      oracle('packages/core/src/oidc/grants/refresh-token.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      phase0('packages/integration-tests/src/compatibility/target-client.ts'),
      phase0('packages/integration-tests/src/compatibility/scenarios/password-code.ts'),
      oracle('packages/core/src/oidc/init.ts'),
      oracle('packages/core/src/oidc/scope.ts'),
    ],
  },
  {
    fixture: 'fullPhase1',
    sourceEvidence: [
      oracle('packages/integration-tests/src/api/application.ts'),
      oracle('packages/console/src/pages/Applications/hooks/use-application-data.ts'),
      oracle('packages/core/src/routes/applications/application.ts'),
      oracle('packages/integration-tests/src/tests/console/applications/index.test.ts'),
    ],
  },
  {
    fixture: 'fullPhase1',
    sourceEvidence: [
      oracle('packages/integration-tests/src/api/admin-user.ts'),
      oracle('packages/console/src/pages/Users/index.tsx'),
      oracle('packages/core/src/routes/admin-user/basics.ts'),
      oracle('packages/integration-tests/src/tests/console/user-management.test.ts'),
    ],
  },
  {
    fixture: 'adminConsole',
    sourceEvidence: [
      oracle('packages/integration-tests/src/helpers/admin-tenant.ts'),
      oracle('packages/console/src/App.tsx'),
      oracle('packages/console/src/hooks/use-api.ts'),
      oracle('packages/core/src/oidc/grants/refresh-token.ts'),
    ],
  },
  {
    fixture: 'adminConsole',
    sourceEvidence: [
      oracle('packages/console/src/containers/ConsoleContent/hooks.ts'),
      oracle('packages/schemas/src/types/tenant-organization.ts'),
      oracle('packages/core/src/oidc/grants/refresh-token.ts'),
      oracle('packages/core/src/oidc/grants/utils.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/organization-token.test.ts'),
    ],
  },
  {
    fixture: 'adminConsole',
    sourceEvidence: [
      oracle('packages/integration-tests/src/helpers/admin-tenant.ts'),
      oracle('packages/console/src/hooks/use-account-api.ts'),
      oracle('packages/console/src/hooks/use-current-user.ts'),
      oracle('packages/core/src/routes/account/index.ts'),
    ],
  },
  {
    fixture: 'fullPhase1',
    sourceEvidence: [
      oracle('packages/core/src/middleware/koa-cors.ts'),
      oracle('packages/core/src/middleware/koa-cors.test.ts'),
      oracle('packages/console/src/hooks/use-api.ts'),
    ],
  },
  {
    fixture: 'fullPhase1',
    sourceEvidence: [
      oracle('packages/integration-tests/src/client/index.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/per-client-interaction-cookie.test.ts'),
      oracle('packages/core/src/oidc/init.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/client/index.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/wildcard-redirect-uri.test.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/mixed-redirect-uri.test.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/tests/api/oidc/discovery.test.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/post-authorization-and-logout.test.ts'),
      oracle('packages/core/src/oidc/init.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/client/index.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/get-access-token.test.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
      oracle('packages/integration-tests/src/client/index.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/client/experience/index.ts'),
      oracle('packages/core/src/routes/experience/verification-routes/password-verification.ts'),
      oracle('packages/core/src/routes/experience/classes/verifications/password-verification.ts'),
      oracle(
        'packages/integration-tests/src/tests/api/experience-api/verifications/password-verification.test.ts'
      ),
    ],
  },
  {
    fixture: 'consentBoundary',
    sourceEvidence: [
      oracle('packages/integration-tests/src/api/interaction.ts'),
      oracle('packages/integration-tests/src/client/index.ts'),
      oracle('packages/integration-tests/src/tests/api/interaction/consent/happy-path.test.ts'),
      oracle('packages/core/src/routes/interaction/consent/index.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
      oracle('packages/core/src/oidc/grants/refresh-token.ts'),
    ],
  },
  {
    fixture: 'fullPhase1',
    sourceEvidence: [
      oracle('packages/console/src/hooks/use-api.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/get-access-token.test.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/organization-api-resource.test.ts'),
      oracle('packages/core/src/routes/applications/application.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
      oracle('packages/integration-tests/src/client/index.ts'),
    ],
  },
  {
    fixture: 'dataProtocol',
    sourceEvidence: [
      oracle('packages/integration-tests/src/tests/api/oidc/get-access-token.test.ts'),
      oracle('packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'),
      oracle('packages/core/src/oidc/grants/refresh-token.ts'),
    ],
  },
];

export const pendingPhase1DifferentialScenarioRun: Phase1DifferentialScenario['run'] =
  Object.freeze(async () => {
    throw new Error('Phase 1 differential scenario implementation is pending');
  });

const buildRegistry = (): readonly Phase1DifferentialScenario[] => {
  if (registryMetadata.length !== phase1ScenarioContracts.length) {
    throw new TypeError('Invalid phase 1 differential scenario registry');
  }

  return phase1ScenarioContracts.map((contract, index) => {
    const metadata = registryMetadata[index];

    if (!metadata) {
      throw new TypeError('Invalid phase 1 differential scenario registry');
    }

    return defineDifferentialScenario({
      id: contract.id,
      evidenceKind: 'differential',
      fixture: metadata.fixture,
      sourceEvidence: metadata.sourceEvidence,
      orderedSteps: contract.orderedSteps,
      observationContract: contract.observationContract,
      normalizablePointers: contract.normalizablePointers,
      semanticProjectionVersion: 1,
      cleanup: 'fresh-fixture-reverse-cleanup',
      run: pendingPhase1DifferentialScenarioRun,
    });
  });
};

export const phase1DifferentialScenarios: readonly Phase1DifferentialScenario[] =
  cloneAndDeepFreeze(buildRegistry());

const equalStrings = (left: readonly string[], right: readonly string[]) => {
  const leftSnapshot = snapshotDensePlainArray<string>(left);
  const rightSnapshot = snapshotDensePlainArray<string>(right);

  if (!leftSnapshot || !rightSnapshot || leftSnapshot.length !== rightSnapshot.length) {
    return false;
  }
  for (const [index, value] of leftSnapshot.entries()) {
    if (value !== rightSnapshot[index]) {
      return false;
    }
  }

  return true;
};
const equalSources = (
  left: readonly Phase1SourceEvidenceRef[],
  right: readonly Phase1SourceEvidenceRef[]
) => {
  const leftSnapshot = snapshotDensePlainArray<Phase1SourceEvidenceRef>(left);
  const rightSnapshot = snapshotDensePlainArray<Phase1SourceEvidenceRef>(right);

  if (!leftSnapshot || !rightSnapshot || leftSnapshot.length !== rightSnapshot.length) {
    return false;
  }
  for (const [index, leftSource] of leftSnapshot.entries()) {
    const rightSource = rightSnapshot[index];

    if (
      !rightSource ||
      leftSource.commit !== rightSource.commit ||
      leftSource.path !== rightSource.path
    ) {
      return false;
    }
  }

  return true;
};
const equalSteps = (
  left: Phase1DifferentialScenario['orderedSteps'],
  right: Phase1DifferentialScenario['orderedSteps']
) => {
  const leftSnapshot = snapshotDensePlainArray<(typeof left)[number]>(left);
  const rightSnapshot = snapshotDensePlainArray<(typeof right)[number]>(right);

  if (!leftSnapshot || !rightSnapshot || leftSnapshot.length !== rightSnapshot.length) {
    return false;
  }
  for (const [index, leftStep] of leftSnapshot.entries()) {
    const rightStep = rightSnapshot[index];

    if (
      !rightStep ||
      leftStep.id !== rightStep.id ||
      !equalStrings(leftStep.kinds, rightStep.kinds)
    ) {
      return false;
    }
  }

  return true;
};
const equalObservations = (
  left: Phase1DifferentialScenario['observationContract'],
  right: Phase1DifferentialScenario['observationContract']
) =>
  equalStrings(left.status, right.status) &&
  equalStrings(left.mediaType, right.mediaType) &&
  equalStrings(left.headers, right.headers) &&
  equalStrings(left.cookies, right.cookies) &&
  equalStrings(left.redirects, right.redirects);

const isExactRegistryEntry = (
  candidate: Phase1DifferentialScenario,
  expected: Phase1DifferentialScenario
) =>
  phase1DifferentialScenarioGuard.safeParse(candidate).success &&
  candidate.id === expected.id &&
  candidate.fixture === expected.fixture &&
  equalSources(candidate.sourceEvidence, expected.sourceEvidence) &&
  equalSteps(candidate.orderedSteps, expected.orderedSteps) &&
  equalObservations(candidate.observationContract, expected.observationContract) &&
  equalStrings(candidate.normalizablePointers, expected.normalizablePointers) &&
  candidate.run === expected.run &&
  candidate.run === pendingPhase1DifferentialScenarioRun;

export const assertExactDifferentialScenarioRegistry = (
  registry: readonly Phase1DifferentialScenario[]
): void => {
  try {
    const snapshot = snapshotDensePlainArray<Phase1DifferentialScenario>(registry, {
      allowFunction: (path, value) =>
        /^\/(?:0|[1-9]\d*)\/run$/u.test(path) && value === pendingPhase1DifferentialScenarioRun,
    });

    if (!snapshot || snapshot.length !== phase1DifferentialScenarios.length) {
      throw new TypeError('Invalid phase 1 differential scenario registry');
    }
    for (const [index, scenario] of snapshot.entries()) {
      const expected = phase1DifferentialScenarios[index];

      if (!expected || !isExactRegistryEntry(scenario, expected)) {
        throw new TypeError('Invalid phase 1 differential scenario registry');
      }
    }
  } catch {
    throw new TypeError('Invalid phase 1 differential scenario registry');
  }
};

assertExactDifferentialScenarioRegistry(phase1DifferentialScenarios);

/* eslint-enable max-lines, unicorn/prevent-abbreviations */
