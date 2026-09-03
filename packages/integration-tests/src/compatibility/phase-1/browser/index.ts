/* eslint-disable complexity, no-await-in-loop, @typescript-eslint/no-loop-func, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-restricted-syntax -- The browser authority performs closed registry/provenance preflight before any provision or launch, then deliberately runs isolated groups and ordered shared-session flows serially while carrying the prior isolated fixture only for a distinctness check. */
import { isDeepStrictEqual } from 'node:util';

import { assertEvidenceIsSanitized } from '../../evidence.js';
import type { TargetConfig } from '../../model.js';
import {
  assertPhase1FixtureAllocationsAreDistinct,
  runWithPhase1Fixture,
  type ProvisionedPhase1Fixture,
} from '../fixtures.js';
import { oracleCommit } from '../model.js';
import { assertBrowserSemantics } from '../profile-semantics/browser.js';
import type { Phase1Profile } from '../profile-types.js';

import type {
  Phase1BrowserFixtureProvisioner,
  Phase1BrowserFlowEvidence,
  Phase1BrowserFlowModule,
  Phase1BrowserGroupEvidence,
  Phase1BrowserGroupId,
  Phase1BrowserGroupObserver,
  Phase1BrowserRunEvidence,
} from './contracts.js';
import { phase1BrowserFlowIds } from './contracts.js';
import { consoleApplicationRead } from './flows/console-application-read.js';
import { consoleCleanAuthentication } from './flows/console-clean-authentication.js';
import { consoleUserRead } from './flows/console-user-read.js';
import { experiencePasswordPkceConsent } from './flows/experience-password-pkce-consent.js';
import { isPlaywrightBrowserGroupObserver } from './playwright-session.js';

const canonicalBrowserFlows = Object.freeze([
  experiencePasswordPkceConsent,
  consoleCleanAuthentication,
  consoleApplicationRead,
  consoleUserRead,
] as const satisfies readonly Phase1BrowserFlowModule[]);
export const canonicalBrowserSourcePaths = Object.freeze([
  ...new Set(canonicalBrowserFlows.flatMap(({ sourcePaths }) => sourcePaths)),
]);

const expectedSourceLengths = Object.freeze([8, 11, 7, 6] as const);
const browserSourceUnionSize = 25;

const fail = (): never => {
  throw new TypeError('Invalid Phase 1 browser registry');
};

export const validatePhase1BrowserRegistry = (
  profile: Readonly<Phase1Profile>,
  modules: readonly Phase1BrowserFlowModule[] = canonicalBrowserFlows
): readonly Phase1BrowserFlowModule[] => {
  try {
    assertBrowserSemantics(profile);
    if (
      modules.length !== phase1BrowserFlowIds.length ||
      profile.browserFlows.length !== phase1BrowserFlowIds.length ||
      profile.reference.oracleCommit !== oracleCommit ||
      new Set(modules.map(({ id }) => id)).size !== modules.length
    ) {
      return fail();
    }
    for (const [index, id] of phase1BrowserFlowIds.entries()) {
      const module = modules[index];
      const flow = profile.browserFlows[index];

      if (
        !module ||
        !flow ||
        module.id !== id ||
        flow.id !== id ||
        module.executionGroup !== flow.executionGroup ||
        module.sourcePaths.length !== expectedSourceLengths[index] ||
        !isDeepStrictEqual(module.sourcePaths, flow.sourceEvidence)
      ) {
        return fail();
      }
    }
    const sourceUnion = [...new Set(modules.flatMap(({ sourcePaths }) => sourcePaths))];

    if (
      sourceUnion.length !== browserSourceUnionSize ||
      !modules[0]?.sourcePaths.includes('packages/demo-app/src/DevPanel.tsx')
    ) {
      return fail();
    }

    return Object.freeze([...modules]);
  } catch {
    return fail();
  }
};

export type RunPhase1BrowserFlowsInput = Readonly<{
  profile: Readonly<Phase1Profile>;
  target: TargetConfig;
  provisioner: Phase1BrowserFixtureProvisioner;
  observer: Phase1BrowserGroupObserver;
  signal: AbortSignal;
  timeoutMs?: number;
}>;

export type RunPhase1BrowserFlowsDependencies = Readonly<{
  modules?: readonly Phase1BrowserFlowModule[];
}>;

const evidenceFor = (
  profile: Readonly<Phase1Profile>,
  module: Phase1BrowserFlowModule,
  observation: Awaited<ReturnType<Phase1BrowserFlowModule['run']>>
): Phase1BrowserFlowEvidence => {
  const sourceEvidence = Object.freeze(
    module.sourcePaths.map((path) => Object.freeze({ commit: oracleCommit, path }))
  );
  const evidence = Object.freeze({
    id: module.id,
    executionGroup: module.executionGroup,
    sourceEvidence,
    observation,
  });
  assertEvidenceIsSanitized({ browserFlow: evidence });

  return evidence;
};

const executePhase1BrowserFlows = async (
  input: RunPhase1BrowserFlowsInput,
  dependencies: RunPhase1BrowserFlowsDependencies
): Promise<Phase1BrowserRunEvidence> => {
  const modules = validatePhase1BrowserRegistry(input.profile, dependencies.modules);
  const moduleById = new Map(modules.map((module) => [module.id, module]));
  const groupEvidence: Phase1BrowserGroupEvidence[] = [];
  let experienceFixture: ProvisionedPhase1Fixture | undefined;

  if (input.signal.aborted) {
    throw new Error('Phase 1 browser run aborted');
  }
  for (const group of input.profile.browserExecutionGroups) {
    const groupId = group.id as Phase1BrowserGroupId;
    const evidence = await runWithPhase1Fixture(
      input.provisioner,
      'fullPhase1',
      async (fixture, fixtureSignal) => {
        if (groupId === 'experience') {
          experienceFixture = fixture;
        } else if (experienceFixture) {
          assertPhase1FixtureAllocationsAreDistinct(experienceFixture, fixture);
        } else {
          throw new Error('Phase 1 browser group order is invalid');
        }
        const signal = AbortSignal.any([input.signal, fixtureSignal]);

        return fixture.withSecretLease(async (lease) =>
          input.observer.runInFreshContext(groupId, signal, input.target, async (session) => {
            const flows: Phase1BrowserFlowEvidence[] = [];

            for (const flowId of group.orderedFlows) {
              const module = moduleById.get(flowId as Phase1BrowserFlowModule['id']);

              if (!module || module.executionGroup !== groupId) {
                throw new Error('Phase 1 browser group is invalid');
              }
              const observation = await module.run({
                profile: input.profile,
                target: input.target,
                fixture,
                lease,
                session,
                readActivityState: async (logicalUserId) =>
                  input.provisioner.readUserActivityState(fixture, logicalUserId),
                projectState: async () => input.provisioner.projectState(fixture),
                signal,
              });
              assertEvidenceIsSanitized({ browserObservation: observation });
              flows.push(evidenceFor(input.profile, module, observation));
            }

            return Object.freeze({ id: groupId, flows: Object.freeze(flows) });
          })
        );
      },
      input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }
    );
    groupEvidence.push(evidence);
  }
  const result = Object.freeze({ groups: Object.freeze(groupEvidence) });
  assertEvidenceIsSanitized({ browserRun: result });

  return result;
};

export const runPhase1BrowserFlows = async (
  input: RunPhase1BrowserFlowsInput
): Promise<Phase1BrowserRunEvidence> => {
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    throw new TypeError('Invalid Phase 1 browser observer');
  }

  return executePhase1BrowserFlows(input, {});
};

/** Test-only lifecycle executor. Production code must use the canonical runner above. */
export const runPhase1BrowserFlowsForTesting = async (
  input: RunPhase1BrowserFlowsInput,
  dependencies: RunPhase1BrowserFlowsDependencies
): Promise<Phase1BrowserRunEvidence> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError('Phase 1 browser test executor is unavailable');
  }

  return executePhase1BrowserFlows(input, dependencies);
};

export { canonicalBrowserFlows };

/* eslint-enable complexity, no-await-in-loop, @typescript-eslint/no-loop-func, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-restricted-syntax */
