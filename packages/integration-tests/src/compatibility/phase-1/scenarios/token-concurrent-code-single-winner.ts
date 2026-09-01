import { isDeepStrictEqual } from 'node:util';

import type { JsonValue } from '../../normalize.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import {
  projectConcurrencyObservation,
  projectHttpObservation,
  projectSemanticStateObservation,
} from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import { withTwoTokenRequestBarrier } from './positive-oidc-concurrency.js';
import {
  exchangePositiveAuthorizationCode,
  withPositiveOidcFlow,
  type PositiveOidcFlowOptions,
} from './positive-oidc-flow.js';
import {
  positiveOidcDataNormalizationContext,
  revokePositiveTokenGrant,
  verifyPositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.concurrent-code-single-winner';
const attempts = Object.freeze([
  Object.freeze({ operation: 'token-concurrent-code-attempt-a', stepId: 'attempt-a' }),
  Object.freeze({ operation: 'token-concurrent-code-attempt-b', stepId: 'attempt-b' }),
] as const);
type ReachableBranch = 'double-success' | 'revoked-single-success';

const doubleSuccessPersistedState = Object.freeze({
  authorizationCodePresent: true,
  authorizationCodeConsumed: true,
  grantPresent: true,
  familyCount: 1,
  activeRefreshDescendantCount: 2,
  unrelatedMutation: false,
});
const revokedSingleSuccessPersistedState = Object.freeze({
  authorizationCodePresent: false,
  grantPresent: false,
  familyCount: 0,
  activeRefreshDescendantCount: 0,
  unrelatedMutation: false,
});
const canonicalState = Object.freeze({
  body: Object.freeze({}),
  semanticState: Object.freeze({ concurrentCodeRace: 'accepted', unrelatedMutation: false }),
  persistedState: Object.freeze({ acceptedOutcomeEnvelope: true, unrelatedMutation: false }),
  generatedIds: Object.freeze({}),
  sideEffects: Object.freeze({ unrelatedMutation: false }),
});
const canonicalRaceOutcomes = Object.freeze([
  Object.freeze({
    kind: 'accepted',
    attempts: 2,
    minimumSuccesses: 1,
    maximumSuccesses: 2,
    allowedError: 'invalid_grant',
  }),
] satisfies readonly JsonValue[]);

const withoutDanglingRefreshDescendantCount = (
  value: Phase1ScenarioStateProjectionInput['persistedState']
) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Phase 1 concurrent authorization code state is invalid');
  }

  const dangling = value.danglingRefreshDescendantCount;

  if (
    dangling !== undefined &&
    (typeof dangling !== 'number' || !Number.isSafeInteger(dangling) || dangling < 0)
  ) {
    throw new Error('Phase 1 concurrent authorization code state is invalid');
  }

  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'danglingRefreshDescendantCount')
  );
};

const requireReachableState = (state: Phase1ScenarioStateProjectionInput): ReachableBranch => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {})
  ) {
    throw new Error('Phase 1 concurrent authorization code state is invalid');
  }
  if (
    isDeepStrictEqual(state.persistedState, doubleSuccessPersistedState) &&
    isDeepStrictEqual(state.sideEffects, {
      sameGrantFamily: true,
      grantRevoked: false,
      unrelatedMutation: false,
    })
  ) {
    return 'double-success';
  }
  if (
    isDeepStrictEqual(
      withoutDanglingRefreshDescendantCount(state.persistedState),
      revokedSingleSuccessPersistedState
    ) &&
    isDeepStrictEqual(state.sideEffects, { grantRevoked: true, unrelatedMutation: false })
  ) {
    return 'revoked-single-success';
  }

  throw new Error('Phase 1 concurrent authorization code state is invalid');
};

const assertCanonicalState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (!isDeepStrictEqual(state, canonicalState)) {
    throw new Error('Phase 1 concurrent authorization code canonical state is invalid');
  }
};

const stateInput = async (
  context: Phase1ScenarioRunContext,
  stepId: 'attempt-a' | 'attempt-b' | 'race' | 'state'
) => context.projectScenarioState({ scenarioId, stepId, fixture: context.fixture });

const projectCanonicalAttempt = (
  stepId: 'attempt-a' | 'attempt-b',
  normalizationContext: ReturnType<typeof positiveOidcDataNormalizationContext>
): Phase1ScenarioStepResult =>
  Object.freeze({
    stepId,
    value: projectHttpObservation(
      {
        ...canonicalState,
        status: 200,
        headers: [],
        body: { presentation: 'validated', slot: stepId },
      },
      normalizationContext
    ),
  });

export type TokenConcurrentCodeSingleWinnerDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
}>;

export const runTokenConcurrentCodeSingleWinner = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenConcurrentCodeSingleWinnerDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (authorizationGrant) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      return withTwoTokenRequestBarrier(
        context,
        [
          {
            ...attempts[0],
            run: async (raceContext) =>
              exchangePositiveAuthorizationCode(raceContext, authorizationGrant, {
                operation: attempts[0].operation,
              }),
          },
          {
            ...attempts[1],
            run: async (raceContext) =>
              exchangePositiveAuthorizationCode(raceContext, authorizationGrant, {
                operation: attempts[1].operation,
              }),
          },
        ],
        {
          normalizationContext,
          readState: async () => canonicalState,
          validateState: assertCanonicalState,
          cleanupFulfilled: revokePositiveTokenGrant,
          consume: async (raced) => {
            const settledByOperation = new Map<string, (typeof raced.settled)[number]>([
              [attempts[0].operation, raced.settled[0]],
              [attempts[1].operation, raced.settled[1]],
            ]);
            const outcomeKinds = raced.presentation.map(({ operation, kind }) => {
              const outcome = settledByOperation.get(operation);

              if (kind === 'success' && outcome?.status === 'fulfilled') {
                return 'success' as const;
              }
              if (
                kind === 'error' &&
                outcome?.status === 'rejected' &&
                raced.rejections[operation]
              ) {
                return 'error' as const;
              }

              throw new Error('Phase 1 concurrent authorization code outcomes are invalid');
            });
            const successCount = outcomeKinds.filter((kind) => kind === 'success').length;
            const rejectionCount = outcomeKinds.filter((kind) => kind === 'error').length;
            const branch: ReachableBranch = (() => {
              if (successCount === 2 && rejectionCount === 0) {
                return 'double-success';
              }
              if (successCount === 1 && rejectionCount === 1) {
                return 'revoked-single-success';
              }

              throw new Error('Phase 1 concurrent authorization code outcomes are invalid');
            })();
            const successfulGrants = raced.settled.flatMap((outcome) =>
              outcome.status === 'fulfilled' ? [outcome.value] : []
            );

            await Promise.all(
              successfulGrants.map(async (grant) => verifyPositiveTokenGrant(context, grant, false))
            );
            const stateCoordinates = ['attempt-a', 'attempt-b', 'race', 'state'] as const;
            const observedStates = await Promise.all(
              stateCoordinates.map(async (stepId) => stateInput(context, stepId))
            );

            if (observedStates.some((state) => requireReachableState(state) !== branch)) {
              throw new Error('Phase 1 concurrent authorization code state is invalid');
            }
            const projectedAttempts = attempts.map(({ stepId }) =>
              projectCanonicalAttempt(stepId, normalizationContext)
            );
            const race = projectConcurrencyObservation(
              { ...canonicalState, status: 200, headers: [], body: canonicalRaceOutcomes },
              normalizationContext
            );
            const state = projectSemanticStateObservation(
              { ...canonicalState, status: 200, headers: [] },
              normalizationContext,
              { scenarioId, stepId: 'state' }
            );
            const output = Object.freeze([
              ...projectedAttempts,
              Object.freeze({ stepId: 'race', value: race }),
              Object.freeze({ stepId: 'state', value: state }),
            ]);
            context.protocol.forAllocation('data').oidc.store.assertNoCredentialMaterial(output);

            return output;
          },
        }
      );
    }
  );

  return result;
};
