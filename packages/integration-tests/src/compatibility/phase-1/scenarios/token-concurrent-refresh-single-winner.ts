import { isDeepStrictEqual } from 'node:util';

import type { JsonValue } from '../../normalize.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import {
  projectConcurrencyObservation,
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
  exchangePositiveRefreshToken,
  positiveOidcDataNormalizationContext,
  projectPositiveTokenGrant,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.concurrent-refresh-single-winner';
const attempts = Object.freeze([
  Object.freeze({ operation: 'token-concurrent-refresh-attempt-a', stepId: 'attempt-a' }),
  Object.freeze({ operation: 'token-concurrent-refresh-attempt-b', stepId: 'attempt-b' }),
] as const);
const logicalTokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const expectedPersistedState = Object.freeze({
  presentationSuccessCount: 2,
  predecessorConsumed: true,
  replacementRefreshCount: 2,
  distinctReplacementCount: 2,
  activeDescendantCount: 2,
  replacementRotationOrdinals: Object.freeze([1, 1]),
  familyCount: 1,
  unrelatedMutation: false,
});
const expectedSideEffects = Object.freeze({
  sameGrantFamily: true,
  siblingDescendantsCreated: true,
  unrelatedMutation: false,
});

const assertAttemptState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, expectedPersistedState) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {}) ||
    !isDeepStrictEqual(state.sideEffects, expectedSideEffects)
  ) {
    throw new Error('Phase 1 concurrent refresh attempt state is invalid');
  }
};

const assertFinalState = (state: Phase1ScenarioStateProjectionInput): void => {
  const { generatedIds } = state;

  if (
    typeof generatedIds !== 'object' ||
    generatedIds === null ||
    Array.isArray(generatedIds) ||
    typeof generatedIds.tokenFamily !== 'string' ||
    !logicalTokenFamilyPattern.test(generatedIds.tokenFamily) ||
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, expectedPersistedState) ||
    !isDeepStrictEqual(state.sideEffects, expectedSideEffects)
  ) {
    throw new Error('Phase 1 concurrent refresh final state is invalid');
  }
};

const stateInput = async (
  context: Phase1ScenarioRunContext,
  stepId: 'attempt-a' | 'attempt-b' | 'race' | 'state'
) => context.projectScenarioState({ scenarioId, stepId, fixture: context.fixture });

export type TokenConcurrentRefreshSingleWinnerDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
  revokePositiveTokenGrant?: typeof revokePositiveTokenGrant;
}>;

export const runTokenConcurrentRefreshSingleWinner = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenConcurrentRefreshSingleWinnerDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const revokeGrant = dependencies.revokePositiveTokenGrant ?? revokePositiveTokenGrant;
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (authorizationGrant) => {
      const initial = await exchangePositiveAuthorizationCode(context, authorizationGrant);

      try {
        const normalizationContext = positiveOidcDataNormalizationContext(context);
        return await withTwoTokenRequestBarrier(
          context,
          [
            {
              ...attempts[0],
              run: async (raceContext) =>
                exchangePositiveRefreshToken(raceContext, initial, attempts[0].operation),
            },
            {
              ...attempts[1],
              run: async (raceContext) =>
                exchangePositiveRefreshToken(raceContext, initial, attempts[1].operation),
            },
          ],
          {
            normalizationContext,
            readState: async (stepId) =>
              stateInput(context, stepId === 'attempt-a' ? 'attempt-a' : 'attempt-b'),
            validateState: assertAttemptState,
            cleanupFulfilled: revokeGrant,
            consume: async (raced) => {
              if (raced.settled.some((outcome) => outcome.status !== 'fulfilled')) {
                throw new Error('Phase 1 concurrent refresh outcomes are invalid');
              }
              const grantsByOperation = new Map<string, (typeof raced.settled)[number]>([
                [attempts[0].operation, raced.settled[0]],
                [attempts[1].operation, raced.settled[1]],
              ]);
              const projectedAttempts = await Promise.all(
                raced.presentation.map(async ({ operation, stepId, kind }) => {
                  const outcome = grantsByOperation.get(operation);

                  if (outcome?.status !== 'fulfilled' || kind !== 'success') {
                    throw new Error('Phase 1 concurrent refresh outcomes are invalid');
                  }
                  const projection = await projectPositiveTokenGrant(context, {
                    scenarioId,
                    stepId,
                    grant: outcome.value,
                    normalizationContext,
                    expectAccessJwt: false,
                    validate: assertAttemptState,
                  });

                  return Object.freeze({
                    step: Object.freeze({ stepId, value: projection }),
                    outcome: Object.freeze({ kind: 'success', status: projection.status }),
                  });
                })
              );
              const outcomes: JsonValue[] = projectedAttempts.map(({ outcome }) => outcome);
              const raceState = await stateInput(context, 'race');
              assertAttemptState(raceState);
              const race = projectConcurrencyObservation(
                { ...raceState, status: 200, headers: [], body: outcomes },
                normalizationContext
              );
              const finalState = await stateInput(context, 'state');
              assertFinalState(finalState);
              const state = projectSemanticStateObservation(
                { ...finalState, status: 200, headers: [] },
                normalizationContext,
                { scenarioId, stepId: 'state' }
              );
              const output = Object.freeze([
                ...projectedAttempts.map(({ step }) => step),
                Object.freeze({ stepId: 'race', value: race }),
                Object.freeze({ stepId: 'state', value: state }),
              ]);
              context.protocol.forAllocation('data').oidc.store.assertNoCredentialMaterial(output);

              return output;
            },
          }
        );
      } finally {
        revokeGrant(initial);
      }
    }
  );

  return result;
};
