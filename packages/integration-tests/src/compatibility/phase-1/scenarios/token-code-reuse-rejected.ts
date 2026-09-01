import { isDeepStrictEqual } from 'node:util';

import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  exchangePositiveAuthorizationCode,
  projectRejectedPositiveAuthorizationCode,
  withPositiveOidcFlow,
  type PositiveOidcFlowOptions,
} from './positive-oidc-flow.js';
import {
  positiveOidcDataNormalizationContext,
  projectPositiveScenarioState,
  projectPositiveTokenGrant,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.code-reuse-rejected';
const logicalTokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const assertFirstExchangeState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, {
      firstExchangeSucceeded: true,
      grantConsumed: true,
      familyCount: 1,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {}) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 first authorization code exchange state is invalid');
  }
};

const assertReplayState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, {
      firstExchangeSucceeded: true,
      replayRejected: true,
      grantPresent: false,
      familyCount: 0,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {}) ||
    !isDeepStrictEqual(state.sideEffects, {
      grantRevoked: true,
      unrelatedMutation: false,
    })
  ) {
    throw new Error('Phase 1 authorization code replay state is invalid');
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
    !isDeepStrictEqual(state.persistedState, {
      firstExchangeSucceeded: true,
      replayRejected: true,
      grantPresent: false,
      familyCount: 0,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.sideEffects, {
      grantRevoked: true,
      unrelatedMutation: false,
    })
  ) {
    throw new Error('Phase 1 authorization code replay final state is invalid');
  }
};

export type TokenCodeReuseRejectedDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
}>;

export const runTokenCodeReuseRejected = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenCodeReuseRejectedDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (authorizationGrant) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      const tokenGrant = await exchangePositiveAuthorizationCode(context, authorizationGrant, {
        operation: 'token-code-first-exchange',
        verifier: 'correct',
      });
      try {
        const firstExchange = await projectPositiveTokenGrant(context, {
          scenarioId,
          stepId: 'first-exchange',
          grant: tokenGrant,
          normalizationContext,
          expectAccessJwt: false,
          validate: assertFirstExchangeState,
        });
        const replay = await projectRejectedPositiveAuthorizationCode(
          context,
          authorizationGrant,
          { operation: 'token-code-replay', verifier: 'correct' },
          async () => {
            const state = await context.projectScenarioState({
              scenarioId,
              stepId: 'replay',
              fixture: context.fixture,
            });
            assertReplayState(state);

            return state;
          },
          normalizationContext
        );
        const state = await projectPositiveScenarioState(context, {
          scenarioId,
          stepId: 'state',
          normalizationContext,
          validate: assertFinalState,
        });

        return Object.freeze([
          Object.freeze({ stepId: 'first-exchange', value: firstExchange }),
          Object.freeze({ stepId: 'replay', value: replay }),
          Object.freeze({ stepId: 'state', value: state }),
        ]);
      } finally {
        revokePositiveTokenGrant(tokenGrant);
      }
    }
  );

  return result;
};
