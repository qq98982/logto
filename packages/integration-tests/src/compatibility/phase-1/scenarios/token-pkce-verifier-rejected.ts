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
  projectPositiveTokenGrantSummary,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.pkce-verifier-rejected';
const logicalTokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const assertBadVerifierState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, {
      firstAttemptConsumed: false,
      grantConsumed: false,
      familyCount: 0,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {}) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 rejected PKCE verifier state is invalid');
  }
};

const assertValidProbeState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, {
      firstAttemptConsumed: false,
      grantConsumed: true,
      familyCount: 1,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {}) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 valid PKCE verifier probe state is invalid');
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
      firstAttemptConsumed: false,
      validProbeSucceeded: true,
      grantConsumed: true,
      familyCount: 1,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 rejected PKCE verifier final state is invalid');
  }
};

export type TokenPkceVerifierRejectedDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
}>;

export const runTokenPkceVerifierRejected = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenPkceVerifierRejectedDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (authorizationGrant) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      const badVerifier = await projectRejectedPositiveAuthorizationCode(
        context,
        authorizationGrant,
        { operation: 'token-pkce-bad-verifier', verifier: 'mismatch' },
        async () => {
          const state = await context.projectScenarioState({
            scenarioId,
            stepId: 'bad-verifier',
            fixture: context.fixture,
          });
          assertBadVerifierState(state);

          return state;
        },
        normalizationContext
      );
      const tokenGrant = await exchangePositiveAuthorizationCode(context, authorizationGrant, {
        operation: 'token-pkce-valid-verifier-probe',
        verifier: 'correct',
      });
      try {
        const validVerifierProbe = await projectPositiveTokenGrantSummary(context, {
          scenarioId,
          stepId: 'valid-verifier-probe',
          grant: tokenGrant,
          normalizationContext,
          validate: assertValidProbeState,
        });
        const state = await projectPositiveScenarioState(context, {
          scenarioId,
          stepId: 'state',
          normalizationContext,
          validate: assertFinalState,
        });

        return Object.freeze([
          Object.freeze({ stepId: 'bad-verifier', value: badVerifier }),
          Object.freeze({ stepId: 'valid-verifier-probe', value: validVerifierProbe }),
          Object.freeze({ stepId: 'state', value: state }),
        ]);
      } finally {
        revokePositiveTokenGrant(tokenGrant);
      }
    }
  );

  return result;
};
