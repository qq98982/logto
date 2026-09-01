import { isDeepStrictEqual } from 'node:util';

import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  exchangePositiveAuthorizationCode,
  withPositiveOidcFlow,
  type PositiveOidcFlowOptions,
} from './positive-oidc-flow.js';
import {
  positiveOidcDataNormalizationContext,
  projectPositiveScenarioState,
  projectPositiveTokenGrant,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.authorization-code';
const logicalTokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const assertAuthorizationCodeState = (state: Phase1ScenarioStateProjectionInput): void => {
  const { generatedIds } = state;

  if (
    typeof generatedIds !== 'object' ||
    generatedIds === null ||
    Array.isArray(generatedIds) ||
    typeof generatedIds.tokenFamily !== 'string' ||
    !logicalTokenFamilyPattern.test(generatedIds.tokenFamily) ||
    !isDeepStrictEqual(state.persistedState, {
      grantConsumed: true,
      familyCount: 1,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 authorization code state is invalid');
  }
};

export type TokenAuthorizationCodeDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
}>;

export const runTokenAuthorizationCode = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenAuthorizationCodeDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: true },
    async (credentials) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      const grant = await exchangePositiveAuthorizationCode(context, credentials);
      try {
        const token = await projectPositiveTokenGrant(context, {
          scenarioId,
          stepId: 'token',
          grant,
          normalizationContext,
          expectAccessJwt: true,
        });
        const state = await projectPositiveScenarioState(context, {
          scenarioId,
          stepId: 'state',
          normalizationContext,
          validate: assertAuthorizationCodeState,
        });

        return Object.freeze([
          Object.freeze({ stepId: 'token', value: token }),
          Object.freeze({ stepId: 'state', value: state }),
        ]);
      } finally {
        revokePositiveTokenGrant(grant);
      }
    }
  );

  return result;
};
