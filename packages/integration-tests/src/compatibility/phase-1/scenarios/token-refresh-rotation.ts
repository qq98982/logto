import { isDeepStrictEqual } from 'node:util';

import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  exchangePositiveAuthorizationCode,
  withPositiveOidcFlow,
  type PositiveOidcFlowOptions,
} from './positive-oidc-flow.js';
import {
  exchangePositiveRefreshToken,
  positiveOidcDataNormalizationContext,
  projectPositiveScenarioState,
  projectPositiveTokenGrant,
  projectPositiveTokenGrantSummary,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.refresh-rotation';
const logicalTokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const assertRefreshFamilyState = (state: Phase1ScenarioStateProjectionInput): void => {
  const { generatedIds } = state;

  if (
    typeof generatedIds !== 'object' ||
    generatedIds === null ||
    Array.isArray(generatedIds) ||
    typeof generatedIds.tokenFamily !== 'string' ||
    !logicalTokenFamilyPattern.test(generatedIds.tokenFamily) ||
    !isDeepStrictEqual(state.persistedState, {
      rotation: { replaced: true, sameFamily: true },
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 refresh family state is invalid');
  }
};

export type TokenRefreshRotationDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
}>;

export const runTokenRefreshRotation = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenRefreshRotationDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (credentials) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      const initial = await exchangePositiveAuthorizationCode(context, credentials);
      try {
        const codeToken = await projectPositiveTokenGrantSummary(context, {
          scenarioId,
          stepId: 'code-token',
          grant: initial,
          normalizationContext,
        });
        const rotated = await exchangePositiveRefreshToken(context, initial);
        try {
          const refreshToken = await projectPositiveTokenGrant(context, {
            scenarioId,
            stepId: 'refresh-token',
            grant: rotated,
            normalizationContext,
            expectAccessJwt: false,
          });
          const familyState = await projectPositiveScenarioState(context, {
            scenarioId,
            stepId: 'family-state',
            normalizationContext,
            validate: assertRefreshFamilyState,
          });

          return Object.freeze([
            Object.freeze({ stepId: 'code-token', value: codeToken }),
            Object.freeze({ stepId: 'refresh-token', value: refreshToken }),
            Object.freeze({ stepId: 'family-state', value: familyState }),
          ]);
        } finally {
          revokePositiveTokenGrant(rotated);
        }
      } finally {
        revokePositiveTokenGrant(initial);
      }
    }
  );

  return result;
};
