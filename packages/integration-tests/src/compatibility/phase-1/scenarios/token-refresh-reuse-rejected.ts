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
  projectRejectedPositiveRefreshToken,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.refresh-reuse-rejected';
const refreshTokenReuseLeewayMilliseconds = 3000;
const refreshTokenReuseProbeDelayMilliseconds = refreshTokenReuseLeewayMilliseconds + 1000;
const logicalTokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

type FamilyState = Readonly<{
  rotationCount: number;
  predecessorConsumed: boolean;
  reuseDetected: boolean;
  descendantProbeRejected?: boolean;
  familyRevoked: boolean;
  activeDescendantCount: number;
  unrelatedMutation: false;
}>;

// eslint-disable-next-line complexity -- Exact pre-rotation, replay, descendant, and final shapes share one closed validator.
const assertState = (
  state: Phase1ScenarioStateProjectionInput,
  persistedState: FamilyState,
  grantRevoked: boolean,
  final = false
): void => {
  const { generatedIds } = state;

  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, persistedState) ||
    !isDeepStrictEqual(state.sideEffects, {
      ...(grantRevoked ? { grantRevoked: true } : {}),
      unrelatedMutation: false,
    }) ||
    (final
      ? typeof generatedIds !== 'object' ||
        generatedIds === null ||
        Array.isArray(generatedIds) ||
        typeof generatedIds.tokenFamily !== 'string' ||
        !logicalTokenFamilyPattern.test(generatedIds.tokenFamily)
      : !isDeepStrictEqual(generatedIds ?? {}, {}))
  ) {
    throw new Error('Phase 1 refresh token reuse state is invalid');
  }
};

const codeTokenState: FamilyState = Object.freeze({
  rotationCount: 0,
  predecessorConsumed: false,
  reuseDetected: false,
  familyRevoked: false,
  activeDescendantCount: 1,
  unrelatedMutation: false,
});
const rotatedState: FamilyState = Object.freeze({
  rotationCount: 1,
  predecessorConsumed: true,
  reuseDetected: false,
  familyRevoked: false,
  activeDescendantCount: 1,
  unrelatedMutation: false,
});
const replayedState: FamilyState = Object.freeze({
  rotationCount: 1,
  predecessorConsumed: true,
  reuseDetected: true,
  familyRevoked: true,
  activeDescendantCount: 0,
  unrelatedMutation: false,
});
const probedState: FamilyState = Object.freeze({
  ...replayedState,
  descendantProbeRejected: true,
});

const waitWithAbort = async (milliseconds: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, milliseconds);
    const cleanup = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(new Error('Phase 1 refresh token reuse wait failed'));
    };

    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
    }
  });

export type TokenRefreshReuseRejectedDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
  wait?: (milliseconds: number) => Promise<void>;
}>;

export const runTokenRefreshReuseRejected = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenRefreshReuseRejectedDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const wait =
    dependencies.wait ??
    (async (milliseconds: number) => waitWithAbort(milliseconds, context.signal));
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (authorizationGrant) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      const initial = await exchangePositiveAuthorizationCode(context, authorizationGrant);
      try {
        const codeToken = await projectPositiveTokenGrantSummary(context, {
          scenarioId,
          stepId: 'code-token',
          grant: initial,
          normalizationContext,
          validate: (state) => {
            assertState(state, codeTokenState, false);
          },
        });
        const rotated = await exchangePositiveRefreshToken(context, initial);
        try {
          const rotate = await projectPositiveTokenGrant(context, {
            scenarioId,
            stepId: 'rotate',
            grant: rotated,
            normalizationContext,
            expectAccessJwt: false,
            validate: (state) => {
              assertState(state, rotatedState, false);
            },
          });
          await wait(refreshTokenReuseProbeDelayMilliseconds);
          const replayOld = await projectRejectedPositiveRefreshToken(
            context,
            initial,
            'token-refresh-replay-old',
            async () => {
              const state = await context.projectScenarioState({
                scenarioId,
                stepId: 'replay-old',
                fixture: context.fixture,
              });
              assertState(state, replayedState, true);

              return state;
            },
            normalizationContext
          );
          const probeDescendant = await projectRejectedPositiveRefreshToken(
            context,
            rotated,
            'token-refresh-probe-descendant',
            async () => {
              const state = await context.projectScenarioState({
                scenarioId,
                stepId: 'probe-descendant',
                fixture: context.fixture,
              });
              assertState(state, probedState, true);

              return state;
            },
            normalizationContext
          );
          const state = await projectPositiveScenarioState(context, {
            scenarioId,
            stepId: 'state',
            normalizationContext,
            validate: (value) => {
              assertState(value, probedState, true, true);
            },
          });

          return Object.freeze([
            Object.freeze({ stepId: 'code-token', value: codeToken }),
            Object.freeze({ stepId: 'rotate', value: rotate }),
            Object.freeze({ stepId: 'replay-old', value: replayOld }),
            Object.freeze({ stepId: 'probe-descendant', value: probeDescendant }),
            Object.freeze({ stepId: 'state', value: state }),
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
