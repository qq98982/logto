import { isDeepStrictEqual } from 'node:util';

import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { projectSemanticStateObservation } from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  withPositiveAdminSession,
  type PositiveAdminFlowRandomSource,
} from './positive-admin-flow.js';
import {
  positiveAdminNormalizationContext,
  refreshPositiveAdminManagementToken,
} from './positive-admin-token.js';

const scenarioId = 'console.admin-auth-resource-refresh';
const tokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const assertManagementRefreshState = (state: Phase1ScenarioStateProjectionInput): void => {
  const { generatedIds } = state;

  if (
    typeof generatedIds !== 'object' ||
    generatedIds === null ||
    Array.isArray(generatedIds) ||
    typeof generatedIds.tokenFamily !== 'string' ||
    !tokenFamilyPattern.test(generatedIds.tokenFamily) ||
    !isDeepStrictEqual(state.persistedState, {
      grantConsumed: true,
      familyCount: 1,
      rotation: { replaced: true, sameFamily: true },
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 admin Management refresh state is invalid');
  }
};

export type ConsoleAdminAuthResourceRefreshDependencies = Readonly<{
  random?: PositiveAdminFlowRandomSource;
}>;

export const runConsoleAdminAuthResourceRefresh = async (
  context: Phase1ScenarioRunContext,
  dependencies: ConsoleAdminAuthResourceRefreshDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const output = await withPositiveAdminSession(
    context,
    {
      random: dependencies.random,
      captureAuthorize: true,
      captureCodeToken: true,
    },
    async (session) => {
      const management = await refreshPositiveAdminManagementToken(context, session, {
        scenarioId,
        stepId: 'management-refresh',
      });

      if (!management) {
        throw new Error('Phase 1 admin Management refresh projection is unavailable');
      }
      const stateInput = await context.projectScenarioState({
        scenarioId,
        stepId: 'state',
        fixture: context.fixture,
      });
      assertManagementRefreshState(stateInput);
      const state = projectSemanticStateObservation(
        { ...stateInput, status: 200, headers: [] },
        positiveAdminNormalizationContext(context),
        { scenarioId, stepId: 'state' }
      );

      return Object.freeze([
        Object.freeze({ stepId: 'management-refresh', value: management }),
        Object.freeze({ stepId: 'state', value: state }),
      ]);
    }
  );

  return Object.freeze([...output.steps, ...output.result]);
};
