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
  refreshPositiveAdminOrganizationToken,
} from './positive-admin-token.js';

const scenarioId = 'console.admin-organization-token-refresh';
const tokenFamilyPattern = /^<token-family\.[1-9]\d*>$/u;

const assertOrganizationRefreshState = (state: Phase1ScenarioStateProjectionInput): void => {
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
      tenantMutation: false,
      membershipMutation: false,
      roleMutation: false,
      consentMutation: false,
    }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 admin organization refresh state is invalid');
  }
};

export type ConsoleAdminOrganizationTokenRefreshDependencies = Readonly<{
  random?: PositiveAdminFlowRandomSource;
}>;

export const runConsoleAdminOrganizationTokenRefresh = async (
  context: Phase1ScenarioRunContext,
  dependencies: ConsoleAdminOrganizationTokenRefreshDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const output = await withPositiveAdminSession(
    context,
    {
      random: dependencies.random,
      captureAuthorize: false,
      captureCodeToken: false,
    },
    async (session) => {
      const organization = await refreshPositiveAdminOrganizationToken(context, session, {
        scenarioId,
        stepId: 'organization-refresh',
      });
      const stateInput = await context.projectScenarioState({
        scenarioId,
        stepId: 'state',
        fixture: context.fixture,
      });
      assertOrganizationRefreshState(stateInput);
      const state = projectSemanticStateObservation(
        { ...stateInput, status: 200, headers: [] },
        positiveAdminNormalizationContext(context),
        { scenarioId, stepId: 'state' }
      );

      return Object.freeze([
        Object.freeze({ stepId: 'organization-refresh', value: organization }),
        Object.freeze({ stepId: 'state', value: state }),
      ]);
    }
  );

  return Object.freeze([...output.steps, ...output.result]);
};
