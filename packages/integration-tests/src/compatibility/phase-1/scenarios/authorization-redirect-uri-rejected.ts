import { isDeepStrictEqual } from 'node:util';

import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { projectSemanticStateObservation } from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  positiveOidcAuthorizationNormalizationContext,
  projectPositiveOidcRedirectUriRejection,
  type PositiveOidcAuthorizationRequestOptions,
} from './positive-oidc-flow.js';

const scenarioId = 'authorization.redirect-uri-rejected';

const assertNoProtocolState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.semanticState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.persistedState, {
      interactionCount: 0,
      grantCount: 0,
      familyCount: 0,
      unrelatedMutation: false,
    }) ||
    !isDeepStrictEqual(state.generatedIds ?? {}, {}) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 rejected redirect state is invalid');
  }
};

const rejectedRedirectUri = (registeredRedirectUri: string): string => {
  const url = new URL(registeredRedirectUri);
  const pathname = `${url.pathname.replace(/\/$/u, '')}/unregistered`;

  return new URL(pathname, `${url.origin}/`).href;
};

export type AuthorizationRedirectUriRejectedDependencies = Readonly<{
  random?: PositiveOidcAuthorizationRequestOptions['random'];
}>;

export const runAuthorizationRedirectUriRejected = async (
  context: Phase1ScenarioRunContext,
  dependencies: AuthorizationRedirectUriRejectedDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const registeredRedirectUri = context.profile.fixtures.dataTenant.applications.find(
    ({ id }) =>
      id === context.profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.appId
  )?.oidcClientMetadata.redirectUris[0];

  if (!registeredRedirectUri) {
    throw new Error('Phase 1 consent redirect URI is invalid');
  }
  const authorize = await projectPositiveOidcRedirectUriRejection(
    context,
    {
      operation: 'authorization-redirect-uri-rejected',
      random: dependencies.random,
      includeResource: false,
      includeState: false,
      redirectUri: rejectedRedirectUri(registeredRedirectUri),
    },
    async () => {
      const state = await context.projectScenarioState({
        scenarioId,
        stepId: 'authorize',
        fixture: context.fixture,
      });
      assertNoProtocolState(state);

      return state;
    }
  );
  const finalState = await context.projectScenarioState({
    scenarioId,
    stepId: 'state',
    fixture: context.fixture,
  });
  assertNoProtocolState(finalState);
  const projectionContext = positiveOidcAuthorizationNormalizationContext(context);
  const state = projectSemanticStateObservation(
    { ...finalState, status: 200, headers: [] },
    projectionContext,
    { scenarioId, stepId: 'state' }
  );

  return Object.freeze([
    Object.freeze({ stepId: 'authorize', value: authorize }),
    Object.freeze({ stepId: 'state', value: state }),
  ]);
};
