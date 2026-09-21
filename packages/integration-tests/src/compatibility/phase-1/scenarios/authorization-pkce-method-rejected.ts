import { isDeepStrictEqual } from 'node:util';

import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { projectSemanticStateObservation } from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  positiveOidcAuthorizationNormalizationContext,
  projectPositiveOidcPkceMethodRejection,
  type PositiveOidcAuthorizationRequestOptions,
} from './positive-oidc-flow.js';

const scenarioId = 'authorization.pkce-method-rejected';
const canonicalRejectedMethods = Object.freeze(['plain', 's256', 'S512', 'unsupported']);

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
    throw new Error('Phase 1 rejected PKCE method state is invalid');
  }
};

export type AuthorizationPkceMethodRejectedDependencies = Readonly<{
  random?: PositiveOidcAuthorizationRequestOptions['random'];
  codeChallengeMethods?: readonly string[];
}>;

export const runAuthorizationPkceMethodRejected = async (
  context: Phase1ScenarioRunContext,
  dependencies: AuthorizationPkceMethodRejectedDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const methods = dependencies.codeChallengeMethods ?? canonicalRejectedMethods;

  if (
    methods.length === 0 ||
    methods.some((method) => !method || method === 'S256') ||
    new Set(methods).size !== methods.length ||
    !methods.includes('plain')
  ) {
    throw new Error('Phase 1 rejected PKCE method is invalid');
  }
  const probe = async (
    remaining: readonly string[],
    completed: ReadonlyArray<
      Readonly<{
        method: string;
        projection: Awaited<ReturnType<typeof projectPositiveOidcPkceMethodRejection>>;
      }>
    >
  ): Promise<
    ReadonlyArray<
      Readonly<{
        method: string;
        projection: Awaited<ReturnType<typeof projectPositiveOidcPkceMethodRejection>>;
      }>
    >
  > => {
    const [method, ...rest] = remaining;

    if (!method) {
      return completed;
    }
    const projection = await projectPositiveOidcPkceMethodRejection(
      context,
      {
        operation: `authorization-pkce-method-rejected-${method}`,
        random: dependencies.random,
        includeResource: false,
        codeChallengeMethod: method,
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

    return probe(rest, [...completed, Object.freeze({ method, projection })]);
  };
  const projections = await probe(methods, []);
  const authorize = projections.find(({ method }) => method === 'plain')?.projection;

  if (!authorize) {
    throw new Error('Phase 1 rejected PKCE method response is invalid');
  }
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
