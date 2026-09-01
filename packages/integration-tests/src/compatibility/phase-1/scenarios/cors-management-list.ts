import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonValue, NormalizationContext } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { projectCorsObservation } from '../projections/cors.js';

import {
  withPositiveAdminSession,
  type PositiveAdminSessionOptions,
} from './positive-admin-flow.js';
import { refreshPositiveAdminManagementToken } from './positive-admin-token.js';

const scenarioId = 'cors.management-list';
const defaultAllowedMethods = ['GET', 'HEAD', 'PUT', 'POST', 'DELETE', 'PATCH'] as const;

export type CorsManagementListDependencies = Readonly<{
  sessionOptions?: PositiveAdminSessionOptions;
  withPositiveAdminSession?: typeof withPositiveAdminSession;
  refreshPositiveAdminManagementToken?: typeof refreshPositiveAdminManagementToken;
}>;

const dataNormalizationContext = (context: Phase1ScenarioRunContext): NormalizationContext => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
  const symbols = allocation && context.protocol.symbolsFor(allocation.allocationId);

  if (!allocation || !symbols) {
    throw new Error('Phase 1 CORS fixture is invalid');
  }

  return { target: context.target, symbols };
};

const headerValues = (response: RawProtocolResponse, name: string): readonly string[] =>
  response.headers
    .filter(([candidate]) => candidate.toLowerCase() === name)
    .map(([, value]) => value);

const commaValues = (value: string): readonly string[] =>
  value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

// eslint-disable-next-line complexity -- The exact CORS matrix is one closed response contract.
const requirePreflight = (
  response: RawProtocolResponse,
  origin: string,
  allowedHeaders: readonly string[]
): void => {
  const allowOrigin = headerValues(response, 'access-control-allow-origin');
  const allowHeaders = headerValues(response, 'access-control-allow-headers');
  const allowMethods = headerValues(response, 'access-control-allow-methods');
  const vary = headerValues(response, 'vary');

  if (
    response.status !== 204 ||
    response.body.length > 0 ||
    headerValues(response, 'content-type').length > 0 ||
    !isDeepStrictEqual(allowOrigin, [origin]) ||
    allowHeaders.length !== 1 ||
    !isDeepStrictEqual(
      commaValues(allowHeaders[0] ?? '').map((value) => value.toLowerCase()),
      allowedHeaders.map((value) => value.toLowerCase())
    ) ||
    allowMethods.length !== 1 ||
    !isDeepStrictEqual(commaValues(allowMethods[0] ?? ''), defaultAllowedMethods) ||
    !vary.some((value) => commaValues(value).includes('Origin')) ||
    headerValues(response, 'access-control-allow-credentials').length > 0
  ) {
    throw new Error('Phase 1 CORS preflight is invalid');
  }
};

const isJsonArray = (value: unknown): value is JsonValue[] =>
  Array.isArray(value) && jsonValueGuard.safeParse(value).success;

const requireGet = (response: RawProtocolResponse, origin: string): JsonValue => {
  try {
    const body: unknown = JSON.parse(response.body);

    if (
      response.status !== 200 ||
      !isJsonArray(body) ||
      body.length > 0 ||
      !isDeepStrictEqual(headerValues(response, 'access-control-allow-origin'), [origin]) ||
      !isDeepStrictEqual(headerValues(response, 'access-control-expose-headers'), ['*']) ||
      !isDeepStrictEqual(headerValues(response, 'total-number'), ['1']) ||
      !headerValues(response, 'vary').some((value) => commaValues(value).includes('Origin')) ||
      headerValues(response, 'access-control-allow-credentials').length > 0
    ) {
      throw new TypeError('invalid response');
    }

    return body;
  } catch {
    throw new Error('Phase 1 CORS GET response is invalid');
  }
};

const assertNoMutationState = (
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>
): void => {
  if (
    !isDeepStrictEqual(state.persistedState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 CORS state is invalid');
  }
};

export const runCorsManagementList = async (
  context: Phase1ScenarioRunContext,
  dependencies: CorsManagementListDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const runSession = dependencies.withPositiveAdminSession ?? withPositiveAdminSession;
  const refreshManagement =
    dependencies.refreshPositiveAdminManagementToken ?? refreshPositiveAdminManagementToken;
  const { result } = await runSession(
    context,
    { ...dependencies.sessionOptions, captureAuthorize: false, captureCodeToken: false },
    async (session) => {
      await refreshManagement(context, session);
      const normalizationContext = dataNormalizationContext(context);
      const before = await context.projectFixtureState();
      const { origin, allowedRequestHeaders } = context.profile.cors;
      const { management } = context.protocol.forAllocation('data');
      const preflightHeaders = {
        origin,
        'access-control-request-method': 'GET',
        'access-control-request-headers': allowedRequestHeaders.join(', '),
      };
      const applicationPreflight = await management.requestManagement(
        'cors-applications-preflight',
        'applications',
        { method: 'OPTIONS', headers: preflightHeaders, authenticated: false }
      );
      const usersPreflight = await management.requestManagement('cors-users-preflight', 'users', {
        method: 'OPTIONS',
        headers: preflightHeaders,
        authenticated: false,
      });
      const applicationsGet = await management.requestManagement(
        'cors-applications-get',
        'applications?page=2&page_size=20&isThirdParty=false',
        { method: 'GET', headers: { origin, 'accept-language': 'en' } }
      );
      const usersGet = await management.requestManagement(
        'cors-users-get',
        'users?page=2&page_size=20',
        { method: 'GET', headers: { origin, 'accept-language': 'en' } }
      );
      requirePreflight(applicationPreflight, origin, allowedRequestHeaders);
      requirePreflight(usersPreflight, origin, allowedRequestHeaders);
      const rawSteps = [
        ['applications-preflight', applicationPreflight, null],
        ['users-preflight', usersPreflight, null],
        ['applications-get', applicationsGet, requireGet(applicationsGet, origin)],
        ['users-get', usersGet, requireGet(usersGet, origin)],
      ] as const;
      const steps = await Promise.all(
        rawSteps.map(async ([stepId, response, body]) => {
          const state = await context.projectScenarioState({
            scenarioId,
            stepId,
            fixture: context.fixture,
          });
          assertNoMutationState(state);

          return Object.freeze({
            stepId,
            value: projectCorsObservation(
              { ...state, status: response.status, headers: response.headers, body },
              normalizationContext
            ),
          });
        })
      );
      const after = await context.projectFixtureState();

      if (!isDeepStrictEqual(before, after)) {
        throw new Error('Phase 1 CORS reads mutated fixture state');
      }

      return Object.freeze(steps);
    }
  );

  return result;
};
