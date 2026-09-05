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
const linkCredentialKeyPattern =
  /(?:^|[_-])(?:code|state|token|credential|session|interaction|resume|verification|nonce)(?:$|[_-])/iu;
const linkCredentialFragmentPattern =
  /(?:^|[?&#])(?:code|state|token|credential|session|interaction|resume|verification|nonce)=/iu;

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

const canonicalHttpOrigin = (value: unknown, diagnostic: string): string => {
  try {
    if (typeof value !== 'string') {
      throw new TypeError('invalid origin');
    }
    const url = new URL(value);

    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      url.origin !== value
    ) {
      throw new TypeError('invalid origin');
    }

    return url.origin;
  } catch {
    throw new Error(diagnostic);
  }
};

const validateLinkHeader = (value: string, runtimeTargetOrigin: string): string => {
  const targets = [...value.matchAll(/<([^>]*)>/gu)];

  if (targets.length === 0) {
    throw new Error('Phase 1 CORS Link header is invalid');
  }

  for (const [, target] of targets) {
    if (!target) {
      throw new Error('Phase 1 CORS Link header is invalid');
    }
    const url = (() => {
      try {
        return new URL(target);
      } catch {
        throw new Error('Phase 1 CORS Link header is invalid');
      }
    })();

    if (
      url.origin !== runtimeTargetOrigin ||
      !['http:', 'https:'].includes(url.protocol) ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      Array.from(url.searchParams.keys()).some((key) => linkCredentialKeyPattern.test(key)) ||
      linkCredentialFragmentPattern.test(url.hash) ||
      !target.startsWith(`${runtimeTargetOrigin}/`)
    ) {
      throw new Error('Phase 1 CORS Link header is invalid');
    }
  }

  return value;
};

const validateCorsHeaders = (
  headers: RawProtocolResponse['headers'],
  runtimeTargetOrigin: string
): RawProtocolResponse['headers'] =>
  Object.freeze(
    headers.map(([name, value]) => {
      const normalizedName = name.toLowerCase();
      const canonicalValue =
        normalizedName === 'link' ? validateLinkHeader(value, runtimeTargetOrigin) : value;

      return Object.freeze([name, canonicalValue] as const);
    })
  );

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

const requireRejectedLocalhostPreflight = (response: RawProtocolResponse): void => {
  const accessControlHeaders = response.headers.filter(([name]) =>
    name.toLowerCase().startsWith('access-control-')
  );

  if (
    response.status !== 200 ||
    response.body.length > 0 ||
    accessControlHeaders.length > 0 ||
    !headerValues(response, 'vary').some((value) => commaValues(value).includes('Origin')) ||
    headerValues(response, 'set-cookie').length > 0
  ) {
    throw new Error('Phase 1 CORS rejected Origin response is invalid');
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
  const {
    origin,
    target,
    allowOriginResponse: rawAllowOriginResponse,
    allowedRequestHeaders,
  } = context.profile.cors;
  const logicalOrigin = canonicalHttpOrigin(origin, 'Phase 1 CORS profile origin is invalid');
  const logicalTargetOrigin = canonicalHttpOrigin(target, 'Phase 1 CORS profile target is invalid');
  const allowOriginResponse = canonicalHttpOrigin(
    rawAllowOriginResponse,
    'Phase 1 CORS profile origin is invalid'
  );

  if (logicalOrigin !== allowOriginResponse) {
    throw new Error('Phase 1 CORS profile origin is invalid');
  }
  if (logicalOrigin === logicalTargetOrigin) {
    throw new Error('Phase 1 CORS profile target is invalid');
  }
  const runtimeOrigin = new URL(context.target.adminUrl).origin;
  const runtimeTargetOrigin = new URL(context.target.coreUrl).origin;
  const foreignRuntimeOrigin = context.fixture.foreignTarget
    ? new URL(context.fixture.foreignTarget.adminUrl).origin
    : undefined;

  if (!foreignRuntimeOrigin || runtimeOrigin === runtimeTargetOrigin) {
    throw new Error('Phase 1 CORS runtime target is invalid');
  }
  const { result } = await runSession(
    context,
    { ...dependencies.sessionOptions, captureAuthorize: false, captureCodeToken: false },
    async (session) => {
      await refreshManagement(context, session);
      const normalizationContext = dataNormalizationContext(context);
      const before = await context.projectFixtureState();
      const { management } = context.protocol.forAllocation('data');
      const { management: foreignManagement } = context.protocol.forAllocation('foreign');
      const preflightHeaders = {
        origin: runtimeOrigin,
        'access-control-request-method': 'GET',
        'access-control-request-headers': allowedRequestHeaders.join(', '),
      };
      // This branch-specific rejection is a fail-closed conformance control. The authorized
      // differential contract continues to publish only the four primary CORS observations.
      const rejectedLocalhostPreflight = await foreignManagement.requestManagement(
        'cors-foreign-localhost-preflight-rejected',
        'applications',
        {
          method: 'OPTIONS',
          headers: { ...preflightHeaders, origin: foreignRuntimeOrigin },
          authenticated: false,
        }
      );
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
        { method: 'GET', headers: { origin: runtimeOrigin, 'accept-language': 'en' } }
      );
      const usersGet = await management.requestManagement(
        'cors-users-get',
        'users?page=2&page_size=20',
        { method: 'GET', headers: { origin: runtimeOrigin, 'accept-language': 'en' } }
      );
      requireRejectedLocalhostPreflight(rejectedLocalhostPreflight);
      requirePreflight(applicationPreflight, runtimeOrigin, allowedRequestHeaders);
      requirePreflight(usersPreflight, runtimeOrigin, allowedRequestHeaders);
      const rawSteps = [
        ['applications-preflight', applicationPreflight, null],
        ['users-preflight', usersPreflight, null],
        ['applications-get', applicationsGet, requireGet(applicationsGet, runtimeOrigin)],
        ['users-get', usersGet, requireGet(usersGet, runtimeOrigin)],
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
              {
                ...state,
                status: response.status,
                headers: validateCorsHeaders(response.headers, runtimeTargetOrigin),
                body,
              },
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
