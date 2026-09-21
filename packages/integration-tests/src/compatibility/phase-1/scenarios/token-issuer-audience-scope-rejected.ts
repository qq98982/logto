/* eslint-disable max-lines, max-params -- The three authority variants, two protected surfaces, closed aggregate projections, and credential boundary stay together for auditability. */
import { isDeepStrictEqual } from 'node:util';

import { decodeJwt } from 'jose';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue, NormalizationContext } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { normalizeLogicalFixtureIds, normalizeOAuthError } from '../normalizers.js';
import {
  projectHttpObservation,
  requireProjectionJson,
  projectSemanticStateObservation,
  projectTokenErrorObservation,
  type Phase1HttpProjection,
} from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import { withPositiveAdminSession, type PositiveAdminSession } from './positive-admin-flow.js';
import {
  positiveAdminNormalizationContext,
  refreshPositiveAdminAccountResourceToken,
  refreshPositiveAdminManagementTokenWithoutAllScope,
  refreshPositiveAdminUserInfoTokenWithoutOpenId,
} from './positive-admin-token.js';
import {
  exchangePositiveAuthorizationCode,
  withPositiveOidcFlow,
  type PositiveOidcFlowOptions,
} from './positive-oidc-flow.js';
import {
  assertPositiveOidcTokenGrantIncludesScope,
  installPositiveOidcAccessToken,
  revokePositiveTokenGrant,
  verifyPositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'token.issuer-audience-scope-rejected';
const variants = ['wrong-issuer', 'wrong-audience', 'missing-scope'] as const;
type Variant = (typeof variants)[number];

type RejectedPair = Readonly<{
  management: RawProtocolResponse;
  managementToken: string;
  userinfo: RawProtocolResponse;
}>;

type ExpectedRejection = Readonly<{
  status: 401 | 403;
  body: JsonObject;
  challenge?: Readonly<{
    error: 'invalid_token' | 'insufficient_scope';
    description: string;
    scope?: 'openid';
  }>;
}>;

const authorityContracts = Object.freeze({
  'wrong-issuer': Object.freeze({
    vector: Object.freeze({
      management: 'foreign-signing-authority-before-issuer-audience-scope',
      userinfo: 'foreign-tenant-token-lookup',
    }),
    management: Object.freeze({
      status: 401,
      body: Object.freeze({
        code: 'auth.unauthorized',
        data: Object.freeze({
          code: 'ERR_JWKS_NO_MATCHING_KEY',
          name: 'JWKSNoMatchingKey',
        }),
        message: 'Unauthorized. Please check credentials and its scope.',
      }),
    }),
    userinfo: Object.freeze({
      status: 401,
      body: Object.freeze({
        code: 'oidc.invalid_token',
        message: 'Invalid token provided.',
        error: 'invalid_token',
        error_description: 'invalid token provided',
      }),
      challenge: Object.freeze({
        error: 'invalid_token',
        description: 'invalid token provided',
      }),
    }),
  }),
  'wrong-audience': Object.freeze({
    vector: Object.freeze({
      management: 'audience-before-scope',
      userinfo: 'structured-resource-token-lookup-before-scope-audience',
    }),
    management: Object.freeze({
      status: 401,
      body: Object.freeze({
        code: 'auth.unauthorized',
        message: 'Unauthorized. Please check credentials and its scope.',
      }),
    }),
    userinfo: Object.freeze({
      status: 401,
      body: Object.freeze({
        code: 'oidc.invalid_token',
        message: 'Invalid token provided.',
        error: 'invalid_token',
        error_description: 'invalid token provided',
      }),
      challenge: Object.freeze({
        error: 'invalid_token',
        description: 'invalid token provided',
      }),
    }),
  }),
  'missing-scope': Object.freeze({
    vector: Object.freeze({
      management: 'missing-all',
      userinfo: 'missing-openid',
    }),
    management: Object.freeze({
      status: 403,
      body: Object.freeze({
        code: 'auth.forbidden',
        message: 'Forbidden. Please check your user roles and permissions.',
      }),
    }),
    userinfo: Object.freeze({
      status: 403,
      body: Object.freeze({
        code: 'oidc.insufficient_scope',
        message: 'Token missing scope `{{scope}}`.',
        error: 'insufficient_scope',
        error_description: 'access token missing openid scope',
        scope: 'openid',
      }),
      challenge: Object.freeze({
        error: 'insufficient_scope',
        description: 'access token missing openid scope',
        scope: 'openid',
      }),
    }),
  }),
} as const satisfies Readonly<
  Record<
    Variant,
    Readonly<{
      vector: JsonObject;
      management: ExpectedRejection;
      userinfo: ExpectedRejection;
    }>
  >
>);

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

const parseJson = (response: RawProtocolResponse, diagnostic: string): JsonObject => {
  try {
    const body: unknown = JSON.parse(response.body);

    if (!isJsonObject(body)) {
      throw new TypeError('invalid body');
    }

    return body;
  } catch {
    throw new Error(diagnostic);
  }
};

const headerValues = (response: RawProtocolResponse, name: string): readonly string[] =>
  response.headers
    .filter(([candidate]) => candidate.toLowerCase() === name)
    .map(([, value]) => value);

const expectedManagementRejection = (
  variant: Variant,
  presentedToken: string
): ExpectedRejection => {
  const expected = authorityContracts[variant].management;

  if (variant !== 'wrong-audience') {
    return expected;
  }
  const payload: unknown = decodeJwt(presentedToken);

  if (!isJsonObject(payload)) {
    throw new Error('Phase 1 management authority rejection is invalid');
  }

  return Object.freeze({
    ...expected,
    body: Object.freeze({
      ...expected.body,
      data: Object.freeze({
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        name: 'JWTClaimValidationFailed',
        claim: 'aud',
        reason: 'check_failed',
        payload,
      }),
    }),
  });
};

const canonicalManagementBody = (variant: Variant, body: JsonObject): JsonObject => {
  const normalized = normalizeOAuthError(body);

  if (variant !== 'wrong-audience') {
    return normalized;
  }
  const { data } = normalized;

  if (!isJsonObject(data) || !isJsonObject(data.payload)) {
    throw new Error('Phase 1 management authority rejection is invalid');
  }

  return {
    ...normalized,
    data: {
      ...Object.fromEntries(Object.entries(data).filter(([key]) => key !== 'payload')),
      payloadMatchesPresentedClaims: true,
    },
  };
};

const requireRejectedResponse = (
  response: RawProtocolResponse,
  surface: 'management' | 'userinfo',
  expected: ExpectedRejection,
  expectedChallengeIssuer?: string
): JsonObject => {
  const diagnostic = `Phase 1 ${surface} authority rejection is invalid`;
  const mediaTypes = headerValues(response, 'content-type').map((value) =>
    value.split(';', 1)[0]?.trim().toLowerCase()
  );
  const body = parseJson(response, diagnostic);
  const challenges = headerValues(response, 'www-authenticate');
  const expectedChallenge = (() => {
    if (!expected.challenge) {
      return;
    }
    if (!expectedChallengeIssuer) {
      throw new Error(diagnostic);
    }

    return `Bearer realm="${expectedChallengeIssuer}", error="${expected.challenge.error}", error_description="${expected.challenge.description}"${expected.challenge.scope ? `, scope="${expected.challenge.scope}"` : ''}`;
  })();

  if (
    response.status !== expected.status ||
    mediaTypes.length !== 1 ||
    mediaTypes[0] !== 'application/json' ||
    headerValues(response, 'location').length > 0 ||
    headerValues(response, 'set-cookie').length > 0 ||
    !isDeepStrictEqual(body, expected.body) ||
    (expectedChallenge === undefined
      ? challenges.length > 0
      : !isDeepStrictEqual(challenges, [expectedChallenge]))
  ) {
    throw new Error(diagnostic);
  }

  return body;
};

const assertNoMutationState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.persistedState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 authority rejection state is invalid');
  }
};

const compactHttp = (projection: Phase1HttpProjection): JsonValue =>
  requireProjectionJson(
    {
      status: projection.status,
      mediaType: projection.mediaType,
      error: projection.error,
      headers: projection.headers,
      body: projection.body,
      redirect: projection.redirect,
      cookies: projection.cookies,
      urls: projection.urls,
    },
    'Invalid phase 1 authority rejection projection'
  );

const projectPair = async (
  context: Phase1ScenarioRunContext,
  variant: Variant,
  pair: RejectedPair,
  normalizationContext: NormalizationContext
): Promise<Phase1ScenarioStepResult> => {
  const contract = authorityContracts[variant];
  const { issuerPath } = context.profile.oidc;

  if (!issuerPath.startsWith('/') || issuerPath.slice(1).startsWith('/')) {
    throw new Error('Phase 1 issuer path is invalid');
  }
  const userinfoIssuer = (() => {
    try {
      const issuer = new URL(issuerPath, context.target.adminUrl);

      if (
        issuer.origin !== new URL(context.target.adminUrl).origin ||
        issuer.username.length > 0 ||
        issuer.password.length > 0 ||
        issuer.search.length > 0 ||
        issuer.hash.length > 0
      ) {
        throw new TypeError('invalid issuer path');
      }

      return issuer.href.replace(/\/$/u, '');
    } catch {
      throw new Error('Phase 1 issuer path is invalid');
    }
  })();
  const managementBody = requireRejectedResponse(
    pair.management,
    'management',
    expectedManagementRejection(variant, pair.managementToken)
  );
  const userinfoBody = requireRejectedResponse(
    pair.userinfo,
    'userinfo',
    contract.userinfo,
    userinfoIssuer
  );
  const state = await context.projectScenarioState({
    scenarioId,
    stepId: variant,
    fixture: context.fixture,
  });
  assertNoMutationState(state);
  const management = projectHttpObservation(
    {
      ...state,
      status: pair.management.status,
      headers: pair.management.headers,
      body: normalizeLogicalFixtureIds(
        canonicalManagementBody(variant, managementBody),
        normalizationContext
      ),
    },
    normalizationContext
  );
  const userinfo = projectTokenErrorObservation(
    { ...state, status: pair.userinfo.status, headers: pair.userinfo.headers, body: userinfoBody },
    normalizationContext
  );
  const value = projectHttpObservation(
    {
      ...state,
      status: 200,
      headers: [],
      body: {
        authorityVector: contract.vector,
        management: compactHttp(management),
        userinfo: compactHttp(userinfo),
      },
    },
    normalizationContext
  );

  context.protocol.forAllocation('admin').oidc.store.assertNoCredentialMaterial(value);
  context.protocol.forAllocation('data').oidc.store.assertNoCredentialMaterial(value);

  return Object.freeze({ stepId: variant, value });
};

const managementPath = 'api/applications?page=2&page_size=1&isThirdParty=false';

const requestPair = async (
  context: Phase1ScenarioRunContext,
  variant: Variant,
  managementToken: string,
  userinfoToken: string,
  managementRole: 'admin' | 'data',
  userinfoRole: 'admin' | 'data'
): Promise<RejectedPair> => {
  const managementClient = context.protocol.forAllocation(managementRole).oidc;
  const userinfo = context.protocol.forAllocation(userinfoRole).oidc;
  const { userinfoPath } = context.profile.oidc;

  if (!userinfoPath.startsWith('/') || userinfoPath.slice(1).startsWith('/')) {
    throw new Error('Phase 1 UserInfo path is invalid');
  }
  managementClient.store.registerSecret(managementToken);
  userinfo.store.registerSecret(userinfoToken);
  const [management, userinfoResponse] = await Promise.all([
    managementClient.request(`authority-${variant}-management`, managementPath, {
      headers: { authorization: `Bearer ${managementToken}` },
      includeCookies: false,
    }),
    userinfo.request(`authority-${variant}-userinfo`, userinfoPath.slice(1), {
      headers: { authorization: `Bearer ${userinfoToken}` },
      includeCookies: false,
    }),
  ]);

  return Object.freeze({ management, managementToken, userinfo: userinfoResponse });
};

export type TokenIssuerAudienceScopeRejectedDependencies = Readonly<{
  withPositiveAdminSession?: typeof withPositiveAdminSession;
  refreshPositiveAdminAccountResourceToken?: typeof refreshPositiveAdminAccountResourceToken;
  refreshPositiveAdminManagementTokenWithoutAllScope?: typeof refreshPositiveAdminManagementTokenWithoutAllScope;
  refreshPositiveAdminUserInfoTokenWithoutOpenId?: typeof refreshPositiveAdminUserInfoTokenWithoutOpenId;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
  oidcFlowOptions?: PositiveOidcFlowOptions;
  exchangePositiveAuthorizationCode?: typeof exchangePositiveAuthorizationCode;
  installPositiveOidcAccessToken?: typeof installPositiveOidcAccessToken;
  verifyPositiveTokenGrant?: typeof verifyPositiveTokenGrant;
  assertPositiveOidcTokenGrantIncludesScope?: typeof assertPositiveOidcTokenGrantIncludesScope;
  revokePositiveTokenGrant?: typeof revokePositiveTokenGrant;
}>;

export const runTokenIssuerAudienceScopeRejected = async (
  context: Phase1ScenarioRunContext,
  dependencies: TokenIssuerAudienceScopeRejectedDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const runAdminSession = dependencies.withPositiveAdminSession ?? withPositiveAdminSession;
  const refreshAccountAuthority =
    dependencies.refreshPositiveAdminAccountResourceToken ??
    refreshPositiveAdminAccountResourceToken;
  const refreshMissingScope =
    dependencies.refreshPositiveAdminManagementTokenWithoutAllScope ??
    refreshPositiveAdminManagementTokenWithoutAllScope;
  const refreshUserInfoMissingScope =
    dependencies.refreshPositiveAdminUserInfoTokenWithoutOpenId ??
    refreshPositiveAdminUserInfoTokenWithoutOpenId;
  const runOidcFlow = dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow;
  const exchangeDataCode =
    dependencies.exchangePositiveAuthorizationCode ?? exchangePositiveAuthorizationCode;
  const installDataAccess =
    dependencies.installPositiveOidcAccessToken ?? installPositiveOidcAccessToken;
  const verifyDataGrant = dependencies.verifyPositiveTokenGrant ?? verifyPositiveTokenGrant;
  const assertGrantScope =
    dependencies.assertPositiveOidcTokenGrantIncludesScope ??
    assertPositiveOidcTokenGrantIncludesScope;
  const revokeDataGrant = dependencies.revokePositiveTokenGrant ?? revokePositiveTokenGrant;
  const { result } = await runAdminSession<readonly Phase1ScenarioStepResult[]>(
    context,
    { captureAuthorize: false, captureCodeToken: false },
    async (session: PositiveAdminSession) => {
      await refreshAccountAuthority(context, session);
      await refreshMissingScope(context, session);
      await refreshUserInfoMissingScope(context, session);
      const missingScopeToken = context.protocol
        .forAllocation('data')
        .oidc.store.getToken('management-missing-scope');
      const wrongAudienceToken = context.protocol
        .forAllocation('admin')
        .oidc.store.getToken('authority-wrong-audience');
      const userInfoMissingScopeToken = context.protocol
        .forAllocation('admin')
        .oidc.store.getToken('userinfo-missing-openid');

      if (!missingScopeToken || !wrongAudienceToken || !userInfoMissingScopeToken) {
        throw new Error('Phase 1 authority token is unavailable');
      }
      const { result: authorityResult } = await runOidcFlow(
        context,
        {
          ...dependencies.oidcFlowOptions,
          captureSteps: false,
          includeResource: true,
          expectOidcConsentAlreadyGranted: false,
        },
        async (authorizationGrant) => {
          const dataGrant = await exchangeDataCode(context, authorizationGrant);
          try {
            await verifyDataGrant(context, dataGrant, true);
            installDataAccess(context, dataGrant, 'authority-wrong-issuer-management');
            const wrongIssuerManagementToken = context.protocol
              .forAllocation('data')
              .oidc.store.getToken('authority-wrong-issuer-management');

            if (!wrongIssuerManagementToken) {
              throw new Error('Phase 1 wrong-issuer token is unavailable');
            }
            const { result: unresourcedResult } = await runOidcFlow(
              context,
              {
                ...dependencies.oidcFlowOptions,
                captureSteps: false,
                includeResource: false,
                expectOidcConsentAlreadyGranted: true,
              },
              async (unresourcedAuthorizationGrant) => {
                const unresourcedGrant = await exchangeDataCode(
                  context,
                  unresourcedAuthorizationGrant
                );
                try {
                  await verifyDataGrant(context, unresourcedGrant, false);
                  assertGrantScope(unresourcedGrant, 'openid');
                  installDataAccess(context, unresourcedGrant, 'authority-wrong-issuer-userinfo');
                  const wrongIssuerUserInfoToken = context.protocol
                    .forAllocation('data')
                    .oidc.store.getToken('authority-wrong-issuer-userinfo');

                  if (!wrongIssuerUserInfoToken) {
                    throw new Error('Phase 1 wrong-issuer UserInfo token is unavailable');
                  }
                  const normalizationContext = positiveAdminNormalizationContext(context);
                  const before = await context.projectFixtureState();
                  const pairs = [
                    await requestPair(
                      context,
                      'wrong-issuer',
                      wrongIssuerManagementToken,
                      wrongIssuerUserInfoToken,
                      'admin',
                      'admin'
                    ),
                    await requestPair(
                      context,
                      'wrong-audience',
                      wrongAudienceToken,
                      wrongAudienceToken,
                      'data',
                      'admin'
                    ),
                    await requestPair(
                      context,
                      'missing-scope',
                      missingScopeToken,
                      userInfoMissingScopeToken,
                      'data',
                      'admin'
                    ),
                  ] as const;
                  const steps = await Promise.all(
                    variants.map(async (variant, index) => {
                      const pair = pairs[index];

                      if (!pair) {
                        throw new Error('Phase 1 authority rejection pair is unavailable');
                      }

                      return projectPair(context, variant, pair, normalizationContext);
                    })
                  );
                  const finalState = await context.projectScenarioState({
                    scenarioId,
                    stepId: 'state',
                    fixture: context.fixture,
                  });
                  assertNoMutationState(finalState);
                  const state = projectSemanticStateObservation(
                    { ...finalState, status: 200, headers: [] },
                    normalizationContext,
                    { scenarioId, stepId: 'state' }
                  );
                  const after = await context.projectFixtureState();

                  if (!isDeepStrictEqual(before, after)) {
                    throw new Error('Phase 1 authority rejection mutated fixture state');
                  }
                  const output = Object.freeze([
                    ...steps,
                    Object.freeze({ stepId: 'state', value: state }),
                  ]);
                  context.protocol
                    .forAllocation('admin')
                    .oidc.store.assertNoCredentialMaterial(output);
                  context.protocol
                    .forAllocation('data')
                    .oidc.store.assertNoCredentialMaterial(output);

                  return output;
                } finally {
                  revokeDataGrant(unresourcedGrant);
                }
              }
            );

            return unresourcedResult;
          } finally {
            revokeDataGrant(dataGrant);
          }
        }
      );

      return authorityResult;
    }
  );

  return result;
};

/* eslint-enable max-lines, max-params */
