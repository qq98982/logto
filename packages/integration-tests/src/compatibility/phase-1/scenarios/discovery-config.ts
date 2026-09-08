import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import type { Phase1ScenarioRun } from '../model.js';
import { createPhase1NormalizationContext } from '../native-surface-profile.js';
import { projectDiscoveryObservation } from '../projections/discovery.js';

const jsonMediaTypes = new Set(['application/json', 'application/jwk-set+json']);
const publicJwkMembers = new Set(['alg', 'crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y']);

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

const requireJsonResponse = (
  response: RawProtocolResponse,
  operation: 'discovery' | 'jwks'
): JsonObject => {
  try {
    const mediaTypes = response.headers
      .filter(([name]) => name.toLowerCase() === 'content-type')
      .map(([, value]) => value.split(';', 1)[0]?.trim().toLowerCase());
    const body: unknown = JSON.parse(response.body);

    if (
      response.status !== 200 ||
      mediaTypes.length !== 1 ||
      !mediaTypes[0] ||
      !jsonMediaTypes.has(mediaTypes[0]) ||
      !isJsonObject(body)
    ) {
      throw new TypeError('invalid response');
    }

    return body;
  } catch {
    throw new Error(`Phase 1 ${operation} response is invalid`);
  }
};

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item: unknown) => typeof item === 'string');

const requireStringArray = (value: unknown, field: string): readonly string[] => {
  if (!isStringArray(value) || new Set(value).size !== value.length) {
    throw new Error(`Phase 1 discovery field is invalid: ${field}`);
  }

  return value;
};

const assertContainsSelection = (
  actual: unknown,
  expected: readonly string[],
  field: string
): void => {
  const values = requireStringArray(actual, field);

  for (const expectedValue of expected) {
    if (!values.includes(expectedValue)) {
      throw new Error(`Phase 1 discovery field is invalid: ${field}`);
    }
  }
};

const endpoint = (targetCoreUrl: string, path: string) => new URL(path, targetCoreUrl).href;

const assertProfileSelectedDiscovery = (
  document: JsonObject,
  context: Parameters<Phase1ScenarioRun>[0]
): void => {
  const { oidc } = context.profile;
  const exactFields: Readonly<Record<string, JsonValue>> = {
    issuer: endpoint(context.target.coreUrl, oidc.issuerPath),
    authorization_endpoint: endpoint(context.target.coreUrl, oidc.authorizationPath),
    token_endpoint: endpoint(context.target.coreUrl, oidc.tokenPath),
    userinfo_endpoint: endpoint(context.target.coreUrl, oidc.userinfoPath),
    jwks_uri: endpoint(context.target.coreUrl, oidc.jwksPath),
    claims_parameter_supported: oidc.claimsParameterSupported,
    authorization_response_iss_parameter_supported: oidc.authorizationResponseIssParameterSupported,
    request_uri_parameter_supported: oidc.requestUriParameterSupported,
  };

  for (const [field, expected] of Object.entries(exactFields)) {
    if (!isDeepStrictEqual(document[field], expected)) {
      throw new Error(`Phase 1 discovery field is invalid: ${field}`);
    }
  }

  const selectedArrays: ReadonlyArray<readonly [string, readonly string[]]> = [
    ['grant_types_supported', oidc.grants],
    ['response_types_supported', oidc.responseTypes],
    ['response_modes_supported', oidc.responseModes],
    ['code_challenge_methods_supported', oidc.pkceCodeChallengeMethods],
    ['token_endpoint_auth_methods_supported', oidc.tokenEndpointAuthMethods],
    ['scopes_supported', oidc.scopesSupported],
    ['claims_supported', oidc.claimsSupported],
    ['subject_types_supported', oidc.subjectTypesSupported],
    ['id_token_signing_alg_values_supported', oidc.idTokenSigningAlgorithmsSupported],
    ['claim_types_supported', oidc.claimTypesSupported],
  ];

  for (const [field, expected] of selectedArrays) {
    assertContainsSelection(document[field], expected, field);
  }
};

const assertAndSelectJwks = (
  document: JsonObject,
  context: Parameters<Phase1ScenarioRun>[0]
): JsonObject => {
  const { keys } = document;

  if (
    Object.keys(document).length !== 1 ||
    !Object.hasOwn(document, 'keys') ||
    !Array.isArray(keys) ||
    keys.length === 0
  ) {
    throw new Error('Phase 1 JWKS metadata is invalid');
  }

  const expected = context.profile.oidc.jwksKeyMetadata;
  const selectedKeys = keys.map((key): JsonObject => {
    if (
      !isJsonObject(key) ||
      Object.keys(key).some((member) => !publicJwkMembers.has(member)) ||
      key.kty !== expected.kty ||
      key.use !== expected.use ||
      key.alg !== expected.alg ||
      key.crv !== expected.crv ||
      typeof key.kid !== 'string' ||
      key.kid.length === 0
    ) {
      throw new Error('Phase 1 JWKS metadata is invalid');
    }

    return key;
  });

  return { keys: selectedKeys };
};

const rawObservation = (
  response: RawProtocolResponse,
  body: JsonObject,
  fixtureState: unknown
) => ({
  status: response.status,
  headers: response.headers,
  body,
  semanticState: fixtureState,
  persistedState: fixtureState,
  sideEffects: { fixtureMutation: false },
});

export const runDiscoveryConfig: Phase1ScenarioRun = async (context) => {
  const before = await context.projectFixtureState();
  const openidResponse = await context.protocol.publicOidc.request(
    'discovery-openid',
    context.profile.oidc.discoveryPath.slice(1),
    { includeCookies: false }
  );
  const openid = requireJsonResponse(openidResponse, 'discovery');
  assertProfileSelectedDiscovery(openid, context);

  const oauthResponse = await context.protocol.publicOidc.request(
    'discovery-oauth-authorization-server',
    context.profile.oidc.oauthAuthorizationServerDiscoveryPath.slice(1),
    { includeCookies: false }
  );
  const oauth = requireJsonResponse(oauthResponse, 'discovery');
  assertProfileSelectedDiscovery(oauth, context);

  if (!isDeepStrictEqual(openid, oauth)) {
    throw new Error('Phase 1 discovery endpoints are not equivalent');
  }

  const jwksResponse = await context.protocol.publicOidc.request(
    'discovery-jwks',
    context.profile.oidc.jwksPath.slice(1),
    { includeCookies: false }
  );
  const jwks = assertAndSelectJwks(requireJsonResponse(jwksResponse, 'jwks'), context);
  const after = await context.projectFixtureState();

  if (!isDeepStrictEqual(before, after)) {
    throw new Error('Phase 1 discovery mutated fixture state');
  }

  const normalizationContext = createPhase1NormalizationContext(
    context.profile,
    context.target,
    context.protocol.publicSymbols
  );

  return Object.freeze([
    Object.freeze({
      stepId: 'oidc-discovery',
      value: projectDiscoveryObservation(
        rawObservation(openidResponse, openid, after),
        normalizationContext
      ),
    }),
    Object.freeze({
      stepId: 'oauth-discovery',
      value: projectDiscoveryObservation(
        rawObservation(oauthResponse, oauth, after),
        normalizationContext
      ),
    }),
    Object.freeze({
      stepId: 'jwks',
      value: projectDiscoveryObservation(
        rawObservation(jwksResponse, jwks, after),
        normalizationContext
      ),
    }),
  ]);
};
