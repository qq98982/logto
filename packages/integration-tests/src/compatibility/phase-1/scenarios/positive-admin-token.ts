/* eslint-disable complexity, max-lines, max-params, no-restricted-syntax -- Admin refresh forms, JWT proof validation, rotation, token installation, and semantic projection are one credential boundary. */
import { decodeJwt, decodeProtectedHeader, type JSONWebKeySet, type JWTPayload } from 'jose';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, NormalizationContext } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import { verifyObservedJwt, type VerifiedJwtObservation } from '../evidence.js';
import { getPhase1FixtureRuntimeId } from '../fixture-map.js';
import type { Phase1DifferentialScenarioId, Phase1ScenarioRunContext } from '../model.js';
import { phase1ImplementationForProfile } from '../native-surface-profile.js';
import { hasValidOptionalProfileTimestamps } from '../profile-timestamps.js';
import {
  projectOrganizationTokenObservation,
  projectTokenObservation,
  type Phase1HttpProjection,
} from '../projections/index.js';

import {
  assertPositiveAdminRefreshTokenIsFresh,
  containsPrivateAdminJwkMaterial,
  createPositiveAdminNormalizationContext,
  readPositiveAdminSession,
  replacePositiveAdminRefreshToken,
  type PositiveAdminSession,
} from './positive-admin-flow.js';

const formContentType = 'application/x-www-form-urlencoded';
const jsonContentType = 'application/json';

export type PositiveAdminProjectionCoordinates = Readonly<{
  scenarioId: Phase1DifferentialScenarioId;
  stepId: string;
}>;

type AdminRefreshGrant = Readonly<{
  response: RawProtocolResponse;
  body: JsonObject;
  accessToken: string;
  idToken: string;
  refreshToken: string;
}>;

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

const headerValues = (
  headers: ReadonlyArray<readonly [string, string]>,
  name: string
): readonly string[] =>
  headers.filter(([candidate]) => candidate.toLowerCase() === name).map(([, value]) => value);

const requireText = (value: unknown, diagnostic: string): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;

      return codePoint <= 31 || codePoint === 127;
    })
  ) {
    throw new Error(diagnostic);
  }

  return value;
};

const requireRefreshResponse = (
  response: RawProtocolResponse,
  expectedScope: string,
  diagnostic: string
): AdminRefreshGrant => {
  try {
    const mediaTypes = headerValues(response.headers, 'content-type').map(
      (value) => value.split(';', 1)[0]?.trim().toLowerCase() ?? ''
    );
    const body: unknown = JSON.parse(response.body);

    if (
      response.status !== 200 ||
      mediaTypes.length !== 1 ||
      mediaTypes[0] !== jsonContentType ||
      !isJsonObject(body) ||
      body.token_type !== 'Bearer' ||
      body.scope !== expectedScope ||
      typeof body.expires_in !== 'number' ||
      !Number.isSafeInteger(body.expires_in) ||
      body.expires_in <= 0
    ) {
      throw new TypeError('invalid refresh response');
    }

    return Object.freeze({
      response,
      body,
      accessToken: requireText(body.access_token, diagnostic),
      idToken: requireText(body.id_token, diagnostic),
      refreshToken: requireText(body.refresh_token, diagnostic),
    });
  } catch {
    throw new Error(diagnostic);
  }
};

const adminAllocation = (context: Phase1ScenarioRunContext) => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'admin');

  if (!allocation) {
    throw new Error('Phase 1 admin allocation is unavailable');
  }

  return allocation;
};

const issuerFor = (context: Phase1ScenarioRunContext): string =>
  new URL('/oidc', context.target.adminUrl).href.replace(/\/$/u, '');

const audienceEquals = (audience: JWTPayload['aud'], expected: string): boolean =>
  audience === expected ||
  (Array.isArray(audience) && audience.length === 1 && audience[0] === expected);

const assertTimes = (claims: JWTPayload): void => {
  const now = Math.floor(Date.now() / 1000);

  if (
    typeof claims.iat !== 'number' ||
    !Number.isSafeInteger(claims.iat) ||
    typeof claims.exp !== 'number' ||
    !Number.isSafeInteger(claims.exp) ||
    claims.exp <= claims.iat ||
    claims.iat > now + 30 ||
    claims.exp < now - 30 ||
    (claims.nbf !== undefined &&
      (typeof claims.nbf !== 'number' ||
        !Number.isSafeInteger(claims.nbf) ||
        claims.nbf > now + 30))
  ) {
    throw new TypeError('invalid token lifetime');
  }
};

const jwksPath = (context: Phase1ScenarioRunContext): string => {
  const path = context.profile.oidc.jwksPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 admin JWKS path is invalid');
  }

  return path.slice(1);
};

const requireJwks = async (context: Phase1ScenarioRunContext): Promise<JSONWebKeySet> => {
  const response = await context.protocol
    .forAllocation('admin')
    .oidc.request('admin-token-jwks', jwksPath(context), { includeCookies: false });
  try {
    const mediaTypes = headerValues(response.headers, 'content-type').map(
      (value) => value.split(';', 1)[0]?.trim().toLowerCase() ?? ''
    );
    const body: unknown = JSON.parse(response.body);

    if (
      response.status !== 200 ||
      mediaTypes.length !== 1 ||
      !['application/json', 'application/jwk-set+json'].includes(mediaTypes[0] ?? '') ||
      !isJsonObject(body) ||
      !Array.isArray(body.keys) ||
      body.keys.length === 0 ||
      body.keys.some(
        (key) =>
          !isJsonObject(key) || typeof key.kty !== 'string' || containsPrivateAdminJwkMaterial(key)
      )
    ) {
      throw new TypeError('invalid JWKS response');
    }

    return { keys: body.keys as JSONWebKeySet['keys'] };
  } catch {
    throw new Error('Phase 1 admin JWKS read failed');
  }
};

const assertJwtPair = async (
  context: Phase1ScenarioRunContext,
  grant: AdminRefreshGrant,
  input: Readonly<{
    audience: string;
    scope: string;
    forbidOrganizationId: boolean;
    diagnostic: string;
  }>
): Promise<readonly VerifiedJwtObservation[]> => {
  try {
    const [algorithm] = context.profile.oidc.idTokenSigningAlgorithmsSupported;
    const accessHeader = decodeProtectedHeader(grant.accessToken);
    const idHeader = decodeProtectedHeader(grant.idToken);
    const accessClaims = decodeJwt(grant.accessToken);
    const idClaims = decodeJwt(grant.idToken);
    const allocation = adminAllocation(context);
    const expectedSubject = getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'user',
      context.profile.fixtures.adminTenant.operator.id
    );
    const clientId = context.profile.consoleAuthentication.applicationId;
    const issuer = issuerFor(context);

    if (
      context.profile.oidc.idTokenSigningAlgorithmsSupported.length !== 1 ||
      accessHeader.alg !== algorithm ||
      idHeader.alg !== algorithm ||
      containsPrivateAdminJwkMaterial(accessHeader) ||
      containsPrivateAdminJwkMaterial(idHeader) ||
      containsPrivateAdminJwkMaterial(accessClaims) ||
      containsPrivateAdminJwkMaterial(idClaims) ||
      accessClaims.iss !== issuer ||
      idClaims.iss !== issuer ||
      accessClaims.sub !== expectedSubject ||
      idClaims.sub !== expectedSubject ||
      !audienceEquals(accessClaims.aud, input.audience) ||
      !audienceEquals(idClaims.aud, clientId) ||
      accessClaims.client_id !== clientId ||
      accessClaims.scope !== input.scope ||
      (input.forbidOrganizationId && Object.hasOwn(accessClaims, 'organization_id'))
    ) {
      throw new TypeError('invalid admin token claims');
    }
    assertTimes(accessClaims);
    assertTimes(idClaims);
    if (
      !hasValidOptionalProfileTimestamps(idClaims, phase1ImplementationForProfile(context.profile))
    ) {
      throw new TypeError('invalid ID Token profile timestamps');
    }
    const jwks = await requireJwks(context);

    return await Promise.all([
      verifyObservedJwt(grant.accessToken, jwks),
      verifyObservedJwt(grant.idToken, jwks),
    ]);
  } catch {
    throw new Error(input.diagnostic);
  }
};

const tokenPath = (context: Phase1ScenarioRunContext): string => {
  const path = context.profile.oidc.tokenPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 admin token path is invalid');
  }

  return path.slice(1);
};

const postRefresh = async (
  context: Phase1ScenarioRunContext,
  operation: string,
  session: PositiveAdminSession,
  additionalForm: Readonly<Record<string, string>>,
  expectedScope: string,
  diagnostic: string
): Promise<AdminRefreshGrant> => {
  const current = readPositiveAdminSession(session);
  const { store } = context.protocol.forAllocation('admin').oidc;
  const response = await context.protocol
    .forAllocation('admin')
    .oidc.request(operation, tokenPath(context), {
      method: 'POST',
      headers: { 'content-type': formContentType },
      body: new URLSearchParams({
        client_id: current.clientId,
        refresh_token: current.refreshToken,
        grant_type: 'refresh_token',
        ...additionalForm,
      }).toString(),
      includeCookies: false,
    });
  const grant = requireRefreshResponse(response, expectedScope, diagnostic);

  assertPositiveAdminRefreshTokenIsFresh(session, grant.refreshToken, [
    grant.accessToken,
    grant.idToken,
  ]);
  for (const secret of [grant.accessToken, grant.idToken, grant.refreshToken]) {
    store.registerSecret(secret);
  }

  return grant;
};

const projectRefresh = async (
  context: Phase1ScenarioRunContext,
  grant: AdminRefreshGrant,
  coordinates: PositiveAdminProjectionCoordinates,
  proofs: readonly VerifiedJwtObservation[],
  normalizationContext: NormalizationContext,
  organization: boolean
): Promise<Phase1HttpProjection> => {
  const state = await context.projectScenarioState({
    scenarioId: coordinates.scenarioId,
    stepId: coordinates.stepId,
    fixture: context.fixture,
  });
  const input = {
    ...state,
    status: grant.response.status,
    headers: grant.response.headers,
    body: grant.body,
  };
  const options = { coordinates, verifiedJwts: proofs };

  return organization
    ? projectOrganizationTokenObservation(input, normalizationContext, options)
    : projectTokenObservation(input, normalizationContext, options);
};

export const positiveAdminNormalizationContext = (
  context: Phase1ScenarioRunContext
): NormalizationContext => createPositiveAdminNormalizationContext(context);

export const refreshPositiveAdminManagementToken = async (
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession,
  coordinates?: PositiveAdminProjectionCoordinates
): Promise<Phase1HttpProjection | void> => {
  const resource = context.profile.consoleAuthentication.configuredResources[0];
  const resourceContract = context.profile.fixtures.adminTenant.resources.find(
    ({ indicator }) => indicator === resource
  );

  if (!resource || !resourceContract) {
    throw new Error('Phase 1 admin Management resource is invalid');
  }
  const expectedScope = resourceContract.scopes.join(' ');
  const grant = await postRefresh(
    context,
    'admin-token-management-refresh',
    session,
    { resource },
    expectedScope,
    'Phase 1 admin Management refresh failed'
  );
  const proofs = await assertJwtPair(context, grant, {
    audience: resource,
    scope: expectedScope,
    forbidOrganizationId: true,
    diagnostic: 'Phase 1 admin Management token claims are invalid',
  });
  replacePositiveAdminRefreshToken(session, grant.refreshToken, [grant.accessToken, grant.idToken]);
  const projection = coordinates
    ? await projectRefresh(
        context,
        grant,
        coordinates,
        proofs,
        positiveAdminNormalizationContext(context),
        false
      )
    : undefined;
  const adminStore = context.protocol.forAllocation('admin').oidc.store;
  const managementStore = context.fixture.public.allocations.some(({ role }) => role === 'data')
    ? context.protocol.forAllocation('data').management.store
    : undefined;
  managementStore?.setToken('management', grant.accessToken);

  if (projection) {
    adminStore.assertNoCredentialMaterial(projection);
    managementStore?.assertNoCredentialMaterial(projection);
  }

  return projection;
};

export const refreshPositiveAdminManagementTokenWithoutAllScope = async (
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession
): Promise<void> => {
  const resource = context.profile.consoleAuthentication.configuredResources[0];

  if (!resource) {
    throw new Error('Phase 1 admin Management resource is invalid');
  }
  const grant = await postRefresh(
    context,
    'admin-token-management-missing-scope-refresh',
    session,
    { resource, scope: 'openid' },
    '',
    'Phase 1 admin Management missing-scope refresh failed'
  );
  await assertJwtPair(context, grant, {
    audience: resource,
    scope: '',
    forbidOrganizationId: true,
    diagnostic: 'Phase 1 admin Management missing-scope token claims are invalid',
  });
  replacePositiveAdminRefreshToken(session, grant.refreshToken, [grant.accessToken, grant.idToken]);
  context.protocol
    .forAllocation('data')
    .oidc.store.setToken('management-missing-scope', grant.accessToken);
};

export const refreshPositiveAdminAccountResourceToken = async (
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession
): Promise<void> => {
  const resource = context.profile.consoleAuthentication.configuredResources[1];
  const resourceContract = context.profile.fixtures.adminTenant.resources.find(
    ({ indicator }) => indicator === resource
  );

  if (!resource || !resourceContract || resourceContract.scopes.join(' ') !== 'all') {
    throw new Error('Phase 1 admin Account resource is invalid');
  }
  const grant = await postRefresh(
    context,
    'admin-token-account-authority-refresh',
    session,
    { resource },
    'all',
    'Phase 1 admin Account authority refresh failed'
  );
  await assertJwtPair(context, grant, {
    audience: resource,
    scope: 'all',
    forbidOrganizationId: true,
    diagnostic: 'Phase 1 admin Account authority token claims are invalid',
  });
  replacePositiveAdminRefreshToken(session, grant.refreshToken, [grant.accessToken, grant.idToken]);
  context.protocol
    .forAllocation('admin')
    .oidc.store.setToken('authority-wrong-audience', grant.accessToken);
};

export const refreshPositiveAdminUserInfoTokenWithoutOpenId = async (
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession
): Promise<void> => {
  const current = readPositiveAdminSession(session);
  const { oidc } = context.protocol.forAllocation('admin');
  const response = await oidc.request(
    'admin-token-userinfo-missing-openid-refresh',
    tokenPath(context),
    {
      method: 'POST',
      headers: { 'content-type': formContentType },
      body: new URLSearchParams({
        client_id: current.clientId,
        refresh_token: current.refreshToken,
        grant_type: 'refresh_token',
        scope: 'profile',
      }).toString(),
      includeCookies: false,
    }
  );
  try {
    const mediaTypes = headerValues(response.headers, 'content-type').map(
      (value) => value.split(';', 1)[0]?.trim().toLowerCase() ?? ''
    );
    const body: unknown = JSON.parse(response.body);

    if (
      response.status !== 200 ||
      mediaTypes.length !== 1 ||
      mediaTypes[0] !== jsonContentType ||
      !isJsonObject(body) ||
      body.token_type !== 'Bearer' ||
      body.scope !== 'profile' ||
      typeof body.expires_in !== 'number' ||
      !Number.isSafeInteger(body.expires_in) ||
      body.expires_in <= 0 ||
      Object.hasOwn(body, 'id_token')
    ) {
      throw new TypeError('invalid token response');
    }
    const accessToken = requireText(
      body.access_token,
      'Phase 1 admin UserInfo missing-openid refresh failed'
    );
    const refreshToken = requireText(
      body.refresh_token,
      'Phase 1 admin UserInfo missing-openid refresh failed'
    );

    if (
      accessToken.includes('.') ||
      refreshToken === current.refreshToken ||
      accessToken === refreshToken
    ) {
      throw new TypeError('invalid token credentials');
    }
    oidc.store.registerSecret(accessToken);
    oidc.store.registerSecret(refreshToken);
    replacePositiveAdminRefreshToken(session, refreshToken, [accessToken]);
    oidc.store.setToken('userinfo-missing-openid', accessToken);
  } catch {
    throw new Error('Phase 1 admin UserInfo missing-openid refresh failed');
  }
};

export function refreshPositiveAdminOrganizationToken(
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession,
  coordinates: PositiveAdminProjectionCoordinates
): Promise<Phase1HttpProjection>;
export function refreshPositiveAdminOrganizationToken(
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession
): Promise<void>;
export async function refreshPositiveAdminOrganizationToken(
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession,
  coordinates?: PositiveAdminProjectionCoordinates
): Promise<Phase1HttpProjection | void> {
  const request = context.profile.consoleOrganizationTokenRequest;
  const organizationId = request.form.organization_id;

  if (
    request.form.client_id !== context.profile.consoleAuthentication.applicationId ||
    request.form.grant_type !== 'refresh_token' ||
    request.form.resource !== null ||
    request.form.scope !== null ||
    request.requiredAccessTokenOmissions.length !== 1 ||
    request.requiredAccessTokenOmissions[0] !== 'organization_id'
  ) {
    throw new Error('Phase 1 admin organization token request is invalid');
  }
  const grant = await postRefresh(
    context,
    'admin-token-organization-refresh',
    session,
    { organization_id: organizationId },
    request.requiredTokenResponseProjection.scope,
    'Phase 1 admin organization refresh failed'
  );
  const proofs = await assertJwtPair(context, grant, {
    audience: request.requiredAccessTokenProjection.aud,
    scope: request.requiredAccessTokenProjection.scope,
    forbidOrganizationId: true,
    diagnostic: 'Phase 1 admin organization token claims are invalid',
  });
  replacePositiveAdminRefreshToken(session, grant.refreshToken, [grant.accessToken, grant.idToken]);
  const projection = coordinates
    ? await projectRefresh(
        context,
        grant,
        coordinates,
        proofs,
        positiveAdminNormalizationContext(context),
        true
      )
    : undefined;
  const { store } = context.protocol.forAllocation('admin').oidc;
  store.setToken('organization', grant.accessToken);
  if (projection) {
    store.assertNoCredentialMaterial(projection);
  }

  return projection;
}

export const installPositiveAdminAccountToken = (
  context: Phase1ScenarioRunContext,
  session: PositiveAdminSession
): void => {
  const { accessToken } = readPositiveAdminSession(session);
  context.protocol.forAllocation('admin').oidc.store.setToken('account', accessToken);
};

/* eslint-enable complexity, max-lines, max-params, no-restricted-syntax */
