/* eslint-disable max-lines, complexity, no-control-regex, no-restricted-syntax -- The admin authorization boundary keeps one cookie jar, password lease, PKCE credentials, query callback, token response, and redacted projections in one auditable flow. */
import { createHash, randomBytes } from 'node:crypto';

import { ReservedScope, userClaims } from '@logto/core-kit';
import { decodeJwt, decodeProtectedHeader, type JSONWebKeySet } from 'jose';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue, NormalizationContext } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import { verifyObservedJwt } from '../evidence.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import {
  createPhase1NormalizationContext,
  phase1ImplementationForProfile,
  projectPhase1NativeScopeForComparison,
} from '../native-surface-profile.js';
import { normalizeTokenResponse } from '../normalizers.js';
import { hasValidOptionalProfileTimestamps } from '../profile-timestamps.js';
import {
  projectAuthorizationObservation,
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from '../projections/index.js';

import { sanitizeSetCookieHeaders } from './positive-oidc-flow.js';

const managementScenarioId = 'console.admin-auth-resource-refresh';
const formContentType = 'application/x-www-form-urlencoded';
const jsonContentType = 'application/json';
const codeVerifierPattern = /^[A-Za-z0-9._~-]{43,128}$/u;
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const userClaimScopeNames = new Set(Object.keys(userClaims));

export type PositiveAdminFlowRandomSource = Readonly<{
  codeVerifier(): string;
  state(): string;
}>;

export type PositiveAdminSessionOptions = Readonly<{
  random?: PositiveAdminFlowRandomSource;
  captureAuthorize?: boolean;
  captureCodeToken?: boolean;
}>;

export type PositiveAdminSessionOutput<Result> = Readonly<{
  steps: readonly Phase1ScenarioStepResult[];
  result: Result;
}>;

export type PositiveAdminSessionCredentials = Readonly<{
  clientId: string;
  accessToken: string;
  idToken: string;
  refreshToken: string;
}>;

type PositiveAdminSessionState = Readonly<{
  credentials: PositiveAdminSessionCredentials;
  issuedCredentials: ReadonlySet<string>;
}>;

const positiveAdminSessionAuthority = Symbol('phase-1-admin-session-authority');
const sessionStates = new WeakMap<PositiveAdminSession, PositiveAdminSessionState>();

export class PositiveAdminSession {
  constructor(authority: unknown, credentials: PositiveAdminSessionCredentials) {
    const values = [credentials.accessToken, credentials.idToken, credentials.refreshToken];

    if (authority !== positiveAdminSessionAuthority || new Set(values).size !== values.length) {
      throw new TypeError('Invalid Phase 1 admin session');
    }
    sessionStates.set(
      this,
      Object.freeze({
        credentials: Object.freeze({ ...credentials }),
        issuedCredentials: new Set(values),
      })
    );
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError('Phase 1 admin session is not serializable');
  }
}

Object.freeze(PositiveAdminSession.prototype);

const readPositiveAdminSessionState = (
  session: PositiveAdminSession
): PositiveAdminSessionState => {
  const state = sessionStates.get(session);

  if (!state) {
    throw new TypeError('Invalid Phase 1 admin session');
  }

  return state;
};

export const readPositiveAdminSession = (
  session: PositiveAdminSession
): PositiveAdminSessionCredentials => readPositiveAdminSessionState(session).credentials;

const requireRotatablePositiveAdminRefreshToken = (
  session: PositiveAdminSession,
  refreshToken: string,
  accompanyingCredentials: readonly string[]
): PositiveAdminSessionState => {
  const state = readPositiveAdminSessionState(session);

  if (
    typeof refreshToken !== 'string' ||
    refreshToken.length === 0 ||
    /[\u0000-\u001F\u007F]/u.test(refreshToken) ||
    ![1, 2].includes(accompanyingCredentials.length) ||
    accompanyingCredentials.some(
      (credential) =>
        typeof credential !== 'string' ||
        credential.length === 0 ||
        /[\u0000-\u001F\u007F]/u.test(credential)
    ) ||
    state.issuedCredentials.has(refreshToken) ||
    accompanyingCredentials.includes(refreshToken)
  ) {
    throw new Error('Phase 1 admin refresh token was not rotated');
  }

  return state;
};

export const assertPositiveAdminRefreshTokenIsFresh = (
  session: PositiveAdminSession,
  refreshToken: string,
  accompanyingCredentials: readonly string[]
): void => {
  requireRotatablePositiveAdminRefreshToken(session, refreshToken, accompanyingCredentials);
};

export const replacePositiveAdminRefreshToken = (
  session: PositiveAdminSession,
  refreshToken: string,
  accompanyingCredentials: readonly string[]
): void => {
  const state = requireRotatablePositiveAdminRefreshToken(
    session,
    refreshToken,
    accompanyingCredentials
  );
  sessionStates.set(
    session,
    Object.freeze({
      credentials: Object.freeze({ ...state.credentials, refreshToken }),
      issuedCredentials: new Set([
        ...state.issuedCredentials,
        ...accompanyingCredentials,
        refreshToken,
      ]),
    })
  );
};

const revokePositiveAdminSession = (session: PositiveAdminSession): void => {
  sessionStates.delete(session);
};

const defaultRandom: PositiveAdminFlowRandomSource = Object.freeze({
  codeVerifier: () => randomBytes(48).toString('base64url'),
  state: () => randomBytes(32).toString('base64url'),
});

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

export const containsPrivateAdminJwkMaterial = (value: unknown): boolean => {
  if (Array.isArray(value)) {
    return value.some((item) => containsPrivateAdminJwkMaterial(item));
  }
  if (!isJsonObject(value)) {
    return false;
  }
  if (
    typeof value.kty === 'string' &&
    Object.keys(value).some((member) => privateJwkMembers.has(member))
  ) {
    return true;
  }

  return Object.entries(value).some(([key, nested]) =>
    key === 'jwk'
      ? !isJsonObject(nested) ||
        typeof nested.kty !== 'string' ||
        containsPrivateAdminJwkMaterial(nested)
      : containsPrivateAdminJwkMaterial(nested)
  );
};

const requireText = (value: unknown, diagnostic: string): string => {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new Error(diagnostic);
  }

  return value;
};

const requireJsonObject = (body: string, diagnostic: string): JsonObject => {
  try {
    const value: unknown = JSON.parse(body);

    if (!isJsonObject(value)) {
      throw new TypeError('invalid JSON object');
    }

    return value;
  } catch {
    throw new Error(diagnostic);
  }
};

const headerValues = (
  headers: ReadonlyArray<readonly [string, string]>,
  name: string
): readonly string[] =>
  headers.filter(([candidate]) => candidate.toLowerCase() === name).map(([, value]) => value);

const requireStatus = <Response extends Readonly<{ status: number }>>(
  response: Response,
  status: number,
  diagnostic: string
): Response => {
  if (response.status !== status) {
    throw new Error(diagnostic);
  }

  return response;
};

const requireMediaType = (
  headers: ReadonlyArray<readonly [string, string]>,
  expected: string,
  diagnostic: string
): void => {
  const values = headerValues(headers, 'content-type').map(
    (value) => value.split(';', 1)[0]?.trim().toLowerCase() ?? ''
  );

  if (values.length !== 1 || values[0] !== expected) {
    throw new Error(diagnostic);
  }
};

const requireLocation = (
  headers: ReadonlyArray<readonly [string, string]>,
  baseUrl: string,
  diagnostic: string
): string => {
  const locations = headerValues(headers, 'location');

  if (locations.length !== 1 || !locations[0]) {
    throw new Error(diagnostic);
  }
  try {
    const url = new URL(locations[0], baseUrl);

    if (url.username.length > 0 || url.password.length > 0) {
      throw new TypeError('credential-bearing location');
    }

    return url.href;
  } catch {
    throw new Error(diagnostic);
  }
};

const absoluteLocationHeaders = (
  headers: ReadonlyArray<readonly [string, string]>,
  location: string
): ReadonlyArray<readonly [string, string]> =>
  Object.freeze(
    headers.map(([name, value]) =>
      Object.freeze([name, name.toLowerCase() === 'location' ? location : value] as const)
    )
  );

const normalizeRedirectBody = (
  body: string,
  headers: ReadonlyArray<readonly [string, string]>,
  absoluteLocation: string,
  diagnostic: string
): JsonValue => {
  if (body.length === 0) {
    return null;
  }
  const [rawLocation] = headerValues(headers, 'location');

  if (!rawLocation) {
    throw new Error(diagnostic);
  }
  const normalized = [rawLocation, absoluteLocation, rawLocation.replaceAll('&', '&amp;')].reduce(
    (value, candidate) => value.replaceAll(candidate, '<response-location>'),
    body
  );

  if (normalized === body) {
    throw new Error(diagnostic);
  }

  return normalized;
};

const parseCallbackRedirect = (
  location: string,
  redirectUri: string,
  expectedState: string,
  issuer: string
): string => {
  try {
    const callback = new URL(location);
    const registered = new URL(redirectUri);
    const codes = callback.searchParams.getAll('code');
    const states = callback.searchParams.getAll('state');
    const issuers = callback.searchParams.getAll('iss');

    if (
      callback.username.length > 0 ||
      callback.password.length > 0 ||
      callback.origin !== registered.origin ||
      callback.pathname !== registered.pathname ||
      callback.hash !== registered.hash ||
      codes.length !== 1 ||
      states.length !== 1 ||
      states[0] !== expectedState ||
      issuers.length !== 1 ||
      issuers[0] !== issuer ||
      callback.searchParams.has('error') ||
      Array.from(callback.searchParams.keys()).some(
        (key) => !['code', 'state', 'iss'].includes(key)
      )
    ) {
      throw new TypeError('invalid callback parameters');
    }

    return requireText(codes[0], 'invalid callback code');
  } catch {
    throw new Error('Phase 1 admin authorization callback is invalid');
  }
};

const parseAdminResumeRedirect = (
  value: unknown,
  adminUrl: string,
  diagnostic: string
): Readonly<{ href: string; path: string; credential: string }> => {
  try {
    const resumeUrl = new URL(requireText(value, diagnostic));
    const segments = resumeUrl.pathname.split('/');
    const encodedCredential = segments[3];

    if (
      resumeUrl.origin !== new URL(adminUrl).origin ||
      resumeUrl.username.length > 0 ||
      resumeUrl.password.length > 0 ||
      resumeUrl.search.length > 0 ||
      resumeUrl.hash.length > 0 ||
      segments.length !== 4 ||
      segments[1] !== 'oidc' ||
      segments[2] !== 'auth' ||
      !encodedCredential
    ) {
      throw new TypeError('invalid resume URL');
    }
    const credential = decodeURIComponent(encodedCredential);

    if (credential.includes('/') || credential.includes('\\')) {
      throw new TypeError('invalid resume credential');
    }

    return Object.freeze({
      href: resumeUrl.href,
      path: `oidc/auth/${encodedCredential}`,
      credential: requireText(credential, 'invalid resume credential'),
    });
  } catch {
    throw new Error(diagnostic);
  }
};

const requireAdminConsentBridge = (
  location: string,
  adminUrl: string,
  clientId: string
): string => {
  try {
    const bridge = new URL(location);
    const applicationIds = bridge.searchParams.getAll('app_id');

    if (
      bridge.origin !== new URL(adminUrl).origin ||
      bridge.username.length > 0 ||
      bridge.password.length > 0 ||
      bridge.pathname !== '/consent' ||
      bridge.hash.length > 0 ||
      applicationIds.length !== 1 ||
      applicationIds[0] !== clientId ||
      Array.from(bridge.searchParams.keys()).some((key) => key !== 'app_id')
    ) {
      throw new TypeError('invalid consent bridge');
    }

    return `${bridge.pathname.slice(1)}${bridge.search}`;
  } catch {
    throw new Error('Phase 1 admin consent bridge redirect is invalid');
  }
};

const adminAllocation = (context: Phase1ScenarioRunContext) => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'admin');

  if (!allocation) {
    throw new Error('Phase 1 admin allocation is unavailable');
  }

  return allocation;
};

export const createPositiveAdminNormalizationContext = (
  context: Phase1ScenarioRunContext
): NormalizationContext => {
  const allocation = adminAllocation(context);
  const symbols = context.protocol.symbolsFor(allocation.allocationId);

  if (!symbols) {
    throw new Error('Phase 1 admin allocation symbols are unavailable');
  }
  const { operator } = context.profile.fixtures.adminTenant;
  symbols.bind(
    'fixture.admin.username',
    getPhase1FixtureRuntimeUsername(operator.username, allocation.allocationId)
  );
  symbols.bind(
    'fixture.admin.email',
    getPhase1FixtureRuntimeEmail(operator.primaryEmail, allocation.allocationId)
  );

  return createPhase1NormalizationContext(context.profile, context.target, symbols);
};

const issuerFor = (context: Phase1ScenarioRunContext): string =>
  new URL('/oidc', context.target.adminUrl).href.replace(/\/$/u, '');

const redirectUriFor = (context: Phase1ScenarioRunContext): string => {
  const configured = new URL(context.profile.consoleAuthentication.redirectUri);

  return new URL(
    `${configured.pathname}${configured.search}${configured.hash}`,
    context.target.adminUrl
  ).href;
};

const authorizationPath = (
  context: Phase1ScenarioRunContext,
  codeChallenge: string,
  state: string
): string => {
  const path = context.profile.oidc.authorizationPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 admin authorization path is invalid');
  }
  const authentication = context.profile.consoleAuthentication;
  const query = new URLSearchParams({
    client_id: authentication.applicationId,
    redirect_uri: redirectUriFor(context),
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    response_type: 'code',
    prompt: authentication.prompt.join(' '),
    scope: authentication.effectiveScopes.join(' '),
  });

  for (const resource of authentication.effectiveResources) {
    query.append('resource', resource);
  }

  return `${path.slice(1)}?${query.toString()}`;
};

const tokenPath = (context: Phase1ScenarioRunContext): string => {
  const path = context.profile.oidc.tokenPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 admin token path is invalid');
  }

  return path.slice(1);
};

const markedJwt = (value: string): boolean => {
  if (value.split('.').length !== 3) {
    return false;
  }
  try {
    return typeof decodeProtectedHeader(value).alg === 'string';
  } catch {
    return false;
  }
};

const loadAdminJwks = async (context: Phase1ScenarioRunContext): Promise<JSONWebKeySet> => {
  const path = context.profile.oidc.jwksPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 admin JWKS path is invalid');
  }
  const response = requireStatus(
    await context.protocol
      .forAllocation('admin')
      .oidc.request('admin-token-jwks', path.slice(1), { includeCookies: false }),
    200,
    'Phase 1 admin JWKS read failed'
  );
  const body = requireJsonObject(response.body, 'Phase 1 admin JWKS read failed');

  if (
    !Array.isArray(body.keys) ||
    body.keys.length === 0 ||
    body.keys.some(
      (key) =>
        !isJsonObject(key) || typeof key.kty !== 'string' || containsPrivateAdminJwkMaterial(key)
    )
  ) {
    throw new Error('Phase 1 admin JWKS read failed');
  }

  return { keys: body.keys as JSONWebKeySet['keys'] };
};

const assertInitialIdToken = async (
  context: Phase1ScenarioRunContext,
  idToken: string,
  clientId: string
): Promise<void> => {
  try {
    const header = decodeProtectedHeader(idToken);
    const claims = decodeJwt(idToken);
    const [algorithm] = context.profile.oidc.idTokenSigningAlgorithmsSupported;
    const allocation = adminAllocation(context);
    const subject = getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'user',
      context.profile.fixtures.adminTenant.operator.id
    );
    const now = Math.floor(Date.now() / 1000);

    if (
      context.profile.oidc.idTokenSigningAlgorithmsSupported.length !== 1 ||
      header.alg !== algorithm ||
      containsPrivateAdminJwkMaterial(header) ||
      containsPrivateAdminJwkMaterial(claims) ||
      claims.iss !== issuerFor(context) ||
      claims.sub !== subject ||
      claims.aud !== clientId ||
      !hasValidOptionalProfileTimestamps(claims, phase1ImplementationForProfile(context.profile)) ||
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
      throw new TypeError('invalid admin ID token');
    }
    await verifyObservedJwt(idToken, await loadAdminJwks(context));
  } catch {
    throw new Error('Phase 1 admin code token claims are invalid');
  }
};

const initialAdminResponseScope = (profile: Phase1ScenarioRunContext['profile']): string =>
  profile.consoleAuthentication.effectiveScopes
    .filter(
      (scope) =>
        scope === ReservedScope.OpenId ||
        scope === ReservedScope.OfflineAccess ||
        userClaimScopeNames.has(projectPhase1NativeScopeForComparison(profile, scope))
    )
    .join(' ');

const parseInitialTokenResponse = async (
  context: Phase1ScenarioRunContext,
  response: RawProtocolResponse
): Promise<Readonly<{ body: JsonObject; credentials: PositiveAdminSessionCredentials }>> => {
  requireStatus(response, 200, 'Phase 1 admin authorization code exchange failed');
  requireMediaType(
    response.headers,
    jsonContentType,
    'Phase 1 admin authorization code exchange failed'
  );
  const body = requireJsonObject(response.body, 'Phase 1 admin authorization code exchange failed');
  const accessToken = requireText(
    body.access_token,
    'Phase 1 admin authorization code exchange failed'
  );
  const idToken = requireText(body.id_token, 'Phase 1 admin authorization code exchange failed');
  const refreshToken = requireText(
    body.refresh_token,
    'Phase 1 admin authorization code exchange failed'
  );
  const clientId = context.profile.consoleAuthentication.applicationId;
  const expectedResponseScope = initialAdminResponseScope(context.profile);

  if (
    markedJwt(accessToken) ||
    !markedJwt(idToken) ||
    new Set([accessToken, idToken, refreshToken]).size !== 3 ||
    body.token_type !== 'Bearer' ||
    body.scope !== expectedResponseScope ||
    typeof body.expires_in !== 'number' ||
    !Number.isSafeInteger(body.expires_in) ||
    body.expires_in <= 0
  ) {
    throw new Error('Phase 1 admin authorization code exchange failed');
  }
  await assertInitialIdToken(context, idToken, clientId);

  return Object.freeze({
    body,
    credentials: Object.freeze({ clientId, accessToken, idToken, refreshToken }),
  });
};

const summarizeToken = (value: JsonValue | undefined, fallbackFormat?: 'opaque'): JsonValue => {
  if (!isJsonObject(value)) {
    return null;
  }

  return {
    ...(fallbackFormat && !Object.hasOwn(value, 'format') ? { format: fallbackFormat } : {}),
    ...Object.fromEntries(
      ['format', 'present', 'characterCount'].flatMap((field) =>
        Object.hasOwn(value, field) ? [[field, value[field]]] : []
      )
    ),
  };
};

const stateInput = async (context: Phase1ScenarioRunContext, stepId: 'authorize' | 'code-token') =>
  context.projectScenarioState({
    scenarioId: managementScenarioId,
    stepId,
    fixture: context.fixture,
  });

const rawObservation = (
  response: Pick<RawProtocolResponse, 'status' | 'headers'>,
  body: JsonValue,
  state: Awaited<ReturnType<typeof stateInput>>,
  overrides: Partial<RawHttpObservation> = {}
): RawHttpObservation => ({
  ...state,
  status: response.status,
  headers: sanitizeSetCookieHeaders(response.headers),
  body,
  ...overrides,
});

const step = (stepId: string, value: Phase1HttpProjection): Phase1ScenarioStepResult =>
  Object.freeze({ stepId, value });

export const withPositiveAdminSession = async <Result>(
  context: Phase1ScenarioRunContext,
  options: PositiveAdminSessionOptions,
  consume: (session: PositiveAdminSession) => Promise<Result>
): Promise<PositiveAdminSessionOutput<Result>> =>
  context.fixture.withSecretLease(async (lease) => {
    const clients = context.protocol.forAllocation('admin');
    const { store } = clients.oidc;

    if (
      clients.experience.store !== store ||
      clients.management.store !== store ||
      clients.account.store !== store
    ) {
      throw new Error('Phase 1 admin clients do not share one secret store');
    }
    const allocation = adminAllocation(context);
    const normalizationContext = createPositiveAdminNormalizationContext(context);
    const random = options.random ?? defaultRandom;
    const verifier = requireText(random.codeVerifier(), 'Phase 1 admin PKCE verifier is invalid');
    const state = requireText(random.state(), 'Phase 1 admin authorization state is invalid');

    if (!codeVerifierPattern.test(verifier)) {
      throw new Error('Phase 1 admin PKCE verifier is invalid');
    }
    store.registerSecret(verifier);
    store.registerSecret(state);
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const authorizeResponse = requireStatus(
      await clients.oidc.request(
        'admin-authorization-start',
        authorizationPath(context, challenge, state),
        { includeCookies: true }
      ),
      303,
      'Phase 1 admin authorization start failed'
    );
    const authorizeLocation = requireLocation(
      authorizeResponse.headers,
      context.target.adminUrl,
      'Phase 1 admin authorization start redirect is invalid'
    );
    const authorizeUrl = new URL(authorizeLocation);

    if (
      authorizeUrl.origin !== new URL(context.target.adminUrl).origin ||
      authorizeUrl.pathname !== '/sign-in' ||
      authorizeUrl.hash.length > 0
    ) {
      throw new Error('Phase 1 admin authorization start redirect is invalid');
    }
    const authorizeStep = options.captureAuthorize
      ? step(
          'authorize',
          projectAuthorizationObservation(
            rawObservation(
              {
                ...authorizeResponse,
                headers: absoluteLocationHeaders(authorizeResponse.headers, authorizeLocation),
              },
              normalizeRedirectBody(
                authorizeResponse.body,
                authorizeResponse.headers,
                authorizeLocation,
                'Phase 1 admin authorization start body is invalid'
              ),
              await stateInput(context, 'authorize'),
              { redirect: authorizeLocation }
            ),
            normalizationContext
          )
        )
      : undefined;
    const jsonHeaders = Object.freeze([Object.freeze(['content-type', jsonContentType] as const)]);
    requireStatus(
      await clients.experience.requestExperience('admin-experience-bootstrap', 'experience', {
        method: 'PUT',
        headers: jsonHeaders,
        body: JSON.stringify({ interactionEvent: 'SignIn' }),
      }),
      204,
      'Phase 1 admin experience bootstrap failed'
    );
    const { operator } = context.profile.fixtures.adminTenant;
    const password = lease.getPassword(operator.id);
    store.registerSecret(password);
    const passwordResponse = requireStatus(
      await clients.experience.requestExperience(
        'admin-experience-password',
        'experience/verification/password',
        {
          method: 'POST',
          headers: jsonHeaders,
          body: JSON.stringify({
            identifier: {
              type: 'username',
              value: getPhase1FixtureRuntimeUsername(operator.username, allocation.allocationId),
            },
            password,
          }),
        }
      ),
      200,
      'Phase 1 admin password verification failed'
    );
    requireMediaType(
      passwordResponse.headers,
      jsonContentType,
      'Phase 1 admin password verification failed'
    );
    const verificationId = requireText(
      requireJsonObject(passwordResponse.body, 'Phase 1 admin password verification failed')
        .verificationId,
      'Phase 1 admin password verification failed'
    );
    store.registerSecret(verificationId);
    requireStatus(
      await clients.experience.requestExperience(
        'admin-experience-identify',
        'experience/identification',
        {
          method: 'POST',
          headers: jsonHeaders,
          body: JSON.stringify({ verificationId }),
        }
      ),
      204,
      'Phase 1 admin identification failed'
    );
    const submitResponse = requireStatus(
      await clients.experience.requestExperience('admin-experience-submit', 'experience/submit', {
        method: 'POST',
      }),
      200,
      'Phase 1 admin interaction submission failed'
    );
    requireMediaType(
      submitResponse.headers,
      jsonContentType,
      'Phase 1 admin interaction submission failed'
    );
    const redirectTo = requireText(
      requireJsonObject(submitResponse.body, 'Phase 1 admin interaction submission failed')
        .redirectTo,
      'Phase 1 admin interaction submission failed'
    );
    const loginResume = parseAdminResumeRedirect(
      redirectTo,
      context.target.adminUrl,
      'Phase 1 admin interaction resume redirect is invalid'
    );
    store.registerSecret(loginResume.credential);
    const consentBridgeResponse = requireStatus(
      await clients.oidc.request('admin-authorization-consent-bridge', loginResume.path, {
        method: 'GET',
        includeCookies: true,
      }),
      303,
      'Phase 1 admin authorization consent bridge failed'
    );
    const consentBridgeLocation = requireLocation(
      consentBridgeResponse.headers,
      loginResume.href,
      'Phase 1 admin consent bridge redirect is invalid'
    );
    const consentPath = requireAdminConsentBridge(
      consentBridgeLocation,
      context.target.adminUrl,
      context.profile.consoleAuthentication.applicationId
    );
    const consentResponse = requireStatus(
      await clients.oidc.request('admin-consent-auto', consentPath, {
        method: 'GET',
        includeCookies: true,
      }),
      302,
      'Phase 1 admin auto-consent failed'
    );
    const consentResumeLocation = requireLocation(
      consentResponse.headers,
      consentBridgeLocation,
      'Phase 1 admin consent resume redirect is invalid'
    );
    const consentResume = parseAdminResumeRedirect(
      consentResumeLocation,
      context.target.adminUrl,
      'Phase 1 admin consent resume redirect is invalid'
    );

    if (consentResume.credential === loginResume.credential) {
      throw new Error('Phase 1 admin consent resume redirect is invalid');
    }
    store.registerSecret(consentResume.credential);
    const resumeResponse = requireStatus(
      await clients.oidc.request('admin-authorization-resume', consentResume.path, {
        method: 'GET',
        includeCookies: true,
      }),
      303,
      'Phase 1 admin authorization resume failed'
    );
    const callbackLocation = requireLocation(
      resumeResponse.headers,
      consentResume.href,
      'Phase 1 admin authorization callback is invalid'
    );
    const code = parseCallbackRedirect(
      callbackLocation,
      redirectUriFor(context),
      state,
      issuerFor(context)
    );
    store.registerSecret(code);
    const tokenResponse = await clients.oidc.request(
      'admin-token-authorization-code',
      tokenPath(context),
      {
        method: 'POST',
        headers: { 'content-type': formContentType },
        body: new URLSearchParams({
          client_id: context.profile.consoleAuthentication.applicationId,
          code,
          code_verifier: verifier,
          redirect_uri: redirectUriFor(context),
          grant_type: 'authorization_code',
        }).toString(),
        includeCookies: false,
      }
    );
    const token = await parseInitialTokenResponse(context, tokenResponse);

    for (const secret of [
      token.credentials.accessToken,
      token.credentials.idToken,
      token.credentials.refreshToken,
    ]) {
      store.registerSecret(secret);
    }
    const codeTokenStep = options.captureCodeToken
      ? (() => {
          const normalized = normalizeTokenResponse(token.body, normalizationContext);
          const { access, id, refresh, ...metadata } = normalized;

          return { normalized: { access, id, refresh, metadata } };
        })()
      : undefined;
    const projectedCodeToken = codeTokenStep
      ? step(
          'code-token',
          projectHttpObservation(
            rawObservation(
              tokenResponse,
              {
                ...codeTokenStep.normalized.metadata,
                access: summarizeToken(codeTokenStep.normalized.access, 'opaque'),
                id: summarizeToken(codeTokenStep.normalized.id),
                refresh: summarizeToken(codeTokenStep.normalized.refresh, 'opaque'),
              },
              await stateInput(context, 'code-token')
            ),
            normalizationContext
          )
        )
      : undefined;
    const steps = Object.freeze(
      [authorizeStep, projectedCodeToken].filter(
        (value): value is Phase1ScenarioStepResult => value !== undefined
      )
    );
    store.assertNoCredentialMaterial(steps);
    const session = new PositiveAdminSession(positiveAdminSessionAuthority, token.credentials);

    try {
      const result = await consume(session);
      store.assertNoCredentialMaterial(result);

      return Object.freeze({ steps, result });
    } catch {
      throw new Error('Phase 1 admin session consumer failed');
    } finally {
      revokePositiveAdminSession(session);
    }
  });

/* eslint-enable max-lines, complexity, no-control-regex, no-restricted-syntax */
