/* eslint-disable complexity, max-lines, max-params -- Token exchange, claim verification, proof ownership, and credential capabilities form one auditable protocol boundary. */
import { decodeJwt, decodeProtectedHeader, type JSONWebKeySet, type JWTPayload } from 'jose';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue, NormalizationContext } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import { verifyObservedJwt, type VerifiedJwtObservation } from '../evidence.js';
import {
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
} from '../fixture-map.js';
import type { Phase1DifferentialScenarioId, Phase1ScenarioRunContext } from '../model.js';
import { normalizeTokenResponse } from '../normalizers.js';
import {
  projectHttpObservation,
  projectSemanticStateObservation,
  projectTokenObservation,
  type Phase1HttpProjection,
} from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  readPositiveOidcAuthorizationGrant,
  type PositiveOidcAuthorizationGrant,
} from './positive-oidc-flow.js';

const formContentType = 'application/x-www-form-urlencoded';
const jsonMediaTypes = new Set(['application/json', 'application/jwk-set+json']);
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

type PositiveOidcTokenGrantSecrets = Readonly<{
  response: RawProtocolResponse;
  body: JsonObject;
  accessToken: string;
  idToken: string;
  refreshToken: string;
  clientId: string;
}>;

const tokenGrantBrand: unique symbol = Symbol('phase-1-token-grant');
const tokenGrantSecrets = new WeakMap<PositiveOidcTokenGrant, PositiveOidcTokenGrantSecrets>();

export class PositiveOidcTokenGrant {
  get [tokenGrantBrand](): true {
    return true;
  }

  constructor(secrets: PositiveOidcTokenGrantSecrets) {
    tokenGrantSecrets.set(this, secrets);
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError('Phase 1 token grant is not serializable');
  }
}

Object.freeze(PositiveOidcTokenGrant.prototype);

const readTokenGrant = (grant: PositiveOidcTokenGrant): PositiveOidcTokenGrantSecrets => {
  const secrets = tokenGrantSecrets.get(grant);

  if (!secrets) {
    throw new TypeError('Invalid Phase 1 token grant');
  }

  return secrets;
};

export const revokePositiveTokenGrant = (grant: PositiveOidcTokenGrant): void => {
  tokenGrantSecrets.delete(grant);
};

export const positiveOidcDataNormalizationContext = (
  context: Phase1ScenarioRunContext
): NormalizationContext => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
  const symbols = allocation && context.protocol.symbolsFor(allocation.allocationId);

  if (!allocation || !symbols) {
    throw new Error('Phase 1 data allocation symbols are unavailable');
  }

  return { target: context.target, symbols };
};

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

const requireJsonResponse = (
  response: RawProtocolResponse,
  diagnostic: string,
  acceptedMediaTypes: ReadonlySet<string> = new Set(['application/json'])
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
      !acceptedMediaTypes.has(mediaTypes[0]) ||
      !isJsonObject(body)
    ) {
      throw new TypeError('invalid response');
    }

    return body;
  } catch {
    throw new Error(diagnostic);
  }
};

const requireTokenText = (value: unknown, diagnostic: string): string => {
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

const requireTokenGrant = (
  response: RawProtocolResponse,
  clientId: string,
  diagnostic: string
): PositiveOidcTokenGrant => {
  const body = requireJsonResponse(response, diagnostic);
  const accessToken = requireTokenText(body.access_token, diagnostic);
  const idToken = requireTokenText(body.id_token, diagnostic);
  const refreshToken = requireTokenText(body.refresh_token, diagnostic);

  if (
    body.token_type !== 'Bearer' ||
    typeof body.expires_in !== 'number' ||
    !Number.isSafeInteger(body.expires_in) ||
    body.expires_in <= 0 ||
    typeof body.scope !== 'string'
  ) {
    throw new Error(diagnostic);
  }

  return new PositiveOidcTokenGrant(
    Object.freeze({ response, body, accessToken, idToken, refreshToken, clientId })
  );
};

const tokenPath = (context: Phase1ScenarioRunContext): string => {
  const path = context.profile.oidc.tokenPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 token path is invalid');
  }

  return path.slice(1);
};

const postToken = async (
  context: Phase1ScenarioRunContext,
  operation: string,
  form: URLSearchParams,
  clientId: string,
  diagnostic: string
): Promise<PositiveOidcTokenGrant> => {
  const { oidc } = context.protocol.forAllocation('data');
  const response = await oidc.request(operation, tokenPath(context), {
    method: 'POST',
    headers: { 'content-type': formContentType },
    body: form.toString(),
    includeCookies: false,
  });
  const grant = requireTokenGrant(response, clientId, diagnostic);
  const secrets = readTokenGrant(grant);

  for (const value of [secrets.accessToken, secrets.idToken, secrets.refreshToken]) {
    oidc.store.registerSecret(value);
  }

  return grant;
};

export const exchangePositiveAuthorizationCode = async (
  context: Phase1ScenarioRunContext,
  grant: PositiveOidcAuthorizationGrant
): Promise<PositiveOidcTokenGrant> => {
  const credentials = readPositiveOidcAuthorizationGrant(grant);
  const { store } = context.protocol.forAllocation('data').oidc;
  store.registerSecret(credentials.code);
  store.registerSecret(credentials.codeVerifier);

  return postToken(
    context,
    'token-authorization-code',
    new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: credentials.clientId,
      code: credentials.code,
      code_verifier: credentials.codeVerifier,
      redirect_uri: credentials.redirectUri,
    }),
    credentials.clientId,
    'Phase 1 authorization code exchange failed'
  );
};

export const exchangePositiveRefreshToken = async (
  context: Phase1ScenarioRunContext,
  initialGrant: PositiveOidcTokenGrant
): Promise<PositiveOidcTokenGrant> => {
  const initial = readTokenGrant(initialGrant);
  const rotated = await postToken(
    context,
    'token-refresh',
    new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: initial.clientId,
      refresh_token: initial.refreshToken,
    }),
    initial.clientId,
    'Phase 1 refresh token exchange failed'
  );
  const replacement = readTokenGrant(rotated);

  if (replacement.refreshToken === initial.refreshToken) {
    throw new Error('Phase 1 refresh token was not rotated');
  }

  return rotated;
};

const requireJwks = async (context: Phase1ScenarioRunContext): Promise<JSONWebKeySet> => {
  const path = context.profile.oidc.jwksPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 JWKS path is invalid');
  }
  const response = await context.protocol.publicOidc.request('token-jwks', path.slice(1), {
    includeCookies: false,
  });
  const body = requireJsonResponse(response, 'Phase 1 token JWKS read failed', jsonMediaTypes);

  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    throw new Error('Phase 1 token JWKS read failed');
  }

  const keys: JSONWebKeySet['keys'] = body.keys.map((key) => {
    if (
      !isJsonObject(key) ||
      typeof key.kty !== 'string' ||
      Object.keys(key).some((member) => privateJwkMembers.has(member))
    ) {
      throw new Error('Phase 1 token JWKS read failed');
    }

    return key;
  });

  return { keys };
};

const isMarkedCompactJwt = (value: string): boolean => {
  if (value.split('.').length !== 3) {
    return false;
  }
  try {
    const header = decodeProtectedHeader(value);

    return typeof header.alg === 'string' && header.alg.length > 0;
  } catch {
    return false;
  }
};

const audienceContainsExactly = (audience: JWTPayload['aud'], expected: string): boolean =>
  audience === expected ||
  (Array.isArray(audience) && audience.length === 1 && audience[0] === expected);

const assertJwtClaims = (
  context: Phase1ScenarioRunContext,
  token: string,
  input: Readonly<{
    kind: 'id' | 'access';
    clientId: string;
    expectedAudience: string;
    expectedScope?: string;
  }>
): void => {
  try {
    const header = decodeProtectedHeader(token);
    const claims = decodeJwt(token);
    const algorithms = context.profile.oidc.idTokenSigningAlgorithmsSupported;
    const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');

    if (!allocation || algorithms.length !== 1 || header.alg !== algorithms[0]) {
      throw new TypeError('invalid JWT metadata');
    }
    const expectedSubject = getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'user',
      context.profile.fixtures.dataTenant.subject.id
    );
    const expectedIssuer = new URL(
      context.profile.oidc.issuerPath,
      context.target.coreUrl
    ).href.replace(/\/$/u, '');
    const now = Math.floor(Date.now() / 1000);

    if (
      claims.iss !== expectedIssuer ||
      claims.sub !== expectedSubject ||
      !audienceContainsExactly(claims.aud, input.expectedAudience) ||
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
          claims.nbf > now + 30)) ||
      (input.kind === 'access' && claims.client_id !== input.clientId) ||
      (input.expectedScope !== undefined && claims.scope !== input.expectedScope)
    ) {
      throw new TypeError('invalid JWT claims');
    }
  } catch {
    throw new Error('Phase 1 token claims are invalid');
  }
};

export const verifyPositiveTokenGrant = async (
  context: Phase1ScenarioRunContext,
  tokenGrant: PositiveOidcTokenGrant,
  expectAccessJwt: boolean
): Promise<readonly VerifiedJwtObservation[]> => {
  const grant = readTokenGrant(tokenGrant);
  const idIsJwt = isMarkedCompactJwt(grant.idToken);
  const accessIsJwt = isMarkedCompactJwt(grant.accessToken);

  if (!idIsJwt || accessIsJwt !== expectAccessJwt) {
    throw new Error('Phase 1 token format is invalid');
  }
  assertJwtClaims(context, grant.idToken, {
    kind: 'id',
    clientId: grant.clientId,
    expectedAudience: grant.clientId,
  });
  if (accessIsJwt) {
    const { resource } = context.profile.fixtures.dataTenant;
    const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');

    if (!allocation) {
      throw new Error('Phase 1 token claims are invalid');
    }
    const expectedScope = resource.scopes
      .map(({ name }) => getPhase1FixtureRuntimeText(name, allocation.allocationId))
      .join(' ');
    assertJwtClaims(context, grant.accessToken, {
      kind: 'access',
      clientId: grant.clientId,
      expectedAudience: getPhase1FixtureRuntimeResourceIndicator(
        resource.indicator,
        allocation.allocationId
      ),
      expectedScope,
    });
  }
  const jwks = await requireJwks(context);

  return Promise.all(
    [grant.idToken, ...(accessIsJwt ? [grant.accessToken] : [])].map(async (token) =>
      verifyObservedJwt(token, jwks)
    )
  );
};

const stateInput = async (
  context: Phase1ScenarioRunContext,
  scenarioId: Phase1DifferentialScenarioId,
  stepId: string
) => context.projectScenarioState({ scenarioId, stepId, fixture: context.fixture });

export const projectPositiveTokenGrant = async (
  context: Phase1ScenarioRunContext,
  input: Readonly<{
    scenarioId: Phase1DifferentialScenarioId;
    stepId: string;
    grant: PositiveOidcTokenGrant;
    normalizationContext: NormalizationContext;
    expectAccessJwt: boolean;
  }>
): Promise<Phase1HttpProjection> => {
  const grant = readTokenGrant(input.grant);
  const [proofs, state] = await Promise.all([
    verifyPositiveTokenGrant(context, input.grant, input.expectAccessJwt),
    stateInput(context, input.scenarioId, input.stepId),
  ]);

  return projectTokenObservation(
    {
      ...state,
      status: grant.response.status,
      headers: grant.response.headers,
      body: grant.body,
    },
    input.normalizationContext,
    {
      coordinates: { scenarioId: input.scenarioId, stepId: input.stepId },
      verifiedJwts: proofs,
    }
  );
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

export const projectPositiveTokenGrantSummary = async (
  context: Phase1ScenarioRunContext,
  input: Readonly<{
    scenarioId: Phase1DifferentialScenarioId;
    stepId: string;
    grant: PositiveOidcTokenGrant;
    normalizationContext: NormalizationContext;
  }>
): Promise<Phase1HttpProjection> => {
  const grant = readTokenGrant(input.grant);
  const verifyAndNormalize = async () => {
    await verifyPositiveTokenGrant(context, input.grant, false);

    return normalizeTokenResponse(grant.body, input.normalizationContext);
  };
  const [normalized, state] = await Promise.all([
    verifyAndNormalize(),
    stateInput(context, input.scenarioId, input.stepId),
  ]);
  const { access, id, refresh, ...metadata } = normalized;

  return projectHttpObservation(
    {
      ...state,
      status: grant.response.status,
      headers: grant.response.headers,
      body: {
        ...metadata,
        access: summarizeToken(access),
        id: summarizeToken(id),
        refresh: summarizeToken(refresh, 'opaque'),
      },
    },
    input.normalizationContext
  );
};

export const requestPositiveUserInfo = async (
  context: Phase1ScenarioRunContext,
  grant: PositiveOidcTokenGrant,
  path: string
): Promise<RawProtocolResponse> => {
  const { accessToken } = readTokenGrant(grant);

  return context.protocol.forAllocation('data').oidc.request('userinfo-openid', path, {
    headers: { authorization: `Bearer ${accessToken}` },
    includeCookies: false,
  });
};

export const projectPositiveScenarioState = async (
  context: Phase1ScenarioRunContext,
  input: Readonly<{
    scenarioId: Phase1DifferentialScenarioId;
    stepId: string;
    normalizationContext: NormalizationContext;
    validate?: (state: Phase1ScenarioStateProjectionInput) => void;
  }>
): Promise<Phase1HttpProjection> => {
  const state = await stateInput(context, input.scenarioId, input.stepId);
  input.validate?.(state);

  return projectSemanticStateObservation(
    { ...state, status: 200, headers: [] },
    input.normalizationContext,
    { scenarioId: input.scenarioId, stepId: input.stepId }
  );
};

/* eslint-enable complexity, max-lines, max-params */
