/* eslint-disable complexity, max-lines, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One Native scenario keeps private callback credentials inside a bounded adapter flow and emits only a closed projection. */
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';
import {
  nativeCodePkceAdapter,
  type NativeCodePkceAdapter,
  type NativeCodePkceCompletionAttempt,
} from '../native-code-pkce-adapter.js';
import { fetchPhase2Discovery, requestPhase2Json } from '../runtime.js';
import { stopSelectedNativeAtCallback } from '../selected-native-callback.js';
import {
  withSelectedNativeFixture,
  type Phase2FixturePublicWithSelectedNative,
  type SelectedNativeFixtureOptions,
} from '../selected-native-fixture.js';

export const commonNativeScenarioIds = Object.freeze(['common.native.code-pkce'] as const);

export type CommonNativeCodePkceProjection = Readonly<{
  applicationType: 'Native';
  firstParty: true;
  pkce: 'S256';
  stateNonceDistinct: true;
  issuerBound: true;
  discoverySameOrigin: true;
  jwksSameOrigin: true;
  userinfoEndpoint: '/oidc/me';
  idTokenAlgorithm: 'ES384';
  expectedSubject: true;
  resourceToken: 'jwt';
  resourceScope: 'session:exchange';
  resourceTtlSeconds: 300;
  profileToken: 'opaque';
  profileSubject: true;
  resourceRefresh: 'jwt';
  resourceRefreshTtlSeconds: 300;
  targetOwnedCleanup: true;
}>;

export type CommonNativeScenarioResult = Readonly<{
  id: (typeof commonNativeScenarioIds)[number];
  projection: CommonNativeCodePkceProjection;
}>;

type SelectedFixture = ProvisionedPhase2Fixture & {
  public: Phase2FixturePublicWithSelectedNative;
};

export type CommonNativeScenarioContext = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  managementRequest: Phase2AdminRequestFunction;
  jwks: Readonly<JSONWebKeySet>;
  requestFetch?: typeof fetch;
  now?: () => number;
  adapter?: NativeCodePkceAdapter;
  prepareCallback?: typeof stopSelectedNativeAtCallback;
  withFixture?: typeof withSelectedNativeFixture;
  getSelectedNativePassword?: () => string;
}>;

const diagnostic = 'Invalid Phase 2 common Native scenario';
const fail = (): never => {
  throw new TypeError(diagnostic);
};

const record = (value: unknown): Readonly<Record<string, unknown>> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  return value as Readonly<Record<string, unknown>>;
};

const bounded = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  ![...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x1f || code === 0x7f;
  })
    ? value
    : fail();

const exactEndpoint = (value: unknown, expected: URL): URL => {
  const endpoint = new URL(bounded(value));
  if (
    endpoint.href !== expected.href ||
    endpoint.origin !== expected.origin ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash
  ) {
    return fail();
  }
  return endpoint;
};

export const validateCommonNativeDiscovery = (
  target: TargetConfig,
  value: unknown
): Readonly<{ issuer: string; jwksUri: string }> => {
  const discovery = record(value);
  const issuer = new URL('/oidc', target.coreUrl);
  const jwks = new URL('/oidc/jwks', target.coreUrl);
  const userinfo = new URL('/oidc/me', target.coreUrl);
  exactEndpoint(discovery.issuer, issuer);
  exactEndpoint(discovery.jwks_uri, jwks);
  exactEndpoint(discovery.userinfo_endpoint, userinfo);
  return Object.freeze({ issuer: issuer.href, jwksUri: jwks.href });
};

const compactKind = (value: string): 'jwt' | 'opaque' =>
  value.split('.').length === 3 ? 'jwt' : 'opaque';

const verifyResourceJwt = async (
  token: string,
  jwks: Readonly<JSONWebKeySet>,
  expected: Readonly<{
    issuer: string;
    audience: string;
    subject: string;
    clientId: string;
    scope: 'session:exchange';
  }>,
  now: number
): Promise<JWTPayload> => {
  const verified = await jwtVerify(token, createLocalJWKSet(jwks), {
    algorithms: ['ES384'],
    issuer: expected.issuer,
    audience: expected.audience,
    currentDate: new Date(now * 1000),
    clockTolerance: 15,
    requiredClaims: ['sub', 'iat', 'exp'],
  }).catch(fail);
  if (
    verified.protectedHeader.typ !== 'at+jwt' ||
    verified.payload.sub !== expected.subject ||
    verified.payload.client_id !== expected.clientId ||
    verified.payload.scope !== expected.scope ||
    !Number.isInteger(verified.payload.iat) ||
    !Number.isInteger(verified.payload.exp) ||
    Number(verified.payload.iat) > now + 15 ||
    Number(verified.payload.exp) - Number(verified.payload.iat) !== 300
  ) {
    return fail();
  }
  return verified.payload;
};

const captureLatestRefresh =
  (
    requestFetch: typeof fetch,
    tokenEndpoint: string,
    capture: (grantType: 'authorization_code' | 'refresh_token', refresh: string) => void
  ): typeof fetch =>
  async (input, init) => {
    const response = await requestFetch(input, init);
    const body = init?.body;
    if (
      String(input) === tokenEndpoint &&
      body instanceof URLSearchParams &&
      (body.get('grant_type') === 'authorization_code' ||
        body.get('grant_type') === 'refresh_token') &&
      response.status === 200
    ) {
      const value = record(await response.clone().json());
      capture(
        body.get('grant_type') === 'authorization_code' ? 'authorization_code' : 'refresh_token',
        bounded(value.refresh_token)
      );
    }
    return response;
  };

export const observeCommonNativeCodePkce = async (
  context: Omit<CommonNativeScenarioContext, 'fixture' | 'managementRequest' | 'withFixture'> &
    Readonly<{ fixture: SelectedFixture }>
): Promise<CommonNativeCodePkceProjection> => {
  const requestFetch = context.requestFetch ?? fetch;
  const discovery = await fetchPhase2Discovery(context.target, requestFetch);
  const endpoints = validateCommonNativeDiscovery(context.target, discovery);
  const selected = context.fixture.public.selectedNative;
  const prepareCallback = context.prepareCallback ?? stopSelectedNativeAtCallback;
  const handoff = await prepareCallback(
    context.target,
    context.fixture,
    endpoints.issuer,
    requestFetch,
    context.getSelectedNativePassword
      ? { getSelectedNativePassword: context.getSelectedNativePassword }
      : undefined
  );
  if (
    handoff.getState() === handoff.getNonce() ||
    handoff.getExpectedSubject() !== selected.identity.id
  ) {
    return fail();
  }
  let initialRefresh: string | undefined;
  let rotatedRefresh: string | undefined;
  const tokenEndpoint = new URL('/oidc/token', context.target.coreUrl).href;
  const fetcher = captureLatestRefresh(requestFetch, tokenEndpoint, (grantType, refresh) => {
    if (grantType === 'authorization_code') {
      initialRefresh = refresh;
    } else {
      rotatedRefresh = refresh;
    }
  });
  const clock = context.now ?? (() => Math.floor(Date.now() / 1000));
  const now = clock();
  if (!Number.isSafeInteger(now) || now <= 0) {
    return fail();
  }
  const config = Object.freeze({
    issuer: endpoints.issuer,
    clientId: selected.clientId,
    redirectUri: selected.redirectUri,
    resource: selected.resource.indicator,
    resourceScope: 'session:exchange' as const,
    idTokenAlgorithm: 'ES384' as const,
  });
  const credentials = await (context.adapter ?? nativeCodePkceAdapter).completeNativeCallback({
    callbackUrl: handoff.getCallbackUrl(),
    attempt: handoff as NativeCodePkceCompletionAttempt,
    config,
    jwks: context.jwks,
    fetcher,
    now,
  });
  const resourceAccess = credentials.getResourceAccessToken();
  const profileAccess = credentials.getProfileAccessToken();
  const expected = Object.freeze({
    issuer: endpoints.issuer,
    audience: selected.resource.indicator,
    subject: selected.identity.id,
    clientId: selected.clientId,
    scope: 'session:exchange' as const,
  });
  await verifyResourceJwt(resourceAccess, context.jwks, expected, now);
  if (
    credentials.subject !== selected.identity.id ||
    record(credentials.profile).sub !== selected.identity.id ||
    initialRefresh === undefined ||
    rotatedRefresh === undefined ||
    rotatedRefresh === initialRefresh ||
    compactKind(profileAccess) !== 'opaque'
  ) {
    return fail();
  }
  const refreshed = await requestPhase2Json(
    {
      url: new URL(tokenEndpoint),
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: rotatedRefresh,
        client_id: selected.clientId,
        resource: selected.resource.indicator,
        scope: 'session:exchange',
      }),
      signal: AbortSignal.timeout(10_000),
    },
    requestFetch
  );
  const refreshBody = record(refreshed.body);
  const refreshedAccess = bounded(refreshBody.access_token);
  if (refreshed.status !== 200 || compactKind(refreshedAccess) !== 'jwt') {
    return fail();
  }
  const refreshedNow = clock();
  if (!Number.isSafeInteger(refreshedNow) || refreshedNow <= 0) {
    return fail();
  }
  await verifyResourceJwt(refreshedAccess, context.jwks, expected, refreshedNow);
  let serializationRejected = false;
  try {
    credentials.toJSON();
  } catch {
    serializationRejected = true;
  }
  if (!serializationRejected) {
    return fail();
  }
  return Object.freeze({
    applicationType: 'Native',
    firstParty: true,
    pkce: 'S256',
    stateNonceDistinct: true,
    issuerBound: true,
    discoverySameOrigin: true,
    jwksSameOrigin: true,
    userinfoEndpoint: '/oidc/me',
    idTokenAlgorithm: 'ES384',
    expectedSubject: true,
    resourceToken: 'jwt',
    resourceScope: 'session:exchange',
    resourceTtlSeconds: 300,
    profileToken: 'opaque',
    profileSubject: true,
    resourceRefresh: 'jwt',
    resourceRefreshTtlSeconds: 300,
    targetOwnedCleanup: true,
  });
};

export const createCommonNativeScenarioRegistry = (
  profile: Readonly<{ differentialScenarios: readonly string[] }>
): readonly [
  Readonly<{
    id: (typeof commonNativeScenarioIds)[number];
    run(context: CommonNativeScenarioContext): Promise<CommonNativeScenarioResult>;
  }>,
] => {
  const index = profile.differentialScenarios.indexOf(commonNativeScenarioIds[0]);
  if (index < 0 || profile.differentialScenarios[index] !== commonNativeScenarioIds[0]) {
    return fail();
  }
  return Object.freeze([
    Object.freeze({
      id: commonNativeScenarioIds[0],
      run: async (context: CommonNativeScenarioContext) => {
        const withFixture = context.withFixture ?? withSelectedNativeFixture;
        const projection = await withFixture(
          context.fixture,
          {
            request: context.managementRequest,
            target: context.target,
            ...(context.getSelectedNativePassword && {
              getSelectedNativePassword: context.getSelectedNativePassword,
            }),
          } satisfies SelectedNativeFixtureOptions,
          async (fixture) =>
            observeCommonNativeCodePkce({
              target: context.target,
              fixture,
              jwks: context.jwks,
              ...(context.getSelectedNativePassword && {
                getSelectedNativePassword: context.getSelectedNativePassword,
              }),
              ...(context.requestFetch && { requestFetch: context.requestFetch }),
              ...(context.now && { now: context.now }),
              ...(context.adapter && { adapter: context.adapter }),
              ...(context.prepareCallback && { prepareCallback: context.prepareCallback }),
            })
        );
        return Object.freeze({ id: commonNativeScenarioIds[0], projection });
      },
    }),
  ]);
};

export const compareCommonNativeCodePkceProjections = (
  oracle: unknown,
  candidate: unknown
): readonly string[] =>
  JSON.stringify(oracle) === JSON.stringify(candidate) ? Object.freeze([]) : Object.freeze(['/']);

/* eslint-enable complexity, max-lines, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
