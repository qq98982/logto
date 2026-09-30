/* eslint-disable complexity, max-lines, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This credential boundary owns the private cookie jar and the complete Admin OIDC interaction. */
import { createHash, randomBytes } from 'node:crypto';

import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import { getPhase1FixtureRuntimeUsername } from '../../phase-1/fixture-map.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';

const diagnostic = 'Invalid Phase 2 Admin Management bearer flow';
const managementResource = 'urn:aster:resource:management';
const accountResource = 'urn:aster:resource:account';
const organizationResource = 'urn:aster:resource:organizations';
const clientId = 'admin-console';
const maximumBodyBytes = 16 * 1024;

export type Phase2AdminManagementBearerOptions = Readonly<{
  fetch?: typeof fetch;
  codeVerifier?: () => string;
  state?: () => string;
}>;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const bounded = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

const readJson = async (response: Response): Promise<Record<string, unknown>> => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBodyBytes)) {
    return fail();
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > maximumBodyBytes) {
    return fail();
  }
  const value: unknown = JSON.parse(text);
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  return value as Record<string, unknown>;
};

const requireStatus = async (response: Response, status: number): Promise<Response> => {
  if (response.status !== status || response.redirected) {
    await response.body?.cancel();
    return fail();
  }
  return response;
};

const discard = async (response: Response): Promise<void> => {
  await response.body?.cancel();
};

const mergeCookies = (cookies: Map<string, string>, response: Response): void => {
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (
      separator <= 0 ||
      !/^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(name) ||
      Buffer.byteLength(value) > 4096 ||
      /[\u0000-\u001F\u007F;]/u.test(value)
    ) {
      fail();
    }
    if (value.length === 0) {
      cookies.delete(name);
    } else {
      cookies.set(name, value);
    }
    if (cookies.size > 16) {
      fail();
    }
  }
};

const cookieHeader = (cookies: Map<string, string>): string =>
  [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');

const localUrl = (value: unknown, origin: URL): URL => {
  const url = new URL(bounded(value), origin);
  if (url.origin !== origin.origin || url.username || url.password || url.hash) {
    return fail();
  }
  return url;
};

const callbackCode = (
  response: Response,
  redirectUri: URL,
  state: string,
  issuer: string
): string => {
  const callback = localUrl(response.headers.get('location'), redirectUri);
  const codes = callback.searchParams.getAll('code');
  const states = callback.searchParams.getAll('state');
  const issuers = callback.searchParams.getAll('iss');
  if (
    callback.origin !== redirectUri.origin ||
    callback.pathname !== redirectUri.pathname ||
    codes.length !== 1 ||
    states.length !== 1 ||
    states[0] !== state ||
    issuers.length !== 1 ||
    issuers[0] !== issuer ||
    callback.searchParams.has('error') ||
    Array.from(callback.searchParams.keys()).some((key) => !['code', 'state', 'iss'].includes(key))
  ) {
    return fail();
  }
  return bounded(codes[0], 4096);
};

export const withPhase2AdminManagementBearer = async <Result>(
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'public' | 'withSecretLease'>,
  use: (bearer: string, lease: Phase2FixtureSecretLease) => Promise<Result>,
  options: Phase2AdminManagementBearerOptions = {}
): Promise<Result> => {
  let stage = 'admission';
  try {
    const target = validateTargetConfig(targetInput);
    const allocationId = fixture.public.admin?.allocationId ?? fail();
    if (typeof use !== 'function') {
      return fail();
    }
    const requestFetch = options.fetch ?? fetch;
    const verifier = bounded(
      (options.codeVerifier ?? (() => randomBytes(48).toString('base64url')))(),
      128
    );
    const state = bounded((options.state ?? (() => randomBytes(32).toString('base64url')))(), 128);
    if (!/^[A-Za-z0-9._~-]{43,128}$/u.test(verifier)) {
      return fail();
    }
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const origin = new URL(target.adminUrl);
    const issuer = new URL('/oidc', origin).href.replace(/\/$/u, '');
    const redirectUri = new URL('/console/callback', origin);
    const cookies = new Map<string, string>();
    const endpoint = (path: string): URL => new URL(path, origin);
    const send = async (
      url: URL,
      method: 'GET' | 'POST' | 'PUT',
      body?: Readonly<Record<string, unknown>> | URLSearchParams,
      includeCookies = true
    ): Promise<Response> => {
      const headers = new Headers();
      if (includeCookies && cookies.size > 0) {
        headers.set('cookie', cookieHeader(cookies));
      }
      if (body !== undefined) {
        headers.set(
          'content-type',
          body instanceof URLSearchParams ? 'application/x-www-form-urlencoded' : 'application/json'
        );
      }
      const response = await requestFetch(url, {
        method,
        headers,
        ...(body === undefined
          ? {}
          : { body: body instanceof URLSearchParams ? body : JSON.stringify(body) }),
        redirect: 'manual',
        signal: AbortSignal.timeout(10_000),
      });
      if (includeCookies) {
        mergeCookies(cookies, response);
      }
      return response;
    };
    let refreshToken: string | undefined;
    try {
      return await fixture.withSecretLease(async (lease) => {
        const password = bounded(lease.getAdminPassword?.() ?? fail(), 256);
        const authorization = endpoint('/oidc/auth');
        authorization.search = new URLSearchParams({
          client_id: clientId,
          redirect_uri: redirectUri.href,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state,
          response_type: 'code',
          prompt: 'login consent',
          scope:
            'openid offline_access profile email phone identities custom_data ' +
            'urn:aster:scope:organizations urn:aster:scope:organization_roles all',
        }).toString();
        for (const resource of [managementResource, accountResource, organizationResource]) {
          authorization.searchParams.append('resource', resource);
        }
        stage = 'authorization';
        await discard(await requireStatus(await send(authorization, 'GET'), 303));
        stage = 'bootstrap';
        await discard(
          await requireStatus(
            await send(endpoint('/api/experience'), 'PUT', { interactionEvent: 'SignIn' }),
            204
          )
        );
        stage = 'password';
        const verified = await readJson(
          await requireStatus(
            await send(endpoint('/api/experience/verification/password'), 'POST', {
              identifier: {
                type: 'username',
                value: getPhase1FixtureRuntimeUsername('phase1-admin', allocationId),
              },
              password,
            }),
            200
          )
        );
        const verificationId = bounded(verified.verificationId, 4096);
        stage = 'identification';
        await discard(
          await requireStatus(
            await send(endpoint('/api/experience/identification'), 'POST', { verificationId }),
            204
          )
        );
        stage = 'submit';
        const submitted = await readJson(
          await requireStatus(await send(endpoint('/api/experience/submit'), 'POST'), 200)
        );
        stage = 'bridge';
        const bridge = await requireStatus(
          await send(localUrl(submitted.redirectTo, origin), 'GET'),
          303
        );
        const consentUrl = localUrl(bridge.headers.get('location'), origin);
        await bridge.body?.cancel();
        if (
          consentUrl.pathname !== '/consent' ||
          consentUrl.searchParams.get('app_id') !== clientId
        ) {
          return fail();
        }
        stage = 'consent';
        const consent = await requireStatus(await send(consentUrl, 'GET'), 302);
        const resumeUrl = localUrl(consent.headers.get('location'), origin);
        await consent.body?.cancel();
        stage = 'resume';
        const resumed = await requireStatus(await send(resumeUrl, 'GET'), 303);
        const code = callbackCode(resumed, redirectUri, state, issuer);
        await resumed.body?.cancel();
        stage = 'code-token';
        const initial = await readJson(
          await requireStatus(
            await send(
              endpoint('/oidc/token'),
              'POST',
              new URLSearchParams({
                client_id: clientId,
                code,
                code_verifier: verifier,
                redirect_uri: redirectUri.href,
                grant_type: 'authorization_code',
              }),
              false
            ),
            200
          )
        );
        const initialAccess = bounded(initial.access_token);
        const initialId = bounded(initial.id_token);
        refreshToken = bounded(initial.refresh_token);
        if (
          initial.token_type !== 'Bearer' ||
          new Set([initialAccess, initialId, refreshToken]).size !== 3
        ) {
          return fail();
        }
        stage = 'management-refresh';
        const refreshed = await readJson(
          await requireStatus(
            await send(
              endpoint('/oidc/token'),
              'POST',
              new URLSearchParams({
                client_id: clientId,
                refresh_token: refreshToken,
                grant_type: 'refresh_token',
                resource: managementResource,
              }),
              false
            ),
            200
          )
        );
        const bearer = bounded(refreshed.access_token);
        const refreshedId = bounded(refreshed.id_token);
        const rotatedRefresh = bounded(refreshed.refresh_token);
        if (
          refreshed.token_type !== 'Bearer' ||
          refreshed.scope !== 'all' ||
          rotatedRefresh === refreshToken ||
          new Set([bearer, refreshedId, rotatedRefresh]).size !== 3
        ) {
          return fail();
        }
        refreshToken = rotatedRefresh;
        stage = 'jwks';
        const jwksBody = await readJson(
          await requireStatus(await send(endpoint('/oidc/jwks'), 'GET', undefined, false), 200)
        );
        if (!Array.isArray(jwksBody.keys) || jwksBody.keys.length === 0) {
          return fail();
        }
        const jwks = jwksBody as unknown as JSONWebKeySet;
        const verifiedBearer = await jwtVerify(bearer, createLocalJWKSet(jwks), {
          issuer,
          audience: managementResource,
        });
        if (
          verifiedBearer.payload.client_id !== clientId ||
          verifiedBearer.payload.scope !== 'all' ||
          Object.hasOwn(verifiedBearer.payload, 'organization_id')
        ) {
          return fail();
        }
        stage = 'consumer';
        return use(bearer, lease);
      });
    } finally {
      cookies.clear();
      if (refreshToken) {
        try {
          const revocation = await send(
            endpoint('/oidc/token/revocation'),
            'POST',
            new URLSearchParams({
              client_id: clientId,
              token: refreshToken,
              token_type_hint: 'refresh_token',
            }),
            false
          );
          await revocation.body?.cancel();
        } catch {
          // Revocation is best effort after the bounded credential callback exits.
        }
      }
    }
  } catch {
    throw new TypeError(`${diagnostic} (${stage})`);
  }
};

/* eslint-enable complexity, max-lines, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
