/* eslint-disable complexity, max-lines, max-params, no-restricted-syntax, no-await-in-loop, no-control-regex, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This bounded transport keeps cookies, password, verifier and issued credentials inside one private flow. */
import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export type IssuedPublicUserTokens = Readonly<{
  access: string;
  refresh: string;
  toJSON(): never;
}>;

export type IssuedPublicUserSession = IssuedPublicUserTokens &
  Readonly<{
    getIdToken(): string;
    getCookieHeader(): string;
  }>;

export type NativeCallbackClient = Readonly<{
  clientId: string;
  redirectUri: string;
  expectedIssuer: string;
  resourceIndicator: string;
  resourceScope: string;
}>;

export type NativeCallbackHandoff = Readonly<{
  getCallbackUrl(): string;
  getVerifier(): string;
  getState(): string;
  getNonce(): string;
  getExpectedSubject(): string;
  toJSON(): never;
}>;

export type NativeCallbackIdentityFixture = Readonly<{
  identity?: Readonly<{ id: string; primaryEmail: string }>;
  withSecretLease<Result>(
    use: (
      lease: Readonly<{ getSelectedNativePassword?(): string; toJSON(): never }>
    ) => Promise<Result>
  ): Promise<Result>;
}>;

const diagnostic = 'Invalid Phase 2 public user token issuance';
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

const jsonBody = async (response: Response): Promise<Record<string, unknown>> => {
  const maximum = 16 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    return fail();
  }
  const reader = response.body?.getReader();
  if (!reader) {
    return fail();
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    // eslint-disable-next-line no-constant-condition -- The response reader terminates on done.
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        return fail();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const parsed: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.getPrototypeOf(parsed) !== Object.prototype
  ) {
    return fail();
  }
  return parsed as Record<string, unknown>;
};

const requireStatus = async (response: Response, expected: number): Promise<Response> => {
  if (response.status !== expected || response.redirected) {
    await response.body?.cancel();
    return fail();
  }
  return response;
};

const discard = async (response: Response): Promise<void> => {
  await response.body?.cancel();
};

const mergeCookies = (jar: Map<string, string>, response: Response): void => {
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
      jar.delete(name);
    } else {
      jar.set(name, value);
    }
    if (jar.size > 16) {
      fail();
    }
  }
};

const cookieHeader = (jar: Map<string, string>): string =>
  [...jar].map(([name, value]) => `${name}=${value}`).join('; ');

const localRedirect = (value: unknown, origin: URL): URL => {
  const destination = new URL(bounded(value), origin);
  if (destination.origin !== origin.origin || destination.username || destination.password) {
    return fail();
  }
  return destination;
};

const issueUserTokens = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  clientKind: 'public' | 'confidential',
  captureBrowserSession: boolean,
  requestFetch: typeof fetch = fetch,
  options: Readonly<{
    subjectPassword?: string;
    subjectUsername?: string;
    subjectIdentifier?: Readonly<{ type: 'username' | 'email'; value: string }>;
    resourceAtCodeExchange?: boolean;
    signal?: AbortSignal;
    nativeClient?: NativeCallbackClient;
    nativeIdentityFixture?: NativeCallbackIdentityFixture;
    stopAtNativeCallback?: boolean;
    authorizationResources?: readonly string[];
    authorizationScope?: string;
  }> = {}
): Promise<IssuedPublicUserTokens | IssuedPublicUserSession | NativeCallbackHandoff> => {
  let stage = 'admission';
  try {
    const target = validateTargetConfig(targetInput);
    const status = fixture.status ?? fail();
    if (
      options.nativeClient &&
      (options.nativeClient.clientId === status.client.id ||
        options.nativeClient.resourceScope !== 'session:exchange')
    ) {
      return fail();
    }
    const nativeIdentity = options.nativeIdentityFixture?.identity;
    if (
      options.stopAtNativeCallback &&
      (!options.nativeIdentityFixture ||
        !nativeIdentity ||
        bounded(nativeIdentity.id, 256) !== nativeIdentity.id ||
        bounded(nativeIdentity.primaryEmail, 320) !== nativeIdentity.primaryEmail)
    ) {
      return fail();
    }
    if (options.stopAtNativeCallback) {
      await options.nativeIdentityFixture?.withSecretLease(async (lease) => {
        bounded(lease.getSelectedNativePassword?.(), 256);
      });
    }
    if (options.nativeClient) {
      const nativeRedirect = new URL(options.nativeClient.redirectUri);
      const expectedIssuer = new URL(options.nativeClient.expectedIssuer);
      if (
        nativeRedirect.search !== '' ||
        nativeRedirect.hash !== '' ||
        expectedIssuer.username !== '' ||
        expectedIssuer.password !== '' ||
        expectedIssuer.search !== '' ||
        expectedIssuer.hash !== ''
      ) {
        return fail();
      }
    }
    const client = options.nativeClient
      ? {
          id: bounded(options.nativeClient.clientId, 256),
          redirectUri: bounded(options.nativeClient.redirectUri),
        }
      : clientKind === 'confidential'
        ? status.confidentialClient
        : status.client;
    const resource = options.nativeClient?.resourceIndicator ?? status.resource.indicator;
    const resourceScope = options.nativeClient?.resourceScope ?? status.resource.scopeName;
    const origin = new URL(target.coreUrl);
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const state = options.stopAtNativeCallback ? randomBytes(32).toString('base64url') : undefined;
    const nonce = options.stopAtNativeCallback ? randomBytes(32).toString('base64url') : undefined;
    const cookies = new Map<string, string>();
    const endpoint = (path: string): URL => new URL(path, origin);
    const send = async (
      url: URL,
      method: 'GET' | 'POST' | 'PUT',
      body?: Readonly<Record<string, unknown>> | URLSearchParams,
      authorization?: string
    ): Promise<Response> => {
      const headers = new Headers();
      if (cookies.size > 0) {
        headers.set('cookie', cookieHeader(cookies));
      }
      if (body !== undefined) {
        headers.set(
          'content-type',
          body instanceof URLSearchParams ? 'application/x-www-form-urlencoded' : 'application/json'
        );
      }
      if (authorization !== undefined) {
        headers.set('authorization', authorization);
      }
      if (url.pathname.startsWith('/api/experience')) {
        headers.set(target.label === 'oracle' ? 'logto-app-id' : 'aster-app-id', client.id);
      }
      const response = await requestFetch(url, {
        method,
        headers,
        ...(body === undefined
          ? {}
          : { body: body instanceof URLSearchParams ? body : JSON.stringify(body) }),
        redirect: 'manual',
        signal: options.signal
          ? AbortSignal.any([options.signal, AbortSignal.timeout(10_000)])
          : AbortSignal.timeout(10_000),
      });
      mergeCookies(cookies, response);
      return response;
    };
    const authorization = endpoint('/oidc/auth');
    const authorizationQuery = new URLSearchParams({
      client_id: client.id,
      redirect_uri: client.redirectUri,
      response_type: 'code',
      prompt: 'login consent',
      scope:
        options.authorizationScope ??
        (options.stopAtNativeCallback
          ? `openid offline_access profile ${resourceScope}`
          : 'openid offline_access profile email address phone ' +
            resourceScope +
            (captureBrowserSession
              ? ` ${target.label === 'oracle' ? 'urn:logto:scope:sessions' : 'urn:aster:scope:sessions'}`
              : '')),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...(state === undefined ? {} : { state }),
      ...(nonce === undefined ? {} : { nonce }),
    });
    for (const requestedResource of options.authorizationResources ?? [resource]) {
      authorizationQuery.append('resource', bounded(requestedResource));
    }
    authorization.search = authorizationQuery.toString();
    stage = 'authorization';
    await discard(await requireStatus(await send(authorization, 'GET'), 303));
    stage = 'bootstrap';
    const identifyWithPassword = async (
      passwordInput: string,
      identifier: Readonly<{ type: 'username' | 'email'; value: string }>
    ) => {
      const password = bounded(passwordInput, 256);
      await discard(
        await requireStatus(
          await send(endpoint('/api/experience'), 'PUT', { interactionEvent: 'SignIn' }),
          204
        )
      );
      stage = 'verification';
      const verification = await jsonBody(
        await requireStatus(
          await send(endpoint('/api/experience/verification/password'), 'POST', {
            identifier: {
              type: identifier.type,
              value: identifier.value,
            },
            password,
          }),
          200
        )
      );
      const verificationId = bounded(verification.verificationId, 4096);
      stage = 'identification';
      await discard(
        await requireStatus(
          await send(endpoint('/api/experience/identification'), 'POST', { verificationId }),
          204
        )
      );
    };
    await (options.stopAtNativeCallback
      ? (options.nativeIdentityFixture?.withSecretLease(async (lease) =>
          identifyWithPassword(lease.getSelectedNativePassword?.() ?? fail(), {
            type: 'email',
            value: nativeIdentity?.primaryEmail ?? fail(),
          })
        ) ?? fail())
      : options.subjectPassword === undefined
        ? fixture.withSecretLease(async (lease) =>
            identifyWithPassword(lease.getSubjectPassword?.() ?? fail(), {
              type: 'username',
              value: options.subjectUsername ?? status.user.username,
            })
          )
        : identifyWithPassword(options.subjectPassword, {
            type: options.subjectIdentifier?.type ?? 'username',
            value:
              options.subjectIdentifier?.value ?? options.subjectUsername ?? status.user.username,
          }));
    stage = 'submit';
    const submitted = await jsonBody(
      await requireStatus(await send(endpoint('/api/experience/submit'), 'POST'), 200)
    );
    stage = 'bridge-url';
    const bridgeUrl = localRedirect(submitted.redirectTo, origin);
    stage = 'bridge-send';
    const bridgeResponse = await send(bridgeUrl, 'GET');
    stage =
      'bridge-http-' +
      (/^[1-5][0-9]{2}$/u.test(String(bridgeResponse.status))
        ? String(bridgeResponse.status)
        : 'other');
    const bridge = await requireStatus(bridgeResponse, 303);
    await bridge.body?.cancel();
    stage = 'consent-read';
    await discard(
      await requireStatus(await send(endpoint('/api/interaction/consent'), 'GET'), 200)
    );
    stage = 'consent-write';
    const consent = await jsonBody(
      await requireStatus(await send(endpoint('/api/interaction/consent'), 'POST', {}), 200)
    );
    stage = 'resume';
    const resumed = await requireStatus(
      await send(localRedirect(consent.redirectTo, origin), 'GET'),
      303
    );
    const location = new URL(bounded(resumed.headers.get('location')));
    await resumed.body?.cancel();
    const expectedRedirect = new URL(client.redirectUri);
    const invalidNativeCallback =
      options.stopAtNativeCallback &&
      (expectedRedirect.search !== '' ||
        expectedRedirect.hash !== '' ||
        location.protocol !== expectedRedirect.protocol ||
        location.username !== expectedRedirect.username ||
        location.password !== expectedRedirect.password ||
        location.hostname !== expectedRedirect.hostname ||
        location.port !== expectedRedirect.port ||
        location.pathname !== expectedRedirect.pathname ||
        location.hash !== '' ||
        [...location.searchParams.keys()].some(
          (key) => key !== 'code' && key !== 'state' && key !== 'iss'
        ) ||
        location.searchParams.getAll('code').length !== 1 ||
        location.searchParams.getAll('state').length !== 1 ||
        location.searchParams.get('state') !== state ||
        location.searchParams.getAll('iss').length !== 1 ||
        location.searchParams.get('iss') !== options.nativeClient?.expectedIssuer);
    if (
      options.stopAtNativeCallback
        ? invalidNativeCallback
        : location.origin + location.pathname !== client.redirectUri
    ) {
      return fail();
    }
    const code = bounded(location.searchParams.get('code'), 4096);
    if (options.stopAtNativeCallback) {
      if (!options.nativeClient || state === undefined || nonce === undefined) {
        return fail();
      }
      const callbackUrl = location.href;
      return Object.freeze({
        getCallbackUrl: () => callbackUrl,
        getVerifier: () => verifier,
        getState: () => state,
        getNonce: () => nonce,
        getExpectedSubject: () => nativeIdentity?.id ?? fail(),
        toJSON: (): never => fail(),
        [inspect.custom]: () => 'NativeCallbackHandoff(<redacted>)',
      });
    }
    stage = 'token-http';
    const exchangeCode = async (authorization?: string): Promise<Response> =>
      requireStatus(
        await send(
          endpoint('/oidc/token'),
          'POST',
          new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            code_verifier: verifier,
            redirect_uri: client.redirectUri,
            ...(options.resourceAtCodeExchange ? { resource } : {}),
            ...(clientKind === 'public' ? { client_id: client.id } : {}),
          }),
          authorization
        ),
        200
      );
    const tokenResponse =
      clientKind === 'public'
        ? await exchangeCode()
        : await fixture.withSecretLease(async (lease) => {
            const secret = bounded(lease.getStatusClientSecret(), 256);
            return exchangeCode(
              `Basic ${Buffer.from(`${client.id}:${secret}`).toString('base64')}`
            );
          });
    stage = 'token-body';
    const issued = await jsonBody(tokenResponse);
    stage = 'token-type';
    if (issued.token_type !== 'Bearer') {
      return fail();
    }
    stage = 'token-access';
    const access = bounded(issued.access_token);
    stage = 'token-refresh';
    const refresh = bounded(issued.refresh_token);
    if (access === refresh) {
      return fail();
    }
    if (captureBrowserSession) {
      const idToken = bounded(issued.id_token);
      const browserCookies = bounded(cookieHeader(cookies), 8192);
      return Object.freeze({
        access,
        refresh,
        getIdToken: () => idToken,
        getCookieHeader: () => browserCookies,
        toJSON: (): never => fail(),
      });
    }
    return Object.freeze({ access, refresh, toJSON: (): never => fail() });
  } catch {
    throw new TypeError(diagnostic + ' (' + stage + ')');
  }
};

export const stopPublicNativeAtCallback = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  nativeIdentityFixture: NativeCallbackIdentityFixture,
  nativeClient: NativeCallbackClient,
  requestFetch: typeof fetch = fetch
): Promise<NativeCallbackHandoff> =>
  issueUserTokens(targetInput, fixture, 'public', false, requestFetch, {
    nativeClient,
    nativeIdentityFixture,
    stopAtNativeCallback: true,
  }) as Promise<NativeCallbackHandoff>;

export const issuePublicUserTokens = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserTokens> =>
  issueUserTokens(
    targetInput,
    fixture,
    'public',
    false,
    requestFetch
  ) as Promise<IssuedPublicUserTokens>;

export const issuePublicUserResourceTokensWithPassword = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  subjectPassword: string,
  signal: AbortSignal,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserTokens> =>
  issueUserTokens(targetInput, fixture, 'public', false, requestFetch, {
    subjectPassword,
    resourceAtCodeExchange: true,
    signal,
  }) as Promise<IssuedPublicUserTokens>;

export const issuePublicUserTokensForSubject = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  subject: Readonly<{ username: string; password: string }>,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserTokens> =>
  issueUserTokens(targetInput, fixture, 'public', false, requestFetch, {
    subjectPassword: subject.password,
    subjectUsername: subject.username,
  }) as Promise<IssuedPublicUserTokens>;

export const issuePublicAccountTokensForSubject = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  subject: Readonly<{ username: string; password: string } | { email: string; password: string }>,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserTokens> =>
  issueUserTokens(targetInput, fixture, 'public', false, requestFetch, {
    subjectPassword: subject.password,
    subjectIdentifier:
      'email' in subject
        ? { type: 'email', value: subject.email }
        : { type: 'username', value: subject.username },
    authorizationResources: [],
    authorizationScope: 'openid offline_access profile email phone identities custom_data',
  }) as Promise<IssuedPublicUserTokens>;

export const issueConfidentialUserSession = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserSession> =>
  issueUserTokens(
    targetInput,
    fixture,
    'confidential',
    true,
    requestFetch
  ) as Promise<IssuedPublicUserSession>;

export const issueConfidentialUserTokens = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserTokens> =>
  issueUserTokens(
    targetInput,
    fixture,
    'confidential',
    false,
    requestFetch
  ) as Promise<IssuedPublicUserTokens>;

export const exchangePublicRefresh = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status'>,
  refreshToken: string,
  options: Readonly<{ resource: boolean; fetch?: typeof fetch }>
): Promise<IssuedPublicUserTokens> => {
  try {
    const target = validateTargetConfig(targetInput);
    const status = fixture.status ?? fail();
    const requestFetch = options.fetch ?? fetch;
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: bounded(refreshToken),
      client_id: status.client.id,
      ...(options.resource ? { resource: status.resource.indicator } : {}),
    });
    const response = await requireStatus(
      await requestFetch(new URL('/oidc/token', target.coreUrl), {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(10_000),
      }),
      200
    );
    const issued = await jsonBody(response);
    if (issued.token_type !== 'Bearer') {
      return fail();
    }
    const access = bounded(issued.access_token);
    const refresh = bounded(issued.refresh_token);
    if (access === refresh || (options.resource && access.split('.').length !== 3)) {
      return fail();
    }
    return Object.freeze({ access, refresh, toJSON: (): never => fail() });
  } catch {
    return fail();
  }
};
/* eslint-enable complexity, max-lines, max-params, no-restricted-syntax, no-await-in-loop, no-control-regex, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
