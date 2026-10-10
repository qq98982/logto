/* eslint-disable max-lines, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake transport records the private authorization sequence and bounded Native callback matrix. */
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  exchangePublicRefresh,
  issueConfidentialUserSession,
  issueConfidentialUserTokens,
  issuePublicAccountTokensForSubject,
  issuePublicUserTokens,
  stopPublicNativeAtCallback,
} from './user-token-issuance.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const expectedIssuer = 'https://identity.example/oidc';

const fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'> = {
  status: {
    user: { id: 'user', username: 'status-user' },
    client: { id: 'public-client', redirectUri: 'https://client.example/callback' },
    confidentialClient: {
      id: 'confidential-client',
      redirectUri: 'https://client.example/callback',
    },
    resource: { id: 'resource', indicator: 'https://api.example.com', scopeName: 'read:profile' },
  },
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use({
      getClientSecret: () => 'unused-private-client-secret',
      getStatusClientSecret: () => 'private-status-client-secret',
      getSubjectPassword: () => 'private-password',
      toJSON: (): never => {
        throw new Error('secret lease');
      },
    }),
};
const nativeIdentityFixture = {
  identity: { id: 'selected-native-user', primaryEmail: 'native@example.com' },
  withSecretLease: async <Result>(
    use: (
      lease: Readonly<{ getSelectedNativePassword(): string; toJSON(): never }>
    ) => Promise<Result>
  ): Promise<Result> =>
    use({
      getSelectedNativePassword: () => 'private-native-password',
      toJSON: (): never => {
        throw new Error('native identity secret lease');
      },
    }),
};

const response = (status: number, body?: unknown, headers?: HeadersInit): Response =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
  });

const flow = (
  override: Readonly<{ step: number; response: Response }> | undefined = undefined
): Readonly<{ fetch: typeof fetch; requests: Array<{ url: URL; init: RequestInit }> }> => {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const replies = [
    response(303, undefined, { 'set-cookie': 'aster-session=private-cookie; Path=/; HttpOnly' }),
    response(204, undefined, { 'set-cookie': 'aster-interaction=; Path=/; Max-Age=0' }),
    response(200, { verificationId: 'private-verification' }),
    response(204),
    response(200, { redirectTo: 'https://candidate.example/oidc/bridge' }),
    response(303),
    response(200, {}),
    response(200, { redirectTo: 'https://candidate.example/oidc/resume' }),
    response(303, undefined, { location: 'https://client.example/callback?code=private-code' }),
    response(200, {
      access_token: 'private-access',
      refresh_token: 'private-refresh',
      id_token: 'private-id-token',
      token_type: 'Bearer',
    }),
  ];
  if (override) {
    replies[override.step] = override.response;
  }
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    requests.push({ url: new URL(String(input)), init: init ?? {} });
    return replies[requests.length - 1] ?? response(500, { private: 'unexpected' });
  }) as typeof fetch;
  return { fetch: requestFetch, requests };
};

const nativeCallbackFlow = (
  callback: (state: string) => string
): Readonly<{ fetch: typeof fetch; requests: Array<{ url: URL; init: RequestInit }> }> => {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const replies = [
    response(303, undefined, { 'set-cookie': 'aster-session=private-cookie; Path=/; HttpOnly' }),
    response(204),
    response(200, { verificationId: 'private-verification' }),
    response(204),
    response(200, { redirectTo: 'https://candidate.example/oidc/bridge' }),
    response(303),
    response(200, {}),
    response(200, { redirectTo: 'https://candidate.example/oidc/resume' }),
  ];
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    requests.push({ url: new URL(String(input)), init: init ?? {} });
    if (requests.length === 9) {
      return response(303, undefined, {
        location: callback(requests[0]?.url.searchParams.get('state') ?? ''),
      });
    }
    return replies[requests.length - 1] ?? response(500, { private: 'unexpected' });
  }) as typeof fetch;
  return { fetch: requestFetch, requests };
};

describe('Phase 2 public user token issuance transport', () => {
  it('stops an explicitly selected Native client at its exact state-bound callback before exchange', async () => {
    const requests: Array<{ url: URL; init: RequestInit }> = [];
    const replies = [
      response(303, undefined, { 'set-cookie': 'aster-session=private-cookie; Path=/; HttpOnly' }),
      response(204),
      response(200, { verificationId: 'private-verification' }),
      response(204),
      response(200, { redirectTo: 'https://candidate.example/oidc/bridge' }),
      response(303),
      response(200, {}),
      response(200, { redirectTo: 'https://candidate.example/oidc/resume' }),
    ];
    const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      const url = new URL(String(input));
      requests.push({ url, init: init ?? {} });
      if (requests.length === 9) {
        const state = requests[0]?.url.searchParams.get('state');
        return response(303, undefined, {
          location: `https://native.example/logto-callback?code=private-code&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
        });
      }
      return replies[requests.length - 1] ?? response(500, { private: 'unexpected' });
    }) as typeof fetch;
    const handoff = await stopPublicNativeAtCallback(
      target,
      fixture,
      nativeIdentityFixture,
      {
        clientId: 'actual-native-client',
        redirectUri: 'https://native.example/logto-callback',
        expectedIssuer,
        resourceIndicator: 'https://native-api.example/api',
        resourceScope: 'session:exchange',
      },
      requestFetch
    );

    expect(requests).toHaveLength(9);
    expect(requests.some(({ url }) => url.pathname === '/oidc/token')).toBe(false);
    expect(requests[0]?.url.searchParams.get('client_id')).toBe('actual-native-client');
    expect(requests[0]?.url.searchParams.get('scope')).toBe(
      'openid offline_access profile session:exchange'
    );
    expect(requests[0]?.url.searchParams.get('resource')).toBe('https://native-api.example/api');
    expect(JSON.parse(String(requests[2]?.init.body))).toEqual({
      identifier: { type: 'email', value: 'native@example.com' },
      password: 'private-native-password',
    });
    expect(handoff.getCallbackUrl()).toBe(
      `https://native.example/logto-callback?code=private-code&state=${handoff.getState()}&iss=${encodeURIComponent(expectedIssuer)}`
    );
    expect(requests[0]?.url.searchParams.get('state')).toBe(handoff.getState());
    expect(requests[0]?.url.searchParams.get('nonce')).toBe(handoff.getNonce());
    expect(handoff.getExpectedSubject()).toBe('selected-native-user');
    expect(handoff.getVerifier()).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(inspect(handoff)).toBe('NativeCallbackHandoff(<redacted>)');
    expect(() => JSON.stringify(handoff)).toThrow('Invalid Phase 2 public user token issuance');
  });

  it('refuses generic-client fallback before starting a Native authorization', async () => {
    const calls = { value: 0 };
    await expect(
      stopPublicNativeAtCallback(
        target,
        fixture,
        nativeIdentityFixture,
        {
          clientId: 'public-client',
          redirectUri: 'https://native.example/logto-callback',
          expectedIssuer,
          resourceIndicator: 'https://native-api.example/api',
          resourceScope: 'session:exchange',
        },
        async () => {
          calls.value += 1;
          return response(500);
        }
      )
    ).rejects.toThrow('Invalid Phase 2 public user token issuance (admission)');
    expect(calls.value).toBe(0);
  });

  it.each([
    [
      'identity',
      {
        withSecretLease: async <Result>(
          use: (
            lease: Readonly<{ getSelectedNativePassword(): string; toJSON(): never }>
          ) => Promise<Result>
        ) =>
          use({
            getSelectedNativePassword: () => 'private-native-password',
            toJSON: (): never => {
              throw new Error('native identity secret lease');
            },
          }),
      },
    ],
    [
      'dedicated password getter',
      {
        identity: { id: 'selected-native-user', primaryEmail: 'native@example.com' },
        withSecretLease: async <Result>(
          use: (lease: Readonly<{ toJSON(): never }>) => Promise<Result>
        ) =>
          use({
            toJSON: (): never => {
              throw new Error('native identity secret lease');
            },
          }),
      },
    ],
  ])('rejects missing selected Native %s before network use', async (_name, identityFixture) => {
    const calls = { value: 0 };
    await expect(
      stopPublicNativeAtCallback(
        target,
        fixture,
        identityFixture,
        {
          clientId: 'actual-native-client',
          redirectUri: 'https://native.example/logto-callback',
          expectedIssuer,
          resourceIndicator: 'https://native-api.example/api',
          resourceScope: 'session:exchange',
        },
        async () => {
          calls.value += 1;
          return response(500);
        }
      )
    ).rejects.toThrow('Invalid Phase 2 public user token issuance (admission)');
    expect(calls.value).toBe(0);
  });

  it.each([
    [
      'wrong state',
      'https://native.example/logto-callback',
      (state: string) =>
        `https://native.example/logto-callback?code=x&state=${state}x&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign HTTPS host',
      'https://native.example/logto-callback',
      (state: string) =>
        `https://foreign.example/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign HTTPS port',
      'https://native.example/logto-callback',
      (state: string) =>
        `https://native.example:444/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign HTTPS path',
      'https://native.example/logto-callback',
      (state: string) =>
        `https://native.example/foreign-path?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign custom scheme',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `foreign://mobile/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign custom host',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://foreign/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign custom path',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/foreign-path?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'foreign credentials',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://user@mobile/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'duplicate code',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/logto-callback?code=x&code=y&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'duplicate state',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/logto-callback?code=x&state=${state}&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'callback error',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/logto-callback?error=denied&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
    [
      'extra response field',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}&extra=value`,
    ],
    [
      'missing issuer',
      'box-ai://mobile/logto-callback',
      (state: string) => `box-ai://mobile/logto-callback?code=x&state=${state}`,
    ],
    [
      'wrong issuer',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/logto-callback?code=x&state=${state}&iss=${encodeURIComponent('https://foreign.example/oidc')}`,
    ],
    [
      'duplicate issuer',
      'box-ai://mobile/logto-callback',
      (state: string) =>
        `box-ai://mobile/logto-callback?code=x&state=${state}&iss=${encodeURIComponent(expectedIssuer)}&iss=${encodeURIComponent(expectedIssuer)}`,
    ],
  ])('rejects Native %s before token exchange', async (_name, redirectUri, callback) => {
    const transport = nativeCallbackFlow(callback);
    await expect(
      stopPublicNativeAtCallback(
        target,
        fixture,
        nativeIdentityFixture,
        {
          clientId: 'actual-native-client',
          redirectUri,
          expectedIssuer,
          resourceIndicator: 'https://native-api.example/api',
          resourceScope: 'session:exchange',
        },
        transport.fetch
      )
    ).rejects.toThrow('Invalid Phase 2 public user token issuance (resume)');
    expect(transport.requests.some(({ url }) => url.pathname === '/oidc/token')).toBe(false);
  });

  it.each([
    'box-ai://mobile/logto-callback?registered=query',
    'box-ai://mobile/logto-callback#registered-fragment',
  ])('rejects configured Native query or fragment before network use', async (redirectUri) => {
    const calls = { value: 0 };
    await expect(
      stopPublicNativeAtCallback(
        target,
        fixture,
        nativeIdentityFixture,
        {
          clientId: 'actual-native-client',
          redirectUri,
          expectedIssuer,
          resourceIndicator: 'https://native-api.example/api',
          resourceScope: 'session:exchange',
        },
        async () => {
          calls.value += 1;
          return response(500);
        }
      )
    ).rejects.toThrow('Invalid Phase 2 public user token issuance (admission)');
    expect(calls.value).toBe(0);
  });

  it('rotates a public refresh credential for the fixture resource without exposing it', async () => {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      requests.push({ url: String(input), init: init ?? {} });
      return response(200, {
        access_token: 'header.payload.signature',
        refresh_token: 'private-rotated-refresh',
        token_type: 'Bearer',
      });
    }) as typeof fetch;
    const tokens = await exchangePublicRefresh(target, fixture, 'private-original-refresh', {
      resource: true,
      fetch: requestFetch,
    });
    expect(tokens.access).toBe('header.payload.signature');
    expect(tokens.refresh).toBe('private-rotated-refresh');
    expect(() => JSON.stringify(tokens)).toThrow('Invalid Phase 2 public user token issuance');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe('https://candidate.example/oidc/token');
    expect(Object.fromEntries(new URLSearchParams(String(requests[0]?.init.body)))).toEqual({
      grant_type: 'refresh_token',
      refresh_token: 'private-original-refresh',
      client_id: 'public-client',
      resource: 'https://api.example.com',
    });
    expect(new Headers(requests[0]?.init.headers).has('authorization')).toBe(false);
  });

  it('issues opaque access and refresh through password, consent and public PKCE', async () => {
    const transport = flow();
    const tokens = await issuePublicUserTokens(target, fixture, transport.fetch);
    expect(tokens.access).toBe('private-access');
    expect(tokens.refresh).toBe('private-refresh');
    expect(() => JSON.stringify(tokens)).toThrow('Invalid Phase 2 public user token issuance');
    expect(transport.requests).toHaveLength(10);
    expect(transport.requests.map(({ url }) => url.pathname)).toEqual([
      '/oidc/auth',
      '/api/experience',
      '/api/experience/verification/password',
      '/api/experience/identification',
      '/api/experience/submit',
      '/oidc/bridge',
      '/api/interaction/consent',
      '/api/interaction/consent',
      '/oidc/resume',
      '/oidc/token',
    ]);
    expect(transport.requests[0]?.url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(transport.requests[0]?.url.searchParams.get('scope')).toBe(
      'openid offline_access profile email address phone read:profile'
    );
    expect(transport.requests[0]?.url.searchParams.get('prompt')).toBe('login consent');
    expect(transport.requests[0]?.url.searchParams.get('resource')).toBe('https://api.example.com');
    const verification = transport.requests[2];
    expect(new Headers(verification?.init.headers).get('cookie')).toBe(
      'aster-session=private-cookie'
    );
    expect(JSON.parse(String(verification?.init.body))).toMatchObject({
      identifier: { type: 'username', value: 'status-user' },
      password: 'private-password',
    });
    const form = new URLSearchParams(String(transport.requests[9]?.init.body));
    expect(form.get('client_id')).toBe('public-client');
    expect(form.get('code')).toBe('private-code');
    expect(form.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(form.get('client_secret')).toBeNull();
  });

  it('issues an opaque Account bearer from the selected subject with ordinary user scopes', async () => {
    const transport = flow();
    const tokens = await issuePublicAccountTokensForSubject(
      target,
      fixture,
      { email: 'account-owner@example.invalid', password: 'private-account-password' },
      transport.fetch
    );
    expect(tokens.access).toBe('private-access');
    expect(tokens.refresh).toBe('private-refresh');
    const authorization = transport.requests[0]?.url;
    expect(authorization?.searchParams.getAll('resource')).toEqual([]);
    expect(authorization?.searchParams.get('scope')).toBe(
      'openid offline_access profile email phone identities custom_data all'
    );
    expect(JSON.parse(String(transport.requests[2]?.init.body))).toMatchObject({
      identifier: { type: 'email', value: 'account-owner@example.invalid' },
      password: 'private-account-password',
    });
    expect(new Headers(transport.requests[2]?.init.headers).get('aster-app-id')).toBe(
      'public-client'
    );
    expect(
      Object.fromEntries(new URLSearchParams(String(transport.requests[9]?.init.body)))
    ).toEqual(
      expect.objectContaining({ grant_type: 'authorization_code', client_id: 'public-client' })
    );
  });

  it('issues confidential user tokens with PKCE and Basic proof kept out of the form', async () => {
    const transport = flow();
    const tokens = await issueConfidentialUserTokens(target, fixture, transport.fetch);
    expect(tokens.access).toBe('private-access');
    expect(tokens.refresh).toBe('private-refresh');
    expect(transport.requests[0]?.url.searchParams.get('client_id')).toBe('confidential-client');
    const tokenRequest = transport.requests[9];
    const form = new URLSearchParams(String(tokenRequest?.init.body));
    expect(Object.fromEntries(form)).toMatchObject({
      grant_type: 'authorization_code',
      code: 'private-code',
      redirect_uri: 'https://client.example/callback',
    });
    expect(form.has('client_id')).toBe(false);
    expect(form.has('client_secret')).toBe(false);
    expect(new Headers(tokenRequest?.init.headers).get('authorization')).toBe(
      `Basic ${Buffer.from('confidential-client:private-status-client-secret').toString('base64')}`
    );
    expect(() => JSON.stringify(tokens)).toThrow('Invalid Phase 2 public user token issuance');
  });

  it('retains a private confidential browser session with the native sessions scope', async () => {
    const transport = flow();
    const session = await issueConfidentialUserSession(target, fixture, transport.fetch);

    expect(session.access).toBe('private-access');
    expect(session.getIdToken()).toBe('private-id-token');
    expect(session.getCookieHeader()).toBe('aster-session=private-cookie');
    expect(transport.requests[0]?.url.searchParams.get('scope')).toBe(
      'openid offline_access profile email address phone read:profile urn:aster:scope:sessions'
    );
    expect(transport.requests[0]?.url.searchParams.get('client_id')).toBe('confidential-client');
    expect(() => JSON.stringify(session)).toThrow('Invalid Phase 2 public user token issuance');
  });

  it('rejects a foreign redirect before sending a credential to that origin', async () => {
    const transport = flow({
      step: 4,
      response: response(200, { redirectTo: 'https://foreign.example/steal' }),
    });
    await expect(issuePublicUserTokens(target, fixture, transport.fetch)).rejects.toThrow(
      'Invalid Phase 2 public user token issuance (bridge-url)'
    );
    expect(transport.requests).toHaveLength(5);
  });

  it('rejects missing refresh credentials with fixed diagnostics', async () => {
    const transport = flow({
      step: 9,
      response: response(200, { access_token: 'private-access', token_type: 'Bearer' }),
    });
    await expect(issuePublicUserTokens(target, fixture, transport.fetch)).rejects.toThrow(
      'Invalid Phase 2 public user token issuance (token-refresh)'
    );
  });

  it('classifies only a fixed bridge HTTP status without reflecting its body', async () => {
    const transport = flow({
      step: 5,
      response: response(200, { private: 'do-not-reflect' }),
    });
    await expect(issuePublicUserTokens(target, fixture, transport.fetch)).rejects.toThrow(
      'Invalid Phase 2 public user token issuance (bridge-http-200)'
    );
  });
});
/* eslint-enable max-lines, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
