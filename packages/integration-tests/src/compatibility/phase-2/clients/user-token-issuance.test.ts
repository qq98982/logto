/* eslint-disable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake transport records the private authorization sequence. */
import type { TargetConfig } from '../../model.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';

import { exchangePublicRefresh, issuePublicUserTokens } from './user-token-issuance.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};

const fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'> = {
  status: {
    user: { id: 'user', username: 'status-user' },
    client: { id: 'public-client', redirectUri: 'https://client.example/callback' },
    resource: { id: 'resource', indicator: 'https://api.example.com' },
  },
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use({
      getClientSecret: () => 'unused-private-client-secret',
      getSubjectPassword: () => 'private-password',
      toJSON: (): never => {
        throw new Error('secret lease');
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
    response(204),
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

describe('Phase 2 public user token issuance transport', () => {
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

  it('rejects a foreign redirect before sending a credential to that origin', async () => {
    const transport = flow({
      step: 4,
      response: response(200, { redirectTo: 'https://foreign.example/steal' }),
    });
    await expect(issuePublicUserTokens(target, fixture, transport.fetch)).rejects.toThrow(
      'Invalid Phase 2 public user token issuance (bridge)'
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
});
/* eslint-enable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
