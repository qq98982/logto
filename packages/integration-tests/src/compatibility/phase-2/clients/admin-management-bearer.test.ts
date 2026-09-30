/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake transport records ordered requests and lease state. */
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withPhase2AdminManagementBearer } from './admin-management-bearer.js';

const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://admin.candidate.example/',
});
const allocationId = 'admin-allocation';
const state = 's'.repeat(48);
const verifier = 'v'.repeat(48);
const password = 'private-admin-password';
const managementResource = 'urn:aster:resource:management';

type RecordedRequest = Readonly<{ url: URL; init: RequestInit }>;

const fixture = (leaseState: {
  active: boolean;
}): Pick<ProvisionedPhase2Fixture, 'public' | 'withSecretLease'> => ({
  public: {
    allocationId: 'data-allocation',
    admin: { allocationId },
    clients: {
      basic: { id: 'basic', method: 'client_secret_basic' },
      post: { id: 'post', method: 'client_secret_post' },
    },
    deviceClients: {
      firstParty: {
        id: 'first',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      },
      thirdParty: {
        id: 'third',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      },
      missingGrant: {
        id: 'missing',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
      ineligibleWeb: {
        id: 'web',
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
    },
    resources: {
      primary: { id: 'primary', indicator: 'https://primary.example' },
      default: { id: 'default', indicator: 'https://default.example' },
    },
    organization: { id: 'org', scopeName: 'organization:read' },
    scopes: {
      read: { id: 'read', name: 'read' },
      write: { id: 'write', name: 'write' },
      unassigned: { id: 'unassigned', name: 'unassigned' },
    },
    boundary: { primary: 'provisioned', foreign: 'unchanged' },
  },
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> => {
    leaseState.active = true;
    try {
      return await use({
        getClientSecret: () => 'unused',
        getStatusClientSecret: () => 'unused',
        getAdminPassword: () => {
          if (!leaseState.active) {
            throw new Error('revoked');
          }
          return password;
        },
        toJSON: (): never => {
          throw new Error('secret lease');
        },
      });
    } finally {
      leaseState.active = false;
    }
  },
});

const response = (status: number, body?: unknown, headers?: HeadersInit): Response =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
  });

const transport = async (
  overrides: Readonly<{ audience?: string; scope?: string; failAt?: number }> = {}
): Promise<Readonly<{ fetch: typeof fetch; requests: RecordedRequest[] }>> => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const now = Math.floor(Date.now() / 1000);
  const bearer = await new SignJWT({ client_id: 'admin-console', scope: overrides.scope ?? 'all' })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
    .setIssuer('https://admin.candidate.example/oidc')
    .setAudience(overrides.audience ?? managementResource)
    .setSubject('phase1-admin')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  const requests: RecordedRequest[] = [];
  const replies = [
    response(303, undefined, { 'set-cookie': 'aster-admin=private-cookie; Path=/; HttpOnly' }),
    response(204),
    response(200, { verificationId: 'private-verification' }),
    response(204),
    response(200, { redirectTo: '/oidc/auth/private-login-resume' }),
    response(303, undefined, { location: '/consent?app_id=admin-console' }),
    response(302, undefined, { location: '/oidc/auth/private-consent-resume' }),
    response(303, undefined, {
      location:
        'https://admin.candidate.example/console/callback?code=private-code&state=' +
        state +
        '&iss=' +
        encodeURIComponent('https://admin.candidate.example/oidc'),
    }),
    response(200, {
      access_token: 'private-initial-access',
      id_token: 'private-initial-id',
      refresh_token: 'private-initial-refresh',
      token_type: 'Bearer',
    }),
    response(200, {
      access_token: bearer,
      id_token: 'private-refreshed-id',
      refresh_token: 'private-rotated-refresh',
      token_type: 'Bearer',
      scope: overrides.scope ?? 'all',
    }),
    response(200, { keys: [{ ...publicJwk, kid: 'test-key', alg: 'ES256', use: 'sig' }] }),
    response(200),
  ];
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    requests.push({ url: new URL(String(input)), init: init ?? {} });
    const index = requests.length - 1;
    if (overrides.failAt === index) {
      return response(418, { token: 'must-not-escape', cookie: 'must-not-escape' });
    }
    return replies[index] ?? response(500, { secret: 'unexpected' });
  }) as typeof fetch;
  return { fetch: requestFetch, requests };
};

describe('Phase 2 Admin Management bearer transport', () => {
  it('runs the real password, PKCE, consent and Management refresh order inside the lease', async () => {
    const leaseState = { active: false };
    const fake = await transport();
    const result = await withPhase2AdminManagementBearer(
      target,
      fixture(leaseState),
      async (bearer, lease) => {
        expect(leaseState.active).toBe(true);
        expect(bearer.split('.')).toHaveLength(3);
        expect(lease.getClientSecret('basic')).toBe('unused');
        return 'used';
      },
      { fetch: fake.fetch, codeVerifier: () => verifier, state: () => state }
    );

    expect(result).toBe('used');
    expect(leaseState.active).toBe(false);
    expect(fake.requests.map(({ url }) => url.pathname)).toEqual([
      '/oidc/auth',
      '/api/experience',
      '/api/experience/verification/password',
      '/api/experience/identification',
      '/api/experience/submit',
      '/oidc/auth/private-login-resume',
      '/consent',
      '/oidc/auth/private-consent-resume',
      '/oidc/token',
      '/oidc/token',
      '/oidc/jwks',
      '/oidc/token/revocation',
    ]);
    const authorization = fake.requests[0]?.url;
    expect(authorization?.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorization?.searchParams.getAll('resource')).toEqual([
      managementResource,
      'urn:aster:resource:account',
      'urn:aster:resource:organizations',
    ]);
    const passwordRequest = fake.requests[2];
    expect(new Headers(passwordRequest?.init.headers).get('cookie')).toBe(
      'aster-admin=private-cookie'
    );
    expect(JSON.parse(String(passwordRequest?.init.body))).toEqual({
      identifier: { type: 'username', value: 'phase1_admin_a_e597de200d860b24' },
      password,
    });
    expect(Object.fromEntries(new URLSearchParams(String(fake.requests[9]?.init.body)))).toEqual({
      client_id: 'admin-console',
      refresh_token: 'private-initial-refresh',
      grant_type: 'refresh_token',
      resource: managementResource,
    });
    expect(Object.fromEntries(new URLSearchParams(String(fake.requests[11]?.init.body)))).toEqual({
      client_id: 'admin-console',
      token: 'private-rotated-refresh',
      token_type_hint: 'refresh_token',
    });
  });

  it('revokes the rotated refresh after consumer failure and returns a fixed error', async () => {
    const fake = await transport();
    await expect(
      withPhase2AdminManagementBearer(
        target,
        fixture({ active: false }),
        async () => {
          throw new Error('private callback token and cookie');
        },
        { fetch: fake.fetch, codeVerifier: () => verifier, state: () => state }
      )
    ).rejects.toThrow('Invalid Phase 2 Admin Management bearer flow (consumer)');
    expect(fake.requests.at(-1)?.url.pathname).toBe('/oidc/token/revocation');
  });

  it('rejects the wrong signed audience, still revokes, and never reflects response secrets', async () => {
    const fake = await transport({ audience: 'urn:aster:resource:account' });
    let called = false;
    let observed = '';
    try {
      await withPhase2AdminManagementBearer(
        target,
        fixture({ active: false }),
        async () => {
          called = true;
        },
        { fetch: fake.fetch, codeVerifier: () => verifier, state: () => state }
      );
    } catch (error: unknown) {
      observed = error instanceof Error ? error.message : String(error);
    }
    expect(called).toBe(false);
    expect(observed).toBe('Invalid Phase 2 Admin Management bearer flow (jwks)');
    expect(observed).not.toMatch(/private|cookie|token/iu);
    expect(fake.requests.at(-1)?.url.pathname).toBe('/oidc/token/revocation');
  });

  it('classifies transport failures without returning response bodies or credentials', async () => {
    const fake = await transport({ failAt: 5 });
    await expect(
      withPhase2AdminManagementBearer(target, fixture({ active: false }), async () => null, {
        fetch: fake.fetch,
        codeVerifier: () => verifier,
        state: () => state,
      })
    ).rejects.toThrow('Invalid Phase 2 Admin Management bearer flow (bridge)');
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
