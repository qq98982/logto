/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake transport records ordered requests and the complete selected-connector lifecycle without splitting one observable contract. */
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

import type { TargetConfig } from '../../model.js';
import {
  getCommonGoogleConfiguredCollisionCheckpoint,
  runCommonGoogleConfiguredCollision,
  withCommonGoogleConfiguredCollisionCheckpoint,
} from '../browser/common-google-configured-collision.js';
import { withSelectedAccountSocialConnector } from '../browser/selected-account-social-connector-fixture.js';
import type {
  Phase2AdminRequestFunction,
  Phase2FixtureSecretLease,
  ProvisionedPhase2Fixture,
} from '../fixtures.js';

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
    const adminFixture = fixture({ active: false });
    const selectedFixture: ProvisionedPhase2Fixture = {
      ...adminFixture,
      status: {
        user: { id: 'fixture-user', username: 'fixture-user' },
        client: {
          id: 'client',
          redirectUri: 'https://app.example/demo-app',
        },
        confidentialClient: {
          id: 'confidential-client',
          redirectUri: 'https://app.example/confidential-callback',
        },
        resource: {
          id: 'resource',
          indicator: 'https://api.example',
          scopeName: 'read:profile',
        },
      },
    };
    let methods: unknown = [
      { identifier: 'username', password: true, verificationCode: false, isPasswordPrimary: true },
    ];
    let branding: unknown = {};
    let targets: unknown = ['github'];
    let accountCenter = { enabled: false, fields: { social: 'ReadOnly' } };
    let metadata = {
      redirectUris: ['https://app.example/demo-app'],
      postLogoutRedirectUris: ['https://app.example/logout'],
    };
    // eslint-disable-next-line complexity -- One fake models the complete ordered Management state contract used by the nested real fixtures.
    const request: Phase2AdminRequestFunction = async (input) => {
      if (input.path === 'resources' && input.query?.includeScopes === 'true') {
        return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
      }
      if (input.path === 'roles' && input.method === 'POST') {
        return {
          id: 'email-role',
          name: 'common-email-data-allocation',
          type: 'User',
          isDefault: false,
        };
      }
      if (input.path === 'roles/email-role/scopes') {
        return [{ id: 'scope', name: 'read:profile', resourceId: 'resource' }];
      }
      if (input.path === 'roles/email-role/users') {
        return 201;
      }
      if (input.path === 'users/email-user/roles') {
        return [{ id: 'email-role', type: 'User' }];
      }
      if (input.path === 'users' && input.method === 'POST') {
        return {
          id: 'email-user',
          primaryEmail: 'common-email-data-allocation@example.invalid',
          hasPassword: true,
          isSuspended: false,
        };
      }
      if (
        input.method === 'DELETE' &&
        (input.path === 'users/email-user' || input.path === 'roles/email-role')
      ) {
        return 204;
      }
      if (input.path === 'sign-in-exp' && input.method === 'GET') {
        return { signIn: { methods }, branding, socialSignInConnectorTargets: targets };
      }
      if (input.path === 'sign-in-exp') {
        const body = input.body as Record<string, unknown>;
        if ('socialSignInConnectorTargets' in body) {
          targets = body.socialSignInConnectorTargets;
        }
        if ('signIn' in body) {
          methods = (body.signIn as { methods: unknown }).methods;
          branding = body.branding;
        }
        return { signIn: { methods }, branding, socialSignInConnectorTargets: targets };
      }
      if (input.path === 'account-center' && input.method === 'GET') {
        return accountCenter;
      }
      if (input.path === 'account-center') {
        accountCenter = input.body as typeof accountCenter;
        return accountCenter;
      }
      if (input.path === 'connectors' && input.method === 'POST') {
        return { id: 'connector', connectorId: 'google-universal' };
      }
      if (input.path === 'connectors/connector') {
        return 204;
      }
      if (input.path === 'applications/client' && input.method === 'GET') {
        return { id: 'client', type: 'SPA', oidcClientMetadata: metadata };
      }
      if (input.path === 'applications/client') {
        metadata = (input.body as { oidcClientMetadata: typeof metadata }).oidcClientMetadata;
        return { id: 'client', type: 'SPA', oidcClientMetadata: metadata };
      }
      throw new TypeError('unexpected selected connector request');
    };
    let helperReached = false;
    const failure = withCommonGoogleConfiguredCollisionCheckpoint(async (retain) =>
      withPhase2AdminManagementBearer(
        target,
        adminFixture,
        async () => {
          await withSelectedAccountSocialConnector({
            fixture: selectedFixture,
            request,
            browser: { clientId: 'client', redirectUri: 'https://app.example/demo-app' },
            callbackOrigin: 'https://core.example/',
            provider: 'google',
            connectorConfig: { clientId: 'owned', clientSecret: 'private' },
            getPassword: () => 'private',
            prepareProvider: async () => ({
              associationData: {},
              takeAccountCode: async () => 'private',
              takeForeignAccountCode: async () => 'private',
              assertAccountProviderCase: async () => {
                // This fixture has no external provider state beyond the nested collision helper.
              },
              stop: async () => {
                // The synthetic provider owns no process or file that requires cleanup.
              },
            }),
            use: async () => {
              try {
                await runCommonGoogleConfiguredCollision({
                  ownerId: 'original',
                  googleSubject: 'google-subject',
                  readOriginalOwner: async () => ({
                    id: 'original',
                    identities: { google: { userId: 'google-subject' } },
                  }),
                  readCollidingUser: async () => ({ id: 'collision', identities: {} }),
                  runConfiguredSignIn: async () => {
                    helperReached = true;
                    throw new TypeError('private configured collision failure');
                  },
                });
              } catch (error: unknown) {
                const checkpoint = getCommonGoogleConfiguredCollisionCheckpoint(error);
                if (checkpoint) {
                  retain(checkpoint);
                }
                throw error;
              }
            },
          });
        },
        { fetch: fake.fetch, codeVerifier: () => verifier, state: () => state }
      )
    );
    const error = await failure.catch((error_: unknown) => error_);
    expect(error).toMatchObject({
      message: 'Invalid Phase 2 Admin Management bearer flow (consumer)',
    });
    expect(helperReached).toBe(true);
    expect(getCommonGoogleConfiguredCollisionCheckpoint(error)).toBe('configured-sign-in');
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

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
