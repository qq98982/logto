/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- The controlled token and Management servers exercise the complete Native fixture and callback boundary without publishing private values. */
import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2FixturePublicWithSelectedNative } from '../selected-native-fixture.js';

import {
  commonNativeScenarioIds,
  createCommonNativeScenarioRegistry,
  observeCommonNativeCodePkce,
  validateCommonNativeDiscovery,
} from './common-native.js';

const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://identity.example/',
  adminUrl: 'https://identity-admin.example/',
});
const issuer = 'https://identity.example/oidc';
const redirectUri = 'https://app.example.test/wechat/logto-callback';
const resource = 'https://app.example.test/api';
const subject = 'native-user';
const clientId = 'native-client';
const now = 1_700_000_000;
const privateValues = Object.freeze([
  'private-code',
  'private-verifier',
  'private-state',
  'private-nonce',
  'private-refresh',
  'private-profile-token',
]);
const selectedNativePassword = () => 'private-native-password-A1!';

const selectedFixture = (): ProvisionedPhase2Fixture & {
  public: Phase2FixturePublicWithSelectedNative;
} =>
  ({
    public: {
      allocationId: 'allocation',
      clients: {
        basic: { id: 'basic', method: 'client_secret_basic' },
        post: { id: 'post', method: 'client_secret_post' },
      },
      deviceClients: {
        firstParty: {
          id: 'device-first',
          applicationType: 'Native',
          authenticationMethod: 'none',
          isThirdParty: false,
          deviceGrantEnabled: true,
        },
        thirdParty: {
          id: 'device-third',
          applicationType: 'Native',
          authenticationMethod: 'none',
          isThirdParty: true,
          deviceGrantEnabled: true,
        },
        missingGrant: {
          id: 'device-missing',
          applicationType: 'Native',
          authenticationMethod: 'none',
          isThirdParty: false,
          deviceGrantEnabled: false,
        },
        ineligibleWeb: {
          id: 'device-web',
          applicationType: 'SPA',
          authenticationMethod: 'none',
          isThirdParty: false,
          deviceGrantEnabled: false,
        },
      },
      resources: {
        primary: { id: 'primary', indicator: 'https://primary.example/api' },
        default: { id: 'default', indicator: 'https://default.example/api' },
      },
      organization: { id: 'organization', scopeName: 'organization:read' },
      scopes: {
        read: { id: 'read', name: 'read' },
        write: { id: 'write', name: 'write' },
        unassigned: { id: 'unassigned', name: 'unassigned' },
      },
      boundary: { primary: 'provisioned', foreign: 'unchanged' },
      selectedNative: {
        clientId,
        applicationType: 'Native',
        redirectUri,
        resource: {
          id: 'selected-resource',
          indicator: resource,
          accessTokenTtl: 300,
          scope: { id: 'selected-scope', name: 'session:exchange' },
        },
        defaultUserRoleId: 'selected-role',
        identity: { id: subject, primaryEmail: 'native@example.invalid' },
      },
    },
    status: {
      user: { id: 'generic-user', username: 'generic-user' },
      client: {
        id: 'generic-public-client',
        name: 'generic public client',
        redirectUri: 'https://generic.example/callback',
      },
      confidentialClient: {
        id: 'generic-confidential-client',
        redirectUri: 'https://generic.example/confidential-callback',
      },
      resource: {
        id: 'generic-resource',
        indicator: 'https://generic.example/api',
        scopeName: 'generic:read',
      },
    },
    withSecretLease: async () => {
      throw new Error('unused');
    },
  }) as ProvisionedPhase2Fixture & { public: Phase2FixturePublicWithSelectedNative };

const baseFixture = (): ProvisionedPhase2Fixture => {
  const value = selectedFixture();
  const { selectedNative, ...publicFixture } = value.public;
  void selectedNative;
  return { ...value, public: publicFixture };
};

const selectedNativeManagement = (): Phase2AdminRequestFunction => {
  let methods: ReadonlyArray<Readonly<Record<string, unknown>>> = [
    {
      identifier: 'username',
      password: true,
      verificationCode: false,
      isPasswordPrimary: true,
    },
  ];
  let identity: Readonly<Record<string, unknown>> = {};
  const resourceValue = { id: 'selected-resource', indicator: resource, accessTokenTtl: 300 };
  const scope = {
    id: 'selected-scope',
    resourceId: resourceValue.id,
    name: 'session:exchange',
  };
  const role = { id: 'selected-role', isDefault: true };
  const application = {
    id: clientId,
    type: 'Native',
    isThirdParty: false,
    oidcClientMetadata: { redirectUris: [redirectUri], postLogoutRedirectUris: [] },
  };
  return async ({ method, path, body }) => {
    if (method === 'GET' && path === 'sign-in-exp') {
      return { signIn: { methods } };
    }
    if (method === 'PATCH' && path === 'sign-in-exp') {
      methods = (body as { signIn: { methods: typeof methods } }).signIn.methods;
      return { signIn: { methods } };
    }
    if (method === 'POST' && path === 'resources') {
      return resourceValue;
    }
    if (method === 'POST' && path === `resources/${resourceValue.id}/scopes`) {
      return scope;
    }
    if (method === 'POST' && path === 'roles') {
      return role;
    }
    if (method === 'POST' && path === 'users') {
      identity = {
        id: subject,
        primaryEmail: (body as { primaryEmail: string }).primaryEmail,
        hasPassword: true,
      };
      return identity;
    }
    if (method === 'POST' && path === 'applications') {
      return application;
    }
    if (method === 'GET' && path === `applications/${clientId}`) {
      return application;
    }
    if (method === 'GET' && path === 'resources') {
      return [{ ...resourceValue, scopes: [scope] }];
    }
    if (method === 'GET' && path === 'roles') {
      return [role];
    }
    if (method === 'GET' && path === `roles/${role.id}/scopes`) {
      return [scope];
    }
    if (method === 'GET' && path === 'users') {
      return [identity];
    }
    if (method === 'DELETE' && (path === `users/${subject}` || path === `roles/${role.id}`)) {
      return 204;
    }
    throw new Error('unexpected selected Native Management request');
  };
};

const createJwtFixture = async (
  options: Readonly<{
    nonce?: string;
    resourceSubject?: string;
    profileSubject?: string;
    refreshedIssuedAt?: number;
  }> = {}
) => {
  const { publicKey, privateKey } = await generateKeyPair('ES384');
  const publicJwk = await exportJWK(publicKey);
  const jwks: JSONWebKeySet = {
    keys: [{ ...publicJwk, kid: 'native-key', alg: 'ES384', use: 'sig' }],
  };
  const signId = async (nonce = options.nonce ?? privateValues[3]) =>
    new SignJWT({ nonce })
      .setProtectedHeader({ alg: 'ES384', kid: 'native-key' })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setSubject(subject)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);
  const signResource = async (tokenSubject = options.resourceSubject ?? subject, issuedAt = now) =>
    new SignJWT({ client_id: clientId, scope: 'session:exchange' })
      .setProtectedHeader({ alg: 'ES384', kid: 'native-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience(resource)
      .setSubject(tokenSubject)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + 300)
      .sign(privateKey);
  return Object.freeze({
    jwks,
    idToken: await signId(),
    idTokenForNonce: signId,
    resourceToken: await signResource(),
    refreshedResourceToken: await signResource(subject, options.refreshedIssuedAt ?? now),
    profileSubject: options.profileSubject ?? subject,
  });
};

const handoff = (overrides: Readonly<{ state?: string; issuer?: string; nonce?: string }> = {}) => {
  const state = privateValues[2];
  const callback = new URL(redirectUri);
  callback.search = new URLSearchParams({
    code: privateValues[0]!,
    state: overrides.state ?? state!,
    iss: overrides.issuer ?? issuer,
  }).toString();
  return Object.freeze({
    getCallbackUrl: () => callback.href,
    getVerifier: () => privateValues[1]!,
    getState: () => state!,
    getNonce: () => overrides.nonce ?? privateValues[3]!,
    getExpectedSubject: () => subject,
    toJSON: (): never => {
      throw new Error('private handoff');
    },
  });
};

const transport =
  (
    tokens: Awaited<ReturnType<typeof createJwtFixture>>,
    calls: string[],
    resourceRefreshTokens: string[] = []
  ): typeof fetch =>
  async (input, init) => {
    const url = new URL(String(input));
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (url.pathname === '/oidc/.well-known/openid-configuration') {
      return Response.json({
        issuer,
        jwks_uri: `${issuer}/jwks`,
        userinfo_endpoint: `${issuer}/me`,
      });
    }
    if (url.pathname === '/oidc/me') {
      return Response.json({ sub: tokens.profileSubject });
    }
    if (url.pathname === '/oidc/token' && init?.body instanceof URLSearchParams) {
      if (init.body.get('grant_type') === 'authorization_code') {
        return Response.json({
          token_type: 'Bearer',
          access_token: tokens.resourceToken,
          refresh_token: privateValues[4],
          id_token: tokens.idToken,
        });
      }
      if (init.body.has('resource')) {
        resourceRefreshTokens.push(init.body.get('refresh_token') ?? 'missing');
        if (init.body.get('refresh_token') !== 'private-profile-refresh') {
          return Response.json({ error: 'invalid_grant' }, { status: 400 });
        }
        return Response.json({
          token_type: 'Bearer',
          access_token: tokens.refreshedResourceToken,
          refresh_token: 'private-resource-refresh',
        });
      }
      return Response.json({
        token_type: 'Bearer',
        access_token: privateValues[5],
        refresh_token: 'private-profile-refresh',
      });
    }
    throw new Error('unexpected request');
  };

const nativeCallbackTransport = (
  tokens: Awaited<ReturnType<typeof createJwtFixture>>,
  calls: string[]
): typeof fetch => {
  const tokenTransport = transport(tokens, calls);
  let state: string | undefined;
  let nonce: string | undefined;
  return async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${url.pathname}`);
    if (url.pathname === '/oidc/auth') {
      state = url.searchParams.get('state') ?? undefined;
      nonce = url.searchParams.get('nonce') ?? undefined;
      return new Response(null, {
        status: 303,
        headers: { 'set-cookie': 'interaction=native; Path=/; HttpOnly' },
      });
    }
    if (url.pathname === '/api/experience' && method === 'PUT') {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/api/experience/verification/password' && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as { password?: unknown };
      expect(body.password).toBe(selectedNativePassword());
      return Response.json({ verificationId: 'native-verification' });
    }
    if (url.pathname === '/api/experience/identification' && method === 'POST') {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/api/experience/submit' && method === 'POST') {
      return Response.json({ redirectTo: `${target.coreUrl}bridge` });
    }
    if (url.pathname === '/bridge') {
      return new Response(null, { status: 303 });
    }
    if (url.pathname === '/api/interaction/consent' && method === 'GET') {
      return Response.json({});
    }
    if (url.pathname === '/api/interaction/consent' && method === 'POST') {
      return Response.json({ redirectTo: `${target.coreUrl}resume` });
    }
    if (url.pathname === '/resume') {
      const location = new URL(redirectUri);
      location.searchParams.set('code', privateValues[0]!);
      location.searchParams.set('state', state ?? 'missing');
      location.searchParams.set('iss', issuer);
      return new Response(null, { status: 303, headers: { location: location.href } });
    }
    if (
      url.pathname === '/oidc/token' &&
      init?.body instanceof URLSearchParams &&
      init.body.get('grant_type') === 'authorization_code'
    ) {
      return Response.json({
        token_type: 'Bearer',
        access_token: tokens.resourceToken,
        refresh_token: privateValues[4],
        id_token: await tokens.idTokenForNonce(nonce ?? 'missing'),
      });
    }
    calls.pop();
    return tokenTransport(input, init);
  };
};

const observe = async (
  tokenOptions: Parameters<typeof createJwtFixture>[0] = {},
  callbackOverrides: Parameters<typeof handoff>[0] = {}
) => {
  const tokens = await createJwtFixture(tokenOptions);
  const calls: string[] = [];
  const projection = await observeCommonNativeCodePkce({
    target,
    fixture: selectedFixture(),
    jwks: tokens.jwks,
    requestFetch: transport(tokens, calls),
    now: () => now,
    prepareCallback: async () => handoff(callbackOverrides),
  });
  return Object.freeze({ projection, calls });
};

describe('common Native code PKCE scenario', () => {
  it('emits one closed projection without retaining callback or credential values', async () => {
    const result = await observe();

    expect(result.projection).toEqual({
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
    expect(result.calls).toEqual([
      'GET /oidc/.well-known/openid-configuration',
      'POST /oidc/token',
      'POST /oidc/token',
      'GET /oidc/me',
      'POST /oidc/token',
    ]);
    const published = JSON.stringify(result.projection);
    for (const privateValue of privateValues) {
      expect(published).not.toContain(privateValue);
    }
  });

  it.each([
    ['wrong callback state', {}, { state: 'wrong-state' }],
    ['wrong callback issuer', {}, { issuer: 'https://foreign.example/oidc' }],
    ['wrong ID token nonce', { nonce: 'wrong-nonce' }, {}],
    ['resource subject mismatch', { resourceSubject: 'foreign-user' }, {}],
    ['profile subject mismatch', { profileSubject: 'foreign-user' }, {}],
  ] as const)(
    'rejects %s without publishing private inputs',
    async (_label, tokenOptions, callback) => {
      await expect(observe(tokenOptions, callback)).rejects.toThrow(
        /callback rejected|common Native/u
      );
    }
  );

  it('rejects cross-origin discovery endpoints before callback preparation', async () => {
    let prepared = false;
    await expect(
      observeCommonNativeCodePkce({
        target,
        fixture: selectedFixture(),
        jwks: { keys: [] },
        requestFetch: async () =>
          Response.json({
            issuer,
            jwks_uri: 'https://foreign.example/oidc/jwks',
            userinfo_endpoint: `${issuer}/me`,
          }),
        prepareCallback: async () => {
          prepared = true;
          return handoff();
        },
      })
    ).rejects.toThrow('Invalid Phase 2 common Native scenario');
    expect(prepared).toBe(false);
  });

  it('rejects a signed refreshed resource token issued beyond clock tolerance', async () => {
    await expect(observe({ refreshedIssuedAt: now + 16 })).rejects.toThrow(
      'Invalid Phase 2 common Native scenario'
    );
  });

  it('uses a fresh verification time after an elapsed callback flow', async () => {
    const tokens = await createJwtFixture({ refreshedIssuedAt: now + 20 });
    const calls: string[] = [];
    const clock = [now, now + 20];
    const projection = await observeCommonNativeCodePkce({
      target,
      fixture: selectedFixture(),
      jwks: tokens.jwks,
      requestFetch: transport(tokens, calls),
      now: () => clock.shift() ?? now + 20,
      prepareCallback: async () => handoff(),
    });

    expect(projection.resourceRefreshTtlSeconds).toBe(300);
    expect(clock).toEqual([]);
  });

  it('uses only the opaque-refresh rotation for the explicit resource exchange', async () => {
    const tokens = await createJwtFixture();
    const calls: string[] = [];
    const resourceRefreshTokens: string[] = [];
    const projection = await observeCommonNativeCodePkce({
      target,
      fixture: selectedFixture(),
      jwks: tokens.jwks,
      requestFetch: transport(tokens, calls, resourceRefreshTokens),
      now: () => now,
      prepareCallback: async () => handoff(),
    });

    expect(projection.resourceRefresh).toBe('jwt');
    expect(resourceRefreshTokens).toEqual(['private-profile-refresh']);
    expect(resourceRefreshTokens).not.toContain(privateValues[4]);
  });

  it('registers exactly one closed scenario id and rejects an absent profile binding', () => {
    const registry = createCommonNativeScenarioRegistry({
      differentialScenarios: commonNativeScenarioIds,
    });
    expect(registry.map(({ id }) => id)).toEqual(commonNativeScenarioIds);
    expect(() => createCommonNativeScenarioRegistry({ differentialScenarios: [] })).toThrow(
      'Invalid Phase 2 common Native scenario'
    );
  });

  it('requires discovery issuer, JWKS and UserInfo endpoints from the same target', () => {
    expect(
      validateCommonNativeDiscovery(target, {
        issuer,
        jwks_uri: `${issuer}/jwks`,
        userinfo_endpoint: `${issuer}/me`,
      })
    ).toEqual({ issuer, jwksUri: `${issuer}/jwks` });
    expect(() =>
      validateCommonNativeDiscovery(target, {
        issuer: 'https://foreign.example/oidc',
        jwks_uri: `${issuer}/jwks`,
        userinfo_endpoint: `${issuer}/me`,
      })
    ).toThrow('Invalid Phase 2 common Native scenario');
  });

  it('keeps the active Native password capability through default setup and callback only', async () => {
    const tokens = await createJwtFixture();
    const calls: string[] = [];
    const registry = createCommonNativeScenarioRegistry({
      differentialScenarios: commonNativeScenarioIds,
    });
    let active = true;
    const guardedPassword = () => {
      if (!active) {
        throw new Error('inactive Native password lease');
      }
      return selectedNativePassword();
    };
    const result = await registry[0].run({
      target,
      fixture: baseFixture(),
      managementRequest: selectedNativeManagement(),
      getSelectedNativePassword: guardedPassword,
      jwks: tokens.jwks,
      requestFetch: nativeCallbackTransport(tokens, calls),
      now: () => now,
    });
    active = false;

    expect(() => guardedPassword()).toThrow('inactive Native password lease');
    expect(result.id).toBe('common.native.code-pkce');
    expect(result.projection.expectedSubject).toBe(true);
  });
});

/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
