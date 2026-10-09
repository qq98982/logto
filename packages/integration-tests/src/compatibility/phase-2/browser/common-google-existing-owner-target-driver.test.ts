/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Stateful transport and browser fakes exercise the complete target composition and compensation order. */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import type {
  Phase1BrowserGroupObserver,
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';
import {
  invokePlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  commonGoogleTargetFixtureStageForTesting,
  type CommonGoogleExistingOwnerTargetDriverInput,
  runCommonGoogleExistingOwnerForTarget,
  runCommonGoogleExistingOwnerForTargetTesting,
  runCommonGoogleExistingOwnerReplayForTargetTesting,
  runCommonGoogleExistingOwnerWrongStateForTargetTesting,
} from './common-google-existing-owner-target-driver.js';
import type { GoogleProviderControl } from './google-provider-lease.js';

const containerId = 'a'.repeat(64);
const image = `sha256:${'b'.repeat(64)}`;
const receipt = {
  tokenRequestCount: 2,
  userinfoRequestCount: 2,
  userinfoGetObserved: true,
  userinfoPostObserved: false,
  grantTypeExact: true,
  callbackUriExact: true,
  clientAuthenticationExact: true,
  issuedBearerObserved: true,
  stableSubjectCaseConsumed: true,
  changedEmailCaseConsumed: true,
  wrongStateControlCodeConsumed: false,
  replayRejected: false,
};

test('bounds target fixture-stage aggregate depth and rejects cycles and accessors', () => {
  const known = new TypeError('Selected Google connector fixture failed: create-role');
  let withinBound: unknown = known;
  for (let index = 0; index < 3; index += 1) {
    withinBound = new AggregateError([withinBound], 'bounded target fixture error');
  }
  expect(commonGoogleTargetFixtureStageForTesting(withinBound)).toBe('fixture-create-role');
  expect(
    commonGoogleTargetFixtureStageForTesting(
      new AggregateError([withinBound], 'over-deep target fixture error')
    )
  ).toBeUndefined();
  const cyclic = new AggregateError([], 'cyclic target fixture error');
  cyclic.errors[0] = cyclic;
  expect(commonGoogleTargetFixtureStageForTesting(cyclic)).toBeUndefined();
  let getterCalls = 0;
  const hostile = Object.defineProperty(
    new AggregateError([], 'hostile target fixture error'),
    'errors',
    {
      get: () => {
        getterCalls += 1;
        throw new Error('private target value');
      },
    }
  );
  expect(commonGoogleTargetFixtureStageForTesting(hostile)).toBeUndefined();
  expect(getterCalls).toBe(0);
});
const target = {
  label: 'oracle' as const,
  coreUrl: 'http://localhost:3321/',
  adminUrl: 'http://localhost:3421/',
};
const browser = {
  storageKey: 'config',
  demo: {
    appId: 'browser-app',
    prompt: 'consent',
    scope: 'openid offline_access profile email read:profile',
    resource: 'https://api.example',
  },
  redirectUri: 'http://localhost:3321/demo-app',
  initialResponseScope: 'openid offline_access profile email',
  resourceScope: 'read:profile',
} as const;

const initialFacts = (): Phase1BrowserNetworkFacts => ({
  signIns: [
    {
      authority: 'core',
      status: 303,
      queryShapeExact: true,
      clientId: 'browser-app',
      redirectUri: browser.redirectUri,
      responseType: 'code',
      prompt: 'consent',
      scope: browser.demo.scope,
      resources: [browser.demo.resource],
      pkceMethod: 'S256',
      stateFormatValid: true,
      challengeFormatValid: true,
    },
  ],
  callbacks: [
    {
      authority: 'core',
      path: '/demo-app',
      status: 200,
      queryShapeExact: true,
      stateMatches: true,
      issuer: 'http://localhost:3321/oidc',
      codePresent: true,
      fragmentEmpty: true,
    },
  ],
  exchanges: [
    {
      kind: 'initial',
      authority: 'core',
      status: 200,
      requestShapeExact: true,
      requestCorrelationValid: true,
      clientId: 'browser-app',
      redirectUri: browser.redirectUri,
      initialRefreshPresent: true,
      replacementFresh: true,
      resource: null,
      organizationId: null,
      responseScope: browser.initialResponseScope,
      accessKind: 'opaque',
    },
  ],
  endpointDiscoveries: [],
  accountReads: [],
  applicationReads: [],
  userReads: [],
});

const refreshedFacts = (): Phase1BrowserNetworkFacts => {
  const initial = initialFacts();
  return {
    ...initial,
    exchanges: [
      ...initial.exchanges,
      {
        kind: 'management',
        authority: 'core',
        status: 200,
        requestShapeExact: true,
        requestCorrelationValid: true,
        clientId: 'browser-app',
        redirectUri: null,
        initialRefreshPresent: false,
        replacementFresh: true,
        resource: browser.demo.resource,
        organizationId: null,
        responseScope: browser.resourceScope,
        accessKind: 'compact',
        compactAccess: {
          issuer: 'http://localhost:3321/oidc',
          subject: 'owned-user',
          audience: browser.demo.resource,
          clientId: 'browser-app',
          scope: browser.resourceScope,
          organizationIdPresent: false,
        },
      },
    ],
  };
};

const json = (value: unknown, status = 200): Response =>
  new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const empty = (status = 204): Response => new Response(null, { status });

const createHarness = async (
  options: Readonly<{
    profileEmail?: string;
    stopFails?: boolean;
    providerWrongIdentity?: boolean;
    providerHealth?: 'healthy' | 'unhealthy';
    callbackRouteFails?: boolean;
    wrongState?: boolean;
    replay?: boolean;
    replayFailure?: boolean;
  }> = {}
) => {
  const root = await mkdtemp('/var/tmp/henry-build/google-target-driver-');
  const configFile = path.join(root, 'provider-config');
  const receiptFile = path.join(root, 'provider-receipt');
  const healthDiagnosticFile = path.join(root, 'provider-health-diagnostic');
  await writeFile(configFile, '', { mode: 0o600 });
  await writeFile(receiptFile, '', { mode: 0o600 });
  await writeFile(healthDiagnosticFile, '', { mode: 0o600 });
  let providerState = {
    Status: 'created',
    Running: false,
    ExitCode: 0,
    Health: { Status: 'starting' },
  };
  const events: string[] = [];
  const providerControl: GoogleProviderControl = {
    run: async (args) => {
      events.push(`provider:${args[0]}`);
      if (args[0] === 'start') {
        providerState = {
          Status: 'running',
          Running: true,
          ExitCode: 0,
          Health: { Status: options.providerHealth ?? 'healthy' },
        };
        await writeFile(
          receiptFile,
          JSON.stringify(
            options.wrongState
              ? {
                  ...receipt,
                  tokenRequestCount: 1,
                  userinfoRequestCount: 1,
                  changedEmailCaseConsumed: false,
                }
              : receipt
          ),
          { mode: 0o600 }
        );
        return containerId;
      }
      if (args[0] === 'stop') {
        if (options.stopFails) {
          throw new Error('private-provider-stop');
        }
        providerState = {
          Status: 'exited',
          Running: false,
          ExitCode: 0,
          Health: { Status: 'healthy' },
        };
        return containerId;
      }
      if (args[2] === '{{json .State}}') {
        return JSON.stringify(providerState);
      }
      return JSON.stringify({
        Id: containerId,
        Name: options.providerWrongIdentity ? '/foreign-provider' : '/google-provider',
        Image: image,
        Config: {
          Image: image,
          Labels: {
            'com.docker.compose.project': 'google-project',
            'com.docker.compose.service': 'google-provider',
          },
        },
        State: providerState,
      });
    },
  };
  let sie = ['github'];
  const previousBranding = { logoUrl: 'https://legacy.invalid/logo.svg' };
  let branding: unknown = previousBranding;
  let appMetadata: Record<string, unknown> = { redirectUris: ['http://old.example/callback'] };
  let role = false;
  let connector = false;
  let user: Record<string, unknown> | undefined;
  const requestFetch: typeof fetch = async (input, init) => {
    const url = new URL(
      typeof input === 'string' ? input : input instanceof URL ? input : input.url
    );
    const method = init?.method ?? 'GET';
    const apiPath = url.pathname.replace(/^\/api\//u, '');
    events.push(`${method}:${url.pathname}`);
    if (url.pathname === '/oidc/.well-known/openid-configuration') {
      return json({ issuer: 'http://localhost:3321/oidc' });
    }
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    if (method === 'GET' && apiPath === 'sign-in-exp') {
      return json({ branding, socialSignInConnectorTargets: sie });
    }
    if (method === 'PATCH' && apiPath === 'sign-in-exp') {
      branding = body.branding;
      sie = [...(body.socialSignInConnectorTargets as string[])];
      return json({ branding, socialSignInConnectorTargets: sie });
    }
    if (method === 'GET' && apiPath === 'applications/browser-app') {
      return json({ id: 'browser-app', type: 'SPA', oidcClientMetadata: appMetadata });
    }
    if (method === 'PATCH' && apiPath === 'applications/browser-app') {
      appMetadata = body.oidcClientMetadata as Record<string, unknown>;
      return json({ oidcClientMetadata: appMetadata });
    }
    if (method === 'GET' && apiPath === 'resources') {
      return json([{ id: 'resource', scopes: [{ id: 'scope', name: browser.resourceScope }] }]);
    }
    if (method === 'POST' && apiPath === 'roles') {
      role = true;
      return json({ id: 'role', type: 'User', isDefault: false });
    }
    if (method === 'DELETE' && apiPath === 'roles/role') {
      role = false;
      return empty();
    }
    if (method === 'POST' && apiPath === 'connectors') {
      connector = true;
      return json({ id: 'connector-instance', connectorId: 'google-universal' });
    }
    if (method === 'DELETE' && apiPath === 'connectors/connector-instance') {
      events.push('connector-delete');
      connector = false;
      return empty();
    }
    if (method === 'POST' && apiPath === 'users') {
      user = { id: 'owned-user', primaryEmail: body.primaryEmail, identities: {} };
      return json(user);
    }
    if (method === 'POST' && apiPath === 'users/owned-user/identities') {
      user = { ...user, identities: { google: { userId: 'google-subject' } } };
      return json({ google: { userId: 'google-subject' } });
    }
    if (method === 'GET' && apiPath === 'users/owned-user') {
      return json(user);
    }
    if (method === 'DELETE' && apiPath === 'users/owned-user') {
      user = undefined;
      return empty();
    }
    if (method === 'POST' && apiPath === 'roles/role/users') {
      return new Response('Created', { status: 201 });
    }
    if (method === 'GET' && apiPath === 'users/owned-user/roles') {
      return json([{ id: 'role' }]);
    }
    throw new Error('private-unexpected-request');
  };
  const fixture: ProvisionedPhase2Fixture = {
    public: { allocationId: 'allocation', admin: { allocationId: 'admin-allocation' } } as never,
    status: {
      user: { id: 'baseline-user', username: 'baseline-name' },
      client: { id: 'browser-app', redirectUri: browser.redirectUri },
      confidentialClient: { id: 'confidential', redirectUri: 'http://localhost/confidential' },
      resource: {
        id: 'resource',
        indicator: browser.demo.resource,
        scopeName: browser.resourceScope,
      },
    },
    withSecretLease: async (use) => {
      events.push('fixture-lease-open');
      try {
        return await use({
          getClientSecret: () => 'unused',
          getStatusClientSecret: () => 'unused',
          getAdminPassword: () => 'private-admin-password',
          toJSON: () => {
            throw new TypeError('private fixture lease');
          },
        });
      } finally {
        events.push('fixture-lease-close');
      }
    },
  };
  const createSession = (capability: PlaywrightExternalAuthorizationCapability) => {
    const initial = initialFacts();
    const refreshed = refreshedFacts();
    const session: Phase1BrowserSession = {
      preloadDemoConfiguration: async () => {},
      navigate: async () => {},
      waitForRoute: async () => {},
      waitForExactRoute: async () => {
        if (options.callbackRouteFails) {
          throw new Error('private callback route');
        }
      },
      assertRoute: async () => {},
      assertExactRoute: async () => {},
      fill: async () => {},
      click: async (step) => {
        if (!['google-provider', 'google-wrong-state-provider'].includes(step)) {
          return;
        }
        const authorization = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authorization.search = new URLSearchParams({
          client_id: 'google-client',
          redirect_uri: 'http://localhost:3321/callback/connector-instance',
          response_type: 'code',
          state: 'abcdefghijk',
          scope: 'openid profile email',
        }).toString();
        const handled = await invokePlaywrightExternalAuthorizationCapability(
          capability,
          'GET',
          authorization,
          { abort: async () => {}, fulfill: async () => {} }
        );
        expect(handled).toBe(true);
        if (options.replay) {
          let replayFetches = 0;
          const response = (status: number, value: unknown, headers: unknown[] = []) => ({
            status: () => status,
            body: async () => Buffer.from(JSON.stringify(value)),
            headersArray: () => headers,
          });
          const replayHandled = await invokePlaywrightExternalAuthorizationCapability(
            capability,
            'POST',
            new URL(
              'http://localhost:3321/api/experience/verification/social/connector-instance/verify'
            ),
            {
              abort: async () => {},
              fulfill: async () => {},
              request: () => ({
                allHeaders: async () => ({
                  'content-type': 'application/json',
                  cookie: 'interaction=private',
                }),
              }),
              fetch: async () => {
                replayFetches += 1;
                return replayFetches === 1
                  ? options.replayFailure
                    ? response(200, {})
                    : response(200, { verificationId: 'private-proof' }, [
                        { name: 'set-cookie', value: 'proof=merged; Path=/; HttpOnly' },
                      ])
                  : response(404, { code: 'session.verification_session_not_found' });
              },
            } as never
          );
          expect(replayHandled).toBe(true);
        }
      },
      expectText: async () => {},
      expectCount: async () => {},
      waitForNetworkFacts: async (step) => (step === 'email-refresh-facts' ? refreshed : initial),
      readExternalCallbackOutcome: async () => ({
        callbackAccepted: false,
        status: 400,
        error: 'unknown',
      }),
      clickAndObserveObject: async (step, _selector, project) =>
        project(
          step === 'email-userinfo'
            ? {
                sub: 'owned-user',
                email: options.profileEmail ?? 'owner@example.invalid',
                email_verified: true,
              }
            : { observed: true }
        ),
    };
    return session;
  };
  let providerCredentialActive = false;
  const input: CommonGoogleExistingOwnerTargetDriverInput = {
    target,
    fixture,
    signal: new AbortController().signal,
    browser,
    provider: {
      control: providerControl,
      container: 'google-provider',
      project: 'google-project',
      service: 'google-provider',
      image,
      configFile,
      receiptFile,
      healthDiagnosticFile,
      googleSubject: 'google-subject',
      originalOwnerEmail: 'owner@example.invalid',
      changedProviderEmail: 'changed@example.invalid',
      expectedUserinfoMethod: 'GET',
    },
    observer: {
      runInFreshContext: async () => {
        throw new Error('unbranded observer must not execute directly');
      },
    },
    createObserverForTesting: (capability) => {
      events.push('observer-create');
      const observer: Phase1BrowserGroupObserver = {
        runInFreshContext: async (_group, _signal, _target, use) => use(createSession(capability)),
      };
      return observer;
    },
    withProviderCredentialLease: async (use) => {
      providerCredentialActive = true;
      events.push('provider-credential-open');
      try {
        return await use({
          getClientId: () => 'google-client',
          getClientSecret: () => 'private-google-secret',
          toJSON: () => {
            throw new TypeError('private provider credentials');
          },
        });
      } finally {
        providerCredentialActive = false;
        events.push('provider-credential-close');
      }
    },
    fetch: requestFetch,
  };
  return {
    root,
    configFile,
    events,
    input,
    state: () => ({
      providerCredentialActive,
      sie,
      branding,
      previousBranding,
      appMetadata,
      role,
      connector,
      user,
    }),
  };
};

const withCandidateAdminTransport = async (
  harness: Awaited<ReturnType<typeof createHarness>>
): Promise<CommonGoogleExistingOwnerTargetDriverInput> => {
  const originalFetch = harness.input.fetch;
  if (!originalFetch) {
    throw new Error('missing test fetch');
  }
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const now = Math.floor(Date.now() / 1000);
  const bearer = await new SignJWT({ client_id: 'admin-console', scope: 'all' })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
    .setIssuer('http://localhost:3421/oidc')
    .setAudience('urn:aster:resource:management')
    .setSubject('phase1-admin')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  let authorizationState = '';
  let tokenRequests = 0;
  return {
    ...harness.input,
    target: { ...harness.input.target, label: 'candidate' },
    fetch: async (input, init) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input : input.url
      );
      if (url.origin !== 'http://localhost:3421') {
        return originalFetch(input, init);
      }
      harness.events.push(`admin:${url.pathname}`);
      if (url.pathname === '/oidc/auth' && url.searchParams.has('state')) {
        authorizationState = url.searchParams.get('state') ?? '';
        return new Response(null, {
          status: 303,
          headers: { 'set-cookie': 'aster-admin=private-cookie; Path=/; HttpOnly' },
        });
      }
      if (url.pathname === '/api/experience' && init?.method === 'PUT') {
        return empty();
      }
      if (url.pathname === '/api/experience/verification/password') {
        return json({ verificationId: 'private-verification' });
      }
      if (url.pathname === '/api/experience/identification') {
        return empty();
      }
      if (url.pathname === '/api/experience/submit') {
        return json({ redirectTo: '/oidc/auth/private-login-resume' });
      }
      if (url.pathname === '/oidc/auth/private-login-resume') {
        return new Response(null, {
          status: 303,
          headers: { location: '/consent?app_id=admin-console' },
        });
      }
      if (url.pathname === '/consent') {
        return new Response(null, {
          status: 302,
          headers: { location: '/oidc/auth/private-consent-resume' },
        });
      }
      if (url.pathname === '/oidc/auth/private-consent-resume') {
        return new Response(null, {
          status: 303,
          headers: {
            location:
              `http://localhost:3421/console/callback?code=private-code&state=${authorizationState}` +
              `&iss=${encodeURIComponent('http://localhost:3421/oidc')}`,
          },
        });
      }
      if (url.pathname === '/oidc/token') {
        tokenRequests += 1;
        return json(
          tokenRequests === 1
            ? {
                access_token: 'private-initial-access',
                id_token: 'private-initial-id',
                refresh_token: 'private-initial-refresh',
                token_type: 'Bearer',
              }
            : {
                access_token: bearer,
                id_token: 'private-refreshed-id',
                refresh_token: 'private-rotated-refresh',
                token_type: 'Bearer',
                scope: 'all',
              }
        );
      }
      if (url.pathname === '/oidc/jwks') {
        return json({ keys: [{ ...publicJwk, kid: 'test-key', alg: 'ES256', use: 'sig' }] });
      }
      if (url.pathname === '/oidc/token/revocation') {
        return json({});
      }
      return json({ private: 'unexpected-admin-route' }, 500);
    },
  };
};

test('runs the reviewed Google fixture and browser flow with exact provider and cleanup binding', async () => {
  const harness = await createHarness();
  const result = await runCommonGoogleExistingOwnerForTargetTesting(harness.input);
  expect(result).toMatchObject({
    provider: 'google',
    existingOwner: true,
    subjectPreserved: true,
    profileEmail: 'original-owner',
    providerEmailChangeObserved: true,
    refreshRotated: true,
  });
  const config = JSON.parse(await readFile(harness.configFile, 'utf8')) as Record<string, unknown>;
  expect(config).toMatchObject({
    connectorId: 'connector-instance',
    clientId: 'google-client',
    targetOrigin: 'http://localhost:3321',
    callbackUri: 'http://localhost:3321/callback/connector-instance',
  });
  const state = harness.state();
  expect(state).toMatchObject({
    providerCredentialActive: false,
    sie: ['github'],
    branding: { logoUrl: 'https://legacy.invalid/logo.svg' },
    appMetadata: { redirectUris: ['http://old.example/callback'] },
    role: false,
    connector: false,
  });
  expect(state.user).toBeUndefined();
  expect(harness.events.indexOf('provider:stop')).toBeLessThan(
    harness.events.indexOf('connector-delete')
  );
  await rm(harness.root, { recursive: true, force: true });
});

test('runs one fresh wrong-state browser callback and preserves the complete owner', async () => {
  const harness = await createHarness({ wrongState: true });
  const result = await runCommonGoogleExistingOwnerWrongStateForTargetTesting(harness.input);
  expect(result).toMatchObject({
    callbackAccepted: false,
    status: 400,
    error: 'unknown',
    ownerPreserved: true,
    authorization: {
      requestCount: 1,
      stateFormatValid: true,
      stateRoundTrip: false,
      fulfilledOnce: true,
    },
  });
  expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
  await rm(harness.root, { recursive: true, force: true });
});

test('replays the normal browser first verification then completes the existing-owner flow', async () => {
  const harness = await createHarness({ replay: true });
  const result = await runCommonGoogleExistingOwnerReplayForTargetTesting(harness.input);
  expect(result).toMatchObject({
    requestCount: 1,
    firstStatus: 200,
    firstOutcome: 'verified',
    secondStatus: 404,
    secondError: 'session.verification_session_not_found',
    secondAccepted: false,
    ownerPreserved: true,
  });
  expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
  await rm(harness.root, { recursive: true, force: true });
});

test('compensates the owner, provider, role, connector, and SIE when replay admission fails', async () => {
  const harness = await createHarness({ replay: true, replayFailure: true });
  await expect(runCommonGoogleExistingOwnerReplayForTargetTesting(harness.input)).rejects.toThrow(
    'Common Google existing-owner failed: provider-click'
  );
  expect(harness.state()).toMatchObject({
    providerCredentialActive: false,
    sie: ['github'],
    branding: { logoUrl: 'https://legacy.invalid/logo.svg' },
    role: false,
    connector: false,
    user: undefined,
  });
  expect(harness.events).toContain('provider:stop');
  await rm(harness.root, { recursive: true, force: true });
});

test('preserves the exact flow stage after fixture redaction and cleanup', async () => {
  const harness = await createHarness({ profileEmail: 'foreign@example.invalid' });
  await expect(runCommonGoogleExistingOwnerForTargetTesting(harness.input)).rejects.toThrow(
    'Common Google existing-owner failed: profile'
  );
  expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
  await rm(harness.root, { recursive: true, force: true });
});

test('preserves an exact callback field after fixture cleanup', async () => {
  const harness = await createHarness({ callbackRouteFails: true });
  await expect(runCommonGoogleExistingOwnerForTargetTesting(harness.input)).rejects.toThrow(
    'Common Google existing-owner failed: callback-callback-route'
  );
  expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
  await rm(harness.root, { recursive: true, force: true });
});

test.each([
  ['/api/roles', 'POST', 'fixture-create-role'],
  ['/api/users/owned-user/identities', 'POST', 'fixture-existing-owner-associate'],
] as const)(
  'preserves the exact fixture stage %s after cleanup',
  async (pathname, method, expected) => {
    const harness = await createHarness();
    const originalFetch = harness.input.fetch;
    if (!originalFetch) {
      throw new Error('missing test fetch');
    }
    const targetInput = {
      ...harness.input,
      fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          typeof input === 'string' ? input : input instanceof URL ? input : input.url
        );
        return url.pathname === pathname && (init?.method ?? 'GET') === method
          ? json({ private: 'must-not-propagate' }, 500)
          : originalFetch(input, init);
      },
    };
    await expect(runCommonGoogleExistingOwnerForTargetTesting(targetInput)).rejects.toThrow(
      `Common Google existing-owner target failed: ${expected}`
    );
    expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
    await rm(harness.root, { recursive: true, force: true });
  }
);

test('preserves exact connector cleanup priority over an owner fixture failure', async () => {
  const harness = await createHarness({ stopFails: true });
  const originalFetch = harness.input.fetch;
  if (!originalFetch) {
    throw new Error('missing test fetch');
  }
  const targetInput = {
    ...harness.input,
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input : input.url
      );
      return url.pathname === '/api/users/owned-user/identities' && init?.method === 'POST'
        ? json({ private: 'must-not-propagate' }, 500)
        : originalFetch(input, init);
    },
  };
  await expect(runCommonGoogleExistingOwnerForTargetTesting(targetInput)).rejects.toThrow(
    'Common Google existing-owner target failed: fixture-stop-provider'
  );
  expect(harness.state().providerCredentialActive).toBe(false);
  await rm(harness.root, { recursive: true, force: true });
});

test.each([
  [{ providerWrongIdentity: true }, 'fixture-prepare-connector-container-admission'],
  [{ providerHealth: 'unhealthy' as const }, 'fixture-prepare-connector-health'],
] as const)('propagates the exact provider lease stage %s', async (options, expected) => {
  const harness = await createHarness(options);
  await expect(runCommonGoogleExistingOwnerForTargetTesting(harness.input)).rejects.toThrow(
    `Common Google existing-owner target failed: ${expected}`
  );
  expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
  await rm(harness.root, { recursive: true, force: true });
});

test('reports cleanup before a latched flow failure', async () => {
  const harness = await createHarness({
    profileEmail: 'foreign@example.invalid',
    stopFails: true,
  });
  await expect(runCommonGoogleExistingOwnerForTargetTesting(harness.input)).rejects.toThrow(
    'Common Google existing-owner target failed: fixture-stop-provider'
  );
  expect(harness.state().providerCredentialActive).toBe(false);
  await rm(harness.root, { recursive: true, force: true });
});

test('production entrypoint rejects an unbranded observer after fixture preparation and cleanup', async () => {
  const harness = await createHarness();
  await expect(runCommonGoogleExistingOwnerForTarget(harness.input)).rejects.toThrow(
    'Common Google existing-owner target failed: capability'
  );
  expect(harness.state()).toMatchObject({ role: false, connector: false, user: undefined });
  await rm(harness.root, { recursive: true, force: true });
});

test('uses the Candidate Admin bearer boundary and closes both credential scopes on failure', async () => {
  const harness = await createHarness();
  const originalFetch = harness.input.fetch;
  if (!originalFetch) {
    throw new Error('missing test fetch');
  }
  const candidateInput: CommonGoogleExistingOwnerTargetDriverInput = {
    ...harness.input,
    target: { ...harness.input.target, label: 'candidate' },
    fetch: async (input, init) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input : input.url
      );
      return url.pathname === '/oidc/.well-known/openid-configuration'
        ? originalFetch(input, init)
        : empty(500);
    },
  };
  await expect(runCommonGoogleExistingOwnerForTargetTesting(candidateInput)).rejects.toThrow(
    'Common Google existing-owner target failed: management'
  );
  expect(harness.state().providerCredentialActive).toBe(false);
  expect(harness.events).not.toContain('provider:start');
  await rm(harness.root, { recursive: true, force: true });
});

test.each([
  ['flow', false, 'Common Google existing-owner failed: profile'],
  ['cleanup', true, 'Common Google existing-owner target failed: fixture-stop-provider'],
] as const)(
  'restores Candidate consumer %s only after Admin and provider cleanup',
  async (_kind, stopFails, expected) => {
    const harness = await createHarness({
      profileEmail: 'foreign@example.invalid',
      stopFails,
    });
    const candidateInput = await withCandidateAdminTransport(harness);
    await expect(runCommonGoogleExistingOwnerForTargetTesting(candidateInput)).rejects.toThrow(
      expected
    );
    expect(harness.events).toContain('observer-create');
    expect(harness.events.at(-2)).toBe('admin:/oidc/token/revocation');
    expect(harness.events.at(-1)).toBe('provider-credential-close');
    expect(harness.state().providerCredentialActive).toBe(false);
    await rm(harness.root, { recursive: true, force: true });
  }
);

test('rejects an invalid target descriptor before discovery or either credential lease', async () => {
  const harness = await createHarness();
  await expect(
    runCommonGoogleExistingOwnerForTargetTesting({
      ...harness.input,
      target: { ...harness.input.target, coreUrl: 'http://user@localhost:3321/' },
    })
  ).rejects.toThrow('Common Google existing-owner target failed: admission');
  expect(harness.events).toEqual([]);
  await rm(harness.root, { recursive: true, force: true });
});

test('rejects foreign discovery before either credential lease or provider operation', async () => {
  const harness = await createHarness();
  const input = {
    ...harness.input,
    fetch: async () => json({ issuer: 'https://foreign.example/oidc' }),
  };
  await expect(runCommonGoogleExistingOwnerForTargetTesting(input)).rejects.toThrow(
    'Common Google existing-owner target failed: discovery'
  );
  expect(harness.events).toEqual([]);
  await rm(harness.root, { recursive: true, force: true });
});
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
