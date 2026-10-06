/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Exact request fake and composed consumer validate lookup, ordering, and cleanup. */
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import type { Phase2AdminRequest, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  commonEmailCodeRegistrationExpectedProjection,
  readRegisteredUserByEmail,
  runCommonEmailCodeRegistrationForTarget,
  runCommonEmailCodeRegistrationForTargetTesting,
} from './common-email-code-registration-target-driver.js';
import { registrationEmailForAllocation } from './selected-email-code-registration-fixture.js';

test('reads one exact registered email through the bounded Management query', async () => {
  const calls: Phase2AdminRequest[] = [];
  const result = await readRegisteredUserByEmail(async (request) => {
    calls.push(request);
    return [
      { id: 'foreign', primaryEmail: 'foreign@example.invalid' },
      { id: 'registered-user', primaryEmail: 'new@example.invalid' },
    ];
  }, 'new@example.invalid');
  expect(result).toEqual({ id: 'registered-user', primaryEmail: 'new@example.invalid' });
  expect(calls).toEqual([
    {
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    },
  ]);
});

test.each([
  [[]],
  [
    [
      { id: 'one', primaryEmail: 'new@example.invalid' },
      { id: 'two', primaryEmail: 'new@example.invalid' },
    ],
  ],
  [[{ id: 'private id', primaryEmail: 'new@example.invalid' }]],
] as const)('rejects zero, ambiguous, or malformed ownership before capture', async (users) => {
  await expect(readRegisteredUserByEmail(async () => users, 'new@example.invalid')).rejects.toThrow(
    'Common email code registration target failed: subject'
  );
});

test('rejects an unbranded observer before discovery, lease, or browser use', async () => {
  let fetches = 0;
  let leases = 0;
  await expect(
    runCommonEmailCodeRegistrationForTarget({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: {
        public: { allocationId: 'allocation' },
        withSecretLease: async () => {
          leases += 1;
          throw new Error('private lease');
        },
      } as unknown as ProvisionedPhase2Fixture,
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser: {
        storageKey: 'config',
        demo: { appId: 'app', prompt: 'consent', scope: 'openid', resource: 'resource' },
        redirectUri: 'https://core.example/demo-app',
        initialResponseScope: 'openid',
        resourceScope: 'read',
      },
      fetch: async () => {
        fetches += 1;
        throw new Error('private fetch');
      },
    })
  ).rejects.toThrow('Common email code registration target failed: capability');
  expect({ fetches, leases }).toEqual({ fetches: 0, leases: 0 });
});

test('preserves an awaited fixture stage across generic observer redaction', async () => {
  const fixture = {
    public: { allocationId: 'allocation' },
    status: {
      client: { id: 'app' },
      resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
    },
    withSecretLease: async (use: (lease: unknown) => Promise<unknown>) =>
      use({ takeVerificationCode: async () => '123456' }),
  } as unknown as ProvisionedPhase2Fixture;
  const observer = {
    runInFreshContext: async (_group, _signal, _target, use) => {
      try {
        return await use({} as never);
      } catch {
        throw new Error('private generic observer error');
      }
    },
  } as Phase1BrowserGroupObserver;
  let requests = 0;
  const operation = runCommonEmailCodeRegistrationForTargetTesting({
    target: { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
    fixture,
    observer,
    signal: new AbortController().signal,
    browser: {
      storageKey: 'config',
      demo: {
        appId: 'app',
        prompt: 'consent',
        scope: 'openid offline_access profile email read:profile',
        resource: 'https://api.example',
      },
      redirectUri: 'https://core.example/demo-app',
      initialResponseScope: 'openid offline_access profile email',
      resourceScope: 'read:profile',
    },
    fetch: async (url) => {
      requests += 1;
      if (String(url).includes('.well-known')) {
        return new Response(JSON.stringify({ issuer: 'https://core.example/oidc' }), {
          status: 200,
        });
      }
      throw new Error('private Management transport failure');
    },
  });
  await expect(operation).rejects.toThrow(
    'Common email code registration target failed: fixture-read-sie'
  );
  await expect(operation).rejects.not.toThrow('private');
  expect(requests).toBe(2);
});

const composedHarness = (
  stateMatches = true,
  failSieRestore = false,
  failControl: false | 'wrong-error' | 'success' = false
) => {
  const email = registrationEmailForAllocation('allocation');
  const users = new Map<string, { id: string; primaryEmail: string; roles: unknown[] }>();
  let rolePresent = false;
  let siePatchCount = 0;
  let route = '/sign-in';
  let reads = 0;
  let sie = {
    branding: { logoUrl: 'https://assets.example/logo.png' },
    signIn: {
      methods: [
        {
          identifier: 'username',
          password: true,
          verificationCode: false,
          isPasswordPrimary: true,
        },
      ],
    },
    signUp: { identifiers: ['username'], password: true, verify: false, secondaryIdentifiers: [] },
    languageInfo: { autoDetect: true },
  };
  const originalSie = structuredClone(sie);
  let metadata = { redirectUris: ['http://localhost:3001/demo-app'], postLogoutRedirectUris: [] };
  const originalMetadata = structuredClone(metadata);
  const initial = {
    signIns: [
      {
        authority: 'core',
        status: 303,
        queryShapeExact: true,
        clientId: 'app',
        redirectUri: 'https://core.example/demo-app',
        responseType: 'code',
        prompt: 'consent',
        scope: 'openid offline_access profile email read:profile',
        resources: ['https://api.example'],
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
        stateMatches,
        issuer: 'https://core.example/oidc',
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
        clientId: 'app',
        redirectUri: 'https://core.example/demo-app',
        initialRefreshPresent: true,
        replacementFresh: true,
        resource: null,
        organizationId: null,
        responseScope: 'openid offline_access profile email',
        accessKind: 'opaque',
      },
    ],
    endpointDiscoveries: [],
    accountReads: [],
    applicationReads: [],
    userReads: [],
  } as const;
  const refreshed = {
    ...initial,
    exchanges: [
      ...initial.exchanges,
      {
        kind: 'management',
        authority: 'core',
        status: 200,
        requestShapeExact: true,
        requestCorrelationValid: true,
        clientId: 'app',
        redirectUri: null,
        initialRefreshPresent: false,
        replacementFresh: true,
        resource: 'https://api.example',
        organizationId: null,
        responseScope: 'read:profile',
        accessKind: 'compact',
        compactAccess: {
          issuer: 'https://core.example/oidc',
          subject: 'registered-user',
          audience: 'https://api.example',
          clientId: 'app',
          scope: 'read:profile',
          organizationIdPresent: false,
        },
      },
    ],
  } as never;
  const phase1 = {
    preloadDemoConfiguration: async () => {},
    navigate: async () => {
      route = '/sign-in';
    },
    waitForRoute: async (_step: string, _endpoint: string, paths: readonly string[]) => {
      if (!paths.includes(route)) {
        throw new Error('private route');
      }
    },
    waitForExactRoute: async () => {
      if (route !== '/demo-app') {
        throw new Error('private callback route');
      }
    },
    assertRoute: async () => {},
    assertExactRoute: async () => {},
    fill: async (_step: string, selector: string) => {
      if (selector === 'input[name="passcode_5"]') {
        users.set('registered-user', {
          id: 'registered-user',
          primaryEmail: email,
          roles: [{ id: 'registration-role', type: 'User', isDefault: true }],
        });
        route = '/consent';
      }
    },
    click: async (_step: string, selector: string) => {
      if (selector.includes('Create account')) {
        route = '/register';
      } else if (selector === 'button[name="submit"]') {
        route = '/register/verification-code';
      } else if (selector.includes('Authorize')) {
        route = '/demo-app';
      }
    },
    expectText: async () => {},
    expectCount: async () => {},
    waitForNetworkFacts: async () => (reads++ < 2 ? initial : refreshed),
    clickAndObserveObject: async (
      _step: string,
      selector: string,
      project: (value: Record<string, unknown>) => unknown
    ) =>
      project(
        selector.includes('Fetch user info')
          ? { sub: 'registered-user', email, email_verified: true }
          : { observed: true }
      ),
  } as never;
  let controlEvent: 'SignIn' | 'Register' = 'SignIn';
  let controlInteraction = 0;
  let verificationCalls = 0;
  const fetch = async (input: URL | RequestInfo, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.pathname.includes('.well-known')) {
      return new Response(JSON.stringify({ issuer: 'https://core.example/oidc' }), { status: 200 });
    }
    if (url.pathname === '/oidc/auth') {
      controlInteraction += 1;
      verificationCalls = 0;
      const headers = new Headers();
      headers.append('set-cookie', `_interaction=i${controlInteraction}; Path=/`);
      headers.append('set-cookie', `_interaction.sig=s${controlInteraction}; Path=/`);
      return new Response(null, { status: 303, headers });
    }
    if (url.pathname === '/api/experience' && init?.method === 'PUT') {
      controlEvent = (JSON.parse(String(init.body)) as { interactionEvent: 'SignIn' | 'Register' })
        .interactionEvent;
      return new Response(null, { status: 204 });
    }
    if (
      url.pathname === '/api/experience/verification/verification-code' &&
      init?.method === 'POST'
    ) {
      return new Response(JSON.stringify({ verificationId: 'control-handle' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (
      url.pathname === '/api/experience/verification/verification-code/verify' &&
      init?.method === 'POST'
    ) {
      verificationCalls += 1;
      if (verificationCalls === 2) {
        return new Response(
          JSON.stringify({ code: 'verification_code.not_found', message: 'private replay detail' }),
          { status: 400, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ verificationId: 'control-proof' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.pathname === '/api/experience/identification' && init?.method === 'POST') {
      if (controlEvent === 'Register' && failControl === 'success') {
        return new Response(null, { status: 200 });
      }
      const code =
        controlEvent === 'SignIn' || failControl === 'wrong-error'
          ? 'user.user_not_exist'
          : 'user.email_already_in_use';
      return new Response(JSON.stringify({ code }), {
        status: controlEvent === 'SignIn' ? 404 : 422,
        headers: { 'content-type': 'application/json' },
      });
    }
    const path = url.pathname.replace(/^\/api\//u, '');
    const method = init?.method ?? 'GET';
    const body = init?.body
      ? (JSON.parse(String(init.body)) as Record<string, unknown>)
      : undefined;
    const json = (value: unknown, status = 200) =>
      new Response(JSON.stringify(value), {
        status,
        headers: { 'content-type': 'application/json' },
      });
    if (path === 'sign-in-exp' && method === 'GET') {
      return json(sie);
    }
    if (path === 'sign-in-exp' && method === 'PATCH') {
      siePatchCount += 1;
      if (failSieRestore && siePatchCount === 2) {
        throw new Error('private SIE restore failure');
      }
      sie = { ...sie, ...body } as typeof sie;
      return json(sie);
    }
    if (path === 'applications/app' && method === 'GET') {
      return json({ id: 'app', type: 'SPA', oidcClientMetadata: metadata });
    }
    if (path === 'applications/app' && method === 'PATCH') {
      metadata = (body?.oidcClientMetadata ?? metadata) as typeof metadata;
      return json({ id: 'app', type: 'SPA', oidcClientMetadata: metadata });
    }
    if (path === 'resources') {
      return json([{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }]);
    }
    if (path === 'roles' && method === 'POST') {
      rolePresent = true;
      return json({ id: 'registration-role', type: 'User', isDefault: true });
    }
    if (path === 'roles/registration-role/scopes') {
      return json([{ id: 'scope', resourceId: 'resource', name: 'read:profile' }]);
    }
    if (path === 'users') {
      return json([...users.values()]);
    }
    if (path === 'users/registered-user/roles') {
      return json(users.get('registered-user')?.roles ?? []);
    }
    if (path === 'users/registered-user' && method === 'GET') {
      return json(users.get('registered-user'));
    }
    if (path === 'users/registered-user' && method === 'DELETE') {
      users.delete('registered-user');
      return new Response(null, { status: 204 });
    }
    if (path === 'roles/registration-role' && method === 'DELETE') {
      rolePresent = false;
      return new Response(null, { status: 204 });
    }
    throw new Error(`private unexpected ${method} ${path}`);
  };
  const fixture = {
    public: { allocationId: 'allocation' },
    status: {
      client: { id: 'app' },
      resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
    },
    withSecretLease: async (use: (lease: unknown) => Promise<unknown>) =>
      use({ takeVerificationCode: async () => '123456' }),
  } as unknown as ProvisionedPhase2Fixture;
  const observer = {
    runInFreshContext: async (_group, _signal, _target, use) => use(phase1),
  } as Phase1BrowserGroupObserver;
  return {
    users,
    originalSie,
    originalMetadata,
    current: () => ({ sie, metadata, rolePresent }),
    fixture,
    observer,
    fetch,
  };
};

test.each([
  [true, false, null],
  [false, false, 'Common email code registration target failed: flow-callback-callback-state'],
  [
    true,
    'wrong-error',
    'Common email code registration target failed: controls-register-identification-identify-s422-user-user-not-exist',
  ],
  [
    true,
    'success',
    'Common email code registration target failed: controls-register-identification-identify-s200-none',
  ],
] as const)(
  'runs the real composed registration consumer with callback state=%s and control failure=%s',
  async (stateMatches, failControl, failure) => {
    const harness = composedHarness(stateMatches, false, failControl);
    const operation = runCommonEmailCodeRegistrationForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: harness.fixture,
      observer: harness.observer,
      signal: new AbortController().signal,
      browser: {
        storageKey: 'config',
        demo: {
          appId: 'app',
          prompt: 'consent',
          scope: 'openid offline_access profile email read:profile',
          resource: 'https://api.example',
        },
        redirectUri: 'https://core.example/demo-app',
        initialResponseScope: 'openid offline_access profile email',
        resourceScope: 'read:profile',
      },
      fetch: harness.fetch,
    });
    await (failure
      ? expect(operation).rejects.toThrow(failure)
      : expect(operation).resolves.toEqual(commonEmailCodeRegistrationExpectedProjection));
    expect(harness.users.has('registered-user')).toBe(false);
    expect(harness.current()).toEqual({
      sie: harness.originalSie,
      metadata: harness.originalMetadata,
      rolePresent: false,
    });
  }
);

test('gives cleanup precedence after verified capture and callback failure', async () => {
  const harness = composedHarness(false, true);
  const operation = runCommonEmailCodeRegistrationForTargetTesting({
    target: { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
    fixture: harness.fixture,
    observer: harness.observer,
    signal: new AbortController().signal,
    browser: {
      storageKey: 'config',
      demo: {
        appId: 'app',
        prompt: 'consent',
        scope: 'openid offline_access profile email read:profile',
        resource: 'https://api.example',
      },
      redirectUri: 'https://core.example/demo-app',
      initialResponseScope: 'openid offline_access profile email',
      resourceScope: 'read:profile',
    },
    fetch: harness.fetch,
  });
  await expect(operation).rejects.toThrow(
    'Common email code registration target failed: fixture-cleanup'
  );
  await expect(operation).rejects.not.toThrow('private SIE restore failure');
  expect(harness.users.has('registered-user')).toBe(false);
  expect(harness.current().metadata).toEqual(harness.originalMetadata);
  expect(harness.current().rolePresent).toBe(false);
  expect(harness.current().sie).not.toEqual(harness.originalSie);
});

test('captures one closed Reference replay observation inside the compensated fixture use', async () => {
  const harness = composedHarness();
  const observations: unknown[] = [];
  await expect(
    runCommonEmailCodeRegistrationForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: harness.fixture,
      observer: harness.observer,
      signal: new AbortController().signal,
      browser: {
        storageKey: 'config',
        demo: {
          appId: 'app',
          prompt: 'consent',
          scope: 'openid offline_access profile email read:profile',
          resource: 'https://api.example',
        },
        redirectUri: 'https://core.example/demo-app',
        initialResponseScope: 'openid offline_access profile email',
        resourceScope: 'read:profile',
      },
      fetch: harness.fetch,
      captureReferenceReplay: async (observation) => {
        observations.push(observation);
      },
    })
  ).resolves.toMatchObject({ registrationOutcome: 'created', refreshRotated: true });
  expect(observations).toEqual([
    {
      first: { status: 's200', outcome: 'verified', error: 'none' },
      second: { status: 's400', outcome: 'error', error: 'verification_code.not_found' },
    },
  ]);
  expect(harness.users.has('registered-user')).toBe(false);
  expect(harness.current()).toEqual({
    sie: harness.originalSie,
    metadata: harness.originalMetadata,
    rolePresent: false,
  });
});
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
