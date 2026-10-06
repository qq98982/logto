/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Fake Phase1 session enforces route and protocol facts. */
import type {
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';

import { adaptPhase1SessionForEmailCodeRegistration } from './email-code-registration-phase1-session-adapter.js';

const configuration = {
  storageKey: 'config',
  demo: {
    appId: 'app',
    prompt: 'consent',
    scope: 'openid offline_access profile email read:profile',
    resource: 'https://api.example',
  },
  expectedIssuer: 'https://core.example/oidc',
  canonicalEmail: 'new@example.invalid',
  resource: 'https://api.example',
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid offline_access profile email',
  resourceScope: 'read:profile',
} as const;

const facts = (
  callback: Readonly<{ stateMatches?: boolean; issuer?: string; codePresent?: boolean }> = {}
): Phase1BrowserNetworkFacts => ({
  signIns: [
    {
      authority: 'core',
      status: 303,
      queryShapeExact: true,
      clientId: 'app',
      redirectUri: configuration.redirectUri,
      responseType: 'code',
      prompt: 'consent',
      scope: configuration.demo.scope,
      resources: [configuration.resource],
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
      stateMatches: callback.stateMatches ?? true,
      issuer: callback.issuer ?? configuration.expectedIssuer,
      codePresent: callback.codePresent ?? true,
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
      redirectUri: configuration.redirectUri,
      initialRefreshPresent: true,
      replacementFresh: true,
      resource: null,
      organizationId: null,
      responseScope: configuration.initialResponseScope,
      accessKind: 'opaque',
    },
  ],
  endpointDiscoveries: [],
  accountReads: [],
  applicationReads: [],
  userReads: [],
});

const phase1 = (
  actions: string[],
  callback: Readonly<{ stateMatches?: boolean; issuer?: string; codePresent?: boolean }> = {},
  refreshSubject = 'registered-user'
): Phase1BrowserSession => {
  let reads = 0;
  const initial = facts(callback);
  const refreshed: Phase1BrowserNetworkFacts = {
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
        resource: configuration.resource,
        organizationId: null,
        responseScope: configuration.resourceScope,
        accessKind: 'compact',
        compactAccess: {
          issuer: configuration.expectedIssuer,
          subject: refreshSubject,
          audience: configuration.resource,
          clientId: 'app',
          scope: configuration.resourceScope,
          organizationIdPresent: false,
        },
      },
    ],
  };
  return {
    preloadDemoConfiguration: async () => {
      actions.push('preload');
    },
    navigate: async (_step, endpoint, path) => {
      actions.push(`navigate:${endpoint}:${path}`);
    },
    waitForRoute: async () => {},
    waitForExactRoute: async () => {},
    assertRoute: async () => {},
    assertExactRoute: async () => {},
    fill: async (_step, selector, _value, guard) => {
      actions.push(`fill:${selector}:${guard.paths.join('|')}`);
    },
    click: async (_step, selector, guard) => {
      actions.push(`click:${selector}:${guard?.paths.join('|') ?? 'none'}`);
    },
    expectText: async () => {},
    expectCount: async () => {},
    waitForNetworkFacts: async () => (reads++ < 2 ? initial : refreshed),
    clickAndObserveObject: async (_step, selector, project) =>
      project(
        selector.includes('Fetch user info')
          ? { sub: 'registered-user', email: configuration.canonicalEmail, email_verified: true }
          : { observed: true }
      ),
  };
};

test('guards Register selectors on exact routes and binds the subject once', async () => {
  const actions: string[] = [];
  const adapter = adaptPhase1SessionForEmailCodeRegistration(phase1(actions), configuration);
  await adapter.session.navigate('open', '/demo-app');
  await adapter.session.click('register', 'role=link[name="Create account"]');
  await adapter.session.fill('email', 'input[name="identifier"]', configuration.canonicalEmail);
  await adapter.session.click('submit', 'button[name="submit"]');
  for (let index = 0; index < 6; index += 1) {
    await adapter.session.fill('code', `input[name="passcode_${index}"]`, String(index));
  }
  adapter.bindRegisteredSubject('registered-user');
  expect(() => {
    adapter.bindRegisteredSubject('foreign-user');
  }).toThrow('Invalid Common email code registration browser adapter');
  expect(actions).toContain('click:role=link[name="Create account"]:/sign-in|/sign-in/password');
  expect(actions).toContain('fill:input[name="identifier"]:/register');
  expect(actions).toContain('fill:input[name="passcode_5"]:/register/verification-code');
});

test('fails callback, profile, and refresh closed before subject binding', async () => {
  const adapter = adaptPhase1SessionForEmailCodeRegistration(phase1([]), configuration);
  await expect(adapter.session.assertInitialCallback()).rejects.toThrow(
    'Invalid Common email code registration browser adapter'
  );
  await expect(adapter.session.readProfile()).rejects.toThrow(
    'Invalid Common email code registration browser adapter'
  );
  await expect(adapter.session.refresh()).rejects.toThrow(
    'Invalid Common email code registration browser adapter'
  );
});

test('retains strict callback state and post-bind profile/resource refresh checks', async () => {
  const adapter = adaptPhase1SessionForEmailCodeRegistration(phase1([]), configuration);
  adapter.bindRegisteredSubject('registered-user');
  await expect(adapter.session.assertInitialCallback()).resolves.toBeUndefined();
  await expect(adapter.session.readProfile()).resolves.toEqual({
    sub: 'registered-user',
    email: configuration.canonicalEmail,
    emailVerified: true,
  });
  await expect(adapter.session.refresh()).resolves.toEqual({
    subject: 'registered-user',
    rotated: true,
  });
});

test.each([
  [{ stateMatches: false }, 'callback-state'],
  [{ issuer: 'https://foreign.example/oidc' }, 'callback-issuer'],
  [{ codePresent: false }, 'callback-code'],
] as const)('retains the strict callback %s rejection', async (override, field) => {
  const adapter = adaptPhase1SessionForEmailCodeRegistration(phase1([], override), configuration);
  adapter.bindRegisteredSubject('registered-user');
  await expect(adapter.session.assertInitialCallback()).rejects.toThrow(
    `Common email password callback failed: ${field}`
  );
});

test('binds resource refresh to the captured registered subject', async () => {
  const adapter = adaptPhase1SessionForEmailCodeRegistration(
    phase1([], {}, 'foreign-user'),
    configuration
  );
  adapter.bindRegisteredSubject('registered-user');
  await adapter.session.assertInitialCallback();
  await expect(adapter.session.refresh()).rejects.toThrow(
    'Common email password refresh failed: subject'
  );
});

test('returns a failed initialization fact without waiting for a send response', async () => {
  const failed: Phase1BrowserNetworkFacts = {
    ...facts(),
    registrationRequests: [{ kind: 'init', status: 404, error: 'session.interaction_not_found' }],
  };
  const base = phase1([]);
  const adapter = adaptPhase1SessionForEmailCodeRegistration(
    {
      ...base,
      waitForNetworkFacts: async (_step, accept) => {
        expect(accept(failed)).toBe(true);
        return failed;
      },
    },
    configuration
  );
  await expect(adapter.session.registrationRequestFacts?.()).resolves.toEqual(
    failed.registrationRequests
  );
});
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
