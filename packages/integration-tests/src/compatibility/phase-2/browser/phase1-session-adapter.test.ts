/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions -- Fake session records the existing Phase 1 browser contract. */
import type {
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';

import {
  adaptPhase1SessionForEmailPassword,
  classifyRefreshScope,
} from './phase1-session-adapter.js';

test.each([
  ['read:profile', 'api-only'],
  ['openid profile read:profile', 'oidc-plus-api'],
  ['openid profile', 'oidc-only'],
  ['', 'missing'],
  ['private:unknown', 'other'],
] as const)('classifies refresh scope without retaining values (%s)', (value, expected) => {
  const result = classifyRefreshScope(value, 'read:profile');
  expect(result).toBe(expected);
  expect(result).not.toContain('private');
});

const initialFacts = (): Phase1BrowserNetworkFacts => ({
  signIns: [
    {
      authority: 'core',
      status: 303,
      queryShapeExact: true,
      clientId: 'app',
      redirectUri: 'https://core.example/demo-app',
      responseType: 'code',
      prompt: 'consent',
      scope: 'openid profile offline_access',
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
      stateMatches: true,
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
      responseScope: 'openid profile offline_access',
      accessKind: 'opaque',
    },
  ],
  endpointDiscoveries: [],
  accountReads: [],
  applicationReads: [],
  userReads: [],
});

const configuration = {
  storageKey: 'config',
  demo: {
    appId: 'app',
    prompt: 'consent',
    scope: 'openid profile offline_access',
    resource: 'https://api.example',
  },
  expectedSubject: 'user',
  expectedIssuer: 'https://core.example/oidc',
  canonicalEmail: 'owner@example.invalid',
  resource: 'https://api.example',
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid profile offline_access',
  resourceScope: 'read:profile',
} as const;

const sessionWithFacts = (
  facts: Phase1BrowserNetworkFacts,
  actions: string[] = []
): Phase1BrowserSession =>
  ({
    preloadDemoConfiguration: async () => {
      actions.push('preload');
    },
    navigate: async () => {
      actions.push('navigate');
    },
    waitForRoute: async () => {},
    waitForExactRoute: async () => {},
    assertRoute: async () => {},
    assertExactRoute: async () => {},
    fill: async () => {},
    click: async () => {},
    expectText: async () => {},
    expectCount: async () => {},
    waitForNetworkFacts: async () => facts,
    clickAndObserveObject: async (_step, _selector, project) =>
      project({ sub: 'user', email: 'owner@example.invalid' }),
  }) as Phase1BrowserSession;

test('requires the complete existing Phase 1 callback chain', async () => {
  const actions: string[] = [];
  const adapter = adaptPhase1SessionForEmailPassword(
    sessionWithFacts(initialFacts(), actions),
    configuration
  );
  await adapter.navigate('open', '/demo-app');
  expect(actions).toEqual(['preload', 'navigate']);
  await expect(adapter.assertInitialCallback()).resolves.toBeUndefined();
});

test('rejects a callback chain whose code exchange is not correlated', async () => {
  const facts = initialFacts();
  const adapter = adaptPhase1SessionForEmailPassword(
    sessionWithFacts({
      ...facts,
      exchanges: [{ ...facts.exchanges[0]!, requestCorrelationValid: false }],
    }),
    configuration
  );
  await expect(adapter.assertInitialCallback()).rejects.toThrow(
    'Common email password callback failed: exchange-correlation'
  );
});

test('rejects a resourceless initial exchange that returns the resource scope', async () => {
  const facts = initialFacts();
  const adapter = adaptPhase1SessionForEmailPassword(
    sessionWithFacts({
      ...facts,
      exchanges: [
        {
          ...facts.exchanges[0]!,
          responseScope: 'openid profile offline_access read:profile',
        },
      ],
    }),
    configuration
  );
  await expect(adapter.assertInitialCallback()).rejects.toThrow(
    'Common email password callback failed: exchange-scope'
  );
});

test('reports bounded callback and initial exchange counts when facts wait fails', async () => {
  const facts = initialFacts();
  const session = sessionWithFacts(facts);
  session.waitForNetworkFacts = async (_step, accept) => {
    accept({ ...facts, callbacks: [], exchanges: [...facts.exchanges, facts.exchanges[0]!] });
    throw new Error('private observer detail');
  };
  const adapter = adaptPhase1SessionForEmailPassword(session, configuration);
  await expect(adapter.assertInitialCallback()).rejects.toThrow(
    'Common email password callback failed: callback-facts-s1-c0-imany'
  );
});

test.each([
  ['string audience', 'https://api.example', null, {}],
  ['one-element audience', ['https://api.example'], null, {}],
  ['foreign audience', ['https://foreign.example'], 'audience', {}],
  ['multiple audiences', ['https://api.example', 'https://foreign.example'], 'audience', {}],
  ['wrong request shape', 'https://api.example', 'request-shape', { requestShapeExact: false }],
  ['wrong correlation', 'https://api.example', 'correlation', { requestCorrelationValid: false }],
  [
    'wrong response scope',
    'https://api.example',
    'response-scope-other-claims-api-only',
    { responseScope: 'other' },
  ],
  [
    'OIDC plus API response scope',
    'https://api.example',
    'response-scope-oidc-plus-api-claims-api-only',
    { responseScope: 'openid profile read:profile' },
  ],
  [
    'OIDC-only response scope',
    'https://api.example',
    'response-scope-oidc-only-claims-api-only',
    { responseScope: 'openid profile' },
  ],
] as const)(
  'proves refresh rotation with %s',
  async (_name, audience, expectedFailure, override) => {
    const before = initialFacts();
    const refreshed: Phase1BrowserNetworkFacts = {
      ...before,
      exchanges: [
        ...before.exchanges,
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
            subject: 'user',
            audience,
            clientId: 'app',
            scope: 'read:profile',
            organizationIdPresent: false,
          },
          ...override,
        },
      ],
    };
    let reads = 0;
    const session = sessionWithFacts(before);
    session.waitForNetworkFacts = async () => (reads++ === 0 ? before : refreshed);
    const adapter = adaptPhase1SessionForEmailPassword(session, configuration);
    await (expectedFailure
      ? expect(adapter.refresh()).rejects.toThrow(
          `Common email password refresh failed: ${expectedFailure}`
        )
      : expect(adapter.refresh()).resolves.toEqual({ subject: 'user', rotated: true }));
  }
);
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions */
