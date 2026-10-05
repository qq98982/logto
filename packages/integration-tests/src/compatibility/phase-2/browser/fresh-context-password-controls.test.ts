/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Fresh fake sessions expose lifecycle and ordered UI calls. */
import type {
  Phase1BrowserGroupObserver,
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';

import { createFreshContextPasswordControls } from './fresh-context-password-controls.js';

const networkFacts: Phase1BrowserNetworkFacts = {
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
};

const fakeSession = (id: number, actions: string[]): Phase1BrowserSession => ({
  preloadDemoConfiguration: async () => {
    actions.push(`${id}:preload`);
  },
  navigate: async () => {
    actions.push(`${id}:navigate`);
  },
  waitForRoute: async (_step, _endpoint, paths) => {
    actions.push(`${id}:route:${paths.join('|')}`);
  },
  waitForExactRoute: async (_step, _endpoint, path) => {
    actions.push(`${id}:exact:${path}`);
  },
  assertRoute: async () => {
    actions.push(`${id}:assert-route`);
  },
  assertExactRoute: async () => {},
  fill: async (step) => {
    actions.push(`${id}:fill:${step}`);
  },
  click: async (step) => {
    actions.push(`${id}:click:${step}`);
  },
  expectText: async (_step, _selector, expected) => {
    actions.push(`${id}:text:${expected}`);
  },
  expectCount: async () => {},
  waitForNetworkFacts: async () => networkFacts,
  clickAndObserveObject: async (_step, _selector, project) =>
    project({ sub: 'username-subject', email: 'preserved@example.invalid' }),
});

test('runs every password control in a distinct fresh context with observable UI proof', async () => {
  const actions: string[] = [];
  let contexts = 0;
  const observer: Phase1BrowserGroupObserver = {
    runInFreshContext: async (_group, _signal, _target, use) => {
      contexts += 1;
      return use(fakeSession(contexts, actions));
    },
  };
  const controls = createFreshContextPasswordControls({
    observer,
    target: {
      label: 'candidate',
      coreUrl: 'https://core.example',
      adminUrl: 'https://admin.example',
    },
    signal: new AbortController().signal,
    configuration: {
      storageKey: 'config',
      demo: {
        appId: 'app',
        prompt: 'consent',
        scope: 'openid profile offline_access',
        resource: 'https://api.example',
      },
      expectedIssuer: 'https://core.example/oidc',
      redirectUri: 'https://core.example/demo-app',
      initialResponseScope: 'openid profile offline_access',
      resourceScope: 'read:profile',
    },
    canonicalEmail: 'owner@example.invalid',
    emailSubject: 'email-subject',
    usernameSubject: 'username-subject',
  });
  await controls.assertInvalidPassword('owner@example.invalid', 'private-wrong');
  await controls.assertSuspended('owner@example.invalid', 'private-right');
  await expect(controls.authenticateUsername('preserved-user', 'private-preserved')).resolves.toBe(
    'username-subject'
  );
  expect(contexts).toBe(3);
  expect(actions).toContain('1:text:Incorrect account or password. Please check your input.');
  expect(actions).toContain('2:exact:/account-suspended?app_id=app');
  expect(actions).toContain('3:click:username-authorize');
  expect(actions).toContain('3:click:open-email-dev-panel');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
