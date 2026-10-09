/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions -- The partial Phase 1 fake records exact registration selector guards. */
import type { Phase1BrowserSession } from '../../phase-1/browser/contracts.js';

import { adaptPhase1SessionForEmailPasswordRegistration } from './email-password-registration-phase1-session-adapter.js';

const configuration = {
  storageKey: 'config',
  demo: {
    appId: 'app',
    prompt: 'consent',
    scope: 'openid offline_access profile email read:profile',
    resource: 'https://api.example',
  },
  expectedIssuer: 'https://core.example/oidc',
  canonicalEmail: 'owner@example.invalid',
  resource: 'https://api.example',
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid offline_access profile email',
  resourceScope: 'read:profile',
} as const;

const phase1 = (actions: string[]): Phase1BrowserSession =>
  ({
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
    expectCount: async (_step, selector, count) => {
      actions.push(`count:${selector}:${count}`);
      if (count === 0) {
        throw new Error('confirmation is present');
      }
    },
    waitForNetworkFacts: async () => {
      throw new Error('private unused facts');
    },
    clickAndObserveObject: async () => {
      throw new Error('private unused observation');
    },
  }) as Phase1BrowserSession;

test('guards registration and fresh sign-in selectors on their exact routes', async () => {
  const actions: string[] = [];
  const adapted = adaptPhase1SessionForEmailPasswordRegistration(phase1(actions), configuration);
  await adapted.session.navigate('open', '/demo-app');
  await adapted.session.click('registration-create', 'role=link[name="Create account"]');
  await adapted.session.fill(
    'registration-email',
    'input[name="identifier"]',
    configuration.canonicalEmail
  );
  await adapted.session.fill('registration-digit-5', 'input[name="passcode_5"]', '5');
  await adapted.session.fill('registration-new-credential', 'input[name="newPassword"]', 'secret');
  await adapted.session.confirmCredentialIfPresent?.('secret');
  await adapted.session.fill(
    'registered-login-email',
    'input[name="identifier"]',
    configuration.canonicalEmail
  );
  await adapted.session.fill('registered-login-credential', 'input[name="password"]', 'secret');
  expect(actions).toContain('fill:input[name="identifier"]:/register');
  expect(actions).toContain('fill:input[name="passcode_5"]:/register/verification-code');
  expect(actions).toContain('fill:input[name="newPassword"]:/continue/password');
  expect(actions).toContain('fill:input[name="confirmPassword"]:/continue/password');
  expect(actions).toContain('fill:input[name="password"]:/sign-in|/sign-in/password');
});

test('requires one valid subject binding before callback, profile, or refresh evidence', async () => {
  const adapted = adaptPhase1SessionForEmailPasswordRegistration(phase1([]), configuration);
  await expect(adapted.session.assertInitialCallback()).rejects.toThrow(
    'Invalid Common email password registration browser adapter'
  );
  adapted.bindRegisteredSubject('registered-owner');
  expect(() => {
    adapted.bindRegisteredSubject('foreign-owner');
  }).toThrow('Invalid Common email password registration browser adapter');
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions */
