import type { TargetConfig } from '../../model.js';
import type {
  Phase1BrowserGroupObserver,
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';

import type { CommonEmailPasswordControls } from './common-email-password-sign-in.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';

const signInRoutes = Object.freeze(['/sign-in', '/sign-in/password']);
const invalidPasswordText = 'Incorrect account or password. Please check your input.';
const suspendedPath = (appId: string) => `/account-suspended?app_id=${encodeURIComponent(appId)}`;
const suspendedText = 'Account suspended';

export type CommonEmailPasswordBrowserConfiguration = Readonly<{
  storageKey: string;
  demo: Phase1ProfiledDemoConfiguration;
  expectedIssuer: string;
  redirectUri: string;
  initialResponseScope: string;
  resourceScope: string;
}>;

const enterPassword = async (
  session: Phase1BrowserSession,
  configuration: CommonEmailPasswordBrowserConfiguration,
  identifier: string,
  password: string
): Promise<void> => {
  await session.preloadDemoConfiguration(
    'preload-control-demo',
    configuration.storageKey,
    configuration.demo
  );
  await session.navigate('open-control-demo', 'core', '/demo-app');
  await session.waitForRoute('wait-control-sign-in', 'core', signInRoutes);
  await session.fill('fill-control-identifier', 'input[name="identifier"]', identifier, {
    endpoint: 'core',
    paths: signInRoutes,
  });
  await session.fill('fill-control-password', 'input[name="password"]', password, {
    endpoint: 'core',
    paths: signInRoutes,
  });
  await session.click('submit-control-password', 'button[name="submit"]', {
    endpoint: 'core',
    paths: signInRoutes,
  });
};

export const createFreshContextPasswordControls = (
  input: Readonly<{
    observer: Phase1BrowserGroupObserver;
    target: TargetConfig;
    signal: AbortSignal;
    configuration: CommonEmailPasswordBrowserConfiguration;
    canonicalEmail: string;
    emailSubject: string;
    usernameSubject: string;
  }>
): Pick<
  CommonEmailPasswordControls,
  'assertInvalidPassword' | 'assertSuspended' | 'authenticateUsername'
> => ({
  assertInvalidPassword: async (identifier, password) =>
    input.observer.runInFreshContext('experience', input.signal, input.target, async (session) => {
      if (identifier !== input.canonicalEmail) {
        throw new TypeError('Invalid Common email password control identity');
      }
      await enterPassword(session, input.configuration, identifier, password);
      await session.assertRoute('invalid-password-route', 'core', signInRoutes);
      await session.expectText(
        'invalid-password-message',
        `text="${invalidPasswordText}"`,
        invalidPasswordText
      );
    }),
  assertSuspended: async (identifier, password) =>
    input.observer.runInFreshContext('experience', input.signal, input.target, async (session) => {
      if (identifier !== input.canonicalEmail || !input.emailSubject) {
        throw new TypeError('Invalid Common email password control identity');
      }
      await enterPassword(session, input.configuration, identifier, password);
      await session.waitForExactRoute(
        'suspended-route',
        'core',
        suspendedPath(input.configuration.demo.appId)
      );
      await session.expectText('suspended-message', `text="${suspendedText}"`, suspendedText);
    }),
  authenticateUsername: async (identifier, password) =>
    input.observer.runInFreshContext('experience', input.signal, input.target, async (session) => {
      await enterPassword(session, input.configuration, identifier, password);
      await session.waitForRoute('username-consent', 'core', ['/consent']);
      await session.click('username-authorize', 'role=button[name="Authorize"]');
      const adapter = adaptPhase1SessionForEmailPassword(session, {
        ...input.configuration,
        expectedSubject: input.usernameSubject,
        canonicalEmail: input.canonicalEmail,
        resource: input.configuration.demo.resource,
      });
      await adapter.assertInitialCallback();
      const profile = await adapter.readProfile();
      if (profile.sub !== input.usernameSubject) {
        throw new TypeError('Invalid Common email password username subject');
      }
      return input.usernameSubject;
    }),
});
