/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One-shot subject binding gates strict callback, profile, and refresh evidence. */
import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';

import type { EmailPasswordRegistrationSession } from './common-email-password-registration.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';

const fail = (): never => {
  throw new TypeError('Invalid Common email password registration browser adapter');
};

export const adaptPhase1SessionForEmailPasswordRegistration = (
  phase1: Phase1BrowserSession,
  configuration: Readonly<{
    storageKey: string;
    demo: Phase1ProfiledDemoConfiguration;
    expectedIssuer: string;
    canonicalEmail: string;
    resource: string;
    redirectUri: string;
    initialResponseScope: string;
    resourceScope: string;
  }>
): Readonly<{
  session: EmailPasswordRegistrationSession;
  bindRegisteredSubject(id: string): void;
}> => {
  let subject: string | undefined;
  const shared = () =>
    subject
      ? adaptPhase1SessionForEmailPassword(phase1, {
          ...configuration,
          expectedSubject: subject,
        })
      : fail();
  const session: EmailPasswordRegistrationSession = Object.freeze({
    navigate: async (step, path) => {
      await phase1.preloadDemoConfiguration(
        'preload-email-password-registration',
        configuration.storageKey,
        configuration.demo
      );
      await phase1.navigate(step, 'core', path);
    },
    waitForRoute: async (step, paths) => phase1.waitForRoute(step, 'core', paths),
    fill: async (step, selector, value) => {
      if (selector === 'input[name="identifier"]') {
        const paths = step.startsWith('registration-')
          ? ['/register']
          : ['/sign-in', '/sign-in/password'];
        return phase1.fill(step, selector, value, { endpoint: 'core', paths });
      }
      if (/^input\[name="passcode_[0-5]"\]$/u.test(selector)) {
        return phase1.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/register/verification-code'],
        });
      }
      if (
        selector === 'input[name="newPassword"]' ||
        selector === 'input[name="confirmPassword"]'
      ) {
        return phase1.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/continue/password'],
        });
      }
      if (selector === 'input[name="password"]') {
        return phase1.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/sign-in', '/sign-in/password'],
        });
      }
      return fail();
    },
    click: async (step, selector) => {
      if (selector === 'role=link[name="Create account"]') {
        return phase1.click(step, selector, {
          endpoint: 'core',
          paths: ['/sign-in', '/sign-in/password'],
        });
      }
      if (selector === 'button[name="submit"]') {
        const paths =
          step === 'registration-submit-email'
            ? ['/register']
            : step === 'registration-save'
              ? ['/continue/password']
              : ['/sign-in', '/sign-in/password'];
        return phase1.click(step, selector, { endpoint: 'core', paths });
      }
      if (selector === 'role=button[name="Authorize"]') {
        return phase1.click(step, selector, { endpoint: 'core', paths: ['/consent'] });
      }
      return fail();
    },
    confirmCredentialIfPresent: async (value) => {
      try {
        await phase1.expectCount('registration-confirm-absent', 'input[name="confirmPassword"]', 0);
        return;
      } catch {
        await phase1.expectCount(
          'registration-confirm-present',
          'input[name="confirmPassword"]',
          1
        );
      }
      await phase1.fill('registration-confirm-credential', 'input[name="confirmPassword"]', value, {
        endpoint: 'core',
        paths: ['/continue/password'],
      });
    },
    assertInitialCallback: async () => shared().assertInitialCallback(),
    readProfile: async () => shared().readProfile(),
    refresh: async () => shared().refresh(),
  });
  return Object.freeze({
    session,
    bindRegisteredSubject: (id: string) => {
      if (subject !== undefined || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) {
        return fail();
      }
      subject = id;
    },
  });
};
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
