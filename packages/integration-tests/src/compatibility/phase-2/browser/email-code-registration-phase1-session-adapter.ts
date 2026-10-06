/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One-shot local subject binding gates the existing strict adapter. */
import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';

import type { CommonEmailCodeBrowserSession } from './common-email-code-sign-in.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';

const fail = (): never => {
  throw new TypeError('Invalid Common email code registration browser adapter');
};

export const adaptPhase1SessionForEmailCodeRegistration = (
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
  session: CommonEmailCodeBrowserSession;
  bindRegisteredSubject(id: string): void;
}> => {
  let subject: string | undefined;
  const shared = (): CommonEmailCodeBrowserSession =>
    subject
      ? adaptPhase1SessionForEmailPassword(phase1, {
          ...configuration,
          expectedSubject: subject,
        })
      : fail();
  const session: CommonEmailCodeBrowserSession = Object.freeze({
    navigate: async (step, path) => {
      await phase1.preloadDemoConfiguration(
        'preload-email-code-registration',
        configuration.storageKey,
        configuration.demo
      );
      await phase1.navigate(step, 'core', path);
    },
    waitForRoute: async (step, paths) => phase1.waitForRoute(step, 'core', paths),
    fill: async (step, selector, value) => {
      if (selector === 'input[name="identifier"]') {
        return phase1.fill(step, selector, value, { endpoint: 'core', paths: ['/register'] });
      }
      if (/^input\[name="passcode_[0-5]"\]$/u.test(selector)) {
        return phase1.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/register/verification-code'],
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
        return phase1.click(step, selector, { endpoint: 'core', paths: ['/register'] });
      }
      if (selector === 'role=button[name="Authorize"]') {
        return phase1.click(step, selector, { endpoint: 'core', paths: ['/consent'] });
      }
      return fail();
    },
    registrationRequestFacts: async () => {
      const facts = await phase1.waitForNetworkFacts(
        'registration-request-facts',
        (value) =>
          value.registrationRequests?.some(
            ({ kind, status }) => kind === 'send' || status < 200 || status >= 300
          ) ?? false
      );
      return facts.registrationRequests ?? [];
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
