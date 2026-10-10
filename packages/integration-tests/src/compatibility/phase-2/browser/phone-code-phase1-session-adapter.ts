import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';

import type { CommonPhoneCodeBrowserSession } from './common-phone-code.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';

const fail = (): never => {
  throw new TypeError('Invalid Common phone code browser adapter');
};

export type PhoneCodeBrowserConfiguration = Readonly<{
  storageKey: string;
  demo: Phase1ProfiledDemoConfiguration;
  expectedIssuer: string;
  resource: string;
  redirectUri: string;
  initialResponseScope: string;
  resourceScope: string;
}>;

export const adaptPhase1SessionForPhoneCode = (
  phase1: Phase1BrowserSession,
  configuration: PhoneCodeBrowserConfiguration,
  expectedSubject: string | (() => string)
): CommonPhoneCodeBrowserSession => {
  const shared = adaptPhase1SessionForEmailPassword(phase1, {
    ...configuration,
    canonicalEmail: 'unused@phone.aster.invalid',
    expectedSubject,
  });
  const readPhoneProfile = async (openPanel: boolean) => {
    if (openPanel) {
      await phase1.click('open-phone-dev-panel', 'role=button[name="Open dev panel"]');
    }
    const value = await phase1.clickAndObserveObject(
      'phone-userinfo',
      'role=button[name="Fetch user info"]',
      (body) => ({
        sub: body.sub ?? null,
        phoneNumber: body.phone_number ?? null,
        phoneNumberVerified: body.phone_number_verified ?? null,
        emailAbsent: !Object.hasOwn(body, 'email') && !Object.hasOwn(body, 'email_verified'),
      })
    );
    return value;
  };
  return Object.freeze({
    navigate: async (step: string, path: string) => {
      await phase1.preloadDemoConfiguration(
        'preload-phone-code',
        configuration.storageKey,
        configuration.demo
      );
      await phase1.navigate(step, 'core', path);
    },
    waitForRoute: async (step: string, paths: readonly string[]) =>
      phase1.waitForRoute(step, 'core', paths),
    selectChinaCountryCode: async (step: string, route: '/sign-in' | '/register') => {
      await phase1.click(`${step}-open`, 'div[role="button"]:has-text("+1")', {
        endpoint: 'core',
        paths: [route],
      });
      await phase1.fill(`${step}-search`, 'input[name="country-code-search"]', '86', {
        endpoint: 'core',
        paths: [route],
      });
      await phase1.click(`${step}-choose`, '[data-id="86"]', {
        endpoint: 'core',
        paths: [route],
      });
    },
    fill: async (step: string, selector: string, value: string) => {
      if (selector === 'input[name="identifier"]') {
        return phase1.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/sign-in', '/register'],
        });
      }
      if (/^input\[name="passcode_[0-5]"\]$/u.test(selector)) {
        return phase1.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/sign-in/verification-code', '/register/verification-code'],
        });
      }
      return fail();
    },
    click: async (step: string, selector: string) => phase1.click(step, selector),
    assertInitialCallback: shared.assertInitialCallback,
    readProfile: async () => readPhoneProfile(true),
    refresh: async () => {
      const refreshed = await shared.refresh();
      const profile = await readPhoneProfile(false);
      return { ...refreshed, phoneNumber: profile.phoneNumber };
    },
  });
};
