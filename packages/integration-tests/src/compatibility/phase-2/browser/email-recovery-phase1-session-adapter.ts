import type { Phase1BrowserSession } from '../../phase-1/browser/contracts.js';

import type { CommonEmailRecoveryBrowserSession } from './common-email-recovery.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';

const signInRoutes = Object.freeze(['/sign-in', '/sign-in/password']);

export const adaptPhase1SessionForEmailRecovery = (
  session: Phase1BrowserSession,
  configuration: CommonEmailPasswordBrowserConfiguration &
    Readonly<{ expectedSubject: string; canonicalEmail: string; resource: string }>
): CommonEmailRecoveryBrowserSession => {
  const shared = adaptPhase1SessionForEmailPassword(session, configuration);
  return Object.freeze({
    navigate: shared.navigate,
    waitForRoute: shared.waitForRoute,
    click: async (step, selector) => session.click(step, selector),
    fill: async (step, selector, value) => {
      const paths = selector.includes('passcode_')
        ? ['/forgot-password/verification-code']
        : selector.includes('newPassword') || selector.includes('confirmPassword')
          ? ['/forgot-password/reset']
          : selector === 'input[name="identifier"]' && step.startsWith('forgot-password')
            ? ['/forgot-password']
            : signInRoutes;
      await session.fill(step, selector, value, { endpoint: 'core', paths });
    },
    assertCallback: shared.assertInitialCallback,
    captureAuthority: async () => ({
      assertAccessUsable: async () => {
        const profile = await shared.readProfile();
        if (
          profile.sub !== configuration.expectedSubject ||
          profile.email !== configuration.canonicalEmail ||
          profile.emailVerified !== true
        ) {
          throw new TypeError('Invalid email recovery profile');
        }
      },
      assertRefreshUsable: async () => {
        const refresh = await shared.refresh();
        if (refresh.subject !== configuration.expectedSubject || !refresh.rotated) {
          throw new TypeError('Invalid email recovery refresh');
        }
      },
    }),
    assertPasswordRejected: async (identifier, password) => {
      await session.fill('old-password-email', 'input[name="identifier"]', identifier, {
        endpoint: 'core',
        paths: signInRoutes,
      });
      await session.fill('old-password-value', 'input[name="password"]', password, {
        endpoint: 'core',
        paths: signInRoutes,
      });
      await session.click('old-password-submit', 'button[name="submit"]');
      await session.assertRoute('old-password-rejected-route', 'core', signInRoutes);
      await session.expectText(
        'old-password-rejected-message',
        'text="Incorrect account or password. Please check your input."',
        'Incorrect account or password. Please check your input.'
      );
    },
  });
};
