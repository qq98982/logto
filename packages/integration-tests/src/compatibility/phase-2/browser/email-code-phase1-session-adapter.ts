import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';

import type { CommonEmailCodeBrowserSession } from './common-email-code-sign-in.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';

const fail = (): never => {
  throw new TypeError('Invalid Common email code browser fill');
};

export const adaptPhase1SessionForEmailCode = (
  session: Phase1BrowserSession,
  configuration: Readonly<{
    storageKey: string;
    demo: Phase1ProfiledDemoConfiguration;
    expectedSubject: string;
    expectedIssuer: string;
    canonicalEmail: string;
    resource: string;
    redirectUri: string;
    initialResponseScope: string;
    resourceScope: string;
  }>
): CommonEmailCodeBrowserSession => {
  const shared = adaptPhase1SessionForEmailPassword(session, configuration);
  return Object.freeze({
    ...shared,
    fill: async (step: string, selector: string, value: string) => {
      if (selector === 'input[name="identifier"]') {
        return session.fill(step, selector, value, { endpoint: 'core', paths: ['/sign-in'] });
      }
      if (/^input\[name="passcode_[0-5]"\]$/u.test(selector)) {
        return session.fill(step, selector, value, {
          endpoint: 'core',
          paths: ['/sign-in/verification-code'],
        });
      }
      return fail();
    },
  });
};
