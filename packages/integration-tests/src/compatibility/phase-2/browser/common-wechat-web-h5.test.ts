/* eslint-disable no-void, @silverhand/fp/no-mutating-methods -- Ordered action capture is the test contract. */
import { assertEvidenceIsSanitized } from '../../evidence.js';

import {
  runCommonWechatH5Registration,
  runCommonWechatWebExistingOwner,
  type CommonWechatBrowserSession,
  type WechatProviderObservation,
} from './common-wechat-web-h5.js';

const observation = (setupRequests: 0 | 1): WechatProviderObservation =>
  Object.freeze({
    setupRequests,
    browserRequests: 1,
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });

const session = (
  actions: string[],
  profile: Record<string, unknown>
): CommonWechatBrowserSession => ({
  navigate: async (step, path) => void actions.push(`${step}:${path}`),
  waitForRoute: async (step, paths) => void actions.push(`${step}:${paths.join('|')}`),
  fill: async (step, selector, value) => void actions.push(`${step}:${selector}:${value.length}`),
  click: async (step, selector) => void actions.push(`${step}:${selector}`),
  expectCount: async (step, selector, count) => void actions.push(`${step}:${selector}:${count}`),
  consentFailureRoute: async () => 'other-none-0-not-applicable-none',
  assertInitialCallback: async () => void actions.push('callback'),
  readProfile: async () => profile,
  refresh: async () => ({ subject: profile.sub, rotated: true }),
});

test('Web distinguishes the Management association from the browser provider transaction', async () => {
  const actions: string[] = [];
  const result = await runCommonWechatWebExistingOwner({
    session: session(actions, { sub: 'web-owner' }),
    selector: 'role=button[name="Continue with WeChat"]',
    expectedSubject: 'web-owner',
    providerObservation: () => observation(1),
  });
  expect(result.provider).toMatchObject({ setupRequests: 1, browserRequests: 1 });
  expect(() => {
    assertEvidenceIsSanitized(result);
  }).not.toThrow();
  expect(actions).toContain('wechat-web-provider-count:role=button[name="Continue with WeChat"]:1');
});

test('H5 follows the pinned mobile phone completion route and six-input auto-submit', async () => {
  const actions: string[] = [];
  const result = await runCommonWechatH5Registration({
    session: session(actions, { sub: 'h5-owner', phone: '13800138019', phoneVerified: true }),
    selector: 'role=button[name="Continue with WeChat"]',
    phone: '13800138019',
    takePasscode: async () => '012345',
    providerObservation: () => observation(0),
  });
  expect(actions.filter((entry) => entry.includes('passcode_'))).toHaveLength(6);
  expect(actions).toContain('wechat-h5-phone:/continue/phone');
  expect(result).toMatchObject({ channel: 'h5', verifiedPhone: true, phoneOnlyFulfillment: true });
  expect(() => {
    assertEvidenceIsSanitized(result);
  }).not.toThrow();
  expect(JSON.stringify(result)).not.toContain('012345');
});

test.each([
  [
    'Web',
    async () =>
      runCommonWechatWebExistingOwner({
        session: session([], { sub: 'web-owner' }),
        selector: 'wechat',
        expectedSubject: 'web-owner',
        providerObservation: () => observation(0),
      }),
  ],
  [
    'H5',
    async () =>
      runCommonWechatH5Registration({
        session: session([], { sub: 'h5-owner', phone: '13800138019', phoneVerified: true }),
        selector: 'wechat',
        phone: '13800138019',
        takePasscode: async () => '123456',
        providerObservation: () => observation(1),
      }),
  ],
])('%s rejects provider-count drift', async (_name, run) => {
  await expect(run()).rejects.toThrow(/Common WeChat (?:Web|H5) failed: provider/u);
});

test('H5 rejects malformed delivery before touching consent', async () => {
  const actions: string[] = [];
  await expect(
    runCommonWechatH5Registration({
      session: session(actions, { sub: 'h5-owner', phone: '13800138019', phoneVerified: true }),
      selector: 'wechat',
      phone: '13800138019',
      takePasscode: async () => '12345',
      providerObservation: () => observation(0),
    })
  ).rejects.toThrow('Common WeChat H5 failed: passcode-format');
  expect(actions).not.toContain('wechat-h5-consent:/consent');
});

test('Web publishes the bounded consent route and failed experience operation', async () => {
  const base = session([], { sub: 'web-owner' });
  await expect(
    runCommonWechatWebExistingOwner({
      session: {
        ...base,
        waitForRoute: async (step, paths) => {
          if (step === 'wechat-web-consent') {
            throw new Error('private response');
          }
          await base.waitForRoute(step, paths);
        },
        consentFailureRoute: async () =>
          'continue-identification-422-not-applicable-user-missing-profile',
      },
      selector: 'wechat',
      expectedSubject: 'web-owner',
      providerObservation: () => observation(1),
    })
  ).rejects.toThrow(
    'Common WeChat Web failed: consent-route-continue-identification-422-not-applicable-user-missing-profile'
  );
});
/* eslint-enable no-void, @silverhand/fp/no-mutating-methods */
