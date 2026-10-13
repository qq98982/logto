/* eslint-disable @silverhand/fp/no-mutating-methods -- Ordered fill capture is the test contract. */
import type { Phase1BrowserSession } from '../../phase-1/browser/contracts.js';

import { createWechatH5Fill, createWechatH5ReadProfile } from './common-wechat-h5-target-driver.js';

test('binds the H5 phone and passcode inputs to their exact continuation routes', async () => {
  const calls: Array<Parameters<Phase1BrowserSession['fill']>> = [];
  const fill: Phase1BrowserSession['fill'] = async (...input) => {
    calls.push(input);
  };
  const h5Fill = createWechatH5Fill({ fill });

  await h5Fill('wechat-h5-phone-input', 'input[type="tel"]', '+8613800138019');
  await h5Fill('wechat-h5-passcode-0', 'input[name="passcode_0"]', '0');
  await h5Fill('wechat-h5-passcode-5', 'input[name="passcode_5"]', '5');

  expect(calls).toEqual([
    [
      'wechat-h5-phone-input',
      'input[type="tel"]',
      '+8613800138019',
      { endpoint: 'core', paths: ['/continue/phone'] },
    ],
    [
      'wechat-h5-passcode-0',
      'input[name="passcode_0"]',
      '0',
      { endpoint: 'core', paths: ['/continue/verification-code'] },
    ],
    [
      'wechat-h5-passcode-5',
      'input[name="passcode_5"]',
      '5',
      { endpoint: 'core', paths: ['/continue/verification-code'] },
    ],
  ]);
});

test.each([
  ['unknown step', 'input[type="tel"]'],
  ['wechat-h5-phone-input', 'input[name="identifier"]'],
  ['wechat-h5-passcode-0', 'input[name="passcode_1"]'],
  ['wechat-h5-passcode-6', 'input[name="passcode_6"]'],
])('rejects an H5 fill outside the exact known step and selector pairs', async (step, selector) => {
  const calls: Array<Parameters<Phase1BrowserSession['fill']>> = [];
  const fill: Phase1BrowserSession['fill'] = async (...input) => {
    calls.push(input);
  };
  const h5Fill = createWechatH5Fill({ fill });

  await expect(h5Fill(step, selector, 'value')).rejects.toThrow(
    'Invalid Common Wechat H5 registration target composition'
  );
  expect(calls).toEqual([]);
});

test('projects the H5 phone UserInfo claims and remembers the refresh subject', async () => {
  const actions: string[] = [];
  const subjects: string[] = [];
  const rememberSubject = (subject: string) => {
    subjects.push(subject);
  };
  const session = {
    click: async (step: string, selector: string) => {
      actions.push(`${step}:${selector}`);
    },
    clickAndObserveObject: async (
      step: string,
      selector: string,
      project: (body: Record<string, unknown>) => Record<string, unknown>
    ) => {
      actions.push(`${step}:${selector}`);
      return project({
        sub: 'h5-owner',
        phone_number: '13800138019',
        phone_number_verified: true,
        email: 'ignored@example.test',
      });
    },
  } as unknown as Pick<Phase1BrowserSession, 'click' | 'clickAndObserveObject'>;
  const readProfile = createWechatH5ReadProfile(session, rememberSubject);

  await expect(readProfile()).resolves.toEqual({
    sub: 'h5-owner',
    phone: '13800138019',
    phoneVerified: true,
  });
  expect(actions).toEqual([
    'open-wechat-h5-dev-panel:role=button[name="Open dev panel"]',
    'wechat-h5-userinfo:role=button[name="Fetch user info"]',
  ]);
  expect(subjects).toEqual(['h5-owner']);
});

test('does not accept nonstandard phone aliases as UserInfo claims', async () => {
  const session = {
    click: async () => {
      // The alias rejection assertion concerns the observed UserInfo object.
    },
    clickAndObserveObject: async (
      _step: string,
      _selector: string,
      project: (body: Record<string, unknown>) => Record<string, unknown>
    ) =>
      project({
        sub: 'h5-owner',
        phone: '13800138019',
        phone_verified: true,
      }),
  } as unknown as Pick<Phase1BrowserSession, 'click' | 'clickAndObserveObject'>;
  const readProfile = createWechatH5ReadProfile(session, () => {
    // Subject capture is asserted independently above.
  });

  await expect(readProfile()).resolves.toEqual({
    sub: 'h5-owner',
    phone: null,
    phoneVerified: null,
  });
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
