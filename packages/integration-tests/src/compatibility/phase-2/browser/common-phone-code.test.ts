/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Ordered fake actions record the observable browser contract. */
import {
  assertCommonPhoneCodeControls,
  runCommonPhoneCodeRegistration,
  runCommonPhoneCodeSignIn,
  type CommonPhoneCodeBrowserSession,
  type CommonPhoneCodeControls,
} from './common-phone-code.js';

const makeSession = (actions: string[], subject = 'owner'): CommonPhoneCodeBrowserSession => ({
  navigate: async (step, path) => {
    actions.push(`${step}:${path}`);
  },
  waitForRoute: async (step, paths) => {
    actions.push(`${step}:${paths.join('|')}`);
  },
  selectChinaCountryCode: async (step, route) => {
    actions.push(`${step}:${route}:86`);
  },
  fill: async (step, selector, value) => {
    actions.push(`${step}:${selector}:${value.length}`);
  },
  click: async (step, selector) => {
    actions.push(`${step}:${selector}`);
  },
  assertInitialCallback: async () => {
    actions.push('callback');
  },
  readProfile: async () => ({
    sub: subject,
    phoneNumber: '8613800138000',
    phoneNumberVerified: true,
    emailAbsent: true,
  }),
  refresh: async () => ({ subject, rotated: true, phoneNumber: '8613800138000' }),
});

test('runs China phone sign-in with armed SignIn delivery and verified UserInfo', async () => {
  const actions: string[] = [];
  const delivery: string[] = [];
  const result = await runCommonPhoneCodeSignIn({
    session: makeSession(actions),
    phone: '8613800138000',
    nationalPhone: '13800138000',
    expectedSubject: 'owner',
    arm: async (recipient, purpose) => {
      delivery.push(`arm:${recipient}:${purpose}`);
    },
    takeCode: async (recipient, purpose) => {
      delivery.push(`take:${recipient}:${purpose}`);
      return '012345';
    },
  });
  expect(delivery).toEqual(['arm:8613800138000:SignIn', 'take:8613800138000:SignIn']);
  expect(actions).toContain('select-sign-in-china:/sign-in:86');
  expect(result).toMatchObject({ identifier: 'phone', outcome: 'accepted', phoneVerified: true });
  expect(JSON.stringify(result)).not.toContain('012345');
});

test('runs China phone registration and binds the created subject before callback checks', async () => {
  const actions: string[] = [];
  let captured = '';
  const result = await runCommonPhoneCodeRegistration({
    session: makeSession(actions, 'registered'),
    phone: '8613800138000',
    nationalPhone: '13800138000',
    arm: async () => {},
    takeCode: async () => '654321',
    readSubject: async () => ({ id: 'registered', primaryPhone: '8613800138000' }),
    captureSubject: async (id) => {
      captured = id;
    },
  });
  expect(captured).toBe('registered');
  expect(actions).toContain('select-registration-china:/register:86');
  expect(result).toMatchObject({ identifier: 'phone', outcome: 'created', phoneVerified: true });
});

test.each([
  [
    'sign-in input',
    async () =>
      runCommonPhoneCodeSignIn({
        session: makeSession([]),
        phone: '+1',
        nationalPhone: '1',
        expectedSubject: 'owner',
        arm: async () => {},
        takeCode: async () => '123456',
      }),
  ],
  [
    'registration code',
    async () =>
      runCommonPhoneCodeRegistration({
        session: makeSession([]),
        phone: '8613800138000',
        nationalPhone: '13800138000',
        arm: async () => {},
        takeCode: async () => 'private',
        readSubject: async () => ({ id: 'registered', primaryPhone: '8613800138000' }),
        captureSubject: async () => {},
      }),
  ],
] as const)('closes private failures at the %s boundary', async (_name, run) => {
  await expect(run()).rejects.toThrow(/^Common phone code stage failed:/u);
  await expect(run()).rejects.not.toThrow('private');
});

test('accepts only the exact status/code/boolean control projection', () => {
  const controls: CommonPhoneCodeControls = {
    occupiedRegistration: {
      status: 422,
      code: 'user.phone_already_in_use',
      ownerUnchanged: true,
    },
    consumedReplay: { status: 400, code: 'verification_code.not_found' },
    recipientMismatch: {
      status: 400,
      code: 'verification_code.phone_mismatch',
      ownerRetained: true,
    },
    suspendedOwner: { status: 401, code: 'user.suspended' },
  };
  expect(assertCommonPhoneCodeControls(controls)).toEqual(controls);
  expect(() =>
    assertCommonPhoneCodeControls({ ...controls, extra: true } as CommonPhoneCodeControls)
  ).toThrow('Common phone code stage failed: controls');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
