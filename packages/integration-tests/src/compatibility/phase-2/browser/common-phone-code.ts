/* eslint-disable no-await-in-loop -- Each six-digit entry is an ordered browser action. */
import { isDeepStrictEqual } from 'node:util';

export type PhoneCodePurpose = 'SignIn' | 'Register';

export type CommonPhoneCodeBrowserSession = Readonly<{
  navigate(step: string, path: string): Promise<void>;
  waitForRoute(step: string, paths: readonly string[]): Promise<void>;
  selectChinaCountryCode(step: string, route: '/sign-in' | '/register'): Promise<void>;
  fill(step: string, selector: string, value: string): Promise<void>;
  click(step: string, selector: string): Promise<void>;
  assertInitialCallback(): Promise<void>;
  readProfile(): Promise<
    Readonly<{
      sub?: unknown;
      phoneNumber?: unknown;
      phoneNumberVerified?: unknown;
      emailAbsent?: unknown;
    }>
  >;
  refresh(): Promise<Readonly<{ subject?: unknown; rotated: boolean; phoneNumber?: unknown }>>;
}>;

export type CommonPhoneCodeControls = Readonly<{
  occupiedRegistration: Readonly<{
    status: 422;
    code: 'user.phone_already_in_use';
    ownerUnchanged: true;
  }>;
  consumedReplay: Readonly<{ status: 400; code: 'verification_code.not_found' }>;
  recipientMismatch: Readonly<{
    status: 400;
    code: 'verification_code.phone_mismatch';
    ownerRetained: true;
  }>;
  suspendedOwner: Readonly<{ status: 401; code: 'user.suspended' }>;
}>;

export type CommonPhoneCodeProjection = Readonly<{
  signIn: Readonly<{
    identifier: 'phone';
    outcome: 'accepted';
    consent: true;
    callback: 'state-issuer-code-bound';
    pkce: 'S256';
    profileSubject: true;
    phoneVerified: true;
    refreshRotated: true;
  }>;
  registration: Readonly<{
    identifier: 'phone';
    outcome: 'created';
    consent: true;
    callback: 'state-issuer-code-bound';
    pkce: 'S256';
    profileSubject: true;
    phoneVerified: true;
    refreshRotated: true;
  }>;
  controls: CommonPhoneCodeControls;
}>;

const fail = (stage: string): never => {
  throw new TypeError(`Common phone code stage failed: ${stage}`);
};

const atStage = async <Result>(
  stage: string,
  operation: () => Promise<Result>
): Promise<Result> => {
  try {
    return await operation();
  } catch {
    return fail(stage);
  }
};

const enterCode = async (
  session: CommonPhoneCodeBrowserSession,
  prefix: string,
  code: string
): Promise<void> => {
  if (!/^\d{6}$/u.test(code)) {
    return fail(`${prefix}-code-format`);
  }
  await atStage(`${prefix}-code-fill`, async () => {
    for (const [index, digit] of [...code].entries()) {
      await session.fill(`${prefix}-code-${index}`, `input[name="passcode_${index}"]`, digit);
    }
  });
};

const assertProfileAndRefresh = async (
  session: CommonPhoneCodeBrowserSession,
  prefix: string,
  subject: string,
  phone: string
): Promise<void> => {
  await atStage(`${prefix}-profile`, async () => {
    const profile = await session.readProfile();
    if (
      profile.sub !== subject ||
      profile.phoneNumber !== phone ||
      profile.phoneNumberVerified !== true ||
      profile.emailAbsent !== true
    ) {
      return fail(`${prefix}-profile`);
    }
  });
  await atStage(`${prefix}-refresh`, async () => {
    const refresh = await session.refresh();
    if (refresh.subject !== subject || !refresh.rotated || refresh.phoneNumber !== phone) {
      return fail(`${prefix}-refresh`);
    }
  });
};

export const runCommonPhoneCodeSignIn = async (
  input: Readonly<{
    session: CommonPhoneCodeBrowserSession;
    phone: string;
    nationalPhone: string;
    expectedSubject: string;
    arm(recipient: string, purpose: 'SignIn'): Promise<void>;
    takeCode(recipient: string, purpose: 'SignIn'): Promise<string>;
  }>
): Promise<CommonPhoneCodeProjection['signIn']> => {
  if (!/^86\d{11}$/u.test(input.phone) || input.phone !== `86${input.nationalPhone}`) {
    return fail('sign-in-input');
  }
  await atStage('sign-in-initialization', async () => {
    await input.session.navigate('open-phone-sign-in', '/demo-app');
    await input.session.waitForRoute('wait-phone-sign-in', ['/sign-in', '/sign-in/password']);
  });
  await atStage('sign-in-identifier', async () => {
    await input.session.selectChinaCountryCode('select-sign-in-china', '/sign-in');
    await input.session.fill('fill-sign-in-phone', 'input[name="identifier"]', input.nationalPhone);
    await input.arm(input.phone, 'SignIn');
    await input.session.click('submit-sign-in-phone', 'button[name="submit"]');
    await input.session.waitForRoute('wait-sign-in-code', ['/sign-in/verification-code']);
  });
  const code = await atStage('sign-in-delivery', async () => input.takeCode(input.phone, 'SignIn'));
  await enterCode(input.session, 'sign-in', code);
  await atStage('sign-in-consent', async () => {
    await input.session.waitForRoute('wait-sign-in-consent', ['/consent']);
    await input.session.click('authorize-sign-in', 'role=button[name="Authorize"]');
  });
  await atStage('sign-in-callback', async () => input.session.assertInitialCallback());
  await assertProfileAndRefresh(input.session, 'sign-in', input.expectedSubject, input.phone);
  return Object.freeze({
    identifier: 'phone',
    outcome: 'accepted',
    consent: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    profileSubject: true,
    phoneVerified: true,
    refreshRotated: true,
  });
};

export const runCommonPhoneCodeRegistration = async (
  input: Readonly<{
    session: CommonPhoneCodeBrowserSession;
    phone: string;
    nationalPhone: string;
    arm(recipient: string, purpose: 'Register'): Promise<void>;
    takeCode(recipient: string, purpose: 'Register'): Promise<string>;
    readSubject(phone: string): Promise<Readonly<{ id: string; primaryPhone: string }>>;
    captureSubject(id: string): Promise<void>;
  }>
): Promise<CommonPhoneCodeProjection['registration']> => {
  if (!/^86\d{11}$/u.test(input.phone) || input.phone !== `86${input.nationalPhone}`) {
    return fail('registration-input');
  }
  await atStage('registration-initialization', async () => {
    await input.session.navigate('open-phone-registration', '/demo-app');
    await input.session.waitForRoute('wait-registration-sign-in', [
      '/sign-in',
      '/sign-in/password',
    ]);
    await input.session.click('open-phone-registration', 'role=link[name="Create account"]');
    await input.session.waitForRoute('wait-phone-registration', ['/register']);
  });
  await atStage('registration-identifier', async () => {
    await input.session.selectChinaCountryCode('select-registration-china', '/register');
    await input.session.fill(
      'fill-registration-phone',
      'input[name="identifier"]',
      input.nationalPhone
    );
    await input.arm(input.phone, 'Register');
    await input.session.click('submit-registration-phone', 'button[name="submit"]');
    await input.session.waitForRoute('wait-registration-code', ['/register/verification-code']);
  });
  const code = await atStage('registration-delivery', async () =>
    input.takeCode(input.phone, 'Register')
  );
  await enterCode(input.session, 'registration', code);
  await atStage('registration-consent', async () =>
    input.session.waitForRoute('wait-registration-consent', ['/consent'])
  );
  const subject = await atStage('registration-subject', async () => {
    const value = await input.readSubject(input.phone);
    if (
      Reflect.ownKeys(value).length !== 2 ||
      !/^[A-Za-z0-9_-]{1,128}$/u.test(value.id) ||
      value.primaryPhone !== input.phone
    ) {
      return fail('registration-subject');
    }
    await input.captureSubject(value.id);
    return value.id;
  });
  await atStage('registration-consent', async () =>
    input.session.click('authorize-registration', 'role=button[name="Authorize"]')
  );
  await atStage('registration-callback', async () => input.session.assertInitialCallback());
  await assertProfileAndRefresh(input.session, 'registration', subject, input.phone);
  return Object.freeze({
    identifier: 'phone',
    outcome: 'created',
    consent: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    profileSubject: true,
    phoneVerified: true,
    refreshRotated: true,
  });
};

export const assertCommonPhoneCodeControls = (
  value: CommonPhoneCodeControls
): CommonPhoneCodeControls => {
  const expected: CommonPhoneCodeControls = {
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
  if (!isDeepStrictEqual(value, expected)) {
    return fail('controls');
  }
  return Object.freeze(value);
};
/* eslint-enable no-await-in-loop */
