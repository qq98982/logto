/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The ordered registration and fresh-login browser sequence is one observable contract. */
import { assertEvidenceIsSanitized } from '../../evidence.js';

import type { CommonEmailCodeBrowserSession } from './common-email-code-sign-in.js';

export type EmailPasswordRegistrationSession = CommonEmailCodeBrowserSession &
  Readonly<{
    confirmCredentialIfPresent?(value: string): Promise<void>;
  }>;

export type CommonEmailPasswordRegistrationPositiveProjection = Readonly<{
  identifier: 'email';
  registrationOutcome: 'created';
  hasPassword: true;
  emailVerified: true;
  consent: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  subsequentSignIn: 'accepted';
  sameOwner: true;
  refreshRotated: true;
}>;

export const commonEmailPasswordRegistrationPositiveProjection = Object.freeze({
  identifier: 'email',
  registrationOutcome: 'created',
  hasPassword: true,
  emailVerified: true,
  consent: true,
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  subsequentSignIn: 'accepted',
  sameOwner: true,
  refreshRotated: true,
}) satisfies CommonEmailPasswordRegistrationPositiveProjection;

type RegistrationStage =
  | 'admission'
  | 'initialization'
  | 'identifier'
  | 'delivery'
  | 'verification'
  | 'credential-fulfillment'
  | 'persisted-user'
  | 'callback'
  | 'registration-profile-refresh'
  | 'fresh-sign-in'
  | 'fresh-profile-refresh';

const fail = (stage: RegistrationStage): never => {
  throw new TypeError(`Common email password registration failed: ${stage}`);
};
const atStage = async <Result>(
  stage: RegistrationStage,
  run: () => Promise<Result>
): Promise<Result> => {
  try {
    return await run();
  } catch {
    return fail(stage);
  }
};
const validEmail = (value: string): boolean =>
  value.length > 0 &&
  value.length <= 320 &&
  value === value.toLowerCase() &&
  /^[^@\s]+@[^@\s]+$/u.test(value);

export const runCommonEmailPasswordRegistration = async (
  input: Readonly<{
    email: string;
    getPassword(): string;
    takePasscode(recipient: string): Promise<string>;
    readCreatedUser(): Promise<Readonly<{ id: string; hasPassword: boolean }>>;
    captureCreatedUser(id: string): Promise<void>;
    withFreshSession<Result>(
      use: (session: EmailPasswordRegistrationSession) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<CommonEmailPasswordRegistrationPositiveProjection> => {
  if (!validEmail(input.email)) {
    return fail('admission');
  }
  const password = input.getPassword();
  if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
    return fail('admission');
  }
  let owner: string | undefined;
  const assertIdentity = async (session: CommonEmailCodeBrowserSession): Promise<void> => {
    const profile = await session.readProfile();
    if (
      owner === undefined ||
      profile.sub !== owner ||
      profile.email !== input.email ||
      profile.emailVerified !== true
    ) {
      return fail('registration-profile-refresh');
    }
    const refreshed = await session.refresh();
    if (refreshed.subject !== owner || !refreshed.rotated) {
      return fail('registration-profile-refresh');
    }
  };

  await input.withFreshSession(async (session) => {
    await atStage('initialization', async () => {
      await session.navigate('registration-open', '/demo-app');
      await session.waitForRoute('registration-sign-in', ['/sign-in', '/sign-in/password']);
      await session.click('registration-create', 'role=link[name="Create account"]');
      await session.waitForRoute('registration-route', ['/register']);
    });
    await atStage('identifier', async () => {
      await session.fill('registration-email', 'input[name="identifier"]', input.email);
      await session.click('registration-submit-email', 'button[name="submit"]');
      await session.waitForRoute('registration-code-route', ['/register/verification-code']);
    });
    const passcode = await atStage('delivery', async () => input.takePasscode(input.email));
    await atStage('verification', async () => {
      if (!/^\d{6}$/u.test(passcode)) {
        return fail('verification');
      }
      for (const [index, digit] of [...passcode].entries()) {
        await session.fill(`registration-digit-${index}`, `input[name="passcode_${index}"]`, digit);
      }
      await session.waitForRoute('registration-fulfill-route', ['/continue/password']);
    });
    await atStage('credential-fulfillment', async () => {
      await session.fill('registration-new-credential', 'input[name="newPassword"]', password);
      await session.confirmCredentialIfPresent?.(password);
      await session.click('registration-save', 'button[name="submit"]');
      await session.waitForRoute('registration-consent', ['/consent']);
    });
    await atStage('persisted-user', async () => {
      const created = await input.readCreatedUser();
      if (!/^[A-Za-z0-9_-]{1,128}$/u.test(created.id) || !created.hasPassword) {
        return fail('persisted-user');
      }
      owner = created.id;
      await input.captureCreatedUser(created.id);
    });
    await atStage('callback', async () => {
      await session.click('registration-authorize', 'role=button[name="Authorize"]');
      await session.assertInitialCallback();
    });
    await atStage('registration-profile-refresh', async () => assertIdentity(session));
  });

  await input.withFreshSession(async (session) => {
    await atStage('fresh-sign-in', async () => {
      await session.navigate('registered-login-open', '/demo-app');
      await session.waitForRoute('registered-login-route', ['/sign-in', '/sign-in/password']);
      await session.fill('registered-login-email', 'input[name="identifier"]', input.email);
      await session.fill('registered-login-credential', 'input[name="password"]', password);
      await session.click('registered-login-submit', 'button[name="submit"]');
      await session.waitForRoute('registered-login-consent', ['/consent']);
      await session.click('registered-login-authorize', 'role=button[name="Authorize"]');
      await session.assertInitialCallback();
    });
    await atStage('fresh-profile-refresh', async () => assertIdentity(session));
  });

  assertEvidenceIsSanitized(commonEmailPasswordRegistrationPositiveProjection);
  return commonEmailPasswordRegistrationPositiveProjection;
};
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
