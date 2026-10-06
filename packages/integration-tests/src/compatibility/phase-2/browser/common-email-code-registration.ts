/* eslint-disable complexity, no-await-in-loop -- The ordered Register UI and callback sequence is one observable contract. */
import { types as nodeTypes } from 'node:util';

import type { CommonEmailCodeBrowserSession } from './common-email-code-sign-in.js';

export type CommonEmailCodeRegistrationProjection = Readonly<{
  identifier: 'email';
  registrationOutcome: 'created';
  consent: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  profileSubject: true;
  emailVerified: true;
  refreshRotated: true;
}>;

type RegistrationStage =
  | 'initialization'
  | 'register-route'
  | 'identifier-submit'
  | 'verification-route'
  | `verification-route-${'init' | 'send'}-s${number}-${string}`
  | 'passcode-retrieval'
  | 'passcode-retrieval-env-missing'
  | 'passcode-retrieval-socket-shape'
  | 'passcode-retrieval-recipient'
  | 'passcode-retrieval-connect'
  | 'passcode-retrieval-timeout'
  | 'passcode-retrieval-not-found'
  | 'passcode-retrieval-response'
  | 'passcode-format'
  | 'passcode-fill'
  | 'registration-subject'
  | 'registration-capture'
  | 'consent'
  | 'callback'
  | `callback-${string}`
  | 'profile'
  | 'refresh';

const fail = (): never => {
  throw new TypeError('Invalid Common email code registration');
};
const ownErrorMessage = (error: unknown): string | undefined => {
  if (nodeTypes.isProxy(error) || !(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const value: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  return typeof value === 'string' ? value : undefined;
};
const atStage = async <Result>(
  stage: RegistrationStage,
  run: () => Promise<Result>
): Promise<Result> => {
  try {
    return await run();
  } catch {
    throw new TypeError(`Common email code registration stage failed: ${stage}`);
  }
};

export const commonEmailCodeRegistrationExpectedProjection = Object.freeze({
  identifier: 'email',
  registrationOutcome: 'created',
  consent: true,
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  profileSubject: true,
  emailVerified: true,
  refreshRotated: true,
}) satisfies CommonEmailCodeRegistrationProjection;

export const runCommonEmailCodeRegistration = async (
  input: Readonly<{
    session: CommonEmailCodeBrowserSession;
    email: string;
    takePasscode(recipient: string): Promise<string>;
    readRegistrationSubject(email: string): Promise<Readonly<{ id: string; primaryEmail: string }>>;
    captureRegisteredUser(id: string): Promise<void>;
  }>
): Promise<CommonEmailCodeRegistrationProjection> => {
  if (
    input.email.length === 0 ||
    input.email.length > 320 ||
    input.email !== input.email.toLowerCase() ||
    !input.email.includes('@')
  ) {
    return fail();
  }
  await atStage('initialization', async () => {
    await input.session.navigate('open-demo', '/demo-app');
    await input.session.waitForRoute('wait-sign-in', ['/sign-in', '/sign-in/password']);
  });
  await atStage('register-route', async () => {
    await input.session.click('open-register', 'role=link[name="Create account"]');
    await input.session.waitForRoute('wait-register', ['/register']);
  });
  await atStage('identifier-submit', async () => {
    await input.session.fill('fill-registration-email', 'input[name="identifier"]', input.email);
    await input.session.click('submit-registration-email', 'button[name="submit"]');
  });
  try {
    await input.session.waitForRoute('wait-registration-passcode', ['/register/verification-code']);
  } catch {
    const facts = await input.session.registrationRequestFacts?.().catch(() => []);
    const failedFacts = (facts ?? []).filter(({ status }) => status < 200 || status >= 300);
    const failed = failedFacts.at(-1);
    if (failed && failed.status >= 100 && failed.status <= 599) {
      const error = [
        'none',
        'guard.invalid_input',
        'session.interaction_not_found',
        'request.message_rate_limited',
        'connector.not_found',
        'connector.invalid_config',
        'connector.general',
        'other',
      ].includes(failed.error)
        ? failed.error.replaceAll(/[._]/gu, '-')
        : 'other';
      throw new TypeError(
        `Common email code registration stage failed: verification-route-${failed.kind}-s${failed.status}-${error}`
      );
    }
    throw new TypeError('Common email code registration stage failed: verification-route');
  }
  const passcode = await (async () => {
    try {
      return await input.takePasscode(input.email);
    } catch (error: unknown) {
      const category =
        error instanceof Error
          ? /^Phase 2 verification delivery failed: (env-missing|socket-shape|recipient|connect|timeout|not-found|response)$/u.exec(
              error.message
            )?.[1]
          : undefined;
      throw new TypeError(
        `Common email code registration stage failed: passcode-retrieval${category ? `-${category}` : ''}`
      );
    }
  })();
  await atStage('passcode-format', async () => {
    if (!/^\d{6}$/u.test(passcode)) {
      return fail();
    }
  });
  await atStage('passcode-fill', async () => {
    for (const [index, digit] of [...passcode].entries()) {
      await input.session.fill(
        `fill-registration-passcode-${index}`,
        `input[name="passcode_${index}"]`,
        digit
      );
    }
  });
  await atStage('consent', async () =>
    input.session.waitForRoute('wait-registration-consent', ['/consent'])
  );
  const subject = await atStage('registration-subject', async () => {
    const value = await input.readRegistrationSubject(input.email);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const { id, primaryEmail } = descriptors;
    if (
      Reflect.ownKeys(value).length !== 2 ||
      !Object.hasOwn(id, 'value') ||
      !id.enumerable ||
      typeof id.value !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/u.test(id.value) ||
      !Object.hasOwn(primaryEmail, 'value') ||
      !primaryEmail.enumerable ||
      primaryEmail.value !== input.email
    ) {
      return fail();
    }
    return id.value;
  });
  await atStage('registration-capture', async () => input.captureRegisteredUser(subject));
  await atStage('consent', async () =>
    input.session.click('authorize-registration-consent', 'role=button[name="Authorize"]')
  );
  try {
    await input.session.assertInitialCallback();
  } catch (error: unknown) {
    const field =
      /^Common email password callback failed: (callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access))$/u.exec(
        ownErrorMessage(error) ?? ''
      )?.[1];
    throw new TypeError(
      `Common email code registration stage failed: callback${field ? `-${field}` : ''}`
    );
  }
  await atStage('profile', async () => {
    const profile = await input.session.readProfile();
    if (
      profile.sub !== subject ||
      profile.email !== input.email ||
      profile.emailVerified !== true
    ) {
      return fail();
    }
  });
  await atStage('refresh', async () => {
    const refreshed = await input.session.refresh();
    if (refreshed.subject !== subject || !refreshed.rotated) {
      return fail();
    }
  });
  return commonEmailCodeRegistrationExpectedProjection;
};
/* eslint-enable complexity, no-await-in-loop */
