/* eslint-disable no-await-in-loop -- The closed browser and control sequence is one observable contract. */
import { isDeepStrictEqual } from 'node:util';

export const commonEmailCodeScenarioId = 'common.email.code-sign-in';

export type CommonEmailCodeBrowserSession = Readonly<{
  navigate(step: string, path: string): Promise<void>;
  waitForRoute(step: string, paths: readonly string[]): Promise<void>;
  fill(step: string, selector: string, value: string): Promise<void>;
  click(step: string, selector: string): Promise<void>;
  assertInitialCallback(): Promise<void>;
  readProfile(): Promise<Readonly<{ sub?: unknown; email?: unknown; emailVerified?: unknown }>>;
  refresh(): Promise<Readonly<{ subject?: unknown; rotated: boolean }>>;
}>;

export type CommonEmailCodeControlResult = Readonly<{
  recipientMismatch: Readonly<{ status: 400; error: 'verification_code.email_mismatch' }>;
  ownerAfterRecipientMismatch: Readonly<{ status: 200; outcome: 'verified' }>;
  consumedReplay: Readonly<{ status: 400; error: 'verification_code.not_found' }>;
  expiry: Readonly<{ status: 400; error: 'verification_code.expired' }>;
  foreignAccountSurface: Readonly<{
    status: 400;
    error: 'verification_record.not_found';
  }>;
  ownerAfterForeignAccountSurface: Readonly<{ status: 200; outcome: 'verified' }>;
  secondaryInteraction: Readonly<{
    admissionStatus: 303;
    interactionBound: true;
    initializationStatus: 204;
  }>;
  secondaryVerify: Readonly<{
    status: 404;
    outcome: 'error';
    error: 'session.verification_session_not_found';
  }>;
  ownerAfterSecondaryVerify: Readonly<{ status: 200; outcome: 'verified' }>;
}>;

export type CommonEmailCodeProjection = Readonly<{
  identifier: 'email';
  casing: 'canonical-owner';
  verificationOutcome: 'accepted';
  consent: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  profileSubject: true;
  emailVerified: true;
  refreshRotated: true;
  controls: CommonEmailCodeControlResult;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Common email code sign-in');
};
type FlowStage =
  | 'initialization'
  | 'identifier-submit'
  | 'verification-route'
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
  | 'consent'
  | 'callback'
  | 'profile'
  | 'refresh'
  | 'controls'
  | 'controls-basic'
  | 'controls-foreign-account'
  | 'controls-secondary-client';
const atStage = async <Result>(stage: FlowStage, run: () => Promise<Result>): Promise<Result> => {
  try {
    return await run();
  } catch (error: unknown) {
    if (
      error instanceof Error &&
      /^Common email code stage failed: controls-(basic|foreign-account|secondary-client)$/u.test(
        error.message
      )
    ) {
      throw error;
    }
    throw new TypeError(`Common email code stage failed: ${stage}`);
  }
};

const expectedControls = Object.freeze({
  recipientMismatch: Object.freeze({
    status: 400,
    error: 'verification_code.email_mismatch',
  }),
  ownerAfterRecipientMismatch: Object.freeze({ status: 200, outcome: 'verified' }),
  consumedReplay: Object.freeze({ status: 400, error: 'verification_code.not_found' }),
  expiry: Object.freeze({ status: 400, error: 'verification_code.expired' }),
  foreignAccountSurface: Object.freeze({
    status: 400,
    error: 'verification_record.not_found',
  }),
  ownerAfterForeignAccountSurface: Object.freeze({ status: 200, outcome: 'verified' }),
  secondaryInteraction: Object.freeze({
    admissionStatus: 303,
    interactionBound: true,
    initializationStatus: 204,
  }),
  secondaryVerify: Object.freeze({
    status: 404,
    outcome: 'error',
    error: 'session.verification_session_not_found',
  }),
  ownerAfterSecondaryVerify: Object.freeze({ status: 200, outcome: 'verified' }),
}) satisfies CommonEmailCodeControlResult;

export const commonEmailCodeExpectedProjection = Object.freeze({
  identifier: 'email',
  casing: 'canonical-owner',
  verificationOutcome: 'accepted',
  consent: true,
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  profileSubject: true,
  emailVerified: true,
  refreshRotated: true,
  controls: expectedControls,
}) satisfies CommonEmailCodeProjection;

const isPlainData = (value: unknown): boolean => {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every((entry) => isPlainData(entry));
  }
  if (typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  if (Reflect.ownKeys(value).some((key) => typeof key !== 'string')) {
    return false;
  }
  const descriptors = Object.values(Object.getOwnPropertyDescriptors(value));
  return descriptors.every(
    (descriptor) => 'value' in descriptor && descriptor.enumerable && isPlainData(descriptor.value)
  );
};

export const runCommonEmailCodeSignIn = async (
  input: Readonly<{
    session: CommonEmailCodeBrowserSession;
    email: string;
    canonicalEmail: string;
    expectedSubject: string;
    takePasscode(recipient: string): Promise<string>;
    runControls(): Promise<CommonEmailCodeControlResult>;
  }>
): Promise<CommonEmailCodeProjection> => {
  if (
    input.email.toLowerCase() !== input.canonicalEmail ||
    input.email === input.canonicalEmail ||
    !input.expectedSubject
  ) {
    return fail();
  }
  await atStage('initialization', async () => {
    await input.session.navigate('open-demo', '/demo-app');
    await input.session.waitForRoute('wait-sign-in', ['/sign-in', '/sign-in/password']);
  });
  await atStage('identifier-submit', async () => {
    await input.session.fill('fill-email', 'input[name="identifier"]', input.email);
    await input.session.click('submit-email', 'button[name="submit"]');
  });
  await atStage('verification-route', async () =>
    input.session.waitForRoute('wait-email-passcode', ['/sign-in/verification-code'])
  );
  const passcode = await (async () => {
    try {
      return await input.takePasscode(input.email);
    } catch (error: unknown) {
      const stage =
        error instanceof Error
          ? /^Phase 2 verification delivery failed: (env-missing|socket-shape|recipient|connect|timeout|not-found|response)$/u.exec(
              error.message
            )?.[1]
          : undefined;
      throw new TypeError(
        `Common email code stage failed: passcode-retrieval${stage ? `-${stage}` : ''}`
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
        `fill-email-passcode-${index}`,
        `input[name="passcode_${index}"]`,
        digit
      );
    }
  });
  await atStage('consent', async () => {
    await input.session.waitForRoute('wait-consent', ['/consent']);
    await input.session.click('authorize-consent', 'role=button[name="Authorize"]');
  });
  await atStage('callback', async () => input.session.assertInitialCallback());
  await atStage('profile', async () => {
    const profile = await input.session.readProfile();
    if (
      profile.sub !== input.expectedSubject ||
      profile.email !== input.canonicalEmail ||
      profile.emailVerified !== true
    ) {
      return fail();
    }
  });
  await atStage('refresh', async () => {
    const refreshed = await input.session.refresh();
    if (refreshed.subject !== input.expectedSubject || !refreshed.rotated) {
      return fail();
    }
  });
  await atStage('controls', async () => {
    const controls: CommonEmailCodeControlResult = await (async () => {
      try {
        return await input.runControls();
      } catch (error: unknown) {
        const group =
          error instanceof Error
            ? /^Common email code control stage failed: (basic|foreign-account|secondary-client)$/u.exec(
                error.message
              )?.[1]
            : undefined;
        if (group) {
          throw new TypeError(`Common email code stage failed: controls-${group}`);
        }
        throw error;
      }
    })();
    if (!isPlainData(controls) || !isDeepStrictEqual(controls, expectedControls)) {
      return fail();
    }
  });
  return commonEmailCodeExpectedProjection;
};
/* eslint-enable no-await-in-loop */
