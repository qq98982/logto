/* eslint-disable no-await-in-loop, no-restricted-syntax -- The H6 verification-code component owns six ordered inputs; the closed stage cast follows validated input. */
import type { CommonEmailPasswordBrowserSession } from './common-email-password-sign-in.js';

export type CommonWechatBrowserSession = Pick<
  CommonEmailPasswordBrowserSession,
  'navigate' | 'waitForRoute' | 'fill' | 'click' | 'assertInitialCallback' | 'refresh'
> &
  Readonly<{
    expectCount(step: string, selector: string, expected: number): Promise<void>;
    consentFailureRoute(): Promise<string>;
    readProfile(): Promise<Readonly<{ sub?: unknown; phone?: unknown; phoneVerified?: unknown }>>;
  }>;

export type WechatProviderObservation = Readonly<{
  setupRequests: 0 | 1;
  browserRequests: 1;
  authorizationExact: true;
  tokenExact: true;
  userinfoExact: true;
  unionIdStable: true;
}>;

type WebStage =
  | 'admission'
  | 'initialization'
  | 'provider-count'
  | 'provider-click'
  | 'consent-route'
  | `consent-route-${string}`
  | 'consent-click'
  | 'callback'
  | `callback-${string}`
  | 'profile'
  | 'refresh'
  | 'provider';
type H5Stage =
  | 'admission'
  | 'initialization'
  | 'registration-transition'
  | 'registration-route'
  | 'provider-count'
  | 'provider-click'
  | 'phone-route'
  | 'phone-submit'
  | 'passcode-route'
  | 'passcode-retrieval'
  | `passcode-retrieval-${'env-missing' | 'socket-shape' | 'recipient' | 'connect' | 'timeout' | 'not-found' | 'response'}`
  | 'passcode-format'
  | 'passcode-fill'
  | 'consent-route'
  | `consent-route-${string}`
  | 'consent-click'
  | 'callback'
  | `callback-${string}`
  | 'profile'
  | 'refresh'
  | 'provider';

const ownMessage = (error: unknown): string | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const value: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
  return typeof value === 'string' ? value : undefined;
};
const webFail = (stage: WebStage): never => {
  throw new TypeError(`Common WeChat Web failed: ${stage}`);
};
const h5Fail = (stage: H5Stage): never => {
  throw new TypeError(`Common WeChat H5 failed: ${stage}`);
};
const webStage = async <Result>(stage: WebStage, operation: () => Promise<Result>) => {
  try {
    return await operation();
  } catch (error: unknown) {
    const callbackField =
      stage === 'callback'
        ? /^Common email password callback failed: (callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access))$/u.exec(
            ownMessage(error) ?? ''
          )?.[1]
        : undefined;
    return webFail(callbackField ? `callback-${callbackField}` : stage);
  }
};
const h5Stage = async <Result>(stage: H5Stage, operation: () => Promise<Result>) => {
  try {
    return await operation();
  } catch (error: unknown) {
    const delivery =
      stage === 'passcode-retrieval'
        ? /^Phase 2 verification delivery failed: (env-missing|socket-shape|recipient|connect|timeout|not-found|response)$/u.exec(
            ownMessage(error) ?? ''
          )?.[1]
        : undefined;
    const callbackField =
      stage === 'callback'
        ? /^Common email password callback failed: (callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access))$/u.exec(
            ownMessage(error) ?? ''
          )?.[1]
        : undefined;
    return h5Fail(
      delivery
        ? (`passcode-retrieval-${delivery}` as H5Stage)
        : callbackField
          ? `callback-${callbackField}`
          : stage
    );
  }
};
const assertProvider = (value: WechatProviderObservation, setupRequests: 0 | 1): void => {
  const expected = {
    setupRequests,
    browserRequests: 1,
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  };
  if (
    Reflect.ownKeys(value).length !== Reflect.ownKeys(expected).length ||
    Object.entries(expected).some(
      ([key, expectedValue]) => Reflect.get(value, key) !== expectedValue
    )
  ) {
    throw new TypeError('Invalid WeChat provider observation');
  }
};

const providerEvidence = (value: WechatProviderObservation) =>
  Object.freeze({
    setupRequests: value.setupRequests,
    browserRequests: value.browserRequests,
    providerRedirectExact: value.authorizationExact,
    exchangeExact: value.tokenExact,
    userinfoExact: value.userinfoExact,
    unionIdStable: value.unionIdStable,
  });

export const runCommonWechatWebExistingOwner = async (
  input: Readonly<{
    session: CommonWechatBrowserSession;
    selector: string;
    expectedSubject: string;
    providerObservation(): WechatProviderObservation;
  }>
) => {
  if (!input.selector || !input.expectedSubject) {
    webFail('admission');
  }
  await webStage('initialization', async () => {
    await input.session.navigate('wechat-web-open', '/demo-app');
    await input.session.waitForRoute('wechat-web-sign-in', ['/sign-in', '/sign-in/identifier']);
  });
  await webStage('provider-count', async () =>
    input.session.expectCount('wechat-web-provider-count', input.selector, 1)
  );
  await webStage('provider-click', async () =>
    input.session.click('wechat-web-provider', input.selector)
  );
  try {
    await input.session.waitForRoute('wechat-web-consent', ['/consent']);
  } catch {
    webFail(`consent-route-${await input.session.consentFailureRoute()}`);
  }
  await webStage('consent-click', async () =>
    input.session.click('wechat-web-authorize', 'role=button[name="Authorize"]')
  );
  await webStage('callback', async () => input.session.assertInitialCallback());
  await webStage('profile', async () => {
    const profile = await input.session.readProfile();
    if (profile.sub !== input.expectedSubject) {
      webFail('profile');
    }
  });
  await webStage('refresh', async () => {
    const refresh = await input.session.refresh();
    if (refresh.subject !== input.expectedSubject || !refresh.rotated) {
      webFail('refresh');
    }
  });
  const provider = input.providerObservation();
  await webStage('provider', async () => {
    assertProvider(provider, 1);
  });
  return Object.freeze({
    channel: 'web' as const,
    existingOwner: true as const,
    subjectPreserved: true as const,
    callback: 'state-issuer-code-bound' as const,
    pkce: 'S256' as const,
    refreshRotated: true as const,
    provider: providerEvidence(provider),
  });
};

export const runCommonWechatH5Registration = async (
  input: Readonly<{
    session: CommonWechatBrowserSession;
    selector: string;
    phone: string;
    takePasscode(recipient: string): Promise<string>;
    providerObservation(): WechatProviderObservation;
  }>
) => {
  if (!input.selector || !/^\d{8,15}$/u.test(input.phone)) {
    h5Fail('admission');
  }
  await h5Stage('initialization', async () => {
    await input.session.navigate('wechat-h5-open', '/demo-app');
    await input.session.waitForRoute('wechat-h5-sign-in', ['/sign-in', '/sign-in/identifier']);
  });
  await h5Stage('registration-transition', async () =>
    input.session.click('wechat-h5-create-account', 'role=link[name="Create account"]')
  );
  await h5Stage('registration-route', async () =>
    input.session.waitForRoute('wechat-h5-register', ['/register'])
  );
  await h5Stage('provider-count', async () =>
    input.session.expectCount('wechat-h5-provider-count', input.selector, 1)
  );
  await h5Stage('provider-click', async () =>
    input.session.click('wechat-h5-provider', input.selector)
  );
  await h5Stage('phone-route', async () =>
    input.session.waitForRoute('wechat-h5-phone', ['/continue/phone'])
  );
  await h5Stage('phone-submit', async () => {
    await input.session.fill('wechat-h5-phone-input', 'input[type="tel"]', input.phone);
    await input.session.click('wechat-h5-phone-continue', 'role=button[name="Continue"]');
  });
  await h5Stage('passcode-route', async () =>
    input.session.waitForRoute('wechat-h5-passcode', ['/continue/verification-code'])
  );
  const passcode = await h5Stage('passcode-retrieval', async () => input.takePasscode(input.phone));
  if (!/^\d{6}$/u.test(passcode)) {
    h5Fail('passcode-format');
  }
  await h5Stage('passcode-fill', async () => {
    for (const [index, digit] of [...passcode].entries()) {
      await input.session.fill(
        `wechat-h5-passcode-${index}`,
        `input[name="passcode_${index}"]`,
        digit
      );
    }
  });
  try {
    await input.session.waitForRoute('wechat-h5-consent', ['/consent']);
  } catch {
    h5Fail(`consent-route-${await input.session.consentFailureRoute()}`);
  }
  await h5Stage('consent-click', async () =>
    input.session.click('wechat-h5-authorize', 'role=button[name="Authorize"]')
  );
  await h5Stage('callback', async () => input.session.assertInitialCallback());
  const profile = await h5Stage('profile', async () => input.session.readProfile());
  if (
    typeof profile.sub !== 'string' ||
    !profile.sub ||
    profile.phone !== input.phone ||
    profile.phoneVerified !== true
  ) {
    h5Fail('profile');
  }
  await h5Stage('refresh', async () => {
    const refresh = await input.session.refresh();
    if (refresh.subject !== profile.sub || !refresh.rotated) {
      h5Fail('refresh');
    }
  });
  const provider = input.providerObservation();
  await h5Stage('provider', async () => {
    assertProvider(provider, 0);
  });
  return Object.freeze({
    channel: 'h5' as const,
    newOwner: true as const,
    identityCreated: true as const,
    verifiedPhone: true as const,
    phoneOnlyFulfillment: true as const,
    callback: 'state-issuer-code-bound' as const,
    pkce: 'S256' as const,
    refreshRotated: true as const,
    provider: providerEvidence(provider),
  });
};
/* eslint-enable no-await-in-loop, no-restricted-syntax */
