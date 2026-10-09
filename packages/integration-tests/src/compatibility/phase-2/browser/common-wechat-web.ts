/* Web-only browser contract for the canonical Common WeChat row. */
import type { CommonEmailPasswordBrowserSession } from './common-email-password-sign-in.js';

export type CommonWechatBrowserSession = Pick<
  CommonEmailPasswordBrowserSession,
  'navigate' | 'waitForRoute' | 'click' | 'assertInitialCallback' | 'refresh'
> &
  Readonly<{
    expectCount(step: string, selector: string, expected: number): Promise<void>;
    consentFailureRoute(): Promise<string>;
    readProfile(): Promise<Readonly<{ sub?: unknown }>>;
  }>;

export type WechatProviderTransportObservation = Readonly<{
  setupRequests: 0 | 1;
  browserRequests: 1;
  tokenExact: true;
  userinfoExact: true;
  unionIdStable: true;
}>;
export type WechatProviderObservation = WechatProviderTransportObservation &
  Readonly<{ authorizationExact: true }>;

export type CommonWechatWebStage =
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
type WebStage = CommonWechatWebStage;
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
    providerObservation(): Promise<WechatProviderObservation>;
    reportStage?(stage: CommonWechatWebStage): void;
  }>
) => {
  if (!input.selector || !input.expectedSubject) {
    webFail('admission');
  }
  input.reportStage?.('initialization');
  await webStage('initialization', async () => {
    await input.session.navigate('wechat-web-open', '/demo-app');
    await input.session.waitForRoute('wechat-web-sign-in', ['/sign-in', '/sign-in/identifier']);
  });
  input.reportStage?.('provider-count');
  await webStage('provider-count', async () =>
    input.session.expectCount('wechat-web-provider-count', input.selector, 1)
  );
  input.reportStage?.('provider-click');
  await webStage('provider-click', async () =>
    input.session.click('wechat-web-provider', input.selector)
  );
  input.reportStage?.('consent-route');
  try {
    await input.session.waitForRoute('wechat-web-consent', ['/consent']);
  } catch {
    webFail(`consent-route-${await input.session.consentFailureRoute()}`);
  }
  input.reportStage?.('consent-click');
  await webStage('consent-click', async () =>
    input.session.click('wechat-web-authorize', 'role=button[name="Authorize"]')
  );
  input.reportStage?.('callback');
  await webStage('callback', async () => input.session.assertInitialCallback());
  input.reportStage?.('profile');
  await webStage('profile', async () => {
    const profile = await input.session.readProfile();
    if (profile.sub !== input.expectedSubject) {
      webFail('profile');
    }
  });
  input.reportStage?.('refresh');
  await webStage('refresh', async () => {
    const refresh = await input.session.refresh();
    if (refresh.subject !== input.expectedSubject || !refresh.rotated) {
      webFail('refresh');
    }
  });
  input.reportStage?.('provider');
  const provider = await webStage('provider', async () => {
    const observed = await input.providerObservation();
    assertProvider(observed, 1);
    return observed;
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
