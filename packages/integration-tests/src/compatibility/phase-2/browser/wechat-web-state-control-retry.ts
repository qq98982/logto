import { isDeepStrictEqual } from 'node:util';

import type { WechatWebAuthorizationObservation } from './wechat-web-authorization-observer.js';

const fail = (): never => {
  throw new TypeError('Invalid WeChat Web state control retry');
};

export const admitsWechatWebStateControlFailure = (
  input: Readonly<{
    errorMessage: string | undefined;
    storedSocialState: boolean;
    expectedStoredSocialState: boolean;
    providerFailureObserved: boolean;
    authorization: WechatWebAuthorizationObservation;
  }>
): boolean => {
  const expectedError = input.expectedStoredSocialState
    ? /^Common WeChat Web failed: consent-route-(?:sign-in|register|continue|demo|error|callback|other)-none-0-not-applicable-none-auth-[01]{9}-state-stored$/u
    : /^Common WeChat Web failed: consent-route-(?:sign-in|register|continue|demo|error|callback|other)-none-0-not-applicable-none-auth-[01]{9}-state-cleared$/u;
  return (
    input.storedSocialState === input.expectedStoredSocialState &&
    !input.providerFailureObserved &&
    expectedError.test(input.errorMessage ?? '') &&
    input.authorization.requestCount === 1 &&
    input.authorization.stateFormatValid &&
    !input.authorization.stateRoundTrip &&
    input.authorization.fulfilledOnce
  );
};

export const completeWechatWebStateControlRetry = async (
  input: Readonly<{
    retryPath: string;
    expectedOwnerId: string;
    ownerBefore: unknown;
    session: Readonly<{
      navigate(step: string, path: string): Promise<void>;
      waitForRoute(step: string, paths: readonly string[]): Promise<void>;
      click(step: string, selector: string): Promise<void>;
      assertInitialCallback(): Promise<void>;
      readProfile(): Promise<Readonly<{ sub?: unknown }>>;
      refresh(): Promise<Readonly<{ subject?: unknown; rotated: boolean }>>;
    }>;
    ownerSnapshot(): Promise<unknown>;
  }>
): Promise<void> => {
  if (!input.retryPath.startsWith('/callback/') || !input.expectedOwnerId) {
    return fail();
  }
  await input.session.navigate('wechat-web-correct-callback-retry', input.retryPath);
  await input.session.waitForRoute('wechat-web-correct-retry-consent', ['/consent']);
  await input.session.click('wechat-web-correct-retry-authorize', 'role=button[name="Authorize"]');
  await input.session.assertInitialCallback();
  const profile = await input.session.readProfile();
  const refreshed = await input.session.refresh();
  const ownerAfter = await input.ownerSnapshot();
  if (
    profile.sub !== input.expectedOwnerId ||
    refreshed.subject !== input.expectedOwnerId ||
    !refreshed.rotated ||
    !isDeepStrictEqual(input.ownerBefore, ownerAfter)
  ) {
    return fail();
  }
};
