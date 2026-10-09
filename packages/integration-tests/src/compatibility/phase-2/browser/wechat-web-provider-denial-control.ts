/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The bounded poll must observe ordered browser responses without overlapping reads. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase1BrowserExperienceFailure } from '../../phase-1/browser/contracts.js';

import type { CommonWechatWebProviderControlObservation } from './common-wechat-web-target-driver.js';

const maximumAttempts = 120;
const intervalMilliseconds = 250;
const fail = (): never => {
  throw new TypeError('Invalid WeChat Web provider denial control');
};

export const runWechatWebProviderDenialControl = async (
  input: Readonly<{
    selector: string;
    expectedStatus: 400 | 401;
    expectedError:
      | 'connector.wechat_unionid_required'
      | 'connector.social_auth_code_invalid'
      | 'connector.invalid_response';
    ownerBefore: unknown;
    session: Readonly<{
      navigate(step: string, path: string): Promise<void>;
      waitForRoute(step: string, paths: readonly string[]): Promise<void>;
      expectCount(step: string, selector: string, expected: number): Promise<void>;
      click(step: string, selector: string): Promise<void>;
      beginExperienceObservation(): Promise<void>;
      readExperienceFailure(): Promise<Phase1BrowserExperienceFailure>;
    }>;
    timing?: Readonly<{ wait(milliseconds: number): Promise<void> }>;
    ownerSnapshot(): Promise<unknown>;
  }>
): Promise<CommonWechatWebProviderControlObservation> => {
  if (!input.selector) {
    return fail();
  }
  await input.session.navigate('wechat-web-control-open', '/demo-app');
  await input.session.waitForRoute('wechat-web-control-sign-in', [
    '/sign-in',
    '/sign-in/identifier',
  ]);
  await input.session.expectCount('wechat-web-control-provider-count', input.selector, 1);
  await input.session.beginExperienceObservation();
  await input.session.click('wechat-web-control-provider', input.selector);
  const timing = input.timing ?? {
    wait: async (milliseconds: number) =>
      new Promise<void>((resolve) => {
        setTimeout(resolve, milliseconds);
      }),
  };
  let observed: Phase1BrowserExperienceFailure | undefined;
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const candidate = await input.session.readExperienceFailure();
    if (candidate.operation === 'social-verify' && candidate.status >= 400) {
      observed = candidate;
      break;
    }
    await timing.wait(intervalMilliseconds);
  }
  const ownerAfter = await input.ownerSnapshot();
  if (
    observed?.operation !== 'social-verify' ||
    observed.status !== input.expectedStatus ||
    observed.code !== input.expectedError ||
    !isDeepStrictEqual(input.ownerBefore, ownerAfter)
  ) {
    return fail();
  }
  return Object.freeze({
    accepted: false,
    status: input.expectedStatus,
    error: input.expectedError,
    ownerPreserved: true,
  });
};
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
