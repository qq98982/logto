/* eslint-disable @silverhand/fp/no-mutating-methods -- Ordered action capture proves the complete retry sequence. */
import {
  admitsWechatWebStateControlFailure,
  completeWechatWebStateControlRetry,
} from './wechat-web-state-control-retry.js';

const rejectedAuthorization = Object.freeze({
  requestCount: 1,
  queryShapeExact: true,
  clientMatched: true,
  callbackMatched: true,
  responseTypeCode: true,
  scopeExact: true,
  stateFormatValid: true,
  stateRoundTrip: false,
  fulfilledOnce: true,
});

const harness = (ownerAfter?: unknown) => {
  const actions: string[] = [];
  const finalOwner = ownerAfter ?? { id: 'owner', email: 'owner@example.invalid' };
  return {
    actions,
    input: {
      retryPath: '/callback/wechat-main?code=private&state=private',
      expectedOwnerId: 'owner',
      ownerBefore: { id: 'owner', email: 'owner@example.invalid' },
      ownerSnapshot: async () => finalOwner,
      session: {
        navigate: async (step: string) => {
          actions.push(step);
        },
        waitForRoute: async (step: string) => {
          actions.push(step);
        },
        click: async (step: string) => {
          actions.push(step);
        },
        assertInitialCallback: async () => {
          actions.push('callback');
        },
        readProfile: async () => {
          actions.push('profile');
          return { sub: 'owner' };
        },
        refresh: async () => {
          actions.push('refresh');
          return { subject: 'owner', rotated: true };
        },
      },
    },
  };
};

test('completes the preserved proof through callback, profile, refresh, and owner equality', async () => {
  const value = harness();
  await expect(completeWechatWebStateControlRetry(value.input)).resolves.toBeUndefined();
  expect(value.actions).toEqual([
    'wechat-web-correct-callback-retry',
    'wechat-web-correct-retry-consent',
    'wechat-web-correct-retry-authorize',
    'callback',
    'profile',
    'refresh',
  ]);
});

test('admits only the closed stored-state rejection before the correct retry', () => {
  const input = {
    errorMessage:
      'Common WeChat Web failed: consent-route-error-none-0-not-applicable-none-auth-111111101-state-stored',
    storedSocialState: true,
    providerFailureObserved: false,
    authorization: rejectedAuthorization,
  };
  expect(admitsWechatWebStateControlFailure(input)).toBe(true);
  expect(admitsWechatWebStateControlFailure({ ...input, storedSocialState: false })).toBe(false);
  expect(admitsWechatWebStateControlFailure({ ...input, providerFailureObserved: true })).toBe(
    false
  );
  expect(
    admitsWechatWebStateControlFailure({
      ...input,
      errorMessage: 'Common WeChat Web failed: private',
    })
  ).toBe(false);
});

test('rejects a retry when the owner changes after proof consumption', async () => {
  const value = harness({ id: 'owner', email: 'changed@example.invalid' });
  await expect(completeWechatWebStateControlRetry(value.input)).rejects.toThrow(
    'Invalid WeChat Web state control retry'
  );
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
