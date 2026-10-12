import {
  commonCompletionScenarioIds,
  compareCommonCompletionProjections,
} from './common-completion.js';
import { commonAccountSocialExpectedProjection } from './common-social-account.js';

test('keeps the approved final fourteen rows in their exact append order', () => {
  expect(commonCompletionScenarioIds).toHaveLength(14);
  expect(new Set(commonCompletionScenarioIds).size).toBe(14);
  expect(commonCompletionScenarioIds[0]).toBe('common.password.policy');
  expect(commonCompletionScenarioIds[13]).toBe('common.session.logout-preservation');
});
test('refuses a same-target false success, wrong provider, and extra private wrapper', () => {
  const expected = commonAccountSocialExpectedProjection('google');
  expect(
    compareCommonCompletionProjections('common.account.google-link', expected, expected)
  ).toEqual([]);
  for (const hostile of [
    { ...expected, profileLinked: false },
    commonAccountSocialExpectedProjection('wechat'),
    { ...expected, privateToken: 'synthetic-private-canary' },
  ]) {
    expect(
      compareCommonCompletionProjections('common.account.google-link', hostile, hostile)
    ).toEqual(['/projection']);
  }
});

test('publishes H5 evidence only when no owner setup request preceded registration', () => {
  const projection = {
    channel: 'h5',
    newOwner: true,
    identityCreated: true,
    verifiedPhone: true,
    phoneOnlyFulfillment: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    refreshRotated: true,
    provider: {
      setupRequests: 0,
      browserRequests: 1,
      providerRedirectExact: true,
      exchangeExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  };
  expect(compareCommonCompletionProjections('common.wechat.h5', projection, projection)).toEqual(
    []
  );
  const precreatedOwner = {
    ...projection,
    provider: { ...projection.provider, setupRequests: 1 },
  };
  expect(
    compareCommonCompletionProjections('common.wechat.h5', precreatedOwner, precreatedOwner)
  ).toEqual(['/projection']);
});
