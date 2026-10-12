import {
  commonAccountSocialExpectedProjection,
  commonGoogleConfiguredCollisionExpectedProjection,
  commonSocialAccountScenarioIds,
  compareCommonAccountSocialProjections,
  compareCommonGoogleConfiguredCollisionProjections,
} from './common-social-account.js';

test('declares the three Common social Account rows in append order', () => {
  expect(commonSocialAccountScenarioIds).toEqual([
    'common.google.configured-collision',
    'common.account.google-link',
    'common.account.wechat-link',
  ]);
  expect(Object.isFrozen(commonSocialAccountScenarioIds)).toBe(true);
});

test.each(['google', 'wechat'] as const)(
  'accepts only the complete %s Account link contract',
  (provider) => {
    const projection = commonAccountSocialExpectedProjection(provider);
    expect(compareCommonAccountSocialProjections(projection, projection)).toEqual([]);
    expect(
      compareCommonAccountSocialProjections(projection, {
        ...projection,
        destinationReplay: { status: 204, error: 'none' },
      })
    ).toEqual(['/projection']);
    expect(
      compareCommonAccountSocialProjections(projection, {
        ...projection,
        credentialsAbsent: false,
      })
    ).toEqual(['/projection']);
  }
);

test('accepts only the configured collision with preserved ownership and no implicit link', () => {
  const projection = commonGoogleConfiguredCollisionExpectedProjection;
  expect(compareCommonGoogleConfiguredCollisionProjections(projection, projection)).toEqual([]);
  expect(
    compareCommonGoogleConfiguredCollisionProjections(projection, {
      ...projection,
      implicitAssociationAbsent: false,
    })
  ).toEqual(['/projection']);
});
