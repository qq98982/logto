import { commonEmailPasswordRegistrationExpectedProjection } from '../browser/common-email-password-registration-target-driver.js';

import {
  commonEmailPasswordRegistrationScenarioIds,
  compareCommonEmailPasswordRegistrationProjections,
} from './common-email-password-registration.js';

test('registers the canonical Common email password registration row', () => {
  expect(commonEmailPasswordRegistrationScenarioIds).toEqual([
    'common.email.password-registration',
  ]);
  expect(Object.isFrozen(commonEmailPasswordRegistrationScenarioIds)).toBe(true);
});

test('compares only the exact positive flow and all required registration controls', () => {
  expect(
    compareCommonEmailPasswordRegistrationProjections(
      commonEmailPasswordRegistrationExpectedProjection,
      commonEmailPasswordRegistrationExpectedProjection
    )
  ).toEqual([]);
  expect(
    compareCommonEmailPasswordRegistrationProjections(
      commonEmailPasswordRegistrationExpectedProjection,
      {
        ...commonEmailPasswordRegistrationExpectedProjection,
        rejectedPolicy: {
          ...commonEmailPasswordRegistrationExpectedProjection.rejectedPolicy,
          afterCount: 1,
        },
      } as never
    )
  ).toEqual(['/projection']);
});
