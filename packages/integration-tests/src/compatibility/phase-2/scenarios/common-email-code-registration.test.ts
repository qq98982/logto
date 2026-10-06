import { commonEmailCodeRegistrationExpectedProjection } from '../browser/common-email-code-registration-target-driver.js';

import {
  commonEmailCodeRegistrationScenarioIds,
  compareCommonEmailCodeRegistrationProjections,
} from './common-email-code-registration.js';

test('registers the Common email Code registration row after sign-in', () => {
  expect(commonEmailCodeRegistrationScenarioIds).toEqual(['common.email.code-registration']);
  expect(Object.isFrozen(commonEmailCodeRegistrationScenarioIds)).toBe(true);
});

test('compares only exact registration projections with all three controls', () => {
  expect(
    compareCommonEmailCodeRegistrationProjections(
      commonEmailCodeRegistrationExpectedProjection,
      commonEmailCodeRegistrationExpectedProjection
    )
  ).toEqual([]);
  expect(
    compareCommonEmailCodeRegistrationProjections(commonEmailCodeRegistrationExpectedProjection, {
      ...commonEmailCodeRegistrationExpectedProjection,
      occupiedRegistration: {
        ...commonEmailCodeRegistrationExpectedProjection.occupiedRegistration,
        ownerUnchanged: false,
      },
    } as never)
  ).toEqual(['/projection']);
});
