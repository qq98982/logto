import {
  assertCommonAccountPhoneChangeProjection,
  commonAccountPhoneChangePendingReferenceProjection,
} from '../browser/common-account-phone-change.js';

import {
  commonAccountPhoneChangeScenarioIds,
  compareCommonAccountPhoneChangeProjections,
} from './common-account-phone-change.js';

test('uses the canonical phone-change id and compares every pending public control exactly', () => {
  expect(commonAccountPhoneChangeScenarioIds).toEqual(['common.account.phone-change']);
  expect(
    compareCommonAccountPhoneChangeProjections(
      commonAccountPhoneChangePendingReferenceProjection,
      commonAccountPhoneChangePendingReferenceProjection
    )
  ).toEqual([]);
  expect(
    assertCommonAccountPhoneChangeProjection(commonAccountPhoneChangePendingReferenceProjection)
  ).toEqual(commonAccountPhoneChangePendingReferenceProjection);
  expect(
    compareCommonAccountPhoneChangeProjections(commonAccountPhoneChangePendingReferenceProjection, {
      ...commonAccountPhoneChangePendingReferenceProjection,
      emailPreserved: false as true,
    })
  ).toEqual(['/projection']);
});
