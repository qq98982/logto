import {
  assertCommonAccountPhoneChangeProjection,
  commonAccountPhoneChangePendingReferenceProjection,
} from './common-account-phone-change.js';

test('keeps the provisional phone-change projection closed pending the actual pair', () => {
  expect(
    assertCommonAccountPhoneChangeProjection(commonAccountPhoneChangePendingReferenceProjection)
  ).toBe(commonAccountPhoneChangePendingReferenceProjection);
  expect(() =>
    assertCommonAccountPhoneChangeProjection({
      ...commonAccountPhoneChangePendingReferenceProjection,
      newPhoneLoginAccepted: false as true,
    })
  ).toThrow('Invalid Common Account phone change flow');
});
