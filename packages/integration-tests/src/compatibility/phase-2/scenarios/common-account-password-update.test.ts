import {
  assertCommonAccountPasswordUpdateProjection,
  commonAccountPasswordUpdateExpectedProjection,
} from '../browser/common-account-password-update.js';

import {
  commonAccountPasswordUpdateScenarioIds,
  compareCommonAccountPasswordUpdateProjections,
} from './common-account-password-update.js';

const observation = (status: number, error: 'none' | 'verification_record.permission_denied') =>
  Object.freeze({ status, error });
const projection = () =>
  Object.freeze({
    bearerOpaque: true as const,
    proof: 'current-password' as const,
    mutation: observation(204, 'none'),
    missingProof: observation(401, 'verification_record.permission_denied'),
    foreignProof: observation(401, 'verification_record.permission_denied'),
    samePassword: Object.freeze({ status: 422, error: 'user.same_password' as const }),
    readOnly: Object.freeze({ status: 400, error: 'account_center.field_not_editable' as const }),
    disabled: Object.freeze({ status: 400, error: 'account_center.not_enabled' as const }),
    denialStatePreserved: true as const,
    oldAccessRetained: true as const,
    oldRefreshRotated: true as const,
    oldPasswordRejected: true as const,
    newPasswordAccepted: true as const,
    ownerPreserved: true as const,
  });

test('uses the canonical password-update id and compares every public control exactly', () => {
  expect(commonAccountPasswordUpdateScenarioIds).toEqual(['common.account.password-update']);
  expect(compareCommonAccountPasswordUpdateProjections(projection(), projection())).toEqual([]);
  expect(assertCommonAccountPasswordUpdateProjection(projection())).toEqual(
    commonAccountPasswordUpdateExpectedProjection
  );
  expect(
    compareCommonAccountPasswordUpdateProjections(projection(), {
      ...projection(),
      foreignProof: observation(404, 'verification_record.permission_denied'),
    })
  ).toEqual(['/projection']);
  for (const field of [
    'missingProof',
    'foreignProof',
    'samePassword',
    'readOnly',
    'disabled',
  ] as const) {
    expect(
      compareCommonAccountPasswordUpdateProjections(
        {
          ...commonAccountPasswordUpdateExpectedProjection,
          [field]: { status: 204, error: 'none' },
        },
        {
          ...commonAccountPasswordUpdateExpectedProjection,
          [field]: { status: 204, error: 'none' },
        }
      )
    ).toEqual(['/projection']);
    expect(() =>
      assertCommonAccountPasswordUpdateProjection({
        ...commonAccountPasswordUpdateExpectedProjection,
        [field]: { status: 204, error: 'none' },
      })
    ).toThrow('Invalid Common Account password update flow');
  }
});
