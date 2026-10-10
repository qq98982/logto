import {
  assertCommonAccountEmailChangeProjection,
  commonAccountEmailChangeExpectedProjection,
} from '../browser/common-account-email-change.js';

import {
  commonAccountEmailChangeScenarioIds,
  compareCommonAccountEmailChangeProjections,
} from './common-account-email-change.js';

const projection = () =>
  Object.freeze({
    opaqueAccess: true as const,
    proof: 'current+destination-email' as const,
    mutation: Object.freeze({ status: 204, error: 'none' as const }),
    missingCurrentProof: Object.freeze({
      status: 401,
      error: 'verification_record.permission_denied' as const,
    }),
    wrongAccountProof: Object.freeze({
      status: 401,
      error: 'verification_record.permission_denied' as const,
    }),
    destinationReplay: Object.freeze({ status: 204, error: 'none' as const }),
    collision: Object.freeze({ status: 422, error: 'user.email_already_in_use' as const }),
    denialStatePreserved: true as const,
    ownerPreserved: true as const,
    newEmailVerified: true as const,
    newEmailLoginAccepted: true as const,
    refreshRotated: true as const,
  });

test('uses the canonical email-change id and compares every public control exactly', () => {
  expect(commonAccountEmailChangeScenarioIds).toEqual(['common.account.email-change']);
  expect(compareCommonAccountEmailChangeProjections(projection(), projection())).toEqual([]);
  expect(assertCommonAccountEmailChangeProjection(projection())).toEqual(
    commonAccountEmailChangeExpectedProjection
  );
  expect(
    compareCommonAccountEmailChangeProjections(projection(), {
      ...projection(),
      destinationReplay: { status: 401, error: 'verification_record.permission_denied' },
    })
  ).toEqual(['/projection']);
  for (const field of [
    'mutation',
    'missingCurrentProof',
    'wrongAccountProof',
    'destinationReplay',
    'collision',
  ] as const) {
    expect(
      compareCommonAccountEmailChangeProjections(
        {
          ...commonAccountEmailChangeExpectedProjection,
          [field]: { status: 500, error: 'unknown' },
        },
        {
          ...commonAccountEmailChangeExpectedProjection,
          [field]: { status: 500, error: 'unknown' },
        }
      )
    ).toEqual(['/projection']);
  }
});
