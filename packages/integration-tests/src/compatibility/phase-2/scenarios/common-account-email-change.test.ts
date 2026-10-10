import {
  commonAccountEmailChangeScenarioIds,
  compareCommonAccountEmailChangeProjections,
} from './common-account-email-change.js';

const projection = () =>
  Object.freeze({
    bearerOpaque: true as const,
    proof: 'current-password+destination-email' as const,
    mutation: Object.freeze({ status: 204, error: 'none' as const }),
    missingCurrentProof: Object.freeze({
      status: 401,
      error: 'verification_record.permission_denied' as const,
    }),
    wrongAccountProof: Object.freeze({
      status: 401,
      error: 'verification_record.permission_denied' as const,
    }),
    destinationReplay: Object.freeze({
      status: 401,
      error: 'verification_record.permission_denied' as const,
    }),
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
  expect(
    compareCommonAccountEmailChangeProjections(projection(), {
      ...projection(),
      destinationReplay: { status: 204, error: 'none' },
    })
  ).toEqual(['/projection']);
});
