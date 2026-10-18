import {
  accountPasswordProofExpiryExpectedProjection,
  accountPasswordProofExpiryScenarioId,
  assertAccountPasswordProofExpiryProjection,
  compareAccountPasswordProofExpiryProjections,
} from './account-password-proof-expiry.js';

it('closes the supplemental stale current-password proof contract', () => {
  expect(accountPasswordProofExpiryScenarioId).toBe('supplemental.account.password-proof-expiry');
  expect(
    assertAccountPasswordProofExpiryProjection(accountPasswordProofExpiryExpectedProjection)
  ).toBe(accountPasswordProofExpiryExpectedProjection);
  expect(
    compareAccountPasswordProofExpiryProjections(
      accountPasswordProofExpiryExpectedProjection,
      accountPasswordProofExpiryExpectedProjection
    )
  ).toEqual([]);
  expect(() =>
    assertAccountPasswordProofExpiryProjection({
      ...accountPasswordProofExpiryExpectedProjection,
      mutation: { status: 204, error: 'none' },
    })
  ).toThrow('Invalid Account password-proof expiry comparison');
});
