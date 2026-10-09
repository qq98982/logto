/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The call latch proves wrong-purpose work does not run after a replay mismatch. */
import {
  commonEmailRecoveryExpectedControls,
  runCommonEmailRecoveryControls,
  type EmailRecoveryControlAttempt,
  type EmailRecoveryControlRuntime,
} from './common-email-recovery-controls.js';

const verified: EmailRecoveryControlAttempt = {
  status: 's200',
  outcome: 'verified',
  error: 'none',
};
const replay: EmailRecoveryControlAttempt = {
  status: 's400',
  outcome: 'error',
  error: 'verification_code.not_found',
};
const wrongPurpose: EmailRecoveryControlAttempt = {
  status: 's404',
  outcome: 'error',
  error: 'session.verification_session_not_found',
};

const runtime = (
  overrides: Partial<EmailRecoveryControlRuntime> = {}
): EmailRecoveryControlRuntime => ({
  replay: async () => ({ first: verified, second: replay }),
  wrongPurpose: async () => ({ recovery: wrongPurpose, ownerAfterRecovery: verified }),
  ...overrides,
});

test('publishes exact replay and wrong-purpose outcomes without verification material', async () => {
  await expect(runCommonEmailRecoveryControls(runtime())).resolves.toEqual(
    commonEmailRecoveryExpectedControls
  );
  expect(Object.isFrozen(commonEmailRecoveryExpectedControls)).toBe(true);
  expect(JSON.stringify(commonEmailRecoveryExpectedControls)).not.toMatch(
    /123456|private|verificationId|passcode/u
  );
});

test.each([
  ['first use', { status: 's400', outcome: 'error', error: 'verification_code.not_found' }],
  ['replay status', { status: 's404', outcome: 'error', error: 'verification_code.not_found' }],
] as const)(
  'rejects an unexpected %s result before wrong-purpose probing',
  async (_name, value) => {
    let wrongPurposeCalled = false;
    await expect(
      runCommonEmailRecoveryControls(
        runtime({
          replay: async () => ({
            first: _name === 'first use' ? value : verified,
            second: _name === 'replay status' ? value : replay,
          }),
          wrongPurpose: async () => {
            wrongPurposeCalled = true;
            return { recovery: wrongPurpose, ownerAfterRecovery: verified };
          },
        })
      )
    ).rejects.toThrow('Common email recovery controls failed: replay');
    expect(wrongPurposeCalled).toBe(false);
  }
);
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */

test('requires the owner challenge to remain usable after the wrong-purpose attempt', async () => {
  await expect(
    runCommonEmailRecoveryControls(
      runtime({
        wrongPurpose: async () => ({ recovery: wrongPurpose, ownerAfterRecovery: replay }),
      })
    )
  ).rejects.toThrow('Common email recovery controls failed: wrong-purpose');
});

test('bounds private runtime failures to their public control stage', async () => {
  await expect(
    runCommonEmailRecoveryControls(
      runtime({
        replay: async () => {
          throw new Error('private transport detail');
        },
      })
    )
  ).rejects.toThrow('Common email recovery controls failed: replay');
});
