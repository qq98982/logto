import { assertClientCredentialsEvidenceIsSanitized } from '../projections/client-credentials.js';
import { assertDeviceAuthorizationEvidenceIsSanitized } from '../projections/device-authorization.js';

import {
  combineEmailRecoveryContextFailure,
  commonEmailRecoveryExpectedProjection,
  commonEmailRecoveryTargetFailureStage,
} from './common-email-recovery-target-driver.js';

test('publishes the complete closed flow and control projection', () => {
  expect(commonEmailRecoveryExpectedProjection).toEqual({
    identifier: 'email',
    recovery: 'completed',
    previousBeforeReset: 'accepted',
    updateApplied: true,
    replacementAccepted: 'accepted',
    previousRejected: 'rejected',
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    profileVerified: true,
    refreshRotated: true,
    priorAccessUsable: true,
    priorSessionUsable: true,
    verificationReplay: {
      first: { status: 's200', outcome: 'verified', error: 'none' },
      second: {
        status: 's400',
        outcome: 'error',
        error: 'verification_code.not_found',
      },
    },
    wrongPurpose: {
      recovery: {
        status: 's404',
        outcome: 'error',
        error: 'session.verification_session_not_found',
      },
      ownerAfterRecovery: { status: 's200', outcome: 'verified', error: 'none' },
    },
  });
  expect(commonEmailRecoveryExpectedProjection.verificationReplay.first).not.toBe(
    commonEmailRecoveryExpectedProjection.wrongPurpose.ownerAfterRecovery
  );
  expect(() => {
    assertClientCredentialsEvidenceIsSanitized(commonEmailRecoveryExpectedProjection);
  }).not.toThrow();
  expect(() => {
    assertDeviceAuthorizationEvidenceIsSanitized(commonEmailRecoveryExpectedProjection);
  }).not.toThrow();
});

test('preserves the finite callback stage when browser cleanup succeeds', () => {
  const callback = new TypeError('Common email recovery failed: prior-access');
  expect(
    commonEmailRecoveryTargetFailureStage(
      combineEmailRecoveryContextFailure(callback, new Error('closed context failure'))
    )
  ).toBe('flow-prior-access');
});

test('adds cleanup to the finite callback stage when browser cleanup fails', () => {
  const callback = new TypeError('Common email recovery failed: new-password-reset');
  expect(
    commonEmailRecoveryTargetFailureStage(
      combineEmailRecoveryContextFailure(
        callback,
        new AggregateError(
          [callback, new Error('private cleanup detail')],
          'context cleanup failed'
        )
      )
    )
  ).toBe('flow-new-password-reset-cleanup');
});
