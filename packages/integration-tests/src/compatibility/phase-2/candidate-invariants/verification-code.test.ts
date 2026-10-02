/* eslint-disable @typescript-eslint/no-unnecessary-condition, no-use-extend-native/no-use-extend-native, @typescript-eslint/consistent-type-assertions -- Negative controls deliberately forge a projection and reorder the closed registry. */
import type { Phase2ProfileRegistries } from '../profile.js';

import {
  runVerificationCodeCandidateInvariants,
  verificationCodeCandidateInvariantExpectedProjection,
  verificationCodeCandidateInvariantIds,
  type VerificationCodeCandidateInvariantExecutor,
} from './verification-code.js';

describe('Phase 2 verification-code candidate invariants', () => {
  it('requires every closed candidate-only control in registry order', async () => {
    const profile = {
      candidateInvariantScenarios: verificationCodeCandidateInvariantIds,
    } as unknown as Phase2ProfileRegistries;
    const executor: VerificationCodeCandidateInvariantExecutor = {
      execute: async (id) => verificationCodeCandidateInvariantExpectedProjection(id),
    };
    const evidence = await runVerificationCodeCandidateInvariants(profile, executor);

    expect(evidence.map(({ id }) => id)).toEqual(verificationCodeCandidateInvariantIds);
    expect(evidence.every(({ positiveControl }) => positiveControl.detected)).toBe(true);
    expect(evidence.every(({ negativeControl }) => negativeControl.detected)).toBe(true);
    expect(new Set(evidence.map(({ negativeControl }) => negativeControl.pointer)).size).toBe(
      evidence.length
    );
    expect(
      verificationCodeCandidateInvariantExpectedProjection(
        'verification-code.retry-budget-committed'
      )
    ).toMatchObject({
      mismatches: 10,
      wrongCodeRejected: true,
      correctCodeRejected: true,
      persistedFailedAttempts: 10,
      envelopeCleared: true,
    });
    expect(
      verificationCodeCandidateInvariantExpectedProjection(
        'verification-code.failed-delivery-state-preserved'
      )
    ).toMatchObject({
      failed: {
        status: 400,
        error: 'connector.general',
        message: 'The email service could not accept the message.',
      },
      previousChallenge: 'verified',
      successfulSendReceipts: 1,
      replacementRows: 0,
    });
  });

  it('rejects a missing, reordered, or mutated control', async () => {
    const profile = {
      candidateInvariantScenarios: [...verificationCodeCandidateInvariantIds].toReversed(),
    } as unknown as Phase2ProfileRegistries;
    await expect(
      runVerificationCodeCandidateInvariants(profile, {
        execute: async (id) => verificationCodeCandidateInvariantExpectedProjection(id),
      })
    ).rejects.toThrow('Invalid Phase 2 verification-code candidate invariant');

    const validProfile = {
      candidateInvariantScenarios: verificationCodeCandidateInvariantIds,
    } as unknown as Phase2ProfileRegistries;
    await expect(
      runVerificationCodeCandidateInvariants(validProfile, {
        execute: async (id) =>
          id === verificationCodeCandidateInvariantIds[0]
            ? ({
                ...verificationCodeCandidateInvariantExpectedProjection(id),
                ownerAfterDenial: 'rejected',
              } as never)
            : verificationCodeCandidateInvariantExpectedProjection(id),
      })
    ).rejects.toThrow('Invalid Phase 2 verification-code candidate invariant');
  });
});
/* eslint-enable @typescript-eslint/no-unnecessary-condition, no-use-extend-native/no-use-extend-native, @typescript-eslint/consistent-type-assertions */
