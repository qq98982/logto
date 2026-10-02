/* eslint-disable no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Closed mutation controls and ordered live execution are kept together. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2CandidateInvariantId, Phase2ProfileRegistries } from '../profile.js';

export const verificationCodeCandidateInvariantIds = Object.freeze([
  'verification-code.cross-tenant-owner-rejected',
  'verification-code.cross-account-owner-rejected',
  'verification-code.cross-client-owner-rejected',
  'verification-code.wrong-audience-rejected',
  'verification-code.retry-budget-committed',
  'verification-code.concurrent-single-consumer',
  'verification-code.failed-delivery-state-preserved',
  'verification-code.envelope-secret-absent',
] as const satisfies readonly Phase2CandidateInvariantId[]);

export type VerificationCodeCandidateInvariantId =
  (typeof verificationCodeCandidateInvariantIds)[number];

type OwnershipProjection = Readonly<{
  denied: Readonly<{ status: 400 | 401; error: string }>;
  ownerAfterDenial: 'verified';
  challengeConsumedByDenial: false;
}>;

export type VerificationCodeCandidateInvariantProjection =
  | (OwnershipProjection & Readonly<{ invariant: 'cross-tenant-owner-rejected' }>)
  | (OwnershipProjection & Readonly<{ invariant: 'cross-account-owner-rejected' }>)
  | (OwnershipProjection & Readonly<{ invariant: 'cross-client-owner-rejected' }>)
  | (OwnershipProjection & Readonly<{ invariant: 'wrong-audience-rejected' }>)
  | Readonly<{
      invariant: 'retry-budget-committed';
      mismatches: 10;
      exhausted: true;
      wrongCodeRejected: true;
      correctCodeRejected: true;
      persistedFailedAttempts: 10;
      envelopeCleared: true;
    }>
  | Readonly<{
      invariant: 'concurrent-single-consumer';
      winnerCount: 1;
      loser: Readonly<{ status: 400; error: 'verification_code.not_found' }>;
      persistedConsumed: true;
    }>
  | Readonly<{
      invariant: 'failed-delivery-state-preserved';
      failed: Readonly<{
        status: 400;
        error: 'connector.general';
        message: 'The email service could not accept the message.';
      }>;
      previousChallenge: 'verified';
      successfulSendReceipts: 1;
      replacementRows: 0;
    }>
  | Readonly<{
      invariant: 'envelope-secret-absent';
      forcedRls: true;
      clearCodeColumns: 'absent';
      codeAbsentFromRows: true;
      ciphertextPresentBeforeConsumption: true;
      ciphertextClearedAfterConsumption: true;
    }>;

export type VerificationCodeCandidateInvariantExecutor = Readonly<{
  execute(
    id: VerificationCodeCandidateInvariantId
  ): Promise<VerificationCodeCandidateInvariantProjection>;
}>;

export type VerificationCodeCandidateInvariantControlEvidence = Readonly<{
  id: VerificationCodeCandidateInvariantId;
  candidate: VerificationCodeCandidateInvariantProjection;
  positiveControl: Readonly<{ detected: true }>;
  negativeControl: Readonly<{ detected: true; pointer: string }>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 verification-code candidate invariant');
};

const ownership = (
  invariant:
    | 'cross-tenant-owner-rejected'
    | 'cross-account-owner-rejected'
    | 'cross-client-owner-rejected'
    | 'wrong-audience-rejected',
  status: 400 | 401,
  error: string
): VerificationCodeCandidateInvariantProjection =>
  Object.freeze({
    invariant,
    denied: Object.freeze({ status, error }),
    ownerAfterDenial: 'verified' as const,
    challengeConsumedByDenial: false as const,
  });

const expected = Object.freeze({
  'verification-code.cross-tenant-owner-rejected': ownership(
    'cross-tenant-owner-rejected',
    401,
    'auth.unauthorized'
  ),
  'verification-code.cross-account-owner-rejected': ownership(
    'cross-account-owner-rejected',
    400,
    'verification_record.not_found'
  ),
  'verification-code.cross-client-owner-rejected': ownership(
    'cross-client-owner-rejected',
    400,
    'verification_record.not_found'
  ),
  'verification-code.wrong-audience-rejected': ownership(
    'wrong-audience-rejected',
    401,
    'auth.unauthorized'
  ),
  'verification-code.retry-budget-committed': Object.freeze({
    invariant: 'retry-budget-committed' as const,
    mismatches: 10 as const,
    exhausted: true as const,
    wrongCodeRejected: true as const,
    correctCodeRejected: true as const,
    persistedFailedAttempts: 10 as const,
    envelopeCleared: true as const,
  }),
  'verification-code.concurrent-single-consumer': Object.freeze({
    invariant: 'concurrent-single-consumer' as const,
    winnerCount: 1 as const,
    loser: Object.freeze({ status: 400 as const, error: 'verification_code.not_found' as const }),
    persistedConsumed: true as const,
  }),
  'verification-code.failed-delivery-state-preserved': Object.freeze({
    invariant: 'failed-delivery-state-preserved' as const,
    failed: Object.freeze({
      status: 400 as const,
      error: 'connector.general' as const,
      message: 'The email service could not accept the message.' as const,
    }),
    previousChallenge: 'verified' as const,
    successfulSendReceipts: 1 as const,
    replacementRows: 0 as const,
  }),
  'verification-code.envelope-secret-absent': Object.freeze({
    invariant: 'envelope-secret-absent' as const,
    forcedRls: true as const,
    clearCodeColumns: 'absent' as const,
    codeAbsentFromRows: true as const,
    ciphertextPresentBeforeConsumption: true as const,
    ciphertextClearedAfterConsumption: true as const,
  }),
}) satisfies Readonly<
  Record<VerificationCodeCandidateInvariantId, VerificationCodeCandidateInvariantProjection>
>;

const pointers = Object.freeze({
  'verification-code.cross-tenant-owner-rejected': '/ownerAfterDenial',
  'verification-code.cross-account-owner-rejected': '/challengeConsumedByDenial',
  'verification-code.cross-client-owner-rejected': '/denied/status',
  'verification-code.wrong-audience-rejected': '/denied/error',
  'verification-code.retry-budget-committed': '/persistedFailedAttempts',
  'verification-code.concurrent-single-consumer': '/winnerCount',
  'verification-code.failed-delivery-state-preserved': '/successfulSendReceipts',
  'verification-code.envelope-secret-absent': '/codeAbsentFromRows',
}) satisfies Readonly<Record<VerificationCodeCandidateInvariantId, string>>;

const mutate = (
  id: VerificationCodeCandidateInvariantId,
  projection: VerificationCodeCandidateInvariantProjection
): unknown => {
  const copy = structuredClone(projection) as Record<string, unknown>;
  const pointer = pointers[id].split('/').slice(1);
  const parent = pointer
    .slice(0, -1)
    .reduce<Record<string, unknown>>((value, key) => value[key] as Record<string, unknown>, copy);
  const key = pointer.at(-1) ?? fail();
  const value = parent[key];
  parent[key] =
    typeof value === 'boolean' ? !value : typeof value === 'number' ? value + 1 : 'mutated';
  return copy;
};

export const runVerificationCodeCandidateInvariantControls = (
  id: VerificationCodeCandidateInvariantId,
  candidate: VerificationCodeCandidateInvariantProjection
): VerificationCodeCandidateInvariantControlEvidence => {
  if (
    !isDeepStrictEqual(candidate, expected[id]) ||
    isDeepStrictEqual(mutate(id, candidate), candidate)
  ) {
    return fail();
  }
  return Object.freeze({
    id,
    candidate,
    positiveControl: Object.freeze({ detected: true as const }),
    negativeControl: Object.freeze({ detected: true as const, pointer: pointers[id] }),
  });
};

export const runVerificationCodeCandidateInvariants = async (
  profile: Phase2ProfileRegistries,
  executor: VerificationCodeCandidateInvariantExecutor
): Promise<readonly VerificationCodeCandidateInvariantControlEvidence[]> => {
  const start = profile.candidateInvariantScenarios.indexOf(
    verificationCodeCandidateInvariantIds[0]
  );
  const segment = profile.candidateInvariantScenarios.slice(
    start,
    start + verificationCodeCandidateInvariantIds.length
  );
  if (
    start < 0 ||
    segment.length !== verificationCodeCandidateInvariantIds.length ||
    segment.some((id, index) => id !== verificationCodeCandidateInvariantIds[index])
  ) {
    return fail();
  }
  const evidence = [];
  for (const id of verificationCodeCandidateInvariantIds) {
    evidence.push(runVerificationCodeCandidateInvariantControls(id, await executor.execute(id)));
  }
  return Object.freeze(evidence);
};

export const verificationCodeCandidateInvariantExpectedProjection = (
  id: VerificationCodeCandidateInvariantId
): VerificationCodeCandidateInvariantProjection => expected[id];
/* eslint-enable no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
