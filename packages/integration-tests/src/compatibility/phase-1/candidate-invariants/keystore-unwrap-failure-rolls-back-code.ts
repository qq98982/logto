import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  publicOutcome: { errorClass: 'key-unwrap-failed', retryable: true },
  semanticState: {
    code: { consumed: false },
    rows: { familyRows: 0, materialRows: 0 },
  },
  retryProbe: { succeeded: true },
};
const negativeProjection = {
  ...positiveProjection,
  semanticState: {
    ...positiveProjection.semanticState,
    code: { consumed: true },
  },
};

export const keystoreUnwrapFailureRollsBackCode = defineCandidateInvariant({
  id: 'keystore.unwrap-failure-rolls-back-code',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'one-valid-unconsumed-authorization-code' },
  perturbation: { kind: 'deterministic-master-key-unwrap-failure-during-issuance' },
  expectedPublicOutcome: positiveProjection.publicOutcome,
  expectedPersistedOutcome: positiveProjection.semanticState,
  forbiddenOutcome: { codeConsumed: true, partialFamily: true, partialMaterial: true },
  cleanup: { kind: 'remove-fault-and-revoke-fixture-code' },
  sanitizedProjection: {
    fields: ['publicOutcome', 'semanticState.code.consumed', 'semanticState.rows', 'retryProbe'],
    sensitiveValuesAbsent: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'unwrap failure rolls back authorization code consumption',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'unwrap failure consumes the authorization code',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/semanticState/code/consumed', value: true },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/semanticState/code/consumed',
  },
} satisfies CandidateInvariantContract);

export default keystoreUnwrapFailureRollsBackCode;
