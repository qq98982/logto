import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  ledger: {
    entries: [
      { keyId: '<wrapping-key.1>', generation: 1, expected: 2, actual: 2 },
      { keyId: '<wrapping-key.2>', generation: 2, expected: 1, actual: 1 },
    ],
    mismatches: [],
    negativeCounts: 0,
    uncommittedDeltas: 0,
  },
};
const negativeProjection = {
  ledger: {
    ...positiveProjection.ledger,
    mismatches: [{ count: 1 }],
  },
};

export const keystoreReferenceCountLedger = defineCandidateInvariant({
  id: 'keystore.reference-count-ledger',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'material-population-spanning-tenants-and-wrapping-keys' },
  perturbation: { kind: 'insert-update-delete-rollback-and-relationship-transitions' },
  expectedPublicOutcome: { ledgerMatchesMaterialPopulation: true, mismatchCount: 0 },
  expectedPersistedOutcome: positiveProjection.ledger,
  forbiddenOutcome: {
    countMismatch: true,
    missedMaterialTable: true,
    uncommittedDelta: true,
    negativeCount: true,
  },
  cleanup: { kind: 'rollback-and-delete-material-fixtures' },
  sanitizedProjection: {
    fields: [
      'ledger.entries.keyId',
      'ledger.entries.generation',
      'ledger.entries.expected',
      'ledger.entries.actual',
      'ledger.mismatches.count',
      'ledger.negativeCounts',
      'ledger.uncommittedDeltas',
    ],
    aggregateOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'reference ledger equals the complete material population',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'reference ledger contains one mismatch',
    input: {
      variant: 'negative',
      fault: { operation: 'add', path: '/ledger/mismatches/0/count', value: 1 },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/ledger/mismatches/0/count',
  },
} satisfies CandidateInvariantContract);

export default keystoreReferenceCountLedger;
