import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  fence: { generation: 2, status: 'completed' },
  lateCommit: { accepted: false, errorClass: 'wrapping-fence' },
  semanticState: {
    ledger: { oldKeyReferences: 0 },
    material: { oldKeyReferences: 0, newKeyReferences: 1 },
  },
};
const negativeProjection = {
  ...positiveProjection,
  semanticState: {
    ...positiveProjection.semanticState,
    material: { ...positiveProjection.semanticState.material, oldKeyReferences: 1 },
  },
};

export const keystoreWrappingFenceLateCommit = defineCandidateInvariant({
  id: 'keystore.wrapping-fence-late-commit',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'old-key-writer-held-before-fence', oldGeneration: 1 },
  perturbation: { kind: 'promote-lock-zero-scan-and-release-late-commit', fenceGeneration: 2 },
  expectedPublicOutcome: positiveProjection.lateCommit,
  expectedPersistedOutcome: positiveProjection.semanticState,
  forbiddenOutcome: { committedOldKeyReferenceAfterFence: true },
  cleanup: { kind: 'rollback-writer-and-remove-staged-fixture' },
  sanitizedProjection: {
    fields: [
      'fence.generation',
      'fence.status',
      'lateCommit',
      'semanticState.ledger',
      'semanticState.material',
    ],
    logicalKeyGenerationsOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'late old-key commit is fenced and rolled back',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'old-key material commits after the fence',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/semanticState/material/oldKeyReferences', value: 1 },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/semanticState/material/oldKeyReferences',
  },
} satisfies CandidateInvariantContract);

export default keystoreWrappingFenceLateCommit;
