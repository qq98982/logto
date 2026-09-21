import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  availability: { tokenSigning: true, cookieSealing: true, cookieVerification: true },
  semanticState: {
    changedColumns: ['envelopeMaterial', 'referenceLedger', 'lastSignedAt', 'lastSealedAt'],
    forbiddenColumnDeltas: [],
  },
};
const negativeProjection = {
  ...positiveProjection,
  availability: { ...positiveProjection.availability, tokenSigning: false },
};

export const keystoreSignSealDuringRewrap = defineCandidateInvariant({
  id: 'keystore.sign-seal-during-rewrap',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'active-signing-and-cookie-keys-serving-traffic' },
  perturbation: { kind: 'rewrap-envelope-material-under-write-fence' },
  expectedPublicOutcome: positiveProjection.availability,
  expectedPersistedOutcome: positiveProjection.semanticState,
  forbiddenOutcome: { protocolOutage: true, lifecycleChange: true, metadataCorruption: true },
  cleanup: { kind: 'finish-or-rollback-rewrap' },
  sanitizedProjection: {
    fields: [
      'availability.tokenSigning',
      'availability.cookieSealing',
      'availability.cookieVerification',
      'semanticState.changedColumns',
      'semanticState.forbiddenColumnDeltas',
    ],
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'token signing and cookie sealing remain available during rewrap',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'token signing becomes unavailable during rewrap',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/availability/tokenSigning', value: false },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/availability/tokenSigning',
  },
} satisfies CandidateInvariantContract);

export default keystoreSignSealDuringRewrap;
