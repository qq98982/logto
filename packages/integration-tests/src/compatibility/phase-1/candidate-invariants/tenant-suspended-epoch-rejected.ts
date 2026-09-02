import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  activation: { mintedEpoch: 7, currentEpoch: 8, accepted: false, errorClass: 'stale-epoch' },
  repositoriesCreated: false,
  mutations: { binding: 0, business: 0 },
};
const negativeProjection = {
  ...positiveProjection,
  activation: { ...positiveProjection.activation, accepted: true },
};

export const tenantSuspendedEpochRejected = defineCandidateInvariant({
  id: 'tenant.suspended-epoch-rejected',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: {
    kind: 'active-tenant-capability-minted-before-suspension',
    mintedEpoch: 7,
  },
  perturbation: {
    kind: 'suspend-and-increment-epoch-before-activation',
    currentEpoch: 8,
  },
  expectedPublicOutcome: positiveProjection.activation,
  expectedPersistedOutcome: {
    repositoriesCreated: false,
    mutations: positiveProjection.mutations,
  },
  forbiddenOutcome: { accepted: true, staleEpochDataAccess: true },
  cleanup: { kind: 'expire-reap-binding-and-restore-status', restoredStatus: 'active' },
  sanitizedProjection: {
    fields: [
      'activation.mintedEpoch',
      'activation.currentEpoch',
      'activation.accepted',
      'activation.errorClass',
      'repositoriesCreated',
      'mutations',
    ],
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'stale epoch activation is denied',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'stale epoch activation is accepted',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/activation/accepted', value: true },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/activation/accepted',
  },
} satisfies CandidateInvariantContract);

export default tenantSuspendedEpochRejected;
