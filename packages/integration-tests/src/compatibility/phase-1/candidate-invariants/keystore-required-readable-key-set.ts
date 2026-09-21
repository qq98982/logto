import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  replica: {
    generation: 2,
    requiredReadable: ['<key.active>', '<key.old-referenced>', '<key.rollback-retained>'],
    locallyLoaded: [
      '<key.active>',
      '<key.old-referenced>',
      '<key.rollback-retained>',
      '<key.staged-optional>',
      '<key.removable-optional>',
    ],
    live: [
      '<key.active>',
      '<key.old-referenced>',
      '<key.rollback-retained>',
      '<key.staged-optional>',
      '<key.removable-optional>',
    ],
    missingRequired: [],
    optionalAccepted: ['<key.staged-optional>', '<key.removable-optional>'],
    negativeCategories: {
      unknown: { ids: ['<key.unknown>'], accepted: false },
      tombstoned: { ids: ['<key.tombstoned>'], accepted: false },
      nonLive: { ids: ['<key.non-live>'], accepted: false },
    },
    readiness: 'ready',
  },
};
const negativeProjection = {
  replica: { ...positiveProjection.replica, missingRequired: ['<key.rollback-retained>'] },
};

export const keystoreRequiredReadableKeySet = defineCandidateInvariant({
  id: 'keystore.required-readable-key-set',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'active-referenced-retained-staged-and-removable-key-fixtures' },
  perturbation: { kind: 'exercise-missing-extra-unknown-tombstoned-and-non-live-loaded-sets' },
  expectedPublicOutcome: {
    readiness: 'ready',
    missingRequired: [],
    negativeCategoriesRejected: true,
  },
  expectedPersistedOutcome: { requiredSubsetLocal: true, localSubsetLive: true },
  forbiddenOutcome: {
    missingRequiredAccepted: true,
    unknownAccepted: true,
    tombstonedAccepted: true,
    nonLiveAccepted: true,
  },
  cleanup: { kind: 'clear-key-fixtures-and-writer-leases' },
  sanitizedProjection: {
    fields: [
      'replica.generation',
      'replica.requiredReadable',
      'replica.locallyLoaded',
      'replica.live',
      'replica.missingRequired',
      'replica.optionalAccepted',
      'replica.negativeCategories',
      'replica.readiness',
    ],
    logicalKeyIdsOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'required readable set is contained in the loaded live set',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'one required readable key is missing',
    input: {
      variant: 'negative',
      fault: {
        operation: 'add',
        path: '/replica/missingRequired/0',
        value: '<key.rollback-retained>',
      },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/replica/missingRequired/0',
  },
} satisfies CandidateInvariantContract);

export default keystoreRequiredReadableKeySet;
