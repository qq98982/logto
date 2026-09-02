import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  semanticState: {
    keyMetadata: {
      activeGeneration: '<generation.1>',
      lifecycle: 'active',
      tenant: 'tenant-a',
      materialRelationship: 'unchanged',
      publicFingerprint: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    },
    before: {
      activeGeneration: '<generation.1>',
      lifecycle: 'active',
      tenant: 'tenant-a',
      materialRelationship: 'unchanged',
      publicFingerprint: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      lastSignedAt: 'baseline',
      lastSealedAt: 'baseline',
    },
    after: {
      activeGeneration: '<generation.1>',
      lifecycle: 'active',
      tenant: 'tenant-a',
      materialRelationship: 'unchanged',
      publicFingerprint: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      lastSignedAt: 'advanced-by-database',
      lastSealedAt: 'advanced-by-database',
    },
    allowedColumnDeltas: ['lastSignedAt', 'lastSealedAt'],
    deniedOperations: [
      'caller-time',
      'lifecycle-change',
      'generation-change',
      'tenant-change',
      'material-change',
      'public-metadata-change',
    ],
  },
};
const negativeProjection = {
  semanticState: {
    ...positiveProjection.semanticState,
    keyMetadata: {
      ...positiveProjection.semanticState.keyMetadata,
      activeGeneration: '<generation.2>',
    },
  },
};

export const keystoreMetadataDmlBoundary = defineCandidateInvariant({
  id: 'keystore.metadata-dml-boundary',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'active-signing-and-cookie-usage-functions' },
  perturbation: { kind: 'direct-and-forged-metadata-dml-attempts' },
  expectedPublicOutcome: {
    allowedUpdates: ['lastSignedAt', 'lastSealedAt'],
    databaseTimeOnly: true,
  },
  expectedPersistedOutcome: positiveProjection.semanticState,
  forbiddenOutcome: { callerTimeAccepted: true, lifecycleOrRelationshipMutation: true },
  cleanup: { kind: 'rollback-metadata-dml-attempts' },
  sanitizedProjection: {
    fields: [
      'semanticState.keyMetadata',
      'semanticState.before',
      'semanticState.after',
      'semanticState.allowedColumnDeltas',
      'semanticState.deniedOperations',
    ],
    timestampValuesCategorized: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'only database-timed last-use metadata advances',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'active key generation changes through runtime metadata DML',
    input: {
      variant: 'negative',
      fault: {
        operation: 'replace',
        path: '/semanticState/keyMetadata/activeGeneration',
        value: '<generation.2>',
      },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/semanticState/keyMetadata/activeGeneration',
  },
} satisfies CandidateInvariantContract);

export default keystoreMetadataDmlBoundary;
