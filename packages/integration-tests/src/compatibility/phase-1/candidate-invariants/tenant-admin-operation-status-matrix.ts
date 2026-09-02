import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const matrix = {
  inactive: { provision: true, keyLifecycle: false, rewrap: true, keyAudit: true },
  active: { provision: false, keyLifecycle: true, rewrap: true, keyAudit: true },
  suspended: { provision: false, keyLifecycle: true, rewrap: true, keyAudit: true },
  deleted: { provision: false, keyLifecycle: false, rewrap: false, keyAudit: false },
  epochChanged: { provision: false, keyLifecycle: false, rewrap: false, keyAudit: false },
};
const positiveProjection = { matrix, invalidPairRowDeltas: 0, functionNarrowing: 'enforced' };
const negativeProjection = {
  ...positiveProjection,
  matrix: { ...matrix, deleted: { ...matrix.deleted, provision: true } },
};

export const tenantAdminOperationStatusMatrix = defineCandidateInvariant({
  id: 'tenant.admin-operation-status-matrix',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: {
    kind: 'closed-admin-operation-status-fixtures',
    statuses: ['inactive', 'active', 'suspended', 'deleted'],
    operationClasses: ['provision', 'key-lifecycle', 'rewrap', 'key-audit'],
  },
  perturbation: { kind: 'exercise-all-status-class-pairs-and-epoch-change' },
  expectedPublicOutcome: { matrix, functionNarrowing: 'enforced' },
  expectedPersistedOutcome: { invalidPairRowDeltas: 0 },
  forbiddenOutcome: { broadenedPair: true, invalidPairDml: true },
  cleanup: { kind: 'restore-status-and-remove-ephemeral-keys' },
  sanitizedProjection: { fields: ['matrix', 'invalidPairRowDeltas', 'functionNarrowing'] },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'only the pinned status and operation pairs are allowed',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'deleted tenant provisioning is broadened',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/matrix/deleted/provision', value: true },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/matrix/deleted/provision',
  },
} satisfies CandidateInvariantContract);

export default tenantAdminOperationStatusMatrix;
