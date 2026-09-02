import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  capability: { tenantId: 'tenant-a', operationClass: 'provision' },
  mutations: [
    { tenantId: 'tenant-a', operationClass: 'provision' },
    { tenantId: null, operationClass: 'provision' },
  ],
  denials: [{ reasonClass: 'tenant-mismatch' }, { reasonClass: 'operation-class-mismatch' }],
};
const negativeProjection = {
  ...positiveProjection,
  mutations: [
    { tenantId: 'tenant-a', operationClass: 'provision' },
    { tenantId: 'tenant-b', operationClass: 'provision' },
  ],
};

export const tenantAdminOperationBinding = defineCandidateInvariant({
  id: 'tenant.admin-operation-binding',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: {
    kind: 'two-tenants-and-one-admin-operation-capability',
    tenants: ['tenant-a', 'tenant-b'],
  },
  perturbation: {
    kind: 'attempt-cross-tenant-and-cross-class-admin-operations',
    capabilityTenant: 'tenant-a',
    capabilityClass: 'provision',
  },
  expectedPublicOutcome: {
    allowedTenant: 'tenant-a',
    allowedOperationClass: 'provision',
    denialCount: 2,
  },
  expectedPersistedOutcome: { mutationTargets: ['tenant-a'], mutationClasses: ['provision'] },
  forbiddenOutcome: { tenantBMutation: true, operationClassEscalation: true },
  cleanup: { kind: 'rollback-and-delete-admin-fixtures', tenants: ['tenant-a', 'tenant-b'] },
  sanitizedProjection: {
    fields: ['capability', 'mutations', 'denials'],
    logicalIdentifiersOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'only the capability tenant and operation class mutate',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'a mutation target crosses the tenant boundary',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/mutations/1/tenantId', value: 'tenant-b' },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/mutations/1/tenantId',
  },
} satisfies CandidateInvariantContract);

export default tenantAdminOperationBinding;
