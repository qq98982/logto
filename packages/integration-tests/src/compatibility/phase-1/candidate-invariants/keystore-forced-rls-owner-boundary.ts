import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  policy: { forceRls: true, usingTrue: false },
  binding: { tenantId: 'tenant-a', operationClass: 'key-lifecycle' },
  semanticState: {
    visibleRows: [{ tenantId: 'tenant-a', count: 1 }],
    crossTenantRows: [],
    mutations: [{ tenantId: 'tenant-a', count: 1 }],
    crossTenantMutations: 0,
  },
};
const negativeProjection = {
  ...positiveProjection,
  semanticState: {
    ...positiveProjection.semanticState,
    crossTenantRows: [{ tenantId: 'tenant-b', count: 1 }],
  },
};

export const keystoreForcedRlsOwnerBoundary = defineCandidateInvariant({
  id: 'keystore.forced-rls-owner-boundary',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'two-tenants-with-key-rows-and-forced-rls' },
  perturbation: {
    kind: 'owner-function-and-owner-wide-table-access-attempts',
    boundTenant: 'tenant-a',
  },
  expectedPublicOutcome: { visibleTenant: 'tenant-a', crossTenantRows: 0 },
  expectedPersistedOutcome: positiveProjection.semanticState,
  forbiddenOutcome: { usingTruePolicy: true, ownerWideVisibility: true, crossTenantDml: true },
  cleanup: { kind: 'rollback-key-fixtures', tenants: ['tenant-a', 'tenant-b'] },
  sanitizedProjection: {
    fields: [
      'policy',
      'binding',
      'semanticState.visibleRows',
      'semanticState.crossTenantRows',
      'semanticState.mutations',
      'semanticState.crossTenantMutations',
    ],
    logicalIdentifiersOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'owner path remains capability-bound to one tenant',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'owner path exposes a cross-tenant row',
    input: {
      variant: 'negative',
      fault: {
        operation: 'add',
        path: '/semanticState/crossTenantRows/0',
        value: { tenantId: 'tenant-b', count: 1 },
      },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/semanticState/crossTenantRows/0',
  },
} satisfies CandidateInvariantContract);

export default keystoreForcedRlsOwnerBoundary;
