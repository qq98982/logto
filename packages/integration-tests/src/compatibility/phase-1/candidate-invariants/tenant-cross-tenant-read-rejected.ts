import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  outcome: {
    boundTenant: 'tenant-a',
    visibleSentinels: ['sentinel-a'],
    crossTenantRows: [],
  },
  mutations: { tenantA: 0, tenantB: 0 },
};
const negativeProjection = {
  ...positiveProjection,
  outcome: { ...positiveProjection.outcome, crossTenantRows: [{ label: 'sentinel-b' }] },
};

export const tenantCrossTenantReadRejected = defineCandidateInvariant({
  id: 'tenant.cross-tenant-read-rejected',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: {
    kind: 'two-active-tenants-with-distinct-sentinels',
    tenants: ['tenant-a', 'tenant-b'],
  },
  perturbation: {
    kind: 'caller-supplied-cross-tenant-relationship',
    boundTenant: 'tenant-a',
    relationshipTenant: 'tenant-b',
  },
  expectedPublicOutcome: positiveProjection.outcome,
  expectedPersistedOutcome: positiveProjection.mutations,
  forbiddenOutcome: { crossTenantRowsPresent: true, mutationCountAboveZero: true },
  cleanup: { kind: 'rollback-fixture-transactions', tenants: ['tenant-a', 'tenant-b'] },
  sanitizedProjection: {
    fields: [
      'outcome.boundTenant',
      'outcome.visibleSentinels',
      'outcome.crossTenantRows',
      'mutations',
    ],
    logicalIdentifiersOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'only the bound tenant sentinel is visible',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'a foreign sentinel row is disclosed',
    input: {
      variant: 'negative',
      fault: {
        operation: 'add',
        path: '/outcome/crossTenantRows/0',
        value: { label: 'sentinel-b' },
      },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/outcome/crossTenantRows/0',
  },
} satisfies CandidateInvariantContract);

export default tenantCrossTenantReadRejected;
