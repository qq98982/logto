import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  roles: {
    aster_request: {
      login: true,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_worker: {
      login: true,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_admin: {
      login: true,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_maintainer: {
      login: true,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_control_resolver: {
      login: true,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_key_runtime: {
      login: true,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_migrator: {
      login: true,
      inherit: false,
      bypassRls: false,
      memberOf: [
        'aster_owner',
        'aster_key_control_owner',
        'aster_key_usage_owner',
        'aster_key_lifecycle_owner',
        'aster_reaper_owner',
      ],
      setRoleOwner: true,
      ownerMembershipGrantable: true,
    },
    aster_owner: {
      login: false,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_key_control_owner: {
      login: false,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_key_usage_owner: {
      login: false,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_key_lifecycle_owner: {
      login: false,
      bypassRls: false,
      memberOf: [],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
    aster_reaper_owner: {
      login: false,
      bypassRls: false,
      memberOf: ['pg_signal_backend', 'pg_read_all_stats'],
      setRoleOwner: false,
      ownerMembershipGrantable: false,
    },
  },
};
const negativeProjection = {
  roles: {
    ...positiveProjection.roles,
    aster_request: { ...positiveProjection.roles.aster_request, memberOf: ['aster_owner'] },
  },
};

export const databaseOwnerRoleMembershipBoundary = defineCandidateInvariant({
  id: 'database.owner-role-membership-boundary',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'designed-database-role-catalog-present' },
  perturbation: { kind: 'runtime-admin-maintainer-membership-and-set-role-attempts' },
  expectedPublicOutcome: { soleGrantableOwnerMember: 'aster_migrator', runtimeOwnerSwitches: 0 },
  expectedPersistedOutcome: { ownerRolesLogin: false, ownerRolesBypassRls: false },
  forbiddenOutcome: { runtimeOwnerMembership: true, runtimeOwnerRoleSwitch: true },
  cleanup: { kind: 'rollback-grants-and-drop-ephemeral-logins' },
  sanitizedProjection: {
    fields: [
      'roles.*.login',
      'roles.*.bypassRls',
      'roles.*.memberOf',
      'roles.*.setRoleOwner',
      'roles.*.ownerMembershipGrantable',
    ],
    completeDesignedCatalog: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'only the migrator can become an Aster owner',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'request role inherits an owner role',
    input: {
      variant: 'negative',
      fault: { operation: 'add', path: '/roles/aster_request/memberOf/0', value: 'aster_owner' },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/roles/aster_request/memberOf/0',
  },
} satisfies CandidateInvariantContract);

export default databaseOwnerRoleMembershipBoundary;
