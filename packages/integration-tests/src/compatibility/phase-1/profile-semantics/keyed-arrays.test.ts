/* eslint-disable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/consistent-type-assertions -- The keyed-array matrix deliberately mutates descriptors, keys, and registry projections per case. */
import type { Phase1Profile, Phase1ProfileSemanticContext } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

import { assertKeyedArraySemantics } from './keyed-arrays.js';

const expectSemanticFailure = (operation: () => void, pointer: string, rule: string) => {
  try {
    operation();
    throw new Error('Expected semantic validation to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 semantics',
      stage: 'semantic',
      pointers: [pointer],
      rules: [rule],
    });
  }
};

const keyedProfile = () =>
  ({
    uiAssetContracts: [{ application: 'console' }, { application: 'demo-app' }],
    fixtures: {
      dataTenant: {
        applications: [{ id: 'app-a' }, { id: 'app-b' }],
        resource: { scopes: [{ id: 'scope-a' }, { id: 'scope-b' }] },
      },
      adminTenant: {
        tenantOrganization: { organizationRoles: [{ id: 'role-a' }, { id: 'role-b' }] },
      },
    },
    interactionOperations: [{ id: 'operation-a' }, { id: 'operation-b' }],
    browserFlows: [{ id: 'flow-a' }, { id: 'flow-b' }],
    browserExecutionGroups: [{ id: 'group-a' }, { id: 'group-b' }],
    conformance: {
      staticClients: [{ id: 'client-a' }, { id: 'client-b' }],
      plans: [{ testPlanName: 'plan-a' }, { testPlanName: 'plan-b' }],
    },
    differentialScenarios: ['difference-a', 'difference-b'],
    candidateInvariantScenarios: ['invariant-a', 'invariant-b'],
  }) as unknown as Phase1Profile;

const semanticContext = () =>
  ({
    baselineCapabilityIds: new Set<string>(),
    differentialRegistryIds: ['difference-a', 'difference-b'],
    candidateInvariantRegistryIds: ['invariant-a', 'invariant-b'],
  }) satisfies Phase1ProfileSemanticContext;

const keyedArrayMutations = [
  {
    name: 'ui asset application',
    pointer: '/uiAssetContracts/1/application',
    mutate: (profile: Phase1Profile) => {
      (profile.uiAssetContracts as unknown as Array<{ application: string }>)[1] = {
        application: 'console',
      };
    },
  },
  {
    name: 'application id',
    pointer: '/fixtures/dataTenant/applications/1/id',
    mutate: (profile: Phase1Profile) => {
      (profile.fixtures.dataTenant.applications as unknown as Array<{ id: string }>)[1] = {
        id: 'app-a',
      };
    },
  },
  {
    name: 'resource scope id',
    pointer: '/fixtures/dataTenant/resource/scopes/1/id',
    mutate: (profile: Phase1Profile) => {
      (profile.fixtures.dataTenant.resource.scopes as unknown as Array<{ id: string }>)[1] = {
        id: 'scope-a',
      } as Phase1Profile['fixtures']['dataTenant']['resource']['scopes'][number];
    },
  },
  {
    name: 'organization role id',
    pointer: '/fixtures/adminTenant/tenantOrganization/organizationRoles/1/id',
    mutate: (profile: Phase1Profile) => {
      (
        profile.fixtures.adminTenant.tenantOrganization.organizationRoles as unknown as Array<{
          id: string;
        }>
      )[1] = { id: 'role-a' };
    },
  },
  {
    name: 'interaction operation id',
    pointer: '/interactionOperations/1/id',
    mutate: (profile: Phase1Profile) => {
      (profile.interactionOperations as unknown as Array<{ id: string }>)[1] = {
        id: 'operation-a',
      };
    },
  },
  {
    name: 'browser flow id',
    pointer: '/browserFlows/1/id',
    mutate: (profile: Phase1Profile) => {
      (profile.browserFlows as unknown as Array<{ id: string }>)[1] = { id: 'flow-a' };
    },
  },
  {
    name: 'browser group id',
    pointer: '/browserExecutionGroups/1/id',
    mutate: (profile: Phase1Profile) => {
      (profile.browserExecutionGroups as unknown as Array<{ id: string }>)[1] = {
        id: 'group-a',
      };
    },
  },
  {
    name: 'conformance client id',
    pointer: '/conformance/staticClients/1/id',
    mutate: (profile: Phase1Profile) => {
      (profile.conformance.staticClients as unknown as Array<{ id: string }>)[1] = {
        id: 'client-a',
      };
    },
  },
  {
    name: 'conformance plan name',
    pointer: '/conformance/plans/1/testPlanName',
    mutate: (profile: Phase1Profile) => {
      (profile.conformance.plans as unknown as Array<{ testPlanName: string }>)[1] = {
        testPlanName: 'plan-a',
      };
    },
  },
] as const;

describe('Phase 1 keyed-array semantics', () => {
  it('accepts unique keyed arrays and exact registry sets', () => {
    expect(() => assertKeyedArraySemantics(keyedProfile(), semanticContext())).not.toThrow();
  });

  it.each(keyedArrayMutations)('rejects duplicate $name at its second pointer', (mutation) => {
    const profile = keyedProfile();
    mutation.mutate(profile);

    expectSemanticFailure(
      () => assertKeyedArraySemantics(profile, semanticContext()),
      mutation.pointer,
      'unique-key'
    );
  });

  it('rejects a profile differential scenario absent from the registry', () => {
    const context = semanticContext();
    context.differentialRegistryIds = ['difference-a'];

    expectSemanticFailure(
      () => assertKeyedArraySemantics(keyedProfile(), context),
      '/differentialScenarios/1',
      'registry-exact-set'
    );
  });

  it('rejects a registry differential scenario absent from the profile', () => {
    const context = semanticContext();
    context.differentialRegistryIds = ['difference-a', 'difference-b', 'difference-c'];

    expectSemanticFailure(
      () => assertKeyedArraySemantics(keyedProfile(), context),
      '/differentialScenarios',
      'registry-exact-set'
    );
  });

  it('rejects a duplicate profile differential scenario at its second pointer', () => {
    const profile = keyedProfile();
    (profile.differentialScenarios as string[])[1] = 'difference-a';

    expectSemanticFailure(
      () => assertKeyedArraySemantics(profile, semanticContext()),
      '/differentialScenarios/1',
      'profile-unique-id'
    );
  });

  it('rejects a candidate invariant profile entry absent from the registry', () => {
    const context = semanticContext();
    context.candidateInvariantRegistryIds = ['invariant-a'];

    expectSemanticFailure(
      () => assertKeyedArraySemantics(keyedProfile(), context),
      '/candidateInvariantScenarios/1',
      'registry-exact-set'
    );
  });

  it('rejects a duplicate profile candidate invariant at its second pointer', () => {
    const profile = keyedProfile();
    (profile.candidateInvariantScenarios as string[])[1] = 'invariant-a';

    expectSemanticFailure(
      () => assertKeyedArraySemantics(profile, semanticContext()),
      '/candidateInvariantScenarios/1',
      'profile-unique-id'
    );
  });

  it('rejects a candidate registry entry absent from the profile', () => {
    const context = semanticContext();
    context.candidateInvariantRegistryIds = ['invariant-a', 'invariant-b', 'invariant-c'];

    expectSemanticFailure(
      () => assertKeyedArraySemantics(keyedProfile(), context),
      '/candidateInvariantScenarios',
      'registry-exact-set'
    );
  });

  it('rejects a reordered candidate registry at the first displaced pointer', () => {
    const context = semanticContext();
    context.candidateInvariantRegistryIds = ['invariant-b', 'invariant-a'];

    expectSemanticFailure(
      () => assertKeyedArraySemantics(keyedProfile(), context),
      '/candidateInvariantScenarios/0',
      'registry-exact-order'
    );
  });

  it.each(['oracle', 'candidate', 'target', 'compare', 'differences', 'oracleComparison'])(
    'rejects the forbidden candidate-invariant %s structure',
    (field) => {
      const context = semanticContext();
      context.candidateInvariantRegistryIds = [
        { id: 'invariant-a', [field]: field === 'target' ? 'oracle' : true },
        { id: 'invariant-b' },
      ] as unknown as string[];

      expectSemanticFailure(
        () => assertKeyedArraySemantics(keyedProfile(), context),
        `/candidateInvariantScenarios/0/${field}`,
        'candidate-invariant-no-oracle'
      );
    }
  );

  it('rejects candidate registry proxies and accessors before reading IDs', () => {
    const variants = [
      new Proxy({ id: 'invariant-a' }, {}),
      Object.defineProperty({}, 'id', {
        configurable: true,
        enumerable: true,
        get: () => 'invariant-a',
      }),
    ];

    for (const entry of variants) {
      const context = semanticContext();
      context.candidateInvariantRegistryIds = [entry, { id: 'invariant-b' }] as unknown as string[];
      expectSemanticFailure(
        () => assertKeyedArraySemantics(keyedProfile(), context),
        '/candidateInvariantScenarios/0',
        'registry-entry'
      );
    }
  });
});

/* eslint-enable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/consistent-type-assertions */
