/* eslint-disable @silverhand/fp/no-mutation -- Dependency replacement is the observable coordinator wiring mutation under test. */
import {
  assertPhase1ProfileSemantics,
  createPhase1ProfileValidationCoordinator,
  type Phase1ProfileValidationDependencies,
} from './profile-semantics.js';
import type { Phase1Profile, Phase1ProfileSemanticContext } from './profile-types.js';
import { Phase1ProfileValidationError } from './profile.js';

const coordinatorProfile = (mutation: string) =>
  ({ coordinatorMutation: mutation }) as unknown as Phase1Profile;

const coordinatorContext = {
  baselineCapabilityIds: new Set(),
  differentialRegistryIds: [],
  candidateInvariantRegistryIds: [],
} as const satisfies Phase1ProfileSemanticContext;

const semanticBranches = [
  {
    dependency: 'assertNativeSurface',
    pointer: '/coordinator/native-surface',
    rule: 'coordinator-native-surface',
  },
  { dependency: 'assertKeyedArrays', pointer: '/coordinator/keyed', rule: 'coordinator-keyed' },
  { dependency: 'assertFixtures', pointer: '/coordinator/fixtures', rule: 'coordinator-fixtures' },
  {
    dependency: 'assertOperations',
    pointer: '/coordinator/operations',
    rule: 'coordinator-operations',
  },
  { dependency: 'assertBrowser', pointer: '/coordinator/browser', rule: 'coordinator-browser' },
  {
    dependency: 'assertConformance',
    pointer: '/coordinator/conformance',
    rule: 'coordinator-conformance',
  },
] as const;

const acceptSyntheticCoordinatorInput = (): void => {
  // Non-target dependencies deliberately accept the compact coordinator fixture.
};

const coordinatorDependencies = (): Phase1ProfileValidationDependencies => ({
  assertNativeSurface: acceptSyntheticCoordinatorInput,
  assertKeyedArrays: acceptSyntheticCoordinatorInput,
  assertFixtures: acceptSyntheticCoordinatorInput,
  assertOperations: acceptSyntheticCoordinatorInput,
  assertBrowser: acceptSyntheticCoordinatorInput,
  assertConformance: acceptSyntheticCoordinatorInput,
  verifyProvenance: async () => ({
    kind: 'review-candidate',
    harnessCommit: 'a'.repeat(40),
    publishable: false,
  }),
});

describe('Phase 1 semantic validator boundary', () => {
  it('reports a static exact pointer without exposing the duplicate key value', () => {
    const privateSentinel = 'private-duplicate-sentinel';
    const profile = {
      uiAssetContracts: [{ application: privateSentinel }, { application: privateSentinel }],
      fixtures: {
        dataTenant: { applications: [], resource: { scopes: [] } },
        adminTenant: { tenantOrganization: { organizationRoles: [] } },
      },
      interactionOperations: [],
      browserFlows: [],
      browserExecutionGroups: [],
      conformance: { staticClients: [], plans: [] },
      differentialScenarios: [],
      candidateInvariantScenarios: [],
    } as unknown as Phase1Profile;
    const context: Phase1ProfileSemanticContext = {
      baselineCapabilityIds: new Set(),
      differentialRegistryIds: [],
      candidateInvariantRegistryIds: [],
    };

    try {
      assertPhase1ProfileSemantics(profile, context);
      throw new Error('Expected semantic validation to fail');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Phase1ProfileValidationError);
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 semantics',
        stage: 'semantic',
        pointers: ['/uiAssetContracts/1/application'],
        rules: ['unique-key'],
      });
      expect(String(error)).not.toContain(privateSentinel);
      expect(error).not.toHaveProperty('cause');
    }
  });

  it.each(semanticBranches)(
    'wires the $dependency aggregate dependency to its exact semantic error',
    ({ dependency, pointer, rule }) => {
      const dependencies = coordinatorDependencies();
      dependencies[dependency] = (profile: Phase1Profile) => {
        if ((profile as unknown as { coordinatorMutation: string }).coordinatorMutation === rule) {
          throw new Phase1ProfileValidationError('semantic', [pointer], [rule]);
        }
      };
      const coordinator = createPhase1ProfileValidationCoordinator(dependencies);

      try {
        coordinator.assertSemantics(coordinatorProfile(rule), coordinatorContext);
        throw new Error('Expected coordinator semantic validation to fail');
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(Phase1ProfileValidationError);
        expect(error).toMatchObject({
          stage: 'semantic',
          pointers: [pointer],
          rules: [rule],
        });
      }
    }
  );

  it('wires the async provenance aggregate dependency to its exact provenance error', async () => {
    const dependencies = coordinatorDependencies();
    dependencies.verifyProvenance = async () => {
      throw new Phase1ProfileValidationError(
        'provenance',
        ['/coordinator/provenance'],
        ['coordinator-provenance']
      );
    };
    const coordinator = createPhase1ProfileValidationCoordinator(dependencies);

    await expect(
      coordinator.verifyProvenance(
        coordinatorProfile('coordinator-provenance'),
        {} as Parameters<typeof coordinator.verifyProvenance>[1]
      )
    ).rejects.toMatchObject({
      stage: 'provenance',
      pointers: ['/coordinator/provenance'],
      rules: ['coordinator-provenance'],
    });
  });
});

/* eslint-enable @silverhand/fp/no-mutation */
