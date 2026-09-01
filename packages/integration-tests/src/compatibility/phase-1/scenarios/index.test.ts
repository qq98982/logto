/* eslint-disable @typescript-eslint/array-type, @typescript-eslint/ban-types, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-explicit-any, @typescript-eslint/restrict-plus-operands, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, no-await-in-loop, unicorn/consistent-function-scoping, unicorn/no-array-for-each -- Complete source-authority mutation tests deliberately bypass readonly types and verify exact canonical function identities. */
import {
  differentialScenarioIds,
  oracleCommit,
  phase0HarnessCommit,
  type Phase1DifferentialScenario,
} from '../model.js';

import { runAuthorizationPasswordPkceConsent } from './authorization-password-pkce-consent.js';
import { runDiscoveryConfig } from './discovery-config.js';
import {
  assertExactDifferentialScenarioRegistry,
  pendingPhase1DifferentialScenarioRun,
  phase1DifferentialScenarios,
} from './index.js';
import { runTokenAuthorizationCode } from './token-authorization-code.js';
import { runTokenRefreshRotation } from './token-refresh-rotation.js';
import { runUserInfoOpenId } from './userinfo-openid.js';

const expectedFixtures = [
  'none',
  'dataProtocol',
  'dataProtocol',
  'dataProtocol',
  'dataProtocol',
  'fullPhase1',
  'fullPhase1',
  'adminConsole',
  'adminConsole',
  'adminConsole',
  'fullPhase1',
  'fullPhase1',
  'dataProtocol',
  'dataProtocol',
  'dataProtocol',
  'dataProtocol',
  'dataProtocol',
  'consentBoundary',
  'dataProtocol',
  'fullPhase1',
  'dataProtocol',
  'dataProtocol',
] as const;

const implementedRuns = Object.freeze([
  runDiscoveryConfig,
  runAuthorizationPasswordPkceConsent,
  runTokenAuthorizationCode,
  runTokenRefreshRotation,
  runUserInfoOpenId,
] as const);
const expectedRuns = Object.freeze([
  ...implementedRuns,
  ...Array.from(
    { length: differentialScenarioIds.length - implementedRuns.length },
    () => pendingPhase1DifferentialScenarioRun
  ),
]);

type SourceText = `oracle:${string}` | `phase0:${string}`;
const expectedSources: readonly (readonly SourceText[])[] = [
  [
    'phase0:packages/integration-tests/src/compatibility/scenarios/discovery.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/discovery.test.ts',
    'oracle:packages/core/src/oidc/init.ts',
  ],
  [
    'oracle:packages/integration-tests/src/client/index.ts',
    'oracle:packages/integration-tests/src/client/experience/index.ts',
    'oracle:packages/integration-tests/src/api/interaction.ts',
    'oracle:packages/integration-tests/src/tests/api/interaction/consent/happy-path.test.ts',
    'oracle:packages/core/src/routes/interaction/consent/index.ts',
  ],
  [
    'oracle:packages/integration-tests/src/client/index.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
    'phase0:packages/integration-tests/src/compatibility/scenarios/password-code.ts',
  ],
  [
    'oracle:packages/integration-tests/src/tests/api/oidc/refresh-token-grant.test.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
    'oracle:packages/core/src/oidc/grants/refresh-token.ts',
  ],
  [
    'phase0:packages/integration-tests/src/compatibility/target-client.ts',
    'phase0:packages/integration-tests/src/compatibility/scenarios/password-code.ts',
    'oracle:packages/core/src/oidc/init.ts',
    'oracle:packages/core/src/oidc/scope.ts',
  ],
  [
    'oracle:packages/integration-tests/src/api/application.ts',
    'oracle:packages/console/src/pages/Applications/hooks/use-application-data.ts',
    'oracle:packages/core/src/routes/applications/application.ts',
    'oracle:packages/integration-tests/src/tests/console/applications/index.test.ts',
  ],
  [
    'oracle:packages/integration-tests/src/api/admin-user.ts',
    'oracle:packages/console/src/pages/Users/index.tsx',
    'oracle:packages/core/src/routes/admin-user/basics.ts',
    'oracle:packages/integration-tests/src/tests/console/user-management.test.ts',
  ],
  [
    'oracle:packages/integration-tests/src/helpers/admin-tenant.ts',
    'oracle:packages/console/src/App.tsx',
    'oracle:packages/console/src/hooks/use-api.ts',
    'oracle:packages/core/src/oidc/grants/refresh-token.ts',
  ],
  [
    'oracle:packages/console/src/containers/ConsoleContent/hooks.ts',
    'oracle:packages/schemas/src/types/tenant-organization.ts',
    'oracle:packages/core/src/oidc/grants/refresh-token.ts',
    'oracle:packages/core/src/oidc/grants/utils.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/organization-token.test.ts',
  ],
  [
    'oracle:packages/integration-tests/src/helpers/admin-tenant.ts',
    'oracle:packages/console/src/hooks/use-account-api.ts',
    'oracle:packages/console/src/hooks/use-current-user.ts',
    'oracle:packages/core/src/routes/account/index.ts',
  ],
  [
    'oracle:packages/core/src/middleware/koa-cors.ts',
    'oracle:packages/core/src/middleware/koa-cors.test.ts',
    'oracle:packages/console/src/hooks/use-api.ts',
  ],
  [
    'oracle:packages/integration-tests/src/client/index.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/per-client-interaction-cookie.test.ts',
    'oracle:packages/core/src/oidc/init.ts',
  ],
  [
    'oracle:packages/integration-tests/src/client/index.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/wildcard-redirect-uri.test.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/mixed-redirect-uri.test.ts',
  ],
  [
    'oracle:packages/integration-tests/src/tests/api/oidc/discovery.test.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/post-authorization-and-logout.test.ts',
    'oracle:packages/core/src/oidc/init.ts',
  ],
  [
    'oracle:packages/integration-tests/src/client/index.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/get-access-token.test.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
  ],
  [
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
    'oracle:packages/integration-tests/src/client/index.ts',
  ],
  [
    'oracle:packages/integration-tests/src/client/experience/index.ts',
    'oracle:packages/core/src/routes/experience/verification-routes/password-verification.ts',
    'oracle:packages/core/src/routes/experience/classes/verifications/password-verification.ts',
    'oracle:packages/integration-tests/src/tests/api/experience-api/verifications/password-verification.test.ts',
  ],
  [
    'oracle:packages/integration-tests/src/api/interaction.ts',
    'oracle:packages/integration-tests/src/client/index.ts',
    'oracle:packages/integration-tests/src/tests/api/interaction/consent/happy-path.test.ts',
    'oracle:packages/core/src/routes/interaction/consent/index.ts',
  ],
  [
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
    'oracle:packages/core/src/oidc/grants/refresh-token.ts',
  ],
  [
    'oracle:packages/console/src/hooks/use-api.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/get-access-token.test.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/organization-api-resource.test.ts',
    'oracle:packages/core/src/routes/applications/application.ts',
  ],
  [
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
    'oracle:packages/integration-tests/src/client/index.ts',
  ],
  [
    'oracle:packages/integration-tests/src/tests/api/oidc/get-access-token.test.ts',
    'oracle:packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts',
    'oracle:packages/core/src/oidc/grants/refresh-token.ts',
  ],
];

const sourceText = (commit: string, path: string): SourceText =>
  `${commit === phase0HarnessCommit ? 'phase0' : 'oracle'}:${path}`;

const mutateRegistryEntry = (
  index: number,
  update: (copy: any) => void
): readonly Phase1DifferentialScenario[] =>
  phase1DifferentialScenarios.map((scenario, scenarioIndex) => {
    if (index !== scenarioIndex) {
      return scenario;
    }
    const copy = {
      ...scenario,
      sourceEvidence: scenario.sourceEvidence.map((reference) => ({ ...reference })),
      orderedSteps: scenario.orderedSteps.map((step) => ({ ...step, kinds: [...step.kinds] })),
      observationContract: {
        status: [...scenario.observationContract.status],
        mediaType: [...scenario.observationContract.mediaType],
        headers: [...scenario.observationContract.headers],
        cookies: [...scenario.observationContract.cookies],
        redirects: [...scenario.observationContract.redirects],
      },
      normalizablePointers: [...scenario.normalizablePointers],
    };
    update(copy);
    return copy as Phase1DifferentialScenario;
  });

describe('phase 1 differential registry', () => {
  it('rejects sparse array-like accessor proxy extra-key and wrong-prototype registries', () => {
    const valid = phase1DifferentialScenarios;
    const holeAt = (index: number) => {
      const value = [...valid];
      Reflect.deleteProperty(value, String(index));
      return value;
    };
    const extra = [...valid];
    Object.defineProperty(extra, 'extra', { enumerable: true, value: true });
    const symbol = [...valid];
    Object.defineProperty(symbol, Symbol('extra'), { enumerable: true, value: true });
    const accessor = [...valid];
    Object.defineProperty(accessor, '0', { enumerable: true, get: () => valid[0] });
    const wrongPrototype = [...valid];
    Object.setPrototypeOf(wrongPrototype, null);
    const invalid = [
      holeAt(0),
      holeAt(Math.floor(valid.length / 2)),
      holeAt(valid.length - 1),
      { 0: valid[0], length: valid.length, some: Array.prototype.some },
      extra,
      symbol,
      accessor,
      new Proxy([...valid], {
        ownKeys: () => {
          throw new Error('must not escape');
        },
      }),
      new Proxy([...valid], {
        getOwnPropertyDescriptor: () => {
          throw new Error('must not escape');
        },
      }),
      wrongPrototype,
    ];

    expect(() => assertExactDifferentialScenarioRegistry(Object.freeze([...valid]))).not.toThrow();
    for (const registry of invalid) {
      expect(() => assertExactDifferentialScenarioRegistry(registry as never)).toThrow(
        /^Invalid phase 1 differential scenario registry$/u
      );
    }
  });

  it('rejects unsafe root and nested source records before Zod or equality reads them', () => {
    const canonical = phase1DifferentialScenarios[0]!;
    const malformedRecords = <Value extends object>(
      valid: Value,
      accessorKey: keyof Value & string
    ) => {
      const nonEnumerable = { ...valid };
      Object.defineProperty(nonEnumerable, 'injected', { enumerable: false, value: true });
      const symbol = { ...valid };
      Object.defineProperty(symbol, Symbol('injected'), { enumerable: true, value: true });
      const accessor = { ...valid };
      Object.defineProperty(accessor, accessorKey, {
        enumerable: true,
        get: () => valid[accessorKey],
      });
      const wrongPrototype = { ...valid };
      Object.setPrototypeOf(wrongPrototype, null);

      return [
        { ...valid, injected: true },
        nonEnumerable,
        symbol,
        accessor,
        new Proxy({ ...valid }, {}),
        new Proxy(
          { ...valid },
          {
            getOwnPropertyDescriptor: () => {
              throw new Error('must not escape');
            },
          }
        ),
        wrongPrototype,
      ];
    };

    for (const malformed of malformedRecords(canonical, 'id')) {
      expect(() =>
        assertExactDifferentialScenarioRegistry([
          malformed,
          ...phase1DifferentialScenarios.slice(1),
        ] as never)
      ).toThrow(/^Invalid phase 1 differential scenario registry$/u);
    }
    const source = canonical.sourceEvidence[0]!;
    for (const malformed of malformedRecords(source, 'path')) {
      const scenario = {
        ...canonical,
        sourceEvidence: [malformed, ...canonical.sourceEvidence.slice(1)],
      };
      expect(() =>
        assertExactDifferentialScenarioRegistry([
          scenario,
          ...phase1DifferentialScenarios.slice(1),
        ] as never)
      ).toThrow(/^Invalid phase 1 differential scenario registry$/u);
    }
  });

  it('contains exact ordered IDs fixtures and structured source evidence', () => {
    expect(phase1DifferentialScenarios.map(({ id }) => id)).toEqual(differentialScenarioIds);
    expect(phase1DifferentialScenarios.map(({ fixture }) => fixture)).toEqual(expectedFixtures);
    expect(
      phase1DifferentialScenarios.map(({ sourceEvidence }) =>
        sourceEvidence.map(({ commit, path }) => sourceText(commit, path))
      )
    ).toEqual(expectedSources);
  });

  it('declares complete metadata with five exact implementations and seventeen pending runs', async () => {
    for (const [index, scenario] of phase1DifferentialScenarios.entries()) {
      expect(scenario.evidenceKind).toBe('differential');
      expect(scenario.orderedSteps.length).toBeGreaterThan(0);
      expect(scenario.semanticProjectionVersion).toBe(1);
      expect(scenario.cleanup).toBe('fresh-fixture-reverse-cleanup');
      expect(scenario.run).toBe(expectedRuns[index]);
      expect(Object.keys(scenario.observationContract)).toEqual([
        'status',
        'mediaType',
        'headers',
        'cookies',
        'redirects',
      ]);
    }
    expect(
      phase1DifferentialScenarios.slice(0, implementedRuns.length).map(({ run }) => run)
    ).toEqual(implementedRuns);
    const pending = phase1DifferentialScenarios.slice(implementedRuns.length);
    expect(pending).toHaveLength(17);
    for (const scenario of pending) {
      await expect(scenario.run({} as never)).rejects.toThrow(
        /^Phase 1 differential scenario implementation is pending$/u
      );
    }
    expect(Object.isFrozen(pendingPhase1DifferentialScenarioRun)).toBe(true);
  });

  it('rejects every replacement proxy and wrong-index canonical run identity', () => {
    phase1DifferentialScenarios.forEach((scenario, index) => {
      const wrongCanonical =
        index < implementedRuns.length ? pendingPhase1DifferentialScenarioRun : runDiscoveryConfig;
      const replacements = [async () => [], wrongCanonical, new Proxy(scenario.run, {})];

      for (const replacement of replacements) {
        expect(() =>
          assertExactDifferentialScenarioRegistry(
            mutateRegistryEntry(index, (copy) => {
              copy.run = replacement;
            })
          )
        ).toThrow(/^Invalid phase 1 differential scenario registry$/u);
      }
    });
  });

  it('allows additional oracle citations while keeping every Phase 0 citation on the base commit', () => {
    for (const scenario of phase1DifferentialScenarios) {
      for (const reference of scenario.sourceEvidence) {
        expect([oracleCommit, phase0HarnessCommit]).toContain(reference.commit);
        if (reference.path.includes('/compatibility/')) {
          expect(reference.commit).toBe(phase0HarnessCommit);
        }
      }
    }
  });

  it('rejects every ID fixture version cleanup and source-reference mutation', () => {
    phase1DifferentialScenarios.forEach((scenario, index) => {
      const mutations: Array<(copy: any) => void> = [
        (copy) => {
          copy.id = `${copy.id}.mutated`;
        },
        (copy) => {
          copy.fixture = copy.fixture === 'none' ? 'dataProtocol' : 'none';
        },
        (copy) => {
          copy.semanticProjectionVersion = 2;
        },
        (copy) => {
          copy.cleanup = 'none';
        },
      ];

      scenario.sourceEvidence.forEach((_reference, sourceIndex) => {
        mutations.push(
          (copy) => {
            copy.sourceEvidence[sourceIndex].path += '.mutated';
          },
          (copy) => {
            copy.sourceEvidence[sourceIndex].commit =
              copy.sourceEvidence[sourceIndex].commit === oracleCommit
                ? phase0HarnessCommit
                : oracleCommit;
          }
        );
      });

      for (const update of mutations) {
        expect(() =>
          assertExactDifferentialScenarioRegistry(mutateRegistryEntry(index, update))
        ).toThrow(/^Invalid phase 1 differential scenario registry$/u);
      }
    });
  });

  it('rejects empty missing duplicate extra reorder and cross-kind registries', () => {
    const first = phase1DifferentialScenarios[0]!;
    const second = phase1DifferentialScenarios[1]!;
    const crossKind = mutateRegistryEntry(0, (copy) => {
      copy.id = 'tenant.cross-tenant-read-rejected';
      copy.evidenceKind = 'candidate-invariant';
    })[0]!;
    const variants = [
      [],
      phase1DifferentialScenarios.slice(0, -1),
      [...phase1DifferentialScenarios, first],
      [first, first, ...phase1DifferentialScenarios.slice(2)],
      [second, first, ...phase1DifferentialScenarios.slice(2)],
      [crossKind, ...phase1DifferentialScenarios.slice(1)],
    ];

    for (const variant of variants) {
      expect(() => assertExactDifferentialScenarioRegistry(variant)).toThrow(
        /^Invalid phase 1 differential scenario registry$/u
      );
    }
  });

  it('is recursively frozen', () => {
    expect(Object.isFrozen(phase1DifferentialScenarios)).toBe(true);
    for (const scenario of phase1DifferentialScenarios) {
      expect(Object.isFrozen(scenario)).toBe(true);
      expect(Object.isFrozen(scenario.sourceEvidence)).toBe(true);
      expect(Object.isFrozen(scenario.sourceEvidence[0])).toBe(true);
      expect(Object.isFrozen(scenario.orderedSteps)).toBe(true);
    }
  });

  it('leaves a fresh Phase 0 registry identity and content unchanged on import', async () => {
    await import.meta.jest.isolateModulesAsync(async () => {
      const beforeModule = await import('../../scenarios/index.js');
      const before = beforeModule.defaultCompatibilityScenarios;
      const contents = before.map(({ id, run }) => ({ id, run }));

      await import('./index.js');
      const afterModule = await import('../../scenarios/index.js');
      const after = afterModule.defaultCompatibilityScenarios;

      expect(after).toBe(before);
      expect(after.map(({ id, run }) => ({ id, run }))).toEqual(contents);
    });
  });
});

/* eslint-enable @typescript-eslint/array-type, @typescript-eslint/ban-types, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-explicit-any, @typescript-eslint/restrict-plus-operands, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, no-await-in-loop, unicorn/consistent-function-scoping, unicorn/no-array-for-each */
