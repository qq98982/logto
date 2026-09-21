/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/catch-error-name -- Adversarial guard tests deliberately build and mutate malformed descriptor graphs, then retain caught values for redaction assertions across every closed projection entity. */
import { inspect } from 'node:util';

import {
  bindPhase1FixtureSymbols,
  createExpectedPhase1FixtureStateProjection,
  createPhase1FixtureMap,
  createPhase1FixtureStateProjection,
  fixtureSetupCapabilityIds,
  getPhase1FixtureRuntimeId,
  phase1FixtureEntityKinds,
  phase1FixtureRecipeDefinitions,
  phase1FixtureRecipeEntityCounts,
  phase1PasswordMatrixUsers,
  type Phase1FixtureMap,
} from './fixture-map.js';
import type { Phase1Profile } from './profile-types.js';

const profile = {
  fixtures: {
    dataTenant: {
      id: 'default',
      subject: {
        id: 'phase1-user',
        username: 'phase1-user',
        name: 'phase1-user',
        primaryEmail: 'phase1-user@example.com',
        primaryPhone: '+15555550101',
        profile: { address: { formatted: '1 Aster Way', country: 'US' } },
        applicationId: null,
      },
      applications: [
        {
          id: 'phase1-app',
          name: 'Phase 1 Application',
          type: 'SPA',
          isThirdParty: false,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
        },
        {
          id: 'phase1-browser',
          name: 'Phase 1 Consent Client',
          type: 'SPA',
          isThirdParty: true,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
          userConsentScopes: ['profile', 'email', 'address', 'phone'],
          resourceConsentScopes: ['phase1-read-profile'],
        },
      ],
      resource: {
        id: 'phase1-api',
        name: 'Phase 1 API',
        indicator: 'https://api.example.com',
        scopes: [
          {
            id: 'phase1-read-profile',
            name: 'read:profile',
            description: "Read the signed-in user's profile",
          },
        ],
      },
      resourceScopeRole: {
        id: 'phase1-reader',
        name: 'Phase 1 Reader',
        description: 'Grants the Phase 1 API read scope',
        type: 'User',
        isDefault: false,
        scopeIds: ['phase1-read-profile'],
        userIds: ['phase1-user'],
      },
    },
    adminTenant: {
      id: 'admin',
      operator: {
        id: 'phase1-admin',
        username: 'phase1-admin',
        primaryEmail: 'phase1-admin@example.com',
        roles: ['default:admin', 'user'],
        customData: { ossOnboarding: { isOnboardingDone: true } },
      },
      application: {
        id: 'admin-console',
        type: 'SPA',
        oidcClientMetadata: {
          redirectUris: ['http://localhost:3002/console/callback'],
          postLogoutRedirectUris: [],
        },
        customClientMetadata: {},
      },
      resources: [
        { indicator: 'https://default.logto.app/api', scopes: ['all'] },
        { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
        {
          indicator: 'urn:logto:resource:organizations',
          scopes: ['urn:logto:scope:organizations'],
        },
      ],
      tenantOrganization: {
        id: 't-default',
        name: 'Tenant default',
        memberUserIds: ['phase1-admin'],
        scopes: ['write:data', 'read:data'],
        organizationRoles: [
          {
            id: 'admin',
            name: 'admin',
            type: 'User',
            scopeNames: ['write:data', 'read:data'],
            userIds: ['phase1-admin'],
          },
        ],
      },
    },
  },
} as unknown as Pick<Phase1Profile, 'fixtures'>;

const expectedCapabilities = [
  'http.management-api.get./api/sign-in-exp',
  'http.management-api.patch./api/sign-in-exp',
  'http.management-api.post./api/users',
  'http.management-api.patch./api/users/{userId}',
  'http.management-api.patch./api/users/{userId}/is-suspended',
  'http.management-api.delete./api/users/{userId}',
  'http.management-api.post./api/applications',
  'http.management-api.delete./api/applications/{id}',
  'http.management-api.post./api/applications/{applicationId}/user-consent-scopes',
  'http.management-api.post./api/resources',
  'http.management-api.delete./api/resources/{id}',
  'http.management-api.post./api/resources/{resourceId}/scopes',
  'http.management-api.delete./api/resources/{resourceId}/scopes/{scopeId}',
  'http.management-api.post./api/roles',
  'http.management-api.delete./api/roles/{id}',
  'http.management-api.get./api/roles',
  'http.management-api.post./api/roles/{id}/users',
  'http.management-api.get./api/organization-roles',
  'http.management-api.post./api/organizations/{id}/users',
  'http.management-api.post./api/organizations/{id}/users/{userId}/roles',
  'http.management-api.delete./api/organizations/{id}/users/{userId}',
] as const;

const isolation = (prefix: string) => ({
  persistenceId: `${prefix}-persistence`,
  cookieKeyId: `${prefix}-cookie-key`,
  signingKeyId: `${prefix}-signing-key`,
});

const allocation = (
  role: 'data' | 'admin' | 'foreign',
  allocationId: string,
  runtimeId = `${allocationId}-runtime`
) => {
  const entities =
    role === 'admin'
      ? [
          { kind: 'tenant' as const, logicalId: 'admin', runtimeId },
          { kind: 'user' as const, logicalId: 'phase1-admin', runtimeId: `${allocationId}-user` },
          {
            kind: 'application' as const,
            logicalId: 'admin-console',
            runtimeId: `${allocationId}-application`,
          },
          ...Array.from({ length: 3 }, (_, index) => ({
            kind: 'resource' as const,
            logicalId: `admin.resource.${index + 1}`,
            runtimeId: `${allocationId}-resource-${index + 1}`,
          })),
          ...['default:admin', 'user'].map((logicalId, index) => ({
            kind: 'role' as const,
            logicalId,
            runtimeId: `${allocationId}-role-${index + 1}`,
          })),
          {
            kind: 'organization' as const,
            logicalId: 't-default',
            runtimeId: `${allocationId}-organization`,
          },
          {
            kind: 'organization-role' as const,
            logicalId: 'admin',
            runtimeId: `${allocationId}-organization-role`,
          },
        ]
      : role === 'foreign'
        ? [
            { kind: 'tenant' as const, logicalId: 'default', runtimeId },
            {
              kind: 'user' as const,
              logicalId: 'consent.foreign.user-b',
              runtimeId: `${allocationId}-user`,
            },
            {
              kind: 'application' as const,
              logicalId: 'consent.foreign.client-b',
              runtimeId: `${allocationId}-application`,
            },
          ]
        : [
            { kind: 'tenant' as const, logicalId: 'default', runtimeId },
            { kind: 'user' as const, logicalId: 'phase1-user', runtimeId: `${allocationId}-user` },
            ...['phase1-app', 'phase1-browser'].map((logicalId, index) => ({
              kind: 'application' as const,
              logicalId,
              runtimeId: `${allocationId}-application-${index + 1}`,
            })),
            {
              kind: 'resource' as const,
              logicalId: 'phase1-api',
              runtimeId: `${allocationId}-resource`,
            },
            {
              kind: 'scope' as const,
              logicalId: 'phase1-read-profile',
              runtimeId: `${allocationId}-scope`,
            },
            {
              kind: 'role' as const,
              logicalId: 'phase1-reader',
              runtimeId: `${allocationId}-role`,
            },
          ];

  return {
    allocationId,
    role,
    target: role === 'foreign' ? ('foreign' as const) : ('primary' as const),
    isolation: isolation(allocationId),
    entities,
  };
};

const fixtureMap = (recipe: Phase1FixtureMap['recipe'], allocations: unknown[]): unknown => ({
  schemaVersion: 1,
  recipe,
  allocations,
});

const stateProjection = (map: Phase1FixtureMap): unknown =>
  createExpectedPhase1FixtureStateProjection(map, profile);

describe('Phase 1 fixture recipe lock', () => {
  it('keeps the seven exact recipe compositions', () => {
    expect(Object.keys(phase1FixtureRecipeDefinitions)).toEqual([
      'none',
      'dataProtocol',
      'passwordMatrix',
      'adminConsole',
      'fullPhase1',
      'corsBoundary',
      'consentBoundary',
    ]);
    expect(phase1FixtureRecipeDefinitions).toEqual({
      none: { allocationRoles: [], mutableSetup: false },
      dataProtocol: { allocationRoles: ['data'], mutableSetup: true },
      passwordMatrix: { allocationRoles: ['data'], mutableSetup: true },
      adminConsole: { allocationRoles: ['admin'], mutableSetup: true },
      fullPhase1: { allocationRoles: ['data', 'admin'], mutableSetup: true },
      corsBoundary: { allocationRoles: ['data', 'admin', 'foreign'], mutableSetup: true },
      consentBoundary: { allocationRoles: ['data', 'foreign'], mutableSetup: true },
    });
    expect(phase1FixtureRecipeEntityCounts.passwordMatrix).toEqual({
      data: {
        tenant: 1,
        user: 3,
        application: 2,
        resource: 1,
        scope: 1,
        role: 1,
        organization: 0,
        'organization-role': 0,
      },
    });
  });

  it('accepts the exact password matrix users and projects only public account state', () => {
    const data = allocation('data', 'password-matrix');
    const map = createPhase1FixtureMap(
      fixtureMap('passwordMatrix', [
        {
          ...data,
          entities: [
            ...data.entities,
            {
              kind: 'user',
              logicalId: phase1PasswordMatrixUsers.passwordless.logicalId,
              runtimeId: 'runtime-passwordless',
            },
            {
              kind: 'user',
              logicalId: phase1PasswordMatrixUsers.suspended.logicalId,
              runtimeId: 'runtime-suspended',
            },
          ],
        },
      ])
    );
    const projection = createExpectedPhase1FixtureStateProjection(map, profile);

    expect(map.allocations[0]?.entities.filter(({ kind }) => kind === 'user')).toHaveLength(3);
    expect(projection.recipe).toBe('passwordMatrix');
    expect(projection.allocations[0]?.entities.filter(({ kind }) => kind === 'user')).toEqual([
      expect.objectContaining({
        kind: 'user',
        logicalId: profile.fixtures.dataTenant.subject.id,
      }),
      {
        kind: 'user',
        logicalId: phase1PasswordMatrixUsers.passwordless.logicalId,
        snapshot: {
          username: phase1PasswordMatrixUsers.passwordless.username,
          name: null,
          primaryEmail: null,
          primaryPhone: null,
          profile: {},
          applicationLogicalId: null,
          customData: {},
          localAuthenticationPresent: false,
        },
      },
      {
        kind: 'user',
        logicalId: phase1PasswordMatrixUsers.suspended.logicalId,
        snapshot: {
          username: phase1PasswordMatrixUsers.suspended.username,
          name: null,
          primaryEmail: null,
          primaryPhone: null,
          profile: {},
          applicationLogicalId: null,
          customData: {},
          localAuthenticationPresent: true,
        },
      },
    ]);
  });

  it('accepts the CORS boundary allocation shape with a tenant-only foreign target', () => {
    const foreign = allocation('foreign', 'foreign-cors');
    const map = createPhase1FixtureMap(
      fixtureMap('corsBoundary', [
        allocation('data', 'data-cors'),
        allocation('admin', 'admin-cors'),
        { ...foreign, entities: foreign.entities.filter(({ kind }) => kind === 'tenant') },
      ])
    );

    expect(map.allocations.map(({ role }) => role)).toEqual(['data', 'admin', 'foreign']);
    expect(map.allocations[2]?.entities.map(({ kind }) => kind)).toEqual(['tenant']);
    expect(stateProjection(map)).toMatchObject({
      recipe: 'corsBoundary',
      allocations: [
        { role: 'data', target: 'primary' },
        { role: 'admin', target: 'primary' },
        {
          role: 'foreign',
          target: 'foreign',
          entities: [{ kind: 'tenant', logicalId: 'default', snapshot: {} }],
        },
      ],
    });
    expect(() =>
      createPhase1FixtureMap(
        fixtureMap('corsBoundary', [
          allocation('data', 'data-cors-extra'),
          allocation('admin', 'admin-cors-extra'),
          allocation('foreign', 'foreign-cors-extra'),
        ])
      )
    ).toThrow('Invalid Phase 1 fixture map');
  });

  it('keeps the twenty-one setup capabilities separate and immutable', () => {
    expect(fixtureSetupCapabilityIds).toEqual(expectedCapabilities);
    expect(new Set(fixtureSetupCapabilityIds).size).toBe(21);
    expect(Object.isFrozen(fixtureSetupCapabilityIds)).toBe(true);
    expect(
      fixtureSetupCapabilityIds.some((capabilityId) => capabilityId.includes('candidate-invariant'))
    ).toBe(false);
  });
});

describe('createPhase1FixtureMap', () => {
  it('accepts exact recipe allocations and deeply freezes the public map', () => {
    const map = createPhase1FixtureMap(
      fixtureMap('fullPhase1', [
        allocation('data', 'experience-1'),
        allocation('admin', 'console-1'),
      ])
    );

    expect(map.recipe).toBe('fullPhase1');
    expect(map.allocations.map(({ role }) => role)).toEqual(['data', 'admin']);
    expect(Object.isFrozen(map)).toBe(true);
    expect(Object.isFrozen(map.allocations)).toBe(true);
    expect(Object.isFrozen(map.allocations[0]?.entities)).toBe(true);
    expect(JSON.stringify(map)).not.toMatch(/password|clientSecret|token|privateKey/u);
  });

  it('allows equal runtime IDs in unrelated allocations without merging symbols', () => {
    const sharedRuntimeId = 'runtime-equal-by-coincidence';
    const map = createPhase1FixtureMap(
      fixtureMap('fullPhase1', [
        allocation('data', 'experience-1', sharedRuntimeId),
        allocation('admin', 'console-1', sharedRuntimeId),
      ])
    );
    const symbols = bindPhase1FixtureSymbols(map);

    expect(symbols.get('experience-1')?.getLogicalName(sharedRuntimeId)).toBe('tenant.default');
    expect(symbols.get('console-1')?.getLogicalName(sharedRuntimeId)).toBe('tenant.admin');
    expect(symbols.get('experience-1')).not.toBe(symbols.get('console-1'));
  });

  it('looks up runtime IDs only inside the requested allocation', () => {
    const map = createPhase1FixtureMap(
      fixtureMap('fullPhase1', [
        allocation('data', 'experience-1', 'data-runtime'),
        allocation('admin', 'console-1', 'admin-runtime'),
      ])
    );

    expect(getPhase1FixtureRuntimeId(map, 'experience-1', 'tenant', 'default')).toBe(
      'data-runtime'
    );
    expect(() => getPhase1FixtureRuntimeId(map, 'console-1', 'tenant', 'default')).toThrow(
      'Unknown Phase 1 fixture identifier'
    );
  });

  it('looks up equal logical IDs by entity kind without collapsing them', () => {
    const admin = allocation('admin', 'console-1', 'admin-tenant');
    const map = createPhase1FixtureMap(fixtureMap('adminConsole', [admin]));

    expect(getPhase1FixtureRuntimeId(map, 'console-1', 'tenant', 'admin')).toBe('admin-tenant');
    expect(getPhase1FixtureRuntimeId(map, 'console-1', 'organization-role', 'admin')).toBe(
      'console-1-organization-role'
    );
  });

  it('allows cross-kind runtime collisions without inventing an ambiguous symbol', () => {
    const admin = allocation('admin', 'console-1', 'admin');
    const colliding = {
      ...admin,
      entities: admin.entities.map((entity) =>
        entity.kind === 'organization-role' ? { ...entity, runtimeId: 'admin' } : entity
      ),
    };
    const map = createPhase1FixtureMap(fixtureMap('adminConsole', [colliding]));
    const symbols = bindPhase1FixtureSymbols(map).get('console-1');

    expect(getPhase1FixtureRuntimeId(map, 'console-1', 'tenant', 'admin')).toBe('admin');
    expect(getPhase1FixtureRuntimeId(map, 'console-1', 'organization-role', 'admin')).toBe('admin');
    expect(symbols?.getLogicalName('admin')).toBeUndefined();
    expect(symbols?.replace('admin')).toBe('admin');
  });

  it('rejects runtime collisions inside one entity namespace', () => {
    const data = allocation('data', 'data');
    const firstApplicationRuntimeId = data.entities.find(
      ({ kind }) => kind === 'application'
    )?.runtimeId;
    let seenApplication = false;
    const colliding = {
      ...data,
      entities: data.entities.map((entity) => {
        if (entity.kind !== 'application') {
          return entity;
        }
        if (!seenApplication) {
          seenApplication = true;
          return entity;
        }

        return { ...entity, runtimeId: firstApplicationRuntimeId ?? entity.runtimeId };
      }),
    };

    expect(() => createPhase1FixtureMap(fixtureMap('dataProtocol', [colliding]))).toThrow(
      'Invalid Phase 1 fixture map'
    );
  });

  it('allows primary tenant allocations to share persistence but not cookie or signing identities', () => {
    const data = allocation('data', 'experience-1');
    const admin = allocation('admin', 'console-1');

    expect(() =>
      createPhase1FixtureMap(
        fixtureMap('fullPhase1', [
          data,
          {
            ...admin,
            isolation: { ...admin.isolation, persistenceId: data.isolation.persistenceId },
          },
        ])
      )
    ).not.toThrow();
  });

  it.each([
    [
      'wrong recipe allocation order',
      fixtureMap('fullPhase1', [allocation('admin', 'a'), allocation('data', 'd')]),
    ],
    [
      'duplicate allocation identity',
      fixtureMap('fullPhase1', [allocation('data', 'same'), allocation('admin', 'same')]),
    ],
    [
      'shared primary key identities',
      fixtureMap('fullPhase1', [
        allocation('data', 'data'),
        { ...allocation('admin', 'admin'), isolation: isolation('data') },
      ]),
    ],
    [
      'foreign target key sharing',
      fixtureMap('consentBoundary', [
        allocation('data', 'data'),
        { ...allocation('foreign', 'foreign'), isolation: isolation('data') },
      ]),
    ],
    [
      'duplicate logical ID in one allocation',
      fixtureMap('dataProtocol', [
        {
          ...allocation('data', 'data'),
          entities: [
            { kind: 'tenant', logicalId: 'default', runtimeId: 'one' },
            { kind: 'tenant', logicalId: 'default', runtimeId: 'two' },
          ],
        },
      ]),
    ],
    [
      'secret-shaped field',
      {
        ...(fixtureMap('dataProtocol', [allocation('data', 'data')]) as Record<string, unknown>),
        password: 'fixture-secret-value',
      },
    ],
    [
      'token-shaped nested field',
      fixtureMap('dataProtocol', [
        { ...allocation('data', 'data'), accessToken: 'fixture-secret-value' },
      ]),
    ],
  ])('rejects %s', (_name, value) => {
    expect(() => createPhase1FixtureMap(value)).toThrow('Invalid Phase 1 fixture map');
  });

  it('rejects non-closed runtime graphs without invoking them', () => {
    let getterCalls = 0;
    const getter = () => {
      getterCalls += 1;
      return 'fixture-secret-value';
    };
    const withAccessor = fixtureMap('dataProtocol', [allocation('data', 'data')]);
    Object.defineProperty(withAccessor, 'hidden', { enumerable: true, get: getter });
    const sparse = fixtureMap('dataProtocol', [allocation('data', 'data')]) as {
      allocations: unknown[];
    };
    sparse.allocations.length = 2;
    const cyclic = fixtureMap('dataProtocol', [allocation('data', 'data')]) as Record<
      string,
      unknown
    >;
    cyclic.cycle = cyclic;
    const withSymbol = fixtureMap('dataProtocol', [allocation('data', 'data')]) as Record<
      string | symbol,
      unknown
    >;
    withSymbol[Symbol('secret')] = 'fixture-secret-value';

    for (const value of [withAccessor, sparse, cyclic, withSymbol, new Proxy({}, {})]) {
      expect(() => createPhase1FixtureMap(value)).toThrow('Invalid Phase 1 fixture map');
    }
    expect(getterCalls).toBe(0);
  });

  it('never includes rejected raw values in errors or inspection', () => {
    const secret = 'fixture-secret-value-never-report';
    let error: unknown;

    try {
      createPhase1FixtureMap({ secret });
    } catch (caught: unknown) {
      error = caught;
    }

    expect(inspect(error, { depth: null })).not.toContain(secret);
    expect(String(error)).not.toContain(secret);
  });
});

describe('createPhase1FixtureStateProjection', () => {
  const map = createPhase1FixtureMap(
    fixtureMap('fullPhase1', [allocation('data', 'data'), allocation('admin', 'admin')])
  );

  it('emits a deeply frozen logical projection without allocation or runtime identifiers', () => {
    const projection = createPhase1FixtureStateProjection(stateProjection(map), map, profile);

    expect(projection.schemaVersion).toBe(1);
    expect(projection.recipe).toBe('fullPhase1');
    expect(projection.allocations.map(({ role }) => role)).toEqual(['data', 'admin']);
    expect(Object.isFrozen(projection)).toBe(true);
    expect(Object.isFrozen(projection.allocations[0]?.entities)).toBe(true);
    expect(
      projection.allocations[0]?.entities.find(({ kind }) => kind === 'role')?.snapshot
    ).toMatchObject({
      scopeLogicalIds: ['phase1-read-profile'],
      userLogicalIds: ['phase1-user'],
    });
    expect(JSON.stringify(projection)).not.toContain('allocationId');
    expect(JSON.stringify(projection)).not.toContain('runtimeId');
    expect(JSON.stringify(projection)).not.toContain('data-user');
  });

  it('projects the reserved organization resource from organization template scopes', () => {
    const projection = createExpectedPhase1FixtureStateProjection(map, profile);
    const resources = projection.allocations
      .find(({ role }) => role === 'admin')
      ?.entities.filter(({ kind }) => kind === 'resource');

    expect(resources).toEqual([
      {
        kind: 'resource',
        logicalId: 'admin.resource.1',
        snapshot: {
          name: null,
          indicator: 'https://default.logto.app/api',
          scopeNames: ['all'],
        },
      },
      {
        kind: 'resource',
        logicalId: 'admin.resource.2',
        snapshot: {
          name: null,
          indicator: 'https://admin.logto.app/me',
          scopeNames: ['all'],
        },
      },
      {
        kind: 'resource',
        logicalId: 'admin.resource.3',
        snapshot: {
          name: null,
          indicator: 'urn:logto:resource:organizations',
          scopeNames: ['write:data', 'read:data'],
        },
      },
    ]);
  });

  it.each(phase1FixtureEntityKinds)(
    'rejects a wrong logical identity with otherwise-correct %s fields',
    (kind) => {
      const candidate = structuredClone(stateProjection(map)) as {
        allocations: Array<{
          entities: Array<{
            kind: string;
            logicalId: string;
            snapshot: Record<string, unknown>;
          }>;
        }>;
      };
      const entity = candidate.allocations
        .flatMap(({ entities }) => entities)
        .find((entry) => entry.kind === kind);

      expect(entity).toBeDefined();
      entity!.logicalId = `${entity!.logicalId}.wrong`;

      expect(() => createPhase1FixtureStateProjection(candidate, map, profile)).toThrow(
        'Invalid Phase 1 fixture map'
      );
    }
  );

  it.each(phase1FixtureEntityKinds)(
    'rejects a right-ID %s entity with a wrong observable field',
    (kind) => {
      const source = structuredClone(stateProjection(map)) as {
        allocations: Array<{
          entities: Array<{ kind: string; snapshot: Record<string, unknown> }>;
        }>;
      };
      const entity = source.allocations
        .flatMap(({ entities }) => entities)
        .find((entry) => entry.kind === kind);
      expect(entity).toBeDefined();
      const field = Object.keys(entity!.snapshot)[0];

      if (field === undefined) {
        entity!.snapshot.unexpected = 'wrong';
      } else {
        const value = entity!.snapshot[field];
        entity!.snapshot[field] =
          typeof value === 'string'
            ? `${value}.wrong`
            : typeof value === 'boolean'
              ? !value
              : value === null
                ? 'wrong'
                : Array.isArray(value)
                  ? [...Array.from(value as readonly unknown[]), 'wrong']
                  : { unexpected: 'wrong' };
      }

      expect(() => createPhase1FixtureStateProjection(source, map, profile)).toThrow(
        'Invalid Phase 1 fixture map'
      );
    }
  );

  it('projects two independently allocated targets to the same semantic state', () => {
    const independentlyAllocated = createPhase1FixtureMap(
      fixtureMap('fullPhase1', [
        allocation('data', 'candidate-data'),
        allocation('admin', 'candidate-admin'),
      ])
    );

    expect(stateProjection(independentlyAllocated)).toEqual(stateProjection(map));
  });

  it('rejects missing, extra, reordered, and cross-allocation entities', () => {
    const source = structuredClone(stateProjection(map)) as {
      allocations: Array<{ entities: unknown[] }>;
    };
    const variants = [
      (() => {
        const candidate = structuredClone(source);
        candidate.allocations[0]?.entities.pop();
        return candidate;
      })(),
      (() => {
        const candidate = structuredClone(source);
        candidate.allocations[0]?.entities.push(
          structuredClone(candidate.allocations[0].entities[0])
        );
        return candidate;
      })(),
      (() => {
        const candidate = structuredClone(source);
        candidate.allocations[0]?.entities.reverse();
        return candidate;
      })(),
      (() => {
        const candidate = structuredClone(source);
        const first = candidate.allocations[0]?.entities[0];
        const second = candidate.allocations[1]?.entities[0];
        candidate.allocations[0]!.entities[0] = second;
        candidate.allocations[1]!.entities[0] = first;
        return candidate;
      })(),
    ];

    for (const candidate of variants) {
      expect(() => createPhase1FixtureStateProjection(candidate, map, profile)).toThrow(
        'Invalid Phase 1 fixture map'
      );
    }
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/catch-error-name */
