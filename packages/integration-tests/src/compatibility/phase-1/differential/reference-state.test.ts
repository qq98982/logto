/* eslint-disable max-lines -- The focused reference-state contract matrix stays in one test module. */
import { SymbolTable } from '../../symbol-table.js';
import {
  createPhase1FixtureMap,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  type Phase1FixtureSymbolTables,
} from '../fixture-map.js';
import { createProvisionedPhase1Fixture } from '../fixtures.js';
import { asterNativeSurfaceContract } from '../native-surface.js';
import type { Phase1Profile } from '../profile-types.js';

import {
  createReferenceScenarioStateProjector,
  parseReferenceStateDriverSnapshot,
  readReferenceStateDriver,
  type ReferenceStateDriverSnapshot,
} from './reference-state.js';

const profile = {
  schemaVersion: 2,
  asterNativeSurface: structuredClone(asterNativeSurfaceContract),
  consoleAuthentication: {
    applicationId: 'admin-console',
    effectiveScopes: [
      'openid',
      'offline_access',
      'profile',
      'email',
      'phone',
      'identities',
      'custom_data',
      'urn:logto:scope:organizations',
      'urn:logto:scope:organization_roles',
      'all',
    ],
    effectiveResources: [
      'https://default.logto.app/api',
      'https://admin.logto.app/me',
      'urn:logto:resource:organizations',
    ],
  },
  fixtures: {
    dataTenant: {
      id: 'default',
      subject: { id: 'phase1-user' },
      applications: [
        { id: 'phase1-app', isThirdParty: false },
        { id: 'phase1-browser', isThirdParty: true, userConsentScopes: ['profile'] },
      ],
      resource: {
        id: 'phase1-api',
        name: 'Phase 1 API',
        indicator: 'https://phase1.example.test/api',
        scopes: [{ id: 'phase1-read-profile', name: 'read:profile' }],
      },
      resourceScopeRole: { id: 'phase1-role' },
    },
    adminTenant: {
      id: 'admin',
      operator: { id: 'phase1-admin' },
      application: { id: 'admin-console' },
      resources: [
        { indicator: 'https://default.logto.app/api', scopes: ['all'] },
        { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
        {
          indicator: 'urn:logto:resource:organizations',
          scopes: ['urn:logto:scope:organizations', 'urn:logto:scope:organization_roles'],
        },
      ],
    },
  },
} as unknown as Phase1Profile;

const fixture = createProvisionedPhase1Fixture({
  public: createPhase1FixtureMap({
    schemaVersion: 1,
    recipe: 'dataProtocol',
    allocations: [
      {
        allocationId: 'data-allocation',
        role: 'data',
        target: 'primary',
        isolation: {
          persistenceId: 'data-persistence',
          cookieKeyId: 'data-cookie',
          signingKeyId: 'data-signing',
        },
        entities: [
          { kind: 'tenant', logicalId: 'default', runtimeId: 'default' },
          { kind: 'user', logicalId: 'phase1-user', runtimeId: 'runtime-user' },
          { kind: 'application', logicalId: 'phase1-app', runtimeId: 'runtime-app' },
          {
            kind: 'application',
            logicalId: 'phase1-browser',
            runtimeId: 'runtime-browser',
          },
          { kind: 'resource', logicalId: 'phase1-api', runtimeId: 'runtime-resource' },
          { kind: 'scope', logicalId: 'phase1-read-profile', runtimeId: 'runtime-scope' },
          { kind: 'role', logicalId: 'phase1-role', runtimeId: 'runtime-role' },
        ],
      },
    ],
  }),
  passwords: [],
  clientSecrets: [],
});

const adminFixture = createProvisionedPhase1Fixture({
  public: createPhase1FixtureMap({
    schemaVersion: 1,
    recipe: 'adminConsole',
    allocations: [
      {
        allocationId: 'admin-allocation',
        role: 'admin',
        target: 'primary',
        isolation: {
          persistenceId: 'admin-persistence',
          cookieKeyId: 'admin-cookie',
          signingKeyId: 'admin-signing',
        },
        entities: [
          { kind: 'tenant', logicalId: 'admin', runtimeId: 'admin' },
          { kind: 'user', logicalId: 'phase1-admin', runtimeId: 'runtime-admin' },
          { kind: 'application', logicalId: 'admin-console', runtimeId: 'admin-console' },
          {
            kind: 'resource',
            logicalId: 'admin.resource.1',
            runtimeId: 'https://default.logto.app/api',
          },
          {
            kind: 'resource',
            logicalId: 'admin.resource.2',
            runtimeId: 'https://admin.logto.app/me',
          },
          {
            kind: 'resource',
            logicalId: 'admin.resource.3',
            runtimeId: 'urn:logto:resource:organizations',
          },
          { kind: 'role', logicalId: 'default:admin', runtimeId: 'runtime-default-admin' },
          { kind: 'role', logicalId: 'user', runtimeId: 'runtime-user' },
          { kind: 'organization', logicalId: 't-default', runtimeId: 't-default' },
          { kind: 'organization-role', logicalId: 'admin', runtimeId: 'admin' },
        ],
      },
    ],
  }),
  passwords: [],
  clientSecrets: [],
});

const family = 'a'.repeat(64);
const model = (
  kind: ReferenceStateDriverSnapshot['models'][number]['kind'],
  overrides: Partial<ReferenceStateDriverSnapshot['models'][number]> = {}
): ReferenceStateDriverSnapshot['models'][number] => ({
  kind,
  tenantId: 'default',
  clientId: 'runtime-browser',
  accountId: 'runtime-user',
  familyFingerprint: family,
  artifactFingerprint: kind === 'grant' ? family : 'b'.repeat(64),
  consumed: false,
  active: true,
  rotation: kind === 'rotation' ? 0 : null,
  verificationCount: 0,
  identified: false,
  oidcScopes: [],
  resources: [],
  ...overrides,
});

const snapshot = (
  scenarioId: ReferenceStateDriverSnapshot['scenarioId'],
  stepId: string,
  models: ReferenceStateDriverSnapshot['models']
): ReferenceStateDriverSnapshot => ({
  schemaVersion: 1,
  scenarioId,
  stepId,
  models,
  extensions: [],
  users: [{ tenantId: 'default', id: 'runtime-user', applicationId: null }],
  verificationRecords: [{ tenantId: 'default', userId: 'runtime-user', count: 0 }],
});

const symbols = (): Phase1FixtureSymbolTables => {
  const table = new SymbolTable();
  table.bind('user.phase1-user', 'runtime-user');
  table.bind('application.phase1-browser', 'runtime-browser');

  return {
    allocationIds: ['data-allocation'],
    get: (allocationId) => (allocationId === 'data-allocation' ? table : undefined),
  };
};

const adminSymbols = (): Phase1FixtureSymbolTables => {
  const table = new SymbolTable();
  table.bind('user.phase1-admin', 'runtime-admin');
  table.bind('application.admin-console', 'admin-console');

  return {
    allocationIds: ['admin-allocation'],
    get: (allocationId) => (allocationId === 'admin-allocation' ? table : undefined),
  };
};

const adminModel = (
  kind: ReferenceStateDriverSnapshot['models'][number]['kind'],
  overrides: Partial<ReferenceStateDriverSnapshot['models'][number]> = {}
): ReferenceStateDriverSnapshot['models'][number] =>
  model(kind, {
    tenantId: 'admin',
    clientId: 'admin-console',
    accountId: 'runtime-admin',
    ...overrides,
  });

const adminCodeTokenSnapshot = (
  overrides: Partial<ReferenceStateDriverSnapshot> = {}
): ReferenceStateDriverSnapshot => ({
  schemaVersion: 1,
  scenarioId: 'console.admin-auth-resource-refresh',
  stepId: 'code-token',
  models: [
    adminModel('grant', {
      oidcScopes: [
        'profile',
        'email',
        'phone',
        'identities',
        'custom_data',
        'urn:logto:scope:organizations',
        'urn:logto:scope:organization_roles',
      ],
      resources: [
        { indicator: 'https://default.logto.app/api', scopes: ['all'] },
        { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
      ],
    }),
    adminModel('one-time', { consumed: true, artifactFingerprint: 'b'.repeat(64) }),
    adminModel('rotation', { artifactFingerprint: 'c'.repeat(64) }),
    adminModel('session', { artifactFingerprint: 'd'.repeat(64) }),
  ],
  extensions: [
    {
      tenantId: 'admin',
      accountId: 'runtime-admin',
      clientId: 'admin-console',
      loginAccountId: 'runtime-admin',
      updatedAt: 1_700_000_000_000,
    },
  ],
  users: [{ tenantId: 'admin', id: 'runtime-admin', applicationId: 'admin-console' }],
  verificationRecords: [{ tenantId: 'admin', userId: 'runtime-admin', count: 0 }],
  ...overrides,
});

const adminRefreshedSnapshot = (
  scenarioId: 'console.admin-auth-resource-refresh' | 'console.admin-organization-token-refresh',
  stepId: 'management-refresh' | 'organization-refresh' | 'state',
  overrides: Partial<ReferenceStateDriverSnapshot> = {}
): ReferenceStateDriverSnapshot => ({
  schemaVersion: 1,
  scenarioId,
  stepId,
  models: [
    adminModel('grant', {
      oidcScopes: [
        'profile',
        'email',
        'phone',
        'identities',
        'custom_data',
        'urn:logto:scope:organizations',
        'urn:logto:scope:organization_roles',
      ],
      resources: [
        { indicator: 'https://default.logto.app/api', scopes: ['all'] },
        { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
      ],
    }),
    adminModel('one-time', { consumed: true, artifactFingerprint: 'b'.repeat(64) }),
    adminModel('rotation', {
      consumed: true,
      rotation: 0,
      artifactFingerprint: 'c'.repeat(64),
    }),
    adminModel('rotation', { rotation: 1, artifactFingerprint: 'd'.repeat(64) }),
    adminModel('session', { artifactFingerprint: 'e'.repeat(64) }),
  ],
  extensions: [
    {
      tenantId: 'admin',
      accountId: 'runtime-admin',
      clientId: 'admin-console',
      loginAccountId: 'runtime-admin',
      updatedAt: 1_700_000_000_000,
    },
  ],
  users: [{ tenantId: 'admin', id: 'runtime-admin', applicationId: 'admin-console' }],
  verificationRecords: [{ tenantId: 'admin', userId: 'runtime-admin', count: 0 }],
  ...overrides,
});

const adminPreConsentSnapshot = (
  overrides: Partial<ReferenceStateDriverSnapshot> = {}
): ReferenceStateDriverSnapshot => ({
  schemaVersion: 1,
  scenarioId: 'console.admin-auth-resource-refresh',
  stepId: 'authorize',
  models: [adminModel('interaction', { accountId: null, familyFingerprint: null })],
  extensions: [],
  users: [{ tenantId: 'admin', id: 'runtime-admin', applicationId: null }],
  verificationRecords: [{ tenantId: 'admin', userId: 'runtime-admin', count: 0 }],
  ...overrides,
});

const projectAdminState = async (
  value: ReferenceStateDriverSnapshot,
  stepId: string,
  scenarioId: ReferenceStateDriverSnapshot['scenarioId'] = 'console.admin-auth-resource-refresh'
) =>
  createReferenceScenarioStateProjector({
    profile,
    primaryContainerId: '1'.repeat(64),
    projectName: 'aster-phase1-0123456789abcdef',
    primaryService: 'oracle-primary-postgres',
    symbols: adminSymbols(),
    readSnapshot: async () => value,
  })({
    scenarioId,
    stepId,
    fixture: adminFixture,
    target: {
      label: 'oracle',
      coreUrl: 'http://localhost:3311/',
      adminUrl: 'http://localhost:3411/',
    },
    signal: new AbortController().signal,
  });

describe('Phase 1 reference scenario state', () => {
  it('rejects an explicitly empty engine socket before invoking the state driver', async () => {
    const runner = import.meta.jest.fn();
    await expect(
      readReferenceStateDriver(
        {
          source: 'primary',
          projectName: 'aster-phase1-0123456789abcdef',
          expectedService: 'oracle-primary-postgres',
          containerId: '1'.repeat(64),
          scenarioId: 'token.authorization-code',
          stepId: 'state',
          signal: new AbortController().signal,
        },
        {
          driverPath:
            '/home/henry/repo/logto/.scripts/compatibility/phase1-reference-state-driver.sh',
          environment: { PATH: '/usr/bin:/bin', ASTER_PHASE1_ENGINE_SOCKET: '' },
          runner,
        }
      )
    ).rejects.toThrow();
    expect(runner).not.toHaveBeenCalled();
  });

  it('requires a clean admin authorization state before auto-consent', async () => {
    const valid = adminPreConsentSnapshot();

    await expect(projectAdminState(valid, 'authorize')).resolves.toMatchObject({
      generatedIds: { interaction: '<interaction.1>' },
      persistedState: { unrelatedMutation: false },
    });
    const invalidSnapshots = [
      { ...valid, models: [...valid.models, adminModel('grant')] },
      { ...valid, models: [...valid.models, adminModel('session')] },
      { ...valid, models: [...valid.models, adminModel('one-time')] },
      { ...valid, models: [...valid.models, adminModel('rotation')] },
      {
        ...valid,
        models: [
          ...valid.models,
          adminModel('interaction', {
            accountId: null,
            familyFingerprint: null,
            artifactFingerprint: 'f'.repeat(64),
            active: false,
          }),
        ],
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'interaction' ? { ...entry, accountId: 'runtime-admin' } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'interaction' ? { ...entry, identified: true } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'interaction' ? { ...entry, verificationCount: 1 } : entry
        ),
      },
      {
        ...valid,
        extensions: [
          {
            tenantId: 'admin',
            accountId: 'runtime-admin',
            clientId: 'admin-console',
            loginAccountId: 'runtime-admin',
            updatedAt: 1_700_000_000_000,
          },
        ],
      },
      {
        ...valid,
        users: [{ tenantId: 'admin', id: 'runtime-admin', applicationId: 'admin-console' }],
      },
      {
        ...valid,
        verificationRecords: [{ tenantId: 'admin', userId: 'runtime-admin', count: 1 }],
      },
    ];

    await Promise.all(
      invalidSnapshots.map(async (invalid) =>
        expect(projectAdminState(invalid, 'authorize')).rejects.toThrow(
          /^Invalid phase 1 reference state$/u
        )
      )
    );
  });

  it('accepts the exact private admin auto-consent state without changing its projection', async () => {
    await expect(projectAdminState(adminCodeTokenSnapshot(), 'code-token')).resolves.toMatchObject({
      persistedState: { unrelatedMutation: false },
      semanticState: { unrelatedMutation: false },
      sideEffects: { unrelatedMutation: false },
    });
  });

  it.each([
    ['console.admin-auth-resource-refresh', 'management-refresh'],
    ['console.admin-auth-resource-refresh', 'state'],
    ['console.admin-organization-token-refresh', 'organization-refresh'],
    ['console.admin-organization-token-refresh', 'state'],
  ] as const)(
    'accepts the exact refreshed admin topology for %s %s',
    async (scenarioId, stepId) => {
      const value = adminRefreshedSnapshot(scenarioId, stepId);

      await expect(projectAdminState(value, stepId, scenarioId)).resolves.toMatchObject({
        semanticState: { unrelatedMutation: false },
        sideEffects: { unrelatedMutation: false },
      });
    }
  );

  it.each(
    (() => {
      const valid = adminCodeTokenSnapshot();

      return [
        [
          'a missing authorization code row',
          { ...valid, models: valid.models.filter(({ kind }) => kind !== 'one-time') },
        ],
        [
          'a missing refresh token row',
          { ...valid, models: valid.models.filter(({ kind }) => kind !== 'rotation') },
        ],
        [
          'a duplicate refresh token row',
          {
            ...valid,
            models: [
              ...valid.models,
              adminModel('rotation', { artifactFingerprint: 'f'.repeat(64) }),
            ],
          },
        ],
        [
          'an inactive interaction row',
          {
            ...valid,
            models: [
              ...valid.models,
              adminModel('interaction', {
                accountId: null,
                familyFingerprint: null,
                artifactFingerprint: 'f'.repeat(64),
                active: false,
              }),
            ],
          },
        ],
        [
          'a consumed grant',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'grant' ? { ...entry, consumed: true } : entry
            ),
          },
        ],
        [
          'an inactive authorization code',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'one-time' ? { ...entry, active: false } : entry
            ),
          },
        ],
        [
          'an unconsumed authorization code',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'one-time' ? { ...entry, consumed: false } : entry
            ),
          },
        ],
        [
          'an authorization code from another grant family',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'one-time' ? { ...entry, familyFingerprint: 'f'.repeat(64) } : entry
            ),
          },
        ],
        [
          'a consumed initial refresh token',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'rotation' ? { ...entry, consumed: true } : entry
            ),
          },
        ],
        [
          'an inactive initial refresh token',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'rotation' ? { ...entry, active: false } : entry
            ),
          },
        ],
        [
          'a nonzero initial refresh token ordinal',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'rotation' ? { ...entry, rotation: 1 } : entry
            ),
          },
        ],
        [
          'an initial refresh token from another grant family',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'rotation' ? { ...entry, familyFingerprint: 'f'.repeat(64) } : entry
            ),
          },
        ],
        [
          'a consumed session',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'session' ? { ...entry, consumed: true } : entry
            ),
          },
        ],
        [
          'model verification residue',
          {
            ...valid,
            models: valid.models.map((entry) =>
              entry.kind === 'session' ? { ...entry, verificationCount: 1 } : entry
            ),
          },
        ],
        [
          'persisted verification residue',
          {
            ...valid,
            verificationRecords: [{ tenantId: 'admin', userId: 'runtime-admin', count: 1 }],
          },
        ],
      ] as const;
    })()
  )('rejects code-token topology containing %s', async (_name, invalid) => {
    await expect(projectAdminState(invalid, 'code-token')).rejects.toThrow(
      /^Invalid phase 1 reference state$/u
    );
  });

  it.each([
    ['console.admin-auth-resource-refresh', 'organization-refresh'],
    ['console.admin-auth-resource-refresh', 'unexpected'],
    ['console.admin-organization-token-refresh', 'code-token'],
    ['console.admin-organization-token-refresh', 'management-refresh'],
  ] as const)('rejects unsupported admin protocol step %s %s', async (scenarioId, stepId) => {
    const value = adminCodeTokenSnapshot({ scenarioId, stepId });

    await expect(projectAdminState(value, stepId, scenarioId)).rejects.toThrow(
      /^Invalid phase 1 reference state$/u
    );
  });

  it.each([
    ['console.admin-auth-resource-refresh', 'management-refresh'],
    ['console.admin-auth-resource-refresh', 'state'],
    ['console.admin-organization-token-refresh', 'organization-refresh'],
    ['console.admin-organization-token-refresh', 'state'],
  ] as const)(
    'rejects malformed refreshed admin topology for %s %s',
    async (scenarioId, stepId) => {
      const valid = adminRefreshedSnapshot(scenarioId, stepId);
      const invalidSnapshots = [
        { ...valid, models: valid.models.filter(({ kind }) => kind !== 'one-time') },
        {
          ...valid,
          models: valid.models.filter(
            ({ kind, rotation }) => kind !== 'rotation' || rotation !== 0
          ),
        },
        {
          ...valid,
          models: valid.models.filter(
            ({ kind, rotation }) => kind !== 'rotation' || rotation !== 1
          ),
        },
        {
          ...valid,
          models: [
            ...valid.models,
            adminModel('rotation', {
              rotation: 1,
              artifactFingerprint: 'f'.repeat(64),
            }),
          ],
        },
        {
          ...valid,
          models: [
            ...valid.models,
            adminModel('interaction', {
              accountId: null,
              familyFingerprint: null,
              artifactFingerprint: 'f'.repeat(64),
              active: false,
            }),
          ],
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'grant' ? { ...entry, consumed: true } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'grant' ? { ...entry, active: false } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'one-time' ? { ...entry, consumed: false } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'one-time' ? { ...entry, active: false } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'one-time' ? { ...entry, familyFingerprint: 'f'.repeat(64) } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 0
              ? { ...entry, consumed: false }
              : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 0 ? { ...entry, active: false } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 0 ? { ...entry, rotation: 2 } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 0
              ? { ...entry, familyFingerprint: 'f'.repeat(64) }
              : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 1 ? { ...entry, consumed: true } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 1 ? { ...entry, active: false } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 1 ? { ...entry, rotation: 2 } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'rotation' && entry.rotation === 1
              ? { ...entry, familyFingerprint: 'f'.repeat(64) }
              : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'session' ? { ...entry, active: false } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'session' ? { ...entry, consumed: true } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'session' ? { ...entry, familyFingerprint: 'f'.repeat(64) } : entry
          ),
        },
        {
          ...valid,
          models: valid.models.map((entry) =>
            entry.kind === 'session' ? { ...entry, verificationCount: 1 } : entry
          ),
        },
        {
          ...valid,
          verificationRecords: [{ tenantId: 'admin', userId: 'runtime-admin', count: 1 }],
        },
      ];

      await Promise.all(
        invalidSnapshots.map(async (invalid) =>
          expect(projectAdminState(invalid, stepId, scenarioId)).rejects.toThrow(
            /^Invalid phase 1 reference state$/u
          )
        )
      );
    }
  );

  it('rejects incomplete or overbroad private admin auto-consent state', async () => {
    const valid = adminCodeTokenSnapshot();
    const grant = valid.models.find(({ kind }) => kind === 'grant');
    const extension = valid.extensions[0];

    if (!grant || !extension) {
      throw new Error('Invalid admin consent test fixture');
    }
    const invalidSnapshots = [
      { ...valid, models: valid.models.filter(({ kind }) => kind !== 'grant') },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant' ? { ...entry, oidcScopes: [...entry.oidcScopes, 'openid'] } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant'
            ? { ...entry, oidcScopes: [...entry.oidcScopes, 'offline_access'] }
            : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant' ? { ...entry, oidcScopes: [...entry.oidcScopes, 'all'] } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant'
            ? {
                ...entry,
                oidcScopes: entry.oidcScopes.filter(
                  (scope) => scope !== 'urn:logto:scope:organizations'
                ),
              }
            : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant'
            ? {
                ...entry,
                oidcScopes: entry.oidcScopes.filter(
                  (scope) => scope !== 'urn:logto:scope:organization_roles'
                ),
              }
            : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant'
            ? {
                ...entry,
                resources: [
                  ...entry.resources,
                  {
                    indicator: 'urn:logto:resource:organizations',
                    scopes: ['urn:logto:scope:organizations', 'urn:logto:scope:organization_roles'],
                  },
                ],
              }
            : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant' ? { ...entry, resources: entry.resources.slice(1) } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant'
            ? {
                ...entry,
                resources: entry.resources.map((resource, index) =>
                  index === 0 ? { ...resource, scopes: ['wrong'] } : resource
                ),
              }
            : entry
        ),
      },
      { ...valid, models: [...valid.models, { ...grant }] },
      { ...valid, models: valid.models.filter(({ kind }) => kind !== 'session') },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'grant' ? { ...entry, active: false } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'session' ? { ...entry, active: false } : entry
        ),
      },
      {
        ...valid,
        models: valid.models.map((entry) =>
          entry.kind === 'session' ? { ...entry, familyFingerprint: 'c'.repeat(64) } : entry
        ),
      },
      {
        ...valid,
        models: [...valid.models, adminModel('session', { artifactFingerprint: 'c'.repeat(64) })],
      },
      { ...valid, extensions: [] },
      {
        ...valid,
        extensions: [{ ...extension, loginAccountId: 'wrong-admin' }],
      },
      {
        ...valid,
        users: [{ tenantId: 'admin', id: 'runtime-admin', applicationId: null }],
      },
      {
        ...valid,
        models: [
          ...valid.models,
          adminModel('interaction', { accountId: null, familyFingerprint: null }),
        ],
      },
    ];

    await Promise.all(
      invalidSnapshots.map(async (invalid) =>
        expect(projectAdminState(invalid, 'code-token')).rejects.toThrow(
          /^Invalid phase 1 reference state$/u
        )
      )
    );
  });

  it('derives non-empty one-time and concurrent refresh state from sanitized database facts', async () => {
    const reads = new Map<string, ReferenceStateDriverSnapshot>([
      [
        'token.authorization-code:state',
        snapshot('token.authorization-code', 'state', [
          model('grant'),
          model('one-time', { consumed: true }),
          model('rotation'),
        ]),
      ],
      [
        'token.concurrent-refresh-single-winner:attempt-a',
        snapshot('token.concurrent-refresh-single-winner', 'attempt-a', [
          model('grant'),
          model('one-time', { consumed: true }),
          model('rotation', { consumed: true, artifactFingerprint: 'c'.repeat(64) }),
          model('rotation', {
            rotation: 1,
            artifactFingerprint: 'd'.repeat(64),
          }),
          model('rotation', {
            rotation: 1,
            artifactFingerprint: 'e'.repeat(64),
          }),
        ]),
      ],
      [
        'token.concurrent-refresh-single-winner:state',
        snapshot('token.concurrent-refresh-single-winner', 'state', [
          model('grant'),
          model('one-time', { consumed: true }),
          model('rotation', { consumed: true, artifactFingerprint: 'c'.repeat(64) }),
          model('rotation', {
            rotation: 1,
            artifactFingerprint: 'd'.repeat(64),
          }),
          model('rotation', {
            rotation: 1,
            artifactFingerprint: 'e'.repeat(64),
          }),
        ]),
      ],
    ]);
    const projector = createReferenceScenarioStateProjector({
      profile,
      primaryContainerId: '1'.repeat(64),
      projectName: 'aster-phase1-0123456789abcdef',
      primaryService: 'oracle-primary-postgres',
      symbols: symbols(),
      readSnapshot: async ({ scenarioId, stepId }) => {
        const value = reads.get(`${scenarioId}:${stepId}`);

        if (!value) {
          throw new Error('unexpected state read');
        }

        return value;
      },
    });

    await expect(
      projector({
        scenarioId: 'token.authorization-code',
        stepId: 'state',
        fixture,
        target: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        signal: new AbortController().signal,
      })
    ).resolves.toMatchObject({
      persistedState: { grantConsumed: true, familyCount: 1, unrelatedMutation: false },
      generatedIds: { tokenFamily: '<token-family.1>' },
    });

    const attempt = await projector({
      scenarioId: 'token.concurrent-refresh-single-winner',
      stepId: 'attempt-a',
      fixture,
      target: {
        label: 'oracle',
        coreUrl: 'http://localhost:3311/',
        adminUrl: 'http://localhost:3411/',
      },
      signal: new AbortController().signal,
    });
    expect(attempt.persistedState).toEqual({
      presentationSuccessCount: 2,
      predecessorConsumed: true,
      replacementRefreshCount: 2,
      distinctReplacementCount: 2,
      activeDescendantCount: 2,
      replacementRotationOrdinals: [1, 1],
      familyCount: 1,
      unrelatedMutation: false,
    });
    await expect(
      projector({
        scenarioId: 'token.concurrent-refresh-single-winner',
        stepId: 'state',
        fixture,
        target: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        signal: new AbortController().signal,
      })
    ).resolves.toMatchObject({ generatedIds: { tokenFamily: '<token-family.1>' } });
  });

  it('rejects extra fields raw artifact identifiers and credential-shaped helper output', () => {
    const valid = snapshot('token.authorization-code', 'state', [model('grant')]);

    for (const invalid of [
      { ...valid, extra: true },
      {
        ...valid,
        models: [{ ...valid.models[0], artifactFingerprint: 'raw-authorization-value' }],
      },
      { ...valid, accessToken: 'private-value' },
    ]) {
      expect(() => parseReferenceStateDriverSnapshot(invalid)).toThrow(
        /^Invalid phase 1 reference state$/u
      );
    }
  });

  it('requires an unconsumed code before accepting the PKCE rejection projection', async () => {
    const projector = createReferenceScenarioStateProjector({
      profile,
      primaryContainerId: '1'.repeat(64),
      projectName: 'aster-phase1-0123456789abcdef',
      primaryService: 'oracle-primary-postgres',
      symbols: symbols(),
      readSnapshot: async ({ scenarioId, stepId }) => snapshot(scenarioId, stepId, []),
    });

    await expect(
      projector({
        scenarioId: 'token.pkce-verifier-rejected',
        stepId: 'bad-verifier',
        fixture,
        target: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        signal: new AbortController().signal,
      })
    ).rejects.toThrow(/^Invalid phase 1 reference state$/u);
  });

  it('rejects hidden extra consent scopes and resources', async () => {
    const expectedIndicator = getPhase1FixtureRuntimeResourceIndicator(
      'https://phase1.example.test/api',
      'data-allocation'
    );
    const expectedScope = getPhase1FixtureRuntimeText('read:profile', 'data-allocation');
    const state = snapshot('authorization.password-pkce-consent', 'state', [
      model('grant', {
        oidcScopes: ['profile', 'email'],
        resources: [
          { indicator: expectedIndicator, scopes: [expectedScope] },
          { indicator: 'https://extra.example.test/api', scopes: ['extra'] },
        ],
      }),
    ]);
    const projector = createReferenceScenarioStateProjector({
      profile,
      primaryContainerId: '1'.repeat(64),
      projectName: 'aster-phase1-0123456789abcdef',
      primaryService: 'oracle-primary-postgres',
      symbols: symbols(),
      readSnapshot: async () => ({
        ...state,
        users: [{ tenantId: 'default', id: 'runtime-user', applicationId: 'runtime-browser' }],
        extensions: [
          {
            tenantId: 'default',
            accountId: 'runtime-user',
            clientId: 'runtime-browser',
            loginAccountId: 'runtime-user',
            updatedAt: 1_700_000_000_000,
          },
        ],
      }),
    });

    await expect(
      projector({
        scenarioId: 'authorization.password-pkce-consent',
        stepId: 'state',
        fixture,
        target: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        signal: new AbortController().signal,
      })
    ).rejects.toThrow(/^Invalid phase 1 reference state$/u);
  });

  it('requires the first-consent application binding in the authorization state projection', async () => {
    const expectedIndicator = getPhase1FixtureRuntimeResourceIndicator(
      'https://phase1.example.test/api',
      'data-allocation'
    );
    const expectedScope = getPhase1FixtureRuntimeText('read:profile', 'data-allocation');
    const state = snapshot('authorization.password-pkce-consent', 'state', [
      model('grant', {
        oidcScopes: ['profile'],
        resources: [{ indicator: expectedIndicator, scopes: [expectedScope] }],
      }),
    ]);
    const projector = createReferenceScenarioStateProjector({
      profile,
      primaryContainerId: '1'.repeat(64),
      projectName: 'aster-phase1-0123456789abcdef',
      primaryService: 'oracle-primary-postgres',
      symbols: symbols(),
      readSnapshot: async () => ({
        ...state,
        users: [{ tenantId: 'default', id: 'runtime-user', applicationId: null }],
        extensions: [
          {
            tenantId: 'default',
            accountId: 'runtime-user',
            clientId: 'runtime-browser',
            loginAccountId: 'runtime-user',
            updatedAt: 1_700_000_000_000,
          },
        ],
      }),
    });

    await expect(
      projector({
        scenarioId: 'authorization.password-pkce-consent',
        stepId: 'state',
        fixture,
        target: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        signal: new AbortController().signal,
      })
    ).rejects.toThrow(/^Invalid phase 1 reference state$/u);
  });

  it('rejects password failure evidence when an issuance or session extension exists', async () => {
    const projector = createReferenceScenarioStateProjector({
      profile,
      primaryContainerId: '1'.repeat(64),
      projectName: 'aster-phase1-0123456789abcdef',
      primaryService: 'oracle-primary-postgres',
      symbols: symbols(),
      readSnapshot: async ({ scenarioId, stepId }) => ({
        ...snapshot(scenarioId, stepId, [
          model('interaction', {
            accountId: null,
            familyFingerprint: null,
            verificationCount: 0,
          }),
          model('one-time'),
        ]),
        extensions: [
          {
            tenantId: 'default',
            accountId: 'runtime-user',
            clientId: 'runtime-browser',
            loginAccountId: null,
            updatedAt: 1_700_000_000_000,
          },
        ],
      }),
    });

    await expect(
      projector({
        scenarioId: 'interaction.password-rejected',
        stepId: 'state',
        fixture,
        target: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        signal: new AbortController().signal,
      })
    ).rejects.toThrow(/^Invalid phase 1 reference state$/u);
  });
});

/* eslint-enable max-lines */
