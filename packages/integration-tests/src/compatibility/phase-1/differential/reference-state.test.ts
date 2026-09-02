import { SymbolTable } from '../../symbol-table.js';
import {
  createPhase1FixtureMap,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  type Phase1FixtureSymbolTables,
} from '../fixture-map.js';
import { createProvisionedPhase1Fixture } from '../fixtures.js';
import type { Phase1Profile } from '../profile-types.js';

import {
  createReferenceScenarioStateProjector,
  parseReferenceStateDriverSnapshot,
  type ReferenceStateDriverSnapshot,
} from './reference-state.js';

const profile = {
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

describe('Phase 1 reference scenario state', () => {
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
