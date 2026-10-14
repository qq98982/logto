/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The cohesive catalog lease tests keep ownership, preservation, and cleanup assertions together. */
import type { Phase2AdminRequest } from '../fixtures.js';

import {
  createManagementOwnershipRefusalObserver,
  createManagementProvisioningFixtureRuntime,
  withManagementProvisioningFixtureRuntime,
} from './management-provisioning-fixture-runtime.js';

test('binds endpoints and bearer and repairs only the exact China Native relation', async () => {
  const requests: Array<{ method: string; path: string }> = [];
  const removedRelations: Array<{ roleId: string; scopeId: string }> = [];
  const runtime = createManagementProvisioningFixtureRuntime({
    target: {
      label: 'candidate',
      coreUrl: 'https://core.example/',
      adminUrl: 'https://admin.example/',
    },
    bearer: 'private-management-bearer',
    globalEnvironment: { BOX_AI_SMTP_HOST: 'smtp.fixture' },
    chinaNativeEnvironment: { BOX_AI_WECHAT_CHANNELS: 'native' },
    withForeignManagementControls: async (use) =>
      use({
        userId: 'foreign-user',
        connectorId: 'foreign-connector',
        applicationId: 'foreign-application',
      }),
    cleanupProvisioningRows: async () => {
      await Promise.resolve();
    },
    removeProvisioningRoleScope: async (ids) => {
      removedRelations.push(ids);
    },
    request: async (request) => {
      requests.push(request);
      if (request.path === 'roles') {
        return [{ id: 'role', name: 'Box-AI Native Session User' }];
      }
      if (request.path === 'roles/role/scopes') {
        return [{ id: 'scope', name: 'session:exchange' }];
      }
      if (request.path.startsWith('users/') || request.path.startsWith('connectors/')) {
        return { code: 'entity.not_found', message: 'Not found' };
      }
      if (request.path === 'sign-in-exp') {
        return { signIn: { methods: [] } };
      }
      if (request.method === 'POST' && request.path === 'applications') {
        return {
          id: 'foreign-owned-application',
          name: 'Box-AI',
          description: 'Foreign owner retained by compatibility fixture',
        };
      }
      if (request.method === 'GET' && request.path === 'applications/foreign-owned-application') {
        return {
          id: 'foreign-owned-application',
          name: 'Box-AI',
          description: 'Foreign owner retained by compatibility fixture',
        };
      }
      if (request.method === 'DELETE') {
        return 204;
      }
      throw new TypeError('unexpected request');
    },
  });
  expect(runtime.environments[0]).toMatchObject({
    BOX_AI_MARKET: 'global',
    BOX_AI_LOGTO_ENDPOINT: 'https://core.example/',
    BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT: 'https://core.example/',
    BOX_AI_LOGTO_MANAGEMENT_TOKEN: 'private-management-bearer',
  });
  await runtime.removeOwnedRoleScope(runtime.environments[0]);
  expect(requests).toEqual([]);
  await runtime.removeOwnedRoleScope(runtime.environments[1]);
  expect(requests.map(({ method, path }) => ({ method, path }))).toEqual([
    { method: 'GET', path: 'roles' },
    { method: 'GET', path: 'roles/role/scopes' },
  ]);
  expect(removedRelations).toEqual([{ roleId: 'role', scopeId: 'scope' }]);
});
test('fails closed when the repair relation is ambiguous', async () => {
  const runtime = createManagementProvisioningFixtureRuntime({
    target: {
      label: 'oracle',
      coreUrl: 'https://core.example/',
      adminUrl: 'https://admin.example/',
    },
    bearer: 'private-management-bearer',
    globalEnvironment: {},
    chinaNativeEnvironment: {},
    withForeignManagementControls: async (use) =>
      use({
        userId: 'foreign-user',
        connectorId: 'foreign-connector',
        applicationId: 'foreign-application',
      }),
    cleanupProvisioningRows: async () => {
      await Promise.resolve();
    },
    request: async () => [
      { id: 'one', name: 'Box-AI Native Session User' },
      { id: 'two', name: 'Box-AI Native Session User' },
    ],
  });
  await expect(runtime.removeOwnedRoleScope(runtime.environments[1])).rejects.toThrow(
    'Invalid Management provisioning fixture runtime'
  );
});
test('ownership refusal requires the pinned client refusal, preserved state, and foreign cleanup', async () => {
  let cleanupCompleted = false;
  let selectedCreateShapeObserved = false;
  const observe = createManagementOwnershipRefusalObserver(
    async ({ method, path, body }) => {
      if (path === 'sign-in-exp') {
        return { signIn: { methods: [] } };
      }
      if (method === 'POST' && path === 'applications') {
        if (
          JSON.stringify(body) !==
          JSON.stringify({
            name: 'Box-AI',
            description: 'Foreign owner retained by compatibility fixture',
            type: 'Traditional',
            isThirdParty: false,
            oidcClientMetadata: { redirectUris: [], postLogoutRedirectUris: [] },
          })
        ) {
          throw new TypeError('selected Traditional application shape rejected');
        }
        selectedCreateShapeObserved = true;
        return {
          id: 'foreign-owned-application',
          name: 'Box-AI',
          description: 'Foreign owner retained by compatibility fixture',
        };
      }
      if (path === 'applications/foreign-owned-application') {
        return {
          id: 'foreign-owned-application',
          name: 'Box-AI',
          description: 'Foreign owner retained by compatibility fixture',
        };
      }
      return { code: 'entity.not_found', message: 'Not found' };
    },
    { BOX_AI_MARKET: 'global' },
    async (use) => {
      const result = await use({
        userId: 'foreign-user',
        connectorId: 'foreign-connector',
        applicationId: 'foreign-application',
      });
      cleanupCompleted = true;
      return result;
    },
    async () => true,
    async (applicationId) => {
      expect(applicationId).toBe('foreign-owned-application');
    }
  );
  await expect(observe()).resolves.toBe(true);
  expect(selectedCreateShapeObserved).toBe(true);
  expect(cleanupCompleted).toBe(true);
});
test('lease preserves unrelated same-named resource scopes and cleans only validated owned rows', async () => {
  const rows: Record<string, Array<Record<string, unknown>>> = {
    roles: [{ id: 'old-role' }],
    resources: [
      {
        id: 'old-resource',
        name: 'Unrelated Native resource',
        indicator: 'https://another.example/api',
        scopes: [
          { id: 'old-scope', name: 'session:exchange', description: 'Unrelated application scope' },
        ],
      },
    ],
    applications: [{ id: 'old-application' }],
    connectors: [{ id: 'old-connector', config: { clientId: 'before' } }],
  };
  const mutations: Array<{ method: string; path: string; body?: unknown }> = [];
  const rejectedDeletion = 'roles/failed-roles';
  const privateCleanupCalls: unknown[] = [];
  let experience: Record<string, unknown> = {
    branding: { logoUrl: 'before' },
    signIn: { methods: [] },
  };
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'GET' && Object.hasOwn(rows, input.path)) {
      return rows[input.path]?.map((row) => ({ ...row }));
    }
    if (input.method === 'GET' && input.path.startsWith('connectors/')) {
      return rows.connectors?.find(({ id }) => id === input.path.split('/')[1]);
    }
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return { ...experience };
    }
    mutations.push(input);
    if (input.method === 'DELETE') {
      if (input.path === rejectedDeletion) {
        throw new TypeError('selected cleanup failure');
      }
      const [kind, id] = input.path.split('/');
      if (!kind || !id) {
        throw new TypeError('invalid test deletion');
      }
      const current: Array<Record<string, unknown>> = rows[kind] ?? [];
      rows[kind] = current.filter((row: Record<string, unknown>) => row.id !== id);
    }
    if (input.method === 'PATCH' && input.path === 'connectors/old-connector') {
      rows.connectors = [{ id: 'old-connector', ...(input.body as Record<string, unknown>) }];
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      experience = input.body as Record<string, unknown>;
    }
    return {};
  };
  const input = {
    target: {
      label: 'candidate',
      coreUrl: 'https://core.example/',
      adminUrl: 'https://admin.example/',
    },
    bearer: 'private-management-bearer',
    globalEnvironment: {},
    chinaNativeEnvironment: { BOX_AI_WECHAT_CHANNELS: 'native' },
    withForeignManagementControls: async <Result>(
      use: (controls: {
        userId: string;
        connectorId: string;
        applicationId: string;
      }) => Promise<Result>
    ) =>
      use({
        userId: 'foreign-user',
        connectorId: 'foreign-connector',
        applicationId: 'foreign-application',
      }),
    cleanupProvisioningRows: async (
      owned: Readonly<{
        resourceId: string;
        applicationIds: readonly [string, string];
      }>
    ) => {
      privateCleanupCalls.push(owned);
      rows.resources = rows.resources?.filter(({ id }) => id !== owned.resourceId) ?? [];
      rows.applications =
        rows.applications?.filter(({ id }) => !owned.applicationIds.includes(String(id))) ?? [];
    },
    request,
  } as const;
  await withManagementProvisioningFixtureRuntime(input, async () => {
    rows.roles?.push({ id: 'new-roles' });
    rows.connectors?.push({ id: 'new-connectors' });
    rows.resources?.push({
      id: 'new-resources',
      name: 'Box-AI Native Session API',
      indicator: 'https://core.example/api',
      accessTokenTtl: 300,
      scopes: [
        {
          id: 'new-scope',
          name: 'session:exchange',
          description: 'Managed by the Box-AI deployment for native session exchange',
        },
      ],
    });
    rows.applications?.push(
      {
        id: 'new-application-global',
        name: 'Box-AI',
        description: 'Managed by the Box-AI deployment',
        type: 'Traditional',
      },
      {
        id: 'new-application-native',
        name: 'Box-AI Native',
        description: 'Managed by the Box-AI deployment as a native public client',
        type: 'Native',
      }
    );
  });
  expect(
    Object.fromEntries(Object.entries(rows).map(([key, value]) => [key, value.map(({ id }) => id)]))
  ).toEqual({
    roles: ['old-role'],
    resources: ['old-resource'],
    applications: ['old-application'],
    connectors: ['old-connector'],
  });
  expect(privateCleanupCalls).toEqual([
    {
      resourceId: 'new-resources',
      applicationIds: ['new-application-global', 'new-application-native'],
    },
  ]);
  expect(mutations.filter(({ method }) => method === 'PATCH')).toEqual([
    {
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { branding: { logoUrl: 'before' }, signIn: { methods: [] } },
      expectedStatuses: [200],
      responseKind: 'object',
    },
  ]);
  mutations.splice(0);
  await expect(
    withManagementProvisioningFixtureRuntime(input, async () => {
      rows.roles?.push({ id: 'failed-roles' });
      rows.connectors?.push({ id: 'failed-connectors' });
      rows.resources?.push({
        id: 'failed-resources',
        name: 'Box-AI Native Session API',
        indicator: 'https://core.example/api',
        accessTokenTtl: 300,
        scopes: [
          {
            id: 'failed-scope',
            name: 'session:exchange',
            description: 'Managed by the Box-AI deployment for native session exchange',
          },
        ],
      });
      rows.applications?.push(
        {
          id: 'failed-application-global',
          name: 'Box-AI',
          description: 'Managed by the Box-AI deployment',
          type: 'Traditional',
        },
        {
          id: 'failed-application-native',
          name: 'Box-AI Native',
          description: 'Managed by the Box-AI deployment as a native public client',
          type: 'Native',
        }
      );
    })
  ).rejects.toThrow('Invalid Management provisioning fixture cleanup');
  expect(mutations.map(({ method, path }) => `${method} ${path}`)).toEqual(
    expect.arrayContaining([
      'DELETE roles/failed-roles',
      'DELETE connectors/failed-connectors',
      'PATCH sign-in-exp',
    ])
  );
});
test.each([
  { path: 'applications', row: { id: 'existing', name: 'Box-AI' } },
  {
    path: 'applications',
    row: { id: 'existing', description: 'Managed by the Box-AI deployment' },
  },
  { path: 'resources', row: { id: 'existing', name: 'Box-AI Native Session API' } },
  { path: 'resources', row: { id: 'existing', indicator: 'https://core.example/api' } },
  { path: 'roles', row: { id: 'existing', name: 'Box-AI Native Session User' } },
  { path: 'connectors', row: { id: 'existing', connectorId: 'google-universal' } },
])(
  'refuses a preexisting selected provisioning namespace before running the lease body: $path $row',
  async ({ path: occupiedPath, row }) => {
    let bodyCalled = false;
    const request = async ({ path }: Phase2AdminRequest): Promise<unknown> => {
      if (path === occupiedPath) {
        return [row];
      }
      if (path === 'connectors/existing') {
        return row;
      }
      if (path === 'sign-in-exp') {
        return { signIn: { methods: [] } };
      }
      return [];
    };
    await expect(
      withManagementProvisioningFixtureRuntime(
        {
          target: {
            label: 'candidate',
            coreUrl: 'https://core.example/',
            adminUrl: 'https://admin.example/',
          },
          bearer: 'private-management-bearer',
          globalEnvironment: { BOX_AI_GOOGLE_CLIENT_ID: 'configured' },
          chinaNativeEnvironment: { BOX_AI_WECHAT_CHANNELS: 'native' },
          withForeignManagementControls: async (use) =>
            use({
              userId: 'foreign-user',
              connectorId: 'foreign-connector',
              applicationId: 'foreign-application',
            }),
          cleanupProvisioningRows: async () => {
            await Promise.resolve();
          },
          request,
        },
        async () => {
          bodyCalled = true;
        }
      )
    ).rejects.toThrow('Invalid Management provisioning fixture runtime');
    expect(bodyCalled).toBe(false);
  }
);
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
