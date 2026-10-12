/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Mutable in-memory catalogs make cleanup order observable. */
import type { Phase2AdminRequest } from '../fixtures.js';

import {
  createManagementOwnershipRefusalObserver,
  createManagementProvisioningFixtureRuntime,
  withManagementProvisioningFixtureRuntime,
} from './management-provisioning-fixture-runtime.js';

test('binds endpoints and bearer and repairs only the exact China Native relation', async () => {
  const requests: Array<{ method: string; path: string }> = [];
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
    { method: 'DELETE', path: 'roles/role/scopes/scope' },
  ]);
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
  const observe = createManagementOwnershipRefusalObserver(
    async ({ method, path }) => {
      if (path === 'sign-in-exp') {
        return { signIn: { methods: [] } };
      }
      if (method === 'POST') {
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
    async () => true
  );

  await expect(observe()).resolves.toBe(true);
  expect(cleanupCompleted).toBe(true);
});
test('lease removes only newly provisioned rows and restores connector and experience state', async () => {
  const rows: Record<string, Array<Record<string, unknown>>> = {
    roles: [{ id: 'old-role' }],
    resources: [{ id: 'old-resource' }],
    applications: [{ id: 'old-application' }],
    connectors: [{ id: 'old-connector', config: { clientId: 'before' } }],
  };
  const mutations: Array<{ method: string; path: string; body?: unknown }> = [];
  const rejectedDeletion = 'roles/failed-roles';
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
    chinaNativeEnvironment: {},
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
    request,
  } as const;
  await withManagementProvisioningFixtureRuntime(input, async () => {
    for (const kind of Object.keys(rows)) {
      rows[kind]?.push({ id: `new-${kind}` });
    }
  });
  expect(
    Object.fromEntries(Object.entries(rows).map(([key, value]) => [key, value.map(({ id }) => id)]))
  ).toEqual({
    roles: ['old-role'],
    resources: ['old-resource'],
    applications: ['old-application'],
    connectors: ['old-connector'],
  });
  expect(mutations.filter(({ method }) => method === 'PATCH')).toEqual([
    {
      method: 'PATCH',
      path: 'connectors/old-connector',
      body: { config: { clientId: 'before' } },
      expectedStatuses: [200],
      responseKind: 'object',
    },
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
      for (const kind of Object.keys(rows)) {
        rows[kind]?.push({ id: `failed-${kind}` });
      }
    })
  ).rejects.toThrow('Invalid Management provisioning fixture cleanup');
  expect(mutations.map(({ method, path }) => `${method} ${path}`)).toEqual(
    expect.arrayContaining([
      'DELETE roles/failed-roles',
      'DELETE resources/failed-resources',
      'DELETE applications/failed-applications',
      'DELETE connectors/failed-connectors',
      'PATCH connectors/old-connector',
      'PATCH sign-in-exp',
    ])
  );
});
test('refuses a preexisting selected provisioning namespace before running the lease body', async () => {
  let bodyCalled = false;
  // This fake is local so the test's occupied namespace remains explicit.
  // eslint-disable-next-line unicorn/consistent-function-scoping
  const request = async ({ path }: Phase2AdminRequest): Promise<unknown> => {
    if (path === 'applications') {
      return [{ id: 'existing', name: 'Box-AI' }];
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
        chinaNativeEnvironment: {},
        withForeignManagementControls: async (use) =>
          use({
            userId: 'foreign-user',
            connectorId: 'foreign-connector',
            applicationId: 'foreign-application',
          }),
        request,
      },
      async () => {
        bodyCalled = true;
      }
    )
  ).rejects.toThrow('Invalid Management provisioning fixture runtime');
  expect(bodyCalled).toBe(false);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
