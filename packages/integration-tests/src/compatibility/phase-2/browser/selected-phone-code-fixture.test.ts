/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Fake Management state exercises setup and reverse compensation. */
import type { Phase2AdminRequest, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedPhoneCodeFixture } from './selected-phone-code-fixture.js';

const fixture = {
  public: { allocationId: 'allocation' },
  status: {
    client: { id: 'client' },
    resource: { id: 'resource', scopeName: 'read:profile' },
  },
} as unknown as ProvisionedPhase2Fixture;

test('copies the private connector configuration into Management and compensates owned state', async () => {
  const calls: Phase2AdminRequest[] = [];
  const originalSie = {
    branding: { light: {} },
    signUp: { identifiers: [], password: false, verify: false },
    signIn: { methods: [{ identifier: 'username', password: true }] },
  };
  let userCounter = 0;
  let registrationPhone = '';
  let registrationOwners: string[] = [];
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return originalSie;
    }
    if (input.method === 'GET' && input.path === 'applications/client') {
      return { id: 'client', type: 'SPA', oidcClientMetadata: { redirectUris: ['old'] } };
    }
    if (input.method === 'GET' && input.path === 'resources') {
      return [
        { id: 'resource', scopes: [{ id: 'scope', resourceId: 'resource', name: 'read:profile' }] },
      ];
    }
    if (input.method === 'GET' && input.path === 'users/registered') {
      return { id: 'registered', primaryPhone: registrationPhone };
    }
    if (input.method === 'GET' && input.path === 'users') {
      return registrationOwners.map((id) => ({ id, primaryPhone: registrationPhone }));
    }
    if (input.method === 'GET' && input.path === 'users/owner/roles') {
      return [{ id: 'role', type: 'User', isDefault: true }];
    }
    if (input.method === 'PATCH' && input.path === 'applications/client') {
      return { oidcClientMetadata: (input.body as Record<string, unknown>).oidcClientMetadata };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      const body = input.body as Record<string, unknown>;
      return body === originalSie ? originalSie : { ...originalSie, ...body };
    }
    if (input.method === 'POST' && input.path === 'roles') {
      return { id: 'role' };
    }
    if (input.method === 'POST' && input.path === 'connectors') {
      return { id: 'connector', connectorId: 'aliyun-short-message-service' };
    }
    if (input.method === 'POST' && input.path === 'users') {
      userCounter += 1;
      return {
        id: ['owner', 'control-owner', 'collision-owner', 'suspended'][userCounter - 1],
        primaryPhone: (input.body as Record<string, unknown>).primaryPhone,
        isSuspended: false,
      };
    }
    if (input.method === 'PATCH' && input.path === 'users/suspended/is-suspended') {
      return {
        id: 'suspended',
        isSuspended: true,
      };
    }
    if (input.method === 'DELETE' && input.path === 'users/registered') {
      registrationOwners = [];
      return 204;
    }
    return input.responseKind === 'status' ? 204 : {};
  };
  const privateConfiguration = Object.freeze({
    accessKeyId: 'private-id',
    accessKeySecret: 'private-secret',
    signName: 'Aster',
    templates: ['SignIn', 'Register', 'ForgotPassword', 'Generic'].map((usageType) => ({
      usageType: usageType as 'SignIn' | 'Register' | 'ForgotPassword' | 'Generic',
      templateCode: `${usageType}-template`,
    })),
    toJSON: () => {
      throw new Error('lease object must not be serialized');
    },
  });
  await expect(
    withSelectedPhoneCodeFixture({
      fixture,
      request,
      browser: { clientId: 'client', redirectUri: 'https://core.example/demo-app' },
      lease: {
        configuration: privateConfiguration,
        arm: async () => {},
        takeCode: async () => '123456',
      },
      use: async (selected) => {
        registrationPhone = selected.registrationPhone;
        registrationOwners = ['registered'];
        await selected.captureRegisteredUser('registered');
        return 'used';
      },
    })
  ).resolves.toBe('used');
  const connector = calls.find(({ method, path }) => method === 'POST' && path === 'connectors');
  expect(connector?.body).toEqual({
    connectorId: 'aliyun-short-message-service',
    config: {
      accessKeyId: 'private-id',
      accessKeySecret: 'private-secret',
      signName: 'Aster',
      templates: privateConfiguration.templates,
    },
  });
  expect(
    calls.filter(({ method, path }) => method === 'DELETE' && path.startsWith('users/'))
  ).toHaveLength(5);
  expect(calls).toContainEqual({
    method: 'PATCH',
    path: 'users/suspended/is-suspended',
    body: { isSuspended: true },
    expectedStatuses: [200],
    responseKind: 'object',
  });
  expect(calls).toContainEqual({
    method: 'GET',
    path: 'users/owner/roles',
    query: { page: '1', page_size: '100' },
    expectedStatuses: [200],
    responseKind: 'array',
  });
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ method: 'DELETE', path: 'connectors/connector' }),
      expect.objectContaining({ method: 'DELETE', path: 'roles/role' }),
    ])
  );
});

test.each([
  { name: 'one exact owner', owners: ['registered'], deleted: true, error: 'use', role: true },
  {
    name: 'ambiguous owners',
    owners: ['registered-a', 'registered-b'],
    deleted: false,
    error: 'cleanup-discover-registered-ambiguous+registered-owner-remains',
    role: true,
  },
  { name: 'missing default role', owners: [], deleted: false, error: 'assign-role', role: false },
])('handles an uncaptured registration with $name', async ({ owners, deleted, error, role }) => {
  const calls: Phase2AdminRequest[] = [];
  let userCounter = 0;
  let useStarted = false;
  let currentOwners = [...owners];
  let registrationPhone = '';
  const originalSie = {
    branding: {},
    signUp: { identifiers: [] },
    signIn: { methods: [{ identifier: 'username' }] },
  };
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return originalSie;
    }
    if (input.method === 'GET' && input.path === 'applications/client') {
      return { id: 'client', type: 'SPA', oidcClientMetadata: { redirectUris: ['old'] } };
    }
    if (input.method === 'GET' && input.path === 'resources') {
      return [
        { id: 'resource', scopes: [{ id: 'scope', resourceId: 'resource', name: 'read:profile' }] },
      ];
    }
    if (input.method === 'GET' && input.path === 'users') {
      return useStarted ? currentOwners.map((id) => ({ id, primaryPhone: registrationPhone })) : [];
    }
    if (input.method === 'GET' && input.path === 'users/fixture-1/roles') {
      return role ? [{ id: 'role', type: 'User', isDefault: true }] : [];
    }
    if (input.method === 'PATCH' && input.path === 'applications/client') {
      return { oidcClientMetadata: (input.body as Record<string, unknown>).oidcClientMetadata };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      return { ...originalSie, ...(input.body as Record<string, unknown>) };
    }
    if (input.method === 'POST' && input.path === 'roles') {
      return { id: 'role' };
    }
    if (input.method === 'POST' && input.path === 'connectors') {
      return { id: 'connector', connectorId: 'aliyun-short-message-service' };
    }
    if (input.method === 'POST' && input.path === 'users') {
      userCounter += 1;
      return {
        id: `fixture-${userCounter}`,
        primaryPhone: Reflect.get(input.body as Record<string, unknown>, 'primaryPhone'),
        isSuspended: false,
      };
    }
    if (input.method === 'PATCH' && input.path === 'users/fixture-4/is-suspended') {
      return { id: 'fixture-4', isSuspended: true };
    }
    if (input.method === 'DELETE' && input.path === 'users/registered') {
      currentOwners = [];
      return 204;
    }
    return input.responseKind === 'status' ? 204 : {};
  };
  const operation = withSelectedPhoneCodeFixture({
    fixture,
    request,
    browser: { clientId: 'client', redirectUri: 'https://core.example/demo-app' },
    lease: {
      configuration: {
        accessKeyId: 'id',
        accessKeySecret: 'secret',
        signName: 'Aster',
        templates: ['SignIn', 'Register', 'ForgotPassword', 'Generic'].map((usageType) => ({
          usageType: usageType as 'SignIn' | 'Register' | 'ForgotPassword' | 'Generic',
          templateCode: `${usageType}-template`,
        })),
      },
      arm: async () => {},
      takeCode: async () => '123456',
    },
    use: async (selected) => {
      registrationPhone = selected.registrationPhone;
      useStarted = true;
      throw new Error('private failure before capture');
    },
  });
  await expect(operation).rejects.toThrow(`Selected phone code fixture failed: ${error}`);
  expect(calls.some(({ method, path }) => method === 'DELETE' && path === 'users/registered')).toBe(
    deleted
  );
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
