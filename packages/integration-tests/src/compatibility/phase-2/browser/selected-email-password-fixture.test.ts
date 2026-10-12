/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment -- Fake Management state records setup and restoration. */
import type { Phase2AdminRequest, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  selectBrowserRedirectUris,
  withSelectedEmailPasswordFixture,
} from './selected-email-password-fixture.js';

const fixture = {
  public: { allocationId: 'allocation' },
  status: {
    resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
  },
} as ProvisionedPhase2Fixture;
const withRoleContract =
  (
    request: (input: Phase2AdminRequest) => Promise<unknown>,
    observe?: (input: Phase2AdminRequest) => void
  ) =>
  async (input: Phase2AdminRequest): Promise<unknown> => {
    observe?.(input);
    if (input.path === 'resources' && input.query?.includeScopes === 'true') {
      return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
    }
    if (input.path === 'roles' && input.method === 'POST') {
      return { id: 'email-role', name: 'common-email-allocation', type: 'User', isDefault: false };
    }
    if (input.path === 'roles/email-role/scopes') {
      return [{ id: 'scope', name: 'read:profile', resourceId: 'resource' }];
    }
    if (input.path === 'roles/email-role/users') {
      return 201;
    }
    if (input.path === 'users/email-user/roles' || input.path === 'users/owned-user/roles') {
      return [{ id: 'email-role', type: 'User' }];
    }
    if (input.path === 'roles/email-role' && input.method === 'DELETE') {
      return 204;
    }
    return request(input);
  };

test('creates an independent email user and restores username methods', async () => {
  const calls: Phase2AdminRequest[] = [];
  const roleCalls: Phase2AdminRequest[] = [];
  let methods: unknown = [
    { identifier: 'username', password: true, verificationCode: false, isPasswordPrimary: true },
  ];
  const previousBranding = {
    darkLogoUrl: 'https://logto.io/logo-dark.svg',
    logoUrl: 'https://logto.io/logo.svg',
  };
  let branding: unknown = previousBranding;
  let applicationMetadata = {
    redirectUris: ['http://localhost:3001/demo-app'],
    postLogoutRedirectUris: [] as string[],
  };
  const request = async (request: Phase2AdminRequest) => {
    calls.push(request);
    if (request.path === 'applications/browser-client' && request.method === 'GET') {
      return {
        id: 'browser-client',
        type: 'SPA',
        oidcClientMetadata: {
          postLogoutRedirectUris: applicationMetadata.postLogoutRedirectUris,
          redirectUris: applicationMetadata.redirectUris,
        },
      };
    }
    if (request.path === 'applications/browser-client') {
      applicationMetadata = (request.body as { oidcClientMetadata: typeof applicationMetadata })
        .oidcClientMetadata;
      return {
        id: 'browser-client',
        type: 'SPA',
        oidcClientMetadata: {
          postLogoutRedirectUris: applicationMetadata.postLogoutRedirectUris,
          redirectUris: applicationMetadata.redirectUris,
        },
      };
    }
    if (request.method === 'GET' && calls.length === 1) {
      return { signIn: { methods }, branding };
    }
    if (request.method === 'GET') {
      return { signIn: { methods }, branding };
    }
    if (request.path === 'sign-in-exp') {
      methods = (request.body as { signIn: { methods: unknown } }).signIn.methods;
      branding = (request.body as { branding: unknown }).branding;
      return { signIn: { methods }, branding };
    }
    if (request.method === 'POST') {
      return {
        id: 'email-user',
        primaryEmail: 'common-email-allocation@example.invalid',
        hasPassword: true,
        isSuspended: false,
      };
    }
    return 204;
  };
  const result = await withSelectedEmailPasswordFixture({
    fixture,
    request: withRoleContract(request, (call) => roleCalls.push(call)),
    getPassword: () => 'private-independent',
    browser: {
      clientId: 'browser-client',
      redirectUri: 'http://localhost:3311/demo-app',
      additionalRedirectUris: ['http://localhost:3001/callback'],
    },
    use: async (identity) => identity,
  });
  expect(result).toEqual({
    id: 'email-user',
    primaryEmail: 'common-email-allocation@example.invalid',
    isSuspended: false,
    browser: {
      clientId: 'browser-client',
      redirectUri: 'http://localhost:3311/demo-app',
    },
  });
  expect(calls).toContainEqual(
    expect.objectContaining({
      method: 'POST',
      path: 'users',
      body: {
        primaryEmail: 'common-email-allocation@example.invalid',
        password: 'private-independent',
      },
    })
  );
  expect(calls).toContainEqual(
    expect.objectContaining({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: {
        signIn: {
          methods: [
            {
              identifier: 'username',
              password: true,
              verificationCode: false,
              isPasswordPrimary: true,
            },
          ],
        },
        branding: previousBranding,
      },
    })
  );
  expect(calls).toContainEqual(
    expect.objectContaining({ method: 'DELETE', path: 'users/email-user' })
  );
  expect(calls).toContainEqual(
    expect.objectContaining({
      method: 'PATCH',
      path: 'applications/browser-client',
      body: {
        oidcClientMetadata: {
          redirectUris: ['http://localhost:3311/demo-app', 'http://localhost:3001/callback'],
          postLogoutRedirectUris: [],
        },
      },
    })
  );
  expect(applicationMetadata.redirectUris).toEqual(['http://localhost:3001/demo-app']);
  expect(branding).toEqual(previousBranding);
  expect(roleCalls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        method: 'GET',
        path: 'resources',
        query: { includeScopes: 'true' },
      }),
      expect.objectContaining({
        method: 'POST',
        path: 'roles',
        body: expect.objectContaining({ type: 'User', isDefault: false, scopeIds: ['scope'] }),
      }),
      expect.objectContaining({ method: 'GET', path: 'roles/email-role/scopes' }),
      expect.objectContaining({
        method: 'POST',
        path: 'roles/email-role/users',
        body: { userIds: ['email-user'] },
      }),
      expect.objectContaining({ method: 'GET', path: 'users/email-user/roles' }),
      expect.objectContaining({ method: 'DELETE', path: 'roles/email-role' }),
    ])
  );
});

test('keeps the existing single browser callback contract unchanged', () => {
  expect(selectBrowserRedirectUris('http://localhost:3311/demo-app')).toEqual([
    'http://localhost:3311/demo-app',
  ]);
  expect(() =>
    selectBrowserRedirectUris('http://localhost:3311/demo-app', ['http://localhost:3311/demo-app'])
  ).toThrow('Invalid selected email password fixture');
});

test('deletes an owned user when the create response is otherwise malformed', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request = async (request: Phase2AdminRequest) => {
    calls.push(request);
    if (request.method === 'GET' && calls.length === 1) {
      return { signIn: { methods: ['previous'] }, branding: {} };
    }
    if (request.method === 'GET') {
      return {
        signIn: {
          methods: (calls.at(-2)?.body as { signIn: { methods: unknown } }).signIn.methods,
        },
        branding: (calls.at(-2)?.body as { branding: unknown }).branding,
      };
    }
    if (request.path === 'sign-in-exp') {
      return {
        signIn: {
          methods:
            request.body && (request.body as { signIn: { methods: unknown } }).signIn.methods,
        },
        branding: (request.body as { branding: unknown }).branding,
      };
    }
    if (request.method === 'POST') {
      return {
        id: 'owned-malformed',
        primaryEmail: 'wrong@example.invalid',
        hasPassword: true,
        isSuspended: false,
      };
    }
    return 204;
  };
  await expect(
    withSelectedEmailPasswordFixture({
      fixture,
      request: withRoleContract(request),
      getPassword: () => 'private-independent',
      use: async () => null,
    })
  ).rejects.toThrow(
    'Common email password fixture failed: primary-post-user;cleanup-none;flow-none'
  );
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'users/owned-malformed' });
});

test('retains fixed body and cleanup stages without exposing raw errors', async () => {
  const calls: Phase2AdminRequest[] = [];
  let signInPatchCount = 0;
  const request = async (request: Phase2AdminRequest) => {
    calls.push(request);
    if (request.method === 'GET' && calls.length === 1) {
      return { signIn: { methods: ['previous'] }, branding: {} };
    }
    if (request.method === 'GET') {
      return {
        signIn: {
          methods: (calls.at(-2)?.body as { signIn: { methods: unknown } }).signIn.methods,
        },
        branding: (calls.at(-2)?.body as { branding: unknown }).branding,
      };
    }
    if (request.path === 'sign-in-exp') {
      signInPatchCount += 1;
      if (signInPatchCount === 2) {
        throw new Error('restore failed');
      }
      return {
        signIn: { methods: (request.body as { signIn: { methods: unknown } }).signIn.methods },
        branding: (request.body as { branding: unknown }).branding,
      };
    }
    if (request.method === 'POST') {
      return {
        id: 'owned-user',
        primaryEmail: 'common-email-allocation@example.invalid',
        hasPassword: true,
        isSuspended: false,
      };
    }
    return 204;
  };
  let failure: unknown;
  try {
    await withSelectedEmailPasswordFixture({
      fixture,
      request: withRoleContract(request),
      getPassword: () => 'private-independent',
      use: async () => {
        throw new Error('private body detail');
      },
    });
  } catch (error: unknown) {
    failure = error;
  }
  expect(failure).toEqual(
    new TypeError('Common email password fixture failed: primary-use;cleanup-restore-sie;flow-none')
  );
  expect(String(failure)).not.toContain('private body detail');
  expect(String(failure)).not.toContain('restore failed');
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'users/owned-user' });
});

test('restores sign-in methods when user creation transport fails', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request = async (request: Phase2AdminRequest) => {
    calls.push(request);
    if (request.method === 'GET' && calls.length === 1) {
      return { signIn: { methods: ['previous'] }, branding: {} };
    }
    if (request.method === 'GET') {
      return {
        signIn: {
          methods: (calls.at(-2)?.body as { signIn: { methods: unknown } }).signIn.methods,
        },
        branding: (calls.at(-2)?.body as { branding: unknown }).branding,
      };
    }
    if (request.path === 'sign-in-exp') {
      return {
        signIn: { methods: (request.body as { signIn: { methods: unknown } }).signIn.methods },
        branding: (request.body as { branding: unknown }).branding,
      };
    }
    if (request.method === 'POST') {
      throw new Error('create transport failed');
    }
    return 204;
  };
  await expect(
    withSelectedEmailPasswordFixture({
      fixture,
      request: withRoleContract(request),
      getPassword: () => 'private-independent',
      use: async () => null,
    })
  ).rejects.toThrow(
    'Common email password fixture failed: primary-post-user;cleanup-none;flow-none'
  );
  expect(calls).toContainEqual(expect.objectContaining({ method: 'PATCH', path: 'sign-in-exp' }));
  expect(calls.at(-1)).toMatchObject({ method: 'GET', path: 'sign-in-exp' });
  expect(calls.some(({ method }) => method === 'DELETE')).toBe(false);
});

test('requires an ordered Management readback before creating the email user', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request = async (request: Phase2AdminRequest) => {
    calls.push(request);
    if (request.method === 'GET' && calls.length === 1) {
      return { signIn: { methods: ['previous'] }, branding: {} };
    }
    if (request.method === 'GET') {
      const getCount = calls.filter(({ method }) => method === 'GET').length;
      return getCount === 2
        ? { signIn: { methods: ['normalized-differently'] }, branding: {} }
        : { signIn: { methods: ['previous'] }, branding: {} };
    }
    if (request.path === 'sign-in-exp') {
      return {
        signIn: { methods: (request.body as { signIn: { methods: unknown } }).signIn.methods },
        branding: (request.body as { branding: unknown }).branding,
      };
    }
    throw new Error('user creation must not run');
  };
  await expect(
    withSelectedEmailPasswordFixture({
      fixture,
      request: withRoleContract(request),
      getPassword: () => 'private-independent',
      use: async () => null,
    })
  ).rejects.toThrow(
    'Common email password fixture failed: primary-read-sie;cleanup-none;flow-none'
  );
  expect(calls.some(({ method }) => method === 'POST')).toBe(false);
  expect(calls.at(-1)).toMatchObject({ method: 'GET', path: 'sign-in-exp' });
});

test('restores browser metadata when the target redirect PATCH acknowledgement is malformed', async () => {
  const applicationPatches: unknown[] = [];
  let signInMethods: unknown = ['previous'];
  const previous = { redirectUris: ['http://localhost:3001/demo-app'], postLogoutRedirectUris: [] };
  const request = async (request: Phase2AdminRequest) => {
    if (request.path === 'sign-in-exp' && request.method === 'GET') {
      return { signIn: { methods: signInMethods }, branding: {} };
    }
    if (request.path === 'sign-in-exp') {
      signInMethods = (request.body as { signIn: { methods: unknown } }).signIn.methods;
      return { signIn: { methods: signInMethods }, branding: {} };
    }
    if (request.path === 'applications/browser-client' && request.method === 'GET') {
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: previous };
    }
    if (request.path === 'applications/browser-client') {
      applicationPatches.push(request.body);
      return applicationPatches.length === 1
        ? { id: 'browser-client', type: 'SPA', oidcClientMetadata: { redirectUris: [] } }
        : { id: 'browser-client', type: 'SPA', oidcClientMetadata: previous };
    }
    throw new Error('user create must not run');
  };
  await expect(
    withSelectedEmailPasswordFixture({
      fixture,
      request: withRoleContract(request),
      getPassword: () => 'private-independent',
      browser: {
        clientId: 'browser-client',
        redirectUri: 'http://localhost:3311/demo-app',
      },
      use: async () => null,
    })
  ).rejects.toThrow(
    'Common email password fixture failed: primary-patch-app;cleanup-none;flow-none'
  );
  expect(applicationPatches).toEqual([
    {
      oidcClientMetadata: {
        redirectUris: ['http://localhost:3311/demo-app'],
        postLogoutRedirectUris: [],
      },
    },
    { oidcClientMetadata: previous },
  ]);
});

test('rejects a browser restore acknowledgement that was not persisted after other cleanup', async () => {
  const calls: Phase2AdminRequest[] = [];
  let methods: unknown = ['previous'];
  const previous = { redirectUris: ['http://localhost:3001/demo-app'], postLogoutRedirectUris: [] };
  const target = { redirectUris: ['http://localhost:3311/demo-app'], postLogoutRedirectUris: [] };
  let metadata = previous;
  let applicationPatchCount = 0;
  const request = async (request: Phase2AdminRequest) => {
    calls.push(request);
    if (request.path === 'sign-in-exp' && request.method === 'GET') {
      return { signIn: { methods }, branding: {} };
    }
    if (request.path === 'sign-in-exp') {
      methods = (request.body as { signIn: { methods: unknown } }).signIn.methods;
      return { signIn: { methods }, branding: {} };
    }
    if (request.path === 'applications/browser-client' && request.method === 'GET') {
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: metadata };
    }
    if (request.path === 'applications/browser-client') {
      applicationPatchCount += 1;
      if (applicationPatchCount === 1) {
        metadata = target;
      }
      return {
        id: 'browser-client',
        type: 'SPA',
        oidcClientMetadata: applicationPatchCount === 1 ? target : previous,
      };
    }
    if (request.method === 'POST') {
      return {
        id: 'email-user',
        primaryEmail: 'common-email-allocation@example.invalid',
        hasPassword: true,
        isSuspended: false,
      };
    }
    return 204;
  };
  await expect(
    withSelectedEmailPasswordFixture({
      fixture,
      request: withRoleContract(request),
      getPassword: () => 'private-independent',
      browser: { clientId: 'browser-client', redirectUri: target.redirectUris[0]! },
      use: async () => null,
    })
  ).rejects.toThrow(
    'Common email password fixture failed: primary-none;cleanup-restore-app-read;flow-none'
  );
  expect(calls).toContainEqual(
    expect.objectContaining({ method: 'DELETE', path: 'users/email-user' })
  );
  expect(calls).toContainEqual(
    expect.objectContaining({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { signIn: { methods: ['previous'] }, branding: {} },
    })
  );
  expect(
    calls.filter(({ method, path }) => method === 'GET' && path === 'applications/browser-client')
  ).toHaveLength(3);
});
/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment */
