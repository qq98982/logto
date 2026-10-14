/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Fake Management state records setup and compensation. */
import { createHash } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import {
  createReferencePhase2AdminRequest,
  type Phase2AdminRequest,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import { withSelectedEmailCodeFixture } from './selected-email-code-fixture.js';

const previousMethods = Object.freeze([
  Object.freeze({
    identifier: 'username',
    password: true,
    verificationCode: false,
    isPasswordPrimary: true,
  }),
]);
const signUp = Object.freeze({ identifiers: [], password: false, verify: false });
const previousBranding = Object.freeze({
  dark: Object.freeze({ logoUrl: 'https://legacy.invalid/logo.svg', name: 'Legacy' }),
  light: Object.freeze({ name: 'Legacy', logoUrl: 'https://legacy.invalid/logo.svg' }),
});
const selectedMethods = Object.freeze([
  previousMethods[0],
  Object.freeze({
    identifier: 'email',
    password: false,
    verificationCode: true,
    isPasswordPrimary: false,
  }),
]);
const fixture = {
  public: { allocationId: 'allocation' },
  status: {
    resource: { id: 'resource-id', scopeName: 'read:profile' },
  },
} as unknown as ProvisionedPhase2Fixture;

const namespaceMarker = (namespace: string) =>
  `common-email-code-${createHash('sha256')
    .update(`allocation:${namespace}`)
    .digest('hex')
    .slice(0, 16)}`;

const createRequest = (
  options: Readonly<{
    initialGetFails?: boolean;
    initialPatchThrows?: boolean;
    initialPatchMalformedAcknowledgement?: boolean;
    malformedCreate?: boolean;
    restoreFails?: boolean;
    restoreMalformedAcknowledgement?: boolean;
    reverseRestoredBrandingKeys?: boolean;
    scopeCount?: number;
    userCreateFails?: boolean;
    userDeleteFails?: boolean;
    userRoles?: readonly unknown[];
    marker?: string;
  }> = {}
) => {
  const calls: Phase2AdminRequest[] = [];
  let methods: unknown = previousMethods;
  let branding: unknown = previousBranding;
  let patchCount = 0;
  const marker = options.marker ?? 'common-email-code-allocation';
  const role = {
    id: 'email-code-role',
    name: marker,
    type: 'User',
    isDefault: false,
  };
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (input.method === 'GET') {
      if (input.path === 'sign-in-exp' && options.initialGetFails) {
        throw new Error('private initial read failure');
      }
      if (input.path === 'resources') {
        return [
          {
            id: 'resource-id',
            scopes: Array.from({ length: options.scopeCount ?? 1 }, (_unused, index) => ({
              id: `scope-${index}`,
              resourceId: 'resource-id',
              name: 'read:profile',
            })),
          },
        ];
      }
      if (input.path === 'users/email-code-user/roles') {
        return options.userRoles ?? [role];
      }
      if (input.path === 'roles/email-code-role/scopes') {
        return [{ id: 'scope-0', resourceId: 'resource-id', name: 'read:profile' }];
      }
      if (options.reverseRestoredBrandingKeys && patchCount === 2) {
        return {
          branding: {
            light: { logoUrl: 'https://legacy.invalid/logo.svg', name: 'Legacy' },
            dark: { name: 'Legacy', logoUrl: 'https://legacy.invalid/logo.svg' },
          },
          signUp,
          signIn: { methods },
        };
      }
      return { branding, signUp, signIn: { methods } };
    }
    if (input.path === 'sign-in-exp') {
      patchCount += 1;
      methods = (input.body as { signIn: { methods: unknown } }).signIn.methods;
      branding = (input.body as { branding: unknown }).branding;
      if (patchCount === 1 && options.initialPatchThrows) {
        throw new Error('initial patch acknowledgement failed');
      }
      if (patchCount === 1 && options.initialPatchMalformedAcknowledgement) {
        return { branding: previousBranding, signUp, signIn: { methods } };
      }
      if (patchCount === 2 && options.restoreFails) {
        throw new Error('restore failed');
      }
      if (patchCount === 2 && options.restoreMalformedAcknowledgement) {
        return { branding: {}, signUp, signIn: { methods: selectedMethods } };
      }
      return { branding, signUp, signIn: { methods } };
    }
    if (input.method === 'POST' && input.path === 'roles') {
      return role;
    }
    if (input.method === 'POST' && input.path === 'roles/email-code-role/users') {
      return undefined;
    }
    if (input.method === 'POST' && input.path === 'users') {
      if (options.userCreateFails) {
        throw new Error('user create failed');
      }
      return {
        id: 'email-code-user',
        primaryEmail: options.malformedCreate
          ? 'wrong@example.invalid'
          : `${marker}@example.invalid`,
        hasPassword: false,
        isSuspended: false,
      };
    }
    if (
      input.method === 'DELETE' &&
      input.path === 'users/email-code-user' &&
      options.userDeleteFails
    ) {
      throw new Error('owned user delete failed');
    }
    return 204;
  };
  return { calls, request };
};

test('enables ordered email code sign-in while preserving signup and cleans owned state', async () => {
  const { calls, request } = createRequest();
  const result = await withSelectedEmailCodeFixture({
    fixture,
    request,
    use: async (identity) => identity,
  });
  expect(result).toEqual({
    id: 'email-code-user',
    primaryEmail: 'common-email-code-allocation@example.invalid',
    isSuspended: false,
  });
  expect(calls.find(({ method, path }) => method === 'GET' && path === 'resources')).toMatchObject({
    query: { includeScopes: 'true' },
  });
  expect(
    calls.find(({ method, path }) => method === 'PATCH' && path === 'sign-in-exp')
  ).toMatchObject({
    method: 'PATCH',
    path: 'sign-in-exp',
    body: { branding: {}, signIn: { methods: selectedMethods } },
  });
  expect(calls.find(({ method, path }) => method === 'POST' && path === 'users')).toMatchObject({
    method: 'POST',
    path: 'users',
    body: { primaryEmail: 'common-email-code-allocation@example.invalid' },
  });
  expect(calls.at(-4)).toMatchObject({
    method: 'PATCH',
    path: 'sign-in-exp',
    body: { branding: previousBranding, signIn: { methods: previousMethods } },
  });
  expect(calls.at(-3)).toMatchObject({ method: 'GET', path: 'sign-in-exp' });
  expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test('isolates admitted namespaces while preserving captured cleanup and body errors', async () => {
  const observed: string[] = [];
  for (const namespace of ['logout-accepted-rp', 'logout-rejected-rp', 'logout-account']) {
    const selected = namespaceMarker(namespace);
    const { calls, request } = createRequest({ marker: selected });
    const bodyError = new Error(`owned-${namespace}`);
    // eslint-disable-next-line no-await-in-loop
    const thrown = await withSelectedEmailCodeFixture({
      fixture,
      request,
      namespace,
      use: async (identity) => {
        observed.push(identity.primaryEmail);
        throw bodyError;
      },
    }).catch((error: unknown) => error);
    expect(thrown).toMatchObject({
      message: 'Common email code fixture failed: primary-use;cleanup-none',
    });
    expect(calls.find(({ method, path }) => method === 'POST' && path === 'roles')).toMatchObject({
      body: { name: selected },
    });
    expect(calls).toContainEqual({
      method: 'POST',
      path: 'users',
      body: { primaryEmail: `${selected}@example.invalid` },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
  }
  expect(new Set(observed).size).toBe(3);
});

test.each(['', 'UPPER', 'starts_with', 'a'.repeat(65)])(
  'rejects invalid namespace %s before Management use',
  async (namespace) => {
    const { calls, request } = createRequest();
    await expect(
      withSelectedEmailCodeFixture({ fixture, request, namespace, use: async () => true })
    ).rejects.toThrow('Invalid selected email code fixture');
    expect(calls).toEqual([]);
  }
);

test('accepts inherited roles while requiring one valid owned role', async () => {
  const inheritedRoles = [
    { id: 'default-role', type: 'User', isDefault: true },
    { id: 'other-role', type: 'User', isDefault: false },
    { id: 'email-code-role', type: 'User', isDefault: false },
  ];
  const { calls, request } = createRequest({ userRoles: inheritedRoles });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async (identity) => identity })
  ).resolves.toMatchObject({ id: 'email-code-user' });
  expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test.each([
  ['missing owned role', [{ id: 'default-role', type: 'User', isDefault: true }]],
  [
    'duplicate owned role',
    [
      { id: 'email-code-role', type: 'User', isDefault: false },
      { id: 'email-code-role', type: 'User', isDefault: false },
    ],
  ],
  [
    'owned role has wrong type',
    [{ id: 'email-code-role', type: 'MachineToMachine', isDefault: false }],
  ],
  ['owned role is default', [{ id: 'email-code-role', type: 'User', isDefault: true }]],
  [
    'inherited role is malformed',
    [
      { id: 'email-code-role', type: 'User', isDefault: false },
      { id: 'default-role', type: 'User' },
    ],
  ],
] as const)('rejects %s and cleans owned state', async (_name, userRoles) => {
  const { calls, request } = createRequest({ userRoles });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => true })
  ).rejects.toThrow('Common email code fixture failed: primary-read-user-roles;cleanup-none');
  expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test.each([
  ['empty 201', '', 201, false],
  ['Koa reason phrase 201', 'Created', 201, true],
  ['wrong status', '', 200, false],
] as const)(
  'requires the observed Reference role assignment response for %s',
  async (_name, body, status, accepted) => {
    const base = createRequest();
    let used = false;
    const target: TargetConfig = {
      label: 'oracle',
      coreUrl: 'http://127.0.0.1:4101',
      adminUrl: 'http://127.0.0.1:4102',
    };
    const request = createReferencePhase2AdminRequest(target, async (input, init) => {
      const url = new URL(String(input));
      const path = url.pathname.replace(/^\/api\//u, '');
      const method = (init?.method ?? 'GET') as Phase2AdminRequest['method'];
      const responseKind =
        method === 'GET'
          ? path === 'resources' || path.endsWith('/roles') || path.endsWith('/scopes')
            ? 'array'
            : 'object'
          : method === 'DELETE' || path.endsWith('/users')
            ? 'status'
            : 'object';
      const value = await base.request({
        method,
        path,
        ...(init?.body ? { body: JSON.parse(String(init.body)) as unknown } : {}),
        expectedStatuses: method === 'POST' && path.endsWith('/users') ? [201] : [200],
        responseKind,
      });
      if (method === 'POST' && path.endsWith('/users')) {
        return new Response(body, { status });
      }
      if (method === 'DELETE') {
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify(value), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const operation = withSelectedEmailCodeFixture({
      fixture,
      request,
      use: async () => {
        used = true;
        return true;
      },
    });
    if (accepted) {
      await expect(operation).resolves.toBe(true);
      expect(used).toBe(true);
    } else {
      await expect(operation).rejects.toThrow(
        'Common email code fixture failed: primary-assign-role;cleanup-none'
      );
      expect(used).toBe(false);
    }
  }
);

test('binds the owned browser redirect and restores it after the flow', async () => {
  const base = createRequest();
  let metadata = { redirectUris: ['http://localhost:3001/demo-app'], postLogoutRedirectUris: [] };
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.path === 'applications/browser-client' && input.method === 'GET') {
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: metadata };
    }
    if (input.path === 'applications/browser-client' && input.method === 'PATCH') {
      metadata = (input.body as { oidcClientMetadata: typeof metadata }).oidcClientMetadata;
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: metadata };
    }
    return base.request(input);
  };
  await withSelectedEmailCodeFixture({
    fixture,
    request,
    browser: { clientId: 'browser-client', redirectUri: 'https://core.example/demo-app' },
    use: async () => {
      expect(metadata.redirectUris).toEqual(['https://core.example/demo-app']);
      return null;
    },
  });
  expect(metadata.redirectUris).toEqual(['http://localhost:3001/demo-app']);
});

test('captures the owned user ID before rejecting a malformed create response', async () => {
  const { calls, request } = createRequest({ malformedCreate: true });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
  ).rejects.toThrow('Common email code fixture failed: primary-create-user;cleanup-none');
  expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test('accepts restored branding with reversed JSON object key order', async () => {
  const { request } = createRequest({ reverseRestoredBrandingKeys: true });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => 'used' })
  ).resolves.toBe('used');
});

test.each([0, 2])(
  'rejects %i matching selected resource scopes before mutation',
  async (scopeCount) => {
    const { calls, request } = createRequest({ scopeCount });
    await expect(
      withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
    ).rejects.toThrow(
      'Common email code fixture failed: primary-read-resource-scopes;cleanup-none'
    );
    expect(calls.some(({ method }) => method === 'POST')).toBe(false);
  }
);

test('deletes the owned role when user creation fails', async () => {
  const { calls, request } = createRequest({ userCreateFails: true });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
  ).rejects.toThrow('Common email code fixture failed: primary-create-user;cleanup-none');
  expect(calls.some(({ method, path }) => method === 'DELETE' && path.startsWith('users/'))).toBe(
    false
  );
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test('rejects a completed diagnostic when sign-in method restoration fails', async () => {
  const { calls, request } = createRequest({ restoreFails: true });
  await expect(
    withSelectedEmailCodeFixture({
      fixture,
      request,
      use: async () => ({ clientGateEvidence: true, complete: false }),
    })
  ).rejects.toThrow('Common email code fixture failed: cleanup-restore-sie');
  expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test('rejects a completed diagnostic when owned user deletion fails', async () => {
  const { calls, request } = createRequest({ userDeleteFails: true });
  await expect(
    withSelectedEmailCodeFixture({
      fixture,
      request,
      use: async () => ({ clientGateEvidence: true, complete: false }),
    })
  ).rejects.toThrow('Common email code fixture failed: cleanup-delete-user');
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test('deletes the owned user when the restoration acknowledgement is malformed', async () => {
  const { calls, request } = createRequest({ restoreMalformedAcknowledgement: true });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
  ).rejects.toThrow('Common email code fixture failed: cleanup-restore-sie');
  expect(calls.at(-3)).toMatchObject({ method: 'GET', path: 'sign-in-exp' });
  expect(calls.at(-2)).toMatchObject({ method: 'DELETE', path: 'users/email-code-user' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});

test('restores a committed initial patch when its acknowledgement throws', async () => {
  const { calls, request } = createRequest({ initialPatchThrows: true });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
  ).rejects.toThrow('Common email code fixture failed: primary-patch-sie-request;cleanup-none');
  expect(calls.some(({ method }) => method === 'POST')).toBe(false);
  expect(calls.at(-2)).toMatchObject({ method: 'PATCH', path: 'sign-in-exp' });
  expect(calls.at(-1)).toMatchObject({ method: 'GET', path: 'sign-in-exp' });
});

test('distinguishes a malformed patch response from a request failure', async () => {
  const { request } = createRequest({ initialPatchMalformedAcknowledgement: true });
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
  ).rejects.toThrow('Common email code fixture failed: primary-patch-sie-response;cleanup-none');
});

test('reports an initial Management read failure without leaking its private error', async () => {
  const { calls, request } = createRequest({ initialGetFails: true });
  const operation = withSelectedEmailCodeFixture({ fixture, request, use: async () => null });
  await expect(operation).rejects.toThrow(
    'Common email code fixture failed: primary-get-sie;cleanup-none'
  );
  await expect(operation).rejects.not.toThrow('private initial read failure');
  expect(calls).toHaveLength(1);
});

test('preserves a closed flow stage through fixture compensation', async () => {
  const { request } = createRequest();
  await expect(
    withSelectedEmailCodeFixture({
      fixture,
      request,
      use: async () => {
        throw new TypeError('Common email code stage failed: initialization');
      },
    })
  ).rejects.toThrow(
    'Common email code fixture failed: primary-use;cleanup-none;flow-initialization'
  );
});

test('restores methods without creating a user when selected methods read back differently', async () => {
  const calls: Phase2AdminRequest[] = [];
  let methods: unknown = previousMethods;
  let branding: unknown = previousBranding;
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (input.method === 'GET') {
      if (input.path === 'resources') {
        return [
          {
            id: 'resource-id',
            scopes: [{ id: 'scope-id', resourceId: 'resource-id', name: 'read:profile' }],
          },
        ];
      }
      if (input.path === 'roles/email-code-role/scopes') {
        return [{ id: 'scope-id', resourceId: 'resource-id', name: 'read:profile' }];
      }
      return {
        branding,
        signUp,
        signIn: { methods: calls.length === 6 ? previousMethods : methods },
      };
    }
    if (input.path === 'sign-in-exp') {
      methods = (input.body as { signIn: { methods: unknown } }).signIn.methods;
      branding = (input.body as { branding: unknown }).branding;
      return { branding, signUp, signIn: { methods } };
    }
    if (input.method === 'POST' && input.path === 'roles') {
      return {
        id: 'email-code-role',
        name: 'common-email-code-allocation',
        type: 'User',
        isDefault: false,
      };
    }
    if (input.method === 'DELETE' && input.path === 'roles/email-code-role') {
      return 204;
    }
    throw new Error('user creation must not run');
  };
  await expect(
    withSelectedEmailCodeFixture({ fixture, request, use: async () => null })
  ).rejects.toThrow('Common email code fixture failed: primary-read-sie;cleanup-none');
  expect(calls.some(({ method, path }) => method === 'POST' && path === 'users')).toBe(false);
  expect(calls.at(-3)).toMatchObject({
    method: 'PATCH',
    path: 'sign-in-exp',
    body: { branding: previousBranding, signIn: { methods: previousMethods } },
  });
  expect(calls.at(-2)).toMatchObject({ method: 'GET', path: 'sign-in-exp' });
  expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: 'roles/email-code-role' });
});
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
