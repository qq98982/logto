/* eslint-disable complexity, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful fake proves registration ownership and independent compensation. */
import { Roles } from '@logto/schemas';

import type { Phase2AdminRequest, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedEmailCodeRegistrationFixture } from './selected-email-code-registration-fixture.js';

const fixture = {
  public: { allocationId: '12345678-1234-4234-8234-123456789abc' },
  status: {
    client: { id: 'browser-client' },
    resource: {
      id: 'resource-id',
      indicator: 'https://resource.example/',
      scopeName: 'read:profile',
    },
  },
} as unknown as ProvisionedPhase2Fixture;

const createState = (
  options: { failAfterRegistration?: boolean; failRestore?: boolean; scopeCount?: number } = {}
) => {
  const calls: Phase2AdminRequest[] = [];
  const users = new Map<string, { id: string; primaryEmail: string; roles: unknown[] }>();
  users.set('foreign-user', {
    id: 'foreign-user',
    primaryEmail: 'foreign@example.invalid',
    roles: [{ id: 'foreign-role', type: 'User', isDefault: true }],
  });
  let sie = {
    branding: { logoUrl: 'https://assets.example/logo.png' },
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
    signUp: { identifiers: ['username'], password: true, verify: false, secondaryIdentifiers: [] },
    languageInfo: { autoDetect: true, fallbackLanguage: 'en' },
  };
  const originalSie = structuredClone(sie);
  let metadata = { redirectUris: ['http://localhost:3001/demo-app'], postLogoutRedirectUris: [] };
  const originalMetadata = structuredClone(metadata);
  let role: { id: string; type: string; isDefault: boolean } | undefined;
  let siePatchCount = 0;

  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (input.path === 'sign-in-exp' && input.method === 'GET') return structuredClone(sie);
    if (input.path === 'sign-in-exp' && input.method === 'PATCH') {
      siePatchCount += 1;
      if (options.failRestore && siePatchCount === 2) throw new Error('private restore failure');
      sie = { ...sie, ...(input.body as typeof sie) };
      return structuredClone(sie);
    }
    if (input.path === 'applications/browser-client' && input.method === 'GET')
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: structuredClone(metadata) };
    if (input.path === 'applications/browser-client' && input.method === 'PATCH') {
      metadata = structuredClone(
        (input.body as { oidcClientMetadata: typeof metadata }).oidcClientMetadata
      );
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: structuredClone(metadata) };
    }
    if (input.path === 'resources' && input.method === 'GET')
      return [
        {
          id: 'resource-id',
          indicator: 'https://resource.example/',
          scopes: Array.from({ length: options.scopeCount ?? 1 }, (_, index) => ({
            id: index === 0 ? 'scope-id' : `scope-${index}`,
            name: 'read:profile',
          })),
        },
      ];
    if (input.path === 'roles' && input.method === 'POST') {
      role = { id: 'registration-role', type: 'User', isDefault: true };
      return role;
    }
    if (input.path === 'roles/registration-role/scopes' && input.method === 'GET')
      return [{ id: 'scope-id', resourceId: 'resource-id', name: 'read:profile' }];
    if (input.path === 'roles/registration-role' && input.method === 'DELETE') {
      role = undefined;
      return undefined;
    }
    if (
      input.path.startsWith('users/') &&
      input.path.endsWith('/roles') &&
      input.method === 'GET'
    ) {
      const id = input.path.split('/')[1] ?? '';
      return users.get(id)?.roles ?? [];
    }
    if (input.path.startsWith('users/') && input.method === 'GET') {
      const id = input.path.split('/')[1] ?? '';
      if (options.failAfterRegistration) throw new Error('private registered-user read failure');
      return users.get(id) ?? null;
    }
    if (input.path.startsWith('users/') && input.method === 'DELETE') {
      users.delete(input.path.split('/')[1] ?? '');
      return undefined;
    }
    throw new Error(`unexpected request ${input.method} ${input.path}`);
  };
  return {
    calls,
    users,
    request,
    originalSie,
    originalMetadata,
    current: () => ({ sie, metadata, role }),
  };
};

test('configures email-code registration, verifies the actual user and default role, then restores owned state', async () => {
  const state = createState();
  let usersBeforeRegistration = -1;
  const result = await withSelectedEmailCodeRegistrationFixture({
    fixture,
    request: state.request,
    browser: { clientId: 'browser-client', redirectUri: 'https://core.example/demo-app' },
    use: async ({ primaryEmail, captureRegisteredUser }) => {
      expect(primaryEmail.split('@')[0]?.length).toBeLessThanOrEqual(64);
      usersBeforeRegistration = state.users.size;
      expect(state.current().role).toEqual({
        id: 'registration-role',
        type: 'User',
        isDefault: true,
      });
      expect(state.current().sie.signUp).toEqual({
        identifiers: ['email'],
        password: false,
        verify: true,
      });
      expect(state.current().sie.branding).toEqual({});
      expect(state.current().sie.languageInfo).toEqual({
        autoDetect: true,
        fallbackLanguage: 'en',
      });
      state.users.set('registered-user', {
        id: 'registered-user',
        primaryEmail,
        roles: [
          { id: 'foreign-default-role', type: 'User', isDefault: true },
          { id: 'registration-role', type: 'User', isDefault: true },
        ],
      });
      await captureRegisteredUser('registered-user');
      return 'browser-complete';
    },
  });
  expect(result).toBe('browser-complete');
  expect(usersBeforeRegistration).toBe(1);
  expect(state.users.has('registered-user')).toBe(false);
  expect(state.users.has('foreign-user')).toBe(true);
  expect(state.current().sie).toEqual(state.originalSie);
  expect(state.current().metadata).toEqual(state.originalMetadata);
  expect(state.current().role).toBeUndefined();
  expect(state.calls).toContainEqual(
    expect.objectContaining({ method: 'POST', path: 'roles', expectedStatuses: [200, 201] })
  );
  const roleCreate = state.calls.find(({ method, path }) => method === 'POST' && path === 'roles');
  expect(Roles.createGuard.omit({ id: true }).safeParse(roleCreate?.body).success).toBe(true);
});

test('does not delete an unverified registered ID when ownership readback fails', async () => {
  const state = createState({ failAfterRegistration: true });
  await expect(
    withSelectedEmailCodeRegistrationFixture({
      fixture,
      request: state.request,
      use: async ({ primaryEmail, captureRegisteredUser }) => {
        state.users.set('registered-user', {
          id: 'registered-user',
          primaryEmail,
          roles: [{ id: 'registration-role', type: 'User', isDefault: true }],
        });
        await captureRegisteredUser('registered-user');
        return null;
      },
    })
  ).rejects.toThrow('Email code registration fixture failed: primary-use;cleanup-none');
  expect(state.users.has('registered-user')).toBe(true);
  expect(state.users.has('foreign-user')).toBe(true);
  expect(state.current().role).toBeUndefined();
});

test('rejects an ambiguous resource scope before browser registration or persisted state', async () => {
  const state = createState({ scopeCount: 2 });
  let useCalled = false;
  await expect(
    withSelectedEmailCodeRegistrationFixture({
      fixture,
      request: state.request,
      use: async () => {
        useCalled = true;
        return null;
      },
    })
  ).rejects.toThrow('Email code registration fixture failed: primary-read-resource;cleanup-none');
  expect(useCalled).toBe(false);
  expect(state.users.size).toBe(1);
  expect(state.users.has('foreign-user')).toBe(true);
  expect(state.current().role).toBeUndefined();
});

test('reports restoration failure after independently deleting owned registration state', async () => {
  const state = createState({ failRestore: true });
  await expect(
    withSelectedEmailCodeRegistrationFixture({
      fixture,
      request: state.request,
      use: async ({ primaryEmail, captureRegisteredUser }) => {
        state.users.set('registered-user', {
          id: 'registered-user',
          primaryEmail,
          roles: [{ id: 'registration-role', type: 'User', isDefault: true }],
        });
        await captureRegisteredUser('registered-user');
        return null;
      },
    })
  ).rejects.toThrow('Email code registration fixture failed: cleanup-restore-sie');
  expect(state.users.has('registered-user')).toBe(false);
  expect(state.current().role).toBeUndefined();
});

test('deletes a captured registered user when the browser flow fails after persistence', async () => {
  const state = createState();
  await expect(
    withSelectedEmailCodeRegistrationFixture({
      fixture,
      request: state.request,
      use: async ({ primaryEmail, captureRegisteredUser }) => {
        state.users.set('registered-user', {
          id: 'registered-user',
          primaryEmail,
          roles: [{ id: 'registration-role', type: 'User', isDefault: true }],
        });
        await captureRegisteredUser('registered-user');
        throw new Error('private browser failure after persistence');
      },
    })
  ).rejects.toThrow('Email code registration fixture failed: primary-use;cleanup-none');
  expect(state.users.has('registered-user')).toBe(false);
  expect(state.users.has('foreign-user')).toBe(true);
  expect(state.current().role).toBeUndefined();
});

test('preserves a foreign user captured by a failing browser flow', async () => {
  const state = createState();
  await expect(
    withSelectedEmailCodeRegistrationFixture({
      fixture,
      request: state.request,
      use: async ({ captureRegisteredUser }) => {
        await captureRegisteredUser('foreign-user');
        throw new Error('private failure after foreign capture');
      },
    })
  ).rejects.toThrow('Email code registration fixture failed: primary-use;cleanup-none');
  expect(state.users.has('foreign-user')).toBe(true);
  expect(state.current().role).toBeUndefined();
});
/* eslint-enable complexity, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
