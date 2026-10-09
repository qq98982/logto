/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Stateful Management fake proves restoration and partial-user compensation. */
import type { Phase2AdminRequest, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedEmailPasswordRegistrationFixture } from './selected-email-password-registration-fixture.js';

const fixture = {
  public: { allocationId: 'registration-allocation' },
  status: {
    client: { id: 'browser-client' },
    resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
  },
} as unknown as ProvisionedPhase2Fixture;

const createState = () => {
  const users = new Map<string, { id: string; primaryEmail: string; hasPassword: boolean }>();
  let sie = {
    branding: { logoUrl: 'https://assets.example/logo.png' },
    signIn: { methods: [{ identifier: 'username', password: true }] },
    signUp: { identifiers: ['username'], password: true, verify: false },
    languageInfo: { autoDetect: true },
  };
  const originalSie = structuredClone(sie);
  let metadata = { redirectUris: ['https://old.example/callback'], postLogoutRedirectUris: [] };
  const originalMetadata = structuredClone(metadata);
  let rolePresent = false;
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.path === 'sign-in-exp' && input.method === 'GET') {
      return structuredClone(sie);
    }
    if (input.path === 'sign-in-exp' && input.method === 'PATCH') {
      sie = { ...sie, ...(input.body as typeof sie) };
      return structuredClone(sie);
    }
    if (input.path === 'applications/browser-client' && input.method === 'GET') {
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: structuredClone(metadata) };
    }
    if (input.path === 'applications/browser-client' && input.method === 'PATCH') {
      metadata = structuredClone(
        (input.body as { oidcClientMetadata: typeof metadata }).oidcClientMetadata
      );
      return { id: 'browser-client', type: 'SPA', oidcClientMetadata: structuredClone(metadata) };
    }
    if (input.path === 'users' && input.method === 'GET') {
      return [...users.values()];
    }
    if (input.path === 'resources' && input.method === 'GET') {
      return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
    }
    if (input.path === 'roles' && input.method === 'POST') {
      rolePresent = true;
      return { id: 'registration-role', type: 'User', isDefault: true };
    }
    if (input.path === 'roles/registration-role/scopes' && input.method === 'GET') {
      return [{ id: 'scope', resourceId: 'resource', name: 'read:profile' }];
    }
    if (input.path === 'roles/registration-role' && input.method === 'DELETE') {
      rolePresent = false;
      return undefined;
    }
    if (input.path === 'users/registered-owner' && input.method === 'GET') {
      return users.get('registered-owner');
    }
    if (input.path === 'users/registered-owner/roles' && input.method === 'GET') {
      return [{ id: 'registration-role', type: 'User', isDefault: true }];
    }
    if (input.path.startsWith('users/') && input.method === 'DELETE') {
      users.delete(input.path.split('/')[1] ?? '');
      return undefined;
    }
    throw new Error(`unexpected ${input.method} ${input.path}`);
  };
  return {
    users,
    request,
    originalSie,
    originalMetadata,
    current: () => ({ sie, metadata, rolePresent }),
  };
};

test('restores borrowed policy and deletes the captured registration owner', async () => {
  const state = createState();
  const result = await withSelectedEmailPasswordRegistrationFixture({
    fixture,
    request: state.request,
    browser: { clientId: 'browser-client', redirectUri: 'https://core.example/demo-app' },
    use: async ({ primaryEmail, captureRegisteredUser }) => {
      state.users.set('registered-owner', {
        id: 'registered-owner',
        primaryEmail,
        hasPassword: true,
      });
      await captureRegisteredUser('registered-owner');
      return 'complete';
    },
  });
  expect(result).toBe('complete');
  expect(state.users.size).toBe(0);
  expect(state.current()).toEqual({
    sie: state.originalSie,
    metadata: state.originalMetadata,
    rolePresent: false,
  });
});

test('discovers and deletes an owned partial user when use fails before capture', async () => {
  const state = createState();
  await expect(
    withSelectedEmailPasswordRegistrationFixture({
      fixture,
      request: state.request,
      browser: { clientId: 'browser-client', redirectUri: 'https://core.example/demo-app' },
      use: async ({ rejectedPolicyEmail }) => {
        state.users.set('partial-owner', {
          id: 'partial-owner',
          primaryEmail: rejectedPolicyEmail,
          hasPassword: false,
        });
        throw new Error('private flow failure');
      },
    })
  ).rejects.toThrow('Email password registration fixture failed: primary-use;cleanup-none');
  expect(state.users.size).toBe(0);
  expect(state.current().rolePresent).toBe(false);
});

test('rejects a colliding fixture email without deleting the preexisting owner', async () => {
  const state = createState();
  const firstEmail = await withSelectedEmailPasswordRegistrationFixture({
    fixture,
    request: state.request,
    browser: { clientId: 'browser-client', redirectUri: 'https://core.example/demo-app' },
    use: async ({ primaryEmail, captureRegisteredUser }) => {
      state.users.set('registered-owner', {
        id: 'registered-owner',
        primaryEmail,
        hasPassword: true,
      });
      await captureRegisteredUser('registered-owner');
      return primaryEmail;
    },
  });
  state.users.set('preexisting-owner', {
    id: 'preexisting-owner',
    primaryEmail: firstEmail,
    hasPassword: true,
  });
  await expect(
    withSelectedEmailPasswordRegistrationFixture({
      fixture,
      request: state.request,
      browser: { clientId: 'browser-client', redirectUri: 'https://core.example/demo-app' },
      use: async () => 'unreachable',
    })
  ).rejects.toThrow(
    'Email password registration fixture failed: primary-read-owned-users;cleanup-none'
  );
  expect(state.users.get('preexisting-owner')).toEqual({
    id: 'preexisting-owner',
    primaryEmail: firstEmail,
    hasPassword: true,
  });
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
