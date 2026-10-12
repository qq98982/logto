/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake records exact setup and compensation order. */
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import {
  runManagementUserSuspendDeleteFamily,
  withManagementEmailPasswordSignIn,
} from './management-user-suspend-delete-family.js';

const previous = {
  methods: [
    {
      identifier: 'username',
      password: true,
      verificationCode: false,
      isPasswordPrimary: true,
    },
  ],
  passwordless: { enabled: false },
};
const wireRecord = (value: unknown): Readonly<Record<string, unknown>> => {
  const cloned: unknown = JSON.parse(JSON.stringify(value));
  if (typeof cloned !== 'object' || cloned === null || Array.isArray(cloned)) {
    throw new TypeError('Invalid fake wire record');
  }
  return Object.fromEntries(Object.entries(cloned));
};

const createRequest = (failRestore = false) => {
  let signIn: Readonly<Record<string, unknown>> = previous;
  const patches: Array<Readonly<Record<string, unknown>>> = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return { signIn };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      const next = Reflect.get(input.body as Record<string, unknown>, 'signIn') as Readonly<
        Record<string, unknown>
      >;
      if (failRestore && patches.length === 1) {
        throw new TypeError('restore failed');
      }
      signIn = wireRecord(next);
      patches.push(signIn);
      return { signIn };
    }
    throw new TypeError('Unexpected request');
  };
  return { request, patches, read: () => signIn };
};

test.each([false, true])(
  'preserves sign-in fields and restores the exact state after body failure=%s',
  async (bodyFails) => {
    const fixture = createRequest();
    const operation = withManagementEmailPasswordSignIn(fixture.request, async () => {
      expect(fixture.read()).toEqual({
        ...previous,
        methods: [
          ...previous.methods,
          {
            identifier: 'email',
            password: true,
            verificationCode: false,
            isPasswordPrimary: true,
          },
        ],
      });
      if (bodyFails) {
        throw new TypeError('lifecycle failed');
      }
      return 'complete';
    });

    await (bodyFails
      ? expect(operation).rejects.toThrow('lifecycle failed')
      : expect(operation).resolves.toBe('complete'));
    expect(fixture.patches).toHaveLength(2);
    expect(fixture.read()).toEqual(previous);
  }
);

test('fails closed when the exact previous sign-in state cannot be restored', async () => {
  const fixture = createRequest(true);
  await expect(
    withManagementEmailPasswordSignIn(fixture.request, async () => 'complete')
  ).rejects.toThrow('restore failed');
});

test('restores the prior state when selected readback mismatches and does not run the consumer', async () => {
  let signIn: Readonly<Record<string, unknown>> = previous;
  let getCount = 0;
  let consumerCalled = false;
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      getCount += 1;
      return { signIn: getCount === 2 ? previous : signIn };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      signIn = wireRecord(
        Reflect.get(input.body as Record<string, unknown>, 'signIn') as Readonly<
          Record<string, unknown>
        >
      );
      return { signIn };
    }
    throw new TypeError('Unexpected request');
  };

  await expect(
    withManagementEmailPasswordSignIn(request, async () => {
      consumerCalled = true;
    })
  ).rejects.toThrow('select-sign-in');
  expect(consumerCalled).toBe(false);
  expect(signIn).toEqual(previous);
  expect(getCount).toBe(3);
});

test('attempts owned-user cleanup when token issuance and sign-in restoration both fail', async () => {
  let signIn: Readonly<Record<string, unknown>> = previous;
  let patchCount = 0;
  const deletedUsers: string[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.method === 'POST' && input.path === 'users') {
      return {
        id: 'owned-user',
        name: null,
        primaryEmail: Reflect.get(input.body as Record<string, unknown>, 'primaryEmail'),
        primaryPhone: null,
        hasPassword: true,
        updatedAt: 1,
      };
    }
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return { signIn };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      patchCount += 1;
      if (patchCount === 2) {
        throw new TypeError('restore failed');
      }
      signIn = wireRecord(
        Reflect.get(input.body as Record<string, unknown>, 'signIn') as Readonly<
          Record<string, unknown>
        >
      );
      return { signIn };
    }
    if (input.method === 'DELETE' && input.path === 'users/owned-user') {
      deletedUsers.push(input.path);
      return;
    }
    throw new TypeError(`Unexpected request ${input.method} ${input.path}`);
  };
  // The token path fails before fixture capabilities beyond the bounded public status are used.
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const fixture: never = {
    public: { allocationId: 'fixture' },
    status: {
      user: { id: 'status-user', username: 'status-user' },
      client: {
        id: 'status-client',
        redirectUri: 'https://candidate.example/callback',
      },
      confidentialClient: {
        id: 'status-confidential',
        redirectUri: 'https://candidate.example/confidential-callback',
      },
      resource: {
        id: 'status-resource',
        indicator: 'https://resource.example/',
        scopeName: 'read',
      },
    },
    withSecretLease: async () => {
      throw new TypeError('Unexpected secret lease');
    },
  } as never;

  await expect(
    runManagementUserSuspendDeleteFamily({
      target: {
        label: 'candidate',
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      },
      fixture,
      request,
      password: 'Fixture-password-1',
      fetch: async () => {
        throw new TypeError('token issuance failed');
      },
      observeForeignPreserved: async () => true,
    })
  ).rejects.toThrow('Lifecycle body and sign-in restoration failed');
  expect(deletedUsers).toEqual(['users/owned-user']);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
