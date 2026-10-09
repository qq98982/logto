/* eslint-disable curly, unicorn/consistent-function-scoping, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Stateful Management fake proves association and compensation. */
import type { Phase2AdminRequest } from '../fixtures.js';

import { withSelectedGoogleExistingOwner } from './selected-google-existing-owner-fixture.js';

test('uses the immutable Google subject owner across an email change and deletes only the owned user', async () => {
  const users = new Map<string, Record<string, unknown>>();
  users.set('foreign', {
    id: 'foreign',
    name: 'foreign',
    identities: { google: { userId: 'foreign-subject' } },
  });
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'POST' && input.path === 'users') {
      const row = { id: 'owned', ...(input.body as object), identities: {} };
      users.set('owned', row);
      return row;
    }
    if (input.method === 'POST' && input.path === 'users/owned/identities') {
      const row = users.get('owned') ?? {};
      const identity = {
        userId: 'immutable-google-subject',
        details: { email: 'owner@example.invalid' },
      };
      const updated = { ...row, identities: { google: identity } };
      users.set('owned', updated);
      return updated.identities;
    }
    if (input.method === 'GET' && input.path === 'users/owned') return users.get('owned');
    if (input.method === 'DELETE' && input.path === 'users/owned') {
      users.delete('owned');
      return undefined;
    }
    throw new Error('unexpected request');
  };
  const result = await withSelectedGoogleExistingOwner({
    fixture: { public: { allocationId: 'allocation' } } as never,
    request,
    googleSubject: 'immutable-google-subject',
    originalEmail: 'owner@example.invalid',
    connectorId: 'owned-google-connector',
    connectorData: { code: 'private-association-code' },
    use: async (owner) => {
      const row = users.get(owner.id) ?? {};
      users.set(owner.id, { ...row, primaryEmail: 'changed@example.invalid' });
      return owner.id;
    },
  });
  expect(result).toBe('owned');
  expect(users.has('owned')).toBe(false);
  expect(users.get('foreign')).toEqual({
    id: 'foreign',
    name: 'foreign',
    identities: { google: { userId: 'foreign-subject' } },
  });
});

test('still deletes the owned user when the immutable subject readback changes', async () => {
  let deleted = false;
  let reads = 0;
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'POST' && input.path === 'users') return { id: 'owned' };
    if (input.method === 'POST' && input.path === 'users/owned/identities')
      return { google: { userId: 'immutable-google-subject' } };
    if (input.method === 'GET') {
      reads += 1;
      return {
        id: 'owned',
        identities: { google: { userId: reads === 1 ? 'immutable-google-subject' : 'other' } },
      };
    }
    if (input.method === 'DELETE') {
      deleted = true;
      return undefined;
    }
    throw new Error('unexpected request');
  };
  await expect(
    withSelectedGoogleExistingOwner({
      fixture: { public: { allocationId: 'allocation' } } as never,
      request,
      googleSubject: 'immutable-google-subject',
      originalEmail: 'owner@example.invalid',
      connectorId: 'owned-google-connector',
      connectorData: { code: 'private-association-code' },
      use: async () => null,
    })
  ).rejects.toThrow('Selected Google fixture failed: read-after');
  expect(deleted).toBe(true);
});

test('redacts private association, callback, and cleanup failures into fixed stages', async () => {
  let deleteAttempts = 0;
  const associationRequest = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'POST' && input.path === 'users') return { id: 'owned' };
    if (input.method === 'POST') throw new Error('private-association-code');
    if (input.method === 'DELETE') {
      deleteAttempts += 1;
      return undefined;
    }
    throw new Error('private-transport');
  };
  await expect(
    withSelectedGoogleExistingOwner({
      fixture: { public: { allocationId: 'allocation' } } as never,
      request: associationRequest,
      googleSubject: 'immutable-google-subject',
      originalEmail: 'owner@example.invalid',
      connectorId: 'owned-google-connector',
      connectorData: { code: 'private-association-code' },
      use: async () => null,
    })
  ).rejects.toThrow('Selected Google fixture failed: associate');
  expect(deleteAttempts).toBe(1);

  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'POST' && input.path === 'users') return { id: 'owned' };
    if (input.method === 'POST') return { google: { userId: 'immutable-google-subject' } };
    if (input.method === 'GET')
      return { id: 'owned', identities: { google: { userId: 'immutable-google-subject' } } };
    if (input.method === 'DELETE') throw new Error('private-delete-token');
    throw new Error('private-transport');
  };
  const operation = withSelectedGoogleExistingOwner({
    fixture: { public: { allocationId: 'allocation' } } as never,
    request,
    googleSubject: 'immutable-google-subject',
    originalEmail: 'owner@example.invalid',
    connectorId: 'owned-google-connector',
    connectorData: { code: 'private-association-code' },
    use: async () => {
      throw new Error('private-use-code');
    },
  });
  await expect(operation).rejects.toMatchObject({
    message: 'Selected Google fixture cleanup failed',
    errors: [
      { message: 'Selected Google fixture failed: cleanup-user' },
      { message: 'Selected Google fixture failed: use' },
    ],
  });
  await expect(operation).rejects.not.toThrow(/private-association|private-delete|private-use/u);
});
/* eslint-enable curly, unicorn/consistent-function-scoping, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
