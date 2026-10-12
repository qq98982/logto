/* eslint-disable @silverhand/fp/no-mutating-methods -- The fake records cleanup attempts in order. */
import { createManagementUser } from '../clients/management-users.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import {
  assertManagementMutation,
  assertManagementUserContactReads,
  assertManagementUserCreateReads,
  deleteOwnedManagementUsers,
} from './common-management-users.js';

const profile = {
  status: 200,
  error: 'none' as const,
  ownerMatches: true,
  emailMatches: true,
  phoneMatches: true,
};
const userInfo = {
  status: 200,
  ownerMatches: true,
  emailMatches: true,
  emailVerified: true,
  phoneMatches: true,
  phoneVerified: true,
};

test('rejects mismatched UserInfo and signed ordinary Account access', () => {
  expect(() => {
    assertManagementUserCreateReads(profile, { ...userInfo, status: 401, ownerMatches: false });
  }).toThrow('Invalid Common Management user flow (create-account-reads)');
  expect(() => {
    assertManagementUserContactReads(profile, userInfo, profile, 'signed.jwt.access');
  }).toThrow('Invalid Common Management user flow (contact-account-reads)');
});

test('reports a closed mutation predicate stage without response details', () => {
  expect(() => {
    assertManagementMutation(
      { status: 409, error: 'user.email_already_in_use' },
      { status: 422, error: 'user.email_already_in_use' },
      'collision'
    );
  }).toThrow('Invalid Common Management user flow (collision-s409-user-email_already_in_use)');
});

test('attempts every owned Management user cleanup when one deletion fails', async () => {
  const paths: string[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    paths.push(input.path);
    if (input.path.endsWith('/collision')) {
      throw new TypeError('private transport detail');
    }
    return 204;
  };

  await expect(deleteOwnedManagementUsers(request, ['collision', 'owner'])).rejects.toThrow(
    'Common Management user cleanup failed'
  );
  expect(paths).toEqual(['users/collision', 'users/owner']);
});

test('cleans up a created user when credential projection validation rejects its response', async () => {
  const paths: string[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    paths.push(input.path);
    return input.method === 'POST'
      ? {
          id: 'owner',
          primaryEmail: 'new@example.invalid',
          passwordHash: 'private',
          updatedAt: 2,
        }
      : 204;
  };
  const ownedIds: string[] = [];

  await expect(
    createManagementUser(request, { email: 'new@example.invalid', password: 'private' }, (id) =>
      ownedIds.push(id)
    )
  ).rejects.toThrow('Invalid Common Management user transport');
  await expect(deleteOwnedManagementUsers(request, ownedIds)).resolves.toBeUndefined();
  expect(paths).toEqual(['users', 'users/owner']);
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
