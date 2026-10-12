/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- The fake records bounded role setup and cleanup calls. */
import type { Phase2AdminRequest, Phase2AdminRequestFunction } from '../fixtures.js';

import {
  closedCommonManagementUserFlowStage,
  withAdditionalDefaultManagementRole,
} from './common-management-users-target-driver.js';

test('preserves a closed mutation status and error stage', () => {
  expect(
    closedCommonManagementUserFlowStage(
      new TypeError(
        'Invalid Common Management user flow (duplicate-s409-user-email_already_in_use)'
      )
    )
  ).toBe('duplicate-s409-user-email_already_in_use');
});

test('rejects unbounded Management flow diagnostics', () => {
  expect(
    closedCommonManagementUserFlowStage(
      new TypeError('Invalid Common Management user flow (duplicate-s409-private.detail)')
    )
  ).toBeUndefined();
});

test('creates and independently deletes the additional default User role', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    if (input.method === 'POST') {
      return {
        id: 'default-role',
        name: 'common-management-default-allocation',
        type: 'User',
        isDefault: true,
      };
    }
    return 204;
  };

  await expect(
    withAdditionalDefaultManagementRole(request, 'allocation', async () => {
      throw new TypeError('private body failure');
    })
  ).rejects.toThrow('private body failure');
  expect(calls).toEqual([
    expect.objectContaining({
      method: 'POST',
      path: 'roles',
      body: expect.objectContaining({ type: 'User', isDefault: true }),
    }),
    expect.objectContaining({ method: 'DELETE', path: 'roles/default-role' }),
  ]);
});

test('deletes the owned role when its returned default projection is invalid', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    return input.method === 'POST'
      ? {
          id: 'default-role',
          name: 'common-management-default-allocation',
          type: 'User',
          isDefault: false,
        }
      : 204;
  };

  await expect(
    withAdditionalDefaultManagementRole(request, 'allocation', async () => 'unused')
  ).rejects.toThrow('Invalid Common Management user target (default-role)');
  expect(calls.map(({ method, path }) => ({ method, path }))).toEqual([
    { method: 'POST', path: 'roles' },
    { method: 'DELETE', path: 'roles/default-role' },
  ]);
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
