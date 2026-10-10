/* eslint-disable unicorn/consistent-function-scoping -- Per-test request fakes assert local inputs. */
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import { readRegisteredUserByPhone } from './common-phone-code-target-driver.js';

test('binds a registration subject only from one exact Management phone match', async () => {
  const request: Phase2AdminRequestFunction = async (input) => {
    expect(input).toEqual({
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    return [
      { id: 'other', primaryPhone: '8613900139000' },
      { id: 'registered', primaryPhone: '8613800138000' },
    ];
  };
  await expect(readRegisteredUserByPhone(request, '8613800138000')).resolves.toEqual({
    id: 'registered',
    primaryPhone: '8613800138000',
  });
});

test.each([
  { users: [] },
  {
    users: [
      { id: 'one', primaryPhone: '8613800138000' },
      { id: 'two', primaryPhone: '8613800138000' },
    ],
  },
])('rejects absent or ambiguous registered phone ownership', async ({ users }) => {
  const request: Phase2AdminRequestFunction = async () => users;
  await expect(readRegisteredUserByPhone(request, '8613800138000')).rejects.toThrow(
    'Common phone code target failed: subject'
  );
});
/* eslint-enable unicorn/consistent-function-scoping */
