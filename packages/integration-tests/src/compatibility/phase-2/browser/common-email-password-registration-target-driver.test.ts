/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions -- Small boundary tests use deliberately incomplete branded-boundary fakes. */
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  readEmailPasswordRegisteredUser,
  runCommonEmailPasswordRegistrationForTarget,
} from './common-email-password-registration-target-driver.js';

test('reads one exact password-bearing registration owner through the bounded Management query', async () => {
  await expect(
    readEmailPasswordRegisteredUser(
      async () => [
        { id: 'foreign-owner', primaryEmail: 'foreign@example.invalid', hasPassword: true },
        { id: 'registered-owner', primaryEmail: 'owner@example.invalid', hasPassword: true },
      ],
      'owner@example.invalid'
    )
  ).resolves.toEqual({ id: 'registered-owner', hasPassword: true });
});

test.each([
  [[]],
  [[{ id: 'registered-owner', primaryEmail: 'owner@example.invalid', hasPassword: false }]],
  [
    [
      { id: 'one', primaryEmail: 'owner@example.invalid', hasPassword: true },
      { id: 'two', primaryEmail: 'owner@example.invalid', hasPassword: true },
    ],
  ],
] as const)('rejects missing, passwordless, or ambiguous registration ownership', async (users) => {
  await expect(
    readEmailPasswordRegisteredUser(async () => users, 'owner@example.invalid')
  ).rejects.toThrow('Common email password registration target failed: subject');
});

test('rejects an unbranded observer before discovery or secret lease use', async () => {
  let fetches = 0;
  let leases = 0;
  await expect(
    runCommonEmailPasswordRegistrationForTarget({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: {
        public: { allocationId: 'allocation' },
        withSecretLease: async () => {
          leases += 1;
          throw new Error('private lease');
        },
      } as unknown as ProvisionedPhase2Fixture,
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser: {
        storageKey: 'config',
        demo: { appId: 'app', prompt: 'consent', scope: 'openid', resource: 'resource' },
        redirectUri: 'https://core.example/demo-app',
        initialResponseScope: 'openid',
        resourceScope: 'read',
      },
      fetch: async () => {
        fetches += 1;
        throw new Error('private fetch');
      },
    })
  ).rejects.toThrow('Common email password registration target failed: capability');
  expect({ fetches, leases }).toEqual({ fetches: 0, leases: 0 });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions */
