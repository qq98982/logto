/* eslint-disable unicorn/consistent-function-scoping, @typescript-eslint/consistent-type-assertions -- Minimal observer/session fakes exercise normalization boundaries only. */
import type { TargetConfig } from '../../model.js';
import type {
  Phase1BrowserGroupObserver,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import {
  readRegisteredUserByPhone,
  runCommonPhoneCodeAdminBoundary,
  runCommonPhoneCodeInFreshContext,
} from './common-phone-code-target-driver.js';

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

test('preserves one finite phone fixture stage across admin consumer normalization', async () => {
  await expect(
    runCommonPhoneCodeAdminBoundary(async (capture) => {
      try {
        return await capture(async () => {
          throw new TypeError('Selected phone code fixture failed: use-registration-profile');
        });
      } catch {
        throw new TypeError('Invalid Phase 2 Admin Management bearer flow (consumer)');
      }
    })
  ).rejects.toThrow('Common phone code target failed: admin-consumer-flow-registration-profile');
});

test('collapses an arbitrary private admin consumer error to the closed other stage', async () => {
  await expect(
    runCommonPhoneCodeAdminBoundary(async (capture) => {
      try {
        return await capture(async () => {
          throw new Error('private credential and response detail');
        });
      } catch {
        throw new TypeError('Invalid Phase 2 Admin Management bearer flow (consumer)');
      }
    })
  ).rejects.toThrow('Common phone code target failed: other');
});

const wrappedObserver = (): Phase1BrowserGroupObserver =>
  ({
    runInFreshContext: async (
      _group: string,
      _signal: AbortSignal,
      _target: TargetConfig,
      use: (session: Phase1BrowserSession) => Promise<unknown>
    ) => {
      try {
        return await use({} as Phase1BrowserSession);
      } catch {
        throw new Error('private observer normalization');
      }
    },
  }) as Phase1BrowserGroupObserver;

test('preserves a finite phone flow stage across browser observer normalization', async () => {
  await expect(
    runCommonPhoneCodeInFreshContext(
      wrappedObserver(),
      new AbortController().signal,
      { label: 'candidate', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
      async () => {
        throw new TypeError('Selected phone code fixture failed: use-registration-identifier');
      }
    )
  ).rejects.toThrow('Common phone code target failed: flow-registration-identifier');
});

test('collapses an unmatched browser error after observer normalization', async () => {
  await expect(
    runCommonPhoneCodeInFreshContext(
      wrappedObserver(),
      new AbortController().signal,
      { label: 'candidate', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
      async () => {
        throw new Error('private browser and credential detail');
      }
    )
  ).rejects.toThrow('Common phone code target failed: browser');
});
/* eslint-enable unicorn/consistent-function-scoping, @typescript-eslint/consistent-type-assertions */
