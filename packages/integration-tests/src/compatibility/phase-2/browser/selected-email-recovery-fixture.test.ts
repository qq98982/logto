/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Stateful request fakes prove selection and compensation. */
import type { Phase2AdminRequest } from '../fixtures.js';

import { withSelectedEmailRecoveryFixtureUsing } from './selected-email-recovery-fixture.js';

test('selects email recovery around the password fixture and restores the prior policy', async () => {
  let methods: readonly string[] = [];
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return { forgotPasswordMethods: methods };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      methods = (input.body as { forgotPasswordMethods: readonly string[] }).forgotPasswordMethods;
      return { forgotPasswordMethods: methods };
    }
    throw new Error('unexpected request');
  };
  await expect(
    withSelectedEmailRecoveryFixtureUsing(
      {
        fixture: {} as never,
        request,
        browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
        getOldPassword: () => 'private-old',
        use: async () => 'completed' as const,
      },
      async (input) => {
        expect(methods).toEqual(['EmailVerificationCode']);
        expect(input.getPassword()).toBe('private-old');
        return input.use({
          id: 'owner',
          primaryEmail: 'owner@example.invalid',
          isSuspended: false,
        });
      }
    )
  ).resolves.toBe('completed');
  expect(methods).toEqual([]);
});

test('restores an omitted recovery policy as an empty selected policy', async () => {
  let methods: readonly string[] | undefined;
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'GET') {
      return methods === undefined ? {} : { forgotPasswordMethods: methods };
    }
    methods = (input.body as { forgotPasswordMethods: readonly string[] }).forgotPasswordMethods;
    return { forgotPasswordMethods: methods };
  };
  await expect(
    withSelectedEmailRecoveryFixtureUsing(
      {
        fixture: {} as never,
        request,
        browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
        getOldPassword: () => 'private-old',
        use: async () => 'completed' as const,
      },
      async (input) =>
        input.use({ id: 'owner', primaryEmail: 'owner@example.invalid', isSuspended: false })
    )
  ).resolves.toBe('completed');
  expect(methods).toEqual([]);
});

test('fails closed when recovery policy restoration fails', async () => {
  let patches = 0;
  await expect(
    withSelectedEmailRecoveryFixtureUsing(
      {
        fixture: {} as never,
        request: async (input) => {
          if (input.method === 'GET') {
            return { forgotPasswordMethods: [] };
          }
          patches += 1;
          if (patches === 2) {
            throw new Error('private restore detail');
          }
          return { forgotPasswordMethods: ['EmailVerificationCode'] };
        },
        browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
        getOldPassword: () => 'private-old',
        use: async () => {},
      },
      async (input) =>
        input.use({ id: 'owner', primaryEmail: 'owner@example.invalid', isSuspended: false })
    )
  ).rejects.toThrow('private restore detail');
});

test('preserves a recovery flow stage after the password fixture completes cleanup', async () => {
  let methods: readonly string[] = [];
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'GET') {
      return { forgotPasswordMethods: methods };
    }
    methods = (input.body as { forgotPasswordMethods: readonly string[] }).forgotPasswordMethods;
    return { forgotPasswordMethods: methods };
  };
  await expect(
    withSelectedEmailRecoveryFixtureUsing(
      {
        fixture: {} as never,
        request,
        browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
        getOldPassword: () => 'private-old',
        use: async () => {
          throw new TypeError('Common email recovery failed: new-password-reset');
        },
      },
      async (input) =>
        input.use({
          id: 'owner',
          primaryEmail: 'owner@example.invalid',
          isSuspended: false,
        })
    )
  ).rejects.toThrow('Common email recovery failed: new-password-reset');
  expect(methods).toEqual([]);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
