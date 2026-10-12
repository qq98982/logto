/* eslint-disable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- Partial fixture doubles are admitted only as the public client required before the failure. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { runCommonPasswordPolicyForTarget } from './common-password-policy.js';

test('Common password policy enables email registration and restores exact settings after initialization fails', async () => {
  const previous = {
    length: { min: 9, max: 128 },
    characterTypes: { min: 2 },
    rejects: { pwned: false, repetitionAndSequence: true, userInfo: false, words: ['retained'] },
  };
  const previousSignUp = { identifiers: ['username'], password: true, verify: false };
  const state = { policy: previous as unknown, signUp: previousSignUp as unknown };
  const writes: unknown[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.path === 'users') {
      return [];
    }
    if (input.path !== 'sign-in-exp') {
      throw new Error('unexpected Management request');
    }
    if (input.method === 'PATCH') {
      if (Object.hasOwn(input.body ?? {}, 'passwordPolicy')) {
        const policy: unknown = Reflect.get(input.body ?? {}, 'passwordPolicy');
        state.policy = policy;
        writes.push(structuredClone(policy));
      }
      if (Object.hasOwn(input.body ?? {}, 'signUp')) {
        state.signUp = Reflect.get(input.body ?? {}, 'signUp');
      }
    }
    return { passwordPolicy: state.policy, signUp: state.signUp };
  };
  const fixture = {
    status: { client: { id: 'owned-client', redirectUri: 'https://client.example/callback' } },
  } as ProvisionedPhase2Fixture;
  const requests: string[] = [];
  const requestFetch: typeof fetch = async (url) => {
    expect(state.signUp).toEqual({ identifiers: ['email'], password: true, verify: true });
    requests.push(new URL(String(url)).pathname);
    return requests.length === 1
      ? new Response(null, { status: 303 })
      : new Response(null, { status: 503 });
  };
  await expect(
    runCommonPasswordPolicyForTarget({
      target: {
        label: 'candidate',
        coreUrl: 'https://core.example/',
        adminUrl: 'https://admin.example/',
      },
      fixture,
      request,
      signal: AbortSignal.timeout(10_000),
      fetch: requestFetch,
      getPassword: () => 'private-password',
      takeRecoveryCode: async () => '123456',
      compromiseFixture: {
        withAttempt: async () => {
          throw new Error('compromise provider must not start');
        },
      },
    })
  ).rejects.toThrow('Invalid Common password policy flow (initialization)');
  expect(requests).toEqual(['/oidc/auth', '/api/experience']);
  expect(writes).toHaveLength(2);
  expect(writes[1]).toEqual(previous);
  expect(isDeepStrictEqual(state.policy, previous)).toBe(true);
  expect(state.signUp).toEqual(previousSignUp);
});

test('Common password policy rejects a configuration acknowledgement that differs from persisted readback', async () => {
  const writes: unknown[] = [];
  const state = { signUp: { identifiers: ['username'], password: true, verify: false } as unknown };
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.path === 'users') {
      return [];
    }
    if (input.method === 'PATCH') {
      if (Object.hasOwn(input.body ?? {}, 'passwordPolicy')) {
        writes.push(Reflect.get(input.body ?? {}, 'passwordPolicy'));
      }
      if (Object.hasOwn(input.body ?? {}, 'signUp')) {
        state.signUp = Reflect.get(input.body ?? {}, 'signUp');
      }
    }
    return { passwordPolicy: { rejects: { pwned: false } }, signUp: state.signUp };
  };
  const fixture = {
    status: { client: { id: 'owned-client', redirectUri: 'https://client.example/callback' } },
  } as ProvisionedPhase2Fixture;
  await expect(
    runCommonPasswordPolicyForTarget({
      target: {
        label: 'candidate',
        coreUrl: 'https://core.example/',
        adminUrl: 'https://admin.example/',
      },
      fixture,
      request,
      signal: AbortSignal.timeout(10_000),
      getPassword: () => 'private-password',
      takeRecoveryCode: async () => '123456',
      compromiseFixture: {
        withAttempt: async () => {
          throw new Error('provider must not start');
        },
      },
      fetch: async () => {
        throw new Error('HTTP flow must not start');
      },
    })
  ).rejects.toThrow('Invalid Common password policy flow (policy-readback)');
  expect(writes).toHaveLength(2);
  expect(writes[1]).toEqual({ rejects: { pwned: false } });
});
/* eslint-enable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
