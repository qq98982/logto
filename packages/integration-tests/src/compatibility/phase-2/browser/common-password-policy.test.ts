/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- Partial fixture doubles and sequential observations are admitted only as the public client required before the failure. */
import { isDeepStrictEqual } from 'node:util';

import { PasswordPolicyChecker } from '@logto/core-kit';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  getCommonPasswordPolicyFailurePhase,
  recoveryUserInfoPassword,
  runCommonPasswordPolicyForTarget,
} from './common-password-policy.js';

test.each([
  ['compromise-compromised', 'compromised', false],
  ['compromise-clear', 'clear', false],
  ['compromise-unavailable', 'unavailable', false],
  ['cleanup-policy', 'compromised', true],
] as const)(
  'Common password policy reports %s when the %s attempt and cleanup finish',
  async (expectedPhase, failedOutcome, cleanupFails) => {
    const previous = { length: { min: 9, max: 128 } };
    const previousSignUp = { identifiers: ['username'], password: true, verify: false };
    const state = { policy: previous as unknown, signUp: previousSignUp as unknown };
    const request: Phase2AdminRequestFunction = async (input) => {
      if (input.path === 'users') {
        return [];
      }
      if (input.method === 'PATCH') {
        if (
          cleanupFails &&
          Object.hasOwn(input.body ?? {}, 'passwordPolicy') &&
          Object.hasOwn(input.body ?? {}, 'signUp')
        ) {
          throw new Error('private cleanup failure');
        }
        if (Object.hasOwn(input.body ?? {}, 'passwordPolicy')) {
          state.policy = Reflect.get(input.body ?? {}, 'passwordPolicy');
        }
        if (Object.hasOwn(input.body ?? {}, 'signUp')) {
          state.signUp = Reflect.get(input.body ?? {}, 'signUp');
        }
      }
      return { passwordPolicy: state.policy, signUp: state.signUp };
    };
    let profile = 0;
    let activeOutcome: 'clear' | 'compromised' | 'unavailable' | undefined;
    const requestFetch: typeof fetch = async (url) => {
      const { pathname } = new URL(String(url));
      if (pathname === '/oidc/auth') {
        return new Response(null, { status: 303 });
      }
      if (pathname === '/api/experience') {
        return new Response(null, { status: 204 });
      }
      profile += 1;
      if (profile === 1) {
        return Response.json(
          {
            code: 'password.rejected',
            data: [{ code: 'password_rejected.too_short', interpolation: { min: 12 } }],
          },
          { status: 422 }
        );
      }
      if (profile === 2) {
        return Response.json(
          { code: 'password.rejected', data: [{ code: 'password_rejected.restricted.words' }] },
          { status: 422 }
        );
      }
      if (activeOutcome === 'compromised') {
        return Response.json(
          { code: 'password.rejected', data: [{ code: 'password_rejected.pwned' }] },
          { status: 422 }
        );
      }
      return new Response(null, { status: 204 });
    };
    const fixture = {
      status: { client: { id: 'owned-client', redirectUri: 'https://client.example/callback' } },
    } as ProvisionedPhase2Fixture;
    const attempts: string[] = [];
    const execution = runCommonPasswordPolicyForTarget({
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
        withAttempt: async ({ outcome }, use) => {
          attempts.push(outcome);
          if (outcome === failedOutcome) {
            throw new Error('private provider failure');
          }
          activeOutcome = outcome;
          try {
            return await use();
          } finally {
            activeOutcome = undefined;
          }
        },
      },
    });
    const failure = await execution.catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(TypeError);
    expect((failure as TypeError).message).toBe(
      `Invalid Common password policy flow (${cleanupFails ? 'cleanup-policy' : 'execution'})`
    );
    expect(getCommonPasswordPolicyFailurePhase(failure)).toBe(expectedPhase);
    expect(attempts.at(-1)).toBe(failedOutcome);
    if (!cleanupFails) {
      expect(state.policy).toEqual(previous);
      expect(state.signUp).toEqual(previousSignUp);
    }
  }
);

test.each([
  ['local-policy-write', 'write'],
  ['local-policy-read', 'read'],
  ['local-policy-readback', 'readback'],
] as const)(
  'Common password policy reports %s and restores persisted settings',
  async (expectedPhase, failedOperation) => {
    const previous = { length: { min: 9, max: 128 } };
    const previousSignUp = { identifiers: ['username'], password: true, verify: false };
    const state = { policy: previous as unknown, signUp: previousSignUp as unknown };
    let awaitingLocalRead = false;
    const request: Phase2AdminRequestFunction = async (input) => {
      if (input.path === 'users') {
        return [];
      }
      if (input.method === 'PATCH') {
        const passwordPolicy: unknown = Reflect.get(input.body ?? {}, 'passwordPolicy');
        const signUp: unknown = Reflect.get(input.body ?? {}, 'signUp');
        if (
          typeof passwordPolicy === 'object' &&
          passwordPolicy !== null &&
          Reflect.get(Reflect.get(passwordPolicy, 'length') ?? {}, 'min') === 12
        ) {
          if (failedOperation === 'write') {
            throw new Error('private local policy write failure');
          }
          state.policy = passwordPolicy;
          awaitingLocalRead = true;
        } else if (passwordPolicy !== undefined) {
          state.policy = passwordPolicy;
        }
        if (signUp !== undefined) {
          state.signUp = signUp;
        }
      } else if (awaitingLocalRead) {
        awaitingLocalRead = false;
        if (failedOperation === 'read') {
          throw new Error('private local policy read failure');
        }
        if (failedOperation === 'readback') {
          return { passwordPolicy: previous, signUp: state.signUp };
        }
      }
      return { passwordPolicy: state.policy, signUp: state.signUp };
    };
    const fixture = {
      status: { client: { id: 'owned-client', redirectUri: 'https://client.example/callback' } },
    } as ProvisionedPhase2Fixture;
    const failure = await runCommonPasswordPolicyForTarget({
      target: {
        label: 'candidate',
        coreUrl: 'https://core.example/',
        adminUrl: 'https://admin.example/',
      },
      fixture,
      request,
      signal: AbortSignal.timeout(10_000),
      fetch: async () => {
        throw new Error('HTTP flow must not start');
      },
      getPassword: () => 'private-password',
      takeRecoveryCode: async () => '123456',
      compromiseFixture: {
        withAttempt: async () => {
          throw new Error('compromise fixture must not start');
        },
      },
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(TypeError);
    expect(getCommonPasswordPolicyFailurePhase(failure)).toBe(expectedPhase);
    expect(state.policy).toEqual(previous);
    expect(state.signUp).toEqual(previousSignUp);
  }
);

test('Common recovery user-info password is rejected by the selected policy', async () => {
  const email = 'common-email-owned@example.invalid';
  const password = recoveryUserInfoPassword(email);
  const checker = new PasswordPolicyChecker({
    length: { min: 12, max: 128 },
    characterTypes: { min: 3 },
    rejects: { pwned: false, repetitionAndSequence: false, userInfo: true, words: [] },
  });

  expect(password).toBe('A9common-email-owned');
  await expect(checker.check(password, { email })).resolves.toContainEqual({
    code: 'password_rejected.restricted.user_info',
  });
});

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
  const execution = runCommonPasswordPolicyForTarget({
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
  });
  const failure = await execution.catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(TypeError);
  expect((failure as TypeError).message).toBe(
    'Invalid Common password policy flow (initialization)'
  );
  expect(getCommonPasswordPolicyFailurePhase(failure)).toBe('local-policy');
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
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
