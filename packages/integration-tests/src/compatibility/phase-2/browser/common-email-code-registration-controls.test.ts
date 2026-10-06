/* eslint-disable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful runtime models private ownership without publishing IDs. */
import {
  runEmailCodeRegistrationControls,
  type RegistrationInteractionRuntime,
} from './common-email-code-registration-controls.js';

const successOutcome = (event: 'SignIn' | 'Register') => ({
  requestStatus: 200,
  requestOutcome: 'created' as const,
  requestError: '',
  verifyStatus: 200,
  verifyOutcome: 'verified' as const,
  verifyError: '',
  identificationStatus: event === 'SignIn' ? 404 : 422,
  identificationError: event === 'SignIn' ? 'user.user_not_exist' : 'user.email_already_in_use',
});

const runtime = (
  options: Readonly<{
    mutateMissing?: boolean;
    replaceOwner?: boolean;
    malformed?: boolean;
    identifySignIn?: boolean;
    failAt?: 'lookup' | 'proof';
  }> = {}
) => {
  const calls: string[] = [];
  let missingLookups = 0;
  let occupiedLookups = 0;
  const implementation: RegistrationInteractionRuntime = {
    authenticatedLookupExactEmail: async (email) => {
      calls.push(`lookup:${email}`);
      if (options.failAt === 'lookup') {
        throw new Error('private lookup failure');
      }
      if (email === 'missing@example.invalid') {
        missingLookups += 1;
        return options.mutateMissing && missingLookups > 1 ? ['private-created-id'] : [];
      }
      occupiedLookups += 1;
      if (options.replaceOwner && occupiedLookups > 1) {
        return ['private-replacement-id'];
      }
      return ['private-owner-id'];
    },
    runFreshVerifiedIdentification: async (event, email) => {
      calls.push(`proof:${event}:${email}`);
      if (options.failAt === 'proof') {
        throw new Error('private code or handle');
      }
      const result =
        options.identifySignIn && event === 'SignIn'
          ? { ...successOutcome(event), identificationStatus: 200, identificationError: '' }
          : successOutcome(event);
      return options.malformed
        ? ({ ...successOutcome(event), privateHandle: 'secret' } as never)
        : result;
    },
  };
  return { calls, implementation };
};

const input = {
  missingEmail: 'missing@example.invalid',
  occupiedEmail: 'occupied@example.invalid',
} as const;

test('proves SignIn does not register and Register collision preserves the exact owner', async () => {
  const { calls, implementation } = runtime();
  const result = await runEmailCodeRegistrationControls(implementation, input);
  expect(calls).toEqual([
    'lookup:missing@example.invalid',
    'proof:SignIn:missing@example.invalid',
    'lookup:missing@example.invalid',
    'lookup:occupied@example.invalid',
    'proof:Register:occupied@example.invalid',
    'lookup:occupied@example.invalid',
  ]);
  expect(result).toEqual({
    noImplicitRegistration: {
      requestStatus: 200,
      verifyStatus: 200,
      identificationStatus: 404,
      error: 'user.user_not_exist',
      beforeCount: 0,
      afterCount: 0,
    },
    occupiedRegistration: {
      requestStatus: 200,
      verifyStatus: 200,
      identificationStatus: 422,
      error: 'user.email_already_in_use',
      beforeCount: 1,
      afterCount: 1,
      ownerUnchanged: true,
    },
  });
  expect(JSON.stringify(result)).not.toMatch(/private-|handle|code|owner-id/u);
});

test.each([
  ['implicit SignIn mutation', { mutateMissing: true }, 'signin-after'],
  ['occupied owner replacement', { replaceOwner: true }, 'register-after'],
  ['malformed proof result', { malformed: true }, 'signin-proof'],
  ['implicit SignIn identification success', { identifySignIn: true }, 'signin-identification'],
] as const)('rejects %s', async (_name, options, stage) => {
  await expect(
    runEmailCodeRegistrationControls(runtime(options).implementation, input)
  ).rejects.toThrow(`Common email code registration controls failed: ${stage}`);
});

test.each([
  ['lookup', 'signin-before'],
  ['proof', 'signin-proof'],
] as const)('redacts an asynchronous %s failure at a finite stage', async (failAt, stage) => {
  const error = await runEmailCodeRegistrationControls(
    runtime({ failAt }).implementation,
    input
  ).catch((error_: unknown) => error_);
  expect(error).toBeInstanceOf(TypeError);
  expect((error as Error).message).toBe(`Common email code registration controls failed: ${stage}`);
  expect(JSON.stringify(error)).not.toContain('private');
});

test('rejects invalid control recipients before invoking the runtime', async () => {
  const { calls, implementation } = runtime();
  await expect(
    runEmailCodeRegistrationControls(implementation, {
      missingEmail: 'Missing@Example.Invalid',
      occupiedEmail: input.occupiedEmail,
    })
  ).rejects.toThrow('Common email code registration controls failed: admission');
  expect(calls).toEqual([]);
});

test('rejects accessor and iterator-backed ownership without invoking them', async () => {
  let getterCalls = 0;
  let iteratorCalls = 0;
  const owners: string[] = [];
  Object.defineProperty(owners, '0', {
    enumerable: true,
    get: () => {
      getterCalls += 1;
      throw new Error('private owner');
    },
  });
  Object.defineProperty(owners, 'length', { value: 1 });
  Object.defineProperty(owners, Symbol.iterator, {
    get: () => {
      iteratorCalls += 1;
      throw new Error('private iterator');
    },
  });
  const { implementation } = runtime();
  await expect(
    runEmailCodeRegistrationControls(
      { ...implementation, authenticatedLookupExactEmail: async () => owners },
      input
    )
  ).rejects.toThrow('Common email code registration controls failed: signin-before');
  expect({ getterCalls, iteratorCalls }).toEqual({ getterCalls: 0, iteratorCalls: 0 });
});

test('rejects proxy ownership and proof records without invoking traps', async () => {
  let traps = 0;
  const proxiedOwners = new Proxy(['private-owner'], {
    ownKeys: () => {
      traps += 1;
      throw new Error('private owner keys');
    },
  });
  const base = runtime().implementation;
  await expect(
    runEmailCodeRegistrationControls(
      { ...base, authenticatedLookupExactEmail: async () => proxiedOwners },
      input
    )
  ).rejects.toThrow('Common email code registration controls failed: signin-before');
  const proxiedProof = new Proxy(successOutcome('SignIn'), {
    ownKeys: () => {
      traps += 1;
      throw new Error('private proof keys');
    },
  });
  await expect(
    runEmailCodeRegistrationControls(
      { ...base, runFreshVerifiedIdentification: async () => proxiedProof },
      input
    )
  ).rejects.toThrow('Common email code registration controls failed: signin-proof');
  expect(traps).toBe(0);
});
/* eslint-enable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
