/* eslint-disable @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Action and getter counters verify the public flow and privacy boundary. */
import {
  runCommonGoogleExistingOwnerSignIn,
  type CommonGoogleBrowserSession,
} from './common-google-existing-owner-sign-in.js';

const authorization = Object.freeze({
  requestCount: 1,
  queryShapeExact: true,
  clientMatched: true,
  callbackMatched: true,
  responseTypeCode: true,
  scopeExact: true,
  stateFormatValid: true,
  stateRoundTrip: true,
  fulfilledOnce: true,
});
const setup = (
  overrides: Partial<CommonGoogleBrowserSession> = {},
  assertCase?: () => Promise<void>
) => {
  const actions: string[] = [];
  const session: CommonGoogleBrowserSession = {
    navigate: async (step, path) => {
      actions.push(`${step}:${path}`);
    },
    waitForRoute: async (step, paths) => {
      actions.push(`${step}:${paths.join(',')}`);
    },
    expectCount: async (step, _selector, expected) => {
      actions.push(`${step}:${expected}`);
    },
    click: async (step) => {
      actions.push(step);
    },
    assertInitialCallback: async () => {
      actions.push('callback');
    },
    readProfile: async () => {
      actions.push('profile');
      return { sub: 'owner', email: 'original@example.invalid', emailVerified: true };
    },
    refresh: async () => {
      actions.push('refresh');
      return { subject: 'owner', rotated: true };
    },
    ...overrides,
  };
  return {
    actions,
    input: {
      session,
      expectedSubject: 'owner',
      originalOwnerEmail: 'original@example.invalid',
      changedProviderEmail: 'changed@example.invalid',
      assertChangedEmailProviderCase:
        assertCase ??
        (async () => {
          actions.push('provider-case');
        }),
      authorizationObservation: () => authorization,
    },
  };
};
test('retains the original owner profile while independently proving the changed provider case', async () => {
  const { input, actions } = setup();
  const result = await runCommonGoogleExistingOwnerSignIn(input);
  expect(result).toMatchObject({
    subjectPreserved: true,
    profileEmail: 'original-owner',
    providerEmailChangeObserved: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    refreshRotated: true,
    authorization,
  });
  expect(actions).toEqual([
    'google-open:/demo-app',
    'google-sign-in:/sign-in,/sign-in/identifier,/sign-in/password',
    'google-provider-count:1',
    'google-provider',
    'google-consent:/consent',
    'google-authorize',
    'callback',
    'profile',
    'refresh',
    'provider-case',
  ]);
  expect(JSON.stringify(result)).not.toMatch(/original@example|changed@example/u);
  expect(result.authorization).not.toBe(authorization);
  expect(Object.isFrozen(result.authorization)).toBe(true);
});
test('preserves a changed profile email as a distinct differential outcome', async () => {
  const { input } = setup({
    readProfile: async () => ({
      sub: 'owner',
      email: 'changed@example.invalid',
      emailVerified: true,
    }),
  });
  expect(await runCommonGoogleExistingOwnerSignIn(input)).toMatchObject({
    profileEmail: 'changed-provider',
  });
});
test.each([
  [
    'count',
    {
      expectCount: async () => {
        throw new Error('private count');
      },
    },
    'provider-count',
  ],
  [
    'click',
    {
      click: async () => {
        throw new Error('private click');
      },
    },
    'provider-click',
  ],
] as const)(
  'reports exact provider %s failure before later flow stages',
  async (_name, override, stage) => {
    const { input, actions } = setup(override);
    await expect(runCommonGoogleExistingOwnerSignIn(input)).rejects.toThrow(
      `Common Google existing-owner failed: ${stage}`
    );
    expect(actions).not.toContain('callback');
    expect(actions).not.toContain('profile');
  }
);
test.each([
  { sub: 'foreign', email: 'original@example.invalid', emailVerified: true },
  { sub: 'owner', email: 'unexpected@example.invalid', emailVerified: true },
  { sub: 'owner', email: 'original@example.invalid', emailVerified: false },
])('rejects foreign ownership, unexpected contact, or an unverified profile', async (profile) => {
  const { input, actions } = setup({ readProfile: async () => profile });
  await expect(runCommonGoogleExistingOwnerSignIn(input)).rejects.toThrow(
    'Common Google existing-owner failed: profile'
  );
  expect(actions).not.toContain('refresh');
  expect(actions).not.toContain('provider-case');
});
test('rejects missing provider-case evidence without exposing its private error', async () => {
  const { input } = setup({}, async () => {
    throw new Error('private-provider-code');
  });
  await expect(runCommonGoogleExistingOwnerSignIn(input)).rejects.toThrow(
    'Common Google existing-owner failed: provider-case'
  );
});
test('does not publish callback success when the inherited protocol assertion rejects', async () => {
  const { input, actions } = setup({
    assertInitialCallback: async () => {
      throw new Error('private-callback-state');
    },
  });
  await expect(runCommonGoogleExistingOwnerSignIn(input)).rejects.toThrow(
    'Common Google existing-owner failed: callback'
  );
  expect(actions).not.toContain('profile');
});

test('preserves an exact inherited callback field without copying unknown callback errors', async () => {
  const { input } = setup({
    assertInitialCallback: async () => {
      throw new TypeError('Common email password callback failed: exchange-scope');
    },
  });
  await expect(runCommonGoogleExistingOwnerSignIn(input)).rejects.toThrow(
    'Common Google existing-owner failed: callback-exchange-scope'
  );
});

test('does not invoke an accessor-backed callback error message', async () => {
  let reads = 0;
  const error = new Error('private callback');
  Object.defineProperty(error, 'message', {
    get: () => {
      reads += 1;
      return 'Common email password callback failed: exchange-scope';
    },
  });
  const { input } = setup({
    assertInitialCallback: async () => {
      throw error;
    },
  });
  await expect(runCommonGoogleExistingOwnerSignIn(input)).rejects.toThrow(
    'Common Google existing-owner failed: callback'
  );
  expect(reads).toBe(0);
});

test('redacts a throwing authorization observer into the fixed authorization stage', async () => {
  const { input } = setup();
  const operation = runCommonGoogleExistingOwnerSignIn({
    ...input,
    authorizationObservation: () => {
      throw new Error('private-authorization-code');
    },
  });
  await expect(operation).rejects.toMatchObject({
    message: 'Common Google existing-owner failed: authorization',
  });
});

test('rejects authorization accessors without executing a secret-bearing getter', async () => {
  const { input } = setup();
  let getterCalls = 0;
  const getter = () => {
    getterCalls += 1;
    throw new Error('private-getter-code');
  };
  const observed = Object.defineProperty({ ...authorization }, 'clientMatched', { get: getter });
  await expect(
    runCommonGoogleExistingOwnerSignIn({
      ...input,
      authorizationObservation: () => observed,
    })
  ).rejects.toMatchObject({ message: 'Common Google existing-owner failed: authorization' });
  expect(getterCalls).toBe(0);
});

test('rejects extra secret fields instead of embedding the caller-owned observation', async () => {
  const { input } = setup();
  await expect(
    runCommonGoogleExistingOwnerSignIn({
      ...input,
      authorizationObservation: () => ({ ...authorization, privateCode: 'private-provider-code' }),
    })
  ).rejects.toMatchObject({ message: 'Common Google existing-owner failed: authorization' });
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
