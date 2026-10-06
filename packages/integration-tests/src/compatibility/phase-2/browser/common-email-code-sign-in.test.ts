/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Ordered browser actions and the control latch are the observable contract. */
import {
  runCommonEmailCodeSignIn,
  type CommonEmailCodeBrowserSession,
  type CommonEmailCodeControlResult,
} from './common-email-code-sign-in.js';

const controls = Object.freeze({
  recipientMismatch: Object.freeze({
    status: 400 as const,
    error: 'verification_code.email_mismatch' as const,
  }),
  ownerAfterRecipientMismatch: Object.freeze({
    status: 200 as const,
    outcome: 'verified' as const,
  }),
  consumedReplay: Object.freeze({
    status: 400 as const,
    error: 'verification_code.not_found' as const,
  }),
  expiry: Object.freeze({ status: 400 as const, error: 'verification_code.expired' as const }),
  foreignAccountSurface: Object.freeze({
    status: 400 as const,
    error: 'verification_record.not_found' as const,
  }),
  ownerAfterForeignAccountSurface: Object.freeze({
    status: 200 as const,
    outcome: 'verified' as const,
  }),
  secondaryInteraction: Object.freeze({
    admissionStatus: 303 as const,
    interactionBound: true as const,
    initializationStatus: 204 as const,
  }),
  secondaryVerify: Object.freeze({
    status: 404 as const,
    outcome: 'error' as const,
    error: 'session.verification_session_not_found' as const,
  }),
  ownerAfterSecondaryVerify: Object.freeze({ status: 200 as const, outcome: 'verified' as const }),
}) satisfies CommonEmailCodeControlResult;

const session = (actions: string[]): CommonEmailCodeBrowserSession => ({
  navigate: async (step, path) => {
    actions.push(`${step}:${path}`);
  },
  waitForRoute: async (step, paths) => {
    actions.push(`${step}:${paths.join('|')}`);
  },
  fill: async (step, selector, value) => {
    actions.push(`${step}:${selector}:${value.length}`);
  },
  click: async (step, selector) => {
    actions.push(`${step}:${selector}`);
  },
  assertInitialCallback: async () => {
    actions.push('callback');
  },
  readProfile: async () => ({
    sub: 'owned-user',
    email: 'owner@example.invalid',
    emailVerified: true,
  }),
  refresh: async () => ({ subject: 'owned-user', rotated: true }),
});

const privateFailure = (): never => {
  throw new Error('private browser detail');
};
const failingSession = (stage: string): CommonEmailCodeBrowserSession => {
  const value = session([]);
  return {
    ...value,
    navigate: async (...input) =>
      stage === 'initialization' ? privateFailure() : value.navigate(...input),
    waitForRoute: async (...input) => {
      if (
        (stage === 'verification-route' && input[0] === 'wait-email-passcode') ||
        (stage === 'consent' && input[0] === 'wait-consent')
      ) {
        return privateFailure();
      }
      return value.waitForRoute(...input);
    },
    fill: async (...input) => {
      if (
        (stage === 'identifier-submit' && input[0] === 'fill-email') ||
        (stage === 'passcode-fill' && input[0] === 'fill-email-passcode-0')
      ) {
        return privateFailure();
      }
      return value.fill(...input);
    },
    assertInitialCallback: async () =>
      stage === 'callback' ? privateFailure() : value.assertInitialCallback(),
    readProfile: async () => (stage === 'profile' ? privateFailure() : value.readProfile()),
    refresh: async () => (stage === 'refresh' ? privateFailure() : value.refresh()),
  };
};

test('runs the six-input email flow and returns the exact shared control contract', async () => {
  const actions: string[] = [];
  const result = await runCommonEmailCodeSignIn({
    session: session(actions),
    email: 'Owner@Example.Invalid',
    canonicalEmail: 'owner@example.invalid',
    expectedSubject: 'owned-user',
    takePasscode: async (recipient) => {
      expect(recipient).toBe('Owner@Example.Invalid');
      return '012345';
    },
    runControls: async () => controls,
  });
  expect(actions.filter((action) => action.includes('passcode_'))).toEqual([
    'fill-email-passcode-0:input[name="passcode_0"]:1',
    'fill-email-passcode-1:input[name="passcode_1"]:1',
    'fill-email-passcode-2:input[name="passcode_2"]:1',
    'fill-email-passcode-3:input[name="passcode_3"]:1',
    'fill-email-passcode-4:input[name="passcode_4"]:1',
    'fill-email-passcode-5:input[name="passcode_5"]:1',
  ]);
  expect(result).toEqual(
    expect.objectContaining({
      verificationOutcome: 'accepted',
      emailVerified: true,
      controls,
    })
  );
  expect(JSON.stringify(result)).not.toContain('012345');
});

test.each([
  'initialization',
  'identifier-submit',
  'verification-route',
  'passcode-retrieval',
  'passcode-format',
  'passcode-fill',
  'consent',
  'callback',
  'profile',
  'refresh',
  'controls',
])('reports only the fixed %s boundary for a private operation error', async (stage) => {
  const operation = runCommonEmailCodeSignIn({
    session: failingSession(stage),
    email: 'Owner@Example.Invalid',
    canonicalEmail: 'owner@example.invalid',
    expectedSubject: 'owned-user',
    takePasscode: async () => {
      if (stage === 'passcode-retrieval') {
        return privateFailure();
      }
      return stage === 'passcode-format' ? '12345' : '123456';
    },
    runControls: async () => (stage === 'controls' ? privateFailure() : controls),
  });
  await expect(operation).rejects.toThrow(`Common email code stage failed: ${stage}`);
  await expect(operation).rejects.not.toThrow('private browser detail');
});

test.each(['basic', 'foreign-account', 'secondary-client'] as const)(
  'preserves only the closed %s control group',
  async (group) => {
    await expect(
      runCommonEmailCodeSignIn({
        session: session([]),
        email: 'Owner@Example.Invalid',
        canonicalEmail: 'owner@example.invalid',
        expectedSubject: 'owned-user',
        takePasscode: async () => '123456',
        runControls: async () => {
          throw new Error(`Common email code control stage failed: ${group}`);
        },
      })
    ).rejects.toThrow(`Common email code stage failed: controls-${group}`);
  }
);

test.each([
  'env-missing',
  'socket-shape',
  'recipient',
  'connect',
  'timeout',
  'not-found',
  'response',
] as const)('preserves only the closed %s delivery category', async (stage) => {
  await expect(
    runCommonEmailCodeSignIn({
      session: session([]),
      email: 'Owner@Example.Invalid',
      canonicalEmail: 'owner@example.invalid',
      expectedSubject: 'owned-user',
      takePasscode: async () => {
        throw new TypeError(`Phase 2 verification delivery failed: ${stage}`);
      },
      runControls: async () => controls,
    })
  ).rejects.toThrow(`Common email code stage failed: passcode-retrieval-${stage}`);
});

test.each([
  { name: 'malformed passcode', passcode: '12345', profile: {} },
  {
    name: 'foreign profile',
    passcode: '123456',
    profile: { sub: 'foreign', email: 'owner@example.invalid', emailVerified: true },
  },
  {
    name: 'unverified email',
    passcode: '123456',
    profile: { sub: 'owned-user', email: 'owner@example.invalid', emailVerified: false },
  },
])('rejects $name before publishing a projection', async ({ passcode, profile }) => {
  let controlsRun = false;
  let refreshRun = false;
  await expect(
    runCommonEmailCodeSignIn({
      session: {
        ...session([]),
        readProfile: async () => profile,
        refresh: async () => {
          refreshRun = true;
          return { subject: 'owned-user', rotated: true };
        },
      },
      email: 'Owner@Example.Invalid',
      canonicalEmail: 'owner@example.invalid',
      expectedSubject: 'owned-user',
      takePasscode: async () => passcode,
      runControls: async () => {
        controlsRun = true;
        return controls;
      },
    })
  ).rejects.toThrow(
    `Common email code stage failed: ${passcode === '123456' ? 'profile' : 'passcode-format'}`
  );
  expect(controlsRun).toBe(false);
  if (passcode === '123456') {
    expect(refreshRun).toBe(false);
  }
});

test.each([
  {
    name: 'wrong observed status',
    result: { ...controls, expiry: { status: 404, error: 'verification_code.expired' } },
  },
  { name: 'extra field', result: { ...controls, unexpected: true } },
  {
    name: 'accessor field',
    result: Object.defineProperty({ ...controls }, 'unexpected', {
      enumerable: true,
      get: () => true,
    }),
  },
  {
    name: 'hidden symbol field',
    result: Object.defineProperty({ ...controls }, Symbol('private'), {
      enumerable: false,
      get: () => {
        throw new Error('symbol accessor must not run');
      },
    }),
  },
])('rejects $name in the control result before publishing', async ({ result }) => {
  await expect(
    runCommonEmailCodeSignIn({
      session: session([]),
      email: 'Owner@Example.Invalid',
      canonicalEmail: 'owner@example.invalid',
      expectedSubject: 'owned-user',
      takePasscode: async () => '123456',
      runControls: async () => result as CommonEmailCodeControlResult,
    })
  ).rejects.toThrow('Common email code stage failed: controls');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
