/* eslint-disable curly, @typescript-eslint/no-empty-function, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Ordered call recording proves capture and callback sequencing. */
import { runCommonEmailCodeRegistration } from './common-email-code-registration.js';
/* eslint-disable no-await-in-loop -- Callback hardening tests exercise two ordered hostile errors. */
import type { CommonEmailCodeBrowserSession } from './common-email-code-sign-in.js';

const session = (actions: string[], failAt?: string): CommonEmailCodeBrowserSession => ({
  navigate: async (step, path) => {
    actions.push(`${step}:${path}`);
    if (failAt === step) throw new Error('private navigation failure');
  },
  waitForRoute: async (step, paths) => {
    actions.push(`${step}:${paths.join('|')}`);
    if (failAt === step) throw new Error('private route failure');
  },
  fill: async (step, selector, value) => {
    actions.push(`${step}:${selector}:${value.length}`);
    if (failAt === step) throw new Error('private fill failure');
  },
  click: async (step, selector) => {
    actions.push(`${step}:${selector}`);
    if (failAt === step) throw new Error('private click failure');
  },
  assertInitialCallback: async () => {
    actions.push('callback');
    if (failAt === 'callback') throw new Error('private callback failure');
  },
  readProfile: async () => {
    actions.push('profile');
    return { sub: 'registered-user', email: 'new@example.invalid', emailVerified: true };
  },
  refresh: async () => {
    actions.push('refresh');
    return { subject: 'registered-user', rotated: true };
  },
});

test('registers with six code inputs, captures the actual subject, then proves callback and refresh', async () => {
  const actions: string[] = [];
  const result = await runCommonEmailCodeRegistration({
    session: session(actions),
    email: 'new@example.invalid',
    takePasscode: async (recipient) => {
      actions.push(`code:${recipient}`);
      return '012345';
    },
    readRegistrationSubject: async (email) => {
      actions.push(`subject:${email}`);
      return { id: 'registered-user', primaryEmail: email };
    },
    captureRegisteredUser: async (id) => {
      actions.push(`capture:${id}`);
    },
  });
  expect(actions).toEqual([
    'open-demo:/demo-app',
    'wait-sign-in:/sign-in|/sign-in/password',
    'open-register:role=link[name="Create account"]',
    'wait-register:/register',
    'fill-registration-email:input[name="identifier"]:19',
    'submit-registration-email:button[name="submit"]',
    'wait-registration-passcode:/register/verification-code',
    'code:new@example.invalid',
    'fill-registration-passcode-0:input[name="passcode_0"]:1',
    'fill-registration-passcode-1:input[name="passcode_1"]:1',
    'fill-registration-passcode-2:input[name="passcode_2"]:1',
    'fill-registration-passcode-3:input[name="passcode_3"]:1',
    'fill-registration-passcode-4:input[name="passcode_4"]:1',
    'fill-registration-passcode-5:input[name="passcode_5"]:1',
    'wait-registration-consent:/consent',
    'subject:new@example.invalid',
    'capture:registered-user',
    'authorize-registration-consent:role=button[name="Authorize"]',
    'callback',
    'profile',
    'refresh',
  ]);
  expect(result).toEqual({
    identifier: 'email',
    registrationOutcome: 'created',
    consent: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    profileSubject: true,
    emailVerified: true,
    refreshRotated: true,
  });
  expect(JSON.stringify(result)).not.toContain('012345');
  expect(JSON.stringify(result)).not.toContain('registered-user');
});

test.each([
  ['init', 404, 'session.interaction_not_found', 'init-s404-session-interaction-not-found'],
  ['send', 501, 'connector.not_found', 'send-s501-connector-not-found'],
] as const)(
  'reports bounded %s request facts when registration does not navigate',
  async (kind, status, error, expected) => {
    await expect(
      runCommonEmailCodeRegistration({
        session: {
          ...session([], 'wait-registration-passcode'),
          registrationRequestFacts: async () => [{ kind, status, error }],
        },
        email: 'new@example.invalid',
        takePasscode: async () => '123456',
        readRegistrationSubject: async (email) => ({ id: 'registered-user', primaryEmail: email }),
        captureRegisteredUser: async () => {},
      })
    ).rejects.toThrow(
      `Common email code registration stage failed: verification-route-${expected}`
    );
  }
);

test('captures the registered subject before a later callback failure', async () => {
  const actions: string[] = [];
  await expect(
    runCommonEmailCodeRegistration({
      session: session(actions, 'callback'),
      email: 'new@example.invalid',
      takePasscode: async () => '123456',
      readRegistrationSubject: async (email) => ({ id: 'registered-user', primaryEmail: email }),
      captureRegisteredUser: async (id) => {
        actions.push(`capture:${id}`);
      },
    })
  ).rejects.toThrow('Common email code registration stage failed: callback');
  expect(actions.indexOf('capture:registered-user')).toBeLessThan(actions.indexOf('callback'));
  expect(actions.join(' ')).not.toContain('private callback failure');
});

test('does not invoke callback message accessors or proxy traps', async () => {
  let traps = 0;
  const accessor = Object.defineProperty(new Error('closed callback failure'), 'message', {
    get: () => {
      traps += 1;
      throw new Error('private callback message');
    },
  });
  const proxied = new Proxy(new Error('Common email password callback failed: callback-state'), {
    getOwnPropertyDescriptor: () => {
      traps += 1;
      throw new Error('private callback descriptor');
    },
  });
  for (const failure of [accessor, proxied]) {
    await expect(
      runCommonEmailCodeRegistration({
        session: {
          ...session([]),
          assertInitialCallback: async () => {
            throw failure;
          },
        },
        email: 'new@example.invalid',
        takePasscode: async () => '123456',
        readRegistrationSubject: async (email) => ({
          id: 'registered-user',
          primaryEmail: email,
        }),
        captureRegisteredUser: async () => {},
      })
    ).rejects.toThrow('Common email code registration stage failed: callback');
  }
  expect(traps).toBe(0);
});
/* eslint-enable no-await-in-loop */

test.each([
  [
    'registration-subject',
    async (): Promise<{ id: string; primaryEmail: string }> => ({ id: '', primaryEmail: '' }),
    async (): Promise<void> => {},
  ],
  [
    'registration-capture',
    async (): Promise<{ id: string; primaryEmail: string }> => ({
      id: 'registered-user',
      primaryEmail: 'new@example.invalid',
    }),
    async (): Promise<void> => {
      throw new Error('private ownership failure');
    },
  ],
] as const)('fails closed at %s without running callback', async (stage, readSubject, capture) => {
  const actions: string[] = [];
  await expect(
    runCommonEmailCodeRegistration({
      session: session(actions),
      email: 'new@example.invalid',
      takePasscode: async () => '123456',
      readRegistrationSubject: readSubject,
      captureRegisteredUser: capture,
    })
  ).rejects.toThrow(`Common email code registration stage failed: ${stage}`);
  expect(actions).not.toContain('callback');
  expect(actions.join(' ')).not.toContain('private ownership failure');
});

test('rejects accessor-backed subject ownership without invoking the accessor', async () => {
  let getterCalls = 0;
  const ownership = Object.defineProperty({ id: 'registered-user' }, 'primaryEmail', {
    enumerable: true,
    get: () => {
      getterCalls += 1;
      throw new Error('private ownership value');
    },
  }) as { id: string; primaryEmail: string };
  await expect(
    runCommonEmailCodeRegistration({
      session: session([]),
      email: 'new@example.invalid',
      takePasscode: async () => '123456',
      readRegistrationSubject: async () => ownership,
      captureRegisteredUser: async () => {},
    })
  ).rejects.toThrow('Common email code registration stage failed: registration-subject');
  expect(getterCalls).toBe(0);
});

test.each([
  ['malformed code', '12345', 'passcode-format'],
  ['delivery error', null, 'passcode-retrieval-timeout'],
] as const)('rejects %s before subject ownership', async (_name, code, stage) => {
  let subjectRead = false;
  await expect(
    runCommonEmailCodeRegistration({
      session: session([]),
      email: 'new@example.invalid',
      takePasscode: async () => {
        if (code === null) throw new Error('Phase 2 verification delivery failed: timeout');
        return code;
      },
      readRegistrationSubject: async () => {
        subjectRead = true;
        return { id: 'registered-user', primaryEmail: 'new@example.invalid' };
      },
      captureRegisteredUser: async () => {},
    })
  ).rejects.toThrow(`Common email code registration stage failed: ${stage}`);
  expect(subjectRead).toBe(false);
});
/* eslint-enable curly, @typescript-eslint/no-empty-function, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
