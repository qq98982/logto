/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The fake browser records actions and uses mutable call flags. */
import {
  runCommonEmailPasswordSignIn,
  type CommonEmailPasswordBrowserSession,
} from './common-email-password-sign-in.js';

test('drives mixed-case email UI and emits a credential-free closed projection', async () => {
  const actions: string[] = [];
  const session: CommonEmailPasswordBrowserSession = {
    navigate: async (_step, path) => {
      actions.push(`navigate:${path}`);
    },
    waitForRoute: async (_step, paths) => {
      actions.push(`route:${paths.join('|')}`);
    },
    fill: async (step, selector, value) => {
      actions.push(`${step}:${selector}:${selector.includes('password') ? '<credential>' : value}`);
    },
    click: async (step, selector) => {
      actions.push(`${step}:${selector}`);
    },
    assertInitialCallback: async () => {
      actions.push('callback');
    },
    readProfile: async () => ({
      sub: 'user-1',
      email: 'owner@example.invalid',
      emailVerified: true,
    }),
    refresh: async () => ({ subject: 'user-1', rotated: true }),
  };
  const projection = await runCommonEmailPasswordSignIn({
    session,
    email: 'Owner@Example.Invalid',
    canonicalEmail: 'owner@example.invalid',
    password: () => 'private-password',
    expectedSubject: 'user-1',
    invalidPassword: () => 'private-wrong-password',
    usernameControl: {
      identifier: 'existing-username',
      password: () => 'private-existing-password',
      expectedSubject: 'existing-user',
    },
    controls: {
      assertInvalidPassword: async (identifier, password) => {
        actions.push(`attempt:${identifier}`);
        expect(password).toBe('private-wrong-password');
      },
      assertSuspended: async (identifier, password) => {
        actions.push(`attempt:${identifier}`);
        expect(password).toBe('private-password');
      },
      authenticateUsername: async (identifier, password) => {
        actions.push(`attempt:${identifier}`);
        expect(password).toBe('private-existing-password');
        return 'existing-user';
      },
      setSuspended: async (userId, suspended) => {
        actions.push(`suspend:${userId}:${String(suspended)}`);
      },
    },
  });
  expect(actions).toEqual([
    'navigate:/demo-app',
    'route:/sign-in|/sign-in/password',
    'fill-email:input[name="identifier"]:Owner@Example.Invalid',
    'fill-password:input[name="password"]:<credential>',
    'submit-sign-in:button[name="submit"]',
    'route:/consent',
    'authorize-consent:role=button[name="Authorize"]',
    'callback',
    'attempt:owner@example.invalid',
    'suspend:user-1:true',
    'attempt:owner@example.invalid',
    'suspend:user-1:false',
    'attempt:existing-username',
  ]);
  expect(projection).toEqual({
    identifier: 'email',
    casing: 'canonical-owner',
    passwordOutcome: 'accepted',
    consent: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    profileSubject: true,
    emailVerified: true,
    refreshRotated: true,
    invalidPassword: 'rejected',
    suspended: 'rejected',
    usernamePreserved: true,
  });
  expect(JSON.stringify(projection)).not.toContain('private-password');
});

test('restores suspension when the suspended login attempt throws', async () => {
  const suspension: boolean[] = [];
  const session = {
    navigate: async () => {},
    waitForRoute: async () => {},
    fill: async () => {},
    click: async () => {},
    assertInitialCallback: async () => {},
    readProfile: async () => ({
      sub: 'user-1',
      email: 'owner@example.invalid',
      emailVerified: true,
    }),
    refresh: async () => ({ subject: 'user-1', rotated: true }),
  } satisfies CommonEmailPasswordBrowserSession;
  await expect(
    runCommonEmailPasswordSignIn({
      session,
      email: 'Owner@Example.Invalid',
      canonicalEmail: 'owner@example.invalid',
      password: () => 'private-password',
      expectedSubject: 'user-1',
      invalidPassword: () => 'wrong',
      usernameControl: {
        identifier: 'existing',
        password: () => 'existing-secret',
        expectedSubject: 'existing-user',
      },
      controls: {
        assertInvalidPassword: async () => {},
        assertSuspended: async () => {
          throw new Error('attempt failed');
        },
        authenticateUsername: async () => 'existing-user',
        setSuspended: async (_userId, value) => {
          suspension.push(value);
        },
      },
    })
  ).rejects.toThrow('Common email password stage failed: controls-suspended-attempt');
  expect(suspension).toEqual([true, false]);
});

test('restores suspension when the mutation acknowledgement throws', async () => {
  const suspension: boolean[] = [];
  const session = {
    navigate: async () => {},
    waitForRoute: async () => {},
    fill: async () => {},
    click: async () => {},
    assertInitialCallback: async () => {},
    readProfile: async () => ({
      sub: 'user-1',
      email: 'owner@example.invalid',
      emailVerified: true,
    }),
    refresh: async () => ({ subject: 'user-1', rotated: true }),
  } satisfies CommonEmailPasswordBrowserSession;
  await expect(
    runCommonEmailPasswordSignIn({
      session,
      email: 'Owner@Example.Invalid',
      canonicalEmail: 'owner@example.invalid',
      password: () => 'private-password',
      expectedSubject: 'user-1',
      invalidPassword: () => 'wrong',
      usernameControl: {
        identifier: 'existing',
        password: () => 'existing-secret',
        expectedSubject: 'existing-user',
      },
      controls: {
        assertInvalidPassword: async () => {},
        assertSuspended: async () => {},
        authenticateUsername: async () => 'existing-user',
        setSuspended: async (_userId, value) => {
          suspension.push(value);
          if (value) {
            throw new Error('malformed mutation acknowledgement');
          }
        },
      },
    })
  ).rejects.toThrow('Common email password stage failed: controls-suspended-set');
  expect(suspension).toEqual([true, false]);
});

test.each([
  ['false', false],
  ['missing', undefined],
  ['string', 'true'],
] as const)(
  'rejects a %s email verification claim before refresh and controls',
  async (_case, emailVerified) => {
    let refreshCalled = false;
    let controlCalled = false;
    const session = {
      navigate: async () => {},
      waitForRoute: async () => {},
      fill: async () => {},
      click: async () => {},
      assertInitialCallback: async () => {},
      readProfile: async () => ({ sub: 'user-1', email: 'owner@example.invalid', emailVerified }),
      refresh: async () => {
        refreshCalled = true;
        return { subject: 'user-1', rotated: true };
      },
    } satisfies CommonEmailPasswordBrowserSession;

    await expect(
      runCommonEmailPasswordSignIn({
        session,
        email: 'Owner@Example.Invalid',
        canonicalEmail: 'owner@example.invalid',
        password: () => 'private-password',
        expectedSubject: 'user-1',
        invalidPassword: () => 'wrong',
        usernameControl: {
          identifier: 'existing',
          password: () => 'existing-secret',
          expectedSubject: 'existing-user',
        },
        controls: {
          assertInvalidPassword: async () => {
            controlCalled = true;
          },
          assertSuspended: async () => {
            controlCalled = true;
          },
          authenticateUsername: async () => {
            controlCalled = true;
            return 'existing-user';
          },
          setSuspended: async () => {
            controlCalled = true;
          },
        },
      })
    ).rejects.toThrow('Common email password stage failed: profile-email-verified');
    expect(refreshCalled).toBe(false);
    expect(controlCalled).toBe(false);
  }
);

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
