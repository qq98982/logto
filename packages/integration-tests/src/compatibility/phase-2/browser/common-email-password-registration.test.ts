/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function -- The stateful fake proves publication ordering and fresh-context ownership. */
import type { EmailPasswordRegistrationSession } from './common-email-password-registration.js';
import {
  commonEmailPasswordRegistrationPositiveProjection,
  runCommonEmailPasswordRegistration,
} from './common-email-password-registration.js';

const harness = (rejectCredential = false) => {
  let persisted = false;
  let captured = false;
  let contexts = 0;
  const session: EmailPasswordRegistrationSession = {
    navigate: async () => {},
    waitForRoute: async () => {},
    fill: async (_step, selector) => {
      if (selector === 'input[name="newPassword"]') {
        if (rejectCredential) {
          throw new Error('private credential rejection');
        }
        persisted = true;
      }
    },
    click: async () => {},
    confirmCredentialIfPresent: async () => {},
    assertInitialCallback: async () => {},
    readProfile: async () => ({
      sub: 'registered-owner',
      email: 'owner@example.invalid',
      emailVerified: true,
    }),
    refresh: async () => ({ subject: 'registered-owner', rotated: true }),
  };
  return {
    input: {
      email: 'owner@example.invalid',
      getPassword: () => 'private-fixture-credential',
      takePasscode: async () => '012345',
      readCreatedUser: async () => ({ id: 'registered-owner', hasPassword: persisted }),
      captureCreatedUser: async () => {
        captured = true;
      },
      withFreshSession: async <Result>(
        use: (value: EmailPasswordRegistrationSession) => Promise<Result>
      ) => {
        contexts += 1;
        return use(session);
      },
    },
    captured: () => captured,
    contexts: () => contexts,
  };
};

test('publishes verified password registration only after persistence and fresh same-owner sign-in', async () => {
  const value = harness();
  await expect(runCommonEmailPasswordRegistration(value.input)).resolves.toEqual(
    commonEmailPasswordRegistrationPositiveProjection
  );
  expect(value.captured()).toBe(true);
  expect(value.contexts()).toBe(2);
  expect(JSON.stringify(commonEmailPasswordRegistrationPositiveProjection)).not.toMatch(
    /private|012345|registered-owner/u
  );
});

test('stops before capture and fresh sign-in when password fulfillment is rejected', async () => {
  const value = harness(true);
  await expect(runCommonEmailPasswordRegistration(value.input)).rejects.toThrow(
    'Common email password registration failed: credential-fulfillment'
  );
  expect(value.captured()).toBe(false);
  expect(value.contexts()).toBe(1);
});

test.each(['invalid', 'UPPER@EXAMPLE.INVALID', `${'a'.repeat(321)}@example.invalid`])(
  'rejects malformed registration email %s before opening a browser',
  async (email) => {
    const value = harness();
    await expect(runCommonEmailPasswordRegistration({ ...value.input, email })).rejects.toThrow(
      'Common email password registration failed: admission'
    );
    expect(value.contexts()).toBe(0);
  }
);
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function */
