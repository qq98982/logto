/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Ordered browser steps and negative latches are the observable test state. */
import { commonGoogleCleanupStageForTesting } from './common-google-registration-target-driver.js';
import type { CommonGoogleBrowserSession } from './common-google-registration.js';
import { runCommonGoogleRegistration } from './common-google-registration.js';

test('preserves the connector DELETE status from cleanup aggregates', () => {
  const error = new AggregateError(
    [new TypeError('Selected Google connector fixture failed: delete-connector-status-500')],
    'Selected Google connector cleanup failed'
  );
  expect(commonGoogleCleanupStageForTesting(error)).toBe('fixture-delete-connector-status-500');
});

const authorization = Object.freeze({
  requestCount: 1 as const,
  queryShapeExact: true as const,
  clientMatched: true as const,
  callbackMatched: true as const,
  responseTypeCode: true as const,
  scopeExact: true as const,
  stateFormatValid: true as const,
  stateRoundTrip: true as const,
  fulfilledOnce: true as const,
});

const createSession = () => {
  const steps: string[] = [];
  const session: CommonGoogleBrowserSession = {
    navigate: async (step) => {
      steps.push(step);
    },
    waitForRoute: async (step) => {
      steps.push(step);
    },
    click: async (step) => {
      steps.push(step);
    },
    expectCount: async (step) => {
      steps.push(step);
    },
    consentFailureRoute: async () => 'other-none-0-none',
    readExperienceFailure: async () => ({
      operation: 'social-verify',
      status: 404,
      code: 'user.identity_not_exist',
    }),
    assertInitialCallback: async () => {
      steps.push('callback');
    },
    readProfile: async () => ({
      sub: 'new-owner',
      email: 'new-owner@example.invalid',
      emailVerified: true,
    }),
    refresh: async () => ({ subject: 'new-owner', rotated: true }),
  };
  return { session, steps };
};

test('registers a verified Google user through the visible registration transition', async () => {
  const { session, steps } = createSession();

  await expect(
    runCommonGoogleRegistration({
      session,
      expectedEmail: 'new-owner@example.invalid',
      assertRegisteredOwner: async (subject) => {
        expect(subject).toBe('new-owner');
        return { hasPassword: false };
      },
      authorizationObservation: () => authorization,
    })
  ).resolves.toEqual({
    provider: 'google',
    newOwner: true,
    identityCreated: true,
    profileEmail: 'verified-provider',
    emailVerified: true,
    passwordVerification: false,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    refreshRotated: true,
    authorization,
  });
  expect(steps).toEqual([
    'google-open',
    'google-sign-in',
    'google-provider-count',
    'google-provider',
    'google-missing-owner-sign-in',
    'google-registration-link-count',
    'google-registration-link',
    'google-register',
    'google-consent',
    'google-authorize',
    'callback',
  ]);
});

test('publishes the bounded route and response when consent is not reached', async () => {
  const { session } = createSession();
  await expect(
    runCommonGoogleRegistration({
      session: {
        ...session,
        waitForRoute: async (step, paths) => {
          if (step === 'google-consent') {
            throw new Error('private response');
          }
          await session.waitForRoute(step, paths);
        },
        consentFailureRoute: async () => 'continue-identification-422-missing-profile',
      },
      expectedEmail: 'new-owner@example.invalid',
      assertRegisteredOwner: async () => ({ hasPassword: false }),
      authorizationObservation: () => authorization,
    })
  ).rejects.toThrow(
    'Common Google registration failed: consent-route-continue-identification-422-missing-profile'
  );
});

test.each([
  ['registration transition', 'google-registration-link', 'registration-transition'],
  ['provider button', 'google-provider', 'provider-click'],
  ['owner lookup', 'owner-lookup', 'owner-lookup'],
] as const)('publishes the closed %s failure stage', async (_name, failedStep, expectedStage) => {
  const { session } = createSession();
  const wrapped = {
    ...session,
    click: async (step: string, selector: string) => {
      if (step === failedStep) {
        throw new Error('private provider value');
      }
      await session.click(step, selector);
    },
  };

  await expect(
    runCommonGoogleRegistration({
      session: wrapped,
      expectedEmail: 'new-owner@example.invalid',
      assertRegisteredOwner: async () => {
        if (failedStep === 'owner-lookup') {
          throw new Error('private owner id');
        }
        return { hasPassword: false };
      },
      authorizationObservation: () => authorization,
    })
  ).rejects.toThrow(`Common Google registration failed: ${expectedStage}`);
});

test('rejects an unverified or mismatched public profile before refresh and owner lookup', async () => {
  const { session } = createSession();
  let refreshed = false;
  let lookedUp = false;

  await expect(
    runCommonGoogleRegistration({
      session: {
        ...session,
        readProfile: async () => ({
          sub: 'new-owner',
          email: 'other@example.invalid',
          emailVerified: false,
        }),
        refresh: async () => {
          refreshed = true;
          return { subject: 'new-owner', rotated: true };
        },
      },
      expectedEmail: 'new-owner@example.invalid',
      assertRegisteredOwner: async () => {
        lookedUp = true;
        return { hasPassword: false };
      },
      authorizationObservation: () => authorization,
    })
  ).rejects.toThrow('Common Google registration failed: profile');
  expect(refreshed).toBe(false);
  expect(lookedUp).toBe(false);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
