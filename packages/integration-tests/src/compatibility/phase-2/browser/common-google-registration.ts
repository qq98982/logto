import { types as nodeTypes } from 'node:util';

import type { CommonEmailPasswordBrowserSession } from './common-email-password-sign-in.js';
import type { GoogleAuthorizationObservation } from './google-authorization-observer.js';
import { googleSignInButtonSelectorCandidate } from './selected-google-connector-fixture.js';

export type CommonGoogleBrowserSession = Pick<
  CommonEmailPasswordBrowserSession,
  'navigate' | 'waitForRoute' | 'click' | 'assertInitialCallback' | 'readProfile' | 'refresh'
> &
  Readonly<{
    expectCount(step: string, selector: string, expected: number): Promise<void>;
    readExperienceFailure(): Promise<Readonly<{ operation: string; status: number; code: string }>>;
    consentFailureRoute(): Promise<`${'sign-in' | 'register' | 'continue' | 'demo' | 'error' | 'other'}-${
      | 'social-verify'
      | 'identification'
      | 'submit'
      | 'none'}-${400 | 401 | 403 | 404 | 409 | 422 | 500 | 503 | 0}-${string}`>;
  }>;

export type CommonGoogleRegistrationProjection = Readonly<{
  provider: 'google';
  newOwner: true;
  identityCreated: true;
  profileEmail: 'verified-provider';
  emailVerified: true;
  passwordVerification: false;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  refreshRotated: true;
  authorization: GoogleAuthorizationObservation;
}>;

type Stage =
  | 'admission'
  | 'initialization'
  | 'registration-transition'
  | 'missing-owner'
  | 'registration-route'
  | 'provider-count'
  | 'provider-click'
  | 'consent-route'
  | `consent-route-${string}`
  | 'consent-click'
  | 'callback'
  | `callback-${string}`
  | 'profile'
  | 'refresh'
  | 'owner-lookup'
  | 'authorization';

const fail = (stage: Stage): never => {
  throw new TypeError(`Common Google registration failed: ${stage}`);
};

const ownErrorMessage = (error: unknown): string | undefined => {
  if (nodeTypes.isProxy(error) || !(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const value: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  return typeof value === 'string' ? value : undefined;
};

const atStage = async <Result>(stage: Stage, operation: () => Promise<Result>): Promise<Result> => {
  try {
    return await operation();
  } catch (error: unknown) {
    const callbackField =
      stage === 'callback'
        ? /^Common email password callback failed: (callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access))$/u.exec(
            ownErrorMessage(error) ?? ''
          )?.[1]
        : undefined;
    return fail(callbackField ? `callback-${callbackField}` : stage);
  }
};

export const runCommonGoogleRegistration = async (
  input: Readonly<{
    session: CommonGoogleBrowserSession;
    expectedEmail: string;
    assertRegisteredOwner(subject: string): Promise<Readonly<{ hasPassword: false }>>;
    authorizationObservation(): GoogleAuthorizationObservation;
  }>
): Promise<CommonGoogleRegistrationProjection> => {
  if (!input.expectedEmail) {
    return fail('admission');
  }

  await atStage('initialization', async () => {
    await input.session.navigate('google-open', '/demo-app');
    await input.session.waitForRoute('google-sign-in', [
      '/sign-in',
      '/sign-in/identifier',
      '/sign-in/password',
    ]);
  });
  await atStage('provider-count', async () =>
    input.session.expectCount('google-provider-count', googleSignInButtonSelectorCandidate, 1)
  );
  await atStage('provider-click', async () =>
    input.session.click('google-provider', googleSignInButtonSelectorCandidate)
  );
  await atStage('missing-owner', async () => {
    await input.session.waitForRoute('google-missing-owner-sign-in', [
      '/sign-in',
      '/sign-in/identifier',
      '/sign-in/password',
    ]);
    const failure = await input.session.readExperienceFailure();
    if (
      failure.operation !== 'social-verify' ||
      failure.status !== 404 ||
      failure.code !== 'user.identity_not_exist'
    ) {
      return fail('missing-owner');
    }
  });
  await atStage('registration-transition', async () => {
    await input.session.expectCount(
      'google-registration-link-count',
      'role=link[name="Create account"]',
      1
    );
    await input.session.click('google-registration-link', 'role=link[name="Create account"]');
  });
  await atStage('registration-route', async () =>
    input.session.waitForRoute('google-register', ['/register'])
  );
  try {
    await input.session.waitForRoute('google-consent', ['/consent']);
  } catch {
    return fail(`consent-route-${await input.session.consentFailureRoute()}`);
  }
  await atStage('consent-click', async () =>
    input.session.click('google-authorize', 'role=button[name="Authorize"]')
  );
  await atStage('callback', async () => input.session.assertInitialCallback());
  const subject = await atStage('profile', async () => {
    const profile = await input.session.readProfile();
    if (
      typeof profile.sub !== 'string' ||
      !profile.sub ||
      profile.email !== input.expectedEmail ||
      profile.emailVerified !== true
    ) {
      return fail('profile');
    }
    return profile.sub;
  });
  await atStage('refresh', async () => {
    const refreshed = await input.session.refresh();
    if (refreshed.subject !== subject || !refreshed.rotated) {
      return fail('refresh');
    }
  });
  const owner = await atStage('owner-lookup', async () => input.assertRegisteredOwner(subject));
  const authorization = await atStage('authorization', async () => {
    const observed = input.authorizationObservation();
    const fields = [
      'requestCount',
      'queryShapeExact',
      'clientMatched',
      'callbackMatched',
      'responseTypeCode',
      'scopeExact',
      'stateFormatValid',
      'stateRoundTrip',
      'fulfilledOnce',
    ];
    const descriptors = Object.getOwnPropertyDescriptors(observed);
    if (
      Object.getOwnPropertySymbols(observed).length > 0 ||
      Object.getOwnPropertyNames(observed).length !== fields.length ||
      fields.some((field) => !descriptors[field] || !('value' in descriptors[field])) ||
      descriptors.requestCount.value !== 1 ||
      fields.slice(1).some((field) => descriptors[field]?.value !== true)
    ) {
      return fail('authorization');
    }
    return Object.freeze({
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
  });

  return Object.freeze({
    provider: 'google',
    newOwner: true,
    identityCreated: true,
    profileEmail: 'verified-provider',
    emailVerified: true,
    passwordVerification: owner.hasPassword,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    refreshRotated: true,
    authorization,
  });
};
