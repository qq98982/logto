import { types as nodeTypes } from 'node:util';

import type { CommonEmailPasswordBrowserSession } from './common-email-password-sign-in.js';
import type { GoogleAuthorizationObservation } from './google-authorization-observer.js';
import { googleSignInButtonSelectorCandidate } from './selected-google-connector-fixture.js';

export type CommonGoogleBrowserSession = Pick<
  CommonEmailPasswordBrowserSession,
  'navigate' | 'waitForRoute' | 'click' | 'assertInitialCallback' | 'readProfile' | 'refresh'
> &
  Readonly<{ expectCount(step: string, selector: string, expected: number): Promise<void> }>;

export type CommonGoogleExistingOwnerProjection = Readonly<{
  provider: 'google';
  existingOwner: true;
  subjectPreserved: true;
  profileEmail: 'original-owner' | 'changed-provider';
  emailVerified: true;
  providerEmailChangeObserved: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  refreshRotated: true;
  authorization: GoogleAuthorizationObservation;
}>;
type Stage =
  | 'admission'
  | 'initialization'
  | 'provider'
  | 'provider-count'
  | 'provider-click'
  | 'consent'
  | 'callback'
  | `callback-${string}`
  | 'profile'
  | 'refresh'
  | 'provider-case'
  | 'authorization';
const fail = (stage: Stage): never => {
  throw new TypeError(`Common Google existing-owner failed: ${stage}`);
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
    if (callbackField) {
      return fail(`callback-${callbackField}`);
    }
    return fail(stage);
  }
};

export const runCommonGoogleExistingOwnerSignIn = async (
  input: Readonly<{
    session: CommonGoogleBrowserSession;
    expectedSubject: string;
    originalOwnerEmail: string;
    changedProviderEmail: string;
    assertChangedEmailProviderCase(): Promise<void>;
    authorizationObservation(): GoogleAuthorizationObservation;
  }>
): Promise<CommonGoogleExistingOwnerProjection> => {
  if (
    !input.expectedSubject ||
    !input.originalOwnerEmail ||
    !input.changedProviderEmail ||
    input.originalOwnerEmail === input.changedProviderEmail
  ) {
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
  await atStage('consent', async () => {
    await input.session.waitForRoute('google-consent', ['/consent']);
    await input.session.click('google-authorize', 'role=button[name="Authorize"]');
  });
  await atStage('callback', async () => input.session.assertInitialCallback());
  const profileEmail = await atStage('profile', async () => {
    const profile = await input.session.readProfile();
    if (profile.sub !== input.expectedSubject || profile.emailVerified !== true) {
      return fail('profile');
    }
    return profile.email === input.originalOwnerEmail
      ? ('original-owner' as const)
      : profile.email === input.changedProviderEmail
        ? ('changed-provider' as const)
        : fail('profile');
  });
  await atStage('refresh', async () => {
    const refreshed = await input.session.refresh();
    if (refreshed.subject !== input.expectedSubject || !refreshed.rotated) {
      return fail('refresh');
    }
  });
  await atStage('provider-case', input.assertChangedEmailProviderCase);
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
    existingOwner: true,
    subjectPreserved: true,
    profileEmail,
    emailVerified: true,
    providerEmailChangeObserved: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    refreshRotated: true,
    authorization,
  });
};
