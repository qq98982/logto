import type { CommonGoogleRegistrationScenarioProjection } from './common-google-registration.js';
import {
  commonGoogleRegistrationScenarioIds,
  compareCommonGoogleRegistrationProjections,
  describeCommonGoogleRegistrationProjectionDifference,
} from './common-google-registration.js';

const projection = Object.freeze({
  provider: 'google',
  newOwner: true,
  identityCreated: true,
  profileEmail: 'verified-provider',
  emailVerified: true,
  hasPassword: false,
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  refreshRotated: true,
  googleRequest: Object.freeze({
    requestCount: 1,
    queryShapeExact: true,
    clientMatched: true,
    callbackMatched: true,
    responseTypeCode: true,
    scopeExact: true,
    stateFormatValid: true,
    stateRoundTrip: true,
    fulfilledOnce: true,
  }),
  unverifiedEmail: Object.freeze({
    accepted: false,
    status: 200,
    error: 'none',
    userCountUnchanged: true,
    associationCreated: false,
    collisionOwnerPreserved: true,
  }),
  occupiedEmail: Object.freeze({
    accepted: false,
    status: 422,
    error: 'user.email_already_in_use',
    userCountUnchanged: true,
    associationCreated: false,
    collisionOwnerPreserved: true,
  }),
}) satisfies CommonGoogleRegistrationScenarioProjection;

test('declares the canonical Common Google registration row', () => {
  expect(commonGoogleRegistrationScenarioIds).toEqual(['common.google.registration']);
  expect(Object.isFrozen(commonGoogleRegistrationScenarioIds)).toBe(true);
});

test('requires exact equal positive and denied-control projections', () => {
  expect(compareCommonGoogleRegistrationProjections(projection, projection)).toEqual([]);
  expect(
    compareCommonGoogleRegistrationProjections(projection, {
      ...projection,
      occupiedEmail: { ...projection.occupiedEmail, status: 400 },
    })
  ).toEqual(['/projection']);
});

test('reports the first public control mismatch', () => {
  expect(
    describeCommonGoogleRegistrationProjectionDifference(projection, {
      ...projection,
      unverifiedEmail: { ...projection.unverifiedEmail, error: 'guard.invalid_input' },
    })
  ).toEqual({
    field: 'unverified-email-error',
    oracle: 'none',
    candidate: 'guard.invalid_input',
  });
});

test('accepts the observed missing-profile denial only for unverified email', () => {
  const unverifiedMissingProfile = {
    ...projection,
    unverifiedEmail: {
      ...projection.unverifiedEmail,
      status: 422,
      error: 'user.missing_profile' as const,
    },
  };
  expect(
    compareCommonGoogleRegistrationProjections(unverifiedMissingProfile, unverifiedMissingProfile)
  ).toEqual([]);
  const occupiedMissingProfile = {
    ...projection,
    occupiedEmail: {
      ...projection.occupiedEmail,
      status: 422,
      error: 'user.missing_profile' as const,
    },
  };
  expect(
    compareCommonGoogleRegistrationProjections(occupiedMissingProfile, occupiedMissingProfile)
  ).toEqual([]);
});

test('rejects accepted, partial, extra, and private control outcomes', () => {
  for (const candidate of [
    { ...projection, unverifiedEmail: { ...projection.unverifiedEmail, accepted: true } },
    { ...projection, occupiedEmail: { ...projection.occupiedEmail, associationCreated: true } },
    { ...projection, occupiedEmail: { ...projection.occupiedEmail, private: 'forbidden' } },
    { ...projection, unverifiedEmail: { ...projection.unverifiedEmail, error: 'private.error' } },
  ]) {
    expect(compareCommonGoogleRegistrationProjections(projection, candidate)).toEqual([
      '/projection',
    ]);
  }
});
