/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Hostile accessor fixture proves the comparator never evaluates getters. */
import type { CommonGoogleExistingOwnerScenarioProjection } from './common-google-existing-owner.js';
import {
  commonGoogleExistingOwnerExpectedProjection,
  commonGoogleExistingOwnerScenarioIds,
  compareCommonGoogleExistingOwnerProjections,
} from './common-google-existing-owner.js';

const projection = Object.freeze({
  provider: commonGoogleExistingOwnerExpectedProjection.provider,
  existingOwner: commonGoogleExistingOwnerExpectedProjection.existingOwner,
  subjectPreserved: commonGoogleExistingOwnerExpectedProjection.subjectPreserved,
  profileEmail: commonGoogleExistingOwnerExpectedProjection.profileEmail,
  emailVerified: commonGoogleExistingOwnerExpectedProjection.emailVerified,
  providerEmailChangeObserved:
    commonGoogleExistingOwnerExpectedProjection.providerEmailChangeObserved,
  callback: commonGoogleExistingOwnerExpectedProjection.callback,
  pkce: commonGoogleExistingOwnerExpectedProjection.pkce,
  refreshRotated: commonGoogleExistingOwnerExpectedProjection.refreshRotated,
  googleRequest: commonGoogleExistingOwnerExpectedProjection.googleRequest,
  wrongState: Object.freeze({
    ...commonGoogleExistingOwnerExpectedProjection.wrongState,
    status: 400,
    error: 'unknown' as const,
  }),
  replay: Object.freeze({
    ...commonGoogleExistingOwnerExpectedProjection.replay,
    secondStatus: 404,
    secondError: 'session.verification_session_not_found' as const,
  }),
}) satisfies CommonGoogleExistingOwnerScenarioProjection;

test('declares the canonical Common Google existing-owner row', () => {
  expect(commonGoogleExistingOwnerScenarioIds).toEqual(['common.google.existing-owner']);
  expect(Object.isFrozen(commonGoogleExistingOwnerScenarioIds)).toBe(true);
});

test('accepts only exact cross-target rejected wrong-state and replay observations', () => {
  expect(compareCommonGoogleExistingOwnerProjections(projection, projection)).toEqual([]);
  expect(
    compareCommonGoogleExistingOwnerProjections(projection, {
      ...projection,
      replay: { ...projection.replay, secondStatus: 409 },
    })
  ).toEqual(['/projection']);
});

test.each([
  {
    name: 'accepted wrong state',
    change: {
      ...projection,
      wrongState: { ...projection.wrongState, callbackAccepted: true },
    },
  },
  {
    name: 'accepted replay',
    change: { ...projection, replay: { ...projection.replay, secondAccepted: true } },
  },
  {
    name: 'unknown replay result',
    change: { ...projection, replay: { ...projection.replay, secondAccepted: 'unknown' } },
  },
] as const)('rejects $name instead of normalizing a security outcome', ({ change }) => {
  expect(compareCommonGoogleExistingOwnerProjections(projection, change)).toEqual(['/projection']);
});

test.each([
  ['top extra field', { ...projection, privateValue: 'forbidden' }],
  [
    'wrong-state extra field',
    { ...projection, wrongState: { ...projection.wrongState, privateValue: 'forbidden' } },
  ],
  [
    'replay extra field',
    { ...projection, replay: { ...projection.replay, privateValue: 'forbidden' } },
  ],
  [
    'top authorization extra field',
    { ...projection, googleRequest: { ...projection.googleRequest, privateValue: 'forbidden' } },
  ],
  [
    'wrong-state authorization extra field',
    {
      ...projection,
      wrongState: {
        ...projection.wrongState,
        googleRequest: { ...projection.wrongState.googleRequest, privateValue: 'forbidden' },
      },
    },
  ],
] as const)('rejects a forged nested shape with a %s', (_name, forged) => {
  expect(compareCommonGoogleExistingOwnerProjections(forged, forged)).toEqual(['/projection']);
});

test.each([
  [
    'string wrong-state status',
    { ...projection, wrongState: { ...projection.wrongState, status: '400' } },
  ],
  [
    'string replay status',
    { ...projection, replay: { ...projection.replay, secondStatus: '404' } },
  ],
  [
    'unknown wrong-state error',
    { ...projection, wrongState: { ...projection.wrongState, error: 'private.error' } },
  ],
  [
    'unknown replay error',
    { ...projection, replay: { ...projection.replay, secondError: 'private.error' } },
  ],
  [
    'false normal authorization flag',
    { ...projection, googleRequest: { ...projection.googleRequest, scopeExact: false } },
  ],
  [
    'false wrong-state authorization flag',
    {
      ...projection,
      wrongState: {
        ...projection.wrongState,
        googleRequest: { ...projection.wrongState.googleRequest, fulfilledOnce: false },
      },
    },
  ],
] as const)('rejects malformed observation: %s', (_name, forged) => {
  expect(compareCommonGoogleExistingOwnerProjections(forged, forged)).toEqual(['/projection']);
});

test('rejects accessors and proxies without invoking a getter', () => {
  let getterCalls = 0;
  const accessor = Object.defineProperty({ ...projection }, 'wrongState', {
    enumerable: true,
    get: () => {
      getterCalls += 1;
      throw new Error('private getter');
    },
  });
  const proxied = { ...projection, replay: new Proxy({ ...projection.replay }, {}) };
  expect(compareCommonGoogleExistingOwnerProjections(accessor, accessor)).toEqual(['/projection']);
  expect(compareCommonGoogleExistingOwnerProjections(proxied, proxied)).toEqual(['/projection']);
  expect(getterCalls).toBe(0);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
