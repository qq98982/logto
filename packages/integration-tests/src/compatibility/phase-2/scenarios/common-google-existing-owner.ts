/* eslint-disable complexity, max-lines -- Exact nested projection validation and scenario execution share one publication boundary. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import type { CommonGoogleExistingOwnerProjection } from '../browser/common-google-existing-owner-sign-in.js';
import {
  runCommonGoogleExistingOwnerForTarget,
  runCommonGoogleExistingOwnerReplayForTarget,
  runCommonGoogleExistingOwnerWrongStateForTarget,
  type CommonGoogleExistingOwnerReplayObservation,
  type CommonGoogleExistingOwnerTargetDriverInput,
  type CommonGoogleExistingOwnerWrongStateObservation,
  type GoogleProviderCredentialLease,
  type GoogleProviderTargetConfiguration,
} from '../browser/common-google-existing-owner-target-driver.js';
import type { GoogleBrowserReplayError } from '../browser/google-browser-replay-control.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonGoogleExistingOwnerScenarioIds = Object.freeze([
  'common.google.existing-owner',
] as const);

const normalGoogleRequest = Object.freeze({
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

const wrongStateGoogleRequest = Object.freeze({
  ...normalGoogleRequest,
  stateRoundTrip: false as const,
});

/**
 * The status and public error remain observation fields until a live Reference run pins them.
 * Rejection, owner preservation, and exact cross-target equality are mandatory now.
 */
const positiveExpectedProjection = Object.freeze({
  provider: 'google' as const,
  existingOwner: true as const,
  subjectPreserved: true as const,
  profileEmail: 'original-owner' as const,
  emailVerified: true as const,
  providerEmailChangeObserved: true as const,
  callback: 'state-issuer-code-bound' as const,
  pkce: 'S256' as const,
  refreshRotated: true as const,
  googleRequest: normalGoogleRequest,
});

export const commonGoogleExistingOwnerExpectedProjection = Object.freeze({
  ...positiveExpectedProjection,
  wrongState: Object.freeze({
    callbackAccepted: false as const,
    ownerPreserved: true as const,
    googleRequest: wrongStateGoogleRequest,
  }),
  replay: Object.freeze({
    requestCount: 1 as const,
    firstStatus: 200 as const,
    firstOutcome: 'verified' as const,
    secondAccepted: false as const,
    ownerPreserved: true as const,
  }),
});

export type CommonGoogleExistingOwnerScenarioProjection = Readonly<{
  provider: 'google';
  existingOwner: true;
  subjectPreserved: true;
  profileEmail: 'original-owner';
  emailVerified: true;
  providerEmailChangeObserved: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  refreshRotated: true;
  googleRequest: CommonGoogleExistingOwnerProjection['authorization'];
  wrongState: Readonly<{
    callbackAccepted: boolean | 'unknown';
    status: number | 'unavailable';
    error: GoogleBrowserReplayError;
    ownerPreserved: true;
    googleRequest: CommonGoogleExistingOwnerWrongStateObservation['authorization'];
  }>;
  replay: CommonGoogleExistingOwnerReplayObservation;
}>;

export type CommonGoogleExistingOwnerScenarioResult = Readonly<{
  id: (typeof commonGoogleExistingOwnerScenarioIds)[number];
  projection: CommonGoogleExistingOwnerScenarioProjection;
}>;

export type CommonGoogleExistingOwnerFixtureRuntime = Readonly<{
  provider: GoogleProviderTargetConfiguration;
  withProviderCredentialLease<Result>(
    use: (lease: GoogleProviderCredentialLease) => Promise<Result>
  ): Promise<Result>;
}>;

const isGoogleRuntime = (value: unknown): value is CommonGoogleExistingOwnerFixtureRuntime =>
  typeof value === 'object' &&
  value !== null &&
  typeof Reflect.get(value, 'provider') === 'object' &&
  Reflect.get(value, 'provider') !== null &&
  typeof Reflect.get(value, 'withProviderCredentialLease') === 'function';

const projectionFields = Object.freeze([
  'provider',
  'existingOwner',
  'subjectPreserved',
  'profileEmail',
  'emailVerified',
  'providerEmailChangeObserved',
  'callback',
  'pkce',
  'refreshRotated',
  'googleRequest',
  'wrongState',
  'replay',
]);
const googleRequestFields = Object.freeze([
  'requestCount',
  'queryShapeExact',
  'clientMatched',
  'callbackMatched',
  'responseTypeCode',
  'scopeExact',
  'stateFormatValid',
  'stateRoundTrip',
  'fulfilledOnce',
]);
const wrongStateFields = Object.freeze([
  'callbackAccepted',
  'status',
  'error',
  'ownerPreserved',
  'googleRequest',
]);
const replayFields = Object.freeze([
  'requestCount',
  'firstStatus',
  'firstOutcome',
  'secondStatus',
  'secondError',
  'secondAccepted',
  'ownerPreserved',
]);
const publicErrors = new Set<unknown>([
  'none',
  'session.verification_session_not_found',
  'entity.not_found',
  'guard.invalid_input',
  'connector.general',
  'unknown',
] satisfies readonly GoogleBrowserReplayError[]);

const exactDataRecord = (
  value: unknown,
  fields: readonly string[]
): Readonly<Record<string, unknown>> | undefined => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== fields.length
  ) {
    return undefined;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    fields.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable;
    })
  ) {
    return undefined;
  }
  return Object.freeze(
    Object.fromEntries(fields.map((field) => [field, descriptors[field]?.value]))
  );
};

const validStatus = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599;
const validPublicError = (value: unknown): value is GoogleBrowserReplayError =>
  publicErrors.has(value);

const matchesExpectedContract = (value: unknown): boolean => {
  const projection = exactDataRecord(value, projectionFields);
  const googleRequest = exactDataRecord(projection?.googleRequest, googleRequestFields);
  const wrongState = exactDataRecord(projection?.wrongState, wrongStateFields);
  const wrongStateGoogleRequest = exactDataRecord(wrongState?.googleRequest, googleRequestFields);
  const replay = exactDataRecord(projection?.replay, replayFields);
  if (!projection || !googleRequest || !wrongState || !wrongStateGoogleRequest || !replay) {
    return false;
  }
  return (
    validStatus(wrongState.status) &&
    validStatus(replay.secondStatus) &&
    validPublicError(wrongState.error) &&
    validPublicError(replay.secondError) &&
    replay.secondError !== 'none' &&
    replay.secondError !== 'unknown' &&
    isDeepStrictEqual(
      {
        provider: projection.provider,
        existingOwner: projection.existingOwner,
        subjectPreserved: projection.subjectPreserved,
        profileEmail: projection.profileEmail,
        emailVerified: projection.emailVerified,
        providerEmailChangeObserved: projection.providerEmailChangeObserved,
        callback: projection.callback,
        pkce: projection.pkce,
        refreshRotated: projection.refreshRotated,
        googleRequest,
        wrongState: {
          callbackAccepted: wrongState.callbackAccepted,
          ownerPreserved: wrongState.ownerPreserved,
          googleRequest: wrongStateGoogleRequest,
        },
        replay: {
          requestCount: replay.requestCount,
          firstStatus: replay.firstStatus,
          firstOutcome: replay.firstOutcome,
          secondAccepted: replay.secondAccepted,
          ownerPreserved: replay.ownerPreserved,
        },
      },
      commonGoogleExistingOwnerExpectedProjection
    )
  );
};

export const compareCommonGoogleExistingOwnerProjections = (
  oracle: unknown,
  candidate: unknown
): readonly string[] =>
  matchesExpectedContract(oracle) &&
  matchesExpectedContract(candidate) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export type CommonGoogleExistingOwnerProjectionDifference =
  | Readonly<{
      field: 'wrong-state-status' | 'replay-second-status';
      oracle: number;
      candidate: number;
    }>
  | Readonly<{
      field: 'wrong-state-error' | 'replay-second-error';
      oracle: GoogleBrowserReplayError;
      candidate: GoogleBrowserReplayError;
    }>
  | Readonly<{
      field: 'contract';
      oracleMatches: boolean;
      candidateMatches: boolean;
    }>;

export const describeCommonGoogleExistingOwnerProjectionDifference = (
  oracle: unknown,
  candidate: unknown
): CommonGoogleExistingOwnerProjectionDifference | undefined => {
  const oracleMatches = matchesExpectedContract(oracle);
  const candidateMatches = matchesExpectedContract(candidate);
  if (!oracleMatches || !candidateMatches) {
    return Object.freeze({ field: 'contract', oracleMatches, candidateMatches });
  }
  if (isDeepStrictEqual(oracle, candidate)) {
    return undefined;
  }
  const oracleProjection = exactDataRecord(oracle, projectionFields);
  const candidateProjection = exactDataRecord(candidate, projectionFields);
  const oracleWrongState = exactDataRecord(oracleProjection?.wrongState, wrongStateFields);
  const candidateWrongState = exactDataRecord(candidateProjection?.wrongState, wrongStateFields);
  const oracleReplay = exactDataRecord(oracleProjection?.replay, replayFields);
  const candidateReplay = exactDataRecord(candidateProjection?.replay, replayFields);
  if (
    !oracleWrongState ||
    !candidateWrongState ||
    !oracleReplay ||
    !candidateReplay ||
    !validStatus(oracleWrongState.status) ||
    !validStatus(candidateWrongState.status) ||
    !validPublicError(oracleWrongState.error) ||
    !validPublicError(candidateWrongState.error) ||
    !validStatus(oracleReplay.secondStatus) ||
    !validStatus(candidateReplay.secondStatus) ||
    !validPublicError(oracleReplay.secondError) ||
    !validPublicError(candidateReplay.secondError)
  ) {
    return Object.freeze({ field: 'contract', oracleMatches: false, candidateMatches: false });
  }
  if (oracleWrongState.status !== candidateWrongState.status) {
    return Object.freeze({
      field: 'wrong-state-status',
      oracle: oracleWrongState.status,
      candidate: candidateWrongState.status,
    });
  }
  if (oracleWrongState.error !== candidateWrongState.error) {
    return Object.freeze({
      field: 'wrong-state-error',
      oracle: oracleWrongState.error,
      candidate: candidateWrongState.error,
    });
  }
  if (oracleReplay.secondStatus !== candidateReplay.secondStatus) {
    return Object.freeze({
      field: 'replay-second-status',
      oracle: oracleReplay.secondStatus,
      candidate: candidateReplay.secondStatus,
    });
  }
  if (oracleReplay.secondError !== candidateReplay.secondError) {
    return Object.freeze({
      field: 'replay-second-error',
      oracle: oracleReplay.secondError,
      candidate: candidateReplay.secondError,
    });
  }
  return undefined;
};

const publishProjection = (
  positive: CommonGoogleExistingOwnerProjection,
  wrongState: CommonGoogleExistingOwnerWrongStateObservation,
  replay: CommonGoogleExistingOwnerReplayObservation
): CommonGoogleExistingOwnerScenarioProjection =>
  Object.freeze({
    provider: positive.provider,
    existingOwner: positive.existingOwner,
    subjectPreserved: positive.subjectPreserved,
    profileEmail:
      positive.profileEmail === 'original-owner'
        ? positive.profileEmail
        : (() => {
            throw new TypeError('Invalid Common Google existing-owner scenario projection');
          })(),
    emailVerified: positive.emailVerified,
    providerEmailChangeObserved: positive.providerEmailChangeObserved,
    callback: positive.callback,
    pkce: positive.pkce,
    refreshRotated: positive.refreshRotated,
    googleRequest: Object.freeze({ ...positive.authorization }),
    wrongState: Object.freeze({
      callbackAccepted: wrongState.callbackAccepted,
      status: wrongState.status,
      error: wrongState.error,
      ownerPreserved: wrongState.ownerPreserved,
      googleRequest: Object.freeze({ ...wrongState.authorization }),
    }),
    replay: Object.freeze({ ...replay }),
  });

export const runCommonGoogleExistingOwnerScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonGoogleExistingOwnerScenarioResult> => {
  const { status } = input.fixture;
  const runtime: unknown = Reflect.get(input.fixture, 'commonGoogleExistingOwner');
  if (!status || !isGoogleRuntime(runtime)) {
    throw new TypeError('Invalid Common Google existing-owner scenario fixture');
  }
  const driverInput: CommonGoogleExistingOwnerTargetDriverInput = {
    ...input,
    browser: {
      storageKey:
        input.target.label === 'oracle'
          ? asterNativeSurfaceContract.markers.demoConfigStorageKey.reference
          : asterNativeSurfaceContract.markers.demoConfigStorageKey.candidate,
      demo: {
        appId: status.client.id,
        prompt: 'consent',
        scope: `openid offline_access profile email ${status.resource.scopeName}`,
        resource: status.resource.indicator,
      },
      redirectUri: new URL('/demo-app', input.target.coreUrl).href,
      initialResponseScope: 'openid offline_access profile email',
      resourceScope: status.resource.scopeName,
    },
    provider: { ...runtime.provider, resetPrivateFilesOnStop: true },
    withProviderCredentialLease: async (use) => runtime.withProviderCredentialLease(use),
  };
  const positive = await runCommonGoogleExistingOwnerForTarget(driverInput);
  const wrongState = await runCommonGoogleExistingOwnerWrongStateForTarget(driverInput);
  const replay = await runCommonGoogleExistingOwnerReplayForTarget(driverInput);
  return Object.freeze({
    id: commonGoogleExistingOwnerScenarioIds[0],
    projection: publishProjection(positive, wrongState, replay),
  });
};
/* eslint-enable complexity, max-lines */
