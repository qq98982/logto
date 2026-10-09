/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Closed projection validation and deterministic diagnostics share one boundary; one callback latch transfers the control observation out of the target driver. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  runCommonGoogleRegistrationForTarget,
  type CommonGoogleRegistrationControlError,
  type CommonGoogleRegistrationControlsObservation,
  type CommonGoogleRegistrationTargetDriverInput,
  type GoogleProviderCredentialLease,
  type GoogleProviderTargetConfiguration,
} from '../browser/common-google-registration-target-driver.js';
import type { CommonGoogleRegistrationProjection } from '../browser/common-google-registration.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonGoogleRegistrationScenarioIds = Object.freeze([
  'common.google.registration',
] as const);

const googleRequest = Object.freeze({
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

export type CommonGoogleRegistrationDenial = Readonly<{
  accepted: false;
  status: number;
  error: CommonGoogleRegistrationControlError;
  userCountUnchanged: true;
  associationCreated: false;
  collisionOwnerPreserved: true;
}>;

export type CommonGoogleRegistrationScenarioProjection = Readonly<{
  provider: 'google';
  newOwner: true;
  identityCreated: true;
  profileEmail: 'verified-provider';
  emailVerified: true;
  hasPassword: false;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  refreshRotated: true;
  googleRequest: CommonGoogleRegistrationProjection['authorization'];
  unverifiedEmail: CommonGoogleRegistrationDenial;
  occupiedEmail: CommonGoogleRegistrationDenial;
}>;

export type CommonGoogleRegistrationScenarioResult = Readonly<{
  id: (typeof commonGoogleRegistrationScenarioIds)[number];
  projection: CommonGoogleRegistrationScenarioProjection;
}>;

export type CommonGoogleRegistrationFixtureRuntime = Readonly<{
  provider: GoogleProviderTargetConfiguration;
  withProviderCredentialLease<Result>(
    use: (lease: GoogleProviderCredentialLease) => Promise<Result>
  ): Promise<Result>;
}>;

const projectionFields = Object.freeze([
  'provider',
  'newOwner',
  'identityCreated',
  'profileEmail',
  'emailVerified',
  'hasPassword',
  'callback',
  'pkce',
  'refreshRotated',
  'googleRequest',
  'unverifiedEmail',
  'occupiedEmail',
]);
const requestFields = Object.freeze(Object.keys(googleRequest));
const denialFields = Object.freeze([
  'accepted',
  'status',
  'error',
  'userCountUnchanged',
  'associationCreated',
  'collisionOwnerPreserved',
]);
const publicControlErrors = new Set([
  'connector.general',
  'guard.invalid_input',
  'user.missing_profile',
  'verification_record.permission_denied',
  'session.identity_conflict',
  'user.email_already_in_use',
  'none',
]);
const isPublicControlError = (value: unknown): value is CommonGoogleRegistrationControlError =>
  typeof value === 'string' && publicControlErrors.has(value);
const isPublicStatus = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599;

const exactRecord = (
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
      return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
    })
  ) {
    return undefined;
  }
  return Object.freeze(
    Object.fromEntries(fields.map((field) => [field, descriptors[field]?.value]))
  );
};

const validDenial = (value: unknown, errors: ReadonlySet<string>): boolean => {
  const denial = exactRecord(value, denialFields);
  return Boolean(
    denial &&
      denial.accepted === false &&
      typeof denial.status === 'number' &&
      Number.isInteger(denial.status) &&
      typeof denial.error === 'string' &&
      denial.status >= 400 &&
      denial.status <= 499 &&
      errors.has(denial.error) &&
      denial.userCountUnchanged === true &&
      denial.associationCreated === false &&
      denial.collisionOwnerPreserved === true
  );
};

const validProjection = (value: unknown): value is CommonGoogleRegistrationScenarioProjection => {
  const projection = exactRecord(value, projectionFields);
  const request = exactRecord(projection?.googleRequest, requestFields);
  return Boolean(
    projection &&
      request &&
      projection.provider === 'google' &&
      projection.newOwner === true &&
      projection.identityCreated === true &&
      projection.profileEmail === 'verified-provider' &&
      projection.emailVerified === true &&
      projection.hasPassword === false &&
      projection.callback === 'state-issuer-code-bound' &&
      projection.pkce === 'S256' &&
      projection.refreshRotated === true &&
      isDeepStrictEqual(request, googleRequest) &&
      validDenial(
        projection.unverifiedEmail,
        new Set([
          'connector.general',
          'guard.invalid_input',
          'user.missing_profile',
          'verification_record.permission_denied',
        ])
      ) &&
      validDenial(
        projection.occupiedEmail,
        new Set([
          'connector.general',
          'guard.invalid_input',
          'session.identity_conflict',
          'user.missing_profile',
          'user.email_already_in_use',
        ])
      )
  );
};

export const compareCommonGoogleRegistrationProjections = (
  oracle: unknown,
  candidate: unknown
): readonly string[] =>
  validProjection(oracle) && validProjection(candidate) && isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export type CommonGoogleRegistrationProjectionDifference =
  | Readonly<{ field: 'contract'; oracleMatches: boolean; candidateMatches: boolean }>
  | Readonly<{
      field:
        | 'unverified-email-status'
        | 'unverified-email-error'
        | 'occupied-email-status'
        | 'occupied-email-error';
      oracle: number | string;
      candidate: number | string;
    }>;

export const describeCommonGoogleRegistrationProjectionDifference = (
  oracle: unknown,
  candidate: unknown
): CommonGoogleRegistrationProjectionDifference | undefined => {
  const oracleProjection = exactRecord(oracle, projectionFields);
  const candidateProjection = exactRecord(candidate, projectionFields);
  const oracleUnverified = exactRecord(oracleProjection?.unverifiedEmail, denialFields);
  const candidateUnverified = exactRecord(candidateProjection?.unverifiedEmail, denialFields);
  const oracleOccupied = exactRecord(oracleProjection?.occupiedEmail, denialFields);
  const candidateOccupied = exactRecord(candidateProjection?.occupiedEmail, denialFields);
  const pairs =
    oracleUnverified && candidateUnverified && oracleOccupied && candidateOccupied
      ? ([
          [oracleUnverified, candidateUnverified, 'unverified-email'],
          [oracleOccupied, candidateOccupied, 'occupied-email'],
        ] as const)
      : undefined;
  if (pairs) {
    for (const [left, right, field] of pairs) {
      const leftStatus = isPublicStatus(left.status) ? left.status : undefined;
      const rightStatus = isPublicStatus(right.status) ? right.status : undefined;
      const leftError = isPublicControlError(left.error) ? left.error : undefined;
      const rightError = isPublicControlError(right.error) ? right.error : undefined;
      if (
        leftStatus === undefined ||
        rightStatus === undefined ||
        leftError === undefined ||
        rightError === undefined
      ) {
        return Object.freeze({
          field: 'contract',
          oracleMatches: validProjection(oracle),
          candidateMatches: validProjection(candidate),
        });
      }
      if (leftStatus !== rightStatus) {
        return Object.freeze({
          field: `${field}-status` as const,
          oracle: leftStatus,
          candidate: rightStatus,
        });
      }
      if (leftError !== rightError) {
        return Object.freeze({
          field: `${field}-error` as const,
          oracle: leftError,
          candidate: rightError,
        });
      }
    }
  }
  const oracleMatches = validProjection(oracle);
  const candidateMatches = validProjection(candidate);
  if (!oracleMatches || !candidateMatches) {
    return Object.freeze({ field: 'contract', oracleMatches, candidateMatches });
  }
  if (isDeepStrictEqual(oracle, candidate)) {
    return undefined;
  }
  return Object.freeze({ field: 'contract', oracleMatches: true, candidateMatches: true });
};

const failureStages = new Set([
  'admission',
  'authorization',
  'callback',
  'capability',
  'cleanup',
  'context',
  'credentials',
  'discovery',
  'fixture',
  'initialization',
  'management',
  'unverified-email-control',
  'unverified-email-owner',
  'occupied-email-control',
  'occupied-email-owner',
  'control-publication',
  'owner-lookup',
  'profile',
  'provider-count',
  'provider-click',
  'refresh',
  'registration-route',
  'registration-transition',
  'consent-click',
  'consent-route',
  'fixture-registration-owner-before',
  'fixture-registration-owner-use',
  'fixture-registration-owner-after',
  'fixture-registration-owner-cleanup',
  'fixture-registration-owner-discovery',
  'fixture-stop-provider',
  'fixture-restore-app',
  'fixture-delete-role',
  'fixture-restore-sie',
  'fixture-delete-connector',
]);

export const describeCommonGoogleRegistrationFailure = (error: unknown): string | undefined => {
  if (nodeTypes.isProxy(error) || !(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const message: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  if (typeof message !== 'string') {
    return undefined;
  }
  const stage = /^Common Google registration (?:target )?failed: ([a-z0-9-]+)$/u.exec(message)?.[1];
  return stage && failureStages.has(stage) ? stage : undefined;
};

const isRuntime = (value: unknown): value is CommonGoogleRegistrationFixtureRuntime =>
  typeof value === 'object' &&
  value !== null &&
  typeof Reflect.get(value, 'provider') === 'object' &&
  Reflect.get(value, 'provider') !== null &&
  typeof Reflect.get(value, 'withProviderCredentialLease') === 'function';

export const runCommonGoogleRegistrationScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonGoogleRegistrationScenarioResult> => {
  const { status } = input.fixture;
  const runtime: unknown = Reflect.get(input.fixture, 'commonGoogleRegistration');
  if (!status || !isRuntime(runtime)) {
    throw new TypeError('Invalid Common Google registration scenario fixture');
  }
  const driverInput: CommonGoogleRegistrationTargetDriverInput = {
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
  let controls: CommonGoogleRegistrationControlsObservation | undefined;
  const positive = await runCommonGoogleRegistrationForTarget({
    ...driverInput,
    onControls: async (observed) => {
      controls = observed;
    },
  });
  if (!controls) {
    throw new TypeError('Invalid Common Google registration controls');
  }
  const denial = (
    observed: CommonGoogleRegistrationControlsObservation['unverifiedEmail']
  ): CommonGoogleRegistrationDenial =>
    Object.freeze({
      accepted: false,
      status: observed.status,
      error: observed.error,
      userCountUnchanged: true,
      associationCreated: false,
      collisionOwnerPreserved: true,
    });
  return Object.freeze({
    id: commonGoogleRegistrationScenarioIds[0],
    projection: Object.freeze({
      provider: positive.provider,
      newOwner: positive.newOwner,
      identityCreated: positive.identityCreated,
      profileEmail: positive.profileEmail,
      emailVerified: positive.emailVerified,
      hasPassword: positive.passwordVerification,
      callback: positive.callback,
      pkce: positive.pkce,
      refreshRotated: positive.refreshRotated,
      googleRequest: Object.freeze({ ...positive.authorization }),
      unverifiedEmail: denial(controls.unverifiedEmail),
      occupiedEmail: denial(controls.occupiedEmail),
    }),
  });
};
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
