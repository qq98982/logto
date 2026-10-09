/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-throw-literal -- Selected recovery policy and independent compensation form one fixture boundary. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  type SelectedEmailPasswordIdentity,
  withSelectedEmailPasswordFixture,
} from './selected-email-password-fixture.js';

const selectedMethods = Object.freeze(['EmailVerificationCode']);
const fail = (stage: string): never => {
  throw new TypeError(`Selected email recovery fixture failed: ${stage}`);
};
const recoveryMethods = (value: unknown): readonly string[] => {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) && value.every((method) => typeof method === 'string')
    ? value
    : fail('read-sie');
};
export const selectedEmailRecoveryBodyError = (error: unknown, stage: string): Error =>
  error instanceof Error &&
  (error.message.startsWith('Common email password fixture failed:') ||
    error.message.startsWith('Common email recovery failed:'))
    ? error
    : new TypeError(`Selected email recovery fixture failed: ${stage}`);

type PasswordFixture = typeof withSelectedEmailPasswordFixture;

export const withSelectedEmailRecoveryFixtureUsing = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser: Readonly<{ clientId: string; redirectUri: string }>;
    getOldPassword(): string;
    use(identity: SelectedEmailPasswordIdentity): Promise<Result>;
  }>,
  passwordFixture: PasswordFixture
): Promise<Result> => {
  let previous: unknown;
  let result: Result | undefined;
  let bodyError: unknown;
  let cleanupError: unknown;
  let recoveryFlowError: unknown;
  let stage = 'read-sie';
  try {
    const current = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { forgotPasswordMethods?: unknown };
    previous = recoveryMethods(current.forgotPasswordMethods);
    stage = 'patch-sie';
    const updated = (await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { forgotPasswordMethods: selectedMethods },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { forgotPasswordMethods?: unknown };
    if (!isDeepStrictEqual(updated.forgotPasswordMethods, selectedMethods)) {
      return fail('patch-sie');
    }
    stage = 'password-fixture';
    result = await passwordFixture({
      fixture: input.fixture,
      request: input.request,
      browser: input.browser,
      getPassword: input.getOldPassword,
      use: async (identity) => {
        try {
          return await input.use(identity);
        } catch (error: unknown) {
          recoveryFlowError = error;
          return undefined as Result;
        }
      },
    });
    if (recoveryFlowError) {
      throw recoveryFlowError;
    }
  } catch (error: unknown) {
    bodyError =
      recoveryFlowError && error !== recoveryFlowError
        ? new AggregateError(
            [recoveryFlowError, error],
            'Selected email recovery password fixture cleanup failed'
          )
        : selectedEmailRecoveryBodyError(error, stage);
  } finally {
    if (Array.isArray(previous)) {
      try {
        await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: { forgotPasswordMethods: previous },
          expectedStatuses: [200],
          responseKind: 'object',
        });
        const restored = (await input.request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        })) as { forgotPasswordMethods?: unknown };
        if (!isDeepStrictEqual(recoveryMethods(restored.forgotPasswordMethods), previous)) {
          fail('restore-sie');
        }
      } catch (error: unknown) {
        cleanupError = error;
      }
    }
  }
  if (bodyError && cleanupError) {
    throw new AggregateError([bodyError, cleanupError], 'Selected email recovery cleanup failed');
  }
  if (cleanupError) {
    throw cleanupError;
  }
  if (bodyError) {
    throw bodyError;
  }
  return result as Result;
};

export const withSelectedEmailRecoveryFixture = async <Result>(
  input: Parameters<typeof withSelectedEmailRecoveryFixtureUsing<Result>>[0]
): Promise<Result> =>
  withSelectedEmailRecoveryFixtureUsing(input, withSelectedEmailPasswordFixture);
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-throw-literal */
