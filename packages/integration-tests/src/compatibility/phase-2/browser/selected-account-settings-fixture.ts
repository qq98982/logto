/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The wrapper preserves primary and cleanup failures across compensated fixture mutation. */
import { isDeepStrictEqual } from 'node:util';

import { passwordPolicyGuard } from '@logto/core-kit';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  type SelectedEmailPasswordIdentity,
  withSelectedEmailPasswordFixture,
} from './selected-email-password-fixture.js';

type AccountField = 'password' | 'email';
type AccountCenterRecord = Readonly<{
  enabled: boolean;
  fields: Readonly<Record<string, unknown>>;
}>;
export type SelectedAccountSettingsFixture = Readonly<{
  identity: SelectedEmailPasswordIdentity;
  setControl(value: Readonly<{ enabled: boolean; field: 'Edit' | 'ReadOnly' }>): Promise<void>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid selected Account settings fixture');
};
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();

export const isolateAccountPasswordPolicy = (
  value?: unknown
): Readonly<{
  previous?: Readonly<Record<string, unknown>>;
  isolated?: Readonly<Record<string, unknown>>;
}> => {
  if (value === undefined) {
    return Object.freeze({});
  }
  const previous = Object.freeze(record(value));
  const rejectsValue = previous.rejects;
  const rejects = rejectsValue === undefined ? {} : record(rejectsValue);
  return Object.freeze({
    previous,
    isolated: Object.freeze(
      passwordPolicyGuard.parse({
        ...previous,
        rejects: Object.freeze({ ...rejects, pwned: false }),
      })
    ),
  });
};

export const accountPasswordPolicyMatches = (
  signInExperience: unknown,
  expected: Readonly<Record<string, unknown>>
): boolean => isDeepStrictEqual(record(signInExperience).passwordPolicy, expected);

const accountCenter = (value: unknown): AccountCenterRecord => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  const enabled: unknown = Reflect.get(value, 'enabled');
  const fields: unknown = Reflect.get(value, 'fields');
  if (
    typeof enabled !== 'boolean' ||
    typeof fields !== 'object' ||
    fields === null ||
    Array.isArray(fields) ||
    Object.getPrototypeOf(fields) !== Object.prototype
  ) {
    return fail();
  }
  return Object.freeze({ enabled, fields: Object.freeze({ ...fields }) });
};

// eslint-disable-next-line complexity -- Setup, owned use and exact two-surface compensation share one boundary.
export const withSelectedAccountSettingsFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser: Readonly<{ clientId: string; redirectUri: string }>;
    field: AccountField;
    getPassword(): string;
    use(value: SelectedAccountSettingsFixture): Promise<Result>;
  }>
): Promise<Result> => {
  const previous = accountCenter(
    await input.request({
      method: 'GET',
      path: 'account-center',
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );
  const signInExperience: unknown = await input.request({
    method: 'GET',
    path: 'sign-in-exp',
    expectedStatuses: [200],
    responseKind: 'object',
  });
  const passwordPolicy = isolateAccountPasswordPolicy(record(signInExperience).passwordPolicy);
  const selected = Object.freeze({
    enabled: true,
    fields: Object.freeze({ ...previous.fields, [input.field]: 'Edit' }),
  });
  const patchControl = async (
    value: Readonly<{ enabled: boolean; field: 'Edit' | 'ReadOnly' }>
  ) => {
    const expected = Object.freeze({
      enabled: value.enabled,
      fields: Object.freeze({ ...previous.fields, [input.field]: value.field }),
    });
    const patched = accountCenter(
      await input.request({
        method: 'PATCH',
        path: 'account-center',
        body: expected,
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    if (!isDeepStrictEqual(patched, expected)) {
      return fail();
    }
  };
  let result: Result | undefined;
  let primaryError: unknown;
  let cleanupError: unknown;
  try {
    if (passwordPolicy.isolated !== undefined) {
      await input.request({
        method: 'PATCH',
        path: 'sign-in-exp',
        body: { passwordPolicy: passwordPolicy.isolated },
        expectedStatuses: [200],
        responseKind: 'object',
      });
      const patchedExperience: unknown = await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      });
      if (!accountPasswordPolicyMatches(patchedExperience, passwordPolicy.isolated)) {
        return fail();
      }
    }
    await patchControl({ enabled: selected.enabled, field: 'Edit' });
    result = await withSelectedEmailPasswordFixture({
      fixture: input.fixture,
      request: input.request,
      browser: input.browser,
      getPassword: input.getPassword,
      use: async (identity) =>
        input.use(
          Object.freeze({
            identity,
            setControl: patchControl,
          })
        ),
    });
  } catch (error: unknown) {
    primaryError = error;
  } finally {
    try {
      if (passwordPolicy.previous !== undefined) {
        await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: { passwordPolicy: passwordPolicy.previous },
          expectedStatuses: [200],
          responseKind: 'object',
        });
        const restoredExperience: unknown = await input.request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        });
        if (!accountPasswordPolicyMatches(restoredExperience, passwordPolicy.previous)) {
          cleanupError = new TypeError('Invalid selected Account settings fixture cleanup');
        }
      }
      const restored = accountCenter(
        await input.request({
          method: 'PATCH',
          path: 'account-center',
          body: previous,
          expectedStatuses: [200],
          responseKind: 'object',
        })
      );
      if (!isDeepStrictEqual(restored, previous)) {
        cleanupError = new TypeError('Invalid selected Account settings fixture cleanup');
      }
    } catch (error: unknown) {
      cleanupError = error;
    }
  }
  if (primaryError && cleanupError) {
    throw new AggregateError([primaryError, cleanupError], 'Selected Account fixture failed');
  }
  if (primaryError instanceof Error) {
    throw primaryError;
  }
  if (primaryError !== undefined || cleanupError !== undefined || result === undefined) {
    return fail();
  }
  return result;
};
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
