/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The wrapper preserves primary and cleanup failures across compensated fixture mutation. */
import { isDeepStrictEqual } from 'node:util';

import { passwordPolicyGuard } from '@logto/core-kit';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  type SelectedEmailPasswordIdentity,
  withSelectedEmailPasswordFixture,
} from './selected-email-password-fixture.js';
import type { CommonPhoneCodeProviderLease } from './selected-phone-code-fixture.js';

type AccountField = 'password' | 'email' | 'phone';
type AccountCenterRecord = Readonly<{
  enabled: boolean;
  fields: Readonly<Record<string, unknown>>;
}>;
export type SelectedAccountSettingsFixture = Readonly<{
  identity: SelectedEmailPasswordIdentity;
  initialPhone?: string;
  setControl(value: Readonly<{ enabled: boolean; field: 'Edit' | 'ReadOnly' }>): Promise<void>;
  setPhoneSignIn(): Promise<void>;
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

export const selectAccountSettingsFields = (
  previous: Readonly<Record<string, unknown>>,
  field: AccountField,
  value: 'Edit' | 'ReadOnly',
  additionalReadOnlyFields: readonly AccountField[] = []
): Readonly<Record<string, unknown>> =>
  Object.freeze({
    ...previous,
    ...(field === 'password' || field === 'phone' ? { email: 'ReadOnly' } : {}),
    ...Object.fromEntries(additionalReadOnlyFields.map((additional) => [additional, 'ReadOnly'])),
    [field]: value,
  });

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

export const runIndependentAccountSettingsCleanup = async (
  input: Readonly<{
    connector(): Promise<void>;
    policy(): Promise<void>;
    accountCenter(): Promise<void>;
  }>
): Promise<void> => {
  const results = await Promise.allSettled([
    input.connector(),
    input.policy(),
    input.accountCenter(),
  ]);
  const failureCount = results.filter((result) => result.status === 'rejected').length;
  if (failureCount > 0) {
    throw new AggregateError(
      Array.from(
        { length: failureCount },
        () => new TypeError('Invalid selected Account settings fixture cleanup')
      ),
      'Selected Account fixture cleanup failed'
    );
  }
};

// eslint-disable-next-line complexity -- Setup, owned use and exact two-surface compensation share one boundary.
export const withSelectedAccountSettingsFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser: Readonly<{
      clientId: string;
      redirectUri: string;
      additionalRedirectUris?: readonly string[];
    }>;
    field: AccountField;
    additionalReadOnlyFields?: readonly AccountField[];
    phoneProvider?: CommonPhoneCodeProviderLease;
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
    fields: selectAccountSettingsFields(
      previous.fields,
      input.field,
      'Edit',
      input.additionalReadOnlyFields
    ),
  });
  let connectorId: string | undefined;
  const patchControl = async (
    value: Readonly<{ enabled: boolean; field: 'Edit' | 'ReadOnly' }>
  ) => {
    const expected = Object.freeze({
      enabled: value.enabled,
      fields: selectAccountSettingsFields(
        previous.fields,
        input.field,
        value.field,
        input.additionalReadOnlyFields
      ),
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
  const captureCleanup = (error: unknown) => {
    cleanupError =
      cleanupError === undefined
        ? error
        : new AggregateError([cleanupError, error], 'Selected Account fixture cleanup failed');
  };
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
    if (input.field === 'phone') {
      const configuration = input.phoneProvider?.configuration ?? fail();
      const usages = configuration.templates.map(({ usageType }) => usageType);
      const requiredUsages: ReadonlyArray<(typeof usages)[number]> = [
        'SignIn',
        'Register',
        'ForgotPassword',
        'Generic',
      ];
      if (
        !configuration.accessKeyId ||
        !configuration.accessKeySecret ||
        !configuration.signName ||
        configuration.templates.length !== 4 ||
        new Set(usages).size !== 4 ||
        !requiredUsages.every((usage) => usages.includes(usage))
      ) {
        return fail();
      }
      const connector = record(
        await input.request({
          method: 'POST',
          path: 'connectors',
          body: {
            connectorId: 'aliyun-short-message-service',
            config: {
              accessKeyId: configuration.accessKeyId,
              accessKeySecret: configuration.accessKeySecret,
              signName: configuration.signName,
              templates: configuration.templates.map(({ usageType, templateCode }) => ({
                usageType,
                templateCode,
              })),
            },
          },
          expectedStatuses: [200, 201],
          responseKind: 'object',
        })
      );
      connectorId = typeof connector.id === 'string' ? connector.id : undefined;
      if (!connectorId || connector.connectorId !== 'aliyun-short-message-service') {
        return fail();
      }
    }
    result = await withSelectedEmailPasswordFixture({
      fixture: input.fixture,
      request: input.request,
      browser: input.browser,
      getPassword: input.getPassword,
      use: async (identity) => {
        const suffix = [...input.fixture.public.allocationId]
          .map((value) => String(value.codePointAt(0) ?? 0))
          .join('')
          .padEnd(9, '0')
          .slice(0, 9);
        const initialPhone = input.field === 'phone' ? `8612${suffix}` : undefined;
        if (initialPhone) {
          const patchedUser = record(
            await input.request({
              method: 'PATCH',
              path: `users/${encodeURIComponent(identity.id)}`,
              body: { primaryPhone: initialPhone },
              expectedStatuses: [200],
              responseKind: 'object',
            })
          );
          if (patchedUser.id !== identity.id || patchedUser.primaryPhone !== initialPhone) {
            return fail();
          }
        }
        return input.use(
          Object.freeze({
            identity,
            ...(initialPhone ? { initialPhone } : {}),
            setControl: patchControl,
            setPhoneSignIn: async () => {
              const methods = [
                {
                  identifier: 'phone',
                  password: false,
                  verificationCode: true,
                  isPasswordPrimary: false,
                },
              ];
              const patched = record(
                await input.request({
                  method: 'PATCH',
                  path: 'sign-in-exp',
                  body: { signIn: { methods }, branding: {} },
                  expectedStatuses: [200],
                  responseKind: 'object',
                })
              );
              if (!isDeepStrictEqual(record(patched.signIn).methods, methods)) {
                return fail();
              }
            },
          })
        );
      },
    });
  } catch (error: unknown) {
    primaryError = error;
  } finally {
    try {
      await runIndependentAccountSettingsCleanup({
        connector: async () => {
          if (!connectorId) {
            return;
          }
          await input.request({
            method: 'DELETE',
            path: `connectors/${encodeURIComponent(connectorId)}`,
            expectedStatuses: [204, 404],
            responseKind: 'status',
          });
        },
        policy: async () => {
          if (passwordPolicy.previous === undefined) {
            return;
          }
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
            return fail();
          }
        },
        accountCenter: async () => {
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
            return fail();
          }
        },
      });
    } catch (error: unknown) {
      captureCleanup(error);
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
/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
