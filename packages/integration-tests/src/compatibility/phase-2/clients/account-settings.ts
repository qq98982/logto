/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition -- Proof leases and bounded streaming transport state are scoped to one Account operation. */
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';

export type AccountSettingsError =
  | 'none'
  | 'auth.unauthorized'
  | 'verification_record.permission_denied'
  | 'account_center.not_enabled'
  | 'account_center.field_not_editable'
  | 'password.rejected'
  | 'user.same_password'
  | 'user.email_already_in_use'
  | 'session.invalid_credentials'
  | 'request.invalid_input'
  | 'unknown';

export type AccountSettingsObservation = Readonly<{
  status: number;
  error: AccountSettingsError;
}>;
export type AccountProfileObservation = Readonly<{
  status: number;
  error: AccountSettingsError;
  ownerMatches: boolean;
  emailMatches: boolean;
}>;
export type AccountUserInfoObservation = Readonly<{
  status: number;
  ownerMatches: boolean;
  emailMatches: boolean;
  emailVerified: boolean;
}>;

export type AccountVerificationLease = Readonly<{
  getVerificationRecordId(): string;
  toJSON(): never;
}>;

const maximumBodyBytes = 64 * 1024;
const fail = (): never => {
  throw new TypeError('Invalid Common Account settings transport');
};
const bounded = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

const responseRecord = async (response: Response): Promise<Record<string, unknown>> => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBodyBytes)) {
    return fail();
  }
  const reader = response.body?.getReader();
  if (!reader) {
    return {};
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    // eslint-disable-next-line no-constant-condition -- The bounded reader exits on done.
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      size += value.byteLength;
      if (size > maximumBodyBytes) {
        await reader.cancel();
        return fail();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (size === 0) {
    return {};
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const value: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
};

const closedError = (value: unknown): AccountSettingsError => {
  switch (value) {
    case undefined: {
      return 'none';
    }
    case 'auth.unauthorized':
    case 'verification_record.permission_denied':
    case 'account_center.not_enabled':
    case 'account_center.field_not_editable':
    case 'password.rejected':
    case 'user.same_password':
    case 'user.email_already_in_use':
    case 'session.invalid_credentials':
    case 'request.invalid_input': {
      return value;
    }
    default: {
      return 'unknown';
    }
  }
};

const send = async (
  target: TargetConfig,
  bearerInput: string,
  path: string,
  method: 'GET' | 'POST',
  body: Readonly<Record<string, unknown>> | undefined,
  verificationRecordId: string | undefined,
  requestFetch: typeof fetch
): Promise<Readonly<{ response: Response; record: Record<string, unknown> }>> => {
  const bearer = bounded(bearerInput);
  const response = await requestFetch(new URL(path, target.coreUrl), {
    method,
    headers: {
      authorization: `Bearer ${bearer}`,
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(verificationRecordId
        ? {
            [target.label === 'oracle' ? 'logto-verification-id' : 'aster-verification-id']:
              bounded(verificationRecordId, 4096),
          }
        : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return Object.freeze({ response, record: await responseRecord(response) });
};

const observation = (
  value: Readonly<{ response: Response; record: Record<string, unknown> }>
): AccountSettingsObservation =>
  Object.freeze({ status: value.response.status, error: closedError(value.record.code) });

export const createAccountPasswordProof = async <Result>(
  input: Readonly<{ target: TargetConfig; bearer: string; password: string }>,
  use: (lease: AccountVerificationLease) => Promise<Result>,
  requestFetch: typeof fetch = fetch
): Promise<Result> => {
  const value = await send(
    input.target,
    input.bearer,
    '/api/verifications/password',
    'POST',
    { password: bounded(input.password, 256) },
    undefined,
    requestFetch
  );
  if (value.response.status !== 201) {
    return fail();
  }
  const verificationRecordId = bounded(value.record.verificationRecordId, 4096);
  let active = true;
  try {
    return await use(
      Object.freeze({
        getVerificationRecordId: () => (active ? verificationRecordId : fail()),
        toJSON: (): never => fail(),
        [inspect.custom]: () => 'AccountVerificationLease(<redacted>)',
      })
    );
  } finally {
    active = false;
  }
};

export const observeAccountPasswordProof = async (
  input: Readonly<{ target: TargetConfig; bearer: string; password: string }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountSettingsObservation> =>
  observation(
    await send(
      input.target,
      input.bearer,
      '/api/verifications/password',
      'POST',
      { password: bounded(input.password, 256) },
      undefined,
      requestFetch
    )
  );

export const requestAccountEmailProof = async (
  input: Readonly<{ target: TargetConfig; bearer: string; email: string }>,
  requestFetch: typeof fetch = fetch
): Promise<
  Readonly<{ observation: AccountSettingsObservation; lease: AccountVerificationLease }>
> => {
  const value = await send(
    input.target,
    input.bearer,
    '/api/verifications/verification-code',
    'POST',
    { identifier: { type: 'email', value: bounded(input.email, 320) } },
    undefined,
    requestFetch
  );
  const verificationRecordId = bounded(value.record.verificationRecordId, 4096);
  return Object.freeze({
    observation: observation(value),
    lease: Object.freeze({
      getVerificationRecordId: () => verificationRecordId,
      toJSON: (): never => fail(),
      [inspect.custom]: () => 'AccountVerificationLease(<redacted>)',
    }),
  });
};

export const verifyAccountEmailProof = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    email: string;
    code: string;
    verificationRecordId: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountSettingsObservation> =>
  observation(
    await send(
      input.target,
      input.bearer,
      '/api/verifications/verification-code/verify',
      'POST',
      {
        identifier: { type: 'email', value: bounded(input.email, 320) },
        verificationId: bounded(input.verificationRecordId, 4096),
        code: bounded(input.code, 64),
      },
      undefined,
      requestFetch
    )
  );

export const updateAccountPassword = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    password: string;
    verificationRecordId?: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountSettingsObservation> =>
  observation(
    await send(
      input.target,
      input.bearer,
      '/api/my-account/password',
      'POST',
      { password: bounded(input.password, 256) },
      input.verificationRecordId,
      requestFetch
    )
  );

export const updateAccountEmail = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    email: string;
    destinationVerificationRecordId: string;
    currentVerificationRecordId?: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountSettingsObservation> =>
  observation(
    await send(
      input.target,
      input.bearer,
      '/api/my-account/primary-email',
      'POST',
      {
        email: bounded(input.email, 320),
        newIdentifierVerificationRecordId: bounded(input.destinationVerificationRecordId, 4096),
      },
      input.currentVerificationRecordId,
      requestFetch
    )
  );

export const readAccountProfile = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    expectedOwnerId: string;
    expectedEmail?: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountProfileObservation> => {
  const value = await send(
    input.target,
    input.bearer,
    '/api/my-account/',
    'GET',
    undefined,
    undefined,
    requestFetch
  );
  return Object.freeze({
    ...observation(value),
    ownerMatches: value.record.id === bounded(input.expectedOwnerId, 256),
    emailMatches:
      input.expectedEmail === undefined ||
      value.record.primaryEmail === bounded(input.expectedEmail, 320) ||
      value.record.email === input.expectedEmail,
  });
};

export const readAccountUserInfo = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    expectedOwnerId: string;
    expectedEmail: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountUserInfoObservation> => {
  const value = await send(
    input.target,
    input.bearer,
    '/oidc/me',
    'GET',
    undefined,
    undefined,
    requestFetch
  );
  return Object.freeze({
    status: value.response.status,
    ownerMatches: value.record.sub === bounded(input.expectedOwnerId, 256),
    emailMatches: value.record.email === bounded(input.expectedEmail, 320),
    emailVerified: value.record.email_verified === true,
  });
};
/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition */
