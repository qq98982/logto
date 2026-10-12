/* eslint-disable max-params, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Provider proof leases expose only closed observations outside one owned Account operation. */
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';

import type { AccountVerificationLease } from './account-settings.js';
import { createCommonExperienceSession } from './common-experience.js';

export type AccountSocialProvider = 'google' | 'wechat';
export type AccountSocialError =
  | 'none'
  | 'auth.unauthorized'
  | 'verification_record.permission_denied'
  | 'account_center.not_enabled'
  | 'account_center.field_not_editable'
  | 'user.identity_already_in_use'
  | 'user.last_sign_in_method_required'
  | 'session.verification_session_not_found'
  | 'request.invalid_input'
  | 'connector.general'
  | 'unknown';
export type AccountSocialObservation = Readonly<{ status: number; error: AccountSocialError }>;

const fail = (): never => {
  throw new TypeError('Invalid Common Account social transport');
};
const bounded = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();
const error = (value: unknown): AccountSocialError => {
  switch (value) {
    case undefined: {
      return 'none';
    }
    case 'auth.unauthorized':
    case 'verification_record.permission_denied':
    case 'account_center.not_enabled':
    case 'account_center.field_not_editable':
    case 'user.identity_already_in_use':
    case 'user.last_sign_in_method_required':
    case 'session.verification_session_not_found':
    case 'request.invalid_input':
    case 'connector.general': {
      return value;
    }
    default: {
      return 'unknown';
    }
  }
};
const send = async (
  input: Readonly<{ target: TargetConfig; bearer: string }>,
  path: string,
  method: 'GET' | 'POST' | 'DELETE',
  body: Readonly<Record<string, unknown>> | undefined,
  permission: string | undefined,
  requestFetch: typeof fetch
): Promise<Readonly<{ status: number; record: Readonly<Record<string, unknown>> }>> => {
  const bearer = bounded(input.bearer);
  const proof = permission === undefined ? undefined : bounded(permission, 4096);
  const session = createCommonExperienceSession({
    target: input.target,
    clientId: 'account-social-client',
    fetch: async (url, init) => {
      const headers = new Headers(init?.headers);
      headers.set('authorization', `Bearer ${bearer}`);
      if (proof !== undefined) {
        headers.set(
          input.target.label === 'oracle' ? 'logto-verification-id' : 'aster-verification-id',
          proof
        );
      }
      return requestFetch(url, { ...init, headers });
    },
  });
  try {
    const response = await session.request(path, method, body);
    return Object.freeze({ status: response.getStatus(), record: response.getRecord() });
  } catch {
    return fail();
  } finally {
    session.close();
  }
};
const observation = (
  value: Readonly<{ status: number; record: Readonly<Record<string, unknown>> }>
): AccountSocialObservation =>
  Object.freeze({ status: value.status, error: error(value.record.code) });

/** The provider callback is supplied by the owned provider, never a fabricated proof. */
export const withAccountSocialProof = async <Result>(
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    connectorId: string;
    redirectUri: string;
    takeProviderCode(authorizationUri: string, state: string): Promise<string>;
  }>,
  use: (proof: AccountVerificationLease) => Promise<Result>,
  requestFetch: typeof fetch = fetch
): Promise<Result> => {
  const state = randomBytes(24).toString('base64url');
  const redirectUri = bounded(input.redirectUri);
  const created = await send(
    input,
    '/api/verifications/social',
    'POST',
    {
      connectorId: bounded(input.connectorId, 256),
      state,
      redirectUri,
    },
    undefined,
    requestFetch
  );
  if (created.status !== 201 || error(created.record.code) !== 'none') {
    return fail();
  }
  const verificationRecordId = bounded(created.record.verificationRecordId, 4096);
  const authorizationUri = bounded(created.record.authorizationUri);
  const expiresAt = Date.parse(bounded(created.record.expiresAt, 128));
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    return fail();
  }
  const code = bounded(await input.takeProviderCode(authorizationUri, state), 4096);
  const verified = await send(
    input,
    '/api/verifications/social/verify',
    'POST',
    {
      verificationRecordId,
      connectorData: { code, redirectUri },
    },
    undefined,
    requestFetch
  );
  if (
    verified.status !== 200 ||
    error(verified.record.code) !== 'none' ||
    (verified.record.verificationRecordId !== undefined &&
      verified.record.verificationRecordId !== verificationRecordId)
  ) {
    return fail();
  }
  let active = true;
  try {
    return await use(
      Object.freeze({
        getVerificationRecordId: () => (active ? verificationRecordId : fail()),
        toJSON: fail,
        [inspect.custom]: () => 'AccountSocialProof(<redacted>)',
      })
    );
  } finally {
    active = false;
  }
};

export const observeAccountSocialMutation = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    operation: 'link' | 'unlink';
    provider: AccountSocialProvider;
    permissionId?: string;
    destinationProofId?: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountSocialObservation> => {
  if (
    !['google', 'wechat'].includes(input.provider) ||
    !['link', 'unlink'].includes(input.operation)
  ) {
    return fail();
  }
  const linking = input.operation === 'link';
  return observation(
    await send(
      input,
      linking ? '/api/my-account/identities' : `/api/my-account/identities/${input.provider}`,
      linking ? 'POST' : 'DELETE',
      linking
        ? { newIdentifierVerificationRecordId: bounded(input.destinationProofId, 4096) }
        : undefined,
      input.permissionId,
      requestFetch
    )
  );
};

export const readAccountSocialProfile = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    provider: AccountSocialProvider;
    expectedOwner: string;
    expectedSocialSubject?: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<
  Readonly<{
    status: number;
    ownerMatches: boolean;
    identityMatches: boolean;
    credentialsAbsent: boolean;
  }>
> => {
  const value = await send(input, '/api/my-account', 'GET', undefined, undefined, requestFetch);
  const { identities } = value.record;
  const identity: unknown =
    typeof identities === 'object' && identities !== null && !Array.isArray(identities)
      ? Reflect.get(identities, input.provider)
      : undefined;
  const actualSubject: unknown =
    typeof identity === 'object' && identity !== null && !Array.isArray(identity)
      ? Reflect.get(identity, 'userId')
      : undefined;
  return Object.freeze({
    status: value.status,
    ownerMatches: value.record.id === input.expectedOwner,
    identityMatches:
      input.expectedSocialSubject === undefined
        ? identity === undefined
        : actualSubject === input.expectedSocialSubject,
    credentialsAbsent: ![
      'password',
      'passwordHash',
      'passwordEncrypted',
      'password_hash',
      'password_encrypted',
    ].some((key) => Object.hasOwn(value.record, key)),
  });
};

/* eslint-enable max-params, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
