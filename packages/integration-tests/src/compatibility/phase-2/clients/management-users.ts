/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The bounded response reader consumes one private HTTP body without buffering beyond its cap. */
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

export type ManagementUserError =
  | 'none'
  | 'guard.invalid_input'
  | 'user.email_already_in_use'
  | 'user.phone_already_in_use'
  | 'auth.unauthorized'
  | 'unknown';
export type ManagementUserSnapshot = Readonly<{
  id: string;
  name: string | undefined;
  primaryEmail: string | undefined;
  primaryPhone: string | undefined;
  hasPassword: boolean;
  updatedAt: number;
}>;
export type ManagementMutationObservation = Readonly<{
  status: number;
  error: ManagementUserError;
}>;
export type ManagementUserMutationObserver = (
  input: Readonly<{ method: 'POST' | 'PATCH'; path: string; body: unknown }>
) => Promise<ManagementMutationObservation>;

const fail = (): never => {
  throw new TypeError('Invalid Common Management user transport');
};
const bounded = (value: unknown, maximum = 512): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum
    ? value
    : fail();
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
const closedError = (value: unknown): ManagementUserError => {
  switch (value) {
    case undefined: {
      return 'none';
    }
    case 'guard.invalid_input':
    case 'user.email_already_in_use':
    case 'user.phone_already_in_use':
    case 'auth.unauthorized': {
      return value;
    }
    default: {
      return 'unknown';
    }
  }
};
const snapshot = (value: unknown): ManagementUserSnapshot => {
  const user = record(value);
  if (
    [
      'password',
      'passwordEncrypted',
      'passwordEncryptionMethod',
      'passwordHash',
      'passwordDigest',
      'mfaVerifications',
      'recoveryCodes',
      'backupCodes',
      'webauthnCredentials',
      'connectorSecrets',
      'secret',
      'clientSecret',
      'privateKey',
    ].some((key) => Object.hasOwn(user, key))
  ) {
    return fail();
  }
  return Object.freeze({
    id: bounded(user.id, 128),
    name: user.name === null ? undefined : bounded(user.name, 256),
    primaryEmail: user.primaryEmail === null ? undefined : bounded(user.primaryEmail, 320),
    primaryPhone: user.primaryPhone === null ? undefined : bounded(user.primaryPhone, 32),
    hasPassword: user.hasPassword === true,
    updatedAt:
      typeof user.updatedAt === 'number' && Number.isSafeInteger(user.updatedAt)
        ? user.updatedAt
        : fail(),
  });
};

export const createManagementUser = async (
  request: Phase2AdminRequestFunction,
  input: Readonly<{ email: string; password: string }>,
  captureOwnedId?: (id: string) => void
): Promise<ManagementUserSnapshot> => {
  const value = await request({
    method: 'POST',
    path: 'users',
    body: {
      primaryEmail: bounded(input.email, 320),
      password: bounded(input.password, 256),
    },
    expectedStatuses: [200, 201],
    responseKind: 'object',
  });
  const created = record(value);
  const id = bounded(created.id, 128);
  if (created.primaryEmail === input.email) {
    captureOwnedId?.(id);
  }
  return snapshot(created);
};

export const readManagementUser = async (
  request: Phase2AdminRequestFunction,
  id: string
): Promise<ManagementUserSnapshot> =>
  snapshot(
    await request({
      method: 'GET',
      path: `users/${encodeURIComponent(bounded(id, 128))}`,
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

export const updateManagementUser = async (
  request: Phase2AdminRequestFunction,
  input: Readonly<{ id: string; name?: string; email?: string; phone?: string }>
): Promise<ManagementUserSnapshot> =>
  snapshot(
    await request({
      method: 'PATCH',
      path: `users/${encodeURIComponent(bounded(input.id, 128))}`,
      body: {
        ...(input.name === undefined ? {} : { name: bounded(input.name, 256) }),
        ...(input.email === undefined ? {} : { primaryEmail: bounded(input.email, 320) }),
        ...(input.phone === undefined ? {} : { primaryPhone: bounded(input.phone, 32) }),
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

const readBoundedJson = async (response: Response): Promise<Record<string, unknown>> => {
  const reader = response.body?.getReader() ?? fail();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      length += result.value.byteLength;
      if (length > 8192) {
        await reader.cancel().catch(() => false);
        return fail();
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return record(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)));
};

export const createManagementUserMutationObserver =
  (
    target: TargetConfig,
    createHeaders: () => Headers,
    requestFetch: typeof fetch = fetch
  ): ManagementUserMutationObserver =>
  async (input) => {
    if (!/^[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u.test(input.path) || input.path.startsWith('/')) {
      return fail();
    }
    const headers = createHeaders();
    headers.set('content-type', 'application/json');
    const response = await requestFetch(new URL(`/api/${input.path}`, target.coreUrl), {
      method: input.method,
      headers,
      body: JSON.stringify(input.body),
      redirect: 'manual',
      signal: AbortSignal.timeout(30_000),
    });
    if (![200, 201, 400, 401, 409, 422].includes(response.status) || response.redirected) {
      return fail();
    }
    const value = await readBoundedJson(response);
    const error = closedError(value.code);
    if ((response.status === 200 || response.status === 201) !== (error === 'none')) {
      return fail();
    }
    return Object.freeze({ status: response.status, error });
  };

export const verifyManagementResourceAccess = async (
  token: string,
  jwks: Readonly<JSONWebKeySet>,
  expected: Readonly<{
    issuer: string;
    audience: string;
    subject: string;
    clientId: string;
    scope: string;
  }>
): Promise<void> => {
  const now = Math.floor(Date.now() / 1000);
  const verified = await jwtVerify(token, createLocalJWKSet(jwks), {
    algorithms: ['ES384'],
    issuer: expected.issuer,
    audience: expected.audience,
    clockTolerance: 15,
    requiredClaims: ['sub', 'iat', 'exp'],
  }).catch(fail);
  const { scope } = verified.payload;
  if (
    verified.protectedHeader.typ !== 'at+jwt' ||
    verified.payload.sub !== expected.subject ||
    verified.payload.client_id !== expected.clientId ||
    typeof scope !== 'string' ||
    !scope.split(' ').includes(expected.scope) ||
    !Number.isInteger(verified.payload.iat) ||
    !Number.isInteger(verified.payload.exp) ||
    Number(verified.payload.iat) > now + 15 ||
    Number(verified.payload.exp) <= now - 15 ||
    Number(verified.payload.exp) <= Number(verified.payload.iat)
  ) {
    return fail();
  }
};

export const readManagementUserRoles = async (request: Phase2AdminRequestFunction, id: string) => {
  const value = await request({
    method: 'GET',
    path: `users/${encodeURIComponent(bounded(id, 128))}/roles`,
    query: { page: '1', page_size: '100' },
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(value) || value.length >= 100) {
    return fail();
  }
  return Object.freeze(
    value.map((entry) => {
      const role = record(entry);
      return Object.freeze({ id: bounded(role.id, 128), isDefault: role.isDefault === true });
    })
  );
};

export const readDefaultManagementUserRoleIds = async (
  request: Phase2AdminRequestFunction
): Promise<readonly string[]> => {
  const value = await request({
    method: 'GET',
    path: 'roles',
    query: { page: '1', page_size: '100' },
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(value) || value.length >= 100) {
    return fail();
  }
  const ids = value
    .filter(
      (role) =>
        typeof role === 'object' &&
        role !== null &&
        Reflect.get(role, 'type') === 'User' &&
        Reflect.get(role, 'isDefault') === true
    )
    .map((role) => {
      const id: unknown = Reflect.get(role, 'id');
      return bounded(id, 128);
    })
    .slice()
    .sort();
  return ids.length > 0 ? Object.freeze(ids) : fail();
};

export const deleteManagementUser = async (request: Phase2AdminRequestFunction, id: string) => {
  await request({
    method: 'DELETE',
    path: `users/${encodeURIComponent(bounded(id, 128))}`,
    expectedStatuses: [204, 404],
    responseKind: 'status',
  });
};
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
