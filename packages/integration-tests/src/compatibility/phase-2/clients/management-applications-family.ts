/* eslint-disable no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Secret values remain in a bounded callback lease and are cleared after use. */
import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Management applications family transport');
};
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
const bounded = (value: unknown, maximum = 512): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum
    ? value
    : fail();
const strings = (value: unknown): readonly string[] =>
  Array.isArray(value) ? Object.freeze(value.map((entry) => bounded(entry, 2048))) : fail();

export type ManagementApplicationSnapshot = Readonly<{
  id: string;
  name: string;
  description: string;
  type: 'Traditional' | 'Native';
  isThirdParty: boolean;
  redirectUris: readonly string[];
  postLogoutRedirectUris: readonly string[];
  backchannelLogoutUri: string;
  backchannelLogoutSessionRequired: boolean;
}>;

export type ManagementSecretMetadata = Readonly<{
  name: string;
  createdAt: number;
  expiresAt: number | undefined;
}>;

const application = (value: unknown): ManagementApplicationSnapshot => {
  const item = record(value);
  const metadata = record(item.oidcClientMetadata);
  const { type } = item;
  if (
    (type !== 'Traditional' && type !== 'Native') ||
    typeof item.isThirdParty !== 'boolean' ||
    ['secret', 'clientSecret', 'client_secret', 'password', 'privateKey'].some(
      (key) => Object.hasOwn(item, key) || Object.hasOwn(metadata, key)
    )
  ) {
    return fail();
  }
  return Object.freeze({
    id: bounded(item.id, 128),
    name: bounded(item.name, 256),
    description: bounded(item.description, 1024),
    type,
    isThirdParty: item.isThirdParty,
    redirectUris: strings(metadata.redirectUris),
    postLogoutRedirectUris: strings(metadata.postLogoutRedirectUris),
    backchannelLogoutUri: bounded(metadata.backchannelLogoutUri, 2048),
    backchannelLogoutSessionRequired:
      typeof metadata.backchannelLogoutSessionRequired === 'boolean'
        ? metadata.backchannelLogoutSessionRequired
        : fail(),
  });
};

const secretMetadata = (value: unknown): ManagementSecretMetadata => {
  const secret = record(value);
  if (!Number.isSafeInteger(secret.createdAt)) {
    return fail();
  }
  return Object.freeze({
    name: bounded(secret.name, 256),
    createdAt: secret.createdAt as number,
    expiresAt:
      secret.expiresAt === null || secret.expiresAt === undefined
        ? undefined
        : Number.isSafeInteger(secret.expiresAt)
          ? (secret.expiresAt as number)
          : fail(),
  });
};

export const createManagementApplication = async (
  request: Phase2AdminRequestFunction,
  input: Readonly<{
    name: string;
    description: string;
    redirectUri: string;
    postLogoutRedirectUri: string;
    backchannelLogoutUri: string;
  }>,
  captureOwnedId: (id: string) => void
): Promise<ManagementApplicationSnapshot> => {
  const value = await request({
    method: 'POST',
    path: 'applications',
    body: {
      name: bounded(input.name, 256),
      description: bounded(input.description, 1024),
      type: 'Traditional',
      isThirdParty: false,
      oidcClientMetadata: {
        redirectUris: [bounded(input.redirectUri, 2048)],
        postLogoutRedirectUris: [bounded(input.postLogoutRedirectUri, 2048)],
        backchannelLogoutUri: bounded(input.backchannelLogoutUri, 2048),
        backchannelLogoutSessionRequired: true,
      },
    },
    expectedStatuses: [200],
    responseKind: 'object',
  });
  const ownership = record(value);
  const ownedId = bounded(ownership.id, 128);
  captureOwnedId(ownedId);
  const ownedName = bounded(ownership.name, 256);
  if (ownedName !== input.name) {
    return fail();
  }
  const created = application(value);
  return created;
};

export const readManagementApplication = async (
  request: Phase2AdminRequestFunction,
  id: string
): Promise<ManagementApplicationSnapshot> =>
  application(
    await request({
      method: 'GET',
      path: `applications/${encodeURIComponent(bounded(id, 128))}`,
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

export const patchManagementApplication = async (
  request: Phase2AdminRequestFunction,
  input: Readonly<{
    id: string;
    name: string;
    description: string;
    redirectUri: string;
    postLogoutRedirectUri: string;
    backchannelLogoutUri: string;
  }>
): Promise<ManagementApplicationSnapshot> =>
  application(
    await request({
      method: 'PATCH',
      path: `applications/${encodeURIComponent(bounded(input.id, 128))}`,
      body: {
        name: bounded(input.name, 256),
        description: bounded(input.description, 1024),
        oidcClientMetadata: {
          redirectUris: [bounded(input.redirectUri, 2048)],
          postLogoutRedirectUris: [bounded(input.postLogoutRedirectUri, 2048)],
          backchannelLogoutUri: bounded(input.backchannelLogoutUri, 2048),
          backchannelLogoutSessionRequired: true,
        },
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

export const withManagementApplicationSecrets = async <Result>(
  request: Phase2AdminRequestFunction,
  applicationId: string,
  use: (
    value: Readonly<{
      metadata: readonly ManagementSecretMetadata[];
      secrets: readonly string[];
      toJSON(): never;
    }>
  ) => Promise<Result>
): Promise<Result> => {
  const values = await request({
    method: 'GET',
    path: `applications/${encodeURIComponent(bounded(applicationId, 128))}/secrets`,
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(values) || values.length === 0 || values.length > 8) {
    return fail();
  }
  let secrets: string[] = [];
  try {
    const metadata = values.map((value) => {
      const item = record(value);
      secrets.push(bounded(item.value, 512));
      return secretMetadata(item);
    });
    return await use(
      Object.freeze({
        metadata: Object.freeze(metadata),
        secrets: Object.freeze(secrets.slice()),
        toJSON: fail,
      })
    );
  } finally {
    secrets = [];
  }
};

export const createManagementApplicationSecret = async <Result>(
  request: Phase2AdminRequestFunction,
  applicationId: string,
  name: string,
  use: (
    value: Readonly<{ metadata: ManagementSecretMetadata; getSecret(): string; toJSON(): never }>
  ) => Promise<Result>
): Promise<Result> => {
  const value = record(
    await request({
      method: 'POST',
      path: `applications/${encodeURIComponent(bounded(applicationId, 128))}/secrets`,
      body: { name: bounded(name, 256) },
      expectedStatuses: [201],
      responseKind: 'object',
    })
  );
  let secret = bounded(value.value, 512);
  try {
    return await use(
      Object.freeze({ metadata: secretMetadata(value), getSecret: () => secret, toJSON: fail })
    );
  } finally {
    secret = '';
  }
};

export const observeClientSecretAuthentication = async (
  target: TargetConfig,
  clientId: string,
  secret: string,
  options: Readonly<{ redirectUri: string; fetch?: typeof fetch }>
): Promise<Readonly<{ accepted: boolean }>> => {
  const requestFetch = options.fetch ?? fetch;
  const observe = async (
    candidate: string
  ): Promise<Readonly<{ status: number; error: unknown }>> => {
    const response = await requestFetch(new URL('/oidc/token', target.coreUrl), {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`${bounded(clientId, 128)}:${bounded(candidate, 512)}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'common-management-nonexistent-code',
        redirect_uri: bounded(options.redirectUri, 2048),
      }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    const body = await response.text();
    if (Buffer.byteLength(body) > 4096) {
      return fail();
    }
    try {
      const value: unknown = JSON.parse(body);
      return Object.freeze({
        status: response.status,
        error:
          typeof value === 'object' && value !== null && !Array.isArray(value)
            ? record(value).error
            : undefined,
      });
    } catch {
      return Object.freeze({ status: response.status, error: undefined });
    }
  };
  const validSecret = bounded(secret, 512);
  const wrongSecret =
    validSecret === 'aster-invalid-secret' ? 'aster-invalid-secret-2' : 'aster-invalid-secret';
  const [valid, invalid] = await Promise.all([observe(validSecret), observe(wrongSecret)]);
  return Object.freeze({
    accepted:
      valid.status === 400 &&
      valid.error === 'invalid_grant' &&
      invalid.status === 401 &&
      invalid.error === 'invalid_client',
  });
};
/* eslint-enable no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
