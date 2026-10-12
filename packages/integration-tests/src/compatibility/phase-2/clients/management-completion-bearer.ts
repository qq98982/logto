/* eslint-disable complexity, no-restricted-syntax, @typescript-eslint/member-ordering, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This boundary owns a short-lived client secret and bearer lease and clears both after callback completion. */
import { randomBytes } from 'node:crypto';

import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

export type ManagementCompletionAuthority = Readonly<{
  resource: string;
  scopeId: string;
  scopeName: 'all';
  issuer: string;
  audience: string;
  algorithm: string;
  tokenType: string;
  accessTokenTtlSeconds: number;
}>;
export type CandidateManagementMachineClient = Readonly<{
  clientId: string;
  resource: string;
  scope: string;
  tokenEndpointAuthMethod: string;
  grantType: string;
  accessTokenAlg: string;
  accessTokenType: string;
  accessTokenTtlSeconds: number;
}>;

const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management M2M bearer (${stage})`);
};
const bounded = (value: unknown, maximum = 4096): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum
    ? value
    : fail('field');
const record = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : fail('response');
const exactScope = (value: unknown, expected: string): boolean =>
  typeof value === 'string' && value.split(' ').filter(Boolean).join(' ') === expected;

export const withManagementCompletionBearer = async <Result>(
  input: Readonly<{
    target: TargetConfig;
    setupRequest: Phase2AdminRequestFunction;
    authority: ManagementCompletionAuthority;
    jwks: Readonly<JSONWebKeySet>;
    captureOwnedApplication(id: string): void;
    bindOwnedApplicationRole(applicationId: string, roleId: string): Promise<void>;
    withCandidateManagementMachineClient?<Value>(
      clientSecret: string,
      use: (client: CandidateManagementMachineClient) => Promise<Value>
    ): Promise<Value>;
    fetch?: typeof fetch;
    use(bearer: string): Promise<Result>;
  }>
): Promise<Result> => {
  const marker = `common-management-m2m-${randomBytes(12).toString('hex')}`;
  if (input.target.label === 'candidate') {
    const fixture = input.withCandidateManagementMachineClient ?? fail('candidate-fixture');
    let secret = randomBytes(32).toString('base64url');
    try {
      return await fixture(secret, async (client) => {
        if (
          client.clientId !== 'aster-mgmt-m2m' ||
          client.resource !== input.authority.resource ||
          client.scope !== input.authority.scopeName ||
          client.tokenEndpointAuthMethod !== 'client_secret_basic' ||
          client.grantType !== 'client_credentials' ||
          client.accessTokenAlg !== input.authority.algorithm ||
          client.accessTokenType !== input.authority.tokenType ||
          client.accessTokenTtlSeconds !== input.authority.accessTokenTtlSeconds
        ) {
          return fail('candidate-fixture');
        }
        return issueManagementBearer(input, client.clientId, secret, input.target.adminUrl);
      });
    } finally {
      secret = '';
    }
  }
  const application = record(
    await input.setupRequest({
      method: 'POST',
      path: 'applications',
      body: { name: marker, type: 'MachineToMachine' },
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );
  const applicationId = bounded(application.id, 128);
  input.captureOwnedApplication(applicationId);
  if (application.name !== marker || application.type !== 'MachineToMachine') {
    return fail('application');
  }
  const secrets = await input.setupRequest({
    method: 'GET',
    path: `applications/${encodeURIComponent(applicationId)}/secrets`,
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(secrets) || secrets.length !== 1) {
    return fail('secret-catalog');
  }
  let secret = bounded(record(secrets[0]).value, 512);
  let roleId: string | undefined;
  try {
    const role = record(
      await input.setupRequest({
        method: 'POST',
        path: 'roles',
        body: {
          name: `${marker}-role`,
          description: 'Common Management M2M authority',
          type: 'MachineToMachine',
          scopeIds: [bounded(input.authority.scopeId, 128)],
        },
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    roleId = bounded(role.id, 128);
    if (role.name !== `${marker}-role` || role.type !== 'MachineToMachine') {
      return fail('role');
    }
    await input.bindOwnedApplicationRole(applicationId, roleId);
    return await issueManagementBearer(input, applicationId, secret, input.target.coreUrl);
  } finally {
    secret = '';
    if (roleId) {
      await input.setupRequest({
        method: 'DELETE',
        path: `roles/${encodeURIComponent(roleId)}`,
        expectedStatuses: [204, 404],
        responseKind: 'status',
      });
    }
  }
};

const issueManagementBearer = async <Result>(
  input: Parameters<typeof withManagementCompletionBearer<Result>>[0],
  applicationId: string,
  secret: string,
  tokenBaseUrl: string
): Promise<Result> => {
  let bearer = '';
  try {
    const response = await (input.fetch ?? fetch)(new URL('/oidc/token', tokenBaseUrl), {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`${applicationId}:${secret}`, 'utf8').toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        resource: bounded(input.authority.resource),
        scope: input.authority.scopeName,
      }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    if (response.status !== 200 || response.redirected) {
      await response.body?.cancel();
      return fail('token-status');
    }
    const responseText = await response.text();
    if (Buffer.byteLength(responseText) > 16 * 1024) {
      return fail('token-body');
    }
    let body: unknown;
    try {
      body = JSON.parse(responseText);
    } catch {
      return fail('token-body');
    }
    const tokenBody = record(body);
    const tokenKeys = Reflect.ownKeys(tokenBody);
    if (
      tokenKeys.some(
        (key) =>
          typeof key !== 'string' ||
          !['access_token', 'token_type', 'expires_in', 'scope'].includes(key)
      ) ||
      tokenBody.token_type !== 'Bearer' ||
      (tokenBody.scope !== undefined && tokenBody.scope !== input.authority.scopeName)
    ) {
      return fail('token-body');
    }
    bearer = bounded(tokenBody.access_token, 16 * 1024);
    let verified: Awaited<ReturnType<typeof jwtVerify>>;
    try {
      verified = await jwtVerify(bearer, createLocalJWKSet(input.jwks), {
        issuer: bounded(input.authority.issuer),
        audience: bounded(input.authority.audience),
        algorithms: [bounded(input.authority.algorithm, 32)],
      });
    } catch {
      return fail('token-verification');
    }
    if (
      verified.protectedHeader.typ !== input.authority.tokenType ||
      verified.payload.client_id !== applicationId ||
      verified.payload.sub !== applicationId ||
      !Number.isSafeInteger(input.authority.accessTokenTtlSeconds) ||
      input.authority.accessTokenTtlSeconds <= 0 ||
      tokenBody.expires_in !== input.authority.accessTokenTtlSeconds ||
      verified.payload.exp === undefined ||
      verified.payload.iat === undefined ||
      verified.payload.exp - verified.payload.iat !== input.authority.accessTokenTtlSeconds ||
      !exactScope(verified.payload.scope, input.authority.scopeName)
    ) {
      return fail('token-claims');
    }
    return await input.use(bearer);
  } finally {
    bearer = '';
  }
};
/* eslint-enable complexity, no-restricted-syntax, @typescript-eslint/member-ordering, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
