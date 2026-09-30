/* eslint-disable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The closed scenario collector validates hostile JSON shapes, owns one ordered evidence journal, and preserves fixed primary and cleanup failure classes. */
import { types as nodeTypes } from 'node:util';

import type { JsonValue } from '../../normalize.js';

export const customJwtScenarioIds = Object.freeze([
  'custom-jwt.management-missing-get',
  'custom-jwt.management-missing-delete',
  'custom-jwt.management-put',
  'custom-jwt.management-get',
  'custom-jwt.management-list',
  'custom-jwt.management-patch',
  'custom-jwt.management-patch-missing-script',
  'custom-jwt.management-patch-nonstring-script',
  'custom-jwt.management-test',
  'custom-jwt.management-unknown-token-type',
  'custom-jwt.management-delete',
  'custom-jwt.m2m-success',
  'custom-jwt.m2m-deny',
  'custom-jwt.m2m-throw-block',
  'custom-jwt.m2m-throw-open',
  'custom-jwt.m2m-protected-claims',
] as const);

export type CustomJwtScenarioId = (typeof customJwtScenarioIds)[number];
export type CustomJwtHttpResponse = Readonly<{
  status: number;
  headers: Readonly<Record<string, string>>;
  body: unknown;
}>;
export type CustomJwtTargetPort = Readonly<{
  request(
    input: Readonly<{
      method: 'GET' | 'PUT' | 'PATCH' | 'POST' | 'DELETE';
      path: string;
      body?: unknown;
    }>
  ): Promise<CustomJwtHttpResponse>;
  issueClientCredentials(
    input: Readonly<{
      caseId: Extract<CustomJwtScenarioId, `custom-jwt.m2m-${string}`>;
    }>
  ): Promise<Readonly<{ status: number; body: unknown }>>;
}>;
export type CustomJwtExpectedClaims = Readonly<{
  issuer: string;
  subject: string;
  audience: string;
  clientId: string;
  scope: string;
}>;
export type CustomJwtScenarioEvidence = Readonly<{
  id: CustomJwtScenarioId;
  projection: Readonly<Record<string, JsonValue>>;
}>;

const path = 'configs/jwt-customizer/client-credentials';
const expectedConfigKeys = Object.freeze([
  'blockIssuanceOnError',
  'contextSample',
  'environmentVariables',
  'script',
  'tokenSample',
]);
const environmentMarker = 'custom-jwt-env-marker';
const scripts = Object.freeze({
  success: `const getCustomJwtClaims = async ({ token, context, environmentVariables }) => ({
    probe_claim: 'merged', probe_env: environmentVariables.probe_env,
    probe_app: context.application.id, probe_aud: token.aud
  });`,
  deny: `const getCustomJwtClaims = async ({ api }) => api.denyAccess('blocked');`,
  throwing: `const getCustomJwtClaims = async () => { throw new Error('boom'); };`,
  protected: `const getCustomJwtClaims = async ({ token }) => ({
    iss: 'override', sub: 'override', aud: 'override', exp: 1, iat: 1, jti: 'override',
    client_id: 'override', scope: 'override', organization_id: 'override', gty: 'override',
    kind: 'override', probe_claim: 'merged', probe_env: 'custom-jwt-env-marker', probe_app: 'client',
    probe_original_jti: token.jti
  });`,
});

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 custom JWT scenario');
};
const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  return value as Record<string, unknown>;
};
const errorCode = (response: CustomJwtHttpResponse): JsonValue => {
  const value = record(response.body);
  return typeof value.code === 'string' ? value.code : null;
};
const safeKeys = (value: unknown): readonly string[] =>
  Object.freeze(Object.keys(record(value)).toSorted());
const evidence = (
  id: CustomJwtScenarioId,
  projection: Record<string, JsonValue>
): CustomJwtScenarioEvidence => Object.freeze({ id, projection: Object.freeze(projection) });
const configuration = (script: string, blockIssuanceOnError: boolean) =>
  Object.freeze({
    script,
    blockIssuanceOnError,
    environmentVariables: Object.freeze({ probe_env: environmentMarker }),
    contextSample: Object.freeze({ application: Object.freeze({ id: 'sample', name: 'sample' }) }),
    tokenSample: Object.freeze({
      kind: 'ClientCredentials',
      aud: 'sample',
      scope: 'read',
      clientId: 'sample',
    }),
  });
const decodeJwtPayload = (value: unknown): Record<string, unknown> => {
  if (typeof value !== 'string' || value.length > 16 * 1024) {
    return fail();
  }
  const parts = value.split('.');
  if (parts.length !== 3 || !parts[1]) {
    return fail();
  }
  try {
    return record(JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')));
  } catch {
    return fail();
  }
};
const tokenBody = (value: unknown): Record<string, unknown> => record(value);
const assertStatus = (response: Readonly<{ status: number }>, expected: number): void => {
  if (response.status !== expected) {
    fail();
  }
};
const assertError = (response: CustomJwtHttpResponse, status: number, code: string): void => {
  assertStatus(response, status);
  if (errorCode(response) !== code) {
    fail();
  }
};
const fixedFailure = (stage: 'primary' | 'cleanup' | 'primary+cleanup'): TypeError =>
  new TypeError(`Phase 2 custom JWT scenario failed (${stage})`);

export const runCustomJwtScenarios = async (
  port: CustomJwtTargetPort,
  input: Readonly<{ expected: CustomJwtExpectedClaims }>
): Promise<readonly CustomJwtScenarioEvidence[]> => {
  const results: CustomJwtScenarioEvidence[] = [];
  const push = (id: CustomJwtScenarioId, projection: Record<string, JsonValue>) =>
    results.push(evidence(id, projection));
  const configure = async (script: string, block: boolean) =>
    port.request({ method: 'PUT', path, body: configuration(script, block) });
  let collected: readonly CustomJwtScenarioEvidence[] | undefined;
  let primaryFailed = false;
  try {
    const missing = await port.request({ method: 'GET', path });
    assertError(missing, 404, 'entity.not_exists_with_id');
    push(customJwtScenarioIds[0], { status: missing.status, errorCode: errorCode(missing) });

    const missingDelete = await port.request({ method: 'DELETE', path });
    assertError(missingDelete, 404, 'entity.not_found');
    push(customJwtScenarioIds[1], {
      status: missingDelete.status,
      errorCode: errorCode(missingDelete),
    });

    const put = await configure(scripts.success, false);
    assertStatus(put, 201);
    push(customJwtScenarioIds[2], { status: put.status, responseKeys: [...safeKeys(put.body)] });
    const get = await port.request({ method: 'GET', path });
    assertStatus(get, 200);
    push(customJwtScenarioIds[3], { status: get.status, responseKeys: [...safeKeys(get.body)] });
    const list = await port.request({ method: 'GET', path: 'configs/jwt-customizer' });
    assertStatus(list, 200);
    const listBody = Array.isArray(list.body) ? list.body : fail();
    if (listBody.length !== 1) {
      fail();
    }
    const listItem = record(listBody[0]);
    if (listItem.key !== 'jwt.clientCredentials') {
      fail();
    }
    const valueKeys = safeKeys(listItem.value);
    if (JSON.stringify(valueKeys) !== JSON.stringify(expectedConfigKeys)) {
      fail();
    }
    push(customJwtScenarioIds[4], {
      status: list.status,
      count: listBody.length,
      itemKey: 'jwt.clientCredentials',
      valueKeys: [...valueKeys],
    });
    const patch = await port.request({
      method: 'PATCH',
      path,
      body: configuration(scripts.success, true),
    });
    assertStatus(patch, 200);
    push(customJwtScenarioIds[5], {
      status: patch.status,
      responseKeys: [...safeKeys(patch.body)],
    });
    const patchMissing = await port.request({
      method: 'PATCH',
      path,
      body: { blockIssuanceOnError: false },
    });
    assertError(patchMissing, 400, 'guard.invalid_input');
    push(customJwtScenarioIds[6], {
      status: patchMissing.status,
      errorCode: errorCode(patchMissing),
    });
    const patchNonstring = await port.request({
      method: 'PATCH',
      path,
      body: { ...configuration(scripts.success, false), script: 7 },
    });
    assertError(patchNonstring, 400, 'guard.invalid_input');
    push(customJwtScenarioIds[7], {
      status: patchNonstring.status,
      errorCode: errorCode(patchNonstring),
    });
    const dryRun = await port.request({
      method: 'POST',
      path: 'configs/jwt-customizer/test',
      body: {
        tokenType: 'client-credentials',
        script: scripts.success,
        environmentVariables: { probe_env: environmentMarker },
        token: configuration(scripts.success, false).tokenSample,
        context: configuration(scripts.success, false).contextSample,
      },
    });
    const dryBody = record(dryRun.body);
    assertStatus(dryRun, 200);
    push(customJwtScenarioIds[8], {
      status: dryRun.status,
      customClaimMerged: dryBody.probe_claim === 'dry' || dryBody.probe_claim === 'merged',
    });
    const unknown = await port.request({
      method: 'GET',
      path: 'configs/jwt-customizer/unknown-token-type',
    });
    assertError(unknown, 400, 'guard.invalid_input');
    push(customJwtScenarioIds[9], { status: unknown.status, errorCode: errorCode(unknown) });
    const deleted = await port.request({ method: 'DELETE', path });
    assertStatus(deleted, 204);
    push(customJwtScenarioIds[10], { status: deleted.status });

    await configure(scripts.success, false);
    const success = await port.issueClientCredentials({ caseId: customJwtScenarioIds[11] });
    assertStatus(success, 200);
    const successPayload = decodeJwtPayload(tokenBody(success.body).access_token);
    push(customJwtScenarioIds[11], {
      status: success.status,
      customClaimMerged: successPayload.probe_claim === 'merged',
      environmentMerged: successPayload.probe_env === environmentMarker,
      applicationContextMatched: successPayload.probe_app === input.expected.clientId,
    });

    await configure(scripts.deny, true);
    const denied = await port.issueClientCredentials({ caseId: customJwtScenarioIds[12] });
    if (denied.status !== 400 || tokenBody(denied.body).error !== 'access_denied') {
      fail();
    }
    push(customJwtScenarioIds[12], {
      status: denied.status,
      error: tokenBody(denied.body).error === 'access_denied' ? 'access_denied' : 'other',
    });
    await configure(scripts.throwing, true);
    const blocked = await port.issueClientCredentials({ caseId: customJwtScenarioIds[13] });
    if (blocked.status !== 400 || tokenBody(blocked.body).error !== 'invalid_request') {
      fail();
    }
    push(customJwtScenarioIds[13], {
      status: blocked.status,
      error: tokenBody(blocked.body).error === 'invalid_request' ? 'invalid_request' : 'other',
    });
    await configure(scripts.throwing, false);
    const open = await port.issueClientCredentials({ caseId: customJwtScenarioIds[14] });
    assertStatus(open, 200);
    if (typeof tokenBody(open.body).access_token !== 'string') {
      fail();
    }
    push(customJwtScenarioIds[14], {
      status: open.status,
      issued: typeof tokenBody(open.body).access_token === 'string',
    });

    await configure(scripts.protected, false);
    const issuedBefore = Math.floor(Date.now() / 1000);
    const protectedResult = await port.issueClientCredentials({ caseId: customJwtScenarioIds[15] });
    const issuedAfter = Math.floor(Date.now() / 1000);
    assertStatus(protectedResult, 200);
    const protectedBody = tokenBody(protectedResult.body);
    const claims = decodeJwtPayload(protectedBody.access_token);
    push(customJwtScenarioIds[15], {
      status: protectedResult.status,
      customClaimMerged: claims.probe_claim === 'merged',
      environmentMerged: claims.probe_env === environmentMarker,
      protectedClaimsPreserved:
        claims.iss === input.expected.issuer &&
        claims.sub === input.expected.subject &&
        claims.aud === input.expected.audience &&
        claims.client_id === input.expected.clientId &&
        claims.scope === input.expected.scope &&
        typeof claims.iat === 'number' &&
        Number.isSafeInteger(claims.iat) &&
        claims.iat >= issuedBefore - 30 &&
        claims.iat <= issuedAfter + 30 &&
        typeof claims.exp === 'number' &&
        Number.isSafeInteger(claims.exp) &&
        claims.exp - claims.iat === protectedBody.expires_in &&
        typeof claims.jti === 'string' &&
        claims.jti.length > 0 &&
        claims.jti === claims.probe_original_jti,
      extensionClaimsOverridden:
        claims.organization_id === 'override' &&
        claims.gty === 'override' &&
        claims.kind === 'override',
    });
    if (
      results.length !== customJwtScenarioIds.length ||
      results.some(({ id }, index) => id !== customJwtScenarioIds[index])
    ) {
      fail();
    }
    collected = Object.freeze(results);
  } catch {
    primaryFailed = true;
  }
  try {
    const cleanup = await port.request({ method: 'DELETE', path });
    if (cleanup.status !== 204 && cleanup.status !== 404) {
      fail();
    }
  } catch {
    throw fixedFailure(primaryFailed ? 'primary+cleanup' : 'cleanup');
  }
  if (primaryFailed) {
    throw fixedFailure('primary');
  }
  return collected ?? fail();
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
