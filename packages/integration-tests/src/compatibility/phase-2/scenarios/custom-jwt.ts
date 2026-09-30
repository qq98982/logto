/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The closed scenario collector validates hostile JSON shapes, owns one ordered evidence journal, and deliberately suppresses cleanup failure after the primary result. */
import { types as nodeTypes } from 'node:util';

import type { JsonValue } from '../../normalize.js';

export const customJwtScenarioIds = Object.freeze([
  'custom-jwt.management-missing',
  'custom-jwt.management-put',
  'custom-jwt.management-get',
  'custom-jwt.management-list',
  'custom-jwt.management-patch',
  'custom-jwt.management-test',
  'custom-jwt.management-malformed',
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
const environmentMarker = 'custom-jwt-env-marker';
const scripts = Object.freeze({
  success: `const getCustomJwtClaims = async ({ token, context, environmentVariables }) => ({
    probe_claim: 'merged', probe_env: environmentVariables.probe_env,
    probe_app: context.application.id, probe_aud: token.aud
  });`,
  deny: `const getCustomJwtClaims = async ({ api }) => api.denyAccess('blocked');`,
  throwing: `const getCustomJwtClaims = async () => { throw new Error('boom'); };`,
  protected: `const getCustomJwtClaims = async () => ({
    iss: 'override', sub: 'override', aud: 'override', exp: 1, iat: 1, jti: 'override',
    client_id: 'override', scope: 'override', organization_id: 'override', gty: 'override',
    kind: 'override', probe_claim: 'merged', probe_env: 'custom-jwt-env-marker', probe_app: 'client'
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

export const runCustomJwtScenarios = async (
  port: CustomJwtTargetPort,
  input: Readonly<{ expected: CustomJwtExpectedClaims }>
): Promise<readonly CustomJwtScenarioEvidence[]> => {
  const results: CustomJwtScenarioEvidence[] = [];
  const push = (id: CustomJwtScenarioId, projection: Record<string, JsonValue>) =>
    results.push(evidence(id, projection));
  const configure = async (script: string, block: boolean) =>
    port.request({ method: 'PUT', path, body: configuration(script, block) });
  try {
    const missing = await port.request({ method: 'GET', path });
    push(customJwtScenarioIds[0], { status: missing.status, errorCode: errorCode(missing) });

    const put = await configure(scripts.success, false);
    push(customJwtScenarioIds[1], { status: put.status, responseKeys: [...safeKeys(put.body)] });
    const get = await port.request({ method: 'GET', path });
    push(customJwtScenarioIds[2], { status: get.status, responseKeys: [...safeKeys(get.body)] });
    const list = await port.request({ method: 'GET', path: 'configs/jwt-customizer' });
    const listBody = Array.isArray(list.body) ? list.body : fail();
    push(customJwtScenarioIds[3], { status: list.status, count: listBody.length });
    const patch = await port.request({
      method: 'PATCH',
      path,
      body: configuration(scripts.success, true),
    });
    push(customJwtScenarioIds[4], {
      status: patch.status,
      responseKeys: [...safeKeys(patch.body)],
    });
    const dryRun = await port.request({
      method: 'POST',
      path: 'configs/jwt-customizer/test',
      body: {
        tokenType: 'client-credentials',
        ...configuration(scripts.success, false),
      },
    });
    const dryBody = record(dryRun.body);
    push(customJwtScenarioIds[5], {
      status: dryRun.status,
      customClaimMerged: dryBody.probe_claim === 'dry' || dryBody.probe_claim === 'merged',
    });
    const malformed = await port.request({
      method: 'PUT',
      path,
      body: { ...configuration(scripts.success, false), script: 7 },
    });
    push(customJwtScenarioIds[6], { status: malformed.status, errorCode: errorCode(malformed) });
    const deleted = await port.request({ method: 'DELETE', path });
    push(customJwtScenarioIds[7], { status: deleted.status });

    await configure(scripts.success, false);
    const success = await port.issueClientCredentials({ caseId: customJwtScenarioIds[8] });
    const successPayload = decodeJwtPayload(tokenBody(success.body).access_token);
    push(customJwtScenarioIds[8], {
      status: success.status,
      customClaimMerged: successPayload.probe_claim === 'merged',
      environmentMerged: successPayload.probe_env === environmentMarker,
      applicationContextMatched: successPayload.probe_app === input.expected.clientId,
    });

    await configure(scripts.deny, true);
    const denied = await port.issueClientCredentials({ caseId: customJwtScenarioIds[9] });
    push(customJwtScenarioIds[9], {
      status: denied.status,
      error: tokenBody(denied.body).error === 'access_denied' ? 'access_denied' : 'other',
    });
    await configure(scripts.throwing, true);
    const blocked = await port.issueClientCredentials({ caseId: customJwtScenarioIds[10] });
    push(customJwtScenarioIds[10], {
      status: blocked.status,
      error: tokenBody(blocked.body).error === 'invalid_request' ? 'invalid_request' : 'other',
    });
    await configure(scripts.throwing, false);
    const open = await port.issueClientCredentials({ caseId: customJwtScenarioIds[11] });
    push(customJwtScenarioIds[11], {
      status: open.status,
      issued: typeof tokenBody(open.body).access_token === 'string',
    });

    await configure(scripts.protected, false);
    const protectedResult = await port.issueClientCredentials({ caseId: customJwtScenarioIds[12] });
    const claims = decodeJwtPayload(tokenBody(protectedResult.body).access_token);
    push(customJwtScenarioIds[12], {
      status: protectedResult.status,
      customClaimMerged: claims.probe_claim === 'merged',
      environmentMerged: claims.probe_env === environmentMarker,
      protectedClaimsPreserved:
        claims.iss === input.expected.issuer &&
        claims.sub === input.expected.subject &&
        claims.aud === input.expected.audience &&
        claims.client_id === input.expected.clientId &&
        claims.scope === input.expected.scope &&
        claims.exp !== 1 &&
        claims.iat !== 1 &&
        claims.jti !== 'override',
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
    return Object.freeze(results);
  } finally {
    await port.request({ method: 'DELETE', path }).catch(() => {});
  }
};

/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
