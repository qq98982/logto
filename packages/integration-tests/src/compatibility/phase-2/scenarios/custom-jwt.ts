/* eslint-disable max-lines, complexity, no-restricted-syntax, no-await-in-loop, @typescript-eslint/ban-types, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The closed scenario collector validates hostile JSON shapes, owns sequential isolated evidence journals, and preserves fixed primary and cleanup failure classes; null is an observed wire value. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

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
  'custom-jwt.user-initial-resource',
  'custom-jwt.user-refresh-context',
  'custom-jwt.user-old-refresh-after-rotation',
  'custom-jwt.user-refresh-deny',
  'custom-jwt.user-refresh-throw-block',
  'custom-jwt.user-refresh-throw-open-retry',
  'custom-jwt.device-resource-refresh-context',
] as const);

export type CustomJwtScenarioId = (typeof customJwtScenarioIds)[number];
export type CustomJwtHttpResponse = Readonly<{
  status: number;
  headers: Readonly<Record<string, string>>;
  body: unknown;
}>;
export type CustomJwtFetchReceipt = Readonly<{
  method: 'GET' | 'POST';
  path: '/text' | '/json' | '/post' | '/not-found' | '/redirect' | '/final' | '/reset-connection';
  headerMatches: boolean;
  bodyMatches: boolean;
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
  issueUserTokens(): Promise<Readonly<{ access: string; refresh: string; toJSON(): never }>>;
  exchangeUserRefresh(
    input: Readonly<{ refreshToken: string }>
  ): Promise<Readonly<{ status: number; body: unknown; toJSON?(): never }>>;
  observeDeviceResourceRefresh(): Promise<
    Readonly<{
      status: number;
      initialAccessOpaque: boolean;
      invoked: boolean;
      userContextPresent: boolean;
      applicationContextPresent: boolean;
      userMatchesToken: boolean;
      applicationMatchesToken: boolean;
      protectedClaimsMatch: boolean;
      tokenKind: string | null;
      grantType: string | null;
    }>
  >;
  verifyAccessToken(token: string): Promise<Readonly<Record<string, unknown>>>;
  readAndResetFetchReceipts?(): Promise<readonly CustomJwtFetchReceipt[]>;
}>;
export type CustomJwtFetchTargetPort = Readonly<{
  request: CustomJwtTargetPort['request'];
  readAndResetFetchReceipts(): Promise<readonly CustomJwtFetchReceipt[]>;
}>;
export type CustomJwtExpectedClaims = Readonly<{
  issuer: string;
  subject: string;
  audience: string;
  clientId: string;
  scope: string;
  userSubject: string;
  userClientId: string;
  userApplicationName: string;
  userAudience: string;
  userScope: string;
}>;
export type CustomJwtScenarioEvidence = Readonly<{
  id: CustomJwtScenarioId;
  projection: Readonly<Record<string, JsonValue>>;
}>;

export const customJwtFetchScenarioIds = Object.freeze([
  'custom-jwt.fetch-get-text',
  'custom-jwt.fetch-get-json',
  'custom-jwt.fetch-post',
  'custom-jwt.fetch-not-found',
  'custom-jwt.fetch-redirect',
  'custom-jwt.fetch-reset-connection',
] as const);
export type CustomJwtFetchScenarioId = (typeof customJwtFetchScenarioIds)[number];
export type CustomJwtFetchScenarioEvidence = Readonly<{
  id: CustomJwtFetchScenarioId;
  projection: Readonly<Record<string, JsonValue>>;
}>;

export const compareCustomJwtProjections = (
  expected: CustomJwtScenarioEvidence['projection'],
  actual: CustomJwtScenarioEvidence['projection']
): boolean => isDeepStrictEqual(expected, actual);

const path = 'configs/jwt-customizer/client-credentials';
const userPath = 'configs/jwt-customizer/access-token';
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
  user: `const getCustomJwtClaims = async ({ token, context }) => ({
    probe_user_id: context.user.id, probe_has_password: context.user.hasPassword,
    // The pinned probe queried "event" and observed null on resource refresh.
    probe_event: context.interaction?.event ?? null,
    probe_verification_type: context.interaction?.verificationRecords?.[0]?.type ?? null,
    probe_application_id: context.application?.id ?? null,
    probe_application_name: context.application?.name ?? null,
    probe_token_aud: token.aud, probe_token_scope: token.scope,
    probe_token_client_id: token.clientId, probe_token_account_id: token.accountId,
    probe_token_gty: token.gty, probe_token_kind: token.kind, probe_survives: 'yes'
  });`,
  device: `const getCustomJwtClaims = async ({ token, context }) => ({
    probe_invoked: true,
    probe_user_context_present: context.user !== undefined,
    probe_application_context_present: context.application !== undefined,
    probe_user_matches_token: context.user?.id === token.accountId,
    probe_application_matches_token: context.application?.id === token.clientId,
    probe_user_id: context.user?.id ?? null,
    probe_application_id: context.application?.id ?? null,
    probe_token_account_id: token.accountId ?? null,
    probe_token_client_id: token.clientId ?? null,
    probe_token_kind: token.kind,
    probe_grant_type: token.gty
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
const userConfiguration = (script: string, blockIssuanceOnError: boolean) =>
  Object.freeze({
    script,
    blockIssuanceOnError,
    environmentVariables: Object.freeze({}),
    contextSample: Object.freeze({
      user: Object.freeze({ id: 'sample', hasPassword: true }),
      application: Object.freeze({ id: 'sample', name: 'sample' }),
    }),
    tokenSample: Object.freeze({
      kind: 'AccessToken',
      aud: 'sample',
      scope: 'read',
      clientId: 'sample',
      accountId: 'sample',
    }),
  });
const tokenBody = (value: unknown): Record<string, unknown> => record(value);
const textOrNull = (value: unknown): string | null =>
  value === null || typeof value === 'string' ? value : fail();
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

const fetchOrigin = 'https://fetch-observer.aster.test:8443';
const fetchScripts = Object.freeze([
  `const getCustomJwtClaims = async () => {
    const response = await fetch('${fetchOrigin}/text');
    return { probe_status: response.status, probe_text_matches: (await response.text()) === 'bounded-text' };
  };`,
  `const getCustomJwtClaims = async () => {
    const response = await fetch('${fetchOrigin}/json');
    const body = await response.json();
    return { probe_status: response.status, probe_json_matches: body.kind === 'bounded-json' && body.count === 2 };
  };`,
  `const getCustomJwtClaims = async () => {
    const response = await fetch('${fetchOrigin}/post', {
      method: 'POST', headers: { 'x-aster-probe': 'bounded-header' }, body: 'bounded-body'
    });
    const body = await response.json();
    return { probe_status: response.status, probe_json_matches:
      body.method === 'POST' && body.header === 'bounded-header' && body.body === 'bounded-body' };
  };`,
  `const getCustomJwtClaims = async () => {
    const response = await fetch('${fetchOrigin}/not-found');
    return { probe_status: response.status, probe_ok: response.ok,
      probe_text_matches: (await response.text()) === 'missing' };
  };`,
  `const getCustomJwtClaims = async () => {
    const response = await fetch('${fetchOrigin}/redirect');
    const finalPathMatches = typeof response.url === 'string' && response.url.endsWith('/final');
    return { probe_status: response.status, probe_redirected: response.redirected,
      probe_final_path_matches: finalPathMatches,
      probe_text_matches: (await response.text()) === 'redirected' };
  };`,
  `const getCustomJwtClaims = async () => {
    try { await fetch('${fetchOrigin}/reset-connection'); }
    catch (error) { return { probe_error_name: error?.name ?? null }; }
    return { probe_error_name: null };
  };`,
] as const);
const fetchTokenSample = Object.freeze({
  kind: 'ClientCredentials',
  aud: 'sample',
  scope: 'read',
  clientId: 'sample',
});
const fetchContextSample = Object.freeze({
  application: Object.freeze({ id: 'sample', name: 'sample' }),
});
const isTrue = (value: unknown): value is true => value === true;
const projectedReceipts = (
  receipts: readonly CustomJwtFetchReceipt[],
  expected: ReadonlyArray<Readonly<{ method: 'GET' | 'POST'; path: CustomJwtFetchReceipt['path'] }>>
): JsonValue[] => {
  if (
    receipts.length !== expected.length ||
    receipts.some((item, index) => {
      const { method, path, headerMatches, bodyMatches } = item;
      return (
        method !== expected[index]?.method ||
        path !== expected[index]?.path ||
        !isTrue(headerMatches) ||
        !isTrue(bodyMatches)
      );
    })
  ) {
    return fail();
  }
  return Object.freeze(
    expected.map(({ method, path }): Record<string, JsonValue> => {
      if (path === '/post') {
        return Object.freeze({ method, path, headerMatches: true, bodyMatches: true });
      }
      return Object.freeze({ method, path });
    })
  ) as unknown as JsonValue[];
};
const observedBoolean = (value: unknown): boolean => (typeof value === 'boolean' ? value : fail());

export const runCustomJwtFetchScenarios = async (
  port: CustomJwtFetchTargetPort
): Promise<readonly CustomJwtFetchScenarioEvidence[]> => {
  const expectedReceipts = Object.freeze([
    [{ method: 'GET', path: '/text' }],
    [{ method: 'GET', path: '/json' }],
    [{ method: 'POST', path: '/post' }],
    [{ method: 'GET', path: '/not-found' }],
    [
      { method: 'GET', path: '/redirect' },
      { method: 'GET', path: '/final' },
    ],
    [{ method: 'GET', path: '/reset-connection' }],
  ] as const);
  const results: CustomJwtFetchScenarioEvidence[] = [];
  for (const [index, id] of customJwtFetchScenarioIds.entries()) {
    const staleReceipts = await port.readAndResetFetchReceipts();
    if (staleReceipts.length > 0) {
      fail();
    }
    const response = await port.request({
      method: 'POST',
      path: 'configs/jwt-customizer/test',
      body: {
        tokenType: 'client-credentials',
        script: fetchScripts[index],
        environmentVariables: {},
        token: fetchTokenSample,
        context: fetchContextSample,
      },
    });
    assertStatus(response, 200);
    const body = record(response.body);
    const receipts = projectedReceipts(
      await port.readAndResetFetchReceipts(),
      expectedReceipts[index] ?? fail()
    );
    const responseStatus = body.probe_status;
    const errorName = body.probe_error_name;
    const textMatches = body.probe_text_matches;
    const jsonMatches = body.probe_json_matches;
    const responseOk = body.probe_ok;
    const redirected = body.probe_redirected;
    const finalPathMatches = body.probe_final_path_matches;
    const projection: Record<string, JsonValue> = {
      managementStatus: response.status,
      ...(index === 5
        ? { errorName: errorName === 'TypeError' ? 'TypeError' : fail() }
        : {
            responseStatus:
              typeof responseStatus === 'number' &&
              Number.isInteger(responseStatus) &&
              responseStatus >= 100 &&
              responseStatus <= 599
                ? responseStatus
                : fail(),
            ...(index === 1 || index === 2
              ? { jsonMatches: observedBoolean(jsonMatches) }
              : {
                  textMatches: observedBoolean(textMatches),
                  ...(index === 3 ? { ok: observedBoolean(responseOk) } : {}),
                  ...(index === 4
                    ? {
                        redirected: observedBoolean(redirected),
                        finalPathMatches: observedBoolean(finalPathMatches),
                      }
                    : {}),
                }),
          }),
      receipts,
    };
    results.push(Object.freeze({ id, projection: Object.freeze(projection) }));
  }
  return Object.freeze(results);
};

export const runCustomJwtScenarios = async (
  port: CustomJwtTargetPort,
  input: Readonly<{ expected: CustomJwtExpectedClaims }>
): Promise<readonly CustomJwtScenarioEvidence[]> => {
  const results: CustomJwtScenarioEvidence[] = [];
  let m2mCreated = false;
  let userCreated = false;
  const push = (id: CustomJwtScenarioId, projection: Record<string, JsonValue>) =>
    results.push(evidence(id, projection));
  const configure = async (script: string, block: boolean) => {
    const response = await port.request({
      method: 'PUT',
      path,
      body: configuration(script, block),
    });
    if (response.status === 200 || response.status === 201) {
      m2mCreated = true;
    }
    return response;
  };
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
    const successTokenValue = tokenBody(success.body).access_token;
    const successToken = typeof successTokenValue === 'string' ? successTokenValue : fail();
    const successPayload = await port.verifyAccessToken(successToken);
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
    const protectedToken =
      typeof protectedBody.access_token === 'string' ? protectedBody.access_token : fail();
    const claims = await port.verifyAccessToken(protectedToken);
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

    const userMissing = await port.request({ method: 'GET', path: userPath });
    assertError(userMissing, 404, 'entity.not_exists_with_id');
    const configureUser = async (script: string, block: boolean) => {
      const response = await port.request({
        method: 'PUT',
        path: userPath,
        body: userConfiguration(script, block),
      });
      if (response.status === 200 || response.status === 201) {
        userCreated = true;
      }
      return response;
    };
    await configureUser(scripts.user, false);
    const firstUser = await port.issueUserTokens();
    const initialClaims = await port.verifyAccessToken(firstUser.access);
    push(customJwtScenarioIds[16], {
      status: 200,
      customized: initialClaims.probe_survives === 'yes',
      subjectMatches: initialClaims.sub === input.expected.userSubject,
      resourceAudienceMatches: initialClaims.aud === input.expected.userAudience,
      clientIdMatches: initialClaims.client_id === input.expected.userClientId,
      accountIdMatches: initialClaims.probe_token_account_id === input.expected.userSubject,
      applicationIdMatches: initialClaims.probe_application_id === input.expected.userClientId,
      applicationNameMatches:
        initialClaims.probe_application_name === input.expected.userApplicationName,
      scopeEmpty: initialClaims.probe_token_scope === '',
      scopeMatchesFixture: initialClaims.probe_token_scope === input.expected.userScope,
      grantType: textOrNull(initialClaims.probe_token_gty),
      kind: textOrNull(initialClaims.probe_token_kind),
    });
    const refreshed = await port.exchangeUserRefresh({ refreshToken: firstUser.refresh });
    assertStatus(refreshed, 200);
    const refreshedBody = tokenBody(refreshed.body);
    const refreshedAccess =
      typeof refreshedBody.access_token === 'string' ? refreshedBody.access_token : fail();
    const refreshedClaims = await port.verifyAccessToken(refreshedAccess);
    push(customJwtScenarioIds[17], {
      status: refreshed.status,
      userIdMatches: refreshedClaims.probe_user_id === input.expected.userSubject,
      hasPassword: refreshedClaims.probe_has_password === true,
      event: refreshedClaims.probe_event === null ? null : 'present',
      verificationType: textOrNull(refreshedClaims.probe_verification_type),
      applicationIdMatches: refreshedClaims.probe_application_id === input.expected.userClientId,
      applicationNameMatches:
        refreshedClaims.probe_application_name === input.expected.userApplicationName,
      audienceMatches: refreshedClaims.probe_token_aud === input.expected.userAudience,
      scopeEmpty: refreshedClaims.probe_token_scope === '',
      scopeMatchesFixture: refreshedClaims.probe_token_scope === input.expected.userScope,
      clientIdMatches: refreshedClaims.probe_token_client_id === input.expected.userClientId,
      accountIdMatches: refreshedClaims.probe_token_account_id === input.expected.userSubject,
      customSurvives: refreshedClaims.probe_survives === 'yes',
      grantType: textOrNull(refreshedClaims.probe_token_gty),
      kind: textOrNull(refreshedClaims.probe_token_kind),
    });

    await configureUser(scripts.user, false);
    const rotationUser = await port.issueUserTokens();
    const rotated = await port.exchangeUserRefresh({ refreshToken: rotationUser.refresh });
    assertStatus(rotated, 200);
    const rotatedBody = tokenBody(rotated.body);
    const rotatedRefresh =
      typeof rotatedBody.refresh_token === 'string' &&
      rotatedBody.refresh_token !== rotationUser.refresh;
    const oldAfterRotation = await port.exchangeUserRefresh({
      refreshToken: rotationUser.refresh,
    });
    push(customJwtScenarioIds[18], {
      status: oldAfterRotation.status,
      error:
        tokenBody(oldAfterRotation.body).error === undefined
          ? null
          : textOrNull(tokenBody(oldAfterRotation.body).error),
      issued: typeof tokenBody(oldAfterRotation.body).access_token === 'string',
      priorRefreshRotated: rotatedRefresh,
    });

    await configureUser(scripts.user, false);
    const denyUser = await port.issueUserTokens();
    await configureUser(scripts.deny, true);
    const userDenied = await port.exchangeUserRefresh({ refreshToken: denyUser.refresh });
    assertStatus(userDenied, 400);
    push(customJwtScenarioIds[19], {
      status: userDenied.status,
      error: tokenBody(userDenied.body).error === 'access_denied' ? 'access_denied' : 'other',
      issued: typeof tokenBody(userDenied.body).access_token === 'string',
    });

    await configureUser(scripts.user, false);
    const blockUser = await port.issueUserTokens();
    await configureUser(scripts.throwing, true);
    const userBlocked = await port.exchangeUserRefresh({ refreshToken: blockUser.refresh });
    assertStatus(userBlocked, 400);
    push(customJwtScenarioIds[20], {
      status: userBlocked.status,
      error: tokenBody(userBlocked.body).error === 'invalid_request' ? 'invalid_request' : 'other',
      issued: typeof tokenBody(userBlocked.body).access_token === 'string',
    });

    await configureUser(scripts.user, false);
    const retryUser = await port.issueUserTokens();
    await configureUser(scripts.deny, true);
    const rejectedDeny = await port.exchangeUserRefresh({ refreshToken: retryUser.refresh });
    assertStatus(rejectedDeny, 400);
    await configureUser(scripts.throwing, true);
    const rejectedThrow = await port.exchangeUserRefresh({ refreshToken: retryUser.refresh });
    assertStatus(rejectedThrow, 400);
    await configureUser(scripts.throwing, false);
    const userOpen = await port.exchangeUserRefresh({ refreshToken: retryUser.refresh });
    assertStatus(userOpen, 200);
    push(customJwtScenarioIds[21], {
      status: userOpen.status,
      issued: typeof tokenBody(userOpen.body).access_token === 'string',
      sameRefreshRemainedUsable: userOpen.status === 200,
    });
    await configureUser(scripts.device, true);
    const deviceRefresh = await port.observeDeviceResourceRefresh();
    push(customJwtScenarioIds[22], {
      status: deviceRefresh.status,
      initialAccessOpaque: deviceRefresh.initialAccessOpaque,
      invoked: deviceRefresh.invoked,
      userContextPresent: deviceRefresh.userContextPresent,
      applicationContextPresent: deviceRefresh.applicationContextPresent,
      userMatchesToken: deviceRefresh.userMatchesToken,
      applicationMatchesToken: deviceRefresh.applicationMatchesToken,
      protectedClaimsMatch: deviceRefresh.protectedClaimsMatch,
      tokenKind: deviceRefresh.tokenKind,
      grantType: deviceRefresh.grantType,
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
    const cleanupResults = await Promise.all(
      [path, userPath].map(async (cleanupPath) => {
        try {
          const cleanup = await port.request({ method: 'DELETE', path: cleanupPath });
          const knownCreated = cleanupPath === path ? m2mCreated : userCreated;
          return knownCreated
            ? cleanup.status === 204
            : cleanup.status === 204 || cleanup.status === 404;
        } catch {
          return false;
        }
      })
    );
    if (cleanupResults.includes(false)) {
      throw fixedFailure(primaryFailed ? 'primary+cleanup' : 'cleanup');
    }
  } catch {
    throw fixedFailure(primaryFailed ? 'primary+cleanup' : 'cleanup');
  }
  if (primaryFailed) {
    throw fixedFailure('primary');
  }
  return collected ?? fail();
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, no-await-in-loop, @typescript-eslint/ban-types, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
