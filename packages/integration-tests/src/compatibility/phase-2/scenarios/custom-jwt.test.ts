/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The stateful fake target proves ordering, lifecycle changes, cleanup, and evidence redaction through one bounded in-memory contract. */

import {
  compareCustomJwtProjections,
  customJwtFetchScenarioIds,
  customJwtScenarioIds,
  runCustomJwtFetchScenarios,
  runCustomJwtScenarios,
  type CustomJwtFetchReceipt,
  type CustomJwtFetchTargetPort,
  type CustomJwtTargetPort,
} from './custom-jwt.js';

const jwt = (payload: Record<string, unknown>) =>
  ['header', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'signature'].join('.');
const verifyJwt = async (token: string) =>
  JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
const userAccessJwt = () =>
  jwt({
    sub: 'user',
    aud: 'resource',
    client_id: 'user-client',
    scope: 'read:profile',
    probe_application_id: 'user-client',
    probe_application_name: 'User Client',
    probe_token_account_id: 'user',
    probe_token_scope: 'read:profile',
    probe_token_gty: 'authorization_code',
    probe_token_kind: 'AccessToken',
    probe_survives: 'yes',
  });

describe('Phase 2 custom JWT scenarios', () => {
  it('collects six isolated fetch dry runs with exact sanitized observer receipts', async () => {
    const pendingReceipts: CustomJwtFetchReceipt[][] = [];
    const scriptsSeen: string[] = [];
    const port: CustomJwtFetchTargetPort = {
      request: async ({ method, path, body }) => {
        expect({ method, path }).toEqual({
          method: 'POST',
          path: 'configs/jwt-customizer/test',
        });
        const { script } = body as { script: string };
        scriptsSeen.push(script);
        if (script.includes('/text')) {
          pendingReceipts.push([
            { method: 'GET', path: '/text', headerMatches: true, bodyMatches: true },
          ]);
          return {
            status: 200,
            headers: {},
            body: { probe_status: 200, probe_text_matches: true },
          };
        }
        if (script.includes('/json')) {
          pendingReceipts.push([
            { method: 'GET', path: '/json', headerMatches: true, bodyMatches: true },
          ]);
          return {
            status: 200,
            headers: {},
            body: { probe_status: 200, probe_json_matches: true },
          };
        }
        if (script.includes('/post')) {
          pendingReceipts.push([
            { method: 'POST', path: '/post', headerMatches: true, bodyMatches: true },
          ]);
          return {
            status: 200,
            headers: {},
            body: { probe_status: 201, probe_json_matches: true },
          };
        }
        if (script.includes('/not-found')) {
          pendingReceipts.push([
            { method: 'GET', path: '/not-found', headerMatches: true, bodyMatches: true },
          ]);
          return {
            status: 200,
            headers: {},
            body: { probe_status: 404, probe_ok: false, probe_text_matches: true },
          };
        }
        if (script.includes('/redirect')) {
          pendingReceipts.push([
            { method: 'GET', path: '/redirect', headerMatches: true, bodyMatches: true },
            { method: 'GET', path: '/final', headerMatches: true, bodyMatches: true },
          ]);
          return {
            status: 200,
            headers: {},
            body: {
              probe_status: 200,
              probe_redirected: true,
              probe_final_path_matches: true,
              probe_text_matches: true,
            },
          };
        }
        pendingReceipts.push([
          {
            method: 'GET',
            path: '/reset-connection',
            headerMatches: true,
            bodyMatches: true,
          },
        ]);
        return { status: 200, headers: {}, body: { probe_error_name: 'TypeError' } };
      },
      readAndResetFetchReceipts: async () => pendingReceipts.shift() ?? [],
    };

    const result = await runCustomJwtFetchScenarios(port);

    expect(result.map(({ id }) => id)).toEqual(customJwtFetchScenarioIds);
    expect(result.map(({ projection }) => projection)).toEqual([
      {
        managementStatus: 200,
        responseStatus: 200,
        textMatches: true,
        receipts: [{ method: 'GET', path: '/text' }],
      },
      {
        managementStatus: 200,
        responseStatus: 200,
        jsonMatches: true,
        receipts: [{ method: 'GET', path: '/json' }],
      },
      {
        managementStatus: 200,
        responseStatus: 201,
        jsonMatches: true,
        receipts: [{ method: 'POST', path: '/post', headerMatches: true, bodyMatches: true }],
      },
      {
        managementStatus: 200,
        responseStatus: 404,
        ok: false,
        textMatches: true,
        receipts: [{ method: 'GET', path: '/not-found' }],
      },
      {
        managementStatus: 200,
        responseStatus: 200,
        redirected: true,
        finalPathMatches: true,
        textMatches: true,
        receipts: [
          { method: 'GET', path: '/redirect' },
          { method: 'GET', path: '/final' },
        ],
      },
      {
        managementStatus: 200,
        errorName: 'TypeError',
        receipts: [{ method: 'GET', path: '/reset-connection' }],
      },
    ]);
    expect(scriptsSeen).toHaveLength(6);
    expect(scriptsSeen[2]).toMatch(
      /method: 'POST'.*'x-aster-probe': 'bounded-header'.*body: 'bounded-body'/su
    );
    expect(scriptsSeen[3]).toContain('probe_ok: response.ok');
    expect(scriptsSeen[4]).toMatch(
      /typeof response\.url === 'string'.*response\.url\.endsWith\('\/final'\).*response\.redirected/su
    );
    expect(scriptsSeen[5]).toContain(
      "fetch('https://fetch-observer.aster.test:8443/reset-connection')"
    );
    expect(JSON.stringify(result)).not.toMatch(
      /bounded-body|bounded-header|fetch-observer\.aster\.test|script|token|cookie/iu
    );
  });

  it.each([
    [
      'stale receipts before invocation',
      [[{ method: 'GET', path: '/text', headerMatches: true, bodyMatches: true }]],
    ],
    [
      'a wrong receipt after invocation',
      [[], [{ method: 'GET', path: '/json', headerMatches: true, bodyMatches: true }]],
    ],
  ] as const)('fails closed on %s', async (_name, journal) => {
    let requestCount = 0;
    let readCount = 0;
    const port: CustomJwtFetchTargetPort = {
      request: async () => {
        requestCount += 1;
        return {
          status: 200,
          headers: {},
          body: { probe_status: 200, probe_text_matches: true },
        };
      },
      readAndResetFetchReceipts: async () => journal[readCount++] ?? [],
    };

    await expect(runCustomJwtFetchScenarios(port)).rejects.toThrow(
      'Invalid Phase 2 custom JWT scenario'
    );
    expect(requestCount).toBe(journal.length === 1 ? 0 : 1);
  });

  it('compares custom JWT status, denial and protected-claim evidence exactly', () => {
    const denied = { status: 400, error: 'access_denied' };
    expect(compareCustomJwtProjections(denied, { ...denied })).toBe(true);
    expect(compareCustomJwtProjections(denied, { status: 200, error: null })).toBe(false);
    expect(
      compareCustomJwtProjections(
        { status: 200, protectedClaimsPreserved: true },
        { status: 200, protectedClaimsPreserved: false }
      )
    ).toBe(false);
  });

  it('collects the fixed management and M2M contract without credential or script material', async () => {
    let configured = false;
    let userConfigured = false;
    const issuedRefreshTokens = new Set<string>();
    let userMode: 'success' | 'deny' | 'block' | 'open' = 'success';
    let deviceRelationshipsMatch = true;
    let failDeviceRefresh = false;
    const calls: string[] = [];
    const port: CustomJwtTargetPort = {
      verifyAccessToken: verifyJwt,
      request: async ({ method, path, body }): ReturnType<CustomJwtTargetPort['request']> => {
        calls.push(`${method} ${path}`);
        if (method === 'DELETE') {
          const access = path.endsWith('/access-token');
          const existed = access ? userConfigured : configured;
          if (access) {
            userConfigured = false;
          } else {
            configured = false;
          }
          return {
            status: existed ? 204 : 404,
            headers: {},
            body: existed ? null : { code: 'entity.not_found' },
          };
        }
        if (path.endsWith('/test')) {
          if (
            typeof body !== 'object' ||
            body === null ||
            !('token' in body) ||
            !('context' in body) ||
            'tokenSample' in body ||
            'contextSample' in body
          ) {
            return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
          }
          return { status: 200, headers: {}, body: { probe_claim: 'dry' } };
        }
        if (path.endsWith('/unknown-token-type')) {
          return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
        }
        if (method === 'PUT') {
          if (typeof (body as { script?: unknown }).script !== 'string') {
            return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
          }
          configured = true;
          if (path.endsWith('/access-token')) {
            userConfigured = true;
            const { script } = body as { script: string };
            userMode = script.includes('denyAccess')
              ? 'deny'
              : script.includes('throw new Error')
                ? (body as { blockIssuanceOnError: boolean }).blockIssuanceOnError
                  ? 'block'
                  : 'open'
                : 'success';
          }
          return { status: 201, headers: { vary: 'Origin' }, body };
        }
        if (method === 'PATCH') {
          if (typeof (body as { script?: unknown }).script !== 'string') {
            return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
          }
          return { status: 200, headers: {}, body };
        }
        if (path.endsWith('/jwt-customizer')) {
          return {
            status: 200,
            headers: {},
            body: configured
              ? [
                  {
                    key: 'jwt.clientCredentials',
                    value: {
                      script: 'hidden',
                      blockIssuanceOnError: true,
                      environmentVariables: {},
                      contextSample: {},
                      tokenSample: {},
                    },
                  },
                ]
              : [],
          };
        }
        if (path.endsWith('/access-token')) {
          return userConfigured
            ? { status: 200, headers: {}, body: body ?? {} }
            : { status: 404, headers: {}, body: { code: 'entity.not_exists_with_id' } };
        }
        return configured
          ? {
              status: 200,
              headers: {},
              body: {
                script: 'hidden',
                blockIssuanceOnError: true,
                environmentVariables: {},
                contextSample: {},
                tokenSample: {},
              },
            }
          : { status: 404, headers: {}, body: { code: 'entity.not_exists_with_id' } };
      },
      issueClientCredentials: async ({ caseId }) => {
        if (caseId === 'custom-jwt.m2m-deny') {
          return { status: 400, body: { error: 'access_denied' } };
        }
        if (caseId === 'custom-jwt.m2m-throw-block') {
          return { status: 400, body: { error: 'invalid_request' } };
        }
        const issuedAt = Math.floor(Date.now() / 1000);
        return {
          status: 200,
          body: {
            expires_in: 3600,
            access_token: jwt({
              probe_claim: 'merged',
              probe_env: 'custom-jwt-env-marker',
              probe_app: 'client',
              iss: 'issuer',
              sub: 'client',
              aud: 'resource',
              exp: issuedAt + 3600,
              iat: issuedAt,
              jti: 'dynamic-id',
              probe_original_jti: 'dynamic-id',
              client_id: 'client',
              scope: 'read',
              organization_id: 'override',
              gty: 'override',
              kind: 'override',
            }),
          },
        };
      },
      issueUserTokens: async () => {
        const refresh = `refresh-token-${issuedRefreshTokens.size + 1}`;
        issuedRefreshTokens.add(refresh);
        return {
          access: userAccessJwt(),
          refresh,
          toJSON: () => {
            throw new Error('must stay private');
          },
        };
      },
      exchangeUserRefresh: async ({ refreshToken }) => {
        if (!issuedRefreshTokens.has(refreshToken)) {
          throw new Error('unknown refresh');
        }
        if (userMode === 'deny') {
          return { status: 400, body: { error: 'access_denied' } };
        }
        if (userMode === 'block') {
          return { status: 400, body: { error: 'invalid_request' } };
        }
        return {
          status: 200,
          body: {
            access_token: jwt({
              probe_user_id: 'user',
              probe_has_password: true,
              probe_event: null,
              probe_verification_type: 'Password',
              probe_application_id: 'user-client',
              probe_application_name: 'User Client',
              probe_token_aud: 'resource',
              probe_token_scope: 'read:profile',
              probe_token_client_id: 'user-client',
              probe_token_account_id: 'user',
              probe_token_gty: 'authorization_code refresh_token',
              probe_token_kind: 'AccessToken',
              probe_survives: 'yes',
            }),
            refresh_token: 'next-refresh-token',
          },
        };
      },
      observeDeviceResourceRefresh: async () => {
        if (failDeviceRefresh) {
          throw new Error('private device failure');
        }
        return {
          status: 200,
          initialAccessOpaque: true,
          invoked: true,
          userContextPresent: true,
          applicationContextPresent: true,
          userMatchesToken: deviceRelationshipsMatch,
          applicationMatchesToken: deviceRelationshipsMatch,
          protectedClaimsMatch: true,
          tokenKind: 'access_token',
          grantType: 'device_code refresh_token',
        };
      },
    };

    const result = await runCustomJwtScenarios(port, {
      expected: {
        issuer: 'issuer',
        subject: 'client',
        audience: 'resource',
        clientId: 'client',
        scope: 'read',
        userSubject: 'user',
        userClientId: 'user-client',
        userApplicationName: 'User Client',
        userAudience: 'resource',
        userScope: 'read:profile',
      },
    });

    expect(result.map(({ id }) => id)).toEqual(customJwtScenarioIds);
    expect(result[15]?.projection).toMatchObject({
      customClaimMerged: true,
      environmentMerged: true,
      protectedClaimsPreserved: true,
      extensionClaimsOverridden: true,
    });
    expect(result.slice(16).map(({ projection }) => projection)).toEqual([
      {
        status: 200,
        customized: true,
        subjectMatches: true,
        resourceAudienceMatches: true,
        clientIdMatches: true,
        accountIdMatches: true,
        applicationIdMatches: true,
        applicationNameMatches: true,
        scopeEmpty: false,
        scopeMatchesFixture: true,
        grantType: 'authorization_code',
        kind: 'AccessToken',
      },
      {
        status: 200,
        userIdMatches: true,
        hasPassword: true,
        event: null,
        verificationType: 'Password',
        applicationIdMatches: true,
        applicationNameMatches: true,
        audienceMatches: true,
        scopeEmpty: false,
        scopeMatchesFixture: true,
        clientIdMatches: true,
        accountIdMatches: true,
        customSurvives: true,
        grantType: 'authorization_code refresh_token',
        kind: 'AccessToken',
      },
      {
        status: 200,
        error: null,
        issued: true,
        priorRefreshRotated: true,
      },
      { status: 400, error: 'access_denied', issued: false },
      { status: 400, error: 'invalid_request', issued: false },
      { status: 200, issued: true, sameRefreshRemainedUsable: true },
      {
        status: 200,
        initialAccessOpaque: true,
        invoked: true,
        userContextPresent: true,
        applicationContextPresent: true,
        userMatchesToken: true,
        applicationMatchesToken: true,
        protectedClaimsMatch: true,
        tokenKind: 'access_token',
        grantType: 'device_code refresh_token',
      },
    ]);
    expect(calls.slice(-2)).toEqual([
      'DELETE configs/jwt-customizer/client-credentials',
      'DELETE configs/jwt-customizer/access-token',
    ]);
    expect({ configured, userConfigured }).toEqual({
      configured: false,
      userConfigured: false,
    });
    deviceRelationshipsMatch = false;
    const mismatchedRelationships = await runCustomJwtScenarios(port, {
      expected: {
        issuer: 'issuer',
        subject: 'client',
        audience: 'resource',
        clientId: 'client',
        scope: 'read',
        userSubject: 'user',
        userClientId: 'user-client',
        userApplicationName: 'User Client',
        userAudience: 'resource',
        userScope: 'read:profile',
      },
    });
    expect(mismatchedRelationships.at(-1)?.projection).toMatchObject({
      userMatchesToken: false,
      applicationMatchesToken: false,
    });
    failDeviceRefresh = true;
    await expect(
      runCustomJwtScenarios(port, {
        expected: {
          issuer: 'issuer',
          subject: 'client',
          audience: 'resource',
          clientId: 'client',
          scope: 'read',
          userSubject: 'user',
          userClientId: 'user-client',
          userApplicationName: 'User Client',
          userAudience: 'resource',
          userScope: 'read:profile',
        },
      })
    ).rejects.toThrow('Phase 2 custom JWT scenario failed (primary:22)');
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/getCustomJwtClaims|custom-jwt-env-marker|signature/u);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it('cleans the customizer when target collection fails', async () => {
    const calls: string[] = [];
    const port: CustomJwtTargetPort = {
      verifyAccessToken: verifyJwt,
      request: async ({ method, path }) => {
        calls.push(`${method} ${path}`);
        if (method === 'DELETE') {
          return { status: 204, headers: {}, body: null };
        }
        throw new Error('target unavailable');
      },
      issueClientCredentials: async () => {
        throw new Error('unexpected issuance');
      },
      issueUserTokens: async () => {
        throw new Error('unexpected issuance');
      },
      exchangeUserRefresh: async () => {
        throw new Error('unexpected refresh');
      },
      observeDeviceResourceRefresh: async () => ({
        status: 200,
        initialAccessOpaque: true,
        invoked: true,
        userContextPresent: true,
        applicationContextPresent: true,
        userMatchesToken: true,
        applicationMatchesToken: true,
        protectedClaimsMatch: true,
        tokenKind: 'access_token',
        grantType: 'device_code refresh_token',
      }),
    };

    await expect(
      runCustomJwtScenarios(port, {
        expected: {
          issuer: 'issuer',
          subject: 'client',
          audience: 'resource',
          clientId: 'client',
          scope: 'read',
          userSubject: 'user',
          userClientId: 'user-client',
          userApplicationName: 'User Client',
          userAudience: 'resource',
          userScope: 'read:profile',
        },
      })
    ).rejects.toThrow('Phase 2 custom JWT scenario failed (primary:0)');
    expect(calls).toEqual([
      'GET configs/jwt-customizer/client-credentials',
      'DELETE configs/jwt-customizer/client-credentials',
      'DELETE configs/jwt-customizer/access-token',
    ]);
  });

  it('rejects wrong protected authority and fails closed on cleanup failure', async () => {
    let deleteCount = 0;
    let failCleanup = false;
    let jtiMismatch = false;
    let configured = false;
    let userConfigured = false;
    const issuedRefreshTokens = new Set<string>();
    let userMode: 'success' | 'deny' | 'block' | 'open' = 'success';
    const port: CustomJwtTargetPort = {
      verifyAccessToken: verifyJwt,
      request: async ({ method, path, body }) => {
        if (method === 'DELETE') {
          deleteCount += 1;
          if (failCleanup && deleteCount === 3) {
            throw new Error('secret cleanup diagnostic');
          }
          const access = path.endsWith('/access-token');
          const existed = access ? userConfigured : configured;
          if (access) {
            userConfigured = false;
          } else {
            configured = false;
          }
          return {
            status: existed ? 204 : 404,
            headers: {},
            body: existed ? null : { code: 'entity.not_found' },
          };
        }
        if (path.endsWith('/unknown-token-type')) {
          return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
        }
        if (path.endsWith('/test')) {
          if (
            typeof body !== 'object' ||
            body === null ||
            !('token' in body) ||
            !('context' in body)
          ) {
            return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
          }
          return { status: 200, headers: {}, body: { probe_claim: 'dry' } };
        }
        if (method === 'PATCH' && typeof (body as { script?: unknown }).script !== 'string') {
          return { status: 400, headers: {}, body: { code: 'guard.invalid_input' } };
        }
        if (path.endsWith('/jwt-customizer')) {
          return {
            status: 200,
            headers: {},
            body: [
              {
                key: 'jwt.clientCredentials',
                value: {
                  script: 'hidden',
                  blockIssuanceOnError: true,
                  environmentVariables: {},
                  contextSample: {},
                  tokenSample: {},
                },
              },
            ],
          };
        }
        if (method === 'GET' && !configured) {
          return { status: 404, headers: {}, body: { code: 'entity.not_exists_with_id' } };
        }
        if (method === 'PUT') {
          if (path.endsWith('/access-token')) {
            userConfigured = true;
          } else {
            configured = true;
          }
          if (path.endsWith('/access-token')) {
            const { script, blockIssuanceOnError } = body as {
              script: string;
              blockIssuanceOnError: boolean;
            };
            userMode = script.includes('denyAccess')
              ? 'deny'
              : script.includes('throw new Error')
                ? blockIssuanceOnError
                  ? 'block'
                  : 'open'
                : 'success';
          }
        }
        if (method === 'GET' && path.endsWith('/access-token') && !userConfigured) {
          return { status: 404, headers: {}, body: { code: 'entity.not_exists_with_id' } };
        }
        return {
          status: method === 'PUT' ? 201 : 200,
          headers: {},
          body: body ?? {
            script: 'hidden',
            blockIssuanceOnError: true,
            environmentVariables: {},
            contextSample: {},
            tokenSample: {},
          },
        };
      },
      issueClientCredentials: async ({ caseId }) => {
        if (caseId.endsWith('deny')) {
          return { status: 400, body: { error: 'access_denied' } };
        }
        if (caseId.endsWith('throw-block')) {
          return { status: 400, body: { error: 'invalid_request' } };
        }
        const issuedAt = Math.floor(Date.now() / 1000);
        return {
          status: 200,
          body: {
            expires_in: 3600,
            access_token: jwt({
              probe_claim: 'merged',
              probe_env: 'custom-jwt-env-marker',
              probe_app: 'client',
              iss: jtiMismatch ? 'issuer' : 'wrong',
              sub: 'client',
              aud: 'resource',
              exp: issuedAt + 3600,
              iat: issuedAt,
              jti: 'dynamic-id',
              probe_original_jti: jtiMismatch ? 'different-id' : 'dynamic-id',
              client_id: 'client',
              scope: 'read',
              organization_id: 'override',
              gty: 'override',
              kind: 'override',
            }),
          },
        };
      },
      issueUserTokens: async () => {
        const refresh = `refresh-token-${issuedRefreshTokens.size + 1}`;
        issuedRefreshTokens.add(refresh);
        return {
          access: userAccessJwt(),
          refresh,
          toJSON: () => {
            throw new Error('must stay private');
          },
        };
      },
      exchangeUserRefresh: async ({ refreshToken }) => {
        if (!issuedRefreshTokens.has(refreshToken)) {
          throw new Error('unknown refresh');
        }
        if (userMode === 'deny') {
          return { status: 400, body: { error: 'access_denied' } };
        }
        if (userMode === 'block') {
          return { status: 400, body: { error: 'invalid_request' } };
        }
        return {
          status: 200,
          body: {
            access_token: jwt({
              probe_user_id: 'user',
              probe_has_password: true,
              probe_event: null,
              probe_verification_type: 'Password',
              probe_application_id: 'user-client',
              probe_application_name: 'User Client',
              probe_token_aud: 'resource',
              probe_token_scope: 'read:profile',
              probe_token_client_id: 'user-client',
              probe_token_account_id: 'user',
              probe_token_gty: 'authorization_code refresh_token',
              probe_token_kind: 'AccessToken',
              probe_survives: 'yes',
            }),
            refresh_token: 'next-refresh-token',
          },
        };
      },
      observeDeviceResourceRefresh: async () => ({
        status: 200,
        initialAccessOpaque: true,
        invoked: true,
        userContextPresent: true,
        applicationContextPresent: true,
        userMatchesToken: true,
        applicationMatchesToken: true,
        protectedClaimsMatch: true,
        tokenKind: 'access_token',
        grantType: 'device_code refresh_token',
      }),
    };
    const expected = {
      issuer: 'issuer',
      subject: 'client',
      audience: 'resource',
      clientId: 'client',
      scope: 'read',
      userSubject: 'user',
      userClientId: 'user-client',
      userApplicationName: 'User Client',
      userAudience: 'resource',
      userScope: 'read:profile',
    };
    const result = await runCustomJwtScenarios(port, { expected });
    expect(result[15]?.projection.protectedClaimsPreserved).toBe(false);
    jtiMismatch = true;
    const wrongJti = await runCustomJwtScenarios(port, { expected });
    expect(wrongJti[15]?.projection.protectedClaimsPreserved).toBe(false);
    deleteCount = 0;
    failCleanup = true;
    await expect(runCustomJwtScenarios(port, { expected })).rejects.toThrow(
      'Phase 2 custom JWT scenario failed (cleanup)'
    );
  });
});

/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
