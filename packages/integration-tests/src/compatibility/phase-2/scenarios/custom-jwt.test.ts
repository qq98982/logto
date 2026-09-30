/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The stateful fake target proves ordering, lifecycle changes, cleanup, and evidence redaction through one bounded in-memory contract. */

import {
  customJwtScenarioIds,
  runCustomJwtScenarios,
  type CustomJwtTargetPort,
} from './custom-jwt.js';

const jwt = (payload: Record<string, unknown>) =>
  ['header', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'signature'].join('.');
const verifyJwt = async (token: string) =>
  JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;

describe('Phase 2 custom JWT scenarios', () => {
  it('collects the fixed management and M2M contract without credential or script material', async () => {
    let configured = false;
    const calls: string[] = [];
    const port: CustomJwtTargetPort = {
      verifyAccessToken: verifyJwt,
      request: async ({ method, path, body }): ReturnType<CustomJwtTargetPort['request']> => {
        calls.push(`${method} ${path}`);
        if (method === 'DELETE') {
          const existed = configured;
          configured = false;
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
    };

    const result = await runCustomJwtScenarios(port, {
      expected: {
        issuer: 'issuer',
        subject: 'client',
        audience: 'resource',
        clientId: 'client',
        scope: 'read',
      },
    });

    expect(result.map(({ id }) => id)).toEqual(customJwtScenarioIds);
    expect(result.at(-1)?.projection).toMatchObject({
      customClaimMerged: true,
      environmentMerged: true,
      protectedClaimsPreserved: true,
      extensionClaimsOverridden: true,
    });
    expect(calls.at(-1)).toBe('DELETE configs/jwt-customizer/client-credentials');
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(
      /access_token|getCustomJwtClaims|custom-jwt-env-marker|signature/u
    );
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
    };

    await expect(
      runCustomJwtScenarios(port, {
        expected: {
          issuer: 'issuer',
          subject: 'client',
          audience: 'resource',
          clientId: 'client',
          scope: 'read',
        },
      })
    ).rejects.toThrow('Phase 2 custom JWT scenario failed (primary)');
    expect(calls).toEqual([
      'GET configs/jwt-customizer/client-credentials',
      'DELETE configs/jwt-customizer/client-credentials',
    ]);
  });

  it('rejects wrong protected authority and fails closed on cleanup failure', async () => {
    let deleteCount = 0;
    let failCleanup = false;
    let jtiMismatch = false;
    let configured = false;
    const port: CustomJwtTargetPort = {
      verifyAccessToken: verifyJwt,
      request: async ({ method, path, body }) => {
        if (method === 'DELETE') {
          deleteCount += 1;
          if (failCleanup && deleteCount > 2) {
            throw new Error('secret cleanup diagnostic');
          }
          const existed = configured;
          configured = false;
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
          configured = true;
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
    };
    const expected = {
      issuer: 'issuer',
      subject: 'client',
      audience: 'resource',
      clientId: 'client',
      scope: 'read',
    };
    const result = await runCustomJwtScenarios(port, { expected });
    expect(result.at(-1)?.projection.protectedClaimsPreserved).toBe(false);
    jtiMismatch = true;
    const wrongJti = await runCustomJwtScenarios(port, { expected });
    expect(wrongJti.at(-1)?.projection.protectedClaimsPreserved).toBe(false);
    deleteCount = 0;
    failCleanup = true;
    await expect(runCustomJwtScenarios(port, { expected })).rejects.toThrow(
      'Phase 2 custom JWT scenario failed (cleanup)'
    );
  });
});

/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
