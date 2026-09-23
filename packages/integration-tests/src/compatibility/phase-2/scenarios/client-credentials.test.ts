/* eslint-disable complexity, max-lines, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument -- The twenty-case fake transport is a stateful negative-control harness and intentionally mutates captured request/response fixtures. */
import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from '../profile.js';
import {
  createClientCredentialsJwtAudit,
  createZeroClientCredentialsSideEffects,
} from '../projections/client-credentials.js';

import {
  assertDiscoveryAbsentFieldsContract,
  assertDiscoveryGrantContract,
  clientCredentialsScenarioIds,
  compareClientCredentialsProjections,
  createClientCredentialsScenarioRegistry,
  runClientCredentialsNegativeControls,
  waitForClientCredentialsFixtureReady,
  type Phase2ScenarioStateDriver,
} from './client-credentials.js';

const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});

const fixture: ProvisionedPhase2Fixture = Object.freeze({
  public: Object.freeze({
    allocationId: 'scenario-fixture',
    clients: Object.freeze({
      basic: Object.freeze({ id: 'phase2-m2m-basic', method: 'client_secret_basic' }),
      post: Object.freeze({ id: 'phase2-m2m-post', method: 'client_secret_post' }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({
        id: 'phase2-resource-primary',
        indicator: 'https://phase2.example.invalid/api-primary',
      }),
      default: Object.freeze({
        id: 'phase2-resource',
        indicator: 'https://phase2.example.invalid/api-default',
      }),
    }),
    organization: Object.freeze({ id: 'phase2-org', scopeName: 'organization:read' }),
    scopes: Object.freeze({
      read: Object.freeze({ id: 'read-scope', name: 'read' }),
      write: Object.freeze({ id: 'write-scope', name: 'write' }),
      unassigned: Object.freeze({ id: 'unassigned-scope', name: 'unassigned' }),
    }),
    boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
  }),
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use(
      Object.freeze({
        getClientSecret: (client: 'basic' | 'post') =>
          client === 'basic'
            ? 'CandidateBasicSecret000000000001'
            : 'CandidatePostSecret0000000000002',
        toJSON: (): never => {
          throw new Error('secret lease');
        },
      })
    ),
});

const profile: Phase2ProfileRegistries = Object.freeze({
  ...phase2ExpectedProfileAuthority,
  differentialScenarios: clientCredentialsScenarioIds,
  candidateInvariantScenarios: Object.freeze([
    'client-credentials.cross-tenant-authority-rejected',
    'client-credentials.request-role-write-rejected',
    'client-credentials.signing-failure-rolls-back',
    'client-credentials.user-authority-unchanged',
  ] as const),
  discovery: Object.freeze({
    grantTypesSupportedAppend: Object.freeze(['client_credentials'] as const),
    stillAbsent: Object.freeze([
      'introspection_endpoint',
      'revocation_endpoint',
      'device_authorization_endpoint',
      'registration_endpoint',
    ] as const),
  }),
});

const errorContracts = new Map<
  string,
  Readonly<{ status: number; error: string; description: string; challenge?: true }>
>([
  [
    'client-credentials.unknown-client-basic',
    {
      status: 400,
      error: 'invalid_client',
      description: 'invalid client phase2-unknown-client-basic',
    },
  ],
  [
    'client-credentials.unknown-client-post',
    {
      status: 400,
      error: 'invalid_client',
      description: 'invalid client phase2-unknown-client-post',
    },
  ],
  [
    'client-credentials.wrong-secret-basic',
    {
      status: 401,
      error: 'invalid_client',
      description: 'client authentication failed',
      challenge: true,
    },
  ],
  [
    'client-credentials.wrong-secret-post',
    { status: 401, error: 'invalid_client', description: 'client authentication failed' },
  ],
  [
    'client-credentials.mixed-authentication',
    {
      status: 400,
      error: 'invalid_request',
      description: 'client authentication must only be provided using one mechanism',
    },
  ],
  [
    'client-credentials.missing-target',
    {
      status: 400,
      error: 'invalid_target',
      description: 'both `resource` and `organization_id` are not provided',
    },
  ],
  [
    'client-credentials.unknown-resource',
    {
      status: 400,
      error: 'invalid_target',
      description: 'resource indicator is missing, or unknown',
    },
  ],
  [
    'client-credentials.unassociated-organization',
    {
      status: 403,
      error: 'access_denied',
      description: 'app has not associated with the organization',
    },
  ],
  [
    'client-credentials.duplicate-resource',
    {
      status: 400,
      error: 'invalid_target',
      description: 'only a single resource indicator value is supported for this grant type',
    },
  ],
]);

const errorCode = (error: string) => `oidc.${error}`;
const errorMessage = (error: string) => {
  if (error === 'invalid_request') {
    return 'Request is invalid.';
  }
  if (error === 'invalid_target') {
    return 'Invalid resource indicator.';
  }
  if (error === 'access_denied') {
    return 'Access denied.';
  }
  return 'An OIDC error occurred: oidc.invalid_client.';
};

describe('Phase 2 client credentials scenarios', () => {
  it('waits for the registered-client wrong-secret boundary before running scenarios', async () => {
    const calls: Array<readonly [URL | RequestInfo, RequestInit | undefined]> = [];
    const sleeps: number[] = [];
    const statuses = [503, 400, 401];
    const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      calls.push([input, init]);
      const status = statuses.shift() ?? 500;
      return new Response(null, {
        status,
        ...(status === 401
          ? { headers: { 'www-authenticate': 'Basic realm="https://candidate.example/oidc"' } }
          : {}),
      });
    }) as typeof fetch;

    await expect(
      waitForClientCredentialsFixtureReady(target, fixture.public, {
        attempts: 3,
        delayMilliseconds: 7,
        fetch: requestFetch,
        sleep: async (milliseconds) => {
          sleeps.push(milliseconds);
        },
        timeoutMilliseconds: 100,
      })
    ).resolves.toBeUndefined();
    expect(calls).toHaveLength(3);
    expect(sleeps).toEqual([7, 7]);
    const [input, init] = calls[0]!;
    expect(String(input)).toBe('https://candidate.example/oidc/token');
    expect(init?.method).toBe('POST');
    expect(init?.redirect).toBe('manual');
    const authorization = new Headers(init?.headers).get('authorization');
    expect(authorization?.startsWith('Basic ')).toBe(true);
    expect(
      Buffer.from(authorization?.slice('Basic '.length) ?? '', 'base64').toString('utf8')
    ).toBe(`${fixture.public.clients.basic.id}:${'W'.repeat(32)}`);
    expect(String(init?.body)).toBe(
      'grant_type=client_credentials&resource=https%3A%2F%2Fphase2.example.invalid%2Fapi-primary'
    );

    let exhaustedCalls = 0;
    await expect(
      waitForClientCredentialsFixtureReady(target, fixture.public, {
        delayMilliseconds: 0,
        fetch: (async () => {
          exhaustedCalls += 1;
          return new Response(null, { status: 400 });
        }) as typeof fetch,
        sleep: async () => {
          await Promise.resolve();
        },
        timeoutMilliseconds: 100,
      })
    ).rejects.toThrow('Invalid Phase 2 client credentials scenario');
    expect(exhaustedCalls).toBe(60);
  });

  it('has exact bytewise registry equality with the profile and rejects drift', () => {
    expect(createClientCredentialsScenarioRegistry(profile).map(({ id }) => id)).toEqual(
      profile.differentialScenarios
    );
    expect(() =>
      createClientCredentialsScenarioRegistry({
        ...profile,
        differentialScenarios: profile.differentialScenarios.slice(1),
      } as Phase2ProfileRegistries)
    ).toThrow('Invalid Phase 2 client credentials scenario');
  });

  it('executes all twenty contracts through the strict client and restores the default resource', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const jwk = await exportJWK(publicKey);
    const jwks: JSONWebKeySet = {
      keys: [{ ...jwk, alg: 'ES384', kid: 'scenario-signing-key', use: 'sig' }],
    };
    let activeId = '';
    let defaultEnabled = true;
    const requests: Array<Readonly<{ id: string; body: URLSearchParams; authorization?: string }>> =
      [];
    const state: Phase2ScenarioStateDriver = {
      observe: async (id, _fixture, execute) => {
        activeId = id;
        const response = await execute();
        const successful = response.jwt !== undefined;
        const responseError = response.body.error;
        const decision = (() => {
          if (successful) {
            return 'authorized' as const;
          }
          if (responseError === 'invalid_client') {
            return 'unauthorized-client' as const;
          }
          if (responseError === 'access_denied') {
            return 'access-denied' as const;
          }
          if (responseError === 'invalid_request') {
            return 'invalid-request' as const;
          }
          if (responseError === 'invalid_target') {
            return 'invalid-target' as const;
          }
          throw new TypeError('unexpected test response error');
        })();
        const organization = id.includes('organization');
        const resourceOrganization = id.endsWith('organization-resource-scope');
        const effectiveScopes = id.endsWith('resource-partial-scope')
          ? ['read']
          : id.endsWith('duplicate-scope-name') ||
              id.endsWith('malformed-scope-whitespace') ||
              resourceOrganization
            ? ['read', 'write']
            : id.endsWith('organization-scope')
              ? ['organization:read']
              : id.endsWith('organization-empty-scope')
                ? []
                : [];
        return {
          response,
          authority: {
            decision,
            targetKind: successful
              ? organization && !resourceOrganization
                ? 'organization'
                : 'resource'
              : 'none',
            target: successful
              ? organization && !resourceOrganization
                ? fixture.public.organization.id
                : id.endsWith('default-resource')
                  ? fixture.public.resources.default.indicator
                  : fixture.public.resources.primary.indicator
              : null,
            availableScopes: [...effectiveScopes].toSorted(),
            effectiveScopes: [...effectiveScopes].toSorted(),
          },
          signingUse: {
            generalKeyUse: successful ? 'verified' : 'unchanged',
            oidcIdTokenKeyUse: 'unchanged',
          },
          sideEffects: createZeroClientCredentialsSideEffects(),
        };
      },
      setDefaultResource: async (_fixture, enabled) => {
        defaultEnabled = enabled;
      },
    };
    const jwtAudit = createClientCredentialsJwtAudit();
    const requestFetch: typeof fetch = async (_input, init = {}) => {
      const body = new URLSearchParams(String(init.body ?? ''));
      const headers = new Headers(init.headers);
      requests.push({
        id: activeId,
        body,
        authorization: headers.get('authorization') ?? undefined,
      });
      const error = errorContracts.get(activeId);
      const responseHeaders: Record<string, string> = {
        'access-control-allow-origin': '*',
        'access-control-expose-headers': 'WWW-Authenticate',
        'aster-core-request-id': '0123456789abcdef',
        'cache-control': 'no-store',
        'content-type': 'application/json; charset=utf-8',
        'cross-origin-resource-policy': 'same-origin',
        'origin-agent-cluster': '?1',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'strict-transport-security': 'max-age=15552000; includeSubDomains',
        vary: 'Accept-Encoding, Origin',
        'x-content-type-options': 'nosniff',
        'x-download-options': 'noopen',
        'x-frame-options': 'SAMEORIGIN',
        'x-permitted-cross-domain-policies': 'none',
        'x-xss-protection': '0',
      };
      let bodyValue: Record<string, unknown>;
      let status: number;
      if (error) {
        status = error.status;
        bodyValue = {
          code: errorCode(error.error),
          message: errorMessage(error.error),
          error: error.error,
          error_description: error.description,
        };
        if (error.challenge) {
          responseHeaders['www-authenticate'] =
            'Basic realm="https://candidate.example/oidc", error="invalid_client", error_description="client authentication failed"';
        }
      } else {
        status = 200;
        const clientId = activeId.endsWith('post-explicit-resource')
          ? fixture.public.clients.post.id
          : fixture.public.clients.basic.id;
        const isDefault = activeId.endsWith('default-resource');
        const isOrganization =
          activeId.endsWith('organization-empty-scope') || activeId.endsWith('organization-scope');
        const isOrganizationResource = activeId.endsWith('organization-resource-scope');
        const scope = activeId.endsWith('resource-partial-scope')
          ? 'read'
          : activeId.endsWith('duplicate-scope-name') ||
              activeId.endsWith('malformed-scope-whitespace') ||
              isOrganizationResource
            ? 'read write'
            : activeId.endsWith('organization-scope')
              ? 'organization:read'
              : activeId.endsWith('organization-empty-scope')
                ? ''
                : undefined;
        const audience = isDefault
          ? fixture.public.resources.default.indicator
          : isOrganization
            ? `urn:aster:organization:${fixture.public.organization.id}`
            : fixture.public.resources.primary.indicator;
        const issuedAt = Math.floor(Date.now() / 1000);
        const claims: Record<string, unknown> = {
          aud: audience,
          client_id: clientId,
          exp: issuedAt + 3600,
          iat: issuedAt,
          iss: 'https://candidate.example/oidc',
          jti: `jti-${activeId.replaceAll('.', '-')}`,
          sub: clientId,
          ...(scope === undefined ? {} : { scope }),
          ...(isOrganizationResource ? { organization_id: fixture.public.organization.id } : {}),
        };
        const token = await new SignJWT(claims)
          .setProtectedHeader({ alg: 'ES384', kid: 'scenario-signing-key', typ: 'at+jwt' })
          .sign(privateKey);
        bodyValue = {
          access_token: token,
          expires_in: 3600,
          token_type: 'Bearer',
          ...(scope === undefined ? {} : { scope }),
        };
      }
      const serialized = JSON.stringify(bodyValue);
      responseHeaders['content-length'] = String(Buffer.byteLength(serialized));
      return new Response(serialized, { status, headers: responseHeaders });
    };

    const results = [];
    for (const scenario of createClientCredentialsScenarioRegistry(profile)) {
      try {
        results.push(
          await scenario.run({ target, fixture, jwks, state, jwtAudit, fetch: requestFetch })
        );
      } catch (error: unknown) {
        throw new Error(`scenario failed: ${scenario.id}`, { cause: error });
      }
    }
    expect(results.map(({ id }) => id)).toEqual(clientCredentialsScenarioIds);
    expect(
      Object.fromEntries(
        results
          .filter(({ projection }) => projection.jwt === null)
          .map(({ id, projection }) => [id, projection.authority.decision])
      )
    ).toMatchObject({
      'client-credentials.unknown-client-basic': 'unauthorized-client',
      'client-credentials.unknown-client-post': 'unauthorized-client',
      'client-credentials.wrong-secret-basic': 'unauthorized-client',
      'client-credentials.wrong-secret-post': 'unauthorized-client',
      'client-credentials.mixed-authentication': 'invalid-request',
      'client-credentials.duplicate-resource': 'invalid-target',
    });
    expect(requests).toHaveLength(20);
    expect(
      requests.find(({ id }) => id.endsWith('mixed-authentication'))?.body.get('client_secret')
    ).toBe('CandidatePostSecret0000000000002');
    expect(
      requests.find(({ id }) => id.endsWith('duplicate-resource'))?.body.getAll('resource')
    ).toEqual([
      fixture.public.resources.primary.indicator,
      fixture.public.resources.default.indicator,
    ]);
    expect(
      requests
        .find(({ id }) => id.endsWith('unsupported-parameter'))
        ?.body.get('unsupported_parameter')
    ).toBe('rejected');
    expect(defaultEnabled).toBe(true);
  });

  it('routes a hanging token request through state abort and restores the default resource', async () => {
    const events: string[] = [];
    const state: Phase2ScenarioStateDriver = {
      observe: async (_id, _fixture, execute) => {
        try {
          await execute();
        } catch (error: unknown) {
          events.push('abort');
          throw error;
        }
        throw new Error('unexpected success');
      },
      setDefaultResource: async (_fixture, enabled) => {
        events.push(enabled ? 'default:on' : 'default:off');
      },
    };
    const scenario = createClientCredentialsScenarioRegistry(profile).find(
      ({ id }) => id === 'client-credentials.missing-target'
    );
    if (!scenario) {
      throw new Error('missing scenario');
    }
    await expect(
      scenario.run({
        target,
        fixture,
        jwks: { keys: [{ kty: 'EC', kid: 'hanging-key' }] },
        state,
        jwtAudit: createClientCredentialsJwtAudit(),
        fetch: (async () =>
          new Promise<Response>(() => {
            // Intentionally unresolved to prove state abort and default restoration.
          })) as typeof fetch,
        requestTimeoutMs: 20,
      })
    ).rejects.toThrow('Client credentials request failed');
    expect(events).toEqual(['default:off', 'abort', 'default:on']);
  });

  it('detects every required field-specific control and only normalizes pinned transport headers', () => {
    const success: any = {
      http: {
        status: 200,
        headers: {},
        body: { expires_in: 3600, scope: 'read', token_type: 'Bearer' },
      },
      jwt: {
        header: { typ: 'at+jwt', alg: 'ES384', kid: '<verified-es384-key>' },
        claims: {
          iss: '<target-issuer>',
          aud: '<resource.primary>',
          sub: '<client.basic>',
          client_id: '<client.basic>',
          scope: 'read',
          organization_id: '<organization.primary>',
          iat: '<issued-at>',
          exp: { afterIssuedAtSeconds: 3600 },
          jti: '<unique-jti>',
        },
        signature: { verified: true, algorithm: 'ES384' },
      },
      authority: {
        decision: 'authorized',
        targetKind: 'resource',
        target: '<resource.primary>',
        availableScopes: ['read'],
        effectiveScopes: ['read'],
      },
      signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
      sideEffects: createZeroClientCredentialsSideEffects(),
    };
    const authenticationError: any = {
      ...success,
      http: {
        status: 401,
        headers: { 'www-authenticate': 'Basic realm="<target-issuer>"' },
        body: {
          code: 'oidc.invalid_client',
          message: 'error',
          error: 'invalid_client',
          error_description: 'client authentication failed',
        },
      },
      jwt: null,
      signingUse: { generalKeyUse: 'unchanged', oidcIdTokenKeyUse: 'unchanged' },
    };
    const controls = runClientCredentialsNegativeControls({
      success,
      authenticationError,
      discoveryGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    });
    expect(controls).toHaveLength(12);
    expect(controls.map(({ name }) => name)).toEqual([
      'status',
      'challenge',
      'error',
      'audience',
      'scope',
      'client-id',
      'organization-id',
      'typ',
      'alg',
      'kid',
      'discovery-grant-order',
      'unexpected-field',
    ]);
    expect(compareClientCredentialsProjections(success, structuredClone(success))).toEqual([]);
    const oracleTransport = structuredClone(success);
    oracleTransport.http.headers = {
      connection: 'keep-alive',
      'keep-alive': 'timeout=5',
    };
    expect(compareClientCredentialsProjections(oracleTransport, structuredClone(success))).toEqual(
      []
    );
    const changedKeepAlive = structuredClone(oracleTransport);
    changedKeepAlive.http.headers['keep-alive'] = 'timeout=6';
    expect(
      compareClientCredentialsProjections(changedKeepAlive, structuredClone(success))
    ).toContainEqual({
      path: '/http/headers/keep-alive',
      expected: 'timeout=6',
      actual: undefined,
    });
    const candidateTransport = structuredClone(success);
    candidateTransport.http.headers = {
      connection: 'keep-alive',
      'keep-alive': 'timeout=5',
    };
    expect(compareClientCredentialsProjections(oracleTransport, candidateTransport)).toEqual([
      { path: '/http/headers/connection', expected: undefined, actual: 'keep-alive' },
      { path: '/http/headers/keep-alive', expected: undefined, actual: 'timeout=5' },
    ]);
  });

  it('projects the selected Oracle grant order and keeps Candidate discovery exact', () => {
    expect(
      assertDiscoveryGrantContract(
        [
          'implicit',
          'authorization_code',
          'refresh_token',
          'client_credentials',
          'urn:ietf:params:oauth:grant-type:device_code',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        ['client_credentials'],
        'oracle'
      )
    ).toEqual(['authorization_code', 'refresh_token', 'client_credentials']);
    expect(
      assertDiscoveryGrantContract(
        ['authorization_code', 'refresh_token', 'client_credentials'],
        ['client_credentials'],
        'candidate'
      )
    ).toEqual(['authorization_code', 'refresh_token', 'client_credentials']);
    expect(() =>
      assertDiscoveryGrantContract(
        ['client_credentials', 'authorization_code', 'refresh_token'],
        ['client_credentials'],
        'oracle'
      )
    ).toThrow('Invalid Phase 2 client credentials scenario');
    expect(() =>
      assertDiscoveryGrantContract(
        ['authorization_code', 'refresh_token', 'client_credentials', 'device_code'],
        ['client_credentials'],
        'candidate'
      )
    ).toThrow('Invalid Phase 2 client credentials scenario');
    expect(() =>
      assertDiscoveryGrantContract(
        ['authorization_code', 'refresh_token', 'client_credentials', 'client_credentials'],
        ['client_credentials'],
        'oracle'
      )
    ).toThrow('Invalid Phase 2 client credentials scenario');
  });

  it('normalizes Oracle-only discovery fields and rejects them on Candidate', () => {
    const expectedAbsent = ['introspection_endpoint', 'revocation_endpoint'] as const;
    expect(
      assertDiscoveryAbsentFieldsContract(
        {
          introspection_endpoint: 'https://oracle.example/oidc/token/introspection',
          revocation_endpoint: 'https://oracle.example/oidc/token/revocation',
        },
        expectedAbsent,
        'oracle'
      )
    ).toEqual(expectedAbsent);
    expect(assertDiscoveryAbsentFieldsContract({}, expectedAbsent, 'candidate')).toEqual(
      expectedAbsent
    );
    expect(() =>
      assertDiscoveryAbsentFieldsContract(
        { introspection_endpoint: 'https://candidate.example/oidc/token/introspection' },
        expectedAbsent,
        'candidate'
      )
    ).toThrow('Invalid Phase 2 client credentials scenario');
  });

  it('rejects credential-bearing response headers instead of normalizing them away', async () => {
    const scenario = createClientCredentialsScenarioRegistry(profile)[0];
    expect(scenario).toBeDefined();
    const state: Phase2ScenarioStateDriver = {
      observe: async (_id, _fixture, execute) => ({
        response: await execute(),
        authority: {
          decision: 'authorized',
          targetKind: 'resource',
          target: fixture.public.resources.primary.indicator,
          availableScopes: [],
          effectiveScopes: [],
        },
        signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
        sideEffects: createZeroClientCredentialsSideEffects(),
      }),
      setDefaultResource: async () => {
        // This request does not mutate the default-resource fixture.
      },
    };
    await expect(
      scenario?.run({
        target,
        fixture,
        jwks: { keys: [{ kty: 'EC', kid: 'key' }] },
        state,
        jwtAudit: createClientCredentialsJwtAudit(),
        fetch: async () =>
          new Response('{}', {
            status: 200,
            headers: { 'set-cookie': 'private=value' },
          }),
      })
    ).rejects.toThrow('Client credentials request failed');
  });
});

/* eslint-enable complexity, max-lines, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument */
