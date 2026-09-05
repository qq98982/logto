/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/prefer-regexp-exec, unicorn/consistent-function-scoping -- The focused fullPhase1 harness records six protected-surface requests and supplies narrow admin-session/state ports. */
import { SymbolTable } from '../../symbol-table.js';
import {
  MemoryProtocolSecretStore,
  protocolHeaderPairs,
  type ProtocolRequestOptions,
} from '../clients/oidc.js';
import { assertPhase1RuntimeCredentialGraphIsSanitized } from '../fixtures.js';
import type { Phase1ScenarioRunContext } from '../model.js';
import { validateExactPhase1ScenarioSteps } from '../scenario-runtime.js';

import { phase1DifferentialScenarios } from './index.js';
import type { PositiveAdminSession } from './positive-admin-flow.js';
import {
  runTokenIssuerAudienceScopeRejected,
  type TokenIssuerAudienceScopeRejectedDependencies,
} from './token-issuer-audience-scope-rejected.js';

const target = {
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
};
const makeToken = (claims: Readonly<Record<string, unknown>>, signature: string) =>
  `${Buffer.from(JSON.stringify({ alg: 'ES384' })).toString('base64url')}.${Buffer.from(
    JSON.stringify(claims)
  ).toString('base64url')}.${signature}`;
const managementClaims = {
  iss: 'https://oracle-admin.example/oidc',
  sub: 'runtime-admin',
  aud: 'https://default.logto.app/api',
  client_id: 'admin-console',
};
const missingScopeToken = makeToken({ ...managementClaims, scope: '' }, 'scope-signature');
const accountResourceToken = makeToken(
  {
    ...managementClaims,
    aud: 'https://admin.logto.app/me',
    scope: 'all',
  },
  'account-signature'
);
const dataResourceToken = makeToken(
  {
    ...managementClaims,
    iss: 'https://oracle.example/oidc',
    aud: 'https://api.example.com',
    scope: 'read:profile',
  },
  'data-signature'
);
const dataUserInfoToken = 'opaque-data-openid-token';
const userInfoMissingScopeToken = 'opaque-userinfo-profile-only-token';
const jwtClaims = (token: string): Readonly<Record<string, unknown>> =>
  JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Readonly<
    Record<string, unknown>
  >;
const stableState = {
  body: { observed: true },
  semanticState: { authority: 'rejected' },
  persistedState: { unrelatedMutation: false },
  generatedIds: {},
  sideEffects: { unrelatedMutation: false },
};

type RecordedRequest = Readonly<{
  operation: string;
  path: string;
  options?: ProtocolRequestOptions;
  token: string;
}>;

const encodeAll = (value: string) =>
  Buffer.from(value, 'utf8')
    .toString('hex')
    .match(/.{2}/gu)
    ?.map((byte) => `%${byte}`)
    .join('') ?? '';

const createHarness = (
  options: Readonly<{
    mutateState?: boolean;
    mutateFixture?: boolean;
    leakVariant?: 'wrong-issuer' | 'wrong-audience' | 'missing-scope';
    omitJoseData?: 'wrong-issuer' | 'wrong-audience';
    mismatchJosePayload?: boolean;
    signatureOnly?: boolean;
    ignoredAuthority?: 'audience' | 'scope';
    wrongUserinfoRealm?: boolean;
    issuerPath?: string;
  }> = {}
) => {
  const adminStore = new MemoryProtocolSecretStore();
  const dataStore = new MemoryProtocolSecretStore();
  const requests: RecordedRequest[] = [];
  const responseFor = (operation: string, authorization: string) => {
    const variant = operation.match(/authority-(wrong-issuer|wrong-audience|missing-scope)-/u)?.[1];
    const surface = operation.endsWith('-management') ? 'management' : 'userinfo';
    const token = authorization.slice(7);
    const defaultStatus = variant === 'wrong-issuer' || variant === 'wrong-audience' ? 401 : 403;
    const status = (() => {
      if (options.signatureOnly) {
        return 200;
      }
      if (options.ignoredAuthority === 'audience' && variant === 'wrong-audience') {
        return 403;
      }
      if (options.ignoredAuthority === 'scope') {
        if (variant === 'missing-scope') {
          return 200;
        }
        if (variant === 'wrong-audience' && surface === 'userinfo') {
          return 401;
        }
      }

      return defaultStatus;
    })();
    const managementJoseData =
      surface !== 'management' || status !== 401 || variant === options.omitJoseData
        ? undefined
        : variant === 'wrong-issuer'
          ? {
              code: 'ERR_JWKS_NO_MATCHING_KEY',
              name: 'JWKSNoMatchingKey',
            }
          : variant === 'wrong-audience'
            ? {
                code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
                name: 'JWTClaimValidationFailed',
                claim: 'aud',
                reason: 'check_failed',
                payload: options.mismatchJosePayload
                  ? { ...jwtClaims(token), sub: 'mismatched-caller' }
                  : jwtClaims(token),
              }
            : undefined;
    const body =
      status === 200
        ? surface === 'management'
          ? [{ id: 'disclosed-tenant-data' }]
          : { sub: 'disclosed-user' }
        : surface === 'management'
          ? status === 403
            ? {
                code: 'auth.forbidden',
                message: 'Forbidden. Please check your user roles and permissions.',
              }
            : {
                code: 'auth.unauthorized',
                ...(managementJoseData ? { data: managementJoseData } : {}),
                message: 'Unauthorized. Please check credentials and its scope.',
              }
          : status === 403
            ? {
                code: 'oidc.insufficient_scope',
                message: 'Token missing scope `{{scope}}`.',
                error: 'insufficient_scope',
                error_description: 'access token missing openid scope',
                scope: 'openid',
              }
            : {
                code: 'oidc.invalid_token',
                message: 'Invalid token provided.',
                error: 'invalid_token',
                error_description: 'invalid token provided',
              };
    const leaked = variant === options.leakVariant ? encodeAll(token) : undefined;
    const userinfoRealm = options.wrongUserinfoRealm
      ? 'https://logical-admin.example/oidc'
      : `${target.adminUrl}oidc`;

    return {
      status,
      headers: [
        ['content-type', 'application/json; charset=utf-8'],
        ['cache-control', 'no-store'],
        ...(surface === 'userinfo'
          ? ([
              [
                'www-authenticate',
                status === 403
                  ? `Bearer realm="${userinfoRealm}", error="insufficient_scope", error_description="access token missing openid scope", scope="openid"`
                  : `Bearer realm="${userinfoRealm}", error="invalid_token", error_description="invalid token provided"`,
              ],
            ] as const)
          : []),
        ...(leaked ? ([['x-credential-leak', leaked]] as const) : []),
      ] as const,
      body: JSON.stringify(body),
    };
  };
  const request = async (
    operation: string,
    path: string,
    requestOptions?: ProtocolRequestOptions
  ) => {
    const authorization = protocolHeaderPairs(requestOptions?.headers).find(
      ([name]) => name.toLowerCase() === 'authorization'
    )?.[1];

    if (!authorization?.startsWith('Bearer ')) {
      throw new Error('missing bearer');
    }
    requests.push({ operation, path, options: requestOptions, token: authorization.slice(7) });

    return responseFor(operation, authorization);
  };
  const oidc = (store: MemoryProtocolSecretStore) => ({
    store,
    request: import.meta.jest.fn(request),
  });
  const adminOidc = oidc(adminStore);
  const dataOidc = oidc(dataStore);
  const adminSymbols = new SymbolTable();
  adminSymbols.bind('user.phase1-admin', 'runtime-admin');
  const fixtureState = { schemaVersion: 1, recipe: 'fullPhase1', allocations: [] };
  let fixtureReads = 0;
  const context = {
    profile: {
      fixtures: {
        adminTenant: {
          operator: {
            id: 'phase1-admin',
            username: 'phase1-admin',
            primaryEmail: 'phase1-admin@example.com',
          },
        },
      },
      oidc: { issuerPath: options.issuerPath ?? '/oidc', userinfoPath: '/oidc/me' },
      consoleAuthentication: { issuer: 'https://logical-admin.example/oidc' },
    },
    target,
    fixture: {
      public: {
        schemaVersion: 1,
        recipe: 'fullPhase1',
        allocations: [
          {
            allocationId: 'admin-allocation',
            role: 'admin',
            target: 'primary',
            isolation: {
              persistenceId: 'admin-persistence',
              cookieKeyId: 'admin-cookie',
              signingKeyId: 'admin-signing',
            },
            entities: [{ kind: 'user', logicalId: 'phase1-admin', runtimeId: 'runtime-admin' }],
          },
          {
            allocationId: 'data-allocation',
            role: 'data',
            target: 'primary',
            isolation: {
              persistenceId: 'data-persistence',
              cookieKeyId: 'data-cookie',
              signingKeyId: 'data-signing',
            },
            entities: [],
          },
        ],
      },
    },
    signal: new AbortController().signal,
    protocol: {
      publicOidc: {} as never,
      publicSymbols: new SymbolTable(),
      forAllocation: (role: string) => {
        const selected = role === 'admin' ? adminOidc : dataOidc;

        return {
          oidc: selected,
          experience: { store: selected.store },
          consent: { store: selected.store },
          management: { store: selected.store },
          account: { store: selected.store },
          state: { store: selected.store },
        } as never;
      },
      symbolsFor: (allocationId: string) =>
        allocationId === 'admin-allocation' ? adminSymbols : new SymbolTable(),
    },
    projectFixtureState: async () => {
      fixtureReads += 1;

      return options.mutateFixture && fixtureReads > 1
        ? { ...fixtureState, mutated: true }
        : fixtureState;
    },
    projectScenarioState: async () =>
      options.mutateState
        ? { ...stableState, persistedState: { unrelatedMutation: true } }
        : stableState,
  } as unknown as Phase1ScenarioRunContext;
  const withPositiveAdminSession: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['withPositiveAdminSession']
  > = async (_context, _options, consume) => ({
    steps: [],
    result: await consume({} as PositiveAdminSession),
  });
  const refreshPositiveAdminAccountResourceToken: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['refreshPositiveAdminAccountResourceToken']
  > = async () => {
    adminStore.setToken('authority-wrong-audience', accountResourceToken);
  };
  const refreshPositiveAdminManagementTokenWithoutAllScope: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['refreshPositiveAdminManagementTokenWithoutAllScope']
  > = async () => {
    dataStore.setToken('management-missing-scope', missingScopeToken);
  };
  const refreshPositiveAdminUserInfoTokenWithoutOpenId: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['refreshPositiveAdminUserInfoTokenWithoutOpenId']
  > = async () => {
    adminStore.setToken('userinfo-missing-openid', userInfoMissingScopeToken);
  };
  const resourceAuthorizationGrant = Object.freeze({ source: 'resource-authorization' }) as never;
  const userInfoAuthorizationGrant = Object.freeze({ source: 'userinfo-authorization' }) as never;
  const oidcFlowOptions: Array<
    Readonly<{
      captureSteps?: boolean;
      includeResource?: boolean;
      expectOidcConsentAlreadyGranted?: boolean;
    }>
  > = [];
  const withPositiveOidcFlow: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['withPositiveOidcFlow']
  > = async (_context, flowOptions, consume) => {
    oidcFlowOptions.push(flowOptions);

    return {
      steps: [],
      result: await consume(
        flowOptions.includeResource === false
          ? userInfoAuthorizationGrant
          : resourceAuthorizationGrant
      ),
    };
  };
  const dataGrant = Object.freeze({ source: 'data-authorization-code' }) as never;
  const dataUserInfoGrant = Object.freeze({ source: 'data-userinfo-authorization-code' }) as never;
  const exchangePositiveAuthorizationCode: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['exchangePositiveAuthorizationCode']
  > = import.meta.jest.fn(async (_context, authorizationGrant) =>
    authorizationGrant === resourceAuthorizationGrant ? dataGrant : dataUserInfoGrant
  );
  const installPositiveOidcAccessToken: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['installPositiveOidcAccessToken']
  > = import.meta.jest.fn((_context, grant, name) => {
    dataStore.setToken(name, grant === dataGrant ? dataResourceToken : dataUserInfoToken);
  });
  const verifyPositiveTokenGrant: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['verifyPositiveTokenGrant']
  > = import.meta.jest.fn(async () => []);
  const assertPositiveOidcTokenGrantIncludesScope: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['assertPositiveOidcTokenGrantIncludesScope']
  > = import.meta.jest.fn();
  const revokedGrants: unknown[] = [];
  const revokePositiveTokenGrant: NonNullable<
    TokenIssuerAudienceScopeRejectedDependencies['revokePositiveTokenGrant']
  > = (grant) => {
    revokedGrants.push(grant);
  };

  return {
    context,
    dataGrant,
    dataUserInfoGrant,
    installPositiveOidcAccessToken,
    oidcFlowOptions,
    requests,
    revokePositiveTokenGrant,
    revokedGrants,
    verifyPositiveTokenGrant,
    assertPositiveOidcTokenGrantIncludesScope,
    dependencies: {
      withPositiveAdminSession,
      refreshPositiveAdminAccountResourceToken,
      refreshPositiveAdminManagementTokenWithoutAllScope,
      refreshPositiveAdminUserInfoTokenWithoutOpenId,
      withPositiveOidcFlow,
      exchangePositiveAuthorizationCode,
      installPositiveOidcAccessToken,
      verifyPositiveTokenGrant,
      assertPositiveOidcTokenGrantIncludesScope,
      revokePositiveTokenGrant,
    },
  };
};

describe('token.issuer-audience-scope-rejected', () => {
  it('rejects wrong issuer audience and scope without exposing credentials or target-tenant data', async () => {
    const harness = createHarness();
    const steps = await runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies);
    const contract = phase1DifferentialScenarios.find(
      ({ id }) => id === 'token.issuer-audience-scope-rejected'
    );

    if (!contract) {
      throw new Error('missing authority rejection scenario contract');
    }

    expect(validateExactPhase1ScenarioSteps(contract, steps).map(({ stepId }) => stepId)).toEqual([
      'wrong-issuer',
      'wrong-audience',
      'missing-scope',
      'state',
    ]);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'authority-wrong-issuer-management',
      'authority-wrong-issuer-userinfo',
      'authority-wrong-audience-management',
      'authority-wrong-audience-userinfo',
      'authority-missing-scope-management',
      'authority-missing-scope-userinfo',
    ]);
    expect(new Set(harness.requests.map(({ token }) => token))).toHaveProperty('size', 5);
    const wrongIssuerRequests = harness.requests.filter(({ operation }) =>
      operation.startsWith('authority-wrong-issuer-')
    );
    expect(wrongIssuerRequests.map(({ token }) => token)).toEqual([
      dataResourceToken,
      dataUserInfoToken,
    ]);
    expect(jwtClaims(dataResourceToken)).toMatchObject({
      iss: `${target.coreUrl}oidc`,
      aud: 'https://api.example.com',
      scope: 'read:profile',
    });
    expect(dataUserInfoToken).not.toContain('.');
    const wrongAudienceRequests = harness.requests.filter(({ operation }) =>
      operation.startsWith('authority-wrong-audience-')
    );
    expect(wrongAudienceRequests.map(({ token }) => token)).toEqual([
      accountResourceToken,
      accountResourceToken,
    ]);
    expect(jwtClaims(accountResourceToken)).toMatchObject({
      iss: `${target.adminUrl}oidc`,
      aud: 'https://admin.logto.app/me',
      scope: 'all',
    });
    const missingScopeRequests = harness.requests.filter(({ operation }) =>
      operation.startsWith('authority-missing-scope-')
    );
    expect(missingScopeRequests).toHaveLength(2);
    expect(missingScopeRequests[0]?.token).toBe(missingScopeToken);
    expect(missingScopeRequests[1]?.token).toBe(userInfoMissingScopeToken);
    expect(missingScopeRequests[1]?.token).not.toContain('.');
    expect(harness.requests.every(({ options }) => options?.includeCookies === false)).toBe(true);
    expect(harness.oidcFlowOptions).toEqual([
      {
        captureSteps: false,
        includeResource: true,
        expectOidcConsentAlreadyGranted: false,
      },
      {
        captureSteps: false,
        includeResource: false,
        expectOidcConsentAlreadyGranted: true,
      },
    ]);
    expect(harness.verifyPositiveTokenGrant).toHaveBeenCalledTimes(2);
    expect(harness.verifyPositiveTokenGrant).toHaveBeenNthCalledWith(
      1,
      harness.context,
      harness.dataGrant,
      true
    );
    expect(harness.verifyPositiveTokenGrant).toHaveBeenNthCalledWith(
      2,
      harness.context,
      harness.dataUserInfoGrant,
      false
    );
    expect(harness.assertPositiveOidcTokenGrantIncludesScope).toHaveBeenCalledTimes(1);
    expect(harness.assertPositiveOidcTokenGrantIncludesScope).toHaveBeenCalledWith(
      harness.dataUserInfoGrant,
      'openid'
    );
    expect(harness.installPositiveOidcAccessToken).toHaveBeenCalledTimes(2);
    expect(harness.installPositiveOidcAccessToken).toHaveBeenNthCalledWith(
      1,
      harness.context,
      harness.dataGrant,
      'authority-wrong-issuer-management'
    );
    expect(harness.installPositiveOidcAccessToken).toHaveBeenNthCalledWith(
      2,
      harness.context,
      harness.dataUserInfoGrant,
      'authority-wrong-issuer-userinfo'
    );
    expect(harness.revokedGrants).toEqual([harness.dataUserInfoGrant, harness.dataGrant]);
    expect(steps[0]?.value.body).toMatchObject({
      authorityVector: {
        management: 'foreign-signing-authority-before-issuer-audience-scope',
        userinfo: 'foreign-tenant-token-lookup',
      },
      management: {
        status: 401,
        body: {
          errorCode: 'auth.unauthorized',
          data: {
            errorCode: 'ERR_JWKS_NO_MATCHING_KEY',
            name: 'JWKSNoMatchingKey',
          },
          message: 'Unauthorized. Please check credentials and its scope.',
        },
        cookies: [],
        redirect: null,
      },
      userinfo: {
        status: 401,
        body: {
          errorCode: 'oidc.invalid_token',
          error: 'invalid_token',
          error_description: 'invalid token provided',
        },
        cookies: [],
        redirect: null,
      },
    });
    expect(steps[1]?.value.body).toMatchObject({
      authorityVector: {
        management: 'audience-before-scope',
        userinfo: 'structured-resource-token-lookup-before-scope-audience',
      },
      management: {
        status: 401,
        body: {
          errorCode: 'auth.unauthorized',
          data: {
            errorCode: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
            name: 'JWTClaimValidationFailed',
            claim: 'aud',
            reason: 'check_failed',
            payloadMatchesPresentedClaims: true,
          },
        },
      },
      userinfo: {
        status: 401,
        body: { errorCode: 'oidc.invalid_token', error: 'invalid_token' },
      },
    });
    expect(steps[2]?.value.body).toMatchObject({
      authorityVector: { management: 'missing-all', userinfo: 'missing-openid' },
      management: { status: 403, body: { errorCode: 'auth.forbidden' } },
      userinfo: {
        status: 403,
        body: {
          errorCode: 'oidc.insufficient_scope',
          error: 'insufficient_scope',
          message: 'Token missing scope `{{scope}}`.',
          scope: 'openid',
        },
      },
    });
    expect(JSON.stringify(steps)).not.toMatch(
      /account-signature|data-signature|runtime-admin|opaque-data-openid-token|opaque-userinfo-profile-only-token/u
    );
    expect(JSON.stringify(steps[1])).not.toContain('"payload"');
    expect(() => {
      assertPhase1RuntimeCredentialGraphIsSanitized(steps);
    }).not.toThrow();
  });

  it.each([
    ['state mutation', { mutateState: true }, 'Phase 1 authority rejection state is invalid'],
    [
      'fixture mutation',
      { mutateFixture: true },
      'Phase 1 authority rejection mutated fixture state',
    ],
  ] as const)('rejects %s', async (_name, options, diagnostic) => {
    const harness = createHarness(options);

    await expect(
      runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
    ).rejects.toThrow(diagnostic);
  });

  it('rejects an implementation that validates signatures but ignores issuer audience and scope', async () => {
    const harness = createHarness({ signatureOnly: true });

    await expect(
      runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
    ).rejects.toThrow('Phase 1 management authority rejection is invalid');
  });

  it('rejects a UserInfo challenge that uses the logical instead of runtime admin issuer', async () => {
    const harness = createHarness({ wrongUserinfoRealm: true });

    await expect(
      runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
    ).rejects.toThrow('Phase 1 userinfo authority rejection is invalid');
  });

  it.each(['https://foreign.example/oidc', '/\\foreign.example/oidc'])(
    'rejects issuer path %s when it escapes the target origin',
    async (issuerPath) => {
      const harness = createHarness({ issuerPath });

      await expect(
        runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
      ).rejects.toThrow('Phase 1 issuer path is invalid');
    }
  );

  it('forces fresh consent on the first flow when injected options request prior consent', async () => {
    const harness = createHarness();

    await runTokenIssuerAudienceScopeRejected(harness.context, {
      ...harness.dependencies,
      oidcFlowOptions: { expectOidcConsentAlreadyGranted: true },
    });

    expect(harness.oidcFlowOptions).toEqual([
      {
        captureSteps: false,
        includeResource: true,
        expectOidcConsentAlreadyGranted: false,
      },
      {
        captureSteps: false,
        includeResource: false,
        expectOidcConsentAlreadyGranted: true,
      },
    ]);
  });

  it('rejects an opaque foreign UserInfo source grant without openid scope', async () => {
    const harness = createHarness();
    const assertScope = import.meta.jest.fn(() => {
      throw new Error('Phase 1 token grant scope is invalid');
    });

    await expect(
      runTokenIssuerAudienceScopeRejected(harness.context, {
        ...harness.dependencies,
        assertPositiveOidcTokenGrantIncludesScope: assertScope,
      })
    ).rejects.toThrow('Phase 1 token grant scope is invalid');
    expect(assertScope).toHaveBeenCalledWith(harness.dataUserInfoGrant, 'openid');
    expect(harness.requests).toEqual([]);
    expect(harness.revokedGrants).toEqual([harness.dataUserInfoGrant, harness.dataGrant]);
  });

  it.each(['wrong-issuer', 'wrong-audience'] as const)(
    'rejects a Management %s response that omits enumerable JOSE diagnostics',
    async (omitJoseData) => {
      const harness = createHarness({ omitJoseData });

      await expect(
        runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
      ).rejects.toThrow('Phase 1 management authority rejection is invalid');
    }
  );

  it('rejects Management diagnostics whose payload does not equal the presented JWT', async () => {
    const harness = createHarness({ mismatchJosePayload: true });

    await expect(
      runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
    ).rejects.toThrow('Phase 1 management authority rejection is invalid');
  });

  it.each(['audience', 'scope'] as const)(
    'rejects an implementation that ignores reachable %s enforcement',
    async (ignoredAuthority) => {
      const harness = createHarness({ ignoredAuthority });

      await expect(
        runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
      ).rejects.toThrow();
    }
  );

  it.each(['wrong-issuer', 'wrong-audience', 'missing-scope'] as const)(
    'rejects a transformed %s bearer leak from a protected surface',
    async (leakVariant) => {
      const harness = createHarness({ leakVariant });

      await expect(
        runTokenIssuerAudienceScopeRejected(harness.context, harness.dependencies)
      ).rejects.toThrow();
    }
  );
});

/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/prefer-regexp-exec, unicorn/consistent-function-scoping */
