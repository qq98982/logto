/* eslint-disable max-lines, complexity, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods -- The closed five-request CORS harness records primary and foreign boundary topology plus the full response matrix in one fixture. */
import { isDeepStrictEqual } from 'node:util';

import { SymbolTable } from '../../symbol-table.js';
import type { ManagementRequestOptions } from '../clients/management.js';
import { MemoryProtocolSecretStore, protocolHeaderPairs } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runCorsManagementList } from './cors-management-list.js';
import type { PositiveAdminSessionOutput } from './positive-admin-flow.js';

const managementToken = 'private-management-token';
const dataAllocationId = 'data-allocation';
const logicalOrigin = 'http://localhost:3002';
const runtimeOrigin = 'http://localhost:3411';
const logicalTargetOrigin = 'http://localhost:3001';
const runtimeTargetOrigin = 'http://localhost:3311';
const foreignRuntimeOrigin = 'http://localhost:3412';
const foreignRuntimeTargetOrigin = 'http://localhost:3312';
const requestHeaders = 'Authorization, Accept-Language, Content-Type';

const defaultLinkHeaders = (resource: 'applications' | 'users'): readonly string[] => {
  const query =
    resource === 'applications' ? 'page=1&page_size=20&isThirdParty=false' : 'page=1&page_size=20';

  return Object.freeze(
    ['first', 'prev', 'last'].map(
      (relation) => `<${runtimeTargetOrigin}/api/${resource}?${query}>; rel="${relation}"`
    )
  );
};

type CorsHarnessOptions = Readonly<{
  preflightResponseOrigin?: string | false;
  getResponseOrigin?: string | false;
  rejectedResponse?: Readonly<{
    status?: number;
    body?: string;
    vary?: string | false;
    extraHeaders?: ReadonlyArray<readonly [string, string]>;
  }>;
  linkHeaders?: readonly string[] | ((resource: 'applications' | 'users') => readonly string[]);
  profileOrigin?: unknown;
  profileTarget?: unknown;
  allowOriginResponse?: unknown;
  omitForeignTarget?: boolean;
  collapseRuntimeOrigins?: boolean;
}>;

const createCorsHarness = (options: CorsHarnessOptions = {}) => {
  const adminStore = new MemoryProtocolSecretStore();
  const dataStore = new MemoryProtocolSecretStore();
  const foreignStore = new MemoryProtocolSecretStore();
  const preflightResponseOrigin = Object.hasOwn(options, 'preflightResponseOrigin')
    ? options.preflightResponseOrigin
    : runtimeOrigin;
  const getResponseOrigin = Object.hasOwn(options, 'getResponseOrigin')
    ? options.getResponseOrigin
    : runtimeOrigin;
  const expectedRequests = [
    {
      boundary: 'foreign',
      operation: 'cors-foreign-localhost-preflight-rejected',
      path: 'applications',
      method: 'OPTIONS',
      authenticated: false,
      optionKeys: ['authenticated', 'headers', 'method'],
      headers: [
        ['origin', foreignRuntimeOrigin],
        ['access-control-request-method', 'GET'],
        ['access-control-request-headers', requestHeaders],
      ],
      bearer: undefined,
      cookie: undefined,
    },
    {
      boundary: 'primary',
      operation: 'cors-applications-preflight',
      path: 'applications',
      method: 'OPTIONS',
      authenticated: false,
      optionKeys: ['authenticated', 'headers', 'method'],
      headers: [
        ['origin', runtimeOrigin],
        ['access-control-request-method', 'GET'],
        ['access-control-request-headers', requestHeaders],
      ],
      bearer: undefined,
      cookie: undefined,
    },
    {
      boundary: 'primary',
      operation: 'cors-users-preflight',
      path: 'users',
      method: 'OPTIONS',
      authenticated: false,
      optionKeys: ['authenticated', 'headers', 'method'],
      headers: [
        ['origin', runtimeOrigin],
        ['access-control-request-method', 'GET'],
        ['access-control-request-headers', requestHeaders],
      ],
      bearer: undefined,
      cookie: undefined,
    },
    {
      boundary: 'primary',
      operation: 'cors-applications-get',
      path: 'applications?page=2&page_size=20&isThirdParty=false',
      method: 'GET',
      authenticated: undefined,
      optionKeys: ['headers', 'method'],
      headers: [
        ['origin', runtimeOrigin],
        ['accept-language', 'en'],
      ],
      bearer: `Bearer ${managementToken}`,
      cookie: undefined,
    },
    {
      boundary: 'primary',
      operation: 'cors-users-get',
      path: 'users?page=2&page_size=20',
      method: 'GET',
      authenticated: undefined,
      optionKeys: ['headers', 'method'],
      headers: [
        ['origin', runtimeOrigin],
        ['accept-language', 'en'],
      ],
      bearer: `Bearer ${managementToken}`,
      cookie: undefined,
    },
  ] as const;
  const requests: Array<(typeof expectedRequests)[number]> = [];
  const linkHeaders = (resource: 'applications' | 'users') =>
    typeof options.linkHeaders === 'function'
      ? options.linkHeaders(resource)
      : (options.linkHeaders ?? defaultLinkHeaders(resource));
  const createRequestManagement = (
    boundary: 'primary' | 'foreign',
    store: MemoryProtocolSecretStore
  ) =>
    import.meta.jest.fn(
      async (operation: string, path: string, requestOptions: ManagementRequestOptions = {}) => {
        const expected = expectedRequests.at(requests.length);
        const headerPairs = protocolHeaderPairs(requestOptions.headers);
        const { authenticated } = requestOptions;
        const suppliedBearer = headerPairs.find(
          ([name]) => name.toLowerCase() === 'authorization'
        )?.[1];
        const suppliedCookie = headerPairs.find(([name]) => name.toLowerCase() === 'cookie')?.[1];
        const bearer = authenticated === false ? undefined : store.getToken('management');
        const actual = {
          boundary,
          operation,
          path,
          method: requestOptions.method,
          authenticated,
          optionKeys: Object.keys(requestOptions).toSorted(),
          headers: headerPairs,
          bearer: bearer && `Bearer ${bearer}`,
          cookie: suppliedCookie,
        };

        if (!expected || suppliedBearer !== undefined || !isDeepStrictEqual(actual, expected)) {
          throw new Error('CORS request topology is invalid');
        }
        requests.push(expected);
        if (operation === 'cors-foreign-localhost-preflight-rejected') {
          const rejectedResponse = options.rejectedResponse ?? {};

          return {
            status: rejectedResponse.status ?? 200,
            headers: [
              ...(rejectedResponse.extraHeaders ?? []),
              ['content-type', 'text/plain; charset=utf-8'],
              ['date', 'Thu, 01 Jan 1970 00:16:40 GMT'],
              ['logto-core-request-id', 'rejected_req_001'],
              ...(rejectedResponse.vary === false
                ? []
                : ([['vary', rejectedResponse.vary ?? 'Origin']] as const)),
            ] as const,
            body: rejectedResponse.body ?? '',
          };
        }
        if (operation.endsWith('preflight')) {
          return {
            status: 204,
            headers: [
              ...(typeof preflightResponseOrigin === 'string'
                ? ([['access-control-allow-origin', preflightResponseOrigin]] as const)
                : []),
              ['access-control-allow-headers', requestHeaders],
              ['access-control-allow-methods', 'GET,HEAD,PUT,POST,DELETE,PATCH'],
              ['date', 'Thu, 01 Jan 1970 00:16:40 GMT'],
              ['logto-core-request-id', 'preflight_req_01'],
              ['vary', 'Origin'],
            ] as const,
            body: '',
          };
        }
        const resource = operation === 'cors-applications-get' ? 'applications' : 'users';

        return {
          status: 200,
          headers: [
            ...(typeof getResponseOrigin === 'string'
              ? ([['access-control-allow-origin', getResponseOrigin]] as const)
              : []),
            ['access-control-expose-headers', '*'],
            ['content-length', '2'],
            ['total-number', '1'],
            ['content-type', 'application/json; charset=utf-8'],
            ['date', 'Thu, 01 Jan 1970 00:16:40 GMT'],
            ['etag', 'W/"2-test"'],
            ...linkHeaders(resource).map((value) => ['link', value] as const),
            ['logto-core-request-id', 'manage_req_00001'],
            ['vary', 'Origin'],
          ] as const,
          body: JSON.stringify([]),
        };
      }
    );
  const requestManagement = createRequestManagement('primary', dataStore);
  const foreignRequestManagement = createRequestManagement('foreign', foreignStore);
  const symbols = new SymbolTable();
  const foreignSymbols = new SymbolTable();
  symbols.bind('application.phase1-app', 'runtime-app');
  symbols.bind('user.phase1-user', 'runtime-user');
  const fixtureState = {
    schemaVersion: 1 as const,
    recipe: 'corsBoundary' as const,
    allocations: [],
  };
  const context: Phase1ScenarioRunContext = {
    profile: {
      fixtures: {
        dataTenant: {
          subject: {
            username: 'phase1-user',
            primaryEmail: 'phase1-user@example.com',
          },
          applications: [{ id: 'phase1-app', name: 'Phase 1 Application', isThirdParty: false }],
          browserClientConfiguration: {
            localStorageKey: 'logto:demo-app:dev:config',
          },
        },
      },
      cors: {
        origin: Object.hasOwn(options, 'profileOrigin') ? options.profileOrigin : logicalOrigin,
        target: Object.hasOwn(options, 'profileTarget')
          ? options.profileTarget
          : logicalTargetOrigin,
        allowOriginResponse: Object.hasOwn(options, 'allowOriginResponse')
          ? options.allowOriginResponse
          : logicalOrigin,
        allowedRequestHeaders: ['Authorization', 'Accept-Language', 'Content-Type'],
      },
    } as never,
    target: {
      label: 'oracle',
      coreUrl: `${options.collapseRuntimeOrigins ? runtimeOrigin : runtimeTargetOrigin}/`,
      adminUrl: `${runtimeOrigin}/`,
    },
    fixture: {
      public: {
        schemaVersion: 1,
        recipe: 'corsBoundary',
        allocations: [
          {
            allocationId: dataAllocationId,
            role: 'data',
            target: 'primary',
            isolation: {
              persistenceId: 'data-persistence',
              cookieKeyId: 'data-cookie',
              signingKeyId: 'data-signing',
            },
            entities: [],
          },
          {
            allocationId: 'admin-allocation',
            role: 'admin',
            target: 'primary',
            isolation: {
              persistenceId: 'data-persistence',
              cookieKeyId: 'admin-cookie',
              signingKeyId: 'admin-signing',
            },
            entities: [],
          },
          {
            allocationId: 'foreign-allocation',
            role: 'foreign',
            target: 'foreign',
            isolation: {
              persistenceId: 'foreign-persistence',
              cookieKeyId: 'foreign-cookie',
              signingKeyId: 'foreign-signing',
            },
            entities: [],
          },
        ],
      },
      ...(!options.omitForeignTarget && {
        foreignTarget: {
          label: 'oracle',
          coreUrl: `${foreignRuntimeTargetOrigin}/`,
          adminUrl: `${foreignRuntimeOrigin}/`,
        },
      }),
    } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: {} as never,
      publicSymbols: new SymbolTable(),
      forAllocation: (role) => {
        const store = role === 'data' ? dataStore : adminStore;

        return role === 'data'
          ? {
              oidc: { store } as never,
              experience: { store } as never,
              consent: { store } as never,
              management: { store, requestManagement },
              account: { store } as never,
              state: { store } as never,
            }
          : role === 'foreign'
            ? {
                oidc: { store: foreignStore } as never,
                experience: { store: foreignStore } as never,
                consent: { store: foreignStore } as never,
                management: { store: foreignStore, requestManagement: foreignRequestManagement },
                account: { store: foreignStore } as never,
                state: { store: foreignStore } as never,
              }
            : {
                oidc: { store } as never,
                experience: { store } as never,
                consent: { store } as never,
                management: { store } as never,
                account: { store } as never,
                state: { store } as never,
              };
      },
      symbolsFor: (requestedAllocationId) =>
        requestedAllocationId === dataAllocationId
          ? symbols
          : requestedAllocationId === 'foreign-allocation'
            ? foreignSymbols
            : undefined,
    },
    projectFixtureState: async () => fixtureState,
    projectScenarioState: async ({ stepId }) => ({
      body: { stepId },
      semanticState: { stepId, unrelatedMutation: false },
      persistedState: { unrelatedMutation: false },
      generatedIds: {},
      sideEffects: { unrelatedMutation: false },
    }),
  };
  const session = Object.freeze({}) as never;
  const sessionRuns: number[] = [];
  const withSession = async <Result>(
    _context: Phase1ScenarioRunContext,
    _options: unknown,
    consume: (session: never) => Promise<Result>
  ): Promise<PositiveAdminSessionOutput<Result>> => {
    sessionRuns.push(1);

    return { steps: [], result: await consume(session) };
  };
  const run = async () =>
    runCorsManagementList(context, {
      withPositiveAdminSession: withSession as never,
      refreshPositiveAdminManagementToken: async (_context, actualSession) => {
        if (actualSession !== session) {
          throw new Error('CORS refresh used an invalid admin session');
        }
        dataStore.setToken('management', managementToken);
      },
    });

  return { adminStore, dataStore, expectedRequests, foreignStore, requests, run, sessionRuns };
};

describe('cors.management-list', () => {
  it('binds runtime origins while publishing target-symbol CORS responses', async () => {
    const harness = createCorsHarness();
    const steps = await harness.run();

    expect(harness.requests).toEqual(harness.expectedRequests);
    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'applications-preflight',
      'users-preflight',
      'applications-get',
      'users-get',
    ]);
    expect(steps[0]?.value.headers).toEqual({
      'access-control-allow-headers': [requestHeaders],
      'access-control-allow-methods': ['GET,HEAD,PUT,POST,DELETE,PATCH'],
      'access-control-allow-origin': ['<target.admin-url>'],
      date: [{ $timestamp: 1000, $toleranceSeconds: 30 }],
      'aster-core-request-id': ['<per-request-id>'],
      vary: ['Origin'],
    });
    expect(steps[2]?.value.headers).toEqual({
      'access-control-allow-origin': ['<target.admin-url>'],
      'access-control-expose-headers': ['*'],
      'content-length': [2],
      'content-type': ['application/json; charset=utf-8'],
      date: [{ $timestamp: 1000, $toleranceSeconds: 30 }],
      etag: [
        {
          weak: true,
          normalizedBodySha256: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
        },
      ],
      link: [
        '<{target.core-origin}/api/applications?page=1&page_size=20&isThirdParty=false>; rel="first"',
        '<{target.core-origin}/api/applications?page=1&page_size=20&isThirdParty=false>; rel="prev"',
        '<{target.core-origin}/api/applications?page=1&page_size=20&isThirdParty=false>; rel="last"',
      ],
      'aster-core-request-id': ['<per-request-id>'],
      'total-number': ['1'],
      vary: ['Origin'],
    });
    expect(steps[2]?.value.body).toEqual([]);
    expect(steps[3]?.value.headers.link).toEqual([
      '<{target.core-origin}/api/users?page=1&page_size=20>; rel="first"',
      '<{target.core-origin}/api/users?page=1&page_size=20>; rel="prev"',
      '<{target.core-origin}/api/users?page=1&page_size=20>; rel="last"',
    ]);
    expect(steps[3]?.value.body).toEqual([]);
    expect(harness.dataStore.getToken('management')).toBe(managementToken);
    expect(harness.adminStore.getToken('management')).toBeUndefined();
    expect(harness.foreignStore.getToken('management')).toBeUndefined();
    harness.dataStore.assertNoCredentialMaterial(steps);
    harness.foreignStore.assertNoCredentialMaterial(steps);
  });

  it('keeps target symbolization stable when the profile origin equals the runtime admin origin', async () => {
    const harness = createCorsHarness({
      profileOrigin: runtimeOrigin,
      allowOriginResponse: runtimeOrigin,
    });
    const steps = await harness.run();

    expect(steps[0]?.value.headers['access-control-allow-origin']).toEqual(['<target.admin-url>']);
    expect(steps[2]?.value.headers['access-control-allow-origin']).toEqual(['<target.admin-url>']);
  });

  it.each([logicalOrigin, '*'])(
    'rejects an unreflected preflight ACAO value %s',
    async (preflightResponseOrigin) => {
      const harness = createCorsHarness({ preflightResponseOrigin });

      await expect(harness.run()).rejects.toThrow('Phase 1 CORS preflight is invalid');
    }
  );

  it('rejects a missing preflight ACAO header', async () => {
    const harness = createCorsHarness({ preflightResponseOrigin: false });

    await expect(harness.run()).rejects.toThrow('Phase 1 CORS preflight is invalid');
  });

  it.each([logicalOrigin, '*'])(
    'rejects an unreflected GET ACAO value %s after valid preflights',
    async (getResponseOrigin) => {
      const harness = createCorsHarness({ getResponseOrigin });

      await expect(harness.run()).rejects.toThrow('Phase 1 CORS GET response is invalid');
    }
  );

  it('rejects a missing GET ACAO header after valid preflights', async () => {
    const harness = createCorsHarness({ getResponseOrigin: false });

    await expect(harness.run()).rejects.toThrow('Phase 1 CORS GET response is invalid');
  });

  it('rejects ACAO on the configured foreign localhost in multi-endpoint production mode', async () => {
    const harness = createCorsHarness({
      rejectedResponse: {
        extraHeaders: [['access-control-allow-origin', foreignRuntimeOrigin]],
      },
    });

    await expect(harness.run()).rejects.toThrow('Phase 1 CORS rejected Origin response is invalid');
  });

  it.each([
    ['status 204', { status: 204 }],
    ['status 404', { status: 404 }],
    ['non-empty body', { body: 'unexpected' }],
    ['missing Vary', { vary: false }],
    ['wrong Vary', { vary: 'Accept' }],
    ['Set-Cookie', { extraHeaders: [['set-cookie', 'sid=opaque; Path=/; HttpOnly']] }],
  ] as const)('rejects a foreign localhost preflight with %s', async (_name, rejectedResponse) => {
    const harness = createCorsHarness({ rejectedResponse });

    await expect(harness.run()).rejects.toThrow('Phase 1 CORS rejected Origin response is invalid');
  });

  it.each([
    ['relative', '</api/applications?page=1>; rel="first"'],
    ['foreign', '<https://foreign.example/api/applications?page=1>; rel="first"'],
    ['credentials', '<http://user:password@localhost:3311/api/applications?page=1>; rel="first"'],
    ['credential query', '<http://localhost:3311/api/applications?code=private>; rel="first"'],
    ['credential fragment', '<http://localhost:3311/api/applications#state=private>; rel="first"'],
    ['missing target', 'rel="first"'],
  ] as const)(
    'rejects a %s pagination Link target with a fixed diagnostic',
    async (_name, link) => {
      const harness = createCorsHarness({ linkHeaders: [link] });

      await expect(harness.run()).rejects.toThrow('Phase 1 CORS Link header is invalid');
    }
  );

  it.each([
    ['mismatched response', { allowOriginResponse: 'https://wrong.example' }],
    ['noncanonical origin', { profileOrigin: `${logicalOrigin}/` }],
    ['noncanonical target', { profileTarget: `${logicalTargetOrigin}/` }],
    ['same logical origin and target', { profileTarget: logicalOrigin }],
    ['missing origin', { profileOrigin: undefined }],
  ] as const)('rejects a %s profile before starting a session', async (_name, options) => {
    const harness = createCorsHarness(options);

    await expect(harness.run()).rejects.toThrow(/^Phase 1 CORS profile/u);
    expect(harness.sessionRuns).toEqual([]);
  });

  it.each([
    ['a missing foreign target', { omitForeignTarget: true }],
    ['collapsed runtime core and admin origins', { collapseRuntimeOrigins: true }],
  ] as const)('rejects %s before starting a session', async (_name, options) => {
    const harness = createCorsHarness(options);

    await expect(harness.run()).rejects.toThrow('Phase 1 CORS runtime target is invalid');
    expect(harness.sessionRuns).toEqual([]);
  });
});

/* eslint-enable max-lines, complexity, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods */
