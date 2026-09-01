/* eslint-disable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods -- The focused protocol/session fixture is structural and records exact request order. */
import { isDeepStrictEqual } from 'node:util';

import { SymbolTable } from '../../symbol-table.js';
import type { ManagementRequestOptions } from '../clients/management.js';
import { MemoryProtocolSecretStore, protocolHeaderPairs } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runCorsManagementList } from './cors-management-list.js';
import type { PositiveAdminSessionOutput } from './positive-admin-flow.js';

const managementToken = 'private-management-token';
const dataAllocationId = 'data-allocation';

describe('cors.management-list', () => {
  it('preserves preflight allow-origin exposed headers and readable Total-Number', async () => {
    const adminStore = new MemoryProtocolSecretStore();
    const dataStore = new MemoryProtocolSecretStore();
    const origin = 'https://admin.example';
    const requestHeaders = 'Authorization, Accept-Language, Content-Type';
    const expectedRequests = [
      {
        operation: 'cors-applications-preflight',
        path: 'applications',
        method: 'OPTIONS',
        authenticated: false,
        optionKeys: ['authenticated', 'headers', 'method'],
        headers: [
          ['origin', origin],
          ['access-control-request-method', 'GET'],
          ['access-control-request-headers', requestHeaders],
        ],
        bearer: undefined,
        cookie: undefined,
      },
      {
        operation: 'cors-users-preflight',
        path: 'users',
        method: 'OPTIONS',
        authenticated: false,
        optionKeys: ['authenticated', 'headers', 'method'],
        headers: [
          ['origin', origin],
          ['access-control-request-method', 'GET'],
          ['access-control-request-headers', requestHeaders],
        ],
        bearer: undefined,
        cookie: undefined,
      },
      {
        operation: 'cors-applications-get',
        path: 'applications?page=2&page_size=20&isThirdParty=false',
        method: 'GET',
        authenticated: undefined,
        optionKeys: ['headers', 'method'],
        headers: [
          ['origin', origin],
          ['accept-language', 'en'],
        ],
        bearer: `Bearer ${managementToken}`,
        cookie: undefined,
      },
      {
        operation: 'cors-users-get',
        path: 'users?page=2&page_size=20',
        method: 'GET',
        authenticated: undefined,
        optionKeys: ['headers', 'method'],
        headers: [
          ['origin', origin],
          ['accept-language', 'en'],
        ],
        bearer: `Bearer ${managementToken}`,
        cookie: undefined,
      },
    ] as const;
    const requests: Array<(typeof expectedRequests)[number]> = [];
    const corsHeaders = [
      ['access-control-allow-origin', origin],
      ['access-control-expose-headers', '*'],
      ['total-number', '1'],
      ['content-type', 'application/json; charset=utf-8'],
      ['vary', 'Origin'],
    ] as const;
    const requestManagement = import.meta.jest.fn(
      async (operation: string, path: string, options: ManagementRequestOptions = {}) => {
        const expected = expectedRequests.at(requests.length);
        const headerPairs = protocolHeaderPairs(options.headers);
        const { authenticated } = options;
        const suppliedBearer = headerPairs.find(
          ([name]) => name.toLowerCase() === 'authorization'
        )?.[1];
        const suppliedCookie = headerPairs.find(([name]) => name.toLowerCase() === 'cookie')?.[1];
        const bearer = authenticated === false ? undefined : dataStore.getToken('management');
        const actual = {
          operation,
          path,
          method: options.method,
          authenticated,
          optionKeys: Object.keys(options).toSorted(),
          headers: headerPairs,
          bearer: bearer && `Bearer ${bearer}`,
          cookie: suppliedCookie,
        };

        if (!expected || suppliedBearer !== undefined || !isDeepStrictEqual(actual, expected)) {
          throw new Error('CORS request topology is invalid');
        }
        requests.push(expected);
        if (operation.endsWith('preflight')) {
          return {
            status: 204,
            headers: [
              ['access-control-allow-origin', origin],
              ['access-control-allow-headers', 'Authorization, Accept-Language, Content-Type'],
              ['access-control-allow-methods', 'GET,HEAD,PUT,POST,DELETE,PATCH'],
              ['vary', 'Origin'],
            ] as const,
            body: '',
          };
        }

        return {
          status: 200,
          headers: corsHeaders,
          body: JSON.stringify([]),
        };
      }
    );
    const symbols = new SymbolTable();
    symbols.bind('application.phase1-app', 'runtime-app');
    symbols.bind('user.phase1-user', 'runtime-user');
    const fixtureState = {
      schemaVersion: 1 as const,
      recipe: 'fullPhase1' as const,
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
          },
        },
        cors: {
          origin,
          allowedRequestHeaders: ['Authorization', 'Accept-Language', 'Content-Type'],
        },
      } as never,
      target: {
        label: 'oracle',
        coreUrl: 'https://data.example/',
        adminUrl: 'https://admin.example/',
      },
      fixture: {
        public: {
          schemaVersion: 1,
          recipe: 'fullPhase1',
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
          ],
        },
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
          requestedAllocationId === dataAllocationId ? symbols : undefined,
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
    const withSession = async <Result>(
      _context: Phase1ScenarioRunContext,
      _options: unknown,
      consume: (session: never) => Promise<Result>
    ): Promise<PositiveAdminSessionOutput<Result>> => ({
      steps: [],
      result: await consume(session),
    });
    const steps = await runCorsManagementList(context, {
      withPositiveAdminSession: withSession as never,
      refreshPositiveAdminManagementToken: async (_context, actualSession) => {
        if (actualSession !== session) {
          throw new Error('CORS refresh used an invalid admin session');
        }
        dataStore.setToken('management', managementToken);
      },
    });

    expect(requests).toEqual(expectedRequests);
    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'applications-preflight',
      'users-preflight',
      'applications-get',
      'users-get',
    ]);
    expect(steps[0]?.value).toMatchObject({
      status: 204,
      mediaType: null,
      headers: {
        'access-control-allow-origin': ['https://admin.example'],
        'access-control-allow-methods': ['GET,HEAD,PUT,POST,DELETE,PATCH'],
      },
    });
    expect(steps[2]?.value).toMatchObject({
      status: 200,
      headers: {
        'access-control-allow-origin': ['https://admin.example'],
        'access-control-expose-headers': ['*'],
        'total-number': ['1'],
      },
      body: [],
    });
    expect(steps[3]?.value).toMatchObject({ body: [] });
    expect(dataStore.getToken('management')).toBe(managementToken);
    expect(adminStore.getToken('management')).toBeUndefined();
    dataStore.assertNoCredentialMaterial(steps);
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods */
