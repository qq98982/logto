/* eslint-disable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods -- The focused harness structurally supplies clients and records ordered observable calls. */
import { SymbolTable } from '../../symbol-table.js';
import { MemoryProtocolSecretStore, type ProtocolRequestOptions } from '../clients/oidc.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimePhone,
  getPhase1FixtureRuntimeUsername,
  type Phase1FixtureMap,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runManagementUserRead } from './management-user-read.js';

const target = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'https://data.example/',
  adminUrl: 'https://admin.example/',
});
const dataAllocationId = 'data-allocation';
const runtimeUserId = 'runtime-subject';
const runtimeUsername = getPhase1FixtureRuntimeUsername('subject-name', dataAllocationId);
const runtimeEmail = getPhase1FixtureRuntimeEmail('subject@example.test', dataAllocationId);
const runtimePhone = getPhase1FixtureRuntimePhone(dataAllocationId);
const createdAt = 1_700_000_000_000;
const updatedAt = 1_700_000_060_000;

const fixtureMap: Phase1FixtureMap = Object.freeze({
  schemaVersion: 1,
  recipe: 'fullPhase1',
  allocations: Object.freeze([
    Object.freeze({
      allocationId: dataAllocationId,
      role: 'data',
      target: 'primary',
      isolation: Object.freeze({
        persistenceId: 'data-persistence',
        cookieKeyId: 'data-cookie',
        signingKeyId: 'data-signing',
      }),
      entities: Object.freeze([
        Object.freeze({ kind: 'user', logicalId: 'subject', runtimeId: runtimeUserId }),
      ]),
    }),
    Object.freeze({
      allocationId: 'admin-allocation',
      role: 'admin',
      target: 'primary',
      isolation: Object.freeze({
        persistenceId: 'admin-persistence',
        cookieKeyId: 'admin-cookie',
        signingKeyId: 'admin-signing',
      }),
      entities: Object.freeze([]),
    }),
  ]),
});

const profile = Object.freeze({
  fixtures: {
    dataTenant: {
      subject: {
        id: 'subject',
        username: 'subject-name',
        name: 'Subject',
        primaryEmail: 'subject@example.test',
        primaryPhone: '+15555550100',
        applicationId: null,
      },
      browserClientConfiguration: {
        localStorageKey: 'logto:demo-app:dev:config',
      },
    },
  },
  consoleReadRequests: [
    {
      method: 'GET',
      path: '/api/users',
      query: { page: '1', page_size: '20' },
      origin: 'https://admin.example',
      headers: { 'Accept-Language': 'en' },
      expectedStatus: 200,
      requiredHeaderValues: { 'Total-Number': '1' },
      requiredBodyLength: 1,
      requiredProjection: [
        {
          id: 'subject',
          username: 'subject-name',
          name: 'Subject',
          primaryEmail: 'subject@example.test',
          primaryPhone: '+15555550100',
          avatar: null,
          applicationId: null,
          lastSignInAt: null,
          isSuspended: false,
          hasPassword: true,
        },
      ],
    },
  ],
});

describe('management.user-read', () => {
  it('returns the exact seeded user with null lastSignInAt', async () => {
    const requests: Array<
      Readonly<{ operation: string; path: string; options: ProtocolRequestOptions | undefined }>
    > = [];
    const stateReads: string[] = [];
    const fixtureReads: unknown[] = [];
    const symbols = new SymbolTable();
    const dataStore = new MemoryProtocolSecretStore();
    symbols.bind('user.subject', runtimeUserId);
    const fixtureState = Object.freeze({ schemaVersion: 1, allocations: Object.freeze([]) });
    const response = Object.freeze({
      status: 200,
      headers: Object.freeze([
        Object.freeze(['content-type', 'application/json; charset=utf-8'] as const),
        Object.freeze(['etag', 'W/"fixture-dependent-user-tag"'] as const),
        Object.freeze(['total-number', '1'] as const),
        Object.freeze([
          'link',
          '<https://data.example/api/users?page=1&page_size=20>; rel="first"',
        ] as const),
        Object.freeze([
          'link',
          '<https://data.example/api/users?page=1&page_size=20>; rel="last"',
        ] as const),
      ]),
      body: JSON.stringify([
        {
          id: runtimeUserId,
          username: runtimeUsername,
          name: 'Subject',
          primaryEmail: runtimeEmail,
          primaryPhone: runtimePhone,
          avatar: null,
          applicationId: null,
          lastSignInAt: null,
          isSuspended: false,
          hasPassword: true,
          createdAt,
          updatedAt,
          customData: { retained: true },
        },
      ]),
    });
    const management = {
      requestManagement: import.meta.jest.fn(
        async (operation: string, path: string, options?: ProtocolRequestOptions) => {
          if (!dataStore.getToken('management')) {
            throw new Error('management token was not installed in the data store');
          }
          requests.push({ operation, path, options });
          return response;
        }
      ),
    };
    const context = {
      profile,
      target,
      fixture: { public: fixtureMap },
      signal: new AbortController().signal,
      protocol: {
        publicOidc: {} as never,
        publicSymbols: new SymbolTable(),
        forAllocation: (role: string) =>
          role === 'data' ? ({ management } as never) : ({} as never),
        symbolsFor: (allocationId: string) =>
          allocationId === dataAllocationId ? symbols : undefined,
      },
      projectFixtureState: async () => {
        fixtureReads.push(fixtureState);
        return fixtureState as never;
      },
      projectScenarioState: async ({ stepId }: { stepId: string }) => {
        stateReads.push(stepId);
        return {
          body: {},
          semanticState: { unrelatedMutation: false },
          persistedState: { unrelatedMutation: false },
          sideEffects: { unrelatedMutation: false },
        };
      },
    } as unknown as Phase1ScenarioRunContext;
    const session = {} as never;
    const withPositiveAdminSession = import.meta.jest.fn(
      async (
        _context: Phase1ScenarioRunContext,
        _options: unknown,
        consume: (value: never) => Promise<unknown>
      ) => Object.freeze({ steps: Object.freeze([]), result: await consume(session) })
    );
    const refreshPositiveAdminManagementToken = import.meta.jest.fn(async () => {
      dataStore.setToken('management', 'private-management-token');
    });
    const steps = await runManagementUserRead(context, {
      withPositiveAdminSession: withPositiveAdminSession as never,
      refreshPositiveAdminManagementToken: refreshPositiveAdminManagementToken as never,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual(['users', 'state']);
    expect(requests).toEqual([
      {
        operation: 'users',
        path: 'users?page=1&page_size=20',
        options: {
          method: 'GET',
          headers: [
            ['Origin', 'https://admin.example'],
            ['Accept-Language', 'en'],
          ],
        },
      },
    ]);
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      mediaType: { type: 'application', subtype: 'json' },
      headers: {
        etag: [
          {
            weak: true,
            normalizedBodySha256:
              '2c5c2928d6da6222c9dd5122da96ab05cb4cbb6f01516eded480cb8db40198b0',
          },
        ],
        link: [
          '<{target.core-origin}/api/users?page=1&page_size=20>; rel="first"',
          '<{target.core-origin}/api/users?page=1&page_size=20>; rel="last"',
        ],
        'total-number': ['1'],
      },
      body: [
        {
          id: '<user.subject>',
          username: '<fixture.data.username>',
          name: 'Subject',
          primaryEmail: '<fixture.data.email>',
          primaryPhone: '<fixture.data.phone>',
          avatar: null,
          applicationId: null,
          lastSignInAt: null,
          isSuspended: false,
          hasPassword: true,
          createdAt: {
            $timestamp: createdAt / 1000,
            $toleranceSeconds: 30,
          },
          updatedAt: {
            $timestamp: updatedAt / 1000,
            $toleranceSeconds: 30,
          },
          customData: { retained: true },
        },
      ],
    });
    expect(steps[1]?.value).toMatchObject({
      persistedState: { unrelatedMutation: false },
      sideEffects: { unrelatedMutation: false },
    });
    expect(stateReads).toEqual(['users', 'state']);
    expect(fixtureReads).toHaveLength(2);
    expect(withPositiveAdminSession).toHaveBeenCalledTimes(1);
    expect(refreshPositiveAdminManagementToken).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(steps)).not.toContain('private-management-token');
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods */
