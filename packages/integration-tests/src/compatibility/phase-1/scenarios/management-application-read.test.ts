/* eslint-disable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods -- The focused harness structurally supplies clients and records ordered observable calls. */
import { SymbolTable } from '../../symbol-table.js';
import { MemoryProtocolSecretStore, type ProtocolRequestOptions } from '../clients/oidc.js';
import { getPhase1FixtureRuntimeText, type Phase1FixtureMap } from '../fixture-map.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runManagementApplicationRead } from './management-application-read.js';

const target = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'https://data.example/',
  adminUrl: 'https://admin.example/',
});
const dataAllocationId = 'data-allocation';
const firstPartyRuntimeId = 'runtime-first-party';
const thirdPartyRuntimeId = 'runtime-third-party';
const firstPartyName = getPhase1FixtureRuntimeText('First Party', dataAllocationId);
const thirdPartyName = getPhase1FixtureRuntimeText('Browser Client', dataAllocationId);
const createdAt = 1_700_000_000_000;

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
        Object.freeze({
          kind: 'application',
          logicalId: 'first-party',
          runtimeId: firstPartyRuntimeId,
        }),
        Object.freeze({
          kind: 'application',
          logicalId: 'browser-client',
          runtimeId: thirdPartyRuntimeId,
        }),
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
      applications: [
        {
          id: 'first-party',
          name: 'First Party',
          type: 'SPA',
          isThirdParty: false,
          customClientMetadata: {},
        },
        {
          id: 'browser-client',
          name: 'Browser Client',
          type: 'SPA',
          isThirdParty: true,
          customClientMetadata: {},
        },
      ],
    },
  },
  consoleReadRequests: [
    {
      method: 'GET',
      path: '/api/applications',
      query: { page: '1', page_size: '20', isThirdParty: 'false' },
      origin: 'https://admin.example',
      headers: { 'Accept-Language': 'en' },
      expectedStatus: 200,
      requiredHeaderValues: { 'Total-Number': '1' },
      requiredBodyLength: 1,
      requiredProjection: [
        {
          id: 'first-party',
          name: 'First Party',
          type: 'SPA',
          isThirdParty: false,
          customClientMetadata: {},
        },
      ],
    },
    {
      method: 'GET',
      path: '/api/applications',
      query: { page: '1', page_size: '20', isThirdParty: 'true' },
      origin: 'https://admin.example',
      headers: { 'Accept-Language': 'en' },
      expectedStatus: 200,
      requiredHeaderValues: { 'Total-Number': '1' },
      requiredBodyLength: 1,
      requiredProjection: [
        {
          id: 'browser-client',
          name: 'Browser Client',
          type: 'SPA',
          isThirdParty: true,
          customClientMetadata: {},
        },
      ],
    },
    {
      method: 'GET',
      path: '/api/applications',
      query: { page: '1', page_size: '1', isThirdParty: 'false', types: 'SAML' },
      origin: 'https://admin.example',
      headers: { 'Accept-Language': 'en' },
      expectedStatus: 200,
      requiredHeaderValues: { 'Total-Number': '0' },
      requiredBodyLength: 0,
      requiredProjection: [],
    },
  ],
});

type RecordedRequest = Readonly<{
  operation: string;
  path: string;
  options: ProtocolRequestOptions | undefined;
}>;

const response = (body: unknown, total: string) =>
  Object.freeze({
    status: 200,
    headers: Object.freeze([
      Object.freeze(['content-type', 'application/json; charset=utf-8'] as const),
      Object.freeze(['total-number', total] as const),
    ]),
    body: JSON.stringify(body),
  });

const createHarness = () => {
  const requests: RecordedRequest[] = [];
  const stateReads: string[] = [];
  const fixtureReads: unknown[] = [];
  const responses = [
    response(
      [
        {
          id: firstPartyRuntimeId,
          name: firstPartyName,
          type: 'SPA',
          isThirdParty: false,
          customClientMetadata: {},
          createdAt,
          description: 'preserved first-party field',
        },
      ],
      '1'
    ),
    response(
      [
        {
          id: thirdPartyRuntimeId,
          name: thirdPartyName,
          type: 'SPA',
          isThirdParty: true,
          customClientMetadata: {},
          createdAt,
          description: 'preserved third-party field',
        },
      ],
      '1'
    ),
    response([], '0'),
  ];
  const symbols = new SymbolTable();
  const dataStore = new MemoryProtocolSecretStore();
  symbols.bind('application.first-party', firstPartyRuntimeId);
  symbols.bind('application.browser-client', thirdPartyRuntimeId);
  const fixtureState = Object.freeze({ schemaVersion: 1, allocations: Object.freeze([]) });
  const management = {
    requestManagement: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        if (!dataStore.getToken('management')) {
          throw new Error('management token was not installed in the data store');
        }
        requests.push({ operation, path, options });
        const next = responses.shift();

        if (!next) {
          throw new Error('unexpected management request');
        }

        return next;
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
      forAllocation: (role: string) => {
        if (role !== 'data') {
          return {} as never;
        }

        return { management } as never;
      },
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

  return {
    context,
    requests,
    stateReads,
    fixtureReads,
    withPositiveAdminSession,
    refreshPositiveAdminManagementToken,
  };
};

describe('management.application-read', () => {
  it('returns exact first-party third-party and empty SAML lists', async () => {
    const harness = createHarness();
    const steps = await runManagementApplicationRead(harness.context, {
      withPositiveAdminSession: harness.withPositiveAdminSession as never,
      refreshPositiveAdminManagementToken: harness.refreshPositiveAdminManagementToken as never,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'first-party',
      'third-party',
      'saml',
      'state',
    ]);
    expect(harness.requests).toEqual([
      {
        operation: 'first-party',
        path: 'applications?page=1&page_size=20&isThirdParty=false',
        options: {
          method: 'GET',
          headers: [
            ['Origin', 'https://admin.example'],
            ['Accept-Language', 'en'],
          ],
        },
      },
      {
        operation: 'third-party',
        path: 'applications?page=1&page_size=20&isThirdParty=true',
        options: {
          method: 'GET',
          headers: [
            ['Origin', 'https://admin.example'],
            ['Accept-Language', 'en'],
          ],
        },
      },
      {
        operation: 'saml',
        path: 'applications?page=1&page_size=1&isThirdParty=false&types=SAML',
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
      headers: { 'total-number': ['1'] },
      body: [
        {
          id: '<application.first-party>',
          name: '<fixture.data.application-name.first-party>',
          type: 'SPA',
          isThirdParty: false,
          customClientMetadata: {},
          createdAt: {
            $timestamp: createdAt / 1000,
            $toleranceSeconds: 30,
          },
          description: 'preserved first-party field',
        },
      ],
    });
    expect(steps[1]?.value).toMatchObject({
      headers: { 'total-number': ['1'] },
      body: [
        {
          id: '<application.browser-client>',
          name: '<fixture.data.application-name.third-party>',
          description: 'preserved third-party field',
        },
      ],
    });
    expect(steps[2]?.value).toMatchObject({
      headers: { 'total-number': ['0'] },
      body: [],
    });
    expect(steps[3]?.value).toMatchObject({
      persistedState: { unrelatedMutation: false },
      sideEffects: { unrelatedMutation: false },
    });
    expect(harness.stateReads).toEqual(['first-party', 'third-party', 'saml', 'state']);
    expect(harness.fixtureReads).toHaveLength(2);
    expect(harness.withPositiveAdminSession).toHaveBeenCalledTimes(1);
    expect(harness.refreshPositiveAdminManagementToken).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(steps)).not.toContain('private-management-token');
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods */
