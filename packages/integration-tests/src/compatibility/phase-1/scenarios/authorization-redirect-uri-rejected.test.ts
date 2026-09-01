/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, unicorn/text-encoding-identifier-case -- The focused transport harness records requests, uses structural stand-ins, and asserts the exact HTTP charset spelling. */
import { SymbolTable } from '../../symbol-table.js';
import { MemoryProtocolSecretStore, type ProtocolRequestOptions } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runAuthorizationRedirectUriRejected } from './authorization-redirect-uri-rejected.js';

const verifier = 'v'.repeat(64);
const responseBody = {
  code: 'oidc.invalid_redirect_uri',
  message: "`redirect_uri` did not match any of the client's registered `redirect_uris`.",
  error: 'invalid_redirect_uri',
  error_description: "redirect_uri did not match any of the client's registered redirect_uris",
  iss: 'https://oracle.example/oidc',
};
const projectedResponseBody = {
  errorCode: responseBody.code,
  message: responseBody.message,
  error: responseBody.error,
  error_description: responseBody.error_description,
  iss: responseBody.iss,
};
const stateProjection = {
  body: {},
  semanticState: { unrelatedMutation: false },
  persistedState: {
    interactionCount: 0,
    grantCount: 0,
    familyCount: 0,
    unrelatedMutation: false,
  },
  generatedIds: {},
  sideEffects: { unrelatedMutation: false },
};

const createHarness = (state = stateProjection) => {
  const store = new MemoryProtocolSecretStore();
  const requests: Array<
    Readonly<{ operation: string; path: string; options?: ProtocolRequestOptions }>
  > = [];
  const symbols = new SymbolTable();
  symbols.bind('application.phase1-browser', 'runtime-client');
  symbols.bind('user.phase1-user', 'runtime-user');
  const responseText = JSON.stringify(responseBody);
  const oidc = {
    store,
    request: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        requests.push({ operation, path, options });

        return {
          status: 400,
          headers: [
            ['content-type', 'application/json; charset=utf-8'],
            ['cache-control', 'no-store'],
            ['x-content-type-options', 'nosniff'],
            ['content-length', String(Buffer.byteLength(responseText))],
          ] as const,
          body: responseText,
        };
      }
    ),
  };
  const context = {
    profile: {
      fixtures: {
        dataTenant: {
          subject: {
            id: 'phase1-user',
            username: 'phase1-user',
            primaryEmail: 'phase1-user@example.com',
            primaryPhone: '+15555550101',
          },
          applications: [
            {
              id: 'phase1-browser',
              name: 'Phase 1 Consent Client',
              isThirdParty: true,
              oidcClientMetadata: {
                redirectUris: ['https://client.example/callback'],
                postLogoutRedirectUris: [],
              },
              userConsentScopes: ['profile'],
              resourceConsentScopes: [],
            },
          ],
          resource: {
            id: 'phase1-api',
            name: 'API',
            indicator: 'https://api.example',
            scopes: [
              {
                id: 'phase1-read-profile',
                name: 'read:profile',
                description: 'Read profile',
              },
            ],
          },
          browserClientConfiguration: {
            localStorageValue: {
              appId: 'phase1-browser',
              prompt: 'login consent',
              scope: 'profile',
              resource: 'https://api.example',
            },
          },
        },
      },
      oidc: { issuerPath: '/oidc', authorizationPath: '/oidc/auth' },
    },
    target: {
      label: 'oracle',
      coreUrl: 'https://oracle.example/',
      adminUrl: 'https://oracle-admin.example/',
    },
    fixture: {
      public: {
        schemaVersion: 1,
        recipe: 'dataProtocol',
        allocations: [
          {
            allocationId: 'data-allocation',
            role: 'data',
            target: 'primary',
            isolation: {
              persistenceId: 'data-persistence',
              cookieKeyId: 'data-cookie',
              signingKeyId: 'data-signing',
            },
            entities: [
              { kind: 'application', logicalId: 'phase1-browser', runtimeId: 'runtime-client' },
              { kind: 'user', logicalId: 'phase1-user', runtimeId: 'runtime-user' },
            ],
          },
        ],
      },
    },
    signal: new AbortController().signal,
    protocol: {
      publicOidc: {} as never,
      publicSymbols: new SymbolTable(),
      forAllocation: () => ({
        oidc,
        experience: { store },
        consent: { store },
        management: {} as never,
        account: {} as never,
        state: {} as never,
      }),
      symbolsFor: () => symbols,
    },
    projectFixtureState: async () => ({
      schemaVersion: 1,
      recipe: 'dataProtocol',
      allocations: [],
    }),
    projectScenarioState: async () => state,
  } as unknown as Phase1ScenarioRunContext;

  return { context, requests };
};

describe('authorization.redirect-uri-rejected', () => {
  it('rejects an unregistered redirect without creating protocol state', async () => {
    const harness = createHarness();
    const steps = await runAuthorizationRedirectUriRejected(harness.context, {
      random: { codeVerifier: () => verifier, state: () => 'unused-private-state' },
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual(['authorize', 'state']);
    expect(harness.requests).toHaveLength(1);
    const request = harness.requests[0];
    const url = new URL(request?.path ?? '', 'https://oracle.example/');
    expect(request).toMatchObject({
      operation: 'authorization-redirect-uri-rejected',
      options: { includeCookies: true },
    });
    expect(url.pathname).toBe('/oidc/auth');
    expect(url.searchParams.get('client_id')).toBe('runtime-client');
    expect(url.searchParams.get('redirect_uri')).toBe(
      'https://client.example/callback/unregistered'
    );
    expect(url.searchParams.has('state')).toBe(false);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(steps[0]?.value).toMatchObject({
      status: 400,
      mediaType: {
        type: 'application',
        subtype: 'json',
        parameters: { charset: ['utf-8'] },
      },
      headers: {
        'cache-control': ['no-store'],
        'content-type': ['application/json; charset=utf-8'],
        'x-content-type-options': ['nosniff'],
      },
      body: projectedResponseBody,
      error: projectedResponseBody,
      redirect: null,
      cookies: [],
    });
    expect(steps[1]?.value).toMatchObject(stateProjection);
    expect(JSON.stringify(steps)).not.toMatch(/vvvv|unused-private-state/u);
  });

  it('rejects a projection that hides created protocol state', async () => {
    const harness = createHarness({
      ...stateProjection,
      persistedState: { ...stateProjection.persistedState, interactionCount: 1 },
    });

    await expect(
      runAuthorizationRedirectUriRejected(harness.context, {
        random: { codeVerifier: () => verifier, state: () => 'unused-private-state' },
      })
    ).rejects.toThrow('Phase 1 rejected redirect state is invalid');
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, unicorn/text-encoding-identifier-case */
