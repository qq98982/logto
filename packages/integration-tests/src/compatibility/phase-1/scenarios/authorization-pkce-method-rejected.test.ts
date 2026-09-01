/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, unicorn/text-encoding-identifier-case -- The focused transport harness records requests, uses structural stand-ins, and asserts the exact HTTP charset spelling. */
import { SymbolTable } from '../../symbol-table.js';
import { MemoryProtocolSecretStore, type ProtocolRequestOptions } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runAuthorizationPkceMethodRejected } from './authorization-pkce-method-rejected.js';

const verifier = 'v'.repeat(64);
const privateState = 'private-authorization-state';
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
  const oidc = {
    store,
    request: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        requests.push({ operation, path, options });
        const callback = new URL('https://client.example/callback');
        callback.searchParams.set('error', 'invalid_request');
        callback.searchParams.set(
          'error_description',
          'not supported value of code_challenge_method'
        );
        callback.searchParams.set('state', privateState);
        callback.searchParams.set('iss', 'https://oracle.example/oidc');
        const body = `Redirecting to ${callback.href}.`;

        return {
          status: 303,
          headers: [
            ['content-type', 'text/html; charset=utf-8'],
            ['cache-control', 'no-store'],
            ['location', callback.href],
            ['content-length', String(Buffer.byteLength(body))],
          ] as const,
          body,
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

describe('authorization.pkce-method-rejected', () => {
  it('rejects every canonical non-S256 probe before issuing a code', async () => {
    const harness = createHarness();
    const steps = await runAuthorizationPkceMethodRejected(harness.context, {
      random: { codeVerifier: () => verifier, state: () => privateState },
    });

    expect(harness.requests).toHaveLength(4);
    expect(
      harness.requests.map(({ operation, path, options }) => {
        const url = new URL(path, 'https://oracle.example/');

        return {
          operation,
          method: url.searchParams.get('code_challenge_method'),
          redirectUri: url.searchParams.get('redirect_uri'),
          state: url.searchParams.get('state'),
          includeCookies: options?.includeCookies,
        };
      })
    ).toEqual(
      ['plain', 's256', 'S512', 'unsupported'].map((method) => ({
        operation: `authorization-pkce-method-rejected-${method}`,
        method,
        redirectUri: 'https://client.example/callback',
        state: privateState,
        includeCookies: true,
      }))
    );
    expect(steps.map(({ stepId }) => stepId)).toEqual(['authorize', 'state']);
    expect(steps[0]?.value).toMatchObject({
      status: 303,
      mediaType: { type: 'text', subtype: 'html', parameters: { charset: ['utf-8'] } },
      body: 'Redirecting to <response-location>.',
      error: null,
      redirect: {
        origin: 'https://client.example',
        path: '/callback',
        query: {
          error: ['invalid_request'],
          error_description: ['not supported value of code_challenge_method'],
          iss: ['https://oracle.example/oidc'],
        },
        redactedParameters: [{ component: 'query', name: 'state', count: 1 }],
      },
      cookies: [],
    });
    expect(steps[1]?.value).toMatchObject(stateProjection);
    expect(JSON.stringify(steps)).not.toMatch(/private-authorization-state|vvvv/u);
  });

  it('rejects a projection that claims an authorization artifact was created', async () => {
    const harness = createHarness({
      ...stateProjection,
      persistedState: { ...stateProjection.persistedState, grantCount: 1 },
    });

    await expect(
      runAuthorizationPkceMethodRejected(harness.context, {
        random: { codeVerifier: () => verifier, state: () => privateState },
      })
    ).rejects.toThrow('Phase 1 rejected PKCE method state is invalid');
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, unicorn/text-encoding-identifier-case */
