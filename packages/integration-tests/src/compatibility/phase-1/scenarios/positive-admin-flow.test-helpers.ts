/* eslint-disable complexity, max-lines, max-params, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- The focused admin protocol harness records one complete credential-bearing flow while keeping secrets inside the shared memory store. */
import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTHeaderParameters } from 'jose';

import type { JsonObject } from '../../normalize.js';
import { SymbolTable } from '../../symbol-table.js';
import {
  MemoryProtocolSecretStore,
  protocolHeaderPairs,
  type ProtocolRequestOptions,
} from '../clients/oidc.js';
import { getPhase1FixtureRuntimeEmail, getPhase1FixtureRuntimeUsername } from '../fixture-map.js';
import type { Phase1FixtureSecretLease } from '../fixtures.js';
import type { Phase1ScenarioRunContext } from '../model.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

export const adminTestTarget = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});

const allocationId = 'admin-allocation';
export const adminRuntime = Object.freeze({
  userId: 'runtime-admin-user',
  username: getPhase1FixtureRuntimeUsername('phase1-admin', allocationId),
  email: getPhase1FixtureRuntimeEmail('phase1-admin@example.com', allocationId),
});

export const adminSecrets = Object.freeze({
  password: 'private-admin-password',
  verifier: 'v'.repeat(64),
  state: 'private-admin-state',
  verificationId: 'private-admin-verification',
  resume: 'private-admin-resume',
  code: 'private-admin-code',
  initialAccess: 'private-admin-opaque-access',
  initialRefresh: 'private-admin-initial-refresh',
  managementRefresh: 'private-admin-management-refresh',
  accountAuthorityRefresh: 'private-admin-account-authority-refresh',
  organizationRefresh: 'private-admin-organization-refresh',
});

export type AdminTestSigner = Readonly<{
  jwk: JWK;
  sign(
    claims: Readonly<Record<string, unknown>>,
    protectedHeader?: Readonly<Record<string, unknown>>
  ): Promise<string>;
}>;

export const createAdminTestSigner = async (): Promise<AdminTestSigner> => {
  const { privateKey, publicKey } = await generateKeyPair('ES384');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'admin-test-key', alg: 'ES384' };

  return Object.freeze({
    jwk,
    sign: async (claims, protectedHeader = {}) =>
      new SignJWT({ ...claims })
        .setProtectedHeader({
          ...protectedHeader,
          alg: 'ES384',
          kid: 'admin-test-key',
        } as JWTHeaderParameters)
        .sign(privateKey),
  });
};

export type AdminTokenBodies = Readonly<{
  initial: Readonly<Record<string, unknown>>;
  management?: Readonly<Record<string, unknown>>;
  managementMissingScope?: Readonly<Record<string, unknown>>;
  accountAuthority?: Readonly<Record<string, unknown>>;
  organization?: Readonly<Record<string, unknown>>;
  userinfoMissingOpenId?: Readonly<Record<string, unknown>>;
}>;

export type AdminRecordedRequest = Readonly<{
  client: 'oidc' | 'experience';
  operation: string;
  path: string;
  options: ProtocolRequestOptions | undefined;
  cookie: string | undefined;
}>;

const profile = Object.freeze({
  fixtures: {
    adminTenant: {
      id: 'admin',
      operator: {
        id: 'phase1-admin',
        username: 'phase1-admin',
        primaryEmail: 'phase1-admin@example.com',
        roles: ['default:admin', 'user'],
        customData: { ossOnboarding: { isOnboardingDone: true } },
      },
      application: {
        id: 'admin-console',
        type: 'SPA',
        oidcClientMetadata: {
          redirectUris: ['https://oracle-admin.example/console/callback'],
          postLogoutRedirectUris: [],
        },
        customClientMetadata: {},
      },
      resources: [
        { indicator: 'https://default.logto.app/api', scopes: ['all'] },
        { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
        {
          indicator: 'urn:logto:resource:organizations',
          scopes: ['urn:logto:scope:organizations', 'urn:logto:scope:organization_roles'],
        },
      ],
      tenantOrganization: {
        id: 't-default',
        name: 'Tenant default',
        memberUserIds: ['phase1-admin'],
        scopes: [
          'read:data',
          'write:data',
          'delete:data',
          'read:member',
          'invite:member',
          'remove:member',
          'update:member:role',
          'manage:tenant',
        ],
        organizationRoles: [
          {
            id: 'admin',
            name: 'admin',
            type: 'User',
            scopeNames: [
              'read:data',
              'write:data',
              'delete:data',
              'read:member',
              'invite:member',
              'remove:member',
              'update:member:role',
              'manage:tenant',
            ],
            userIds: ['phase1-admin'],
          },
        ],
      },
    },
  },
  consoleAuthentication: {
    endpoint: adminTestTarget.adminUrl.slice(0, -1),
    issuer: `${adminTestTarget.adminUrl}oidc`,
    managementDataTenant: 'default',
    applicationId: 'admin-console',
    redirectUri: `${adminTestTarget.adminUrl}console/callback`,
    prompt: ['login', 'consent'],
    grants: ['authorization_code', 'refresh_token'],
    configuredResources: ['https://default.logto.app/api', 'https://admin.logto.app/me'],
    effectiveResources: [
      'https://default.logto.app/api',
      'https://admin.logto.app/me',
      'urn:logto:resource:organizations',
    ],
    configuredScopes: [
      'profile',
      'email',
      'phone',
      'identities',
      'custom_data',
      'urn:logto:scope:organizations',
      'urn:logto:scope:organization_roles',
      'all',
    ],
    effectiveScopes: [
      'openid',
      'offline_access',
      'profile',
      'email',
      'phone',
      'identities',
      'custom_data',
      'urn:logto:scope:organizations',
      'urn:logto:scope:organization_roles',
      'all',
    ],
  },
  consoleOrganizationTokenRequest: {
    form: {
      client_id: 'admin-console',
      grant_type: 'refresh_token',
      refresh_token: 'in-memory credential omitted from evidence',
      organization_id: 't-default',
      resource: null,
      scope: null,
    },
    expectedStatus: 200,
    requiredTokenResponseProjection: { token_type: 'Bearer', scope: '' },
    requiredAccessTokenProjection: {
      format: 'JWT',
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: 'phase1-admin',
      aud: 'urn:logto:organization:t-default',
      client_id: 'admin-console',
      scope: '',
    },
    requiredAccessTokenOmissions: ['organization_id'],
  },
  oidc: {
    authorizationPath: '/oidc/auth',
    tokenPath: '/oidc/token',
    jwksPath: '/oidc/jwks',
    idTokenSigningAlgorithmsSupported: ['ES384'],
  },
});

const fixtureMap = Object.freeze({
  schemaVersion: 1 as const,
  recipe: 'adminConsole' as const,
  allocations: Object.freeze([
    Object.freeze({
      allocationId,
      role: 'admin' as const,
      target: 'primary' as const,
      isolation: Object.freeze({
        persistenceId: 'admin-persistence',
        cookieKeyId: 'admin-cookie',
        signingKeyId: 'admin-signing',
      }),
      entities: Object.freeze([
        Object.freeze({ kind: 'tenant' as const, logicalId: 'admin', runtimeId: 'admin' }),
        Object.freeze({
          kind: 'user' as const,
          logicalId: 'phase1-admin',
          runtimeId: adminRuntime.userId,
        }),
        Object.freeze({
          kind: 'application' as const,
          logicalId: 'admin-console',
          runtimeId: 'admin-console',
        }),
        ...profile.fixtures.adminTenant.resources.map(({ indicator }, index) =>
          Object.freeze({
            kind: 'resource' as const,
            logicalId: `admin.resource.${index + 1}`,
            runtimeId: indicator,
          })
        ),
        Object.freeze({
          kind: 'organization' as const,
          logicalId: 't-default',
          runtimeId: 't-default',
        }),
      ]),
    }),
  ]),
});

const dataAllocation = Object.freeze({
  allocationId: 'data-allocation',
  role: 'data' as const,
  target: 'primary' as const,
  isolation: Object.freeze({
    persistenceId: 'data-persistence',
    cookieKeyId: 'data-cookie',
    signingKeyId: 'data-signing',
  }),
  entities: Object.freeze([]),
});

const response = (
  status: number,
  body: unknown = '',
  headers: ReadonlyArray<readonly [string, string]> = []
) =>
  Object.freeze({
    status,
    headers: Object.freeze(headers.map((header) => Object.freeze(header))),
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

const callbackLocation = () => {
  const callback = new URL(profile.consoleAuthentication.redirectUri);

  callback.searchParams.set('code', adminSecrets.code);
  callback.searchParams.set('state', adminSecrets.state);
  callback.searchParams.set('iss', profile.consoleAuthentication.issuer);
  return callback.href;
};

const headerValue = (
  headers: ProtocolRequestOptions['headers'],
  name: string
): string | undefined =>
  protocolHeaderPairs(headers).find(([candidate]) => candidate.toLowerCase() === name)?.[1];

export const createAdminScenarioHarness = (
  input: Readonly<{
    jwk: JWK;
    tokens: AdminTokenBodies;
    includeDataAllocation?: boolean;
    resumeStatus?: number;
    callbackLocations?: readonly string[];
    resumeBody?: string;
    resumeRedirectTo?: string;
    accountBody?: JsonObject;
  }>
) => {
  const store = new MemoryProtocolSecretStore();
  const dataStore = new MemoryProtocolSecretStore();
  const records: AdminRecordedRequest[] = [];
  const stateReads: string[] = [];
  const symbols = new SymbolTable();
  const dataSymbols = new SymbolTable();
  const [allocation] = fixtureMap.allocations;
  const publicMap = input.includeDataAllocation
    ? Object.freeze({
        ...fixtureMap,
        recipe: 'fullPhase1' as const,
        allocations: Object.freeze([...fixtureMap.allocations, dataAllocation]),
      })
    : fixtureMap;

  if (!allocation) {
    throw new Error('missing admin test allocation');
  }
  for (const entity of allocation.entities) {
    symbols.bind(`${entity.kind}.${entity.logicalId}`, entity.runtimeId);
  }
  symbols.bind('fixture.admin.username', adminRuntime.username);
  symbols.bind('fixture.admin.email', adminRuntime.email);

  const applyCookies = (
    raw: ReturnType<typeof response>,
    requestUrl: URL
  ): ReturnType<typeof response> => {
    for (const [name, value] of raw.headers) {
      if (name.toLowerCase() === 'set-cookie') {
        store.setCookie(value, requestUrl);
      }
    }

    return raw;
  };
  const record = (
    client: AdminRecordedRequest['client'],
    operation: string,
    path: string,
    options: ProtocolRequestOptions | undefined,
    url: URL
  ) => {
    records.push({ client, operation, path, options, cookie: store.getCookieHeader(url) });
  };
  const oidc = {
    store,
    request: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        const url = new URL(path, adminTestTarget.adminUrl);
        record('oidc', operation, path, options, url);

        if (operation === 'admin-authorization-start') {
          return applyCookies(
            response(303, 'Redirecting to /sign-in.', [
              ['location', '/sign-in'],
              ['set-cookie', '_interaction=private-admin-cookie; Path=/; HttpOnly; SameSite=Lax'],
              [
                'set-cookie',
                '_interaction.sig=private-admin-cookie-signature; Path=/; HttpOnly; SameSite=Lax',
              ],
            ]),
            url
          );
        }
        if (operation === 'admin-authorization-resume') {
          const locations = input.callbackLocations ?? [callbackLocation()];

          return applyCookies(
            response(input.resumeStatus ?? 303, input.resumeBody ?? 'Redirecting.', [
              ...locations.map((location) => ['location', location] as const),
              ['content-type', 'text/html; charset=utf-8'],
              ['set-cookie', '_interaction=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'],
            ]),
            url
          );
        }
        if (operation === 'admin-token-jwks') {
          return response(200, { keys: [input.jwk] }, [
            ['content-type', 'application/jwk-set+json'],
          ]);
        }
        const tokenBody =
          operation === 'admin-token-authorization-code'
            ? input.tokens.initial
            : operation === 'admin-token-management-refresh'
              ? input.tokens.management
              : operation === 'admin-token-management-missing-scope-refresh'
                ? input.tokens.managementMissingScope
                : operation === 'admin-token-account-authority-refresh'
                  ? input.tokens.accountAuthority
                  : operation === 'admin-token-organization-refresh'
                    ? input.tokens.organization
                    : operation === 'admin-token-userinfo-missing-openid-refresh'
                      ? input.tokens.userinfoMissingOpenId
                      : undefined;

        if (tokenBody) {
          return response(200, tokenBody, [['content-type', 'application/json']]);
        }

        throw new Error(`unexpected OIDC operation: ${operation}`);
      }
    ),
  };
  const experience = {
    store,
    requestExperience: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        const url = new URL(path, new URL('/api/', adminTestTarget.adminUrl));
        record('experience', operation, path, options, url);

        if (operation === 'admin-experience-bootstrap') {
          return response(204);
        }
        if (operation === 'admin-experience-password') {
          expect(options?.body).toContain(adminSecrets.password);
          return response(200, { verificationId: adminSecrets.verificationId }, [
            ['content-type', 'application/json'],
          ]);
        }
        if (operation === 'admin-experience-identify') {
          return response(204);
        }
        if (operation === 'admin-experience-submit') {
          return applyCookies(
            response(
              200,
              {
                redirectTo:
                  input.resumeRedirectTo ??
                  `${adminTestTarget.adminUrl}oidc/auth/${adminSecrets.resume}`,
              },
              [
                ['content-type', 'application/json'],
                [
                  'set-cookie',
                  `_interaction_resume=${adminSecrets.resume}; Path=/oidc/auth/${adminSecrets.resume}; HttpOnly; SameSite=Lax`,
                ],
              ]
            ),
            url
          );
        }

        throw new Error(`unexpected Experience operation: ${operation}`);
      }
    ),
  };
  const management = {
    store,
    requestManagement: import.meta.jest.fn(async () => {
      throw new Error('unexpected management request');
    }),
  };
  const account = {
    store,
    requestAccount: import.meta.jest.fn(async (operation: string, path: string) => {
      const initialAccessToken = input.tokens.initial.access_token;

      if (
        !input.accountBody ||
        operation !== 'account-admin-operator-read' ||
        path !== 'my-account/' ||
        typeof initialAccessToken !== 'string' ||
        store.getToken('account') !== initialAccessToken
      ) {
        throw new Error('unexpected account request');
      }

      return response(200, input.accountBody, [
        ['content-type', 'application/json; charset=utf-8'],
      ]);
    }),
  };
  const dataClients = {
    oidc: { store: dataStore, request: import.meta.jest.fn() },
    experience: { store: dataStore, requestExperience: import.meta.jest.fn() },
    consent: { store: dataStore, requestConsent: import.meta.jest.fn() },
    management: { store: dataStore, requestManagement: import.meta.jest.fn() },
    account: { store: dataStore, requestAccount: import.meta.jest.fn() },
    state: { store: dataStore, requestState: import.meta.jest.fn() },
  };
  const context: Phase1ScenarioRunContext = {
    profile: profile as never,
    target: adminTestTarget,
    fixture: {
      public: publicMap,
      withSecretLease: async <Result>(use: (lease: Phase1FixtureSecretLease) => Promise<Result>) =>
        use({ getPassword: () => adminSecrets.password } as never),
    } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: { request: oidc.request, allocationRole: undefined } as never,
      publicSymbols: new SymbolTable(),
      forAllocation: (role) =>
        role === 'data'
          ? dataClients
          : {
              oidc,
              experience,
              consent: { store } as never,
              management,
              account,
              state: { store } as never,
            },
      symbolsFor: (requestedAllocationId) =>
        requestedAllocationId === dataAllocation.allocationId ? dataSymbols : symbols,
    },
    projectFixtureState: async () => ({
      schemaVersion: 1,
      recipe: publicMap.recipe,
      allocations: [],
    }),
    projectScenarioState: async ({
      scenarioId,
      stepId,
    }): Promise<Phase1ScenarioStateProjectionInput> => {
      stateReads.push(`${scenarioId}:${stepId}`);
      const isFinal = stepId === 'state';
      const persistedState: JsonObject =
        scenarioId === 'account.admin-operator-read'
          ? { unrelatedMutation: false }
          : scenarioId === 'console.admin-organization-token-refresh' && isFinal
            ? {
                grantConsumed: true,
                familyCount: 1,
                rotation: { replaced: true, sameFamily: true },
                tenantMutation: false,
                membershipMutation: false,
                roleMutation: false,
                consentMutation: false,
              }
            : isFinal
              ? {
                  grantConsumed: true,
                  familyCount: 1,
                  rotation: { replaced: true, sameFamily: true },
                  unrelatedMutation: false,
                }
              : { unrelatedMutation: false };

      return {
        body: { observed: true },
        semanticState: { unrelatedMutation: false },
        persistedState,
        generatedIds:
          stepId === 'authorize'
            ? { interaction: '<interaction.1>' }
            : isFinal
              ? { tokenFamily: '<token-family.1>' }
              : {},
        sideEffects: { unrelatedMutation: false },
      };
    },
  };

  return Object.freeze({
    context,
    records,
    stateReads,
    store,
    dataStore,
    management,
    account,
  });
};

export const tokenBody = (
  accessToken: string,
  idToken: string,
  refreshToken: string,
  scope: string
) => ({
  access_token: accessToken,
  id_token: idToken,
  refresh_token: refreshToken,
  token_type: 'Bearer',
  expires_in: 3600,
  scope,
});

export const requestForm = (record: AdminRecordedRequest | undefined) =>
  Object.fromEntries(new URLSearchParams(record?.options?.body));

export const requestContentType = (record: AdminRecordedRequest | undefined) =>
  headerValue(record?.options?.headers, 'content-type');

/* eslint-enable complexity, max-lines, max-params, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
