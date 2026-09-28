/* eslint-disable complexity, max-lines, @typescript-eslint/prefer-nullish-coalescing, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, @typescript-eslint/no-loop-func, unicorn/consistent-function-scoping -- The test double records ordered multi-flow calls and marks operation-produced projections. */
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type {
  DeviceAuthorizationProjection,
  DeviceAuthorizationTransportLease,
  DeviceCodeLease,
  DeviceCredentialLease,
  DeviceLifecycleProjection,
  DeviceVerificationXsrfLease,
  DeviceVerificationUserCodeLease,
} from '../clients/device-authorization.js';
import { createDeviceAuthorizationTransportLease } from '../clients/device-authorization.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2ProfileRegistries } from '../profile.js';
import type {
  DeviceCredentialProjection,
  DeviceCredentialProjectionInput,
} from '../projections/device-authorization.js';

import {
  createDeviceAuthorizationScenarioRegistry,
  compareDeviceScenarioProjections,
  createDeviceConcurrencyBarrierFetch,
  deviceAuthorizationScenarioIds,
  publishDeviceScenarioProjection,
  runDeviceAuthorizationNegativeControls,
  type DeviceAuthorizationScenarioId,
  type DeviceScenarioProjection,
  type DeviceScenarioStateAction,
} from './device-authorization.js';

const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});
const fixture: ProvisionedPhase2Fixture = {
  public: Object.freeze({
    allocationId: 'device-scenarios-test',
    clients: Object.freeze({
      basic: Object.freeze({ id: 'basic-client', method: 'client_secret_basic' as const }),
      post: Object.freeze({ id: 'post-client', method: 'client_secret_post' as const }),
    }),
    deviceClients: Object.freeze({
      firstParty: Object.freeze({
        id: 'device-first',
        applicationType: 'Native' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: false,
        deviceGrantEnabled: true,
      }),
      thirdParty: Object.freeze({
        id: 'device-third',
        applicationType: 'Native' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: true,
        deviceGrantEnabled: true,
      }),
      missingGrant: Object.freeze({
        id: 'device-no-grant',
        applicationType: 'Native' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
      ineligibleWeb: Object.freeze({
        id: 'device-web',
        applicationType: 'SPA' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({
        id: 'primary-resource',
        indicator: 'https://phase2.example.invalid/api-primary',
      }),
      default: Object.freeze({
        id: 'default-resource',
        indicator: 'https://phase2.example.invalid/api-default',
      }),
    }),
    organization: Object.freeze({ id: 'phase2-org', scopeName: 'organization:read' as const }),
    scopes: Object.freeze({
      read: Object.freeze({ id: 'read-id', name: 'read' as const }),
      write: Object.freeze({ id: 'write-id', name: 'write' as const }),
      unassigned: Object.freeze({ id: 'unassigned-id', name: 'unassigned' as const }),
    }),
    boundary: Object.freeze({ primary: 'provisioned' as const, foreign: 'unchanged' as const }),
  }),
  status: Object.freeze({
    user: Object.freeze({ id: 'phase2-user-id', username: 'phase2-user' }),
    client: Object.freeze({ id: 'status-client', redirectUri: 'https://status.example/callback' }),
    confidentialClient: Object.freeze({
      id: 'status-confidential',
      redirectUri: 'https://status.example/confidential',
    }),
    resource: Object.freeze({
      id: 'status-resource',
      indicator: 'https://status.example/api',
      scopeName: 'read:profile',
    }),
  }),
  withSecretLease: async (use) =>
    use({
      getClientSecret: () => 'private-machine-secret',
      getStatusClientSecret: () => 'private-status-secret',
      getSubjectPassword: () => 'private-subject-password',
      toJSON: () => {
        throw new TypeError('secret');
      },
    }),
};
const profile = (ids: readonly string[] = deviceAuthorizationScenarioIds) =>
  ({ differentialScenarios: ids }) as unknown as Phase2ProfileRegistries;

const authorizationProjection = {
  status: 200,
  contentType: 'application/json',
  headers: {},
  keys: [],
  cookies: [],
  challenge: undefined,
  location: undefined,
  oauthError: { category: undefined, description: undefined },
  userCodeShape: undefined,
  deviceCodeShape: undefined,
  expiresIn: undefined,
  interval: undefined,
  tokenType: undefined,
  verificationUri: undefined,
  verificationUriComplete: undefined,
  experience: undefined,
} as DeviceAuthorizationProjection;
const authorizationResponse = (status = 200): DeviceAuthorizationProjection => ({
  ...authorizationProjection,
  status,
  headers: {},
  keys: [],
  cookies: [],
  oauthError: { category: undefined, description: undefined },
});
const concurrencyResponse = (winner: boolean): DeviceAuthorizationProjection => ({
  ...authorizationResponse(winner ? 200 : 400),
  headers: {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'WWW-Authenticate',
    'cache-control': 'no-store',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'x-content-type-options': 'nosniff',
  },
  keys: winner
    ? ['access_token', 'expires_in', 'id_token', 'scope', 'token_type']
    : ['code', 'error', 'error_description', 'error_uri', 'message'],
  oauthError: winner
    ? { category: undefined, description: undefined }
    : { category: 'invalid_grant', description: 'grant request is invalid' },
  expiresIn: winner ? 3600 : undefined,
  tokenType: winner ? 'Bearer' : undefined,
});
const lifecycleProjection = (
  kind: DeviceLifecycleProjection['kind']
): DeviceLifecycleProjection => {
  const base = {
    kind,
    status: 200,
    contentType: 'application/json',
    headers: {},
    cookies: [],
    challenge: undefined,
    location: undefined,
    oauthError: { category: undefined, description: undefined },
  };
  const facts = (() => {
    switch (kind) {
      case 'verification-success': {
        return { marker: 'device-success', shell: 'experience-app' };
      }
      case 'experience-open': {
        return { marker: 'experience-opened' };
      }
      case 'password-verification': {
        return { marker: 'password-verified' };
      }
      case 'identification': {
        return { marker: 'subject-identified' };
      }
      case 'experience-submit': {
        return {
          marker: 'experience-submitted',
          redirect: { origin: target.coreUrl.slice(0, -1), path: '/resume', queryKeys: [] },
        };
      }
      case 'consent-read': {
        return {
          marker: 'consent-presented',
          redirectUriAbsent: true,
          missingOidcScopes: [],
          missingResourceScopeCount: 0,
        };
      }
      case 'consent-write': {
        return {
          marker: 'consent-recorded',
          redirect: { origin: target.coreUrl.slice(0, -1), path: '/resume', queryKeys: [] },
        };
      }
      case 'resume': {
        return { marker: 'device-success-redirect', stage: 'after-consent-write' };
      }
      case 'refresh': {
        return { marker: 'oauth-error' };
      }
      case 'userinfo': {
        return { marker: 'userinfo', subject: '<subject>', keys: ['sub'] };
      }
      case 'introspection': {
        return {
          marker: 'introspection',
          active: true,
          subject: '<subject>',
          clientId: '<client>',
          issuer: '<target-issuer>',
          issuedAt: '<issued-at>',
          lifetimeSeconds: 3600,
          scopes: ['openid'],
        };
      }
      case 'revocation': {
        return { marker: 'revoked' };
      }
      case 'logout-open': {
        return { marker: 'logout-finished' };
      }
      case 'logout-confirm': {
        return { marker: 'logout-finished' };
      }
      case 'oidc-discovery':
      case 'oauth-discovery': {
        const endpoint = (path: string) => ({
          origin: target.coreUrl.slice(0, -1),
          path,
          queryKeys: [],
        });
        return {
          marker: kind,
          issuer: '<target-issuer>',
          endpoints: {
            authorization_endpoint: endpoint('/oidc/auth'),
            token_endpoint: endpoint('/oidc/token'),
            jwks_uri: endpoint('/oidc/jwks'),
            userinfo_endpoint: endpoint('/oidc/me'),
            device_authorization_endpoint: endpoint('/oidc/device/auth'),
            introspection_endpoint: endpoint('/oidc/token/introspection'),
            revocation_endpoint: endpoint('/oidc/token/revocation'),
            end_session_endpoint: endpoint('/oidc/session/end'),
          },
          keys: ['issuer'],
        };
      }
    }
  })();
  return { ...base, facts } as DeviceLifecycleProjection;
};
const credentialProjection = {
  access: { format: 'opaque', present: true },
  id: undefined,
  refresh: undefined,
} as DeviceCredentialProjection;
const absentPreviousRefreshToken: string | undefined = undefined;

const expectedPrimaryOperation = (id: DeviceAuthorizationScenarioId): string => {
  if (id.startsWith('device-authorization.')) {
    if (id === 'device-authorization.json-object-success') {
      return 'authorize:json';
    }
    return [
      'device-authorization.malformed-form',
      'device-authorization.malformed-json',
      'device-authorization.unknown-extension',
      'device-authorization.json-array-rejected',
      'device-authorization.text-body-rejected',
    ].includes(id)
      ? 'authorize:raw'
      : 'authorize:form';
  }
  if (id === 'device-verification.shortcut-redirect') {
    return 'verify:GET:/device';
  }
  if (id === 'device-verification.complete-url-entry') {
    return 'verify:GET:<projected-location>';
  }
  if (id === 'device-verification.success-page') {
    return 'lifecycle:verification-success';
  }
  if (id.startsWith('device-verification.')) {
    return 'verify:POST:/oidc/device';
  }
  if (id.startsWith('device-consent.')) {
    return 'lifecycle:consent-read';
  }
  if (id.startsWith('device-discovery.')) {
    return id.endsWith('oidc') ? 'lifecycle:oidc-discovery' : 'lifecycle:oauth-discovery';
  }
  if (id.startsWith('device-token-status.')) {
    return id.endsWith('revocation') ? 'lifecycle:revocation' : 'lifecycle:introspection';
  }
  if (
    id === 'device-token.id-token-signature-and-claims' ||
    id === 'device-token.resource-authority' ||
    id === 'device-token.organization-authority' ||
    id === 'device-token.refresh-resource-selection' ||
    id === 'device-token.refresh-organization-selection'
  ) {
    return 'credential-lease';
  }
  if (id === 'device-token.userinfo' || id === 'device-token.session-bound-expiry') {
    return 'lifecycle:userinfo';
  }
  if (id.includes('refresh')) {
    return 'lifecycle:refresh';
  }
  return 'poll';
};

describe('Phase 2 device authorization scenarios', () => {
  it('requires the exact ordered 69-ID device segment', () => {
    expect(createDeviceAuthorizationScenarioRegistry(profile()).map(({ id }) => id)).toEqual(
      deviceAuthorizationScenarioIds
    );
    const mutations = [
      deviceAuthorizationScenarioIds.slice(1),
      deviceAuthorizationScenarioIds.with(1, deviceAuthorizationScenarioIds[0]),
      [
        deviceAuthorizationScenarioIds[1],
        deviceAuthorizationScenarioIds[0],
        ...deviceAuthorizationScenarioIds.slice(2),
      ],
      [...deviceAuthorizationScenarioIds, 'device-token.extra'],
    ];
    for (const ids of mutations) {
      expect(() => createDeviceAuthorizationScenarioRegistry(profile(ids))).toThrow(
        'Invalid Phase 2 device authorization scenario'
      );
    }
  });

  it('sends the exact oracle-pinned admission request bytes', async () => {
    const calls: Array<readonly [string, RequestInit]> = [];
    const registry = new Map(
      createDeviceAuthorizationScenarioRegistry(profile()).map((scenario) => [
        scenario.id,
        scenario,
      ])
    );
    const request = async (id: DeviceAuthorizationScenarioId) => {
      calls.length = 0;
      await registry.get(id)?.run({
        target,
        fixture,
        jwks: { keys: [] } as JSONWebKeySet,
        state: {
          withDeviceHandle: async (_scenarioId, _fixture, use) =>
            use({
              capture: async () => {
                // Admission scenarios never open a state handle.
              },
              transition: async () => {
                // Admission scenarios never request a state transition.
              },
            }),
        },
        createTransport: (options) =>
          createDeviceAuthorizationTransportLease({
            ...options,
            fetch: (async (input, init) => {
              calls.push([String(input), init ?? {}]);
              return new Response(
                JSON.stringify({
                  error: 'invalid_request',
                  error_description: 'request is invalid',
                }),
                { status: 400, headers: { 'content-type': 'application/json' } }
              );
            }) as typeof fetch,
          }),
      });
      expect(calls).toHaveLength(1);
      const [url, init] = calls[0] ?? [];
      return {
        url,
        method: init?.method,
        contentType: new Headers(init?.headers).get('content-type'),
        authorization: new Headers(init?.headers).get('authorization'),
        body: String(init?.body ?? ''),
      };
    };
    const form = (body: string) => ({
      url: 'https://candidate.example/oidc/device/auth',
      method: 'POST',
      contentType: 'application/x-www-form-urlencoded',
      authorization: null,
      body,
    });
    await expect(request('device-authorization.json-object-success')).resolves.toEqual({
      ...form('{"client_id":"device-first","scope":"openid"}'),
      contentType: 'application/json',
    });
    await expect(request('device-authorization.unknown-client')).resolves.toEqual(
      form('client_id=unknown-device-client&scope=openid')
    );
    await expect(request('device-authorization.ineligible-web-client')).resolves.toEqual(
      form('client_id=device-web&scope=openid')
    );
    await expect(request('device-authorization.confidential-client')).resolves.toEqual({
      ...form('client_id=status-confidential&scope=openid'),
      authorization: `Basic ${Buffer.from(
        'status-confidential:private-status-secret',
        'utf8'
      ).toString('base64')}`,
    });
    await expect(request('device-authorization.public-client-basic-rejected')).resolves.toEqual({
      ...form('client_id=device-first&scope=openid'),
      authorization: `Basic ${Buffer.from('device-first:', 'utf8').toString('base64')}`,
    });
    await expect(
      request('device-authorization.public-client-secret-post-rejected')
    ).resolves.toEqual(form('client_id=device-first&client_secret=incorrect-secret&scope=openid'));
    await expect(request('device-authorization.duplicate-client')).resolves.toEqual(
      form('client_id=device-first&client_id=device-first&scope=openid')
    );
    const resource = encodeURIComponent(fixture.public.resources.primary.indicator);
    await expect(request('device-authorization.duplicate-resource')).resolves.toEqual(
      form(`client_id=device-first&resource=${resource}&resource=${resource}`)
    );
    await expect(request('device-authorization.unknown-resource')).resolves.toEqual(
      form('client_id=device-first&resource=https%3A%2F%2Funknown.invalid%2Fapi')
    );
    await expect(request('device-authorization.malformed-json')).resolves.toEqual({
      ...form('{"client_id":'),
      contentType: 'application/json',
    });
    await expect(request('device-authorization.query-only-rejected')).resolves.toEqual({
      ...form(''),
      url: 'https://candidate.example/oidc/device/auth?client_id=device-first&scope=openid',
    });
    await expect(request('device-authorization.unknown-scope')).resolves.toEqual(
      form('client_id=device-first&scope=unknown_scope')
    );
    await expect(request('device-authorization.unsupported-parameter')).resolves.toEqual(
      form('client_id=device-first&request_uri=x')
    );
  });

  it('executes a transport, lifecycle, credential projection or state operation for every ID', async () => {
    const produced = new WeakSet<Record<string, unknown>>();
    const operations = new Map<DeviceAuthorizationScenarioId, string[]>();
    const credentialInputs = new Map<
      DeviceAuthorizationScenarioId,
      DeviceCredentialProjectionInput
    >();
    const stateOperations = new Map<DeviceAuthorizationScenarioId, DeviceScenarioStateAction[]>();
    let activeId: DeviceAuthorizationScenarioId | undefined;
    let secretLeaseActive = false;
    const mark = <Projection extends DeviceScenarioProjection>(
      projection: Projection
    ): Projection => {
      produced.add(projection);
      return projection;
    };
    const record = (operation: string) => {
      if (!activeId) {
        throw new TypeError('missing active ID');
      }
      const current = operations.get(activeId) ?? [];
      current.push(operation);
      operations.set(activeId, current);
    };
    const createTransport = (): DeviceAuthorizationTransportLease => ({
      requestAuthorization: async (request) => {
        record(`authorize:${request.encoding}`);
        if (
          request.encoding === 'form' &&
          (activeId === 'device-token.refresh-resource-selection' ||
            activeId === 'device-token.refresh-organization-selection')
        ) {
          expect(request.fields).toContainEqual([
            activeId.endsWith('resource-selection') ? 'resource' : 'organization_id',
            activeId.endsWith('resource-selection')
              ? fixture.public.resources.primary.indicator
              : fixture.public.organization.id,
          ]);
        }
        if (
          request.encoding === 'form' &&
          (activeId === 'device-token.organization-authority' ||
            activeId === 'device-token.refresh-organization-selection')
        ) {
          expect(request.fields).toContainEqual([
            'scope',
            'openid offline_access urn:aster:scope:organizations',
          ]);
        }
        return mark(authorizationResponse());
      },
      requestVerification: async (request) => {
        record(
          request.method === 'FOLLOW_PROJECTED_LOCATION'
            ? 'verify:GET:<projected-location>'
            : `verify:${request.method}:${request.path}`
        );
        if (
          activeId === 'device-verification.complete-url-entry' &&
          request.method === 'GET' &&
          request.path === '/device'
        ) {
          return mark({
            ...authorizationResponse(302),
            contentType: 'text/html',
            location: {
              origin: target.coreUrl.slice(0, -1),
              path: '/oidc/device',
              queryKeys: ['user_code'],
            },
          });
        }
        if (
          activeId === 'device-verification.complete-url-entry' &&
          request.method === 'FOLLOW_PROJECTED_LOCATION'
        ) {
          return mark({ ...authorizationResponse(), contentType: 'text/html' });
        }
        return mark(authorizationResponse());
      },
      pollToken: async () => {
        record('poll');
        const pollCount = operations
          .get(activeId ?? deviceAuthorizationScenarioIds[0])
          ?.filter((entry) => entry === 'poll').length;
        return mark(
          activeId === 'device-token.concurrent-reference-multi-winner'
            ? concurrencyResponse((pollCount ?? 0) % 2 !== 0)
            : authorizationResponse()
        );
      },
      requestLifecycle: async (request) => {
        record(`lifecycle:${request.kind}`);
        if (request.kind === 'refresh' && activeId === 'device-token.refresh-resource-selection') {
          expect(request).toMatchObject({
            resource: fixture.public.resources.primary.indicator,
            scope: 'read',
          });
        }
        if (
          request.kind === 'refresh' &&
          activeId === 'device-token.refresh-organization-selection'
        ) {
          expect(request).toMatchObject({
            organizationId: fixture.public.organization.id,
          });
          expect(request).not.toHaveProperty('scope');
          return mark({
            ...lifecycleProjection('refresh'),
            facts: {
              marker: 'tokens-refreshed',
              tokenType: 'Bearer',
              expiresIn: 3600,
              refreshRotated: true,
              idTokenIssued: true,
              scopes: [],
            },
          } as DeviceLifecycleProjection);
        }
        if (request.kind === 'password-verification') {
          expect(secretLeaseActive).toBe(true);
          expect(request.password).toBe('private-subject-password');
        }
        const rawBase = lifecycleProjection(request.kind);
        const base =
          request.kind === 'introspection'
            ? ({
                ...rawBase,
                facts:
                  request.token === 'access'
                    ? { ...rawBase.facts, credentialKind: 'access' }
                    : {
                        marker: 'introspection',
                        active: true,
                        credentialKind: 'refresh',
                        subject: '<subject>',
                        clientId: '<client>',
                        issuer: '<target-issuer>',
                        issuedAt: '<issued-at>',
                        lifetimeSeconds: 1_209_600,
                        scopes: ['openid'],
                      },
              } as DeviceLifecycleProjection)
            : rawBase;
        const calls = operations.get(activeId ?? deviceAuthorizationScenarioIds[0]) ?? [];
        const sameKindCount = calls.filter((entry) => entry === `lifecycle:${request.kind}`).length;
        if (
          request.kind === 'introspection' &&
          ((activeId?.endsWith('revocation') && sameKindCount > 2) ||
            (activeId === 'device-token.session-bound-expiry' && sameKindCount > 1))
        ) {
          return mark({
            ...base,
            facts: { marker: 'introspection', active: false },
          } as DeviceLifecycleProjection);
        }
        if (
          request.kind === 'userinfo' &&
          activeId === 'device-token.session-bound-expiry' &&
          sameKindCount > 1
        ) {
          return mark({
            ...base,
            status: 401,
            oauthError: { category: 'invalid_token', description: undefined },
            facts: { marker: 'oauth-error' },
          } as DeviceLifecycleProjection);
        }
        if (request.kind === 'refresh' && activeId === 'device-token-status.access-revocation') {
          return mark({
            ...base,
            status: 400,
            oauthError: { category: 'invalid_grant', description: undefined },
          } as DeviceLifecycleProjection);
        }
        return mark(base);
      },
      withCredentialLease: async <Result>(
        use: (lease: DeviceCredentialLease) => Result | Promise<Result>
      ) => {
        record('credential-lease');
        return use({
          getAccessToken: () => 'private-access',
          getRefreshToken: () => 'private-refresh',
          getIdToken: () => 'private-id',
          getPreviousRefreshToken: () => absentPreviousRefreshToken,
          toJSON: () => {
            throw new TypeError('secret');
          },
        });
      },
      withVerificationXsrfLease: async <Result>(
        use: (lease: DeviceVerificationXsrfLease) => Result | Promise<Result>
      ) => {
        record('xsrf-lease');
        return use({
          getXsrf: () => 'private-xsrf',
          toJSON: () => {
            throw new TypeError('secret');
          },
        });
      },
      withVerificationUserCodeLease: async <Result>(
        use: (lease: DeviceVerificationUserCodeLease) => Result | Promise<Result>
      ) => {
        record('user-code-lease');
        return use({
          getUserCode: () => 'BCDF-GHJK',
          getXsrf: () => 'private-xsrf',
          toJSON: () => {
            throw new TypeError('secret');
          },
        });
      },
      withDeviceCodeLease: async <Result>(
        use: (lease: DeviceCodeLease) => Result | Promise<Result>
      ) => {
        record('device-code-lease');
        return use({
          getDeviceCode: () => 'private-device-code',
          toJSON: () => {
            throw new TypeError('secret');
          },
        });
      },
      clear: () => {
        record('clear');
      },
      toJSON: () => {
        throw new TypeError('lease');
      },
    });
    const scopedFixture: ProvisionedPhase2Fixture = {
      ...fixture,
      withSecretLease: async (use) => {
        secretLeaseActive = true;
        const secret = {
          getClientSecret: () => {
            if (!secretLeaseActive) {
              throw new TypeError('inactive secret lease');
            }
            return 'private-machine-secret';
          },
          getStatusClientSecret: () => {
            if (!secretLeaseActive) {
              throw new TypeError('inactive secret lease');
            }
            return 'private-status-secret';
          },
          getSubjectPassword: () => {
            if (!secretLeaseActive) {
              throw new TypeError('inactive secret lease');
            }
            return 'private-subject-password';
          },
          toJSON: (): never => {
            throw new TypeError('secret');
          },
        };
        try {
          const result = await use(secret);
          expect(JSON.stringify(result)).not.toContain('private-subject-password');
          return result;
        } finally {
          secretLeaseActive = false;
        }
      },
    };
    const registry = createDeviceAuthorizationScenarioRegistry(profile());
    for (const scenario of registry) {
      activeId = scenario.id;
      const result = await scenario.run({
        target,
        fixture: scopedFixture,
        jwks: { keys: [] } as JSONWebKeySet,
        state: {
          withDeviceHandle: async (scenarioId, _fixture, use) => {
            expect(scenarioId).toBe(activeId);
            record('state:device-begin');
            try {
              return await use({
                capture: async () => {
                  record('state:device-capture');
                },
                transition: async (action) => {
                  const current = stateOperations.get(scenarioId) ?? [];
                  current.push(action);
                  stateOperations.set(scenarioId, current);
                  record(`state:${action}`);
                },
              });
            } finally {
              record('state:device-abort');
            }
          },
        },
        createTransport,
        projectCredentials: async (input) => {
          credentialInputs.set(scenario.id, input);
          return mark({ ...credentialProjection });
        },
      });
      expect(result.id).toBe(scenario.id);
      expect(produced.has(result.projection) || Object.hasOwn(result.projection, 'kind')).toBe(
        true
      );
      expect(operations.get(scenario.id)?.some((entry) => entry !== 'clear')).toBe(true);
      expect(operations.get(scenario.id)).toContain(expectedPrimaryOperation(scenario.id));
      expect(secretLeaseActive).toBe(false);
    }
    expect(operations.size).toBe(69);
    expect(operations.get('device-token.refresh-resource-selection')?.slice(-4)).toEqual([
      'poll',
      'lifecycle:refresh',
      'credential-lease',
      'clear',
    ]);
    expect(operations.get('device-token.refresh-organization-selection')?.slice(-4)).toEqual([
      'poll',
      'lifecycle:refresh',
      'credential-lease',
      'clear',
    ]);
    expect(credentialInputs.get('device-token.resource-authority')?.expected).toMatchObject({
      accessFormat: 'opaque',
      resource: fixture.public.resources.primary.indicator,
    });
    expect(credentialInputs.get('device-token.organization-authority')?.expected).toMatchObject({
      organizationId: fixture.public.organization.id,
    });
    expect(
      credentialInputs.get('device-token.organization-authority')?.expected
    ).not.toHaveProperty('accessFormat');
    expect(credentialInputs.get('device-token.refresh-resource-selection')?.expected).toMatchObject(
      {
        accessFormat: 'verified-jwt',
        audience: fixture.public.resources.primary.indicator,
        scopes: ['read'],
      }
    );
    expect(
      credentialInputs.get('device-token.refresh-resource-selection')?.expected
    ).not.toHaveProperty('resource');
    expect(
      credentialInputs.get('device-token.refresh-organization-selection')?.expected
    ).toMatchObject({
      accessFormat: 'verified-jwt',
      audience: `urn:aster:organization:${fixture.public.organization.id}`,
      organizationId: fixture.public.organization.id,
      accessOrganizationIdRequired: false,
      scopes: [],
    });
    expect(stateOperations).toEqual(
      new Map([
        ['device-verification.expired-code', ['expire']],
        ['device-verification.already-used-code', ['consume']],
        ['device-token.session-bound-expiry', ['expire-session']],
        ['device-token.expired-code', ['expire']],
      ])
    );
    expect(operations.get('device-token.in-flight-poll')).toEqual([
      'authorize:form',
      'verify:GET:/oidc/device',
      'verify:POST:/oidc/device',
      'poll',
      'clear',
    ]);
    expect(operations.get('device-verification.cross-cookie-xsrf')).toEqual([
      'authorize:form',
      'verify:GET:/oidc/device',
      'verify:GET:/oidc/device',
      'user-code-lease',
      'verify:POST:/oidc/device',
      'clear',
      'clear',
    ]);
    expect(operations.get('device-consent.approval')).toEqual(
      expect.arrayContaining([
        'lifecycle:password-verification',
        'lifecycle:consent-read',
        'lifecycle:consent-write',
        'lifecycle:resume',
      ])
    );
    expect(operations.get('device-token-status.access-introspection')).toContain(
      'lifecycle:introspection'
    );
    expect(
      operations
        .get('device-token.concurrent-reference-multi-winner')
        ?.filter(
          (entry) => entry === 'authorize:form' || entry === 'device-code-lease' || entry === 'poll'
        )
    ).toEqual([
      'authorize:form',
      'device-code-lease',
      'poll',
      'poll',
      'authorize:form',
      'device-code-lease',
      'poll',
      'poll',
      'authorize:form',
      'device-code-lease',
      'poll',
      'poll',
    ]);
    expect(operations.get('device-token-status.access-revocation')?.slice(-6)).toEqual([
      'lifecycle:introspection',
      'lifecycle:introspection',
      'lifecycle:revocation',
      'lifecycle:introspection',
      'lifecycle:refresh',
      'clear',
    ]);
    expect(operations.get('device-token-status.refresh-revocation')?.slice(-6)).toEqual([
      'lifecycle:introspection',
      'lifecycle:introspection',
      'lifecycle:revocation',
      'lifecycle:introspection',
      'lifecycle:introspection',
      'clear',
    ]);
    expect(operations.get('device-token.session-bound-expiry')?.slice(-7)).toEqual([
      'lifecycle:userinfo',
      'lifecycle:introspection',
      'state:expire-session',
      'lifecycle:userinfo',
      'lifecycle:introspection',
      'state:device-abort',
      'clear',
    ]);
    expect(operations.get('device-discovery.oauth')).toEqual([
      'lifecycle:oauth-discovery',
      'clear',
    ]);
  });

  it('detects status, path, cookie clearing, OAuth, claim-key and discovery mutations', () => {
    const authorization = {
      status: 200,
      contentType: 'application/json',
      headers: {},
      keys: [],
      cookies: [],
      challenge: undefined,
      location: undefined,
      oauthError: { category: undefined, description: undefined },
      userCodeShape: undefined,
      deviceCodeShape: undefined,
      expiresIn: undefined,
      interval: undefined,
      tokenType: undefined,
      verificationUri: { origin: 'https://candidate.example', path: '/device', queryKeys: [] },
      verificationUriComplete: undefined,
      experience: undefined,
    } as DeviceAuthorizationProjection;
    const jwt = {
      format: 'verified-jwt' as const,
      header: {
        algorithm: '<verified-signing-algorithm>' as const,
        keyId: '<verified-key>' as const,
        type: 'JWT' as const,
      },
      claims: {
        claimKeys: ['aud', 'exp', 'iat', 'iss', 'sub'],
        claimTypes: {
          aud: 'string-array' as const,
          exp: 'number' as const,
          iat: 'number' as const,
          iss: 'string' as const,
          sub: 'string' as const,
        },
        issuer: '<target-issuer>' as const,
        audience: ['device-first'],
        subject: '<subject>' as const,
        issuedAt: '<issued-at>' as const,
        lifetimeSeconds: 3600,
      },
      signature: { verified: true as const },
    };
    const endpoint = (path: string) => ({
      origin: 'https://candidate.example',
      path,
      queryKeys: [],
    });
    const controls = runDeviceAuthorizationNegativeControls([
      { id: 'device-authorization.urlencoded-success', projection: authorization },
      {
        id: 'device-verification.completed-cookie-cleanup',
        projection: {
          ...authorization,
          cookies: [{ name: '_aster_device_flow_xsrf', options: ['path'], clearing: true }],
        },
      },
      {
        id: 'device-token.pending-poll',
        projection: {
          ...authorization,
          status: 400,
          oauthError: { category: 'authorization_pending', description: undefined },
        },
      },
      {
        id: 'device-token.id-token-signature-and-claims',
        projection: { access: { format: 'opaque', present: true }, id: jwt, refresh: undefined },
      },
      {
        id: 'device-discovery.oidc',
        projection: {
          kind: 'oidc-discovery',
          status: 200,
          contentType: 'application/json',
          headers: {},
          cookies: [],
          challenge: undefined,
          location: undefined,
          oauthError: { category: undefined, description: undefined },
          facts: {
            marker: 'oidc-discovery',
            issuer: '<target-issuer>',
            endpoints: {
              authorization_endpoint: endpoint('/oidc/auth'),
              token_endpoint: endpoint('/oidc/token'),
              jwks_uri: endpoint('/oidc/jwks'),
              userinfo_endpoint: endpoint('/oidc/me'),
              device_authorization_endpoint: endpoint('/oidc/device/auth'),
              introspection_endpoint: endpoint('/oidc/token/introspection'),
              revocation_endpoint: endpoint('/oidc/token/revocation'),
              end_session_endpoint: endpoint('/oidc/session/end'),
            },
            keys: ['issuer'],
          },
        },
      },
    ]);
    expect(controls).toEqual([
      { name: 'status', pointer: '/status', detected: true },
      { name: 'path', pointer: '/verificationUri/path', detected: true },
      { name: 'cookie-clearing', pointer: '/cookies/0/clearing', detected: true },
      { name: 'oauth', pointer: '/oauthError/category', detected: true },
      { name: 'claimKeys', pointer: '/id/claims/claimKeys', detected: true },
      { name: 'discovery-fields', pointer: '/facts/keys', detected: true },
    ]);
  });

  it('validates exact concurrency winner/loser responses and only normalizes contention', () => {
    const projection = (kind: 'oracle' | 'candidate') => ({
      kind: 'device-concurrency' as const,
      target: kind,
      referenceExpectedMultiWinner: true as const,
      trials: [0, 1, 2].map(() => {
        const responses =
          kind === 'oracle'
            ? ([concurrencyResponse(true), concurrencyResponse(true)] as const)
            : ([concurrencyResponse(true), concurrencyResponse(false)] as const);
        return { winnerCount: kind === 'oracle' ? 2 : 1, responses };
      }),
    });
    const oracle = projection('oracle') as unknown as DeviceScenarioProjection;
    const candidate = projection('candidate') as unknown as DeviceScenarioProjection;
    expect(
      publishDeviceScenarioProjection(candidate, 'device-token.concurrent-reference-multi-winner')
    ).toBe(candidate);
    expect(
      compareDeviceScenarioProjections(
        oracle,
        candidate,
        'device-token.concurrent-reference-multi-winner'
      )
    ).toEqual([]);
    for (const invalidResponse of [
      authorizationResponse(200),
      { ...concurrencyResponse(false), status: 500 },
    ]) {
      const invalid = projection('candidate');
      invalid.trials[0] = {
        winnerCount: 1,
        responses: [concurrencyResponse(true), invalidResponse],
      };
      expect(() =>
        publishDeviceScenarioProjection(
          invalid as unknown as DeviceScenarioProjection,
          'device-token.concurrent-reference-multi-winner'
        )
      ).toThrow('Invalid Phase 2 device authorization scenario');
    }
  });

  it('bounds a one-participant concurrency barrier without starting fetch', async () => {
    let calls = 0;
    const barrier = createDeviceConcurrencyBarrierFetch(async () => {
      calls += 1;
      return new Response();
    }, 20);
    await expect(barrier.fetch('https://candidate.example/oidc/token')).rejects.toThrow(
      'Invalid Phase 2 device authorization scenario'
    );
    expect(calls).toBe(0);
  });

  it('rejects a waiting participant when the second poll fails before fetch', async () => {
    let calls = 0;
    const barrier = createDeviceConcurrencyBarrierFetch(async () => {
      calls += 1;
      return new Response();
    }, 1000);
    const first = barrier.fetch('https://candidate.example/oidc/token');
    barrier.abort(new TypeError('second poll rejected before fetch'));
    await expect(first).rejects.toThrow('second poll rejected before fetch');
    expect(calls).toBe(0);
  });
});

/* eslint-enable complexity, max-lines, @typescript-eslint/prefer-nullish-coalescing, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, @typescript-eslint/no-loop-func, unicorn/consistent-function-scoping */
