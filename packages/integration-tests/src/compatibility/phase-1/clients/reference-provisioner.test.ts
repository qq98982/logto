/* eslint-disable max-lines, import/order, complexity, prefer-destructuring, @silverhand/fp/no-let, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-assign -- The black-box fake records a long exact operation sequence and injects mutable partial-failure/status cases for reverse-cleanup assertions. */
import { createServer } from 'node:http';
import { inspect } from 'node:util';

import { ReservedResource } from '@logto/core-kit';

import type { TargetConfig } from '../../model.js';
import type { Phase1Profile } from '../profile-types.js';
import { createExpectedPhase1FixtureStateProjection } from '../fixture-map.js';
import { revokeProvisionedPhase1Fixture } from '../fixtures.js';

import { createReferencePhase1FixtureProvisioner } from './reference-provisioner.js';

const profile = {
  fixtures: {
    dataTenant: {
      id: 'default',
      subject: {
        id: 'phase1-user',
        username: 'phase1-user',
        name: 'phase1-user',
        primaryEmail: 'phase1-user@example.com',
        primaryPhone: '+15555550101',
        profile: { address: { formatted: '1 Aster Way', country: 'US' } },
        applicationId: null,
      },
      applications: [
        {
          id: 'phase1-app',
          name: 'Phase 1 Application',
          type: 'SPA',
          isThirdParty: false,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
        },
        {
          id: 'phase1-browser',
          name: 'Phase 1 Consent Client',
          type: 'SPA',
          isThirdParty: true,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
          userConsentScopes: ['profile', 'email', 'address', 'phone'],
          resourceConsentScopes: ['phase1-read-profile'],
        },
      ],
      resource: {
        id: 'phase1-api',
        name: 'Phase 1 API',
        indicator: 'https://api.example.com',
        scopes: [
          {
            id: 'phase1-read-profile',
            name: 'read:profile',
            description: "Read the signed-in user's profile",
          },
        ],
      },
      resourceScopeRole: {
        id: 'phase1-reader',
        name: 'Phase 1 Reader',
        description: 'Grants the Phase 1 API read scope',
        type: 'User',
        isDefault: false,
        scopeIds: ['phase1-read-profile'],
        userIds: ['phase1-user'],
      },
      browserClientConfiguration: {
        route: '/demo-app?app_id=phase1-browser',
        localStorageKey: 'logto:demo-app:dev:config',
        localStorageValue: {
          appId: 'phase1-browser',
          prompt: 'login consent',
          scope: 'profile email address phone read:profile',
          resource: 'https://api.example.com',
        },
        effectiveScopes: [],
        scopeDerivation: 'pinned',
        scopeDerivationSources: [],
      },
    },
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
          redirectUris: ['http://localhost:3002/console/callback'],
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
        scopes: ['write:data', 'read:data'],
        organizationRoles: [
          {
            id: 'admin',
            name: 'admin',
            type: 'User',
            scopeNames: ['write:data', 'read:data'],
            userIds: ['phase1-admin'],
          },
        ],
      },
    },
  },
} as unknown as Pick<Phase1Profile, 'fixtures'>;

const primaryTarget: TargetConfig = {
  label: 'oracle',
  coreUrl: 'http://localhost:3011/',
  adminUrl: 'http://localhost:3012/',
};
const foreignTarget: TargetConfig = {
  label: 'oracle',
  coreUrl: 'http://localhost:3031/',
  adminUrl: 'http://localhost:3032/',
};
const referenceIsolation = {
  data: {
    persistenceId: 'reference-primary-database',
    cookieKeyId: 'reference-data-cookie-key',
    signingKeyId: 'reference-data-signing-key',
  },
  admin: {
    persistenceId: 'reference-primary-database',
    cookieKeyId: 'reference-admin-cookie-key',
    signingKeyId: 'reference-admin-signing-key',
  },
  foreign: {
    persistenceId: 'reference-foreign-database',
    cookieKeyId: 'reference-foreign-cookie-key',
    signingKeyId: 'reference-foreign-signing-key',
  },
} as const;
const unrelatedCredentialValues = [
  'eyJhbGciOiJIUzI1NiJ9.e30.c2ln',
  'Bearer unrelated-opaque-credential',
  'Cookie: sid=unrelated-opaque-credential',
  'Set-Cookie: sid=unrelated-opaque-credential; Path=/; Secure',
  'sid=unrelated-opaque-credential; Path=/; Secure; HttpOnly',
  '-----BEGIN PRIVATE KEY-----',
] as const;

type Request = Readonly<{
  targetRole: 'data' | 'admin' | 'foreign';
  method: string;
  path: string;
  body?: unknown;
}>;

const stripAllocationNamespace = (value: string): string => value.replace(/_a_[a-f0-9]{16}$/u, '');

const configuredSignInExperience = {
  signInMode: 'SignInAndRegister',
  signUp: { identifiers: ['username'], password: true, verify: false },
  signIn: {
    methods: [
      {
        identifier: 'username',
        password: true,
        verificationCode: false,
        isPasswordPrimary: true,
      },
    ],
  },
  passwordPolicy: {},
};

const organizationScopeRows = (...names: readonly string[]) =>
  names.map((name, index) => ({ id: `admin-organization-scope-${index + 1}`, name }));

const generatedIdFor = (request: Request): string | undefined => {
  if (request.method !== 'POST') {
    return undefined;
  }
  if (request.path === 'users') {
    return `${request.targetRole}-${stripAllocationNamespace(
      (request.body as { username: string }).username
    )}-id`;
  }
  if (request.path === 'resources') {
    return `${request.targetRole}-resource-id`;
  }
  if (request.path.endsWith('/scopes')) {
    return `${request.targetRole}-scope-id`;
  }
  if (request.path === 'roles') {
    return `${request.targetRole}-role-id`;
  }
  if (request.path === 'applications') {
    const name = stripAllocationNamespace((request.body as { name: string }).name)
      .replaceAll(' ', '-')
      .toLowerCase();
    return `${request.targetRole}-${name}-id`;
  }

  return undefined;
};

const createRequestForId = (
  history: readonly Request[],
  targetRole: Request['targetRole'],
  runtimeId: string
): Request | undefined =>
  history.find(
    (candidate) => candidate.targetRole === targetRole && generatedIdFor(candidate) === runtimeId
  );

const patchBodyFor = (
  history: readonly Request[],
  targetRole: Request['targetRole'],
  path: string
): Readonly<Record<string, unknown>> =>
  (history.find(
    (candidate) =>
      candidate.targetRole === targetRole && candidate.method === 'PATCH' && candidate.path === path
  )?.body ?? {}) as Readonly<Record<string, unknown>>;

const responseFor = (request: Request, history: readonly Request[] = []): unknown => {
  if (request.method === 'GET' && request.path === 'sign-in-exp') {
    return history.some(
      ({ targetRole, method, path }) =>
        targetRole === request.targetRole && method === 'PATCH' && path === 'sign-in-exp'
    )
      ? configuredSignInExperience
      : { signInMode: 'SignInAndRegister', signIn: { methods: [] } };
  }
  if (request.method === 'GET' && request.path === 'roles') {
    return [
      { id: 'runtime-default-admin-role', name: 'default:admin', type: 'User' },
      { id: 'runtime-user-role', name: 'user', type: 'User' },
    ];
  }
  if (request.method === 'GET' && request.path === 'organization-roles') {
    return [{ id: 'admin', name: 'admin', type: 'User' }];
  }
  if (request.method === 'GET' && request.path === 'organization-scopes') {
    return organizationScopeRows(
      ...profile.fixtures.adminTenant.tenantOrganization.scopes.toSorted()
    );
  }
  if (request.method === 'GET' && request.path === 'resources') {
    return profile.fixtures.adminTenant.resources.flatMap(({ indicator }, index) =>
      indicator === ReservedResource.Organization
        ? []
        : [
            {
              id: `admin-resource-${index + 1}`,
              name: `Admin resource ${index + 1}`,
              indicator,
            },
          ]
    );
  }
  if (request.method === 'GET' && request.path === 'organizations') {
    return [{ id: 't-default', name: 'Tenant default' }];
  }
  if (request.method === 'GET' && request.path === 'organizations/t-default/users') {
    return [{ id: 'admin-phase1_admin-id' }];
  }
  if (
    request.method === 'GET' &&
    request.path === 'organizations/t-default/users/admin-phase1_admin-id/roles'
  ) {
    return [{ id: 'admin' }];
  }
  if (request.method === 'GET' && request.path === 'organization-roles/admin/scopes') {
    return [
      'read:data',
      'write:data',
      'delete:data',
      'read:member',
      'invite:member',
      'remove:member',
      'update:member:role',
      'manage:tenant',
    ].map((name, index) => ({ id: `admin-organization-scope-${index + 1}`, name }));
  }
  if (request.method === 'GET' && request.path.startsWith('users/')) {
    const id = decodeURIComponent(request.path.slice('users/'.length));
    const create = createRequestForId(history, request.targetRole, id);
    const createBody = (create?.body ?? {}) as Readonly<Record<string, unknown>>;
    const patch = patchBodyFor(history, request.targetRole, `users/${encodeURIComponent(id)}`);
    return JSON.parse(
      JSON.stringify({
        id,
        username: createBody.username ?? null,
        name: patch.name ?? null,
        primaryEmail: patch.primaryEmail ?? null,
        primaryPhone: patch.primaryPhone ?? null,
        profile: patch.profile ?? {},
        applicationId: patch.applicationId ?? null,
        customData: patch.customData ?? {},
        hasPassword: true,
      })
    ) as unknown;
  }
  if (
    request.method === 'GET' &&
    request.path.startsWith('applications/') &&
    request.path.endsWith('/user-consent-scopes')
  ) {
    return {
      organizationScopes: [],
      resourceScopes: request.path.includes('phase-1-consent-client')
        ? [
            {
              resource: { id: 'data-resource-id' },
              scopes: [{ id: 'data-scope-id' }],
            },
          ]
        : [],
      organizationResourceScopes: [],
      userScopes: request.path.includes('phase-1-consent-client')
        ? ['phone', 'address', 'email', 'profile']
        : [],
    };
  }
  if (request.method === 'GET' && request.path.startsWith('applications/')) {
    const id = decodeURIComponent(request.path.slice('applications/'.length));
    const create = createRequestForId(history, request.targetRole, id);
    const body = (create?.body ?? {}) as Readonly<Record<string, unknown>>;
    const adminApplication = profile.fixtures.adminTenant.application;
    return JSON.parse(
      JSON.stringify({
        id,
        name: body.name ?? 'Admin Console',
        type: body.type ?? adminApplication.type,
        isThirdParty: body.isThirdParty ?? false,
        oidcClientMetadata: body.oidcClientMetadata ?? {
          redirectUris: [],
          postLogoutRedirectUris: [],
        },
        customClientMetadata: body.customClientMetadata ?? adminApplication.customClientMetadata,
      })
    ) as unknown;
  }
  if (request.method === 'GET' && request.path === 'resources/data-resource-id') {
    const create = createRequestForId(history, request.targetRole, 'data-resource-id');
    const body = (create?.body ?? {}) as Readonly<Record<string, unknown>>;
    return {
      id: 'data-resource-id',
      name: body.name,
      indicator: body.indicator,
    };
  }
  if (request.method === 'GET' && request.path === 'resources/data-resource-id/scopes') {
    const create = createRequestForId(history, request.targetRole, 'data-scope-id');
    const body = (create?.body ?? {}) as Readonly<Record<string, unknown>>;
    return [
      {
        id: 'data-scope-id',
        name: body.name,
        description: body.description,
        resourceId: 'data-resource-id',
      },
    ];
  }
  if (request.method === 'GET' && /^resources\/admin-resource-\d+\/scopes$/u.test(request.path)) {
    const index = Number.parseInt(request.path.split('-').at(-1)?.split('/')[0] ?? '0', 10) - 1;
    return (profile.fixtures.adminTenant.resources[index]?.scopes ?? []).map(
      (name, scopeIndex) => ({
        id: `admin-resource-${index + 1}-scope-${scopeIndex + 1}`,
        name,
        resourceId: `admin-resource-${index + 1}`,
      })
    );
  }
  if (request.method === 'GET' && request.path.startsWith('roles/')) {
    const parts = request.path.split('/');
    const id = parts[1]!;
    if (parts[2] === 'scopes') {
      return id === 'data-role-id' ? [{ id: 'data-scope-id' }] : [];
    }
    if (parts[2] === 'users') {
      return [{ id: id === 'data-role-id' ? 'data-phase1_user-id' : 'admin-phase1_admin-id' }];
    }
    const created = createRequestForId(history, request.targetRole, id);
    const body = (created?.body ?? {}) as Readonly<Record<string, unknown>>;
    const adminName = id === 'runtime-default-admin-role' ? 'default:admin' : 'user';
    return {
      id,
      name: body.name ?? adminName,
      description: body.description ?? 'Admin role',
      type: body.type ?? 'User',
      isDefault: body.isDefault ?? false,
    };
  }
  if (request.method === 'POST' && request.path === 'users') {
    const username = (request.body as { username: string }).username;
    return { id: `${request.targetRole}-${stripAllocationNamespace(username)}-id` };
  }
  if (request.method === 'POST' && request.path === 'resources') {
    return { id: `${request.targetRole}-resource-id` };
  }
  if (request.method === 'POST' && request.path.endsWith('/scopes')) {
    return { id: `${request.targetRole}-scope-id` };
  }
  if (request.method === 'POST' && request.path === 'roles') {
    return { id: `${request.targetRole}-role-id` };
  }
  if (request.method === 'POST' && request.path === 'applications') {
    const name = stripAllocationNamespace((request.body as { name: string }).name)
      .replaceAll(' ', '-')
      .toLowerCase();
    return { id: `${request.targetRole}-${name}-id` };
  }

  return {};
};

const createHarness = (
  options: {
    failAt?: number;
    cleanupFailure?: string;
    cleanupFailureCount?: number;
    createAllocationId?: () => string;
    organizationRoleAssignedToPreexistingMemberOnly?: boolean;
    userActivityResponses?: Partial<Record<'data' | 'admin', unknown>>;
    // eslint-disable-next-line @typescript-eslint/ban-types -- The reference API returns JSON null before first consent.
    dataUserApplicationIds?: Array<string | null>;
    // eslint-disable-next-line @typescript-eslint/ban-types -- The reference API returns JSON null before first consent.
    adminUserApplicationIds?: Array<string | null>;
    hiddenAdminResourceIndicators?: readonly string[];
    adminOrganizationScopesResponse?: unknown;
    includeReservedAdminResource?: boolean;
    applicationRedirectUriMode?: 'profile' | 'target';
    signInExperienceBrandingMode?: 'preserve' | 'clear';
    profileOverride?: typeof profile;
  } = {}
) => {
  const requests: Request[] = [];
  let callCount = 0;
  let remainingCleanupFailures = options.cleanupFailureCount ?? Number.POSITIVE_INFINITY;
  const request = async (input: Request): Promise<unknown> => {
    requests.push(structuredClone(input));
    callCount += 1;

    if (options.failAt === callCount) {
      throw new Error('raw process output with seeded-password-value-7391');
    }
    if (
      options.cleanupFailure === input.path &&
      input.method === 'DELETE' &&
      remainingCleanupFailures > 0
    ) {
      remainingCleanupFailures -= 1;
      throw new Error('raw cleanup output with seeded-password-value-7391');
    }
    if (options.organizationRoleAssignedToPreexistingMemberOnly && input.method === 'GET') {
      if (input.path === 'organizations/t-default/users') {
        return [{ id: 'admin-phase1_admin-id' }, { id: 'preexisting-admin-id' }];
      }
      if (input.path === 'organizations/t-default/users/admin-phase1_admin-id/roles') {
        return [];
      }
      if (input.path === 'organizations/t-default/users/preexisting-admin-id/roles') {
        return [{ id: 'admin' }];
      }
    }
    if (
      input.method === 'GET' &&
      input.targetRole === 'admin' &&
      input.path === 'resources' &&
      options.includeReservedAdminResource
    ) {
      return [
        ...(responseFor(input, requests) as readonly unknown[]),
        {
          id: 'unexpected-reserved-organization-resource',
          name: 'Unexpected reserved organization resource',
          indicator: ReservedResource.Organization,
        },
      ];
    }
    if (
      input.method === 'GET' &&
      input.targetRole === 'admin' &&
      input.path === 'organization-scopes' &&
      options.adminOrganizationScopesResponse !== undefined
    ) {
      return options.adminOrganizationScopesResponse;
    }
    if (
      input.method === 'GET' &&
      input.targetRole === 'admin' &&
      input.path === 'resources' &&
      (options.hiddenAdminResourceIndicators?.length ?? 0) > 0
    ) {
      return (
        responseFor(input, requests) as ReadonlyArray<Readonly<{ indicator: string }>>
      ).filter(({ indicator }) => !options.hiddenAdminResourceIndicators?.includes(indicator));
    }
    if (
      input.method === 'GET' &&
      input.targetRole === 'data' &&
      input.path === 'users/data-phase1_user-id' &&
      (options.dataUserApplicationIds?.length ?? 0) > 0
    ) {
      return {
        ...(responseFor(input, requests) as Readonly<Record<string, unknown>>),
        applicationId: options.dataUserApplicationIds?.shift(),
      };
    }
    if (
      input.method === 'GET' &&
      input.targetRole === 'admin' &&
      input.path === 'users/admin-phase1_admin-id' &&
      (options.adminUserApplicationIds?.length ?? 0) > 0
    ) {
      return {
        ...(responseFor(input, requests) as Readonly<Record<string, unknown>>),
        applicationId: options.adminUserApplicationIds?.shift(),
      };
    }
    if (
      input.method === 'GET' &&
      input.path.startsWith('users/') &&
      Object.hasOwn(options.userActivityResponses ?? {}, input.targetRole)
    ) {
      return options.userActivityResponses?.[input.targetRole as 'data' | 'admin'];
    }

    return responseFor(input, requests);
  };
  let allocation = 0;
  const provisioner = createReferencePhase1FixtureProvisioner({
    profile: options.profileOverride ?? profile,
    target: primaryTarget,
    foreignTarget,
    isolation: referenceIsolation,
    request,
    createAllocationId: options.createAllocationId ?? (() => `allocation-${++allocation}`),
    createSecret: () => 'seeded-password-value-7391',
    applicationRedirectUriMode: options.applicationRedirectUriMode,
    signInExperienceBrandingMode: options.signInExperienceBrandingMode,
  });

  return { provisioner, requests };
};

const withDefaultRequestServer = async <Result>(
  use: (
    baseUrl: string,
    requests: Request[],
    metrics: { oversizedChunksWritten: number }
  ) => Promise<Result>,
  options: Readonly<{
    streamOversizedSignIn?: boolean;
    textSignIn?: boolean;
    unexpectedTextMutation?: 'sign-in-patch' | 'user-create' | 'user-patch';
    acknowledgementStatus?: number;
  }> = {}
): Promise<Result> => {
  const requests: Request[] = [];
  const metrics = { oversizedChunksWritten: 0 };
  const server = createServer(async (incoming, response) => {
    const chunks: Uint8Array[] = [];
    for await (const chunk of incoming as AsyncIterable<Uint8Array>) {
      chunks.push(chunk);
    }
    const bodyText = Buffer.concat(chunks).toString('utf8');
    const pathname = new URL(incoming.url ?? '/', 'http://localhost').pathname;
    const request: Request = {
      targetRole: 'data',
      method: incoming.method ?? 'GET',
      path: pathname.replace(/^\/api\//u, ''),
      ...(bodyText.length > 0 && { body: JSON.parse(bodyText) as unknown }),
    };
    requests.push(structuredClone(request));

    if (options.textSignIn && request.method === 'GET' && request.path === 'sign-in-exp') {
      response.statusCode = 200;
      response.setHeader('content-type', 'text/plain; charset=utf-8');
      response.end('OK');
      return;
    }

    const unexpectedTextMutation =
      (options.unexpectedTextMutation === 'sign-in-patch' &&
        request.method === 'PATCH' &&
        request.path === 'sign-in-exp') ||
      (options.unexpectedTextMutation === 'user-create' &&
        request.method === 'POST' &&
        request.path === 'users') ||
      (options.unexpectedTextMutation === 'user-patch' &&
        request.method === 'PATCH' &&
        /^users\/[^/]+$/u.test(request.path));

    if (unexpectedTextMutation) {
      response.statusCode = request.method === 'POST' ? 201 : 200;
      response.setHeader('content-type', 'text/plain; charset=utf-8');
      response.end('Created');
      return;
    }

    if (
      options.streamOversizedSignIn &&
      request.method === 'GET' &&
      request.path === 'sign-in-exp'
    ) {
      response.statusCode = 200;
      response.setHeader('content-type', 'application/json');
      const timer = setInterval(() => {
        metrics.oversizedChunksWritten += 1;
        response.write('x'.repeat(16_384));
        if (metrics.oversizedChunksWritten === 20) {
          clearInterval(timer);
          response.end();
        }
      }, 2);
      response.once('close', () => {
        clearInterval(timer);
      });
      return;
    }

    if (request.method === 'DELETE') {
      response.statusCode = 204;
      response.end();
      return;
    }
    if (request.method === 'POST' && /^roles\/[^/]+\/users$/u.test(request.path)) {
      response.statusCode = options.acknowledgementStatus ?? 201;
      response.setHeader('content-type', 'text/plain; charset=utf-8');
      response.end(response.statusCode === 204 ? undefined : 'Created');
      return;
    }
    if (request.method === 'POST' && request.path.endsWith('/user-consent-scopes')) {
      response.statusCode = options.acknowledgementStatus ?? 201;
      response.end();
      return;
    }
    const result = responseFor(request, requests);
    response.statusCode = request.method === 'POST' ? 201 : 200;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(result));
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Failed to start reference fixture test server');
  }
  const baseUrl = `http://127.0.0.1:${address.port}/`;

  try {
    return await use(baseUrl, requests, metrics);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }
};

describe('reference Phase 1 fixture provisioner', () => {
  it('provisions fullPhase1 in the required black-box order and fixes t-default', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('fullPhase1');

    expect(
      requests.map(({ targetRole, method, path }) => `${targetRole}:${method}:${path}`)
    ).toEqual([
      'data:GET:sign-in-exp',
      'admin:GET:sign-in-exp',
      'data:PATCH:sign-in-exp',
      'admin:PATCH:sign-in-exp',
      'data:POST:users',
      'data:PATCH:users/data-phase1_user-id',
      'data:POST:resources',
      'data:POST:resources/data-resource-id/scopes',
      'data:POST:roles',
      'data:POST:roles/data-role-id/users',
      'data:POST:applications',
      'data:POST:applications',
      'data:POST:applications/data-phase-1-consent-client-id/user-consent-scopes',
      'admin:POST:users',
      'admin:PATCH:users/admin-phase1_admin-id',
      'admin:GET:roles',
      'admin:POST:roles/runtime-default-admin-role/users',
      'admin:POST:roles/runtime-user-role/users',
      'admin:GET:organization-roles',
      'admin:POST:organizations/t-default/users',
      'admin:POST:organizations/t-default/users/admin-phase1_admin-id/roles',
    ]);
    expect(
      requests
        .filter(({ method, path }) => method === 'PATCH' && path === 'sign-in-exp')
        .map(({ body }) => body)
    ).toEqual([configuredSignInExperience, configuredSignInExperience]);
    expect(requests.find(({ path }) => path === 'organizations/t-default/users')?.body).toEqual({
      userIds: ['admin-phase1_admin-id'],
    });
    const createdUser = requests.find(({ method, path }) => method === 'POST' && path === 'users')
      ?.body as { username?: unknown } | undefined;
    const patchedUser = requests.find(
      ({ method, path }) => method === 'PATCH' && path.startsWith('users/data-')
    )?.body as { primaryPhone?: unknown } | undefined;
    expect(createdUser?.username).toEqual(expect.any(String));
    expect(createdUser?.username).toMatch(/^[A-Z_a-z]\w*$/u);
    expect(patchedUser?.primaryPhone).toEqual(expect.any(String));
    expect(patchedUser?.primaryPhone).toMatch(/^\d+$/u);
    expect(fixture.public.allocations.map(({ role }) => role)).toEqual(['data', 'admin']);
    expect(fixture.public.allocations[0]?.allocationId).not.toBe(
      fixture.public.allocations[1]?.allocationId
    );
    expect(JSON.stringify(fixture.public)).not.toMatch(/seeded-password|token|cookieValue/u);

    await fixture.withSecretLease(async (lease) => {
      expect(lease.getPassword('phase1-user')).toBe('seeded-password-value-7391');
      expect(lease.getPassword('phase1-admin')).toBe('seeded-password-value-7391');
    });
    revokeProvisionedPhase1Fixture(fixture);
  });

  it('rebases application redirect URIs for browser-target fixture provisioning', async () => {
    const { provisioner, requests } = createHarness({
      applicationRedirectUriMode: 'target',
      signInExperienceBrandingMode: 'clear',
    });
    const fixture = await provisioner.provision('dataProtocol');
    const applicationMetadata = requests
      .filter(
        ({ targetRole, method, path }) =>
          targetRole === 'data' && method === 'POST' && path === 'applications'
      )
      .map(
        ({ body }) =>
          (
            body as {
              oidcClientMetadata: {
                redirectUris: readonly string[];
                postLogoutRedirectUris: readonly string[];
              };
            }
          ).oidcClientMetadata
      );

    expect(applicationMetadata).toEqual([
      {
        redirectUris: ['http://localhost:3011/demo-app'],
        postLogoutRedirectUris: [],
      },
      {
        redirectUris: ['http://localhost:3011/demo-app'],
        postLogoutRedirectUris: [],
      },
    ]);
    expect(
      requests.find(({ method, path }) => method === 'PATCH' && path === 'sign-in-exp')?.body
    ).toEqual({ ...configuredSignInExperience, branding: {} });
    await expect(provisioner.projectState(fixture)).resolves.toBeDefined();
    await provisioner.cleanup(fixture);
  });

  it('keeps a double-slash callback path on the target origin', async () => {
    const profileOverride = {
      ...profile,
      fixtures: {
        ...profile.fixtures,
        dataTenant: {
          ...profile.fixtures.dataTenant,
          applications: profile.fixtures.dataTenant.applications.map((application) => ({
            ...application,
            oidcClientMetadata: {
              ...application.oidcClientMetadata,
              redirectUris: ['http://localhost:3001//foreign.example/demo-app'],
            },
          })),
        },
      },
    };
    const { provisioner, requests } = createHarness({
      applicationRedirectUriMode: 'target',
      profileOverride,
    });
    const fixture = await provisioner.provision('dataProtocol');
    const redirectUris = requests
      .filter(
        ({ targetRole, method, path }) =>
          targetRole === 'data' && method === 'POST' && path === 'applications'
      )
      .map(
        ({ body }) =>
          (body as { oidcClientMetadata: { redirectUris: readonly string[] } }).oidcClientMetadata
            .redirectUris
      );

    expect(redirectUris).toEqual([
      ['http://localhost:3011//foreign.example/demo-app'],
      ['http://localhost:3011//foreign.example/demo-app'],
    ]);
    await expect(provisioner.projectState(fixture)).resolves.toBeDefined();
    await provisioner.cleanup(fixture);
  });

  it('cleans up in strict reverse dependency order and restores both sign-in snapshots', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('fullPhase1');
    const provisionCount = requests.length;

    await provisioner.cleanup(fixture);

    expect(
      requests
        .slice(provisionCount)
        .map(({ targetRole, method, path }) => `${targetRole}:${method}:${path}`)
    ).toEqual([
      'admin:DELETE:organizations/t-default/users/admin-phase1_admin-id',
      'admin:DELETE:users/admin-phase1_admin-id',
      'data:DELETE:applications/data-phase-1-consent-client-id',
      'data:DELETE:applications/data-phase-1-application-id',
      'data:DELETE:roles/data-role-id',
      'data:DELETE:resources/data-resource-id/scopes/data-scope-id',
      'data:DELETE:resources/data-resource-id',
      'data:DELETE:users/data-phase1_user-id',
      'admin:PATCH:sign-in-exp',
      'data:PATCH:sign-in-exp',
    ]);
  });

  it('provisions the CORS boundary with full primary state and a tenant-only foreign allocation', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('corsBoundary');
    const foreign = fixture.public.allocations.find(({ role }) => role === 'foreign');
    const provisionRequestCount = requests.length;

    expect(fixture.foreignTarget).toEqual(foreignTarget);
    expect(fixture.public.allocations.map(({ role }) => role)).toEqual([
      'data',
      'admin',
      'foreign',
    ]);
    expect(foreign?.entities.map(({ kind }) => kind)).toEqual(['tenant']);
    expect(
      requests
        .filter(({ targetRole }) => targetRole === 'foreign')
        .map(({ method, path }) => `${method}:${path}`)
    ).toEqual(['GET:sign-in-exp', 'PATCH:sign-in-exp']);

    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
    expect(
      requests
        .slice(provisionRequestCount)
        .filter(({ targetRole }) => targetRole === 'foreign')
        .map(({ method, path }) => `${method}:${path}`)
    ).toEqual(['PATCH:sign-in-exp']);
  });

  it.each(['corsBoundary', 'consentBoundary'] as const)(
    'requires a separately keyed foreign target for the %s recipe',
    async (recipe) => {
      const provisioner = createReferencePhase1FixtureProvisioner({
        profile,
        target: primaryTarget,
        isolation: referenceIsolation,
        request: async () => ({}),
      });

      await expect(provisioner.provision(recipe)).rejects.toThrow(
        'Invalid reference fixture provisioner configuration'
      );
    }
  );

  it('shares configured sign-in state across overlapping fixtures and restores it once', async () => {
    const { provisioner, requests } = createHarness();
    const first = await provisioner.provision('dataProtocol');
    const second = await provisioner.provision('dataProtocol');
    const beforeCleanup = requests.length;

    await provisioner.cleanup(first);
    const afterFirstCleanup = requests.length;
    await provisioner.cleanup(second);

    expect(
      requests
        .slice(0, beforeCleanup)
        .filter(({ path }) => path === 'sign-in-exp')
        .map(({ method }) => method)
    ).toEqual(['GET', 'PATCH']);
    expect(
      requests.slice(beforeCleanup, afterFirstCleanup).filter(({ path }) => path === 'sign-in-exp')
    ).toHaveLength(0);
    expect(
      requests
        .slice(afterFirstCleanup)
        .filter(({ path }) => path === 'sign-in-exp')
        .map(({ method }) => method)
    ).toEqual(['PATCH']);
  });

  it('accepts non-JSON successful mutation acknowledgements from the default client', async () => {
    await withDefaultRequestServer(async (baseUrl, requests) => {
      const provisioner = createReferencePhase1FixtureProvisioner({
        profile,
        target: {
          label: 'oracle',
          coreUrl: baseUrl,
          adminUrl: baseUrl.replace('127.0.0.1', 'localhost'),
        },
        isolation: referenceIsolation,
        createAllocationId: () => 'default-request-allocation',
        createSecret: () => 'default-request-password-9517',
      });

      const fixture = await provisioner.provision('dataProtocol');
      await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
      expect(
        requests.filter(
          ({ method, path }) =>
            method === 'POST' &&
            (/^roles\/[^/]+\/users$/u.test(path) || path.endsWith('/user-consent-scopes'))
        )
      ).toHaveLength(2);
    });
  });

  it('rejects a non-JSON successful read response from the default client', async () => {
    await withDefaultRequestServer(
      async (baseUrl) => {
        const provisioner = createReferencePhase1FixtureProvisioner({
          profile,
          target: {
            label: 'oracle',
            coreUrl: baseUrl,
            adminUrl: baseUrl.replace('127.0.0.1', 'localhost'),
          },
          isolation: referenceIsolation,
          createAllocationId: () => 'text-read-response-allocation',
          createSecret: () => 'text-read-response-password-9517',
        });

        await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
          'Reference fixture operation failed'
        );
      },
      { textSignIn: true }
    );
  });

  it.each([200, 202, 204])(
    'rejects a non-JSON mutation acknowledgement with status %i',
    async (acknowledgementStatus) => {
      await withDefaultRequestServer(
        async (baseUrl) => {
          const provisioner = createReferencePhase1FixtureProvisioner({
            profile,
            target: {
              label: 'oracle',
              coreUrl: baseUrl,
              adminUrl: baseUrl.replace('127.0.0.1', 'localhost'),
            },
            isolation: referenceIsolation,
            createAllocationId: () => `status-${acknowledgementStatus}-allocation`,
            createSecret: () => `status-${acknowledgementStatus}-password-9517`,
          });

          await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
            /Reference fixture (?:operation|provisioning and cleanup) failed/u
          );
        },
        { acknowledgementStatus }
      );
    }
  );

  it.each(['sign-in-patch', 'user-create', 'user-patch'] as const)(
    'rejects an unexpected non-JSON successful %s mutation response',
    async (unexpectedTextMutation) => {
      await withDefaultRequestServer(
        async (baseUrl) => {
          const provisioner = createReferencePhase1FixtureProvisioner({
            profile,
            target: {
              label: 'oracle',
              coreUrl: baseUrl,
              adminUrl: baseUrl.replace('127.0.0.1', 'localhost'),
            },
            isolation: referenceIsolation,
            createAllocationId: () => `text-${unexpectedTextMutation}-allocation`,
            createSecret: () => `text-${unexpectedTextMutation}-password-9517`,
          });

          await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
            /Reference fixture (?:operation|provisioning and cleanup) failed/u
          );
        },
        { unexpectedTextMutation }
      );
    }
  );

  it('cancels an oversized streamed default response before buffering the full body', async () => {
    await withDefaultRequestServer(
      async (baseUrl, _requests, metrics) => {
        const provisioner = createReferencePhase1FixtureProvisioner({
          profile,
          target: {
            label: 'oracle',
            coreUrl: baseUrl,
            adminUrl: baseUrl.replace('127.0.0.1', 'localhost'),
          },
          isolation: referenceIsolation,
          createAllocationId: () => 'oversized-response-allocation',
          createSecret: () => 'oversized-response-password-9517',
        });

        await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
          'Reference fixture operation failed'
        );
        expect(metrics.oversizedChunksWritten).toBeLessThan(20);
      },
      { streamOversizedSignIn: true }
    );
  });

  it('retries only failed reference cleanup steps and makes completed cleanup idempotent', async () => {
    const requests: Request[] = [];
    const transientPath = 'roles/data-role-id';
    let remainingFailures = 1;
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        requests.push(structuredClone(input));
        if (input.method === 'DELETE' && input.path === transientPath && remainingFailures > 0) {
          remainingFailures -= 1;
          throw new Error('transient cleanup failure');
        }
        return responseFor(input);
      },
      createAllocationId: () => 'retry-allocation',
      createSecret: () => 'retry-seeded-password-9517',
    });
    const fixture = await provisioner.provision('dataProtocol');
    const provisionCount = requests.length;

    await expect(provisioner.cleanup(fixture)).rejects.toThrow('Reference fixture cleanup failed');
    const afterFirst = requests.length;
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
    const afterSecond = requests.length;
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();

    expect(
      requests.slice(provisionCount, afterFirst).map(({ method, path }) => `${method}:${path}`)
    ).toEqual([
      'DELETE:applications/data-phase-1-consent-client-id',
      'DELETE:applications/data-phase-1-application-id',
      `DELETE:${transientPath}`,
      'PATCH:sign-in-exp',
    ]);
    expect(
      requests.slice(afterFirst, afterSecond).map(({ method, path }) => `${method}:${path}`)
    ).toEqual([
      `DELETE:${transientPath}`,
      'DELETE:resources/data-resource-id/scopes/data-scope-id',
      'DELETE:resources/data-resource-id',
      'DELETE:users/data-phase1_user-id',
    ]);
    expect(requests).toHaveLength(afterSecond);
  });

  it('retries a failed sign-in restore without repeating successful parent cleanup', async () => {
    const requests: Request[] = [];
    let signInPatchCount = 0;
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        requests.push(structuredClone(input));
        if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
          signInPatchCount += 1;
          if (signInPatchCount === 2) {
            throw new Error('transient restore failure');
          }
        }
        return responseFor(input);
      },
      createAllocationId: () => 'restore-retry-allocation',
      createSecret: () => 'restore-retry-password-9517',
    });
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.cleanup(fixture)).rejects.toThrow('Reference fixture cleanup failed');
    const beforeRetry = requests.length;
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();

    expect(requests.slice(beforeRetry).map(({ method, path }) => `${method}:${path}`)).toEqual([
      'PATCH:sign-in-exp',
    ]);
  });

  it('blocks new provisioning until a failed shared sign-in restore recovers', async () => {
    let signInPatchCount = 0;
    let remainingRestoreFailures = 2;
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
          signInPatchCount += 1;
          if (signInPatchCount > 1 && remainingRestoreFailures > 0) {
            remainingRestoreFailures -= 1;
            throw new Error('transient restore failure');
          }
        }
        return responseFor(input);
      },
      createAllocationId: () => 'shared-restore-allocation',
      createSecret: () => 'shared-restore-password-9517',
    });
    const first = await provisioner.provision('dataProtocol');

    await expect(provisioner.cleanup(first)).rejects.toThrow('Reference fixture cleanup failed');
    await expect(provisioner.provision('none')).rejects.toThrow(
      'Reference pending shared fixture cleanup failed'
    );
    const second = await provisioner.provision('none');
    await expect(provisioner.cleanup(second)).resolves.toBeUndefined();
  });

  it('serializes concurrent reference cleanup calls', async () => {
    let releaseFirstDelete: (() => void) | undefined;
    const firstDeleteReleased = new Promise<void>((resolve) => {
      releaseFirstDelete = resolve;
    });
    let markFirstDeleteStarted: (() => void) | undefined;
    const firstDeleteStarted = new Promise<void>((resolve) => {
      markFirstDeleteStarted = resolve;
    });
    let deleteCalls = 0;
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        if (input.method === 'DELETE') {
          deleteCalls += 1;
          if (deleteCalls === 1) {
            markFirstDeleteStarted?.();
            await firstDeleteReleased;
          }
        }
        return responseFor(input);
      },
      createAllocationId: () => 'concurrent-cleanup-allocation',
      createSecret: () => 'concurrent-cleanup-password-9517',
    });
    const fixture = await provisioner.provision('dataProtocol');
    const first = provisioner.cleanup(fixture);
    await firstDeleteStarted;
    const second = provisioner.cleanup(fixture);
    expect(deleteCalls).toBe(1);
    releaseFirstDelete?.();

    await expect(Promise.all([first, second])).resolves.toEqual([undefined, undefined]);
    expect(deleteCalls).toBe(6);
  });

  it('projects every persisted data entity and relation through black-box reads', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('dataProtocol');
    const provisionCount = requests.length;

    const projection = await provisioner.projectState(fixture);
    expect(projection).toEqual(createExpectedPhase1FixtureStateProjection(fixture.public, profile));
    expect(requests.slice(provisionCount).map(({ method, path }) => `${method}:${path}`)).toEqual([
      'GET:sign-in-exp',
      'GET:users/data-phase1_user-id',
      'GET:applications/data-phase-1-application-id',
      'GET:applications/data-phase-1-application-id/user-consent-scopes',
      'GET:applications/data-phase-1-consent-client-id',
      'GET:applications/data-phase-1-consent-client-id/user-consent-scopes',
      'GET:resources/data-resource-id',
      'GET:resources/data-resource-id/scopes',
      'GET:roles/data-role-id',
      'GET:roles/data-role-id/scopes',
      'GET:roles/data-role-id/users',
    ]);
  });

  it('accepts and pins the expected first-consent application mutation', async () => {
    const thirdPartyApplicationId = 'data-phase-1-consent-client-id';
    const { provisioner } = createHarness({
      dataUserApplicationIds: [null, thirdPartyApplicationId, thirdPartyApplicationId, null],
    });
    const fixture = await provisioner.provision('dataProtocol');

    try {
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('accepts and pins the expected admin auto-consent application mutation', async () => {
    const { provisioner } = createHarness({
      adminUserApplicationIds: [null, 'admin-console', 'admin-console', null],
    });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('rejects an unexpected admin application mutation after auto-consent', async () => {
    const { provisioner } = createHarness({
      adminUserApplicationIds: [null, 'unexpected-admin-application'],
    });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('accepts an already-completed admin auto-consent on the first observation', async () => {
    const { provisioner } = createHarness({
      adminUserApplicationIds: ['admin-console', 'admin-console', null],
    });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('rejects an unknown admin application on the first observation', async () => {
    const { provisioner } = createHarness({
      adminUserApplicationIds: ['unexpected-admin-application'],
    });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it.each([
    ['the first observation', ['unexpected-application-id'], 0],
    ['a transition after null', [null, 'unexpected-application-id'], 1],
  ] as const)(
    'rejects an unexpected user application id on %s',
    async (_name, dataUserApplicationIds, successfulReads) => {
      const { provisioner } = createHarness({
        dataUserApplicationIds: [...dataUserApplicationIds],
      });
      const fixture = await provisioner.provision('dataProtocol');

      try {
        if (successfulReads === 1) {
          await expect(provisioner.projectState(fixture)).resolves.toEqual(
            createExpectedPhase1FixtureStateProjection(fixture.public, profile)
          );
        }
        await expect(provisioner.projectState(fixture)).rejects.toThrow(
          'Invalid reference fixture response'
        );
      } finally {
        await provisioner.cleanup(fixture);
      }
    }
  );

  it('reads only the logical data or admin user last-sign-in state', async () => {
    const { provisioner, requests } = createHarness({
      userActivityResponses: {
        data: { id: 'data-phase1_user-id', lastSignInAt: null },
        admin: { id: 'admin-phase1_admin-id', lastSignInAt: 1_725_000_000_000 },
      },
    });
    const fixture = await provisioner.provision('fullPhase1');
    const provisionCount = requests.length;

    await expect(provisioner.readUserActivityState(fixture, 'phase1-user')).resolves.toEqual({
      lastSignInState: 'never',
    });
    await expect(provisioner.readUserActivityState(fixture, 'phase1-admin')).resolves.toEqual({
      lastSignInState: 'present',
    });
    expect(requests.slice(provisionCount)).toEqual([
      {
        targetRole: 'data',
        method: 'GET',
        path: 'users/data-phase1_user-id',
      },
      {
        targetRole: 'admin',
        method: 'GET',
        path: 'users/admin-phase1_admin-id',
      },
    ]);
  });

  it('rejects an unknown reference fixture or logical user before reading activity', async () => {
    const first = createHarness();
    const second = createHarness();
    const fixture = await first.provisioner.provision('dataProtocol');
    const foreignFixture = await second.provisioner.provision('dataProtocol');
    const requestCount = first.requests.length;

    await expect(
      first.provisioner.readUserActivityState(foreignFixture, 'phase1-user')
    ).rejects.toThrow('Unknown reference fixture');
    await expect(first.provisioner.readUserActivityState(fixture, 'missing-user')).rejects.toThrow(
      'Invalid Phase 1 browser activity fixture user'
    );
    expect(first.requests).toHaveLength(requestCount);
  });

  it.each([true, 0, -1, 1.5, '1725000000000'])(
    'rejects malformed reference lastSignInAt value %p',
    async (lastSignInAt) => {
      const { provisioner } = createHarness({
        userActivityResponses: { data: { lastSignInAt } },
      });
      const fixture = await provisioner.provision('dataProtocol');

      await expect(provisioner.readUserActivityState(fixture, 'phase1-user')).rejects.toThrow(
        'Invalid Phase 1 browser activity state'
      );
    }
  );

  it('rejects a secret-bearing reference activity response without exposing it', async () => {
    const credential = 'Bearer unrelated-activity-credential';
    const { provisioner } = createHarness({
      userActivityResponses: { data: { lastSignInAt: null, note: credential } },
    });
    const fixture = await provisioner.provision('dataProtocol');
    let caught: unknown;

    try {
      await provisioner.readUserActivityState(fixture, 'phase1-user');
    } catch (error: unknown) {
      caught = error;
    }

    expect(String(caught)).toBe('TypeError: Invalid reference fixture response');
    expect(inspect(caught)).not.toContain(credential);
  });

  it.each(['none', 'adminConsole', 'fullPhase1', 'corsBoundary', 'consentBoundary'] as const)(
    'projects canonical persisted state for the %s recipe',
    async (recipe) => {
      const { provisioner } = createHarness();
      const fixture = await provisioner.provision(recipe);

      await expect(provisioner.projectState(fixture)).resolves.toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
    }
  );

  it('projects reserved organization template scopes without querying a reserved resource endpoint', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('adminConsole');
    const provisionRequestCount = requests.length;

    try {
      const projection = await provisioner.projectState(fixture);

      expect(projection).toEqual(
        createExpectedPhase1FixtureStateProjection(fixture.public, profile)
      );
      expect(
        projection.allocations[0]?.entities.find(
          ({ logicalId }) => logicalId === 'admin.resource.3'
        )?.snapshot
      ).toMatchObject({ scopeNames: ['write:data', 'read:data'] });
      const projectionPaths = requests
        .slice(provisionRequestCount)
        .map(({ method, path }) => `${method}:${path}`);

      expect(projectionPaths).toContain('GET:resources');
      expect(projectionPaths).toContain('GET:organization-scopes');
      expect(projectionPaths).toContain('GET:resources/admin-resource-1/scopes');
      expect(projectionPaths).toContain('GET:resources/admin-resource-2/scopes');
      expect(projectionPaths).not.toContain('GET:resources/admin-resource-3/scopes');
      expect(projectionPaths).not.toContain(
        `GET:resources/${encodeURIComponent(ReservedResource.Organization)}/scopes`
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it.each([
    ['missing', organizationScopeRows('read:data')],
    ['extra', organizationScopeRows('delete:data', 'read:data', 'write:data')],
    ['duplicate', organizationScopeRows('read:data', 'write:data', 'write:data')],
    ['wrong', organizationScopeRows('delete:data', 'read:data')],
  ] as const)('rejects %s organization template scope evidence', async (_name, response) => {
    const { provisioner } = createHarness({ adminOrganizationScopesResponse: response });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('rejects a reserved organization row returned by Management resources', async () => {
    const { provisioner } = createHarness({ includeReservedAdminResource: true });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('rejects a missing non-reserved configured admin resource', async () => {
    const { provisioner } = createHarness({
      hiddenAdminResourceIndicators: ['https://default.logto.app/api'],
    });
    const fixture = await provisioner.provision('adminConsole');

    try {
      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Invalid reference fixture response'
      );
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('rejects an organization role held only by a pre-existing member', async () => {
    const { provisioner } = createHarness({
      organizationRoleAssignedToPreexistingMemberOnly: true,
    });
    const fixture = await provisioner.provision('adminConsole');

    await expect(provisioner.projectState(fixture)).rejects.toThrow(
      'Invalid reference fixture response'
    );
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
  });

  it('accepts only a 404 from a child cleanup and rejects parent not-found', async () => {
    const child = createHarness();
    const childFixture = await child.provisioner.provision('dataProtocol');
    const childScopePath = 'resources/data-resource-id/scopes/data-scope-id';
    const childRequest = child.requests;
    const childProvisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        childRequest.push(structuredClone(input));
        if (input.method === 'DELETE' && input.path === childScopePath) {
          throw Object.assign(new Error('raw missing child'), { status: 404 });
        }
        return responseFor(input);
      },
      createAllocationId: () => 'child-allocation',
      createSecret: () => 'another-seeded-password-9517',
    });
    const fixture = await childProvisioner.provision('dataProtocol');
    await expect(childProvisioner.cleanup(fixture)).resolves.toBeUndefined();
    revokeProvisionedPhase1Fixture(childFixture);

    const parentProvisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        if (input.method === 'DELETE' && input.path === 'users/data-phase1_user-id') {
          throw Object.assign(new Error('raw missing parent'), { status: 404 });
        }
        return responseFor(input);
      },
      createAllocationId: () => 'parent-allocation',
      createSecret: () => 'third-seeded-password-9517',
    });
    const parentFixture = await parentProvisioner.provision('dataProtocol');

    await expect(parentProvisioner.cleanup(parentFixture)).rejects.toThrow(
      'Reference fixture cleanup failed'
    );
  });

  it('cleans partial provisioning and aggregates sanitized cleanup errors after the primary', async () => {
    const { provisioner } = createHarness({
      failAt: 8,
      cleanupFailure: 'resources/data-resource-id',
    });
    let caught: unknown;

    try {
      await provisioner.provision('dataProtocol');
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors).toHaveLength(2);
    expect(inspect(caught)).not.toContain('seeded-password-value-7391');
    expect((caught as AggregateError).errors.map(String)).toEqual([
      'Error: Reference fixture operation failed',
      'Error: Reference fixture cleanup operation failed',
    ]);
  });

  it('retries a retained partial-provisioning compensation before the next provision', async () => {
    const { provisioner, requests } = createHarness({
      failAt: 8,
      cleanupFailure: 'resources/data-resource-id',
      cleanupFailureCount: 1,
      createAllocationId: () => 'retryable-partial-allocation',
    });

    await expect(provisioner.provision('dataProtocol')).rejects.toBeInstanceOf(AggregateError);
    const fixture = await provisioner.provision('dataProtocol');
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();

    expect(
      requests.filter(
        ({ method, path }) => method === 'DELETE' && path === 'resources/data-resource-id'
      )
    ).toHaveLength(3);
  });

  it('quarantines an unresolved create while allowing a fresh allocation to proceed', async () => {
    const allocationIds = [
      'ambiguous-create-allocation',
      'ambiguous-create-allocation',
      'fresh-allocation',
    ];
    let loseCreateResponse = true;
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        if (loseCreateResponse && input.method === 'POST' && input.path === 'users') {
          loseCreateResponse = false;
          throw new Error('response lost after create commit');
        }
        return responseFor(input);
      },
      createAllocationId: () => allocationIds.shift() ?? 'unexpected-allocation',
      createSecret: () => 'ambiguous-create-password-9517',
    });

    await expect(provisioner.provision('dataProtocol')).rejects.toBeInstanceOf(AggregateError);
    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Reference fixture operation failed'
    );
    const fixture = await provisioner.provision('dataProtocol');
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
  });

  it('recovers a failed returned-fixture cleanup before the next provision', async () => {
    const { provisioner, requests } = createHarness({
      cleanupFailure: 'resources/data-resource-id',
      cleanupFailureCount: 1,
    });
    const first = await provisioner.provision('dataProtocol');

    await expect(provisioner.cleanup(first)).rejects.toThrow('Reference fixture cleanup failed');
    const second = await provisioner.provision('none');
    await expect(provisioner.cleanup(second)).resolves.toBeUndefined();
    expect(
      requests.filter(
        ({ method, path }) => method === 'DELETE' && path === 'resources/data-resource-id'
      )
    ).toHaveLength(2);
  });

  it('restores sign-in settings when the configuring PATCH commits but its response is lost', async () => {
    const requests: Request[] = [];
    let patchCalls = 0;
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        requests.push(structuredClone(input));
        if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
          patchCalls += 1;
          if (patchCalls === 1) {
            throw new Error('response lost after commit');
          }
        }
        return responseFor(input);
      },
      createAllocationId: () => 'lost-response-allocation',
      createSecret: () => 'lost-response-password-9517',
    });

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Reference fixture operation failed'
    );
    expect(requests.map(({ method, path }) => `${method}:${path}`)).toEqual([
      'GET:sign-in-exp',
      'PATCH:sign-in-exp',
      'PATCH:sign-in-exp',
    ]);
    expect(requests[2]?.body).toEqual({
      signInMode: 'SignInAndRegister',
      signIn: { methods: [] },
    });
  });

  it('pre-registers a failed create and reports an unresolved committed runtime ID', async () => {
    const requests: Request[] = [];
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        requests.push(structuredClone(input));
        if (input.method === 'POST' && input.path === 'users') {
          throw new Error('response lost after create commit');
        }
        return responseFor(input);
      },
      createAllocationId: () => 'lost-create-allocation',
      createSecret: () => 'lost-create-password-9517',
    });
    let caught: unknown;

    try {
      await provisioner.provision('dataProtocol');
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors.map(String)).toEqual([
      'Error: Reference fixture operation failed',
      'Error: Reference fixture cleanup operation failed',
    ]);
    expect(requests.map(({ method, path }) => `${method}:${path}`)).toEqual([
      'GET:sign-in-exp',
      'PATCH:sign-in-exp',
      'POST:users',
      'PATCH:sign-in-exp',
    ]);
  });

  it('provisions same-tenant B and a separately keyed foreign target without cloud or database access', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('consentBoundary');

    expect(fixture.foreignTarget).toEqual(foreignTarget);
    expect(requests.some(({ targetRole }) => targetRole === 'foreign')).toBe(true);
    expect(
      requests.every(
        ({ path }) =>
          !path.includes('tenant') && !path.includes('cloud') && !path.includes('database')
      )
    ).toBe(true);
    const [primary, foreign] = fixture.public.allocations;
    expect(primary?.isolation.persistenceId).not.toBe(foreign?.isolation.persistenceId);
    expect(primary?.isolation.cookieKeyId).not.toBe(foreign?.isolation.cookieKeyId);
    expect(primary?.isolation.signingKeyId).not.toBe(foreign?.isolation.signingKeyId);
    expect(primary?.entities.some(({ logicalId }) => logicalId === 'consent.primary.user-b')).toBe(
      true
    );
    expect(foreign?.entities.some(({ logicalId }) => logicalId === 'consent.foreign.user-b')).toBe(
      true
    );
  });

  it('rejects foreign topology evidence from a different implementation label', () => {
    expect(() =>
      createReferencePhase1FixtureProvisioner({
        profile,
        target: primaryTarget,
        foreignTarget: { ...foreignTarget, label: 'candidate' },
        isolation: referenceIsolation,
      })
    ).toThrow('Invalid reference fixture provisioner configuration');
  });

  it.each([
    [
      'foreign core cross-swapped with primary admin',
      { ...foreignTarget, coreUrl: primaryTarget.adminUrl },
    ],
    [
      'foreign admin cross-swapped with primary core',
      { ...foreignTarget, adminUrl: primaryTarget.coreUrl },
    ],
    ['foreign core and admin duplicated', { ...foreignTarget, adminUrl: foreignTarget.coreUrl }],
    ['normalized foreign core alias', { ...foreignTarget, coreUrl: 'HTTP://LOCALHOST:3011' }],
  ])('rejects %s', (_name, invalidForeignTarget) => {
    expect(() =>
      createReferencePhase1FixtureProvisioner({
        profile,
        target: primaryTarget,
        foreignTarget: invalidForeignTarget,
        isolation: referenceIsolation,
      })
    ).toThrow('Invalid reference fixture provisioner configuration');
  });

  it('rejects a primary target whose canonical core and admin origins alias', () => {
    expect(() =>
      createReferencePhase1FixtureProvisioner({
        profile,
        target: { ...primaryTarget, adminUrl: 'HTTP://LOCALHOST:3011' },
        foreignTarget,
        isolation: referenceIsolation,
      })
    ).toThrow('Invalid reference fixture provisioner configuration');
  });

  it.each([
    ['exact duplicate', { ...primaryTarget, adminUrl: primaryTarget.coreUrl }],
    ['case and trailing-slash alias', { ...primaryTarget, adminUrl: 'HTTP://LOCALHOST:3011' }],
    [
      'default-port alias',
      { ...primaryTarget, coreUrl: 'http://localhost:80/', adminUrl: 'HTTP://LOCALHOST' },
    ],
  ])('rejects no-foreign primary origin %s', (_name, invalidTarget) => {
    expect(() =>
      createReferencePhase1FixtureProvisioner({
        profile,
        target: invalidTarget,
        isolation: referenceIsolation,
      })
    ).toThrow('Invalid reference fixture provisioner configuration');
  });

  it('accepts no-foreign primary origins when canonical origins differ', () => {
    expect(() =>
      createReferencePhase1FixtureProvisioner({
        profile,
        target: primaryTarget,
        isolation: referenceIsolation,
      })
    ).not.toThrow();
  });

  it.each(unrelatedCredentialValues)(
    'rejects unrelated credentials returned as public runtime IDs without echoing them',
    async (credential) => {
      const provisioner = createReferencePhase1FixtureProvisioner({
        profile,
        target: primaryTarget,
        isolation: referenceIsolation,
        request: async (input: Request) =>
          input.method === 'POST' && input.path === 'users'
            ? { id: credential }
            : responseFor(input),
        createAllocationId: () => 'credential-response-allocation',
        createSecret: () => 'credential-response-password-9517',
      });
      let caught: unknown;
      try {
        await provisioner.provision('dataProtocol');
      } catch (error: unknown) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(AggregateError);
      expect((caught as AggregateError).errors.map(String)).toEqual([
        'Error: Reference fixture operation failed',
        'Error: Reference fixture cleanup operation failed',
      ]);
      expect(inspect(caught, { depth: null })).not.toContain(credential);
      expect(String(caught)).not.toContain(credential);
    }
  );

  it('allocates every provision call independently', async () => {
    const { provisioner, requests } = createHarness();
    const experience = await provisioner.provision('dataProtocol');
    const consoleFixture = await provisioner.provision('dataProtocol');

    expect(experience.public.allocations[0]?.allocationId).not.toBe(
      consoleFixture.public.allocations[0]?.allocationId
    );
    const createdUniqueValues = requests
      .filter(
        ({ method, path }) =>
          method === 'POST' && ['users', 'resources', 'roles', 'applications'].includes(path)
      )
      .map(({ path, body }) => {
        const record = body as { username?: string; name?: string; indicator?: string };
        return `${path}:${record.username ?? record.name ?? record.indicator}`;
      });
    expect(new Set(createdUniqueValues).size).toBe(createdUniqueValues.length);
  });

  it('rejects an injected allocator that reuses an earlier fixture identity', async () => {
    const requests: Request[] = [];
    const provisioner = createReferencePhase1FixtureProvisioner({
      profile,
      target: primaryTarget,
      isolation: referenceIsolation,
      request: async (input: Request) => {
        requests.push(structuredClone(input));
        return responseFor(input);
      },
      createAllocationId: () => 'reused-allocation',
      createSecret: () => 'unique-seeded-password-9517',
    });
    await provisioner.provision('dataProtocol');
    const postCount = requests.filter(({ method }) => method === 'POST').length;

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Reference fixture operation failed'
    );
    expect(requests.filter(({ method }) => method === 'POST')).toHaveLength(postCount);
  });
});

/* eslint-enable max-lines, import/order, complexity, prefer-destructuring, @silverhand/fp/no-let, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-assign */
