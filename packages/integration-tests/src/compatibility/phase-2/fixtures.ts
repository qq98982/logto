/* eslint-disable max-lines, complexity, max-params, no-await-in-loop, no-restricted-syntax, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition -- This boundary owns two real fixture protocols, reverse compensation, reconciliation, secret leases, and hostile command/API results. */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../config.js';
import type { TargetConfig } from '../model.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../phase-1/clients/command-provisioner.js';
import { assertPhase1RuntimeCredentialGraphIsSanitized } from '../phase-1/fixtures.js';
import { snapshotClosedDataGraph } from '../phase-1/model.js';

import type { Phase2InvocationFence } from './runtime.js';

export type Phase2MachineClientMethod = 'client_secret_basic' | 'client_secret_post';

export type Phase2FixturePublic = Readonly<{
  allocationId: string;
  clients: Readonly<{
    basic: Readonly<{ id: string; method: 'client_secret_basic' }>;
    post: Readonly<{ id: string; method: 'client_secret_post' }>;
  }>;
  deviceClients: Readonly<{
    firstParty: Phase2DeviceClientPublic;
    thirdParty: Phase2DeviceClientPublic;
    missingGrant: Phase2DeviceClientPublic;
    ineligibleWeb: Phase2DeviceClientPublic;
  }>;
  resources: Readonly<{
    primary: Readonly<{ id: string; indicator: string }>;
    default: Readonly<{ id: string; indicator: string }>;
  }>;
  organization: Readonly<{ id: string; scopeName: 'organization:read' }>;
  scopes: Readonly<{
    read: Readonly<{ id: string; name: 'read' }>;
    write: Readonly<{ id: string; name: 'write' }>;
    unassigned: Readonly<{ id: string; name: 'unassigned' }>;
  }>;
  boundary: Readonly<{
    primary: 'provisioned';
    foreign: 'unchanged';
  }>;
}>;

type Phase2DeviceClientPublic = Readonly<{
  id: string;
  applicationType: 'SPA' | 'Native';
  authenticationMethod: 'none';
  isThirdParty: boolean;
  deviceGrantEnabled: boolean;
}>;

export type Phase2StatusPublic = Readonly<{
  user: Readonly<{ id: string; username: string }>;
  client: Readonly<{ id: string; redirectUri: string }>;
  confidentialClient: Readonly<{ id: string; redirectUri: string }>;
  resource: Readonly<{ id: string; indicator: string; scopeName: string }>;
}>;

export type Phase2FixtureSecretLease = {
  getClientSecret(logicalClient: 'basic' | 'post'): string;
  getStatusClientSecret(): string;
  getSubjectPassword?(): string;
  toJSON(): never;
};

export type ProvisionedPhase2Fixture = {
  readonly public: Phase2FixturePublic;
  readonly status?: Phase2StatusPublic;
  withSecretLease<Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result>;
};

export type Phase2FixtureProvisioner = {
  provision(): Promise<ProvisionedPhase2Fixture>;
  projectState(fixture: ProvisionedPhase2Fixture): Promise<unknown>;
  cleanup(fixture: ProvisionedPhase2Fixture): Promise<void>;
};

export type Phase2AdminRequest = Readonly<{
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  body?: unknown;
  expectedStatuses: readonly number[];
  responseKind: 'object' | 'array' | 'created' | 'empty' | 'status';
}>;

export type Phase2AdminRequestFunction = (request: Phase2AdminRequest) => Promise<unknown>;

export type Phase2CommandRunner = (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;

type ReferenceProvisionerOptions = Readonly<{
  target: TargetConfig;
  foreignTarget: TargetConfig;
  request?: Phase2AdminRequestFunction;
  createAllocationId?: () => string;
}>;

export type Phase2CandidateFixtureRecipe = 'dataProtocol' | 'phase2CandidateInvariants';

type CandidateProvisionerOptions = Readonly<{
  target: TargetConfig;
  foreignTarget: TargetConfig;
  environment?: Readonly<Record<string, string | undefined>>;
  runner?: Phase2CommandRunner;
  executablePath: string;
  identityFence?: Phase2InvocationFence;
  createAllocationId?: () => string;
  createSecret?: () => string;
  recipe?: Phase2CandidateFixtureRecipe;
}>;

type FixtureState = {
  allocationId: string;
  secrets: Readonly<{
    basic: string;
    post: string;
    statusConfidential: string;
    subjectPassword: string;
  }>;
  sensitiveValues: readonly string[];
  coordinatorPublic?: Readonly<Record<string, unknown>>;
  previousDefaultResourceId?: string;
  previousSignInExperience?: unknown;
  previousAccountCenter?: unknown;
  revoked: boolean;
  cleanup?: Promise<void>;
};

type ReferenceCleanup = Readonly<{
  name: string;
  path: string;
}>;

const failure = 'Phase 2 fixture operation failed';
const cleanupFailure = 'Phase 2 fixture cleanup failed';
const maximumResponseBytes = 64 * 1024;
const commandTimeoutMs = 30_000;
const maximumCommandOutputBytes = 262_144;
const safeIdPattern = /^[A-Za-z0-9._~-]{1,128}$/u;
const safeAllocationPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u;
const markerPrefix = 'phase2-client-credentials-';
const primaryIndicator = 'https://phase2.example.invalid/api-primary';
const defaultIndicator = 'https://phase2.example.invalid/api-default';
const statusIndicator = 'https://api.example.com';
const statusRedirectUri = 'http://localhost:3001/demo-app';
const statusConfidentialClientId = 'phase2-status';
const logicalClientIds = Object.freeze({ basic: 'phase2-m2m-basic', post: 'phase2-m2m-post' });
const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
const logicalDeviceClientIds = Object.freeze({
  firstParty: 'phase2-device-first',
  thirdParty: 'phase2-device-third',
  missingGrant: 'phase2-device-nogrant',
  ineligibleWeb: 'phase2-device-web',
});
const deviceUserConsentScopes = Object.freeze(['profile', 'email', 'address', 'phone']);
const referenceDeviceUserConsentScopes = Object.freeze([
  ...deviceUserConsentScopes,
  'urn:logto:scope:organizations',
]);
const candidateDeviceUserConsentScopes = Object.freeze([
  ...deviceUserConsentScopes,
  'urn:aster:scope:organizations',
]);
const deviceResourceScopeIds = Object.freeze(['phase1-read-profile', 'read-scope', 'write-scope']);
const requestTimeoutMs = 10_000;

const phase2PrimaryCoordinatorEntities = Object.freeze([
  ['tenant', 'default', 'default'],
  ['user', 'phase1-user', 'zdata-user'],
  ['application', 'phase1-app', 'phase1-app'],
  ['application', 'phase1-browser', 'phase1-browser'],
  ['resource', 'phase1-api', 'phase1-api'],
  ['scope', 'phase1-read-profile', 'phase1-read-profile'],
  ['role', 'phase1-reader', 'phase1-reader'],
  ['application', 'phase2-m2m-basic', 'phase2-m2m-basic'],
  ['application', 'phase2-m2m-post', 'phase2-m2m-post'],
  ['application', 'phase2-status', 'phase2-status'],
  ['application', 'phase2-device-first', 'phase2-device-first'],
  ['application', 'phase2-device-third', 'phase2-device-third'],
  ['application', 'phase2-device-nogrant', 'phase2-device-nogrant'],
  ['application', 'phase2-device-web', 'phase2-device-web'],
  ['resource', 'phase2-resource-primary', 'p2-resource-primary'],
  ['scope', 'read-scope', 'read-scope'],
  ['scope', 'write-scope', 'write-scope'],
  ['scope', 'unassigned-scope', 'unassigned-scope'],
  ['resource', 'phase2-resource', 'phase2-resource'],
  ['scope', 'default-scope', 'default-scope'],
  ['organization', 'phase2-org', 'phase2-org'],
] as const);
const phase2ForeignCoordinatorEntities = Object.freeze([
  ['tenant', 'default', 'default'],
  ['application', 'phase2-device-first', 'phase2-device-first'],
] as const);

const frozenCandidateFixtures = Object.freeze({
  adminTenant: Object.freeze({
    id: 'admin',
    operator: Object.freeze({
      id: 'phase1-admin',
      username: 'phase1-admin',
      primaryEmail: 'phase1-admin@example.com',
      roles: Object.freeze(['default:admin', 'user']),
      customData: Object.freeze({ ossOnboarding: Object.freeze({ isOnboardingDone: true }) }),
    }),
    application: Object.freeze({
      id: 'admin-console',
      type: 'SPA',
      oidcClientMetadata: Object.freeze({
        redirectUris: Object.freeze(['http://localhost:3002/console/callback']),
        postLogoutRedirectUris: Object.freeze([]),
      }),
      customClientMetadata: Object.freeze({}),
    }),
    resources: Object.freeze([
      Object.freeze({ indicator: 'urn:aster:resource:management', scopes: Object.freeze(['all']) }),
      Object.freeze({ indicator: 'urn:aster:resource:account', scopes: Object.freeze(['all']) }),
      Object.freeze({
        indicator: 'urn:aster:resource:organizations',
        scopes: Object.freeze([
          'urn:aster:scope:organizations',
          'urn:aster:scope:organization_roles',
        ]),
      }),
    ]),
    tenantOrganization: Object.freeze({
      id: 't-default',
      name: 'Tenant default',
      memberUserIds: Object.freeze(['phase1-admin']),
      scopes: Object.freeze([
        'read:data',
        'write:data',
        'delete:data',
        'read:member',
        'invite:member',
        'remove:member',
        'update:member:role',
        'manage:tenant',
      ]),
      organizationRoles: Object.freeze([
        Object.freeze({
          id: 'admin',
          name: 'admin',
          type: 'User',
          scopeNames: Object.freeze([
            'read:data',
            'write:data',
            'delete:data',
            'read:member',
            'invite:member',
            'remove:member',
            'update:member:role',
            'manage:tenant',
          ]),
          userIds: Object.freeze(['phase1-admin']),
        }),
      ]),
    }),
  }),
  dataTenant: Object.freeze({
    id: 'default',
    subject: Object.freeze({
      id: 'phase1-user',
      username: 'phase1-user',
      name: 'phase1-user',
      primaryEmail: 'phase1-user@example.com',
      primaryPhone: '+15555550101',
      profile: Object.freeze({
        address: Object.freeze({ formatted: '1 Aster Way', country: 'US' }),
      }),
      applicationId: null,
    }),
    applications: Object.freeze([
      Object.freeze({
        id: 'phase1-app',
        name: 'Phase 1 Application',
        type: 'SPA',
        isThirdParty: false,
        oidcClientMetadata: Object.freeze({
          redirectUris: Object.freeze(['http://localhost:3001/demo-app']),
          postLogoutRedirectUris: Object.freeze([]),
        }),
        customClientMetadata: Object.freeze({}),
      }),
      Object.freeze({
        id: 'phase1-browser',
        name: 'Phase 1 Consent Client',
        type: 'SPA',
        isThirdParty: true,
        oidcClientMetadata: Object.freeze({
          redirectUris: Object.freeze(['http://localhost:3001/demo-app']),
          postLogoutRedirectUris: Object.freeze([]),
        }),
        customClientMetadata: Object.freeze({}),
        userConsentScopes: Object.freeze(['profile', 'email', 'address', 'phone']),
        resourceConsentScopes: Object.freeze(['phase1-read-profile']),
      }),
    ]),
    resource: Object.freeze({
      id: 'phase1-api',
      name: 'Phase 1 API',
      indicator: 'https://api.example.com',
      scopes: Object.freeze([
        Object.freeze({
          id: 'phase1-read-profile',
          name: 'read:profile',
          description: "Read the signed-in user's profile",
        }),
      ]),
    }),
    resourceScopeRole: Object.freeze({
      id: 'phase1-reader',
      name: 'Phase 1 Reader',
      description: 'Grants the Phase 1 API read scope',
      type: 'User',
      isDefault: false,
      scopeIds: Object.freeze(['phase1-read-profile']),
      userIds: Object.freeze(['phase1-user']),
    }),
    browserClientConfiguration: Object.freeze({
      route: '/demo-app?app_id=phase1-browser',
      localStorageKey: 'aster:demo-app:dev:config',
      localStorageValue: Object.freeze({
        appId: 'phase1-browser',
        prompt: 'login consent',
        scope: 'profile email address phone read:profile',
        resource: 'https://api.example.com',
      }),
      effectiveScopes: Object.freeze([
        'openid',
        'offline_access',
        'profile',
        'email',
        'address',
        'phone',
        'read:profile',
      ]),
      scopeDerivation:
        'the pinned @logto/client 3.1.1 and @logto/js 5.1.0 add openid, offline_access, and profile and deduplicate configured scopes',
      scopeDerivationSources: Object.freeze([
        'pnpm-lock.yaml blob fdc5b51ec59f07b0e8b0440d61dae311acce2aab',
        '@logto/client/lib/types/index.js normalizeLogtoConfig',
        '@logto/js/lib/utils/scopes.js withReservedScopes',
      ]),
    }),
  }),
});

const fail = (message = failure): never => {
  throw new Error(message);
};

const exactRecord = (value: unknown, keys?: readonly string[]): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.some((key) => typeof key !== 'string') ||
    (keys !== undefined &&
      (ownKeys.length !== keys.length || ownKeys.some((key) => !keys.includes(key as string))))
  ) {
    return fail();
  }
  for (const key of ownKeys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }
  }
  return value as Record<string, unknown>;
};

const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const safeId = (value: unknown): string =>
  typeof value === 'string' && safeIdPattern.test(value) ? value : fail();

const safeAllocationId = (value: unknown): string =>
  typeof value === 'string' && safeAllocationPattern.test(value) ? value : fail();

const assertPairwiseTargets = (primary: TargetConfig, foreign: TargetConfig): void => {
  if (
    foreign.label !== primary.label ||
    primary.coreUrl === foreign.coreUrl ||
    primary.adminUrl === foreign.adminUrl
  ) {
    fail();
  }
};

const createFixture = (
  publicFixture: Phase2FixturePublic,
  secrets: FixtureState['secrets'],
  state: FixtureState,
  status: Phase2StatusPublic
): ProvisionedPhase2Fixture => {
  let leaseActive = false;
  const fixture = Object.freeze({
    public: publicFixture,
    status,
    withSecretLease: async <Result>(
      use: (lease: Phase2FixtureSecretLease) => Promise<Result>
    ): Promise<Result> => {
      if (state.revoked || leaseActive || typeof use !== 'function') {
        return fail();
      }
      leaseActive = true;
      const lease = Object.freeze({
        getClientSecret: (logicalClient: 'basic' | 'post') => {
          if (!leaseActive || state.revoked) {
            return fail();
          }
          return secrets[logicalClient];
        },
        getStatusClientSecret: () => {
          if (!leaseActive || state.revoked) {
            return fail();
          }
          return secrets.statusConfidential;
        },
        getSubjectPassword: () => {
          if (!leaseActive || state.revoked) {
            return fail();
          }
          return secrets.subjectPassword;
        },
        toJSON: (): never => fail(),
      });
      try {
        return await use(lease);
      } finally {
        leaseActive = false;
      }
    },
  });
  return fixture;
};

const revoke = (state: FixtureState): void => {
  state.revoked = true;
};

const readBoundedResponseBody = async (
  response: Response,
  maximumBytes: number
): Promise<Uint8Array> => {
  const contentLength = response.headers.get('content-length');
  if (
    contentLength !== null &&
    (!/^(?:0|[1-9]\d*)$/u.test(contentLength) || Number(contentLength) > maximumBytes)
  ) {
    await response.body?.cancel().catch(() => false);
    return fail();
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel().catch(() => false);
        return fail();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
};

const createFetchAdminRequest =
  (target: TargetConfig, requestFetch: typeof fetch = fetch): Phase2AdminRequestFunction =>
  async (input) => {
    if (!/^[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u.test(input.path) || input.path.startsWith('/')) {
      return fail();
    }
    const headers = new Headers({ 'development-user-id': 'integration-test-admin-user' });
    if (input.body !== undefined) {
      headers.set('content-type', 'application/json');
    }
    const response = await requestFetch(new URL(`/api/${input.path}`, target.coreUrl), {
      method: input.method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(requestTimeoutMs),
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    });
    if (!input.expectedStatuses.includes(response.status) || response.redirected) {
      return fail();
    }
    if (input.responseKind === 'status') {
      return response.status;
    }
    const bytes = await readBoundedResponseBody(response, maximumResponseBytes);
    if (input.responseKind === 'empty') {
      return bytes.byteLength === 0 ? undefined : fail();
    }
    const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    if (input.responseKind === 'created') {
      return text === 'Created' ? undefined : fail();
    }
    const value: unknown = JSON.parse(text);
    if (input.responseKind === 'array') {
      return Array.isArray(value) ? (value as unknown[]) : fail();
    }
    return exactRecord(value);
  };

const referenceCall = async (
  request: Phase2AdminRequestFunction,
  method: Phase2AdminRequest['method'],
  apiPath: string,
  body?: unknown,
  expectedStatuses: readonly number[] = [200, 201],
  responseKind: Phase2AdminRequest['responseKind'] = 'object'
): Promise<unknown> => request({ method, path: apiPath, body, expectedStatuses, responseKind });

const referencePublicFixture = (
  allocationId: string,
  values: Readonly<{
    basicId: string;
    postId: string;
    primaryId: string;
    defaultId: string;
    readId: string;
    writeId: string;
    unassignedId: string;
    organizationId: string;
    deviceFirstPartyId: string;
    deviceThirdPartyId: string;
    deviceMissingGrantId: string;
    deviceIneligibleWebId: string;
  }>
): Phase2FixturePublic =>
  Object.freeze({
    allocationId,
    clients: Object.freeze({
      basic: Object.freeze({ id: values.basicId, method: 'client_secret_basic' }),
      post: Object.freeze({ id: values.postId, method: 'client_secret_post' }),
    }),
    deviceClients: Object.freeze({
      firstParty: Object.freeze({
        id: values.deviceFirstPartyId,
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      }),
      thirdParty: Object.freeze({
        id: values.deviceThirdPartyId,
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      }),
      missingGrant: Object.freeze({
        id: values.deviceMissingGrantId,
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
      ineligibleWeb: Object.freeze({
        id: values.deviceIneligibleWebId,
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({ id: values.primaryId, indicator: primaryIndicator }),
      default: Object.freeze({ id: values.defaultId, indicator: defaultIndicator }),
    }),
    organization: Object.freeze({ id: values.organizationId, scopeName: 'organization:read' }),
    scopes: Object.freeze({
      read: Object.freeze({ id: values.readId, name: 'read' }),
      write: Object.freeze({ id: values.writeId, name: 'write' }),
      unassigned: Object.freeze({ id: values.unassignedId, name: 'unassigned' }),
    }),
    boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
  });

const allocationSuffix = (allocationId: string): string =>
  createHash('sha256').update(allocationId).digest('hex').slice(0, 16);

const statusUsername = (allocationId: string): string =>
  `phase1_user_a_${allocationSuffix(allocationId)}`;

const candidateStatusIndicator = (allocationId: string): string => {
  const url = new URL(statusIndicator);
  url.searchParams.set('aster_fixture', allocationSuffix(allocationId));
  return url.toString();
};

const candidatePublicFixture = (allocationId: string): Phase2FixturePublic =>
  referencePublicFixture(allocationId, {
    basicId: logicalClientIds.basic,
    postId: logicalClientIds.post,
    primaryId: 'phase2-resource-primary',
    defaultId: 'phase2-resource',
    readId: 'read-scope',
    writeId: 'write-scope',
    unassignedId: 'unassigned-scope',
    organizationId: 'phase2-org',
    deviceFirstPartyId: logicalDeviceClientIds.firstParty,
    deviceThirdPartyId: logicalDeviceClientIds.thirdParty,
    deviceMissingGrantId: logicalDeviceClientIds.missingGrant,
    deviceIneligibleWebId: logicalDeviceClientIds.ineligibleWeb,
  });

const referenceOwnedDefinitions = (allocationId: string) => {
  const marker = `${markerPrefix}${allocationId}`;
  return Object.freeze([
    Object.freeze({
      path: 'organizations',
      owns: (row: Record<string, unknown>) => own(row, 'name') === `Phase 2 ${marker} organization`,
    }),
    Object.freeze({
      path: 'applications',
      owns: (row: Record<string, unknown>) =>
        own(row, 'name') === `Phase 2 ${marker} basic client` ||
        own(row, 'name') === `Phase 2 ${marker} post client` ||
        own(row, 'name') === `Phase 2 ${marker} confidential status client` ||
        own(row, 'name') === `Phase 2 ${marker} status client` ||
        own(row, 'name') === `Phase 2 ${marker} first-party device client` ||
        own(row, 'name') === `Phase 2 ${marker} third-party device client` ||
        own(row, 'name') === `Phase 2 ${marker} missing-grant device client` ||
        own(row, 'name') === `Phase 2 ${marker} ineligible-web device client`,
    }),
    Object.freeze({
      path: 'users',
      owns: (row: Record<string, unknown>) => own(row, 'username') === statusUsername(allocationId),
    }),
    Object.freeze({
      path: 'organization-roles',
      owns: (row: Record<string, unknown>) => own(row, 'name') === `${marker}-organization-role`,
    }),
    Object.freeze({
      path: 'organization-scopes',
      owns: (row: Record<string, unknown>) =>
        own(row, 'description') === `Phase 2 ${marker} organization scope`,
    }),
    Object.freeze({
      path: 'roles',
      owns: (row: Record<string, unknown>) =>
        own(row, 'name') === `${marker}-resource-role` ||
        own(row, 'name') === `${marker}-device-subject-role` ||
        own(row, 'name') === `${marker}-status-role`,
    }),
    Object.freeze({
      path: 'resources',
      owns: (row: Record<string, unknown>) =>
        own(row, 'name') === `Phase 2 ${marker} primary resource` ||
        own(row, 'name') === `Phase 2 ${marker} default resource` ||
        own(row, 'name') === `Phase 2 ${marker} status resource`,
    }),
  ]);
};

const referenceReconcile = async (
  request: Phase2AdminRequestFunction,
  allocationId: string
): Promise<void> => {
  const definitions = referenceOwnedDefinitions(allocationId);

  for (const definition of definitions) {
    const listed = await referenceCall(request, 'GET', definition.path, undefined, [200], 'array');
    if (!Array.isArray(listed)) {
      return fail(cleanupFailure);
    }
    for (const rawRow of listed) {
      const row = exactRecord(rawRow);
      if (definition.owns(row)) {
        await referenceCall(
          request,
          'DELETE',
          `${definition.path}/${encodeURIComponent(safeId(own(row, 'id')))}`,
          undefined,
          [204, 404],
          'status'
        );
      }
    }
  }
};

const assertReferenceCleanup = async (
  request: Phase2AdminRequestFunction,
  allocationId: string,
  previousDefaultResourceId: string | undefined
): Promise<void> => {
  for (const definition of referenceOwnedDefinitions(allocationId)) {
    const listed = await referenceCall(request, 'GET', definition.path, undefined, [200], 'array');
    if (
      !Array.isArray(listed) ||
      listed.map((entry) => exactRecord(entry)).some((row) => definition.owns(row))
    ) {
      return fail(cleanupFailure);
    }
  }
  const resources = await referenceCall(request, 'GET', 'resources', undefined, [200], 'array');
  if (!Array.isArray(resources)) {
    return fail(cleanupFailure);
  }
  const rows = resources.map((entry) => exactRecord(entry));
  const defaults = rows.filter((row) => own(row, 'isDefault') === true);
  if (
    previousDefaultResourceId === undefined
      ? defaults.length > 0
      : defaults.length !== 1 || own(defaults[0] ?? {}, 'id') !== previousDefaultResourceId
  ) {
    return fail(cleanupFailure);
  }
};

export const createReferencePhase2FixtureProvisioner = (
  options: ReferenceProvisionerOptions
): Phase2FixtureProvisioner => {
  const target = validateTargetConfig(options.target);
  const foreignTarget = validateTargetConfig(options.foreignTarget);
  assertPairwiseTargets(target, foreignTarget);
  const request = options.request ?? createFetchAdminRequest(target);
  const createAllocationId = options.createAllocationId ?? randomUUID;
  const states = new WeakMap<object, FixtureState & { journal: ReferenceCleanup[] }>();

  const cleanupState = async (
    state: FixtureState & { journal: ReferenceCleanup[] },
    fixture?: ProvisionedPhase2Fixture
  ): Promise<void> => {
    if (fixture) {
      revoke(state);
    }
    if (state.cleanup) {
      return state.cleanup;
    }
    const cleanup = (async () => {
      const failures: unknown[] = [];
      while (state.journal.length > 0) {
        const operation = state.journal.pop();
        if (!operation) {
          break;
        }
        try {
          await referenceCall(request, 'DELETE', operation.path, undefined, [204, 404], 'status');
        } catch (error: unknown) {
          failures.push(error);
        }
      }
      try {
        await referenceReconcile(request, state.allocationId);
      } catch (error: unknown) {
        failures.push(error);
      }
      if (state.previousDefaultResourceId) {
        try {
          await referenceCall(
            request,
            'PATCH',
            `resources/${encodeURIComponent(state.previousDefaultResourceId)}/is-default`,
            { isDefault: true },
            [200]
          );
        } catch (error: unknown) {
          failures.push(error);
        }
      }
      if (state.previousSignInExperience) {
        try {
          await referenceCall(request, 'PATCH', 'sign-in-exp', state.previousSignInExperience, [
            200,
          ]);
        } catch (error: unknown) {
          failures.push(error);
        }
      }
      if (state.previousAccountCenter) {
        try {
          await referenceCall(request, 'PATCH', 'account-center', state.previousAccountCenter, [
            200,
          ]);
        } catch (error: unknown) {
          failures.push(error);
        }
      }
      try {
        await assertReferenceCleanup(request, state.allocationId, state.previousDefaultResourceId);
      } catch (error: unknown) {
        failures.push(error);
      }
      if (failures.length > 0) {
        throw new AggregateError(failures, cleanupFailure);
      }
    })();
    state.cleanup = cleanup;
    try {
      await cleanup;
    } finally {
      state.cleanup = undefined;
    }
  };

  return Object.freeze({
    provision: async (): Promise<ProvisionedPhase2Fixture> => {
      const allocationId = safeAllocationId(createAllocationId());
      const marker = `${markerPrefix}${allocationId}`;
      const subjectPassword = `${randomBytes(20).toString('base64url')}A1!`;
      const state: FixtureState & { journal: ReferenceCleanup[] } = {
        allocationId,
        secrets: Object.freeze({
          basic: '',
          post: '',
          statusConfidential: '',
          subjectPassword,
        }),
        sensitiveValues: Object.freeze([subjectPassword]),
        revoked: false,
        journal: [],
      };
      const add = (name: string, apiPath: string): void => {
        state.journal.push(Object.freeze({ name, path: apiPath }));
      };
      try {
        const existingResources = await referenceCall(
          request,
          'GET',
          'resources',
          undefined,
          [200],
          'array'
        );
        if (!Array.isArray(existingResources)) {
          return fail();
        }
        const defaults = existingResources
          .map((entry) => exactRecord(entry))
          .filter((entry) => own(entry, 'isDefault') === true);
        if (defaults.length > 1) {
          return fail();
        }
        if (defaults[0]) {
          state.previousDefaultResourceId = safeId(own(defaults[0], 'id'));
        }
        const createApplication = async (label: 'basic' | 'post') => {
          const application = exactRecord(
            await referenceCall(request, 'POST', 'applications', {
              name: `Phase 2 ${marker} ${label} client`,
              type: 'MachineToMachine',
            })
          );
          const id = safeId(own(application, 'id'));
          add(`application-${label}`, `applications/${encodeURIComponent(id)}`);
          const secrets = await referenceCall(
            request,
            'GET',
            `applications/${encodeURIComponent(id)}/secrets`,
            undefined,
            [200],
            'array'
          );
          if (!Array.isArray(secrets) || secrets.length !== 1) {
            return fail();
          }
          const secret = own(exactRecord(secrets[0]), 'value');
          if (typeof secret !== 'string' || !/^[A-Za-z0-9]{32}$/u.test(secret)) {
            return fail();
          }
          return Object.freeze({ id, secret });
        };
        const createResource = async (label: 'primary' | 'default', indicator: string) => {
          const resource = exactRecord(
            await referenceCall(
              request,
              'POST',
              'resources',
              { name: `Phase 2 ${marker} ${label} resource`, indicator },
              [201]
            )
          );
          const id = safeId(own(resource, 'id'));
          add(`resource-${label}`, `resources/${encodeURIComponent(id)}`);
          return Object.freeze({ id, indicator });
        };
        const createScope = async (
          resource: Readonly<{ id: string }>,
          name: 'read' | 'write' | 'unassigned'
        ) => {
          const scope = exactRecord(
            await referenceCall(
              request,
              'POST',
              `resources/${encodeURIComponent(resource.id)}/scopes`,
              { name, description: `Phase 2 ${name}` },
              [201]
            )
          );
          const id = safeId(own(scope, 'id'));
          add(
            `resource-scope-${name}`,
            `resources/${encodeURIComponent(resource.id)}/scopes/${encodeURIComponent(id)}`
          );
          return Object.freeze({ id, name });
        };

        const basic = await createApplication('basic');
        const post = await createApplication('post');
        const statusConfidentialApplication = exactRecord(
          await referenceCall(request, 'POST', 'applications', {
            name: `Phase 2 ${marker} confidential status client`,
            type: 'Traditional',
            isThirdParty: true,
            oidcClientMetadata: {
              redirectUris: [statusRedirectUri],
              postLogoutRedirectUris: [],
            },
            customClientMetadata: { alwaysIssueRefreshToken: true },
          })
        );
        const referenceStatusConfidentialClientId = safeId(
          own(statusConfidentialApplication, 'id')
        );
        add(
          'status-confidential-client',
          `applications/${encodeURIComponent(referenceStatusConfidentialClientId)}`
        );
        const statusConfidentialSecrets = await referenceCall(
          request,
          'GET',
          `applications/${encodeURIComponent(referenceStatusConfidentialClientId)}/secrets`,
          undefined,
          [200],
          'array'
        );
        if (!Array.isArray(statusConfidentialSecrets) || statusConfidentialSecrets.length !== 1) {
          return fail();
        }
        const statusConfidentialSecret = own(exactRecord(statusConfidentialSecrets[0]), 'value');
        if (
          typeof statusConfidentialSecret !== 'string' ||
          !/^[A-Za-z0-9]{32}$/u.test(statusConfidentialSecret)
        ) {
          return fail();
        }
        state.secrets = Object.freeze({
          basic: basic.secret,
          post: post.secret,
          statusConfidential: statusConfidentialSecret,
          subjectPassword,
        });
        state.sensitiveValues = Object.freeze([
          basic.secret,
          post.secret,
          statusConfidentialSecret,
          subjectPassword,
        ]);
        const primary = await createResource('primary', primaryIndicator);
        const defaultResource = await createResource('default', defaultIndicator);
        const read = await createScope(primary, 'read');
        const write = await createScope(primary, 'write');
        const unassigned = await createScope(primary, 'unassigned');
        const resourceRole = exactRecord(
          await referenceCall(request, 'POST', 'roles', {
            name: `${marker}-resource-role`,
            description: `Phase 2 ${marker} resource authority`,
            type: 'MachineToMachine',
            scopeIds: [read.id, write.id],
          })
        );
        const resourceRoleId = safeId(own(resourceRole, 'id'));
        add('resource-role', `roles/${encodeURIComponent(resourceRoleId)}`);
        for (const [label, client] of [
          ['basic', basic],
          ['post', post],
        ] as const) {
          add(
            `application-${label}-resource-role`,
            `applications/${encodeURIComponent(client.id)}/roles/${encodeURIComponent(resourceRoleId)}`
          );
          await referenceCall(
            request,
            'POST',
            `applications/${encodeURIComponent(client.id)}/roles`,
            { roleIds: [resourceRoleId] },
            [201]
          );
        }
        const organization = exactRecord(
          await referenceCall(
            request,
            'POST',
            'organizations',
            { name: `Phase 2 ${marker} organization` },
            [201]
          )
        );
        const organizationId = safeId(own(organization, 'id'));
        add('organization', `organizations/${encodeURIComponent(organizationId)}`);
        const organizationScope = exactRecord(
          await referenceCall(
            request,
            'POST',
            'organization-scopes',
            {
              name: 'organization:read',
              description: `Phase 2 ${marker} organization scope`,
            },
            [201]
          )
        );
        const organizationScopeId = safeId(own(organizationScope, 'id'));
        add('organization-scope', `organization-scopes/${encodeURIComponent(organizationScopeId)}`);
        const organizationRole = exactRecord(
          await referenceCall(
            request,
            'POST',
            'organization-roles',
            {
              name: `${marker}-organization-role`,
              description: `Phase 2 ${marker} organization authority`,
              type: 'MachineToMachine',
              organizationScopeIds: [organizationScopeId],
              resourceScopeIds: [read.id, write.id],
            },
            [201]
          )
        );
        const organizationRoleId = safeId(own(organizationRole, 'id'));
        add('organization-role', `organization-roles/${encodeURIComponent(organizationRoleId)}`);
        add(
          'organization-application-association',
          `organizations/${encodeURIComponent(organizationId)}/applications/${encodeURIComponent(basic.id)}`
        );
        await referenceCall(
          request,
          'POST',
          `organizations/${encodeURIComponent(organizationId)}/applications`,
          { applicationIds: [basic.id] },
          [201],
          'created'
        );
        add(
          'organization-application-role',
          `organizations/${encodeURIComponent(organizationId)}/applications/${encodeURIComponent(basic.id)}/roles/${encodeURIComponent(organizationRoleId)}`
        );
        await referenceCall(
          request,
          'POST',
          `organizations/${encodeURIComponent(organizationId)}/applications/${encodeURIComponent(basic.id)}/roles`,
          { organizationRoleIds: [organizationRoleId] },
          [201],
          'created'
        );
        const username = statusUsername(allocationId);
        const user = exactRecord(
          await referenceCall(request, 'POST', 'users', {
            username,
            password: subjectPassword,
            name: `Phase 2 ${marker} status user`,
          })
        );
        const statusUserId = safeId(own(user, 'id'));
        add('status-user', `users/${encodeURIComponent(statusUserId)}`);
        add(
          'organization-user-association',
          `organizations/${encodeURIComponent(organizationId)}/users/${encodeURIComponent(statusUserId)}`
        );
        await referenceCall(
          request,
          'POST',
          `organizations/${encodeURIComponent(organizationId)}/users`,
          { userIds: [statusUserId] },
          [201],
          'status'
        );
        const deviceSubjectRole = exactRecord(
          await referenceCall(request, 'POST', 'roles', {
            name: `${marker}-device-subject-role`,
            description: `Phase 2 ${marker} device subject authority`,
            type: 'User',
            isDefault: false,
            scopeIds: [read.id],
          })
        );
        const deviceSubjectRoleId = safeId(own(deviceSubjectRole, 'id'));
        add('device-subject-role', `roles/${encodeURIComponent(deviceSubjectRoleId)}`);
        add(
          'device-subject-role-user-association',
          `roles/${encodeURIComponent(deviceSubjectRoleId)}/users/${encodeURIComponent(statusUserId)}`
        );
        await referenceCall(
          request,
          'POST',
          `roles/${encodeURIComponent(deviceSubjectRoleId)}/users`,
          { userIds: [statusUserId] },
          [201],
          'status'
        );
        const statusResource = exactRecord(
          await referenceCall(request, 'POST', 'resources', {
            name: `Phase 2 ${marker} status resource`,
            indicator: statusIndicator,
          })
        );
        const statusResourceId = safeId(own(statusResource, 'id'));
        add('status-resource', `resources/${encodeURIComponent(statusResourceId)}`);
        const statusScope = exactRecord(
          await referenceCall(
            request,
            'POST',
            `resources/${encodeURIComponent(statusResourceId)}/scopes`,
            {
              name: 'read:profile',
              description: `Phase 2 ${marker} status scope`,
            }
          )
        );
        const statusScopeId = safeId(own(statusScope, 'id'));
        add(
          'status-scope',
          `resources/${encodeURIComponent(statusResourceId)}/scopes/${encodeURIComponent(statusScopeId)}`
        );
        const statusRole = exactRecord(
          await referenceCall(request, 'POST', 'roles', {
            name: `${marker}-status-role`,
            description: `Phase 2 ${marker} status authority`,
            type: 'User',
            isDefault: false,
            scopeIds: [statusScopeId],
          })
        );
        const statusRoleId = safeId(own(statusRole, 'id'));
        add('status-role', `roles/${encodeURIComponent(statusRoleId)}`);
        await referenceCall(
          request,
          'POST',
          `roles/${encodeURIComponent(statusRoleId)}/users`,
          { userIds: [statusUserId] },
          [201],
          'status'
        );
        await referenceCall(
          request,
          'POST',
          `applications/${encodeURIComponent(referenceStatusConfidentialClientId)}/user-consent-scopes`,
          {
            userScopes: ['profile', 'email', 'address', 'phone', 'urn:logto:scope:sessions'],
            resourceScopes: [statusScopeId],
          },
          [201],
          'status'
        );
        const createDeviceApplication = async (
          label: 'first-party' | 'third-party' | 'missing-grant' | 'ineligible-web',
          isThirdParty: boolean,
          deviceGrantEnabled: boolean,
          applicationType: 'Native' | 'SPA' = 'Native'
        ): Promise<string> => {
          const application = exactRecord(
            await referenceCall(request, 'POST', 'applications', {
              name: `Phase 2 ${marker} ${label} device client`,
              type: applicationType,
              isThirdParty,
              oidcClientMetadata: {
                redirectUris: label === 'ineligible-web' ? [statusRedirectUri] : [],
                postLogoutRedirectUris: [],
              },
              customClientMetadata: deviceGrantEnabled ? { isDeviceFlow: true } : {},
            })
          );
          const id = safeId(own(application, 'id'));
          add(`device-client-${label}`, `applications/${encodeURIComponent(id)}`);
          if (isThirdParty) {
            await referenceCall(
              request,
              'POST',
              `applications/${encodeURIComponent(id)}/user-consent-scopes`,
              {
                userScopes: referenceDeviceUserConsentScopes,
                resourceScopes: [statusScopeId, read.id, write.id],
              },
              [201],
              'status'
            );
          }
          return id;
        };
        const deviceFirstPartyId = await createDeviceApplication('first-party', false, true);
        const deviceThirdPartyId = await createDeviceApplication('third-party', true, true);
        const deviceMissingGrantId = await createDeviceApplication('missing-grant', false, false);
        const deviceIneligibleWebId = await createDeviceApplication(
          'ineligible-web',
          false,
          false,
          'SPA'
        );
        const accountCenter = exactRecord(
          await referenceCall(request, 'GET', 'account-center', undefined, [200])
        );
        const accountCenterEnabled = own(accountCenter, 'enabled');
        const accountCenterFields = exactRecord(own(accountCenter, 'fields'));
        if (
          typeof accountCenterEnabled !== 'boolean' ||
          Object.values(accountCenterFields).some(
            (value) => !['Off', 'ReadOnly', 'Edit'].includes(String(value))
          )
        ) {
          return fail();
        }
        state.previousAccountCenter = Object.freeze({
          enabled: accountCenterEnabled,
          fields: Object.freeze({ ...accountCenterFields }),
        });
        await referenceCall(
          request,
          'PATCH',
          'account-center',
          {
            enabled: true,
            fields: { ...accountCenterFields, session: 'Edit' },
          },
          [200]
        );
        const statusClient = exactRecord(
          await referenceCall(request, 'POST', 'applications', {
            name: `Phase 2 ${marker} status client`,
            type: 'SPA',
            isThirdParty: true,
            oidcClientMetadata: {
              redirectUris: [statusRedirectUri],
              postLogoutRedirectUris: [],
            },
            customClientMetadata: {},
          })
        );
        const statusClientId = safeId(own(statusClient, 'id'));
        add('status-client', `applications/${encodeURIComponent(statusClientId)}`);
        await referenceCall(
          request,
          'POST',
          `applications/${encodeURIComponent(statusClientId)}/user-consent-scopes`,
          {
            userScopes: ['profile', 'email', 'address', 'phone', 'urn:logto:scope:sessions'],
            resourceScopes: [statusScopeId],
          },
          [201],
          'status'
        );
        const signInExperience = exactRecord(
          await referenceCall(request, 'GET', 'sign-in-exp', undefined, [200])
        );
        state.previousSignInExperience = signInExperience;
        await referenceCall(request, 'PATCH', 'sign-in-exp', {
          signInMode: 'SignInAndRegister',
          signUp: { identifiers: [], password: false, verify: false },
          signIn: {
            methods: [
              {
                identifier: 'username',
                password: true,
                verificationCode: false,
                isPasswordPrimary: false,
              },
            ],
          },
          mfa: { factors: [], policy: 'PromptAtSignInAndSignUp' },
        });
        await referenceCall(
          request,
          'PATCH',
          `resources/${encodeURIComponent(defaultResource.id)}/is-default`,
          { isDefault: true },
          [200]
        );
        const publicFixture = referencePublicFixture(allocationId, {
          basicId: basic.id,
          postId: post.id,
          primaryId: primary.id,
          defaultId: defaultResource.id,
          readId: read.id,
          writeId: write.id,
          unassignedId: unassigned.id,
          organizationId,
          deviceFirstPartyId,
          deviceThirdPartyId,
          deviceMissingGrantId,
          deviceIneligibleWebId,
        });
        const fixture = createFixture(publicFixture, state.secrets, state, {
          user: Object.freeze({ id: statusUserId, username }),
          client: Object.freeze({ id: statusClientId, redirectUri: statusRedirectUri }),
          confidentialClient: Object.freeze({
            id: referenceStatusConfidentialClientId,
            redirectUri: statusRedirectUri,
          }),
          resource: Object.freeze({
            id: statusResourceId,
            indicator: statusIndicator,
            scopeName: 'read:profile',
          }),
        });
        states.set(fixture as object, state);
        return fixture;
      } catch (error: unknown) {
        try {
          await cleanupState(state);
        } catch (cleanupError: unknown) {
          throw new AggregateError([error, cleanupError], failure);
        }
        throw new Error(failure);
      }
    },
    projectState: async (fixture: ProvisionedPhase2Fixture): Promise<unknown> => {
      const state = states.get(fixture as object);
      if (!state || state.revoked) {
        return fail();
      }
      return Object.freeze({
        allocationId: state.allocationId,
        authority: Object.freeze({
          clients: Object.freeze(['basic', 'post']),
          resources: Object.freeze(['primary', 'default']),
          organization: 'primary',
        }),
        boundary: fixture.public.boundary,
      });
    },
    cleanup: async (fixture: ProvisionedPhase2Fixture): Promise<void> => {
      const state = states.get(fixture as object);
      if (!state) {
        return fail(cleanupFailure);
      }
      await cleanupState(state, fixture);
      states.delete(fixture as object);
    },
  });
};

const commandEnvironment = (
  target: TargetConfig,
  foreignTarget: TargetConfig,
  environment: CandidateProvisionerOptions['environment']
): Readonly<Record<string, string>> => {
  const fixtureSocket = environment?.ASTER_FIXTURE_SOCKET;
  if (typeof fixtureSocket !== 'string' || !fixtureSocket.startsWith('/')) {
    return fail();
  }
  return Object.freeze({
    ASTER_FIXTURE_SOCKET: fixtureSocket,
    ASTER_TARGET_LABEL: target.label,
    ASTER_CORE_URL: target.coreUrl,
    ASTER_ADMIN_URL: target.adminUrl,
    ASTER_FOREIGN_CORE_URL: foreignTarget.coreUrl,
    ASTER_FOREIGN_ADMIN_URL: foreignTarget.adminUrl,
    LC_ALL: 'C',
  });
};

const requireCommandResult = (value: unknown): CommandRunnerResult => {
  const result = exactRecord(value, [
    'exitCode',
    'signal',
    'stdout',
    'stderr',
    'timedOut',
    'killed',
    'reaped',
  ]);
  const stdout = own(result, 'stdout');
  const stderr = own(result, 'stderr');
  if (
    own(result, 'exitCode') !== 0 ||
    own(result, 'signal') !== null ||
    typeof stdout !== 'string' ||
    typeof stderr !== 'string' ||
    stderr !== '' ||
    Buffer.byteLength(stdout) > maximumCommandOutputBytes ||
    Buffer.byteLength(stderr) > maximumCommandOutputBytes ||
    own(result, 'timedOut') !== false ||
    own(result, 'killed') !== false ||
    own(result, 'reaped') !== true
  ) {
    return fail();
  }
  return value as CommandRunnerResult;
};

const requireRejectedCommandResult = (value: unknown): CommandRunnerResult => {
  const result = exactRecord(value, [
    'exitCode',
    'signal',
    'stdout',
    'stderr',
    'timedOut',
    'killed',
    'reaped',
  ]);
  const stdout = own(result, 'stdout');
  const stderr = own(result, 'stderr');
  if (
    own(result, 'exitCode') !== 1 ||
    own(result, 'signal') !== null ||
    stdout !== '' ||
    stderr !== 'Aster compatibility fixture command failed\n' ||
    own(result, 'timedOut') !== false ||
    own(result, 'killed') !== false ||
    own(result, 'reaped') !== true
  ) {
    return fail();
  }
  return value as CommandRunnerResult;
};

const parseCommandOutput = (
  result: CommandRunnerResult,
  operation: 'provision' | 'projectState' | 'cleanup',
  secrets: readonly string[]
): Record<string, unknown> => {
  try {
    assertPhase1RuntimeCredentialGraphIsSanitized(
      { stdout: result.stdout, stderr: result.stderr },
      secrets
    );
    const parsed = exactRecord(JSON.parse(result.stdout) as unknown);
    if (own(parsed, 'schemaVersion') !== 1 || own(parsed, 'operation') !== operation) {
      return fail();
    }
    assertPhase1RuntimeCredentialGraphIsSanitized(parsed, secrets);
    return parsed;
  } catch {
    return fail();
  }
};

const validateCoordinatorPublic = (
  value: unknown,
  allocationId: string,
  recipe: Phase2CandidateFixtureRecipe
): Readonly<Record<string, unknown>> => {
  const publicMap = exactRecord(value, ['schemaVersion', 'recipe', 'allocations']);
  const allocations = own(publicMap, 'allocations');
  const expectedAllocations =
    recipe === 'phase2CandidateInvariants'
      ? ([
          {
            role: 'data',
            target: 'primary',
            entities: phase2PrimaryCoordinatorEntities,
          },
          {
            role: 'foreign',
            target: 'foreign',
            entities: phase2ForeignCoordinatorEntities,
          },
        ] as const)
      : ([
          {
            role: 'data',
            target: 'primary',
            entities: phase2PrimaryCoordinatorEntities,
          },
        ] as const);
  if (
    own(publicMap, 'schemaVersion') !== 1 ||
    own(publicMap, 'recipe') !== recipe ||
    !Array.isArray(allocations) ||
    allocations.length !== expectedAllocations.length
  ) {
    return fail();
  }
  const closedAllocations = expectedAllocations.map((expected, index) => {
    const allocation = exactRecord(allocations[index], [
      'allocationId',
      'role',
      'target',
      'entities',
    ]);
    const entities = own(allocation, 'entities');
    if (
      own(allocation, 'allocationId') !== allocationId ||
      own(allocation, 'role') !== expected.role ||
      own(allocation, 'target') !== expected.target ||
      !Array.isArray(entities) ||
      entities.length !== expected.entities.length
    ) {
      return fail();
    }
    const closedEntities = expected.entities.map(([kind, logicalId, runtimeId], entityIndex) => {
      const entity = exactRecord(entities[entityIndex], ['kind', 'logicalId', 'runtimeId']);
      if (
        own(entity, 'kind') !== kind ||
        own(entity, 'logicalId') !== logicalId ||
        own(entity, 'runtimeId') !== runtimeId
      ) {
        return fail();
      }
      return Object.freeze({ kind, logicalId, runtimeId });
    });
    return Object.freeze({
      allocationId,
      role: expected.role,
      target: expected.target,
      entities: Object.freeze(closedEntities),
    });
  });
  return Object.freeze({
    schemaVersion: 1,
    recipe,
    allocations: Object.freeze(closedAllocations),
  });
};

export const createCandidatePhase2FixtureProvisioner = (
  options: CandidateProvisionerOptions
): Phase2FixtureProvisioner => {
  const target = validateTargetConfig(options.target);
  const foreignTarget = validateTargetConfig(options.foreignTarget);
  assertPairwiseTargets(target, foreignTarget);
  const environment = commandEnvironment(target, foreignTarget, options.environment ?? process.env);
  const runner = options.runner ?? runPhase1FixtureCommand;
  const createAllocationId = options.createAllocationId ?? randomUUID;
  const createSecret = options.createSecret ?? (() => randomBytes(16).toString('hex'));
  const recipe = options.recipe ?? 'dataProtocol';
  const states = new WeakMap<object, FixtureState>();

  const run = async (
    descriptor: Readonly<Record<string, unknown>>,
    operation: 'provision' | 'projectState' | 'cleanup',
    secrets: readonly string[]
  ): Promise<Record<string, unknown>> => {
    const invoke = async () =>
      requireCommandResult(
        await runner({
          command: options.executablePath,
          args: Object.freeze(['fixture', 'apply']),
          stdin: JSON.stringify(descriptor),
          env: environment,
          timeoutMs: commandTimeoutMs,
          maxStdoutBytes: maximumCommandOutputBytes,
          maxStderrBytes: maximumCommandOutputBytes,
          shell: false,
        })
      );
    const result = options.identityFence ? await options.identityFence.run(invoke) : await invoke();
    return parseCommandOutput(result, operation, secrets);
  };

  const runRejected = async (
    descriptor: Readonly<Record<string, unknown>>,
    secrets: readonly string[]
  ): Promise<void> => {
    const invoke = async () =>
      requireRejectedCommandResult(
        await runner({
          command: options.executablePath,
          args: Object.freeze(['fixture', 'apply']),
          stdin: JSON.stringify(descriptor),
          env: environment,
          timeoutMs: commandTimeoutMs,
          maxStdoutBytes: maximumCommandOutputBytes,
          maxStderrBytes: maximumCommandOutputBytes,
          shell: false,
        })
      );
    const result = options.identityFence ? await options.identityFence.run(invoke) : await invoke();
    assertPhase1RuntimeCredentialGraphIsSanitized(
      { stdout: result.stdout, stderr: result.stderr },
      secrets
    );
  };

  const cleanupAllocation = async (state: FixtureState): Promise<void> => {
    try {
      const descriptor = Object.freeze({
        schemaVersion: 1,
        operation: 'cleanup',
        recipe,
        allocationId: state.allocationId,
        ...(state.coordinatorPublic && { public: state.coordinatorPublic }),
      });
      const result = await run(descriptor, 'cleanup', state.sensitiveValues);
      if (own(result, 'ok') !== true) {
        return fail(cleanupFailure);
      }
      await runRejected(descriptor, state.sensitiveValues);
    } catch {
      return fail(cleanupFailure);
    }
  };

  const cleanupState = async (state: FixtureState): Promise<void> => {
    revoke(state);
    if (state.cleanup) {
      return state.cleanup;
    }
    const cleanup = cleanupAllocation(state);
    state.cleanup = cleanup;
    try {
      await cleanup;
    } finally {
      state.cleanup = undefined;
    }
  };

  return Object.freeze({
    provision: async (): Promise<ProvisionedPhase2Fixture> => {
      const allocationId = safeAllocationId(createAllocationId());
      const basic = createSecret();
      const post = createSecret();
      const statusConfidential = createSecret();
      const subjectPassword = createSecret();
      const secrets = Object.freeze({
        basic,
        post,
        statusConfidential,
        subjectPassword,
      });
      if (
        secrets.basic === secrets.post ||
        statusConfidential === secrets.basic ||
        statusConfidential === secrets.post ||
        subjectPassword === secrets.basic ||
        subjectPassword === secrets.post ||
        subjectPassword === statusConfidential ||
        !/^[a-z0-9]{32}$/u.test(secrets.basic) ||
        !/^[a-z0-9]{32}$/u.test(secrets.post) ||
        !/^[a-z0-9]{32}$/u.test(statusConfidential) ||
        !/^[a-z0-9]{32}$/u.test(subjectPassword)
      ) {
        return fail();
      }
      const state: FixtureState = {
        allocationId,
        secrets,
        sensitiveValues: Object.freeze([
          secrets.basic,
          secrets.post,
          statusConfidential,
          subjectPassword,
        ]),
        revoked: false,
      };
      const phase2 = Object.freeze({
        subjectPrimaryEmail: null,
        subjectResourceScopeIds: Object.freeze(['read-scope']),
        machineClients: Object.freeze([
          Object.freeze({
            clientId: logicalClientIds.basic,
            grantTypes: Object.freeze(['client_credentials']),
            resourceScopeIds: Object.freeze(['read-scope', 'write-scope']),
            organizations: Object.freeze([
              Object.freeze({
                organizationId: 'phase2-org',
                scopeNames: Object.freeze(['organization:read']),
                resourceScopeIds: Object.freeze(['read-scope', 'write-scope']),
              }),
            ]),
          }),
          Object.freeze({
            clientId: logicalClientIds.post,
            grantTypes: Object.freeze(['client_credentials']),
            resourceScopeIds: Object.freeze(['read-scope', 'write-scope']),
            organizations: Object.freeze([]),
          }),
        ]),
        defaultResourceId: 'phase2-resource',
        statusClient: Object.freeze({
          clientId: statusConfidentialClientId,
          redirectUri: statusRedirectUri,
          authenticationMethod: 'client_secret_basic',
          userConsentScopes: Object.freeze([
            'profile',
            'email',
            'address',
            'phone',
            'urn:aster:scope:sessions',
          ]),
          resourceScopeIds: Object.freeze(['phase1-read-profile']),
        }),
        deviceClients: Object.freeze([
          Object.freeze({
            clientId: logicalDeviceClientIds.firstParty,
            applicationType: 'Native',
            authenticationMethod: 'none',
            isThirdParty: false,
            grantTypes: Object.freeze([deviceGrant]),
            userConsentScopes: candidateDeviceUserConsentScopes,
            resourceScopeIds: deviceResourceScopeIds,
          }),
          Object.freeze({
            clientId: logicalDeviceClientIds.thirdParty,
            applicationType: 'Native',
            authenticationMethod: 'none',
            isThirdParty: true,
            grantTypes: Object.freeze([deviceGrant]),
            userConsentScopes: candidateDeviceUserConsentScopes,
            resourceScopeIds: deviceResourceScopeIds,
          }),
          Object.freeze({
            clientId: logicalDeviceClientIds.missingGrant,
            applicationType: 'Native',
            authenticationMethod: 'none',
            isThirdParty: false,
            grantTypes: Object.freeze([]),
            userConsentScopes: candidateDeviceUserConsentScopes,
            resourceScopeIds: deviceResourceScopeIds,
          }),
          Object.freeze({
            clientId: logicalDeviceClientIds.ineligibleWeb,
            applicationType: 'SPA',
            authenticationMethod: 'none',
            isThirdParty: false,
            grantTypes: Object.freeze([]),
            userConsentScopes: candidateDeviceUserConsentScopes,
            resourceScopeIds: deviceResourceScopeIds,
          }),
        ]),
      });
      const descriptor = Object.freeze({
        schemaVersion: 1,
        operation: 'provision',
        recipe,
        allocationId,
        profile: Object.freeze({
          fixtures: Object.freeze({ ...frozenCandidateFixtures, phase2 }),
        }),
        seeds: Object.freeze({
          passwords: Object.freeze([
            Object.freeze({ logicalId: 'phase1-user', value: subjectPassword }),
          ]),
          clientSecrets: Object.freeze([
            Object.freeze({ logicalId: logicalClientIds.basic, value: secrets.basic }),
            Object.freeze({ logicalId: logicalClientIds.post, value: secrets.post }),
            Object.freeze({ logicalId: statusConfidentialClientId, value: statusConfidential }),
          ]),
        }),
      });
      const failures: unknown[] = [];
      try {
        let result: Record<string, unknown>;
        try {
          result = await run(descriptor, 'provision', state.sensitiveValues);
        } catch (error: unknown) {
          failures.push(error);
          await cleanupAllocation(state);
          result = await run(descriptor, 'provision', state.sensitiveValues);
        }
        state.coordinatorPublic = validateCoordinatorPublic(
          own(result, 'public'),
          allocationId,
          recipe
        );
        const publicFixture = candidatePublicFixture(allocationId);
        const fixture = createFixture(publicFixture, secrets, state, {
          user: Object.freeze({ id: 'zdata-user', username: statusUsername(allocationId) }),
          client: Object.freeze({ id: 'phase1-browser', redirectUri: statusRedirectUri }),
          confidentialClient: Object.freeze({
            id: statusConfidentialClientId,
            redirectUri: statusRedirectUri,
          }),
          resource: Object.freeze({
            id: 'phase1-api',
            indicator: candidateStatusIndicator(allocationId),
            scopeName: `read:profile_a_${allocationSuffix(allocationId)}`,
          }),
        });
        states.set(fixture as object, state);
        return fixture;
      } catch (error: unknown) {
        failures.push(error);
        try {
          await cleanupState(state);
        } catch (cleanupError: unknown) {
          failures.push(cleanupError);
        }
        if (failures.length > 1) {
          throw new AggregateError(failures, failure);
        }
        throw new Error(failure);
      }
    },
    projectState: async (fixture: ProvisionedPhase2Fixture): Promise<unknown> => {
      const state = states.get(fixture as object);
      if (!state || state.revoked) {
        return fail();
      }
      const result = await run(
        Object.freeze({
          schemaVersion: 1,
          operation: 'projectState',
          recipe,
          allocationId: state.allocationId,
          public: state.coordinatorPublic ?? fail(),
        }),
        'projectState',
        state.sensitiveValues
      );
      const projection = snapshotClosedDataGraph(own(result, 'projection'));
      return projection ?? fail();
    },
    cleanup: async (fixture: ProvisionedPhase2Fixture): Promise<void> => {
      const state = states.get(fixture as object);
      if (!state) {
        return fail(cleanupFailure);
      }
      await cleanupState(state);
      states.delete(fixture as object);
    },
  });
};

export const runWithPhase2Fixture = async <Result>(
  provisioner: Phase2FixtureProvisioner,
  use: (fixture: ProvisionedPhase2Fixture) => Promise<Result>
): Promise<Result> => {
  const fixture = await provisioner.provision();
  let bodyError: unknown;
  let result: Result | undefined;
  try {
    result = await use(fixture);
  } catch (error: unknown) {
    bodyError = error;
  }
  try {
    await provisioner.cleanup(fixture);
  } catch (cleanupError: unknown) {
    if (bodyError !== undefined) {
      throw new AggregateError([bodyError, cleanupError], failure);
    }
    throw cleanupError;
  }
  if (bodyError !== undefined) {
    throw bodyError instanceof Error ? bodyError : new Error(failure);
  }
  return result as Result;
};

export const phase2FixtureContract = Object.freeze({
  clients: logicalClientIds,
  deviceClients: logicalDeviceClientIds,
  statusClient: Object.freeze({ id: statusConfidentialClientId, redirectUri: statusRedirectUri }),
  resources: Object.freeze({ primary: primaryIndicator, default: defaultIndicator }),
  organization: Object.freeze({ id: 'phase2-org', scope: 'organization:read' }),
  scopes: Object.freeze(['read', 'write', 'unassigned']),
});

/* eslint-enable max-lines, complexity, max-params, no-await-in-loop, no-restricted-syntax, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition */
