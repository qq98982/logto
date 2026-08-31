/* eslint-disable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-definitions, no-control-regex, unicorn/escape-case, @typescript-eslint/prefer-nullish-coalescing, unicorn/no-array-callback-reference, @typescript-eslint/member-ordering -- This module is the single closed, descriptor-aware runtime boundary for the public fixture map and preserves the plan's exact interface spelling. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import { SymbolTable } from '../symbol-table.js';

import type { Phase1FixtureRecipe } from './model.js';
import type { Phase1Profile } from './profile-types.js';

export const fixtureSetupCapabilityIds = Object.freeze([
  'http.management-api.get./api/sign-in-exp',
  'http.management-api.patch./api/sign-in-exp',
  'http.management-api.post./api/users',
  'http.management-api.patch./api/users/{userId}',
  'http.management-api.delete./api/users/{userId}',
  'http.management-api.post./api/applications',
  'http.management-api.delete./api/applications/{id}',
  'http.management-api.post./api/applications/{applicationId}/user-consent-scopes',
  'http.management-api.post./api/resources',
  'http.management-api.delete./api/resources/{id}',
  'http.management-api.post./api/resources/{resourceId}/scopes',
  'http.management-api.delete./api/resources/{resourceId}/scopes/{scopeId}',
  'http.management-api.post./api/roles',
  'http.management-api.delete./api/roles/{id}',
  'http.management-api.get./api/roles',
  'http.management-api.post./api/roles/{id}/users',
  'http.management-api.get./api/organization-roles',
  'http.management-api.post./api/organizations/{id}/users',
  'http.management-api.post./api/organizations/{id}/users/{userId}/roles',
  'http.management-api.delete./api/organizations/{id}/users/{userId}',
] as const);

export const phase1FixtureRecipeDefinitions = Object.freeze({
  none: Object.freeze({ allocationRoles: Object.freeze([]), mutableSetup: false }),
  dataProtocol: Object.freeze({ allocationRoles: Object.freeze(['data']), mutableSetup: true }),
  adminConsole: Object.freeze({ allocationRoles: Object.freeze(['admin']), mutableSetup: true }),
  fullPhase1: Object.freeze({
    allocationRoles: Object.freeze(['data', 'admin']),
    mutableSetup: true,
  }),
  consentBoundary: Object.freeze({
    allocationRoles: Object.freeze(['data', 'foreign']),
    mutableSetup: true,
  }),
} as const satisfies Record<Phase1FixtureRecipe, unknown>);

export const phase1FixtureEntityKinds = Object.freeze([
  'tenant',
  'user',
  'application',
  'resource',
  'scope',
  'role',
  'organization',
  'organization-role',
] as const);

export type Phase1FixtureEntityKind = (typeof phase1FixtureEntityKinds)[number];
export type Phase1FixtureAllocationRole = 'data' | 'admin' | 'foreign';

const dataEntityCounts = Object.freeze({
  tenant: 1,
  user: 1,
  application: 2,
  resource: 1,
  scope: 1,
  role: 1,
  organization: 0,
  'organization-role': 0,
});
const adminEntityCounts = Object.freeze({
  tenant: 1,
  user: 1,
  application: 1,
  resource: 3,
  scope: 0,
  role: 2,
  organization: 1,
  'organization-role': 1,
});
const consentDataEntityCounts = Object.freeze({
  ...dataEntityCounts,
  user: 2,
  application: 3,
});
const foreignEntityCounts = Object.freeze({
  tenant: 1,
  user: 1,
  application: 1,
  resource: 0,
  scope: 0,
  role: 0,
  organization: 0,
  'organization-role': 0,
});

export const phase1FixtureRecipeEntityCounts = Object.freeze({
  none: Object.freeze({}),
  dataProtocol: Object.freeze({ data: dataEntityCounts }),
  adminConsole: Object.freeze({ admin: adminEntityCounts }),
  fullPhase1: Object.freeze({ data: dataEntityCounts, admin: adminEntityCounts }),
  consentBoundary: Object.freeze({
    data: consentDataEntityCounts,
    foreign: foreignEntityCounts,
  }),
} as const);

export type Phase1FixtureEntityId = Readonly<{
  kind: Phase1FixtureEntityKind;
  logicalId: string;
  runtimeId: string;
}>;

export type Phase1FixtureIsolation = Readonly<{
  persistenceId: string;
  cookieKeyId: string;
  signingKeyId: string;
}>;

export type Phase1FixtureAllocation = Readonly<{
  allocationId: string;
  role: Phase1FixtureAllocationRole;
  target: 'primary' | 'foreign';
  isolation: Phase1FixtureIsolation;
  entities: readonly Phase1FixtureEntityId[];
}>;

export type Phase1FixtureMap = Readonly<{
  schemaVersion: 1;
  recipe: Phase1FixtureRecipe;
  allocations: readonly Phase1FixtureAllocation[];
}>;

type Phase1StateSignInExperience = Readonly<{
  signInMode: string;
  signUp: Readonly<{
    identifiers: readonly string[];
    localAuthentication: boolean;
    verify: boolean;
  }>;
  signIn: Readonly<{
    methods: ReadonlyArray<
      Readonly<{
        identifier: string;
        localAuthentication: boolean;
        verificationCode: boolean;
        isPrimaryAuthentication: boolean;
      }>
    >;
  }>;
  localAuthenticationPolicy: Readonly<Record<string, never>>;
}>;

type Phase1StateUserSnapshot = Readonly<{
  username: string | null;
  name: string | null;
  primaryEmail: string | null;
  primaryPhone: string | null;
  profile: Readonly<
    | Record<string, never>
    | {
        address: Readonly<{ formatted: string; country: string }>;
      }
  >;
  applicationLogicalId: string | null;
  customData: Readonly<
    | Record<string, never>
    | {
        ossOnboarding: Readonly<{ isOnboardingDone: boolean }>;
      }
  >;
  localAuthenticationPresent: boolean;
}>;

type Phase1StateApplicationSnapshot = Readonly<{
  name: string | null;
  type: string;
  isThirdParty: boolean;
  oidcClientMetadata: Readonly<{
    redirectUris: readonly string[];
    postLogoutRedirectUris: readonly string[];
  }>;
  customClientMetadata: Readonly<Record<string, never>>;
  consent: Readonly<{
    userScopes: readonly string[];
    resourceScopeLogicalIds: readonly string[];
  }>;
}>;

type Phase1StateEntitySnapshot =
  | Readonly<Record<string, never>>
  | Phase1StateUserSnapshot
  | Phase1StateApplicationSnapshot
  | Readonly<{
      name: string | null;
      indicator: string;
      scopeNames: readonly string[];
    }>
  | Readonly<{
      name: string;
      description: string;
      resourceLogicalId: string;
    }>
  | Readonly<{
      name: string;
      description: string | null;
      type: string;
      isDefault: boolean | null;
      scopeLogicalIds: readonly string[];
      userLogicalIds: readonly string[];
    }>
  | Readonly<{
      name: string;
      memberUserLogicalIds: readonly string[];
      memberOrganizationRoleLogicalIds: readonly string[];
    }>
  | Readonly<{
      name: string;
      type: string;
      scopeNames: readonly string[];
      userLogicalIds: readonly string[];
    }>;

export type Phase1FixtureStateEntityProjection = Readonly<{
  kind: Phase1FixtureEntityKind;
  logicalId: string;
  snapshot: Phase1StateEntitySnapshot;
}>;

export type Phase1FixtureStateAllocationProjection = Readonly<{
  role: Phase1FixtureAllocationRole;
  target: 'primary' | 'foreign';
  signInExperience: Phase1StateSignInExperience;
  entities: readonly Phase1FixtureStateEntityProjection[];
}>;

export type Phase1FixtureStateProjection = Readonly<{
  schemaVersion: 1;
  recipe: Phase1FixtureRecipe;
  allocations: readonly Phase1FixtureStateAllocationProjection[];
}>;

export type Phase1FixtureEntityKeyMap = Readonly<
  Partial<Record<Phase1FixtureAllocationRole, readonly string[]>>
>;

export interface Phase1FixtureSymbolTables {
  readonly allocationIds: readonly string[];
  get(allocationId: string): SymbolTable | undefined;
}

const invalidFixtureMapMessage = 'Invalid Phase 1 fixture map';
const maximumDepth = 24;
const maximumArrayLength = 256;
const maximumStringLength = 1024;
const denseArrayIndexPattern = /^(?:0|[1-9]\d*)$/u;
const safeStringPattern = /^[^\u0000-\u001f\u007f]+$/u;
const forbiddenFieldPattern =
  /(?:password|client.?secret|access.?token|refresh.?token|id.?token|cookie(?!KeyId$)|private.?key|credential|session)/iu;
const entityKindSet = new Set<string>(phase1FixtureEntityKinds);
const allocationRoleSet = new Set<string>(['data', 'admin', 'foreign']);
const fixtureRecipeSet = new Set<string>(Object.keys(phase1FixtureRecipeDefinitions));

const fail = (): never => {
  throw new TypeError(invalidFixtureMapMessage);
};

const nullableString = (value: unknown): string | null =>
  value === null ? null : assertSafeString(value);

const isUnknownArray = (value: unknown): value is readonly unknown[] => Array.isArray(value);

const exactStringArray = (value: unknown): readonly string[] => {
  if (!isUnknownArray(value)) {
    return fail();
  }
  const values = value.map((candidate) => assertSafeString(candidate));

  if (new Set(values).size !== values.length) {
    fail();
  }

  return Object.freeze(values);
};

const exactBoolean = (value: unknown): boolean => {
  if (typeof value !== 'boolean') {
    return fail();
  }

  return value;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const assertExactKeys = (value: Record<string, unknown>, expected: readonly string[]): void => {
  const actual = Object.keys(value);

  if (actual.length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    fail();
  }
};

const assertSafeString = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximumStringLength ||
    !safeStringPattern.test(value)
  ) {
    fail();
  }

  return value as string;
};

const snapshotClosedValue = (
  value: unknown,
  ancestors: WeakSet<object>,
  depth: number
): unknown => {
  if (depth > maximumDepth) {
    fail();
  }
  if (value === null || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    return assertSafeString(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      fail();
    }

    return value;
  }
  if (typeof value !== 'object' || nodeTypes.isProxy(value) || ancestors.has(value)) {
    fail();
  }
  const objectValue = value as object;

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > maximumArrayLength) {
      fail();
    }
    const keys = Reflect.ownKeys(value);

    if (
      keys.length !== value.length + 1 ||
      keys.some(
        (key) =>
          typeof key !== 'string' ||
          (key !== 'length' &&
            (!denseArrayIndexPattern.test(key) || Number.parseInt(key, 10) >= value.length))
      )
    ) {
      fail();
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');

    if (
      !lengthDescriptor ||
      !Object.hasOwn(lengthDescriptor, 'value') ||
      lengthDescriptor.value !== value.length ||
      lengthDescriptor.enumerable ||
      lengthDescriptor.configurable
    ) {
      fail();
    }
    ancestors.add(value);
    const result = Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));

      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
        fail();
      }

      return snapshotClosedValue(
        (descriptor as PropertyDescriptor & { value: unknown }).value,
        ancestors,
        depth + 1
      );
    });
    ancestors.delete(value);

    return Object.freeze(result);
  }

  if (Object.getPrototypeOf(objectValue) !== Object.prototype) {
    fail();
  }
  const keys = Reflect.ownKeys(objectValue);

  if (keys.some((key) => typeof key !== 'string')) {
    fail();
  }
  ancestors.add(objectValue);
  const result: Record<string, unknown> = {};

  for (const key of keys as string[]) {
    if (forbiddenFieldPattern.test(key)) {
      fail();
    }
    const descriptor = Object.getOwnPropertyDescriptor(objectValue, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      fail();
    }
    Object.defineProperty(result, key, {
      configurable: false,
      enumerable: true,
      value: snapshotClosedValue(
        (descriptor as PropertyDescriptor & { value: unknown }).value,
        ancestors,
        depth + 1
      ),
      writable: false,
    });
  }
  ancestors.delete(objectValue);

  return Object.freeze(result);
};

const assertEntity = (value: unknown): Phase1FixtureEntityId => {
  if (!isRecord(value)) {
    return fail();
  }
  assertExactKeys(value, ['kind', 'logicalId', 'runtimeId']);
  const kind = assertSafeString(value.kind);

  if (!entityKindSet.has(kind)) {
    fail();
  }

  return Object.freeze({
    kind: kind as Phase1FixtureEntityKind,
    logicalId: assertSafeString(value.logicalId),
    runtimeId: assertSafeString(value.runtimeId),
  });
};

const assertIsolation = (value: unknown): Phase1FixtureIsolation => {
  if (!isRecord(value)) {
    return fail();
  }
  assertExactKeys(value, ['persistenceId', 'cookieKeyId', 'signingKeyId']);
  const values = [
    assertSafeString(value.persistenceId),
    assertSafeString(value.cookieKeyId),
    assertSafeString(value.signingKeyId),
  ];

  if (new Set(values).size !== values.length) {
    fail();
  }

  return Object.freeze({
    persistenceId: values[0] ?? fail(),
    cookieKeyId: values[1] ?? fail(),
    signingKeyId: values[2] ?? fail(),
  });
};

const assertAllocation = (value: unknown): Phase1FixtureAllocation => {
  if (!isRecord(value)) {
    return fail();
  }
  assertExactKeys(value, ['allocationId', 'role', 'target', 'isolation', 'entities']);
  assertSafeString(value.allocationId);
  const role = assertSafeString(value.role);
  const target = assertSafeString(value.target);

  const rawEntities = value.entities;

  if (
    !allocationRoleSet.has(role) ||
    (role === 'foreign' ? target !== 'foreign' : target !== 'primary') ||
    !Array.isArray(rawEntities) ||
    rawEntities.length === 0
  ) {
    fail();
  }
  const isolation = assertIsolation(value.isolation);
  const entities = (rawEntities as unknown[]).map((candidate) => assertEntity(candidate));
  const logicalIds = entities.map(
    ({ kind, logicalId }) => `${kind}.${assertSafeString(logicalId)}`
  );
  const runtimeIds = entities.map(({ runtimeId }) => assertSafeString(runtimeId));

  if (
    new Set(logicalIds).size !== logicalIds.length ||
    new Set(runtimeIds).size !== runtimeIds.length ||
    !entities.some(({ kind }) => kind === 'tenant')
  ) {
    fail();
  }

  return Object.freeze({
    allocationId: assertSafeString(value.allocationId),
    role: role as Phase1FixtureAllocationRole,
    target: target as Phase1FixtureAllocation['target'],
    isolation,
    entities: Object.freeze(entities),
  });
};

const assertRecipeAllocations = (
  recipe: Phase1FixtureRecipe,
  allocations: readonly Phase1FixtureAllocation[]
): void => {
  const expectedRoles = phase1FixtureRecipeDefinitions[recipe].allocationRoles;

  if (
    expectedRoles.length !== allocations.length ||
    expectedRoles.some((role, index) => allocations[index]?.role !== role)
  ) {
    fail();
  }
  const allocationIds = allocations.map(({ allocationId }) => allocationId);

  if (new Set(allocationIds).size !== allocationIds.length) {
    fail();
  }
  const cookieKeyIds = allocations.map(({ isolation }) => isolation.cookieKeyId);
  const signingKeyIds = allocations.map(({ isolation }) => isolation.signingKeyId);
  const foreign = allocations.find(({ role }) => role === 'foreign');
  const primaryPersistenceIds = new Set(
    allocations
      .filter(({ role }) => role !== 'foreign')
      .map(({ isolation }) => isolation.persistenceId)
  );

  if (
    new Set(cookieKeyIds).size !== cookieKeyIds.length ||
    new Set(signingKeyIds).size !== signingKeyIds.length ||
    (foreign !== undefined && primaryPersistenceIds.has(foreign.isolation.persistenceId))
  ) {
    fail();
  }
  const contracts = phase1FixtureRecipeEntityCounts[recipe] as Readonly<
    Partial<Record<Phase1FixtureAllocationRole, Readonly<Record<Phase1FixtureEntityKind, number>>>>
  >;

  for (const allocation of allocations) {
    const contract = contracts[allocation.role];

    if (
      !contract ||
      phase1FixtureEntityKinds.some(
        (kind) =>
          allocation.entities.filter((entity) => entity.kind === kind).length !== contract[kind]
      )
    ) {
      fail();
    }
  }
};

export const createPhase1FixtureMap = (value: unknown): Phase1FixtureMap => {
  try {
    const snapshot = snapshotClosedValue(value, new WeakSet(), 0);

    if (!isRecord(snapshot)) {
      return fail();
    }
    assertExactKeys(snapshot, ['schemaVersion', 'recipe', 'allocations']);

    if (snapshot.schemaVersion !== 1 || !Array.isArray(snapshot.allocations)) {
      return fail();
    }
    const recipe = assertSafeString(snapshot.recipe);

    if (!fixtureRecipeSet.has(recipe)) {
      return fail();
    }
    const allocations = snapshot.allocations.map(assertAllocation);
    assertRecipeAllocations(recipe as Phase1FixtureRecipe, allocations);

    return Object.freeze({
      schemaVersion: 1,
      recipe: recipe as Phase1FixtureRecipe,
      allocations: Object.freeze(allocations),
    });
  } catch {
    return fail();
  }
};

const fixedStateSignInExperience: Phase1StateSignInExperience = Object.freeze({
  signInMode: 'SignInAndRegister',
  signUp: Object.freeze({
    identifiers: Object.freeze(['username']),
    localAuthentication: true,
    verify: false,
  }),
  signIn: Object.freeze({
    methods: Object.freeze([
      Object.freeze({
        identifier: 'username',
        localAuthentication: true,
        verificationCode: false,
        isPrimaryAuthentication: true,
      }),
    ]),
  }),
  localAuthenticationPolicy: Object.freeze({}),
});

const peerLogicalPrefix = (logicalId: string): 'consent.primary' | 'consent.foreign' | undefined =>
  logicalId.startsWith('consent.primary.')
    ? 'consent.primary'
    : logicalId.startsWith('consent.foreign.')
      ? 'consent.foreign'
      : undefined;

const expectedUserSnapshot = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  allocation: Phase1FixtureAllocation,
  logicalId: string
): Phase1StateUserSnapshot => {
  if (allocation.role === 'admin') {
    const { operator } = profile.fixtures.adminTenant;

    if (logicalId !== operator.id) {
      return fail();
    }

    return Object.freeze({
      username: assertSafeString(operator.username),
      name: null,
      primaryEmail: assertSafeString(operator.primaryEmail),
      primaryPhone: null,
      profile: Object.freeze({}),
      applicationLogicalId: null,
      customData: Object.freeze({
        ossOnboarding: Object.freeze({
          isOnboardingDone: operator.customData.ossOnboarding.isOnboardingDone,
        }),
      }),
      localAuthenticationPresent: true,
    });
  }
  const { subject } = profile.fixtures.dataTenant;

  if (logicalId === subject.id) {
    return Object.freeze({
      username: assertSafeString(subject.username),
      name: assertSafeString(subject.name),
      primaryEmail: assertSafeString(subject.primaryEmail),
      primaryPhone: assertSafeString(subject.primaryPhone),
      profile: Object.freeze({
        address: Object.freeze({
          formatted: assertSafeString(subject.profile.address.formatted),
          country: assertSafeString(subject.profile.address.country),
        }),
      }),
      applicationLogicalId: subject.applicationId,
      customData: Object.freeze({}),
      localAuthenticationPresent: true,
    });
  }
  const prefix = peerLogicalPrefix(logicalId);

  if (!prefix || logicalId !== `${prefix}.user-b`) {
    return fail();
  }

  return Object.freeze({
    username: `${assertSafeString(subject.username)}_boundary_b`,
    name: null,
    primaryEmail: null,
    primaryPhone: null,
    profile: Object.freeze({}),
    applicationLogicalId: null,
    customData: Object.freeze({}),
    localAuthenticationPresent: true,
  });
};

const expectedApplicationSnapshot = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  allocation: Phase1FixtureAllocation,
  logicalId: string
): Phase1StateApplicationSnapshot => {
  if (allocation.role === 'admin') {
    const { application } = profile.fixtures.adminTenant;

    if (logicalId !== application.id) {
      return fail();
    }

    return Object.freeze({
      name: null,
      type: assertSafeString(application.type),
      isThirdParty: false,
      oidcClientMetadata: Object.freeze({
        redirectUris: Object.freeze([]),
        postLogoutRedirectUris: Object.freeze([]),
      }),
      customClientMetadata: Object.freeze({}),
      consent: Object.freeze({
        userScopes: Object.freeze([]),
        resourceScopeLogicalIds: Object.freeze([]),
      }),
    });
  }
  const application = profile.fixtures.dataTenant.applications.find(({ id }) => id === logicalId);

  if (application) {
    return Object.freeze({
      name: assertSafeString(application.name),
      type: assertSafeString(application.type),
      isThirdParty: application.isThirdParty,
      oidcClientMetadata: Object.freeze({
        redirectUris: Object.freeze(
          application.oidcClientMetadata.redirectUris.map(assertSafeString)
        ),
        postLogoutRedirectUris: Object.freeze(
          application.oidcClientMetadata.postLogoutRedirectUris.map(assertSafeString)
        ),
      }),
      customClientMetadata: Object.freeze({}),
      consent: Object.freeze({
        userScopes: Object.freeze(
          application.isThirdParty ? application.userConsentScopes.map(assertSafeString) : []
        ),
        resourceScopeLogicalIds: Object.freeze(
          application.isThirdParty ? application.resourceConsentScopes.map(assertSafeString) : []
        ),
      }),
    });
  }
  const prefix = peerLogicalPrefix(logicalId);
  const thirdParty = profile.fixtures.dataTenant.applications.find(
    (candidate) => candidate.isThirdParty
  );

  if (!prefix || logicalId !== `${prefix}.client-b` || !thirdParty) {
    return fail();
  }

  return Object.freeze({
    name: `${prefix} client B`,
    type: assertSafeString(thirdParty.type),
    isThirdParty: true,
    oidcClientMetadata: Object.freeze({
      redirectUris: Object.freeze(thirdParty.oidcClientMetadata.redirectUris.map(assertSafeString)),
      postLogoutRedirectUris: Object.freeze(
        thirdParty.oidcClientMetadata.postLogoutRedirectUris.map(assertSafeString)
      ),
    }),
    customClientMetadata: Object.freeze({}),
    consent: Object.freeze({
      userScopes: Object.freeze([]),
      resourceScopeLogicalIds: Object.freeze([]),
    }),
  });
};

const expectedEntitySnapshot = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  allocation: Phase1FixtureAllocation,
  entity: Phase1FixtureEntityId
): Phase1StateEntitySnapshot => {
  if (entity.kind === 'tenant') {
    return Object.freeze({});
  }
  if (entity.kind === 'user') {
    return expectedUserSnapshot(profile, allocation, entity.logicalId);
  }
  if (entity.kind === 'application') {
    return expectedApplicationSnapshot(profile, allocation, entity.logicalId);
  }
  if (entity.kind === 'resource') {
    if (allocation.role === 'admin') {
      const match = /^admin\.resource\.(\d+)$/u.exec(entity.logicalId);
      const resource = match
        ? profile.fixtures.adminTenant.resources[Number.parseInt(match[1] ?? '0', 10) - 1]
        : undefined;

      if (!resource) {
        return fail();
      }

      return Object.freeze({
        name: null,
        indicator: assertSafeString(resource.indicator),
        scopeNames: Object.freeze(resource.scopes.map(assertSafeString)),
      });
    }
    const { resource } = profile.fixtures.dataTenant;

    if (entity.logicalId !== resource.id) {
      return fail();
    }

    return Object.freeze({
      name: assertSafeString(resource.name),
      indicator: assertSafeString(resource.indicator),
      scopeNames: Object.freeze(resource.scopes.map(({ name }) => assertSafeString(name))),
    });
  }
  if (entity.kind === 'scope') {
    const { resource } = profile.fixtures.dataTenant;
    const scope = resource.scopes.find(({ id }) => id === entity.logicalId);

    if (!scope || allocation.role !== 'data') {
      return fail();
    }

    return Object.freeze({
      name: assertSafeString(scope.name),
      description: assertSafeString(scope.description),
      resourceLogicalId: assertSafeString(resource.id),
    });
  }
  if (entity.kind === 'role') {
    if (allocation.role === 'admin') {
      const { operator } = profile.fixtures.adminTenant;

      if (!operator.roles.includes(entity.logicalId)) {
        return fail();
      }

      return Object.freeze({
        name: assertSafeString(entity.logicalId),
        description: null,
        type: 'User',
        isDefault: null,
        scopeLogicalIds: Object.freeze([]),
        userLogicalIds: Object.freeze([assertSafeString(operator.id)]),
      });
    }
    const role = profile.fixtures.dataTenant.resourceScopeRole;

    if (entity.logicalId !== role.id) {
      return fail();
    }

    return Object.freeze({
      name: assertSafeString(role.name),
      description: assertSafeString(role.description),
      type: assertSafeString(role.type),
      isDefault: role.isDefault,
      scopeLogicalIds: Object.freeze(role.scopeIds.map(assertSafeString)),
      userLogicalIds: Object.freeze(role.userIds.map(assertSafeString)),
    });
  }
  if (entity.kind === 'organization') {
    const organization = profile.fixtures.adminTenant.tenantOrganization;

    if (allocation.role !== 'admin' || entity.logicalId !== organization.id) {
      return fail();
    }

    return Object.freeze({
      name: assertSafeString(organization.name),
      memberUserLogicalIds: Object.freeze(organization.memberUserIds.map(assertSafeString)),
      memberOrganizationRoleLogicalIds: Object.freeze(
        organization.organizationRoles.map(({ id }) => assertSafeString(id))
      ),
    });
  }
  const organizationRole = profile.fixtures.adminTenant.tenantOrganization.organizationRoles.find(
    ({ id }) => id === entity.logicalId
  );

  if (allocation.role !== 'admin' || !organizationRole) {
    return fail();
  }

  return Object.freeze({
    name: assertSafeString(organizationRole.name),
    type: assertSafeString(organizationRole.type),
    scopeNames: Object.freeze(organizationRole.scopeNames.map(assertSafeString)),
    userLogicalIds: Object.freeze(organizationRole.userIds.map(assertSafeString)),
  });
};

export const createExpectedPhase1FixtureStateProjection = (
  publicMap: Phase1FixtureMap,
  profile: Pick<Phase1Profile, 'fixtures'>
): Phase1FixtureStateProjection => {
  try {
    const map = createPhase1FixtureMap(publicMap);
    const projection = {
      schemaVersion: 1 as const,
      recipe: map.recipe,
      allocations: map.allocations.map((allocation) => ({
        role: allocation.role,
        target: allocation.target,
        signInExperience: fixedStateSignInExperience,
        entities: allocation.entities.map((entity) => ({
          kind: entity.kind,
          logicalId: entity.logicalId,
          snapshot: expectedEntitySnapshot(profile, allocation, entity),
        })),
      })),
    };
    const snapshot = snapshotClosedValue(projection, new WeakSet(), 0);

    if (!isRecord(snapshot)) {
      return fail();
    }

    return snapshot as Phase1FixtureStateProjection;
  } catch {
    return fail();
  }
};

export const createPhase1FixtureStateProjection = (
  value: unknown,
  publicMap: Phase1FixtureMap,
  profile: Pick<Phase1Profile, 'fixtures'>
): Phase1FixtureStateProjection => {
  try {
    const expected = createExpectedPhase1FixtureStateProjection(publicMap, profile);
    const snapshot = snapshotClosedValue(value, new WeakSet(), 0);

    if (!isDeepStrictEqual(snapshot, expected)) {
      return fail();
    }

    return expected;
  } catch {
    return fail();
  }
};

class FixtureSymbolTables implements Phase1FixtureSymbolTables {
  readonly #tables: ReadonlyMap<string, SymbolTable>;
  readonly allocationIds: readonly string[];

  constructor(map: Phase1FixtureMap) {
    const tables = map.allocations.map(({ allocationId, entities }) => {
      const table = new SymbolTable();

      for (const { kind, logicalId, runtimeId } of entities) {
        table.bind(`${kind}.${logicalId}`, runtimeId);
      }

      return [allocationId, table] as const;
    });
    this.#tables = new Map(tables);
    this.allocationIds = Object.freeze(tables.map(([allocationId]) => allocationId));
    Object.freeze(this);
  }

  get(allocationId: string): SymbolTable | undefined {
    return this.#tables.get(allocationId);
  }
}

export const bindPhase1FixtureSymbols = (map: Phase1FixtureMap): Phase1FixtureSymbolTables =>
  new FixtureSymbolTables(createPhase1FixtureMap(map));

export const getPhase1FixtureEntityKey = ({ kind, logicalId }: Phase1FixtureEntityId): string =>
  `${kind}.${logicalId}`;

export const getExpectedPhase1FixtureEntityKeys = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  recipe: Phase1FixtureRecipe
): Phase1FixtureEntityKeyMap => {
  const { adminTenant, dataTenant } = profile.fixtures;
  const data = [
    `tenant.${dataTenant.id}`,
    `user.${dataTenant.subject.id}`,
    ...dataTenant.applications.map(({ id }) => `application.${id}`),
    `resource.${dataTenant.resource.id}`,
    ...dataTenant.resource.scopes.map(({ id }) => `scope.${id}`),
    `role.${dataTenant.resourceScopeRole.id}`,
  ];
  const admin = [
    `tenant.${adminTenant.id}`,
    `user.${adminTenant.operator.id}`,
    `application.${adminTenant.application.id}`,
    ...adminTenant.resources.map((_resource, index) => `resource.admin.resource.${index + 1}`),
    ...adminTenant.operator.roles.map((id) => `role.${id}`),
    `organization.${adminTenant.tenantOrganization.id}`,
    ...adminTenant.tenantOrganization.organizationRoles.map(({ id }) => `organization-role.${id}`),
  ];
  const primaryPeer = ['user.consent.primary.user-b', 'application.consent.primary.client-b'];
  const foreign = [
    `tenant.${dataTenant.id}`,
    'user.consent.foreign.user-b',
    'application.consent.foreign.client-b',
  ];

  return Object.freeze(
    recipe === 'none'
      ? {}
      : recipe === 'dataProtocol'
        ? { data: Object.freeze(data) }
        : recipe === 'adminConsole'
          ? { admin: Object.freeze(admin) }
          : recipe === 'fullPhase1'
            ? { data: Object.freeze(data), admin: Object.freeze(admin) }
            : {
                data: Object.freeze([...data, ...primaryPeer]),
                foreign: Object.freeze(foreign),
              }
  );
};

export const assertPhase1FixtureMapEntityKeys = (
  map: Phase1FixtureMap,
  expected: Phase1FixtureEntityKeyMap
): void => {
  for (const allocation of map.allocations) {
    const expectedKeys = expected[allocation.role];
    const actualKeys = allocation.entities.map(getPhase1FixtureEntityKey);

    if (
      !expectedKeys ||
      actualKeys.length !== expectedKeys.length ||
      actualKeys.toSorted().some((key, index) => key !== expectedKeys.toSorted()[index])
    ) {
      fail();
    }
  }
};

export const getPhase1FixtureRuntimeId = (
  map: Phase1FixtureMap,
  allocationId: string,
  kind: Phase1FixtureEntityKind,
  logicalId: string
): string => {
  const allocation = map.allocations.find((candidate) => candidate.allocationId === allocationId);
  const entity = allocation?.entities.find(
    (candidate) => candidate.kind === kind && candidate.logicalId === logicalId
  );

  if (!entity) {
    throw new Error('Unknown Phase 1 fixture identifier');
  }

  return entity.runtimeId;
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-definitions, no-control-regex, unicorn/escape-case, @typescript-eslint/prefer-nullish-coalescing, unicorn/no-array-callback-reference, @typescript-eslint/member-ordering */
