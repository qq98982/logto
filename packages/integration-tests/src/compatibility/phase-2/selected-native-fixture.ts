/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This fixture owns ordered public Management setup, policy restoration, compensation, and a private password lease. */
import { createHash } from 'node:crypto';
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../config.js';
import type { TargetConfig } from '../model.js';

import type {
  Phase2AdminRequest,
  Phase2AdminRequestFunction,
  Phase2SelectedNativePublic,
  ProvisionedPhase2Fixture,
} from './fixtures.js';

const diagnostic = 'Invalid Phase 2 selected Native fixture';
const callbackUri = 'https://app.example.test/wechat/logto-callback';
const resourceIndicator = 'https://app.example.test/api';
const scopeName = 'session:exchange';

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const exactRecord = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).some((key) => typeof key !== 'string')
  ) {
    return fail();
  }
  return value as Record<string, unknown>;
};

const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const unknownArray = (value: unknown): unknown[] =>
  Array.isArray(value) ? value.map((entry: unknown) => entry) : fail();

const safeId = (value: unknown): string =>
  typeof value === 'string' && /^[A-Za-z0-9._~-]{1,128}$/u.test(value) ? value : fail();

type SelectedNativeCleanup = Readonly<{ path: string }>;
type SelectedSignInMethod = Readonly<{
  identifier: string;
  password: boolean;
  verificationCode: boolean;
  isPasswordPrimary: boolean;
}>;

export type SelectedNativeFixtureOptions = Readonly<{
  request: Phase2AdminRequestFunction;
  target: TargetConfig;
}>;

const call = async (
  request: Phase2AdminRequestFunction,
  method: Phase2AdminRequest['method'],
  path: string,
  body?: unknown,
  expectedStatuses: readonly number[] = [200, 201],
  responseKind: Phase2AdminRequest['responseKind'] = 'object',
  query?: Readonly<Record<string, string>>
): Promise<unknown> => request({ method, path, query, body, expectedStatuses, responseKind });

const sameStrings = (value: unknown, expected: readonly string[]): boolean =>
  Array.isArray(value) &&
  value.length === expected.length &&
  value.every((entry, index) => entry === expected[index]);

const signInMethods = (value: unknown): SelectedSignInMethod[] => {
  const experience = exactRecord(value);
  const signIn = exactRecord(own(experience, 'signIn'));
  return unknownArray(own(signIn, 'methods')).map((entry) => {
    const method = exactRecord(entry);
    const identifier = own(method, 'identifier');
    const password = own(method, 'password');
    const verificationCode = own(method, 'verificationCode');
    const isPasswordPrimary = own(method, 'isPasswordPrimary');
    if (
      typeof identifier !== 'string' ||
      typeof password !== 'boolean' ||
      typeof verificationCode !== 'boolean' ||
      typeof isPasswordPrimary !== 'boolean'
    ) {
      return fail();
    }
    return Object.freeze({ identifier, password, verificationCode, isPasswordPrimary });
  });
};

const readSignInMethods = async (
  request: Phase2AdminRequestFunction
): Promise<readonly SelectedSignInMethod[]> =>
  Object.freeze(
    signInMethods(await call(request, 'GET', 'sign-in-exp', undefined, [200], 'object'))
  );

const configureEmailPassword = async (
  request: Phase2AdminRequestFunction,
  previous: readonly SelectedSignInMethod[]
): Promise<void> => {
  const desired = Object.freeze([
    Object.freeze({
      identifier: 'email',
      password: true,
      verificationCode: false,
      isPasswordPrimary: true,
    }),
    ...previous.filter(({ identifier }) => identifier !== 'email'),
  ]);
  const updated = await call(
    request,
    'PATCH',
    'sign-in-exp',
    { signIn: { methods: desired } },
    [200],
    'object'
  );
  if (JSON.stringify(signInMethods(updated)) !== JSON.stringify(desired)) {
    return fail();
  }
};

const restoreSignInMethods = async (
  request: Phase2AdminRequestFunction,
  previous: readonly SelectedSignInMethod[]
): Promise<void> => {
  const restored = await call(
    request,
    'PATCH',
    'sign-in-exp',
    { signIn: { methods: previous } },
    [200],
    'object'
  );
  if (JSON.stringify(signInMethods(restored)) !== JSON.stringify(previous)) {
    return fail();
  }
};

const assertApplication = (value: unknown, expectedId?: string): string => {
  const application = exactRecord(value);
  const id = safeId(own(application, 'id'));
  const metadata = exactRecord(own(application, 'oidcClientMetadata'));
  if (
    (expectedId !== undefined && id !== expectedId) ||
    own(application, 'type') !== 'Native' ||
    own(application, 'isThirdParty') !== false ||
    !sameStrings(own(metadata, 'redirectUris'), [callbackUri]) ||
    !sameStrings(own(metadata, 'postLogoutRedirectUris'), [])
  ) {
    return fail();
  }
  return id;
};

const assertResource = (value: unknown, expectedId?: string): string => {
  const resource = exactRecord(value);
  const id = safeId(own(resource, 'id'));
  if (
    (expectedId !== undefined && id !== expectedId) ||
    own(resource, 'indicator') !== resourceIndicator ||
    own(resource, 'accessTokenTtl') !== 300
  ) {
    return fail();
  }
  return id;
};

const assertScope = (value: unknown, resourceId: string, expectedId?: string): string => {
  const scope = exactRecord(value);
  const id = safeId(own(scope, 'id'));
  if (
    (expectedId !== undefined && id !== expectedId) ||
    own(scope, 'resourceId') !== resourceId ||
    own(scope, 'name') !== scopeName
  ) {
    return fail();
  }
  return id;
};

const assertRole = (value: unknown, expectedId?: string): string => {
  const role = exactRecord(value);
  const id = safeId(own(role, 'id'));
  if ((expectedId !== undefined && id !== expectedId) || own(role, 'isDefault') !== true) {
    return fail();
  }
  return id;
};

const assertIdentity = (value: unknown, primaryEmail: string, expectedId?: string): string => {
  const identity = exactRecord(value);
  const id = safeId(own(identity, 'id'));
  if (
    (expectedId !== undefined && id !== expectedId) ||
    own(identity, 'primaryEmail') !== primaryEmail ||
    own(identity, 'hasPassword') !== true
  ) {
    return fail();
  }
  return id;
};

const readSelectedNative = async (
  request: Phase2AdminRequestFunction,
  expected: Readonly<{
    applicationId: string;
    resourceId: string;
    scopeId: string;
    roleId: string;
    identityId: string;
    primaryEmail: string;
  }>
): Promise<void> => {
  assertApplication(
    await call(
      request,
      'GET',
      `applications/${encodeURIComponent(expected.applicationId)}`,
      undefined,
      [200]
    ),
    expected.applicationId
  );
  const resources = await call(request, 'GET', 'resources', undefined, [200], 'array', {
    includeScopes: 'true',
  });
  const resource = unknownArray(resources).find(
    (entry) => own(exactRecord(entry), 'id') === expected.resourceId
  );
  assertResource(resource, expected.resourceId);
  const scopes = own(exactRecord(resource), 'scopes');
  const scope = unknownArray(scopes).find(
    (entry) => own(exactRecord(entry), 'id') === expected.scopeId
  );
  assertScope(scope, expected.resourceId, expected.scopeId);
  const roles = await call(request, 'GET', 'roles', undefined, [200], 'array', {
    page: '1',
    page_size: '20',
  });
  assertRole(
    unknownArray(roles).find((entry) => own(exactRecord(entry), 'id') === expected.roleId),
    expected.roleId
  );
  const roleScopes = await call(
    request,
    'GET',
    `roles/${encodeURIComponent(expected.roleId)}/scopes`,
    undefined,
    [200],
    'array'
  );
  if (
    !Array.isArray(roleScopes) ||
    roleScopes.length !== 1 ||
    assertScope(roleScopes[0], expected.resourceId, expected.scopeId) !== expected.scopeId
  ) {
    return fail();
  }
  const users = await call(request, 'GET', 'users', undefined, [200], 'array', {
    page: '1',
    page_size: '100',
  });
  assertIdentity(
    unknownArray(users).find((entry) => own(exactRecord(entry), 'id') === expected.identityId),
    expected.primaryEmail,
    expected.identityId
  );
};

const provisionSelectedNative = async (
  fixture: ProvisionedPhase2Fixture,
  request: Phase2AdminRequestFunction,
  cleanup: SelectedNativeCleanup[],
  targetLabel: TargetConfig['label']
): Promise<Phase2SelectedNativePublic> => {
  const suffix = createHash('sha256')
    .update(fixture.public.allocationId)
    .digest('hex')
    .slice(0, 16);
  const marker = `phase2-native-${suffix}`;
  const primaryEmail = `${marker}@example.invalid`;
  const resource = exactRecord(
    await call(request, 'POST', 'resources', {
      name: `${marker} API`,
      indicator: resourceIndicator,
      accessTokenTtl: 300,
    })
  );
  const resourceId = safeId(own(resource, 'id'));
  cleanup.push(Object.freeze({ path: `resources/${encodeURIComponent(resourceId)}` }));
  assertResource(resource, resourceId);
  const scope = exactRecord(
    await call(request, 'POST', `resources/${encodeURIComponent(resourceId)}/scopes`, {
      name: scopeName,
      description: 'Exchange a Native session',
    })
  );
  const scopeId = safeId(own(scope, 'id'));
  assertScope(scope, resourceId, scopeId);
  const role = exactRecord(
    await call(request, 'POST', 'roles', {
      name: `${marker} default user`,
      description: 'Grants Native session exchange',
      type: 'User',
      isDefault: true,
      scopeIds: [scopeId],
    })
  );
  const roleId = safeId(own(role, 'id'));
  cleanup.push(Object.freeze({ path: `roles/${encodeURIComponent(roleId)}` }));
  assertRole(role, roleId);
  const identity = await fixture.withSecretLease(async (lease) => {
    const getPassword = lease.getSelectedNativePassword ?? fail();
    return exactRecord(
      await call(request, 'POST', 'users', {
        primaryEmail,
        password: getPassword(),
      })
    );
  });
  const identityId = safeId(own(identity, 'id'));
  cleanup.push(Object.freeze({ path: `users/${encodeURIComponent(identityId)}` }));
  assertIdentity(identity, primaryEmail, identityId);
  const application = exactRecord(
    await call(request, 'POST', 'applications', {
      name: `${marker} client`,
      type: 'Native',
      isThirdParty: false,
      oidcClientMetadata: { redirectUris: [callbackUri], postLogoutRedirectUris: [] },
    })
  );
  const applicationId = safeId(own(application, 'id'));
  cleanup.push(Object.freeze({ path: `applications/${encodeURIComponent(applicationId)}` }));
  assertApplication(application, applicationId);
  await readSelectedNative(request, {
    applicationId,
    resourceId,
    scopeId,
    roleId,
    identityId,
    primaryEmail,
  });
  return Object.freeze({
    clientId: applicationId,
    applicationType: 'Native',
    redirectUri: callbackUri,
    resource: Object.freeze({
      id: resourceId,
      indicator: resourceIndicator,
      accessTokenTtl: 300,
      scope: Object.freeze({ id: scopeId, name: scopeName }),
    }),
    defaultUserRoleId: roleId,
    identity: Object.freeze({ id: identityId, primaryEmail }),
  });
};

const cleanupSelectedNative = async (
  request: Phase2AdminRequestFunction,
  cleanup: readonly SelectedNativeCleanup[]
): Promise<void> => {
  const failures: unknown[] = [];
  for (const operation of [...cleanup].reverse()) {
    try {
      await call(request, 'DELETE', operation.path, undefined, [204, 404], 'status');
    } catch (error: unknown) {
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, diagnostic);
  }
};

export const withSelectedNativeFixture = async <Result>(
  fixture: ProvisionedPhase2Fixture,
  options: SelectedNativeFixtureOptions,
  use: (
    fixture: ProvisionedPhase2Fixture & {
      public: Phase2FixturePublicWithSelectedNative;
    }
  ) => Promise<Result>
): Promise<Result> => {
  if (fixture.public.selectedNative !== undefined || typeof use !== 'function') {
    return fail();
  }
  const target = validateTargetConfig(options.target);
  const cleanup: SelectedNativeCleanup[] = [];
  let previousSignInMethods: readonly SelectedSignInMethod[] | undefined;
  let bodyError: unknown;
  let result: Result | undefined;
  try {
    previousSignInMethods = await readSignInMethods(options.request);
    await configureEmailPassword(options.request, previousSignInMethods);
    const selectedNative = await provisionSelectedNative(
      fixture,
      options.request,
      cleanup,
      target.label
    );
    const overlay = Object.freeze({
      ...fixture,
      public: Object.freeze({ ...fixture.public, selectedNative }),
    });
    result = await use(overlay);
  } catch (error: unknown) {
    bodyError = error;
  }
  if (previousSignInMethods !== undefined) {
    try {
      await restoreSignInMethods(options.request, previousSignInMethods);
    } catch (restoreError: unknown) {
      bodyError =
        bodyError === undefined
          ? restoreError
          : new AggregateError([bodyError, restoreError], diagnostic);
    }
  }
  if (target.label === 'oracle') {
    try {
      await cleanupSelectedNative(options.request, cleanup);
    } catch (cleanupError: unknown) {
      if (bodyError !== undefined) {
        throw new AggregateError([bodyError, cleanupError], diagnostic);
      }
      throw cleanupError;
    }
  }
  if (bodyError !== undefined) {
    throw bodyError instanceof Error ? bodyError : new Error(diagnostic);
  }
  return result as Result;
};

export type Phase2FixturePublicWithSelectedNative = Omit<
  ProvisionedPhase2Fixture['public'],
  'selectedNative'
> &
  Readonly<{ selectedNative: Phase2SelectedNativePublic }>;

/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
