/* eslint-disable complexity, max-lines, no-restricted-syntax, unicorn/error-message, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal, @typescript-eslint/no-unsafe-assignment -- Ordered setup and independent compensation remain in one fixture scope. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid selected email code fixture');
};

const methods = Object.freeze([
  Object.freeze({
    identifier: 'username',
    password: true,
    verificationCode: false,
    isPasswordPrimary: true,
  }),
  Object.freeze({
    identifier: 'email',
    password: false,
    verificationCode: true,
    isPasswordPrimary: false,
  }),
]);

type SignInExperience = Readonly<{
  branding?: unknown;
  signUp?: unknown;
  signIn?: Readonly<{ methods?: unknown }>;
}>;

export type SelectedEmailCodeIdentity = Readonly<{
  id: string;
  primaryEmail: string;
  isSuspended: false;
}>;

export const withSelectedEmailCodeFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser?: Readonly<{ clientId: string; redirectUri: string }>;
    use(identity: SelectedEmailCodeIdentity): Promise<Result>;
  }>
): Promise<Result> => {
  const status = input.fixture.status ?? fail();
  let previousMethods: unknown;
  let previousSignUp: unknown;
  let previousBranding: unknown;
  const selectedBranding = Object.freeze({});
  let userId: string | undefined;
  let roleId: string | undefined;
  let result: Result | undefined;
  let bodyError: unknown;
  let primaryFailed = false;
  let primaryStage = 'get-sie';
  let flowStage: string | undefined;
  const cleanupStages: string[] = [];
  let previousRedirectUris: readonly string[] | undefined;
  try {
    const current = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as SignInExperience;
    previousMethods = current.signIn?.methods;
    previousSignUp = current.signUp;
    previousBranding = current.branding;
    if (
      !Array.isArray(previousMethods) ||
      previousSignUp === undefined ||
      typeof previousBranding !== 'object' ||
      previousBranding === null ||
      Array.isArray(previousBranding)
    ) {
      return fail();
    }
    if (input.browser) {
      primaryStage = 'get-app';
      const path = `applications/${encodeURIComponent(input.browser.clientId)}`;
      const app = (await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      const metadata = Reflect.get(app, 'oidcClientMetadata');
      const redirects =
        typeof metadata === 'object' && metadata !== null
          ? Reflect.get(metadata, 'redirectUris')
          : null;
      if (
        Reflect.get(app, 'id') !== input.browser.clientId ||
        Reflect.get(app, 'type') !== 'SPA' ||
        !Array.isArray(redirects) ||
        !redirects.every((value) => typeof value === 'string')
      ) {
        return fail();
      }
      const metadataRecord = metadata as Record<string, unknown>;
      previousRedirectUris = Object.freeze([...redirects]);
      const target = Object.freeze({
        ...metadataRecord,
        redirectUris: [input.browser.redirectUri],
      });
      primaryStage = 'patch-app';
      const patched = (await input.request({
        method: 'PATCH',
        path,
        body: { oidcClientMetadata: target },
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      if (!isDeepStrictEqual(Reflect.get(patched, 'oidcClientMetadata'), target)) {
        return fail();
      }
      primaryStage = 'read-app';
      const readBack = (await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      if (!isDeepStrictEqual(Reflect.get(readBack, 'oidcClientMetadata'), target)) {
        return fail();
      }
    }
    primaryStage = 'read-resource-scopes';
    const resources = await input.request({
      method: 'GET',
      path: 'resources',
      query: { includeScopes: 'true' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (!Array.isArray(resources)) {
      return fail();
    }
    const selectedResources = Array.from<unknown>(resources).filter(
      (resource): resource is Record<string, unknown> =>
        typeof resource === 'object' &&
        resource !== null &&
        Reflect.get(resource, 'id') === status.resource.id
    );
    const [selectedResource] = selectedResources;
    if (selectedResources.length !== 1 || selectedResource === undefined) {
      return fail();
    }
    const scopes: unknown = Reflect.get(selectedResource, 'scopes');
    if (!Array.isArray(scopes)) {
      return fail();
    }
    const matching = scopes.filter(
      (scope) =>
        typeof scope === 'object' &&
        scope !== null &&
        Reflect.get(scope, 'name') === status.resource.scopeName &&
        Reflect.get(scope, 'resourceId') === status.resource.id
    );
    if (matching.length !== 1 || typeof Reflect.get(matching[0], 'id') !== 'string') {
      return fail();
    }
    const scopeId = Reflect.get(matching[0], 'id') as string;
    primaryStage = 'patch-sie-request';
    const updated = (await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { branding: selectedBranding, signIn: { methods } },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as SignInExperience;
    primaryStage = 'patch-sie-response';
    if (
      !isDeepStrictEqual(updated.signIn?.methods, methods) ||
      !isDeepStrictEqual(updated.signUp, previousSignUp) ||
      !isDeepStrictEqual(updated.branding, selectedBranding)
    ) {
      return fail();
    }
    primaryStage = 'create-role';
    const createdRole = (await input.request({
      method: 'POST',
      path: 'roles',
      body: {
        name: `common-email-code-${input.fixture.public.allocationId}`,
        description: 'Common email code selected-user authority',
        type: 'User',
        isDefault: false,
        scopeIds: [scopeId],
      },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (typeof createdRole.id === 'string' && createdRole.id.length > 0) {
      roleId = createdRole.id;
    }
    if (
      !roleId ||
      createdRole.name !== `common-email-code-${input.fixture.public.allocationId}` ||
      createdRole.type !== 'User' ||
      createdRole.isDefault !== false
    ) {
      return fail();
    }
    primaryStage = 'read-role-scopes';
    const roleScopes = await input.request({
      method: 'GET',
      path: `roles/${encodeURIComponent(roleId)}/scopes`,
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (
      !Array.isArray(roleScopes) ||
      roleScopes.length !== 1 ||
      typeof roleScopes[0] !== 'object' ||
      roleScopes[0] === null ||
      Reflect.get(roleScopes[0], 'id') !== scopeId ||
      Reflect.get(roleScopes[0], 'name') !== status.resource.scopeName ||
      Reflect.get(roleScopes[0], 'resourceId') !== status.resource.id
    ) {
      return fail();
    }
    primaryStage = 'read-sie';
    const readBack = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as SignInExperience;
    if (
      !isDeepStrictEqual(readBack.signIn?.methods, methods) ||
      !isDeepStrictEqual(readBack.signUp, previousSignUp) ||
      !isDeepStrictEqual(readBack.branding, selectedBranding)
    ) {
      return fail();
    }
    const primaryEmail = `common-email-code-${input.fixture.public.allocationId}@example.invalid`;
    primaryStage = 'create-user';
    const created = (await input.request({
      method: 'POST',
      path: 'users',
      body: { primaryEmail },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as {
      id?: unknown;
      primaryEmail?: unknown;
      hasPassword?: unknown;
      isSuspended?: unknown;
    };
    if (typeof created.id === 'string' && created.id.length > 0) {
      userId = created.id;
    }
    if (
      !userId ||
      created.primaryEmail !== primaryEmail ||
      created.hasPassword !== false ||
      created.isSuspended !== false
    ) {
      return fail();
    }
    const ownedUserId = userId;
    const ownedRoleId = roleId;
    primaryStage = 'assign-role';
    await input.request({
      method: 'POST',
      path: `roles/${encodeURIComponent(ownedRoleId)}/users`,
      body: { userIds: [ownedUserId] },
      expectedStatuses: [201],
      responseKind: 'created',
    });
    primaryStage = 'read-user-roles';
    const roles = await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(ownedUserId)}/roles`,
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (
      !Array.isArray(roles) ||
      roles.length !== 1 ||
      typeof roles[0] !== 'object' ||
      roles[0] === null ||
      Reflect.get(roles[0], 'id') !== ownedRoleId ||
      Reflect.get(roles[0], 'type') !== 'User' ||
      Reflect.get(roles[0], 'isDefault') !== false
    ) {
      return fail();
    }
    primaryStage = 'use';
    result = await input.use(Object.freeze({ id: userId, primaryEmail, isSuspended: false }));
  } catch (error: unknown) {
    primaryFailed = true;
    flowStage =
      primaryStage === 'use' && error instanceof Error
        ? /^Common email code stage failed: (initialization|identifier-submit|verification-route|passcode-retrieval(?:-(?:env-missing|socket-shape|recipient|connect|timeout|not-found|response))?|passcode-format|passcode-fill|consent|callback|profile|refresh|controls(?:-(?:basic|foreign-account|secondary-client))?)$/u.exec(
            error.message
          )?.[1]
        : undefined;
    bodyError = error;
  }
  if (Array.isArray(previousMethods) && previousSignUp !== undefined) {
    try {
      const restored = (await input.request({
        method: 'PATCH',
        path: 'sign-in-exp',
        body: { branding: previousBranding, signIn: { methods: previousMethods } },
        expectedStatuses: [200],
        responseKind: 'object',
      })) as SignInExperience;
      if (
        !isDeepStrictEqual(restored.signIn?.methods, previousMethods) ||
        !isDeepStrictEqual(restored.signUp, previousSignUp) ||
        !isDeepStrictEqual(restored.branding, previousBranding)
      ) {
        return fail();
      }
    } catch (error: unknown) {
      cleanupStages.push('restore-sie');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
  }
  if (input.browser && previousRedirectUris) {
    try {
      const path = `applications/${encodeURIComponent(input.browser.clientId)}`;
      const currentApp = (await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      const currentMetadata = Reflect.get(currentApp, 'oidcClientMetadata');
      if (typeof currentMetadata !== 'object' || currentMetadata === null) {
        return fail();
      }
      const restoredMetadata = Object.freeze({
        ...currentMetadata,
        redirectUris: previousRedirectUris,
      });
      const restored = (await input.request({
        method: 'PATCH',
        path,
        body: { oidcClientMetadata: restoredMetadata },
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      if (!isDeepStrictEqual(Reflect.get(restored, 'oidcClientMetadata'), restoredMetadata)) {
        return fail();
      }
      const readBack = (await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      if (!isDeepStrictEqual(Reflect.get(readBack, 'oidcClientMetadata'), restoredMetadata)) {
        return fail();
      }
    } catch (error: unknown) {
      cleanupStages.push('restore-app');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
  }
  if (Array.isArray(previousMethods) && previousSignUp !== undefined) {
    try {
      const restoredReadBack = (await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })) as SignInExperience;
      if (
        !isDeepStrictEqual(restoredReadBack.signIn?.methods, previousMethods) ||
        !isDeepStrictEqual(restoredReadBack.signUp, previousSignUp) ||
        !isDeepStrictEqual(restoredReadBack.branding, previousBranding)
      ) {
        return fail();
      }
    } catch (error: unknown) {
      cleanupStages.push('read-restored-sie');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
  }
  if (userId) {
    try {
      await input.request({
        method: 'DELETE',
        path: `users/${encodeURIComponent(userId)}`,
        expectedStatuses: [204, 404],
        responseKind: 'status',
      });
    } catch (error: unknown) {
      cleanupStages.push('delete-user');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
  }
  if (roleId) {
    try {
      await input.request({
        method: 'DELETE',
        path: `roles/${encodeURIComponent(roleId)}`,
        expectedStatuses: [204, 404],
        responseKind: 'status',
      });
    } catch (error: unknown) {
      cleanupStages.push('delete-role');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
  }
  if (bodyError) {
    if (primaryFailed) {
      throw new TypeError(
        `Common email code fixture failed: primary-${primaryStage};cleanup-${cleanupStages.join('+') || 'none'}${flowStage ? `;flow-${flowStage}` : ''}`
      );
    }
    if (cleanupStages.length > 0) {
      throw new TypeError(`Common email code fixture failed: cleanup-${cleanupStages.join('+')}`);
    }
    throw bodyError;
  }
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-restricted-syntax, unicorn/error-message, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal, @typescript-eslint/no-unsafe-assignment */
