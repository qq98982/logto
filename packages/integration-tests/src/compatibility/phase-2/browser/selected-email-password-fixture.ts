/* eslint-disable complexity, max-lines, no-restricted-syntax, unicorn/error-message, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Ordered setup and compensation retain bounded state inside one fixture scope. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid selected email password fixture');
};
const assertBrowserApplication = (
  value: unknown,
  clientId: string,
  metadata: Readonly<{
    redirectUris: readonly string[];
    postLogoutRedirectUris: readonly string[];
  }>
): void => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Reflect.get(value, 'id') !== clientId ||
    Reflect.get(value, 'type') !== 'SPA' ||
    !isDeepStrictEqual(Reflect.get(value, 'oidcClientMetadata'), metadata)
  ) {
    fail();
  }
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
    password: true,
    verificationCode: false,
    isPasswordPrimary: true,
  }),
]);

export type SelectedEmailPasswordIdentity = Readonly<{
  id: string;
  primaryEmail: string;
  isSuspended: false;
  browser?: Readonly<{ clientId: string; redirectUri: string }>;
}>;

export const selectBrowserRedirectUris = (
  redirectUri: string,
  additionalRedirectUris: readonly string[] = []
): readonly string[] => {
  const selected = [redirectUri, ...additionalRedirectUris];
  if (
    selected.some((value) => typeof value !== 'string' || value.length === 0) ||
    new Set(selected).size !== selected.length
  ) {
    return fail();
  }
  return Object.freeze(selected);
};

export const withSelectedEmailPasswordFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser?: Readonly<{
      clientId: string;
      redirectUri: string;
      additionalRedirectUris?: readonly string[];
    }>;
    getPassword(): string;
    use(identity: SelectedEmailPasswordIdentity): Promise<Result>;
  }>
): Promise<Result> => {
  let previous: unknown;
  let previousBranding: unknown;
  let userId: string | undefined;
  let roleId: string | undefined;
  let result: Result | undefined;
  let bodyError: unknown;
  let primaryFailed = false;
  let primaryStage = 'setup-config';
  let flowStage = 'none';
  const cleanupStages: string[] = [];
  let previousClientMetadata:
    | Readonly<{
        redirectUris: readonly string[];
        postLogoutRedirectUris: readonly string[];
      }>
    | undefined;
  try {
    const current = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { signIn?: { methods?: unknown }; branding?: unknown };
    previous = current.signIn?.methods;
    previousBranding = current.branding;
    if (
      !Array.isArray(previous) ||
      typeof previousBranding !== 'object' ||
      previousBranding === null ||
      Array.isArray(previousBranding)
    ) {
      return fail();
    }
    primaryStage = 'patch-sie';
    const updated = (await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { signIn: { methods }, branding: {} },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { signIn?: { methods?: unknown }; branding?: unknown };
    if (
      !isDeepStrictEqual(updated.signIn?.methods, methods) ||
      !isDeepStrictEqual(updated.branding, {})
    ) {
      return fail();
    }
    primaryStage = 'read-sie';
    const readBack = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { signIn?: { methods?: unknown }; branding?: unknown };
    if (
      !isDeepStrictEqual(readBack.signIn?.methods, methods) ||
      !isDeepStrictEqual(readBack.branding, {})
    ) {
      return fail();
    }
    if (input.browser) {
      primaryStage = 'get-app';
      const applicationPath = `applications/${encodeURIComponent(input.browser.clientId)}`;
      const application = (await input.request({
        method: 'GET',
        path: applicationPath,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as {
        id?: unknown;
        type?: unknown;
        oidcClientMetadata?: {
          redirectUris?: unknown;
          postLogoutRedirectUris?: unknown;
        };
      };
      const redirectUris = application.oidcClientMetadata?.redirectUris;
      const postLogoutRedirectUris = application.oidcClientMetadata?.postLogoutRedirectUris;
      if (
        application.id !== input.browser.clientId ||
        application.type !== 'SPA' ||
        !Array.isArray(redirectUris) ||
        !redirectUris.every((value) => typeof value === 'string') ||
        !Array.isArray(postLogoutRedirectUris) ||
        !postLogoutRedirectUris.every((value) => typeof value === 'string')
      ) {
        return fail();
      }
      previousClientMetadata = Object.freeze({
        redirectUris: Object.freeze([...redirectUris]),
        postLogoutRedirectUris: Object.freeze([...postLogoutRedirectUris]),
      });
      const targetMetadata = Object.freeze({
        redirectUris: selectBrowserRedirectUris(
          input.browser.redirectUri,
          input.browser.additionalRedirectUris
        ),
        postLogoutRedirectUris: previousClientMetadata.postLogoutRedirectUris,
      });
      primaryStage = 'patch-app';
      const patchedApplication = (await input.request({
        method: 'PATCH',
        path: applicationPath,
        body: { oidcClientMetadata: targetMetadata },
        expectedStatuses: [200],
        responseKind: 'object',
      })) as { id?: unknown; type?: unknown; oidcClientMetadata?: unknown };
      if (
        patchedApplication.id !== input.browser.clientId ||
        patchedApplication.type !== 'SPA' ||
        !isDeepStrictEqual(patchedApplication.oidcClientMetadata, targetMetadata)
      ) {
        return fail();
      }
      primaryStage = 'read-app';
      const applicationReadBack = (await input.request({
        method: 'GET',
        path: applicationPath,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as { id?: unknown; type?: unknown; oidcClientMetadata?: unknown };
      if (
        applicationReadBack.id !== input.browser.clientId ||
        applicationReadBack.type !== 'SPA' ||
        !isDeepStrictEqual(applicationReadBack.oidcClientMetadata, targetMetadata)
      ) {
        return fail();
      }
    }
    const statusResource = input.fixture.status?.resource;
    if (!statusResource) {
      return fail();
    }
    primaryStage = 'read-resource-scopes';
    const resources = (await input.request({
      method: 'GET',
      path: 'resources',
      query: { includeScopes: 'true' },
      expectedStatuses: [200],
      responseKind: 'array',
    })) as unknown[];
    const selectedResources = resources.filter(
      (resource) =>
        typeof resource === 'object' &&
        resource !== null &&
        Reflect.get(resource, 'id') === statusResource.id
    );
    const selectedResource = selectedResources[0];
    if (selectedResources.length !== 1 || !selectedResource) {
      return fail();
    }
    const nestedScopes: unknown = Reflect.get(selectedResource, 'scopes');
    if (!Array.isArray(nestedScopes)) {
      return fail();
    }
    const scopes: unknown[] = nestedScopes;
    const matchingScopes = scopes.filter(
      (scope) =>
        typeof scope === 'object' &&
        scope !== null &&
        Reflect.get(scope, 'name') === statusResource.scopeName &&
        typeof Reflect.get(scope, 'id') === 'string'
    );
    const matchingScope = matchingScopes[0];
    if (matchingScopes.length !== 1 || !matchingScope) {
      return fail();
    }
    const scopeId = Reflect.get(matchingScope, 'id') as string;
    primaryStage = 'post-resource-role';
    const role = (await input.request({
      method: 'POST',
      path: 'roles',
      body: {
        name: `common-email-${input.fixture.public.allocationId}`,
        description: 'Common email password resource authority',
        type: 'User',
        isDefault: false,
        scopeIds: [scopeId],
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; name?: unknown; type?: unknown; isDefault?: unknown };
    if (typeof role.id === 'string' && role.id.length > 0) {
      roleId = role.id;
    }
    if (
      !roleId ||
      role.name !== `common-email-${input.fixture.public.allocationId}` ||
      role.type !== 'User' ||
      role.isDefault !== false
    ) {
      return fail();
    }
    primaryStage = 'read-resource-role-scopes';
    const roleScopes = (await input.request({
      method: 'GET',
      path: `roles/${encodeURIComponent(roleId)}/scopes`,
      expectedStatuses: [200],
      responseKind: 'array',
    })) as unknown[];
    if (
      roleScopes.length !== 1 ||
      typeof roleScopes[0] !== 'object' ||
      roleScopes[0] === null ||
      Reflect.get(roleScopes[0], 'id') !== scopeId ||
      Reflect.get(roleScopes[0], 'name') !== statusResource.scopeName ||
      Reflect.get(roleScopes[0], 'resourceId') !== statusResource.id
    ) {
      return fail();
    }
    const primaryEmail = `common-email-${input.fixture.public.allocationId}@example.invalid`;
    primaryStage = 'post-user';
    const created = (await input.request({
      method: 'POST',
      path: 'users',
      body: { primaryEmail, password: input.getPassword() },
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
      created.hasPassword !== true ||
      created.isSuspended !== false
    ) {
      return fail();
    }
    primaryStage = 'assign-resource-role';
    await input.request({
      method: 'POST',
      path: `roles/${encodeURIComponent(roleId)}/users`,
      body: { userIds: [userId] },
      expectedStatuses: [201],
      responseKind: 'status',
    });
    primaryStage = 'read-user-roles';
    const userRoles = (await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(userId)}/roles`,
      expectedStatuses: [200],
      responseKind: 'array',
    })) as unknown[];
    if (
      !userRoles.some(
        (userRole) =>
          typeof userRole === 'object' &&
          userRole !== null &&
          Reflect.get(userRole, 'id') === roleId &&
          Reflect.get(userRole, 'type') === 'User'
      )
    ) {
      return fail();
    }
    primaryStage = 'use';
    result = await input.use(
      Object.freeze({
        id: userId,
        primaryEmail,
        isSuspended: false,
        ...(input.browser
          ? {
              browser: Object.freeze({
                clientId: input.browser.clientId,
                redirectUri: input.browser.redirectUri,
              }),
            }
          : {}),
      })
    );
  } catch (error: unknown) {
    primaryFailed = true;
    flowStage =
      error instanceof Error
        ? (/^Common email password stage failed: (initialization|credentials|consent|callback(?:-(?:cardinality|signin-authority|signin-response|signin-client|signin-redirect|signin-mode|signin-scope|signin-resource|signin-pkce|callback-authority|callback-response|callback-state|callback-issuer|callback-code|callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|exchange-authority|exchange-response|exchange-correlation|exchange-client|exchange-refresh|exchange-target|exchange-scope|exchange-access))?|profile|profile-sub|profile-email|refresh|refresh-sub|refresh-rotation|refresh-exchange-kind|refresh-authority|refresh-status|refresh-request-shape|refresh-correlation|refresh-client|refresh-redirect|refresh-initial-refresh-flag|refresh-replacement-fresh|refresh-resource|refresh-organization|refresh-response-scope(?:-(?:api-only|oidc-plus-api|oidc-only|missing|other)-claims-(?:api-only|oidc-plus-api|oidc-only|missing|other))?|refresh-access-kind|refresh-compact-issuer|refresh-subject|refresh-audience|refresh-compact-client|refresh-scope|refresh-organization-present|controls-invalid|controls-suspended(?:-set|-attempt|-restore|-attempt-restore|-set-restore)?|controls-username|username-sub)$/u.exec(
            error.message
          )?.[1] ?? 'none')
        : 'none';
    bodyError = error;
  }
  if (Array.isArray(previous)) {
    try {
      await input.request({
        method: 'PATCH',
        path: 'sign-in-exp',
        body: { signIn: { methods: previous }, branding: previousBranding },
        expectedStatuses: [200],
        responseKind: 'object',
      });
      const restored = (await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })) as { signIn?: { methods?: unknown }; branding?: unknown };
      if (
        !isDeepStrictEqual(restored.signIn?.methods, previous) ||
        !isDeepStrictEqual(restored.branding, previousBranding)
      ) {
        fail();
      }
    } catch (error: unknown) {
      cleanupStages.push('restore-sie');
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
  if (previousClientMetadata && input.browser) {
    try {
      const restored = await input.request({
        method: 'PATCH',
        path: `applications/${encodeURIComponent(input.browser.clientId)}`,
        body: { oidcClientMetadata: previousClientMetadata },
        expectedStatuses: [200],
        responseKind: 'object',
      });
      assertBrowserApplication(restored, input.browser.clientId, previousClientMetadata);
    } catch (error: unknown) {
      cleanupStages.push('restore-app-patch');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
    try {
      const restoredReadBack = await input.request({
        method: 'GET',
        path: `applications/${encodeURIComponent(input.browser.clientId)}`,
        expectedStatuses: [200],
        responseKind: 'object',
      });
      assertBrowserApplication(restoredReadBack, input.browser.clientId, previousClientMetadata);
    } catch (error: unknown) {
      cleanupStages.push('restore-app-read');
      bodyError = bodyError ? new AggregateError([bodyError, error]) : error;
    }
  }
  if (primaryFailed) {
    throw new TypeError(
      `Common email password fixture failed: primary-${primaryStage};cleanup-${cleanupStages.join('+') || 'none'};flow-${flowStage}`
    );
  }
  if (cleanupStages.length > 0) {
    throw new TypeError(
      `Common email password fixture failed: primary-none;cleanup-${cleanupStages.join('+')};flow-none`
    );
  }
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-restricted-syntax, unicorn/error-message, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
