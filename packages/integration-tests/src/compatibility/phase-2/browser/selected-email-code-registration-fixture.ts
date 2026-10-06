/* eslint-disable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- One fixture owns borrowed registration configuration and compensates actual browser-created state. */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid selected email code registration fixture');
};
const sameJson = (left: unknown, right: unknown): boolean =>
  isDeepStrictEqual(structuredClone(left), structuredClone(right));
const selectedSignUp = Object.freeze({
  identifiers: Object.freeze(['email']),
  password: false,
  verify: true,
});
export const registrationEmailForAllocation = (allocationId: string): string => {
  const suffix = createHash('sha256').update(allocationId).digest('hex').slice(0, 16);
  return `common-email-code-registration-${suffix}@example.invalid`;
};
const selectedMethods = Object.freeze([
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
type Experience = Readonly<{
  branding?: unknown;
  signIn?: Readonly<{ methods?: unknown }>;
  signUp?: unknown;
}>;
export const withSelectedEmailCodeRegistrationFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser?: Readonly<{ clientId: string; redirectUri: string }>;
    use(
      value: Readonly<{
        primaryEmail: string;
        captureRegisteredUser(id: string): Promise<void>;
      }>
    ): Promise<Result>;
  }>
): Promise<Result> => {
  const resource = input.fixture.status?.resource ?? fail();
  const { allocationId } = input.fixture.public;
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(allocationId)) return fail();
  const primaryEmail = registrationEmailForAllocation(allocationId);
  let previous: Experience | undefined;
  let previousMetadata: Record<string, unknown> | undefined;
  let roleId: string | undefined;
  let userId: string | undefined;
  let result: Result | undefined;
  let primaryFailed = false;
  let primaryStage = 'read-sie';
  const cleanupStages: string[] = [];
  try {
    const current = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Experience;
    if (
      !Array.isArray(current.signIn?.methods) ||
      current.signUp === undefined ||
      typeof current.branding !== 'object' ||
      current.branding === null ||
      Array.isArray(current.branding)
    )
      return fail();
    previous = structuredClone(current);
    if (input.browser) {
      primaryStage = 'read-app';
      const path = `applications/${encodeURIComponent(input.browser.clientId)}`;
      const app = (await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      const metadata: unknown = app.oidcClientMetadata;
      const redirects: unknown =
        typeof metadata === 'object' && metadata !== null
          ? (metadata as Record<string, unknown>).redirectUris
          : null;
      if (
        Reflect.get(app, 'id') !== input.browser.clientId ||
        Reflect.get(app, 'type') !== 'SPA' ||
        !Array.isArray(redirects) ||
        !redirects.every((value) => typeof value === 'string')
      )
        return fail();
      previousMetadata = structuredClone(metadata as Record<string, unknown>);
      const target = { ...previousMetadata, redirectUris: [input.browser.redirectUri] };
      primaryStage = 'patch-app';
      const patched = (await input.request({
        method: 'PATCH',
        path,
        body: { oidcClientMetadata: target },
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      if (!sameJson(Reflect.get(patched, 'oidcClientMetadata'), target)) return fail();
      const read = (await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })) as Record<string, unknown>;
      if (!sameJson(Reflect.get(read, 'oidcClientMetadata'), target)) return fail();
    }
    primaryStage = 'read-resource';
    const resources = await input.request({
      method: 'GET',
      path: 'resources',
      query: { includeScopes: 'true' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (!Array.isArray(resources)) return fail();
    const scopes = resources.flatMap((entry) =>
      typeof entry === 'object' &&
      entry !== null &&
      Reflect.get(entry, 'id') === resource.id &&
      Array.isArray(Reflect.get(entry, 'scopes'))
        ? (Reflect.get(entry, 'scopes') as unknown[])
        : []
    );
    const matching = scopes.filter(
      (scope) =>
        typeof scope === 'object' &&
        scope !== null &&
        Reflect.get(scope, 'name') === resource.scopeName &&
        typeof Reflect.get(scope, 'id') === 'string'
    );
    if (matching.length !== 1) return fail();
    const matchingScope = matching[0];
    if (typeof matchingScope !== 'object' || matchingScope === null) return fail();
    const scopeId = Reflect.get(matchingScope, 'id') as string;
    primaryStage = 'create-role';
    const role = (await input.request({
      method: 'POST',
      path: 'roles',
      body: {
        name: `common-email-code-registration-${allocationId}`,
        description: 'Common email code registration fixture',
        type: 'User',
        isDefault: true,
        scopeIds: [scopeId],
      },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (typeof role.id === 'string' && role.id.length > 0) roleId = role.id;
    if (!roleId || role.type !== 'User' || role.isDefault !== true) return fail();
    const roleScopes = await input.request({
      method: 'GET',
      path: `roles/${encodeURIComponent(roleId)}/scopes`,
      expectedStatuses: [200],
      responseKind: 'array',
    });
    const roleScope: unknown = Array.isArray(roleScopes) ? roleScopes[0] : undefined;
    if (
      !Array.isArray(roleScopes) ||
      roleScopes.length !== 1 ||
      typeof roleScope !== 'object' ||
      roleScope === null ||
      Reflect.get(roleScope, 'id') !== scopeId ||
      Reflect.get(roleScope, 'resourceId') !== resource.id ||
      Reflect.get(roleScope, 'name') !== resource.scopeName
    )
      return fail();
    primaryStage = 'patch-sie';
    const selectedBranding = {};
    const selected = {
      branding: selectedBranding,
      signIn: { methods: selectedMethods },
      signUp: selectedSignUp,
    };
    const selectedExpected = {
      ...previous,
      branding: selectedBranding,
      signIn: { ...previous.signIn, methods: selectedMethods },
      signUp: selectedSignUp,
    };
    const patched = (await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: selected,
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Experience;
    if (!sameJson(patched, selectedExpected)) return fail();
    const selectedRead = await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    });
    if (!sameJson(selectedRead, selectedExpected)) return fail();
    primaryStage = 'use';
    result = await input.use(
      Object.freeze({
        primaryEmail,
        captureRegisteredUser: async (id: string) => {
          if (userId !== undefined || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) return fail();
          const user = await input.request({
            method: 'GET',
            path: `users/${encodeURIComponent(id)}`,
            expectedStatuses: [200],
            responseKind: 'object',
          });
          if (
            typeof user !== 'object' ||
            user === null ||
            Reflect.get(user, 'id') !== id ||
            Reflect.get(user, 'primaryEmail') !== primaryEmail
          )
            return fail();
          userId = id;
        },
      })
    );
    if (!userId) return fail();
    primaryStage = 'read-user-roles';
    const roles = await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(userId)}/roles`,
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (
      !Array.isArray(roles) ||
      roles.filter(
        (entry) =>
          typeof entry === 'object' &&
          entry !== null &&
          Reflect.get(entry, 'id') === roleId &&
          Reflect.get(entry, 'type') === 'User' &&
          Reflect.get(entry, 'isDefault') === true
      ).length !== 1
    )
      return fail();
  } catch {
    primaryFailed = true;
  } finally {
    if (previous) {
      try {
        const restore = {
          branding: previous.branding,
          signIn: { methods: previous.signIn?.methods },
          signUp: previous.signUp,
        };
        const restored = await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: restore,
          expectedStatuses: [200],
          responseKind: 'object',
        });
        const read = await input.request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        });
        if (!sameJson(restored, previous) || !sameJson(read, previous))
          cleanupStages.push('restore-sie');
      } catch {
        cleanupStages.push('restore-sie');
      }
    }
    if (input.browser && previousMetadata) {
      try {
        const path = `applications/${encodeURIComponent(input.browser.clientId)}`;
        const restored = await input.request({
          method: 'PATCH',
          path,
          body: { oidcClientMetadata: previousMetadata },
          expectedStatuses: [200],
          responseKind: 'object',
        });
        const read = await input.request({
          method: 'GET',
          path,
          expectedStatuses: [200],
          responseKind: 'object',
        });
        if (
          !sameJson(
            Reflect.get(restored as Record<string, unknown>, 'oidcClientMetadata'),
            previousMetadata
          ) ||
          !sameJson(
            Reflect.get(read as Record<string, unknown>, 'oidcClientMetadata'),
            previousMetadata
          )
        )
          cleanupStages.push('restore-app');
      } catch {
        cleanupStages.push('restore-app');
      }
    }
    if (userId)
      await input
        .request({
          method: 'DELETE',
          path: `users/${encodeURIComponent(userId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => cleanupStages.push('delete-user'));
    if (roleId)
      await input
        .request({
          method: 'DELETE',
          path: `roles/${encodeURIComponent(roleId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => cleanupStages.push('delete-role'));
  }
  if (cleanupStages.length > 0)
    throw new TypeError(
      `Email code registration fixture failed: cleanup-${cleanupStages.join('+')}`
    );
  if (primaryFailed)
    throw new TypeError(
      `Email code registration fixture failed: primary-${primaryStage};cleanup-none`
    );
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
