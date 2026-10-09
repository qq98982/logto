/* eslint-disable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- Reflected Management values are validated before use. */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid selected email password registration fixture');
};
const sameJson = (left: unknown, right: unknown): boolean =>
  isDeepStrictEqual(structuredClone(left), structuredClone(right));
export const passwordRegistrationEmailForAllocation = (allocationId: string): string => {
  const suffix = createHash('sha256').update(allocationId).digest('hex').slice(0, 16);
  return `common-email-password-registration-${suffix}@example.invalid`;
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
    password: true,
    verificationCode: false,
    isPasswordPrimary: true,
  }),
]);
const selectedSignUp = Object.freeze({
  identifiers: Object.freeze(['email']),
  password: true,
  verify: true,
});
type Experience = Readonly<{
  branding?: unknown;
  signIn?: Readonly<{ methods?: unknown }>;
  signUp?: unknown;
}>;
const exactOwnedUserIds = async (
  request: Phase2AdminRequestFunction,
  emails: ReadonlySet<string>
): Promise<readonly string[]> => {
  const users = await request({
    method: 'GET',
    path: 'users',
    query: { page: '1', page_size: '100' },
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(users) || users.length >= 100) return fail();
  const ids: string[] = [];
  for (const user of users) {
    if (
      typeof user === 'object' &&
      user !== null &&
      emails.has(String(Reflect.get(user, 'primaryEmail')))
    ) {
      const id = Reflect.get(user, 'id');
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) return fail();
      ids.push(id);
    }
  }
  return Object.freeze(ids);
};

export const withSelectedEmailPasswordRegistrationFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser: Readonly<{ clientId: string; redirectUri: string }>;
    use(
      value: Readonly<{
        primaryEmail: string;
        incompleteEmail: string;
        rejectedPolicyEmail: string;
        captureRegisteredUser(id: string): Promise<void>;
      }>
    ): Promise<Result>;
  }>
): Promise<Result> => {
  const resource = input.fixture.status?.resource ?? fail();
  const { allocationId } = input.fixture.public;
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(allocationId)) return fail();
  const primaryEmail = passwordRegistrationEmailForAllocation(allocationId);
  const incompleteEmail = passwordRegistrationEmailForAllocation(`${allocationId}-incomplete`);
  const rejectedPolicyEmail = passwordRegistrationEmailForAllocation(`${allocationId}-policy`);
  const ownedEmails = new Set([primaryEmail, incompleteEmail, rejectedPolicyEmail]);
  let previous: Experience | undefined;
  let previousMetadata: Record<string, unknown> | undefined;
  let roleId: string | undefined;
  let capturedUserId: string | undefined;
  let baselineOwnedUserIds: ReadonlySet<string> | undefined;
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

    primaryStage = 'read-app';
    const applicationPath = `applications/${encodeURIComponent(input.browser.clientId)}`;
    const application = (await input.request({
      method: 'GET',
      path: applicationPath,
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    const metadata = application.oidcClientMetadata;
    const redirects =
      typeof metadata === 'object' && metadata !== null
        ? Reflect.get(metadata, 'redirectUris')
        : undefined;
    if (
      application.id !== input.browser.clientId ||
      application.type !== 'SPA' ||
      !Array.isArray(redirects) ||
      !redirects.every((value) => typeof value === 'string')
    )
      return fail();
    previousMetadata = structuredClone(metadata as Record<string, unknown>);
    const selectedMetadata = { ...previousMetadata, redirectUris: [input.browser.redirectUri] };
    primaryStage = 'patch-app';
    const patchedApplication = (await input.request({
      method: 'PATCH',
      path: applicationPath,
      body: { oidcClientMetadata: selectedMetadata },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    const readApplication = (await input.request({
      method: 'GET',
      path: applicationPath,
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (
      !sameJson(patchedApplication.oidcClientMetadata, selectedMetadata) ||
      !sameJson(readApplication.oidcClientMetadata, selectedMetadata)
    )
      return fail();

    primaryStage = 'read-owned-users';
    const preexistingOwnedUsers = await exactOwnedUserIds(input.request, ownedEmails);
    baselineOwnedUserIds = new Set(preexistingOwnedUsers);
    if (preexistingOwnedUsers.length > 0) return fail();
    primaryStage = 'read-resource';
    const resources = await input.request({
      method: 'GET',
      path: 'resources',
      query: { includeScopes: 'true' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (!Array.isArray(resources)) return fail();
    const matchingScopes = resources.flatMap((entry) =>
      typeof entry === 'object' &&
      entry !== null &&
      Reflect.get(entry, 'id') === resource.id &&
      Array.isArray(Reflect.get(entry, 'scopes'))
        ? (Reflect.get(entry, 'scopes') as unknown[]).filter(
            (scope) =>
              typeof scope === 'object' &&
              scope !== null &&
              Reflect.get(scope, 'name') === resource.scopeName &&
              typeof Reflect.get(scope, 'id') === 'string'
          )
        : []
    );
    if (matchingScopes.length !== 1) return fail();
    const scopeId = Reflect.get(matchingScopes[0] as Record<string, unknown>, 'id') as string;
    primaryStage = 'create-role';
    const role = (await input.request({
      method: 'POST',
      path: 'roles',
      body: {
        name: `common-email-password-registration-${createHash('sha256').update(allocationId).digest('hex').slice(0, 16)}`,
        description: 'Common email password registration fixture',
        type: 'User',
        isDefault: true,
        scopeIds: [scopeId],
      },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (typeof role.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(role.id)) roleId = role.id;
    if (!roleId || role.type !== 'User' || role.isDefault !== true) return fail();
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
      Reflect.get(roleScopes[0], 'resourceId') !== resource.id ||
      Reflect.get(roleScopes[0], 'name') !== resource.scopeName
    )
      return fail();

    primaryStage = 'patch-sie';
    const selected = {
      branding: {},
      signIn: { methods: selectedMethods },
      signUp: selectedSignUp,
    };
    const selectedExpected = {
      ...previous,
      branding: {},
      signIn: { ...previous.signIn, methods: selectedMethods },
      signUp: selectedSignUp,
    };
    const patched = await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: selected,
      expectedStatuses: [200],
      responseKind: 'object',
    });
    const selectedRead = await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    });
    if (!sameJson(patched, selectedExpected) || !sameJson(selectedRead, selectedExpected))
      return fail();

    primaryStage = 'use';
    result = await input.use(
      Object.freeze({
        primaryEmail,
        incompleteEmail,
        rejectedPolicyEmail,
        captureRegisteredUser: async (id: string) => {
          if (capturedUserId !== undefined || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) return fail();
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
          capturedUserId = id;
        },
      })
    );
    if (!capturedUserId) return fail();
    primaryStage = 'read-user-roles';
    const userRoles = await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(capturedUserId)}/roles`,
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (
      !Array.isArray(userRoles) ||
      userRoles.filter(
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
    if (previousMetadata) {
      try {
        const path = `applications/${encodeURIComponent(input.browser.clientId)}`;
        const restored = (await input.request({
          method: 'PATCH',
          path,
          body: { oidcClientMetadata: previousMetadata },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as Record<string, unknown>;
        const read = (await input.request({
          method: 'GET',
          path,
          expectedStatuses: [200],
          responseKind: 'object',
        })) as Record<string, unknown>;
        if (
          !sameJson(restored.oidcClientMetadata, previousMetadata) ||
          !sameJson(read.oidcClientMetadata, previousMetadata)
        )
          cleanupStages.push('restore-app');
      } catch {
        cleanupStages.push('restore-app');
      }
    }
    try {
      if (baselineOwnedUserIds) {
        const ownedUserIds = await exactOwnedUserIds(input.request, ownedEmails);
        await Promise.all(
          ownedUserIds
            .filter((id) => !baselineOwnedUserIds?.has(id))
            .map(async (id) =>
              input.request({
                method: 'DELETE',
                path: `users/${encodeURIComponent(id)}`,
                expectedStatuses: [204, 404],
                responseKind: 'status',
              })
            )
        );
      }
    } catch {
      cleanupStages.push('delete-users');
    }
    if (roleId) {
      await input
        .request({
          method: 'DELETE',
          path: `roles/${encodeURIComponent(roleId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => cleanupStages.push('delete-role'));
    }
  }
  if (cleanupStages.length > 0) {
    throw new TypeError(
      `Email password registration fixture failed: cleanup-${cleanupStages.join('+')}`
    );
  }
  if (primaryFailed) {
    throw new TypeError(
      `Email password registration fixture failed: primary-${primaryStage};cleanup-none`
    );
  }
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
