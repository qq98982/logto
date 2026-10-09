/* eslint-disable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unnecessary-condition -- The registration-only fixture preserves the reviewed generic connector lifecycle while fixing owner mode to registration; reflective Management API records remain untrusted until the explicit checks below. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  createGoogleAuthorizationObserver,
  type GoogleAuthorizationObservation,
} from './google-authorization-observer.js';
import { googleProviderLeaseFailureStage } from './google-provider-lease.js';
import { withSelectedGoogleExistingOwner } from './selected-google-existing-owner-fixture.js';

const fail = (): never => {
  throw new TypeError('Invalid selected Google connector fixture');
};

const ownerStages = new Set([
  'create-user',
  'associate',
  'read-before',
  'use',
  'read-after',
  'cleanup-user',
]);
const ownMessage = (error: unknown): string | undefined => {
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'message') : undefined;
  return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
};
const responseStatus = (error: unknown): number | undefined => {
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'responseStatus') : undefined;
  const value: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  return typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599
    ? value
    : undefined;
};
const ownerStage = (error: unknown, depth = 0): string | undefined => {
  if (depth >= 4) return undefined;
  const direct = /^Selected Google fixture failed: ([a-z]+(?:-[a-z]+)*)$/u.exec(
    ownMessage(error) ?? ''
  )?.[1];
  if (direct && ownerStages.has(direct)) return `existing-owner-${direct}`;
  if (!(error instanceof AggregateError)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(error, 'errors');
  const members: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  if (!Array.isArray(members) || members.length === 0 || members.length > 8) return undefined;
  const entries = Object.getOwnPropertyDescriptors(members);
  const stages: string[] = [];
  for (let index = 0; index < members.length; index += 1) {
    const entry = entries[String(index)];
    if (!entry || !Object.hasOwn(entry, 'value') || !entry.enumerable) return undefined;
    const entryValue: unknown = entry.value;
    const stage = ownerStage(entryValue, depth + 1);
    if (stage) stages.push(stage);
  }
  return stages.find((stage) => stage === 'existing-owner-cleanup-user') ?? stages[0];
};

export const selectedGoogleOwnerFixtureStageForTesting = (error: unknown): string | undefined => {
  if (process.env.NODE_ENV !== 'test') return undefined;
  return ownerStage(error);
};

// English Experience source renders action.sign_in_with using the connector name.
export const googleSignInButtonSelectorCandidate = 'role=button[name=/Continue with Google$/]';

export type SelectedGoogleProviderLease = Readonly<{
  associationData: Readonly<Record<string, unknown>>;
  assertChangedEmailProviderCase(): Promise<void>;
  assertPrimaryRegistrationProviderCase(): Promise<void>;
  takeUnverifiedEmailControlCode(): Promise<string>;
  takeOccupiedEmailControlCode(): Promise<string>;
  stop(): Promise<void>;
}>;

export type SelectedGoogleRegistrationFixtureInput<Result> = Readonly<{
  fixture: ProvisionedPhase2Fixture;
  request: Phase2AdminRequestFunction;
  targetOrigin: string;
  browser: Readonly<{ clientId: string; redirectUri: string }>;
  clientId: string;
  clientSecret: string;
  googleSubject: string;
  originalEmail: string;
  controlEmail: string;
  prepareConnector(connectorId: string): Promise<SelectedGoogleProviderLease>;
  takeBrowserCode(): Promise<string>;
  takeUnverifiedEmailControlCode(): Promise<string>;
  takeOccupiedEmailControlCode(): Promise<string>;
  onDeleteConnectorFailure?(status: number | undefined): Promise<void>;
  use(
    value: Readonly<{
      ownerId?: string;
      connectorId: string;
      capability: ReturnType<typeof createGoogleAuthorizationObserver>['capability'];
      unverifiedEmailCapability: ReturnType<typeof createGoogleAuthorizationObserver>['capability'];
      occupiedEmailCapability: ReturnType<typeof createGoogleAuthorizationObserver>['capability'];
      observation(): GoogleAuthorizationObservation;
      unverifiedEmailObservation(): GoogleAuthorizationObservation;
      occupiedEmailObservation(): GoogleAuthorizationObservation;
      assertRegisteredOwner(subject: string): Promise<Readonly<{ hasPassword: false }>>;
      assertControlsPreservedOwner(): Promise<void>;
      assertChangedEmailProviderCase(): Promise<void>;
    }>
  ): Promise<Result>;
}>;

export const withSelectedGoogleRegistrationFixture = async <Result>(
  rawInput: SelectedGoogleRegistrationFixtureInput<Result>
): Promise<Result> => {
  const input = Object.freeze({ ...rawInput, ownerMode: 'registration' as const });
  let previousTargets: unknown;
  let previousBranding: unknown;
  let previousSignInMode: unknown;
  let previousSignUp: unknown;
  let connectorId: string | undefined;
  let roleId: string | undefined;
  let previousClientMetadata: unknown;
  let preparedProvider: SelectedGoogleProviderLease | undefined;
  let registrationOwnerId: string | undefined;
  let result: Result | undefined;
  let bodyFailed = false;
  let primaryStage = 'read-sie';
  const cleanupStages: string[] = [];
  const registrationOwners = async (): Promise<unknown[]> => {
    const users = (await input.request({
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    })) as unknown[];
    if (users.length >= 100) return fail();
    return users.filter(
      (value) =>
        typeof value === 'object' &&
        value !== null &&
        Reflect.get(value, 'primaryEmail') === input.originalEmail
    );
  };
  const controlAffectedUsers = async (): Promise<unknown[]> => {
    const users = (await input.request({
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    })) as unknown[];
    if (users.length >= 100) return fail();
    return users.filter((value) => {
      if (typeof value !== 'object' || value === null) return false;
      const email = Reflect.get(value, 'primaryEmail');
      const google = Reflect.get(Reflect.get(value, 'identities') ?? {}, 'google');
      const googleSubject =
        typeof google === 'object' && google !== null ? Reflect.get(google, 'userId') : undefined;
      return (
        email === input.originalEmail ||
        email === input.controlEmail ||
        googleSubject === input.googleSubject ||
        googleSubject === `${input.googleSubject}-unverified` ||
        googleSubject === `${input.googleSubject}-occupied`
      );
    });
  };
  try {
    const sie = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as {
      socialSignInConnectorTargets?: unknown;
      branding?: unknown;
      signInMode?: unknown;
      signUp?: unknown;
    };
    previousTargets = sie.socialSignInConnectorTargets;
    previousBranding = sie.branding;
    previousSignInMode = sie.signInMode;
    previousSignUp = sie.signUp;
    if (
      !Array.isArray(previousTargets) ||
      !previousTargets.every((value) => typeof value === 'string') ||
      typeof previousBranding !== 'object' ||
      previousBranding === null ||
      Array.isArray(previousBranding) ||
      previousSignInMode !== 'SignInAndRegister' ||
      typeof previousSignUp !== 'object' ||
      previousSignUp === null ||
      Array.isArray(previousSignUp)
    )
      return fail();
    primaryStage = 'get-app';
    const applicationPath = `applications/${encodeURIComponent(input.browser.clientId)}`;
    const application = (await input.request({
      method: 'GET',
      path: applicationPath,
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; type?: unknown; oidcClientMetadata?: unknown };
    if (
      application.id !== input.browser.clientId ||
      application.type !== 'SPA' ||
      typeof application.oidcClientMetadata !== 'object' ||
      application.oidcClientMetadata === null
    )
      return fail();
    const capturedMetadata = application.oidcClientMetadata as Record<string, unknown>;
    previousClientMetadata = capturedMetadata;
    const targetMetadata = { ...capturedMetadata, redirectUris: [input.browser.redirectUri] };
    primaryStage = 'patch-app';
    const patchedApp = (await input.request({
      method: 'PATCH',
      path: applicationPath,
      body: { oidcClientMetadata: targetMetadata },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { oidcClientMetadata?: unknown };
    if (!isDeepStrictEqual(patchedApp.oidcClientMetadata, targetMetadata)) return fail();
    primaryStage = 'read-app';
    const appRead = (await input.request({
      method: 'GET',
      path: applicationPath,
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { oidcClientMetadata?: unknown };
    if (!isDeepStrictEqual(appRead.oidcClientMetadata, targetMetadata)) return fail();
    const resource = input.fixture.status?.resource;
    if (!resource) return fail();
    primaryStage = 'read-resource';
    const resources = (await input.request({
      method: 'GET',
      path: 'resources',
      query: { includeScopes: 'true' },
      expectedStatuses: [200],
      responseKind: 'array',
    })) as unknown[];
    const selected = resources.filter(
      (value) =>
        typeof value === 'object' && value !== null && Reflect.get(value, 'id') === resource.id
    );
    const selectedResource: unknown = selected[0];
    const scopes: unknown =
      selected.length === 1 && selectedResource
        ? Reflect.get(selectedResource, 'scopes')
        : undefined;
    if (!Array.isArray(scopes)) return fail();
    const matching = scopes.filter(
      (value) =>
        typeof value === 'object' &&
        value !== null &&
        Reflect.get(value, 'name') === resource.scopeName &&
        typeof Reflect.get(value, 'id') === 'string'
    );
    if (matching.length !== 1) return fail();
    const scopeId = Reflect.get(matching[0], 'id') as string;
    primaryStage = 'create-role';
    const role = (await input.request({
      method: 'POST',
      path: 'roles',
      body: {
        name: `common-google-${input.fixture.public.allocationId}`,
        description: 'Common Google resource authority',
        type: 'User',
        isDefault: input.ownerMode === 'registration',
        scopeIds: [scopeId],
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; type?: unknown; isDefault?: unknown };
    if (typeof role.id === 'string' && role.id.length > 0) roleId = role.id;
    if (!roleId || role.type !== 'User' || role.isDefault !== (input.ownerMode === 'registration'))
      return fail();
    const activeRoleId = roleId;
    primaryStage = 'create-connector';
    const connector = (await input.request({
      method: 'POST',
      path: 'connectors',
      body: {
        connectorId: 'google-universal',
        config: {
          clientId: input.clientId,
          clientSecret: input.clientSecret,
          scope: 'openid profile email',
          prompts: [],
          offlineAccess: false,
        },
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; connectorId?: unknown };
    if (typeof connector.id === 'string' && connector.id.length > 0) connectorId = connector.id;
    if (!connectorId || connector.connectorId !== 'google-universal') return fail();
    const activeConnectorId = connectorId;
    primaryStage = 'prepare-connector';
    const prepared = await input.prepareConnector(activeConnectorId);
    preparedProvider = prepared;
    primaryStage = 'patch-sie';
    const updated = (await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: {
        branding: {},
        ...(input.ownerMode === 'registration' && {
          signUp: { identifiers: ['email'], password: false, verify: true },
        }),
        socialSignInConnectorTargets: ['google'],
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as {
      socialSignInConnectorTargets?: unknown;
      branding?: unknown;
      signInMode?: unknown;
      signUp?: unknown;
    };
    if (
      !isDeepStrictEqual(updated.socialSignInConnectorTargets, ['google']) ||
      !isDeepStrictEqual(updated.branding, {}) ||
      updated.signInMode !== 'SignInAndRegister' ||
      !isDeepStrictEqual(
        updated.signUp,
        input.ownerMode === 'registration'
          ? { identifiers: ['email'], password: false, verify: true }
          : previousSignUp
      )
    )
      return fail();
    primaryStage = 'read-sie-updated';
    const readBack = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as {
      socialSignInConnectorTargets?: unknown;
      branding?: unknown;
      signInMode?: unknown;
      signUp?: unknown;
    };
    if (
      !isDeepStrictEqual(readBack.socialSignInConnectorTargets, ['google']) ||
      !isDeepStrictEqual(readBack.branding, {}) ||
      readBack.signInMode !== 'SignInAndRegister' ||
      !isDeepStrictEqual(
        readBack.signUp,
        input.ownerMode === 'registration'
          ? { identifiers: ['email'], password: false, verify: true }
          : previousSignUp
      )
    )
      return fail();
    const authorization = createGoogleAuthorizationObserver({
      connectorId: activeConnectorId,
      clientId: input.clientId,
      targetOrigin: input.targetOrigin,
      takeCode: input.takeBrowserCode,
    });
    const unverifiedEmailAuthorization = createGoogleAuthorizationObserver({
      connectorId: activeConnectorId,
      clientId: input.clientId,
      targetOrigin: input.targetOrigin,
      takeCode: input.takeUnverifiedEmailControlCode,
    });
    const occupiedEmailAuthorization = createGoogleAuthorizationObserver({
      connectorId: activeConnectorId,
      clientId: input.clientId,
      targetOrigin: input.targetOrigin,
      takeCode: input.takeOccupiedEmailControlCode,
    });
    primaryStage =
      input.ownerMode === 'registration' ? 'registration-owner-before' : 'existing-owner';
    if (input.ownerMode === 'registration') {
      const before = await registrationOwners();
      if (before.length > 0) return fail();
      primaryStage = 'registration-owner-use';
      result = await input.use({
        connectorId: activeConnectorId,
        capability: authorization.capability,
        observation: authorization.observation,
        unverifiedEmailCapability: unverifiedEmailAuthorization.capability,
        occupiedEmailCapability: occupiedEmailAuthorization.capability,
        unverifiedEmailObservation: unverifiedEmailAuthorization.observation,
        occupiedEmailObservation: occupiedEmailAuthorization.observation,
        assertRegisteredOwner: async (subject) => {
          const owners = await controlAffectedUsers();
          const owner: unknown = owners[0];
          if (
            owners.length !== 1 ||
            typeof owner !== 'object' ||
            owner === null ||
            Reflect.get(owner, 'id') !== subject ||
            Reflect.get(owner, 'primaryEmail') !== input.originalEmail ||
            Reflect.get(owner, 'hasPassword') !== false ||
            typeof Reflect.get(owner, 'identities') !== 'object' ||
            Reflect.get(owner, 'identities') === null ||
            typeof Reflect.get(Reflect.get(owner, 'identities'), 'google') !== 'object' ||
            Reflect.get(Reflect.get(owner, 'identities'), 'google') === null ||
            Reflect.get(Reflect.get(Reflect.get(owner, 'identities'), 'google'), 'userId') !==
              input.googleSubject
          )
            return fail();
          registrationOwnerId = subject;
          return Object.freeze({ hasPassword: false as const });
        },
        assertControlsPreservedOwner: async () => {
          if (!registrationOwnerId) return fail();
          const owners = await controlAffectedUsers();
          const owner: unknown = owners[0];
          if (
            owners.length !== 1 ||
            typeof owner !== 'object' ||
            owner === null ||
            Reflect.get(owner, 'id') !== registrationOwnerId ||
            Reflect.get(owner, 'primaryEmail') !== input.originalEmail ||
            Reflect.get(owner, 'hasPassword') !== false ||
            Reflect.get(Reflect.get(owner, 'identities'), 'google') === undefined ||
            Reflect.get(Reflect.get(Reflect.get(owner, 'identities'), 'google'), 'userId') !==
              input.googleSubject
          )
            return fail();
        },
        assertChangedEmailProviderCase: async () => prepared.assertChangedEmailProviderCase(),
      });
      primaryStage = 'registration-owner-after';
      const after = await registrationOwners();
      const owner: unknown = after[0];
      if (
        after.length !== 1 ||
        typeof owner !== 'object' ||
        owner === null ||
        typeof Reflect.get(owner, 'id') !== 'string' ||
        Reflect.get(owner, 'primaryEmail') !== input.originalEmail ||
        Reflect.get(owner, 'hasPassword') !== false ||
        typeof Reflect.get(owner, 'identities') !== 'object' ||
        Reflect.get(owner, 'identities') === null ||
        typeof Reflect.get(Reflect.get(owner, 'identities'), 'google') !== 'object' ||
        Reflect.get(Reflect.get(owner, 'identities'), 'google') === null ||
        Reflect.get(Reflect.get(Reflect.get(owner, 'identities'), 'google'), 'userId') !==
          input.googleSubject
      )
        return fail();
      registrationOwnerId = Reflect.get(owner, 'id') as string;
      await prepared.assertPrimaryRegistrationProviderCase();
    } else
      result = await withSelectedGoogleExistingOwner({
        fixture: input.fixture,
        request: input.request,
        googleSubject: input.googleSubject,
        originalEmail: input.originalEmail,
        connectorId,
        connectorData: prepared.associationData,
        use: async (owner) => {
          await input.request({
            method: 'POST',
            path: `roles/${encodeURIComponent(activeRoleId)}/users`,
            body: { userIds: [owner.id] },
            expectedStatuses: [201],
            responseKind: 'created',
          });
          const roles = (await input.request({
            method: 'GET',
            path: `users/${encodeURIComponent(owner.id)}/roles`,
            expectedStatuses: [200],
            responseKind: 'array',
          })) as unknown[];
          if (
            !roles.some(
              (value) =>
                typeof value === 'object' &&
                value !== null &&
                Reflect.get(value, 'id') === activeRoleId
            )
          )
            return fail();
          return input.use({
            ownerId: owner.id,
            connectorId: activeConnectorId,
            capability: authorization.capability,
            observation: authorization.observation,
            unverifiedEmailCapability: unverifiedEmailAuthorization.capability,
            occupiedEmailCapability: occupiedEmailAuthorization.capability,
            unverifiedEmailObservation: unverifiedEmailAuthorization.observation,
            occupiedEmailObservation: occupiedEmailAuthorization.observation,
            assertRegisteredOwner: async () => fail(),
            assertControlsPreservedOwner: async () => fail(),
            assertChangedEmailProviderCase: async () => prepared.assertChangedEmailProviderCase(),
          });
        },
      });
  } catch (error: unknown) {
    const providerStage = googleProviderLeaseFailureStage(error);
    primaryStage = providerStage
      ? `prepare-connector-${providerStage}`
      : (ownerStage(error) ?? primaryStage);
    bodyFailed = true;
  } finally {
    if (preparedProvider) {
      try {
        await preparedProvider.stop();
      } catch {
        cleanupStages.push('stop-provider');
      }
    }
    if (previousClientMetadata !== undefined) {
      let restoredApp = false;
      try {
        const ack = (await input.request({
          method: 'PATCH',
          path: `applications/${encodeURIComponent(input.browser.clientId)}`,
          body: { oidcClientMetadata: previousClientMetadata },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as { oidcClientMetadata?: unknown };
        const read = (await input.request({
          method: 'GET',
          path: `applications/${encodeURIComponent(input.browser.clientId)}`,
          expectedStatuses: [200],
          responseKind: 'object',
        })) as { oidcClientMetadata?: unknown };
        restoredApp =
          isDeepStrictEqual(ack.oidcClientMetadata, previousClientMetadata) &&
          isDeepStrictEqual(read.oidcClientMetadata, previousClientMetadata);
      } catch {
        restoredApp = false;
      }
      if (!restoredApp) cleanupStages.push('restore-app');
    }
    if (input.ownerMode === 'registration' && !registrationOwnerId) {
      try {
        const owners = await registrationOwners();
        const owner: unknown = owners[0];
        if (
          owners.length === 1 &&
          typeof owner === 'object' &&
          owner !== null &&
          typeof Reflect.get(owner, 'id') === 'string'
        ) {
          registrationOwnerId = Reflect.get(owner, 'id') as string;
        }
      } catch {
        cleanupStages.push('registration-owner-discovery');
      }
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
    if (registrationOwnerId) {
      await input
        .request({
          method: 'DELETE',
          path: `users/${encodeURIComponent(registrationOwnerId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => cleanupStages.push('registration-owner-cleanup'));
    }
    if (
      previousTargets !== undefined &&
      previousBranding !== undefined &&
      previousSignInMode !== undefined &&
      previousSignUp !== undefined
    ) {
      let restored = false;
      try {
        const restoredAck = (await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: {
            branding: previousBranding,
            signUp: previousSignUp,
            socialSignInConnectorTargets: previousTargets,
          },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as {
          socialSignInConnectorTargets?: unknown;
          branding?: unknown;
          signInMode?: unknown;
          signUp?: unknown;
        };
        const restoredRead = (await input.request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        })) as {
          socialSignInConnectorTargets?: unknown;
          branding?: unknown;
          signInMode?: unknown;
          signUp?: unknown;
        };
        restored =
          isDeepStrictEqual(restoredAck.socialSignInConnectorTargets, previousTargets) &&
          isDeepStrictEqual(restoredRead.socialSignInConnectorTargets, previousTargets) &&
          isDeepStrictEqual(restoredAck.branding, previousBranding) &&
          isDeepStrictEqual(restoredRead.branding, previousBranding) &&
          restoredAck.signInMode === previousSignInMode &&
          restoredRead.signInMode === previousSignInMode &&
          isDeepStrictEqual(restoredAck.signUp, previousSignUp) &&
          isDeepStrictEqual(restoredRead.signUp, previousSignUp);
      } catch {
        restored = false;
      }
      if (!restored) cleanupStages.push('restore-sie');
    }
    if (connectorId) {
      await input
        .request({
          method: 'DELETE',
          path: `connectors/${encodeURIComponent(connectorId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(async (error: unknown) => {
          const status = responseStatus(error);
          await input.onDeleteConnectorFailure?.(status).catch(() => false);
          cleanupStages.push(status ? `delete-connector-status-${status}` : 'delete-connector');
        });
    }
  }
  if (cleanupStages.length > 0)
    throw new AggregateError(
      [
        ...cleanupStages.map(
          (stage) => new TypeError(`Selected Google connector fixture failed: ${stage}`)
        ),
        ...(bodyFailed
          ? [new TypeError(`Selected Google connector fixture failed: ${primaryStage}`)]
          : []),
      ],
      'Selected Google connector cleanup failed'
    );
  if (bodyFailed) throw new TypeError(`Selected Google connector fixture failed: ${primaryStage}`);
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unnecessary-condition */
