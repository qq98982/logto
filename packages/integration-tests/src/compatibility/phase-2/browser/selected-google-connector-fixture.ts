/* eslint-disable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Connector, SIE, owner association, and compensation form one bounded fixture lifecycle. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  createGoogleAuthorizationObserver,
  createGoogleAuthorizationWrongStateTestControl,
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
  assertChangedEmailProviderCase(mode?: 'positive' | 'replay'): Promise<void>;
  assertWrongStateProviderCase?(): Promise<void>;
  stop(): Promise<void>;
}>;

export const withSelectedGoogleConnectorFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    targetOrigin: string;
    browser: Readonly<{ clientId: string; redirectUri: string }>;
    clientId: string;
    clientSecret: string;
    googleSubject: string;
    originalEmail: string;
    authorizationMode?: 'normal' | 'wrong-state';
    prepareConnector(connectorId: string): Promise<SelectedGoogleProviderLease>;
    takeBrowserCode(): Promise<string>;
    takeWrongStateControlCode?(): Promise<string>;
    use(
      value: Readonly<{
        ownerId: string;
        connectorId: string;
        capability: ReturnType<typeof createGoogleAuthorizationObserver>['capability'];
        observation(): GoogleAuthorizationObservation;
        ownerSnapshot(): Promise<unknown>;
        assertChangedEmailProviderCase(mode?: 'positive' | 'replay'): Promise<void>;
        assertWrongStateProviderCase(): Promise<void>;
      }>
    ): Promise<Result>;
  }>
): Promise<Result> => {
  if (
    input.authorizationMode === 'wrong-state' &&
    typeof input.takeWrongStateControlCode !== 'function'
  ) {
    return fail();
  }
  let previousTargets: unknown;
  let previousBranding: unknown;
  let connectorId: string | undefined;
  let roleId: string | undefined;
  let previousClientMetadata: unknown;
  let preparedProvider: SelectedGoogleProviderLease | undefined;
  let result: Result | undefined;
  let bodyFailed = false;
  let primaryStage = 'read-sie';
  const cleanupStages: string[] = [];
  try {
    const sie = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { socialSignInConnectorTargets?: unknown; branding?: unknown };
    previousTargets = sie.socialSignInConnectorTargets;
    previousBranding = sie.branding;
    if (
      !Array.isArray(previousTargets) ||
      !previousTargets.every((value) => typeof value === 'string') ||
      typeof previousBranding !== 'object' ||
      previousBranding === null ||
      Array.isArray(previousBranding)
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
        isDefault: false,
        scopeIds: [scopeId],
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; type?: unknown; isDefault?: unknown };
    if (typeof role.id === 'string' && role.id.length > 0) roleId = role.id;
    if (!roleId || role.type !== 'User' || role.isDefault !== false) return fail();
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
      body: { branding: {}, socialSignInConnectorTargets: ['google'] },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { socialSignInConnectorTargets?: unknown; branding?: unknown };
    if (
      !isDeepStrictEqual(updated.socialSignInConnectorTargets, ['google']) ||
      !isDeepStrictEqual(updated.branding, {})
    )
      return fail();
    primaryStage = 'read-sie-updated';
    const readBack = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { socialSignInConnectorTargets?: unknown; branding?: unknown };
    if (
      !isDeepStrictEqual(readBack.socialSignInConnectorTargets, ['google']) ||
      !isDeepStrictEqual(readBack.branding, {})
    )
      return fail();
    const authorizationInput = {
      connectorId: activeConnectorId,
      clientId: input.clientId,
      targetOrigin: input.targetOrigin,
      takeCode:
        input.authorizationMode === 'wrong-state'
          ? (input.takeWrongStateControlCode ?? fail)
          : input.takeBrowserCode,
    };
    const authorization =
      input.authorizationMode === 'wrong-state'
        ? createGoogleAuthorizationWrongStateTestControl(authorizationInput)
        : createGoogleAuthorizationObserver(authorizationInput);
    primaryStage = 'existing-owner';
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
          ownerSnapshot: async () =>
            input.request({
              method: 'GET',
              path: `users/${encodeURIComponent(owner.id)}`,
              expectedStatuses: [200],
              responseKind: 'object',
            }),
          assertChangedEmailProviderCase: async (mode) =>
            prepared.assertChangedEmailProviderCase(mode),
          assertWrongStateProviderCase: async () =>
            prepared.assertWrongStateProviderCase?.() ?? fail(),
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
    if (previousTargets !== undefined && previousBranding !== undefined) {
      let restored = false;
      try {
        const restoredAck = (await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: {
            branding: previousBranding,
            socialSignInConnectorTargets: previousTargets,
          },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as { socialSignInConnectorTargets?: unknown; branding?: unknown };
        const restoredRead = (await input.request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        })) as { socialSignInConnectorTargets?: unknown; branding?: unknown };
        restored =
          isDeepStrictEqual(restoredAck.socialSignInConnectorTargets, previousTargets) &&
          isDeepStrictEqual(restoredRead.socialSignInConnectorTargets, previousTargets) &&
          isDeepStrictEqual(restoredAck.branding, previousBranding) &&
          isDeepStrictEqual(restoredRead.branding, previousBranding);
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
        .catch(() => cleanupStages.push('delete-connector'));
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
/* eslint-enable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
