/* eslint-disable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Connector, SIE, owner association, and compensation form one bounded fixture lifecycle. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import type { WechatProviderObservation } from './common-wechat-web.js';
import { withSelectedWechatWebExistingOwner } from './selected-wechat-web-existing-owner-fixture.js';
import {
  createWechatWebAuthorizationObserver,
  type WechatWebAuthorizationObservation,
} from './wechat-web-authorization-observer.js';

const fail = (): never => {
  throw new TypeError('Invalid selected Wechat connector fixture');
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
const providerStages = new Set([
  'docker-environment',
  'admission',
  'configuration-file',
  'receipt-file',
  'container-admission',
  'configuration-write',
  'start',
  'health',
  'compensation',
  'stop-state',
  'stop-config-identity',
  'stop-receipt-identity',
  'unknown',
]);
const wechatProviderLeaseFailureStage = (error: unknown): string | undefined => {
  const message = ownMessage(error);
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'leaseStage') : undefined;
  const propertyStage: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  const stage =
    /^WeChat provider lease failed: ([a-z]+(?:-[a-z]+)*)$/u.exec(message ?? '')?.[1] ??
    (message === 'Invalid WechatBrowser provider lease' && typeof propertyStage === 'string'
      ? propertyStage
      : undefined);
  return stage && providerStages.has(stage) ? stage : undefined;
};
const ownerStage = (error: unknown, depth = 0): string | undefined => {
  if (depth >= 4) return undefined;
  const direct = /^Selected Wechat fixture failed: ([a-z]+(?:-[a-z]+)*)$/u.exec(
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

export const selectedWechatWebOwnerFixtureStageForTesting = (
  error: unknown
): string | undefined => {
  if (process.env.NODE_ENV !== 'test') return undefined;
  return ownerStage(error);
};

// English Experience source renders action.sign_in_with using the connector name.
export const wechatWebSignInButtonSelectorCandidate = 'role=button[name=/Continue with WeChat$/]';
export type SelectedWechatWebProviderLease = Readonly<{
  associationData: Readonly<Record<string, unknown>>;
  takeControlCode?(
    kind: 'noUnionId' | 'invalidCode' | 'replay' | 'malformedProvider'
  ): Promise<string>;
  observation(): WechatProviderObservation;
  stop(): Promise<void>;
}>;

export type SelectedWechatWebConnectorFixtureInput<Result> = Readonly<{
  fixture: ProvisionedPhase2Fixture;
  request: Phase2AdminRequestFunction;
  targetOrigin: string;
  browser: Readonly<{ clientId: string; redirectUri: string }>;
  clientId: string;
  clientSecret: string;
  channel: 'web';
  wechatSubject: string;
  ownerEmail?: string;
  callbackMode?: 'normal' | 'missing-state' | 'wrong-state' | 'wrong-callback';
  prepareConnector(connectorId: string): Promise<SelectedWechatWebProviderLease>;
  takeBrowserCode(): Promise<string>;
  use(
    value: Readonly<{
      ownerId?: string;
      connectorId: string;
      capability: ReturnType<typeof createWechatWebAuthorizationObserver>['capability'];
      observation(): WechatWebAuthorizationObservation;
      retryPath(): string | undefined;
      ownerSnapshot(): Promise<unknown>;
    }>
  ): Promise<Result>;
}>;

export const withSelectedWechatWebConnectorFixture = async <Result>(
  input: SelectedWechatWebConnectorFixtureInput<Result>
): Promise<Result> => {
  let previousTargets: unknown;
  let previousBranding: unknown;
  let previousSignInMode: unknown;
  let previousSignUp: unknown;
  let connectorId: string | undefined;
  let roleId: string | undefined;
  let previousClientMetadata: unknown;
  let preparedProvider: SelectedWechatWebProviderLease | undefined;
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
        name: `common-wechat-${input.fixture.public.allocationId}`,
        description: 'Common Wechat resource authority',
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
        connectorId: 'wechat-web',
        config: {
          appId: input.clientId,
          appSecret: input.clientSecret,
        },
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; connectorId?: unknown };
    if (typeof connector.id === 'string' && connector.id.length > 0) connectorId = connector.id;
    if (!connectorId || connector.connectorId !== 'wechat-web') return fail();
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
        socialSignInConnectorTargets: ['wechat'],
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
      !isDeepStrictEqual(updated.socialSignInConnectorTargets, ['wechat']) ||
      !isDeepStrictEqual(updated.branding, {}) ||
      updated.signInMode !== 'SignInAndRegister' ||
      !isDeepStrictEqual(updated.signUp, previousSignUp)
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
      !isDeepStrictEqual(readBack.socialSignInConnectorTargets, ['wechat']) ||
      !isDeepStrictEqual(readBack.branding, {}) ||
      readBack.signInMode !== 'SignInAndRegister' ||
      !isDeepStrictEqual(readBack.signUp, previousSignUp)
    )
      return fail();
    const authorization = createWechatWebAuthorizationObserver({
      connectorId: activeConnectorId,
      clientId: input.clientId,
      targetOrigin: input.targetOrigin,
      takeCode: input.takeBrowserCode,
      callbackMode: input.callbackMode,
    });
    primaryStage = 'existing-owner';
    result = await withSelectedWechatWebExistingOwner({
      fixture: input.fixture,
      request: input.request,
      wechatSubject: input.wechatSubject,
      originalEmail: input.ownerEmail ?? '',
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
          retryPath: authorization.retryPath,
          ownerSnapshot: async () =>
            input.request({
              method: 'GET',
              path: `users/${encodeURIComponent(owner.id)}`,
              expectedStatuses: [200],
              responseKind: 'object',
            }),
        });
      },
    });
  } catch (error: unknown) {
    const providerStage = wechatProviderLeaseFailureStage(error);
    primaryStage = providerStage
      ? `prepare-connector-${providerStage}`
      : (ownerStage(error) ?? primaryStage);
    bodyFailed = true;
  } finally {
    if (preparedProvider) {
      try {
        await preparedProvider.stop();
      } catch (error: unknown) {
        const stage = wechatProviderLeaseFailureStage(error);
        cleanupStages.push(
          stage?.startsWith('stop-') ? `stop-provider-${stage.slice(5)}` : 'stop-provider'
        );
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
    if (
      previousTargets !== undefined &&
      previousBranding !== undefined &&
      previousSignInMode !== undefined &&
      previousSignUp !== undefined
    ) {
      // The enclosing Phase2 fixture owns the full SIE snapshot.
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
          restoredRead.signInMode === previousSignInMode;
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
          (stage) => new TypeError(`Selected Wechat connector fixture failed: ${stage}`)
        ),
        ...(bodyFailed
          ? [new TypeError(`Selected Wechat connector fixture failed: ${primaryStage}`)]
          : []),
      ],
      'Selected Wechat connector cleanup failed'
    );
  if (bodyFailed) throw new TypeError(`Selected Wechat connector fixture failed: ${primaryStage}`);
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
