/* eslint-disable complexity, max-lines, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Connector, SIE, owner association, and compensation form one bounded fixture lifecycle. */
import { isDeepStrictEqual } from 'node:util';

import { registerPlaywrightExternalAuthorizationCapability } from '../../phase-1/browser/playwright-session.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import type { WechatProviderObservation } from './common-wechat-web-h5.js';
import { withSelectedWechatExistingOwner } from './selected-wechat-existing-owner-fixture.js';
import {
  createWechatAuthorizationObserver,
  type WechatAuthorizationObservation,
} from './wechat-authorization-observer.js';

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

export const selectedWechatOwnerFixtureStageForTesting = (error: unknown): string | undefined => {
  if (process.env.NODE_ENV !== 'test') return undefined;
  return ownerStage(error);
};

// English Experience source renders action.sign_in_with using the connector name.
export const wechatWebSignInButtonSelectorCandidate = 'role=button[name=/Continue with WeChat$/]';
export const wechatH5SignInButtonSelectorCandidate =
  'role=button[name=/Continue with WeChat Official Account$/]';

export type SelectedWechatProviderLease = Readonly<{
  associationData: Readonly<Record<string, unknown>>;
  takeCode?(): Promise<string>;
  takeControlCode?(
    kind: 'noUnionId' | 'invalidCode' | 'replay' | 'malformedProvider'
  ): Promise<string>;
  takeCollisionCode?(): Promise<string>;
  takePhoneCode?(recipient: string): Promise<string>;
  observation(): WechatProviderObservation;
  stop(): Promise<void>;
}>;

export type SelectedWechatSmsConfiguration = Readonly<{
  accessKeyId: string;
  accessKeySecret: string;
  signName: string;
  templates: Readonly<Record<'Register' | 'SignIn' | 'ForgotPassword' | 'Generic', string>>;
}>;

export type SelectedWechatConnectorFixtureInput<Result> = Readonly<{
  fixture: ProvisionedPhase2Fixture;
  request: Phase2AdminRequestFunction;
  targetOrigin: string;
  browser: Readonly<{ clientId: string; redirectUri: string }>;
  clientId: string;
  clientSecret: string;
  channel: 'web' | 'h5' | 'mini';
  wechatSubject: string;
  ownerEmail?: string;
  registrationPhone?: string;
  smsConfiguration?: SelectedWechatSmsConfiguration;
  ownerMode?: 'existing' | 'registration';
  prepareConnector(connectorId: string): Promise<SelectedWechatProviderLease>;
  takeBrowserCode?(): Promise<string>;
  use(
    value: Readonly<{
      ownerId?: string;
      connectorId: string;
      provider: SelectedWechatProviderLease;
      capability: ReturnType<typeof createWechatAuthorizationObserver>['capability'];
      observation(): WechatAuthorizationObservation;
      takePhoneCode?(recipient: string): Promise<string>;
    }>
  ): Promise<Result>;
}>;

export const withSelectedWechatConnectorFixture = async <Result>(
  input: SelectedWechatConnectorFixtureInput<Result>
): Promise<Result> => {
  let previousTargets: unknown;
  let previousBranding: unknown;
  let previousSignInMode: unknown;
  let previousSignUp: unknown;
  let connectorId: string | undefined;
  let smsConnectorId: string | undefined;
  let roleId: string | undefined;
  let previousClientMetadata: unknown;
  let preparedProvider: SelectedWechatProviderLease | undefined;
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
        Reflect.get(value, 'primaryPhone') === input.registrationPhone
    );
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
        name: `common-wechat-${input.fixture.public.allocationId}`,
        description: 'Common Wechat resource authority',
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
        connectorId: `wechat-${input.channel}`,
        config: {
          appId: input.clientId,
          appSecret: input.clientSecret,
        },
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as { id?: unknown; connectorId?: unknown };
    if (typeof connector.id === 'string' && connector.id.length > 0) connectorId = connector.id;
    if (!connectorId || connector.connectorId !== `wechat-${input.channel}`) return fail();
    const activeConnectorId = connectorId;
    if (input.ownerMode === 'registration') {
      primaryStage = 'create-sms-connector';
      const smsConfiguration = input.smsConfiguration ?? fail();
      const sms = (await input.request({
        method: 'POST',
        path: 'connectors',
        body: {
          connectorId: 'aliyun-short-message-service',
          config: {
            accessKeyId: smsConfiguration.accessKeyId,
            accessKeySecret: smsConfiguration.accessKeySecret,
            signName: smsConfiguration.signName,
            templates: [
              { usageType: 'Register', templateCode: smsConfiguration.templates.Register },
              { usageType: 'SignIn', templateCode: smsConfiguration.templates.SignIn },
              {
                usageType: 'ForgotPassword',
                templateCode: smsConfiguration.templates.ForgotPassword,
              },
              { usageType: 'Generic', templateCode: smsConfiguration.templates.Generic },
            ],
          },
        },
        expectedStatuses: [200],
        responseKind: 'object',
      })) as { id?: unknown; connectorId?: unknown };
      if (typeof sms.id === 'string' && sms.id.length > 0) smsConnectorId = sms.id;
      if (!smsConnectorId || sms.connectorId !== 'aliyun-short-message-service') return fail();
    }
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
          signUp: { identifiers: ['phone'], password: false, verify: true },
        }),
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
      !isDeepStrictEqual(
        updated.signUp,
        input.ownerMode === 'registration'
          ? { identifiers: ['phone'], password: false, verify: true }
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
      !isDeepStrictEqual(readBack.socialSignInConnectorTargets, ['wechat']) ||
      !isDeepStrictEqual(readBack.branding, {}) ||
      readBack.signInMode !== 'SignInAndRegister' ||
      !isDeepStrictEqual(
        readBack.signUp,
        input.ownerMode === 'registration'
          ? { identifiers: ['phone'], password: false, verify: true }
          : previousSignUp
      )
    )
      return fail();
    const authorization =
      input.channel === 'mini'
        ? Object.freeze({
            capability: registerPlaywrightExternalAuthorizationCapability(async () => false),
            observation: () =>
              Object.freeze({
                requestCount: 0,
                queryShapeExact: false,
                clientMatched: false,
                callbackMatched: false,
                responseTypeCode: false,
                scopeExact: false,
                stateFormatValid: false,
                stateRoundTrip: false,
                fulfilledOnce: false,
              }),
          })
        : createWechatAuthorizationObserver({
            connectorId: activeConnectorId,
            clientId: input.clientId,
            channel: input.channel,
            targetOrigin: input.targetOrigin,
            takeCode: input.takeBrowserCode ?? fail,
          });
    primaryStage =
      input.ownerMode === 'registration' ? 'registration-owner-before' : 'existing-owner';
    if (input.ownerMode === 'registration') {
      const before = await registrationOwners();
      if (before.length > 0) return fail();
      primaryStage = 'registration-owner-use';
      result = await input.use({
        connectorId: activeConnectorId,
        provider: prepared,
        capability: authorization.capability,
        observation: authorization.observation,
        takePhoneCode: prepared.takePhoneCode,
      });
      primaryStage = 'registration-owner-after';
      const after = await registrationOwners();
      const owner: unknown = after[0];
      if (
        after.length !== 1 ||
        typeof owner !== 'object' ||
        owner === null ||
        typeof Reflect.get(owner, 'id') !== 'string' ||
        Reflect.get(owner, 'primaryPhone') !== input.registrationPhone ||
        Reflect.get(owner, 'hasPassword') !== false ||
        typeof Reflect.get(owner, 'identities') !== 'object' ||
        Reflect.get(owner, 'identities') === null ||
        typeof Reflect.get(Reflect.get(owner, 'identities'), 'wechat') !== 'object' ||
        Reflect.get(Reflect.get(owner, 'identities'), 'wechat') === null ||
        Reflect.get(Reflect.get(Reflect.get(owner, 'identities'), 'wechat'), 'userId') !==
          input.wechatSubject
      )
        return fail();
      registrationOwnerId = Reflect.get(owner, 'id') as string;
    } else
      result = await withSelectedWechatExistingOwner({
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
            provider: prepared,
            capability: authorization.capability,
            observation: authorization.observation,
            takePhoneCode: prepared.takePhoneCode,
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
      // The enclosing Phase2 fixture owns the full SIE snapshot, including registration signUp.
      // This inner fixture restores only its branding and social-target edits.
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
        .catch(() => {
          cleanupStages.push('delete-connector');
        });
    }
    if (smsConnectorId) {
      await input
        .request({
          method: 'DELETE',
          path: `connectors/${encodeURIComponent(smsConnectorId)}`,
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
