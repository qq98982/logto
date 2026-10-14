/* eslint-disable max-lines -- Four channel projections share one exact public-wire contract and raw-provider translation. */
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { withPlaywrightExternalAuthorizationCapability } from '../../phase-1/browser/playwright-session.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  runCommonWechatH5RegistrationForTarget,
  type CommonWechatH5RegistrationTargetDriverInput,
} from '../browser/common-wechat-h5-target-driver.js';
import type { SelectedWechatSmsConfiguration } from '../browser/selected-wechat-connector-fixture.js';
import type { SmsProviderLease } from '../browser/sms-provider-lease.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  runCommonWechatMiniPhoneRegistrationScenarioRow,
  runCommonWechatMiniScenarioRow,
} from './common-wechat-mini.js';
import {
  runCommonWechatNativeScenarioRow,
  type WechatNativeProviderLease,
} from './common-wechat-native.js';

export const commonWechatFamilyScenarioIds = Object.freeze([
  'common.wechat.h5',
  'common.wechat.mini',
  'common.wechat.mini-phone-registration',
  'common.wechat.native',
] as const);
export type CommonWechatFamilyScenarioId = (typeof commonWechatFamilyScenarioIds)[number];
type H5Runtime = Pick<
  CommonWechatH5RegistrationTargetDriverInput,
  'provider' | 'withProviderCredentialLease' | 'prepareProvider'
>;
type MiniRuntime = Readonly<{
  managementRequest: Phase2AdminRequestFunction;
  clientId: string;
  clientSecret: string;
  wechatSubject: string;
  ownerEmail: string;
  phone: string;
  smsConfiguration: SelectedWechatSmsConfiguration;
  prepareProvider: Parameters<typeof runCommonWechatMiniScenarioRow>[0]['prepareProvider'];
  withSmsProviderLease: <Result>(
    use: (lease: SmsProviderLease) => Promise<Result>
  ) => Promise<Result>;
}>;
type NativeRuntime = Readonly<{
  managementRequest: Phase2AdminRequestFunction;
  clientId: string;
  clientSecret: string;
  universalLink: string;
  wechatSubject: string;
  prepareProvider(connectorId: string): Promise<WechatNativeProviderLease>;
}>;
export type CommonWechatFamilyRuntime = Readonly<{
  h5: H5Runtime;
  mini: MiniRuntime;
  native: NativeRuntime;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Common WeChat family scenario');
};
const closedRecord = (
  value: unknown,
  expected: Readonly<Record<string, unknown>>
): Readonly<Record<string, unknown>> => {
  const descriptors =
    typeof value === 'object' && value !== null && !Array.isArray(value)
      ? Object.getOwnPropertyDescriptors(value)
      : {};
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== Reflect.ownKeys(expected).length ||
    Object.entries(expected).some(([key, literal]) => {
      const descriptor = descriptors[key];
      const observed: unknown =
        descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable
          ? descriptor.value
          : fail();
      return literal === true ? observed !== true : literal !== undefined && observed !== literal;
    })
  ) {
    return fail();
  }
  return Object.freeze(
    Object.fromEntries(
      Object.keys(expected).map((key) => Object.freeze([key, descriptors[key]?.value]))
    )
  );
};
const providerProjection = (value: unknown) =>
  closedRecord(value, {
    setupRequests: 0,
    browserRequests: 1,
    providerRedirectExact: true,
    exchangeExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });
const rawProviderProjection = (value: unknown, setupRequests: 0 | 1 = 1) =>
  closedRecord(value, {
    setupRequests,
    browserRequests: 1,
    providerRedirectExact: true,
    exchangeExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });
const projectRawProviderProjection = (value: unknown, setupRequests: 0 | 1 = 1) => {
  const raw = closedRecord(value, {
    setupRequests,
    browserRequests: 1,
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });
  return Object.freeze({
    setupRequests: raw.setupRequests,
    browserRequests: raw.browserRequests,
    providerRedirectExact: raw.authorizationExact,
    exchangeExact: raw.tokenExact,
    userinfoExact: raw.userinfoExact,
    unionIdStable: raw.unionIdStable,
  });
};
const providerDenial = (
  value: unknown,
  status: 400 | 401,
  error:
    | 'connector.wechat_unionid_required'
    | 'connector.social_auth_code_invalid'
    | 'connector.invalid_response'
) => closedRecord(value, { status, error, accepted: false });
const projectWechatFamilyProjection = (
  id: CommonWechatFamilyScenarioId,
  value: unknown,
  rawProvider: boolean
): Readonly<Record<string, unknown>> => {
  if (id === 'common.wechat.h5') {
    const row = closedRecord(value, {
      channel: 'h5',
      newOwner: true,
      identityCreated: true,
      verifiedPhone: true,
      phoneOnlyFulfillment: true,
      callback: 'state-issuer-code-bound',
      pkce: 'S256',
      refreshRotated: true,
      provider: undefined,
    });
    return Object.freeze({ ...row, provider: providerProjection(row.provider) });
  }
  const positive =
    id === 'common.wechat.mini'
      ? { calls: 5, existingOwner: true, unionIdRequired: true }
      : id === 'common.wechat.mini-phone-registration'
        ? {
            calls: 16,
            registered: true,
            unionIdRequired: true,
            callbackScheme: 'box-ai-wechat-mini:',
            collision: undefined,
          }
        : {
            applicationType: 'Native',
            firstParty: true,
            pkce: 'S256',
            stateNonceDistinct: true,
            issuerBound: true,
            discoverySameOrigin: true,
            jwksSameOrigin: true,
            userinfoEndpoint: '/oidc/me',
            idTokenAlgorithm: 'ES384',
            expectedSubject: true,
            resourceToken: 'jwt',
            resourceScope: 'session:exchange',
            resourceTtlSeconds: 300,
            profileToken: 'opaque',
            profileSubject: true,
            resourceRefresh: 'jwt',
            resourceRefreshTtlSeconds: 300,
            targetOwnedCleanup: true,
          };
  const row = closedRecord(value, {
    ...positive,
    noUnionId: undefined,
    invalidCode: undefined,
    malformedProvider: undefined,
    replay: undefined,
    crossInteraction: undefined,
    provider: undefined,
  });
  const noUnionId = providerDenial(row.noUnionId, 400, 'connector.wechat_unionid_required');
  const invalidCode = providerDenial(row.invalidCode, 401, 'connector.social_auth_code_invalid');
  const malformedProvider = providerDenial(
    row.malformedProvider,
    400,
    'connector.invalid_response'
  );
  const collision =
    id === 'common.wechat.mini-phone-registration'
      ? closedRecord(row.collision, {
          status: 422,
          error: 'user.phone_already_in_use',
          partialOwnerCreated: false,
          ownersPreserved: true,
        })
      : undefined;
  const replay = closedRecord(row.replay, {
    firstStatus: 200,
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
  });
  const crossInteraction = closedRecord(row.crossInteraction, {
    status: 404,
    error: 'session.verification_session_not_found',
    accepted: false,
  });
  const provider =
    id === 'common.wechat.native'
      ? rawProvider
        ? (() => {
            const raw = closedRecord(row.provider, {
              authorizationExact: true,
              tokenExact: true,
              userinfoExact: true,
              unionIdStable: true,
            });
            return Object.freeze({
              providerRedirectExact: raw.authorizationExact,
              exchangeExact: raw.tokenExact,
              userinfoExact: raw.userinfoExact,
              unionIdStable: raw.unionIdStable,
            });
          })()
        : closedRecord(row.provider, {
            providerRedirectExact: true,
            exchangeExact: true,
            userinfoExact: true,
            unionIdStable: true,
          })
      : (rawProvider ? projectRawProviderProjection : rawProviderProjection)(
          row.provider,
          id === 'common.wechat.mini-phone-registration' ? 0 : 1
        );
  return Object.freeze({
    ...positive,
    ...(collision && { collision }),
    noUnionId,
    invalidCode,
    malformedProvider,
    replay,
    crossInteraction,
    provider,
  });
};
export const projectRawCommonWechatFamilyProjection = (
  id: Exclude<CommonWechatFamilyScenarioId, 'common.wechat.h5'>,
  value: unknown
): Readonly<Record<string, unknown>> => projectWechatFamilyProjection(id, value, true);
export const projectCommonWechatFamilyProjection = (
  id: CommonWechatFamilyScenarioId,
  value: unknown
): Readonly<Record<string, unknown>> => projectWechatFamilyProjection(id, value, false);
export const assertCommonWechatFamilyProjection = (
  id: CommonWechatFamilyScenarioId,
  value: unknown
): void => {
  projectCommonWechatFamilyProjection(id, value);
};
export const runCommonWechatFamilyScenarioRow = async (
  input: Readonly<{
    id: CommonWechatFamilyScenarioId;
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
    jwks: Readonly<JSONWebKeySet>;
    runtime: CommonWechatFamilyRuntime;
    fetch?: typeof fetch;
  }>
) => {
  if (!commonWechatFamilyScenarioIds.includes(input.id)) {
    return fail();
  }
  const status = input.fixture.status ?? fail();
  if (input.id === 'common.wechat.h5') {
    const projection = await runCommonWechatH5RegistrationForTarget({
      target: input.target,
      fixture: input.fixture,
      signal: input.signal,
      ...input.runtime.h5,
      ...(input.fetch && { fetch: input.fetch }),
      browser: {
        storageKey:
          input.target.label === 'oracle'
            ? asterNativeSurfaceContract.markers.demoConfigStorageKey.reference
            : asterNativeSurfaceContract.markers.demoConfigStorageKey.candidate,
        demo: {
          appId: status.client.id,
          prompt: 'consent',
          scope: `openid offline_access profile email phone ${status.resource.scopeName}`,
          resource: status.resource.indicator,
        },
        redirectUri: new URL('/demo-app', input.target.coreUrl).href,
        initialResponseScope: 'openid offline_access profile email phone',
        resourceScope: status.resource.scopeName,
      },
      createObserver: (capability) =>
        withPlaywrightExternalAuthorizationCapability(input.observer, capability),
    });
    return Object.freeze({
      id: input.id,
      projection: projectCommonWechatFamilyProjection(input.id, projection),
    });
  }
  const miniInput = {
    target: input.target,
    fixture: input.fixture,
    ...input.runtime.mini,
    ...(input.fetch && { fetch: input.fetch }),
  };
  if (input.id === 'common.wechat.mini') {
    const result = await input.runtime.mini.withSmsProviderLease(async (smsLease) =>
      runCommonWechatMiniScenarioRow({ ...miniInput, smsLease })
    );
    return Object.freeze({
      id: input.id,
      projection: projectRawCommonWechatFamilyProjection(input.id, result.projection),
    });
  }
  if (input.id === 'common.wechat.mini-phone-registration') {
    const result = await input.runtime.mini.withSmsProviderLease(async (smsLease) =>
      runCommonWechatMiniPhoneRegistrationScenarioRow({ ...miniInput, smsLease })
    );
    return Object.freeze({
      id: input.id,
      projection: projectRawCommonWechatFamilyProjection(input.id, result.projection),
    });
  }
  const result = await runCommonWechatNativeScenarioRow({
    target: input.target,
    fixture: input.fixture,
    jwks: input.jwks,
    ...input.runtime.native,
    ...(input.fetch && { fetch: input.fetch }),
  });
  return Object.freeze({
    id: input.id,
    projection: projectRawCommonWechatFamilyProjection(input.id, result.projection),
  });
};
/* eslint-enable max-lines */
