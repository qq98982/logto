import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { withPlaywrightExternalAuthorizationCapability } from '../../phase-1/browser/playwright-session.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  runCommonWechatH5RegistrationForTarget,
  type CommonWechatH5RegistrationTargetDriverInput,
} from '../browser/common-wechat-h5-target-driver.js';
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
  smsAccessSecret: string;
  prepareProvider: Parameters<typeof runCommonWechatMiniScenarioRow>[0]['prepareProvider'];
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
const rawProviderProjection = (value: unknown) =>
  closedRecord(value, {
    setupRequests: 1,
    browserRequests: 1,
    authorizationExact: true,
    tokenExact: true,
    userinfoExact: true,
    unionIdStable: true,
  });
const providerDenial = (
  value: unknown,
  status: 400 | 401,
  error:
    | 'connector.wechat_unionid_required'
    | 'connector.social_auth_code_invalid'
    | 'connector.invalid_response'
) => closedRecord(value, { status, error, accepted: false });
export const assertCommonWechatFamilyProjection = (
  id: CommonWechatFamilyScenarioId,
  value: unknown
): void => {
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
    providerProjection(row.provider);
    return;
  }
  const positive =
    id === 'common.wechat.mini'
      ? { calls: 5, existingOwner: true, unionIdRequired: true }
      : id === 'common.wechat.mini-phone-registration'
        ? {
            calls: 13,
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
  providerDenial(row.noUnionId, 400, 'connector.wechat_unionid_required');
  providerDenial(row.invalidCode, 401, 'connector.social_auth_code_invalid');
  providerDenial(row.malformedProvider, 400, 'connector.invalid_response');
  if (id === 'common.wechat.mini-phone-registration') {
    closedRecord(row.collision, {
      status: 422,
      error: 'user.phone_already_in_use',
      partialOwnerCreated: false,
      ownersPreserved: true,
    });
  }
  closedRecord(row.replay, {
    firstStatus: 200,
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
  });
  closedRecord(row.crossInteraction, {
    status: 404,
    error: 'session.verification_session_not_found',
    accepted: false,
  });
  if (id === 'common.wechat.native') {
    closedRecord(row.provider, {
      authorizationExact: true,
      tokenExact: true,
      userinfoExact: true,
      unionIdStable: true,
    });
  } else {
    rawProviderProjection(row.provider);
  }
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
    assertCommonWechatFamilyProjection(input.id, projection);
    return Object.freeze({ id: input.id, projection });
  }
  const miniInput = {
    target: input.target,
    fixture: input.fixture,
    ...input.runtime.mini,
    ...(input.fetch && { fetch: input.fetch }),
  };
  if (input.id === 'common.wechat.mini') {
    const result = await runCommonWechatMiniScenarioRow(miniInput);
    assertCommonWechatFamilyProjection(input.id, result.projection);
    return result;
  }
  if (input.id === 'common.wechat.mini-phone-registration') {
    const result = await runCommonWechatMiniPhoneRegistrationScenarioRow(miniInput);
    assertCommonWechatFamilyProjection(input.id, result.projection);
    return result;
  }
  const result = await runCommonWechatNativeScenarioRow({
    target: input.target,
    fixture: input.fixture,
    jwks: input.jwks,
    ...input.runtime.native,
    ...(input.fetch && { fetch: input.fetch }),
  });
  assertCommonWechatFamilyProjection(input.id, result.projection);
  return result;
};
