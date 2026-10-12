/* eslint-disable complexity, no-restricted-syntax, no-unsafe-finally, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal -- Native application, connector, provider, identity, and callback share one compensated scope. */
import { createHash, randomBytes } from 'node:crypto';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { createCommonExperienceSession } from '../clients/common-experience.js';
import { stopPublicNativeSocialAtCallback } from '../clients/user-token-issuance.js';
import {
  createWechatNativeIdentityDriver,
  runWechatNativeProviderControls,
} from '../clients/wechat-native-identity.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';
import { withSelectedNativeFixture } from '../selected-native-fixture.js';

import { observeCommonNativeCodePkce } from './common-native.js';

export const commonWechatNativeScenarioIds = Object.freeze(['common.wechat.native'] as const);
const fail = (): never => {
  throw new TypeError('Invalid Common WeChat Native scenario');
};
const nativeAuthorizationPath = (clientId: string, redirectUri: string, resource: string) => {
  const verifier = randomBytes(32).toString('base64url');
  return `/oidc/auth?${new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    prompt: 'login consent',
    scope: 'openid offline_access profile session:exchange',
    resource,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: randomBytes(24).toString('base64url'),
    nonce: randomBytes(24).toString('base64url'),
  }).toString()}`;
};

export type WechatNativeProviderLease = Readonly<{
  associationData: Readonly<{ code: string }>;
  takeCode(): Promise<string>;
  takeControlCode(
    kind: 'noUnionId' | 'invalidCode' | 'replay' | 'malformedProvider'
  ): Promise<string>;
  observation(): Promise<
    Readonly<{
      authorizationExact: true;
      tokenExact: true;
      userinfoExact: true;
      unionIdStable: true;
    }>
  >;
  stop(): Promise<void>;
}>;

export const runCommonWechatNativeScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    managementRequest: Phase2AdminRequestFunction;
    jwks: Readonly<JSONWebKeySet>;
    clientId: string;
    clientSecret: string;
    universalLink: string;
    wechatSubject: string;
    fetch?: typeof fetch;
    withNativeFixture?: typeof withSelectedNativeFixture;
    prepareProvider(connectorId: string): Promise<WechatNativeProviderLease>;
  }>
) =>
  (input.withNativeFixture ?? withSelectedNativeFixture)(
    input.fixture,
    { request: input.managementRequest, target: input.target, namespace: 'wechat-native' },
    async (fixture) => {
      let connectorId: string | undefined;
      let provider: WechatNativeProviderLease | undefined;
      let primary: unknown;
      try {
        const connector = (await input.managementRequest({
          method: 'POST',
          path: 'connectors',
          body: {
            connectorId: 'wechat-native',
            config: {
              appId: input.clientId,
              appSecret: input.clientSecret,
              universalLinks: input.universalLink,
            },
          },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as { id?: unknown; connectorId?: unknown };
        if (typeof connector.id !== 'string' || connector.connectorId !== 'wechat-native') {
          return fail();
        }
        connectorId = connector.id;
        provider = await input.prepareProvider(connectorId);
        const ownerId = fixture.public.selectedNative.identity.id;
        const identities = (await input.managementRequest({
          method: 'POST',
          path: `users/${encodeURIComponent(ownerId)}/identities`,
          body: { connectorId, connectorData: provider.associationData },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as Record<string, unknown>;
        if (
          typeof identities.wechat !== 'object' ||
          identities.wechat === null ||
          Reflect.get(identities.wechat, 'userId') !== input.wechatSubject
        ) {
          return fail();
        }
        const state = randomBytes(24).toString('base64url');
        const projection = await observeCommonNativeCodePkce({
          target: input.target,
          fixture,
          jwks: input.jwks,
          ...(input.fetch && { requestFetch: input.fetch }),
          prepareCallback: async (target, selectedFixture, issuer, requestFetch) =>
            stopPublicNativeSocialAtCallback(
              target,
              selectedFixture,
              {
                identity: selectedFixture.public.selectedNative.identity,
                withSecretLease: selectedFixture.withSecretLease,
              },
              {
                clientId: selectedFixture.public.selectedNative.clientId,
                redirectUri: selectedFixture.public.selectedNative.redirectUri,
                expectedIssuer: issuer,
                resourceIndicator: selectedFixture.public.selectedNative.resource.indicator,
                resourceScope: 'session:exchange',
              },
              createWechatNativeIdentityDriver({
                connectorId: connectorId ?? fail(),
                redirectUri: selectedFixture.public.selectedNative.redirectUri,
                state,
                appId: input.clientId,
                universalLink: input.universalLink,
                takeProviderCode: provider?.takeCode ?? fail,
              }),
              requestFetch
            ),
        });
        const observed = await provider.observation();
        if (!Object.values(observed).every(Boolean)) {
          return fail();
        }
        const controls = await runWechatNativeProviderControls({
          connectorId,
          redirectUri: fixture.public.selectedNative.redirectUri,
          appId: input.clientId,
          universalLink: input.universalLink,
          createSession: () =>
            createCommonExperienceSession({
              target: input.target,
              clientId: fixture.public.selectedNative.clientId,
              ...(input.fetch && { fetch: input.fetch }),
            }),
          authorizationPath: () =>
            nativeAuthorizationPath(
              fixture.public.selectedNative.clientId,
              fixture.public.selectedNative.redirectUri,
              fixture.public.selectedNative.resource.indicator
            ),
          takeControlCode: provider.takeControlCode,
        });
        return Object.freeze({
          id: commonWechatNativeScenarioIds[0],
          projection: Object.freeze({ ...projection, provider: observed, ...controls }),
        });
      } catch (error: unknown) {
        primary = error;
      } finally {
        const cleanup: unknown[] = [];
        if (provider) {
          await provider.stop().catch((error: unknown) => cleanup.push(error));
        }
        if (connectorId) {
          await input
            .managementRequest({
              method: 'DELETE',
              path: `connectors/${encodeURIComponent(connectorId)}`,
              expectedStatuses: [204, 404],
              responseKind: 'status',
            })
            .catch((error: unknown) => cleanup.push(error));
        }
        if (cleanup.length > 0) {
          throw new AggregateError(
            [...(primary === undefined ? [] : [primary]), ...cleanup],
            'Common WeChat Native cleanup failed'
          );
        }
      }
      throw primary ?? new TypeError('Common WeChat Native scenario did not complete');
    }
  );
/* eslint-enable complexity, no-restricted-syntax, no-unsafe-finally, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal */
