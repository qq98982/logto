/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Three existing identity entries share one owned application and receiver boundary. */
import { isDeepStrictEqual } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { requestAccountEmailProof, verifyAccountEmailProof } from '../clients/account-settings.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import { createCommonExperienceSession } from '../clients/common-experience.js';
import { createEmailCodeIdentityDriver } from '../clients/email-code-identity.js';
import { issuePublicIdentitySession } from '../clients/user-token-issuance.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  createScopedPhase2Fixture,
  type Phase2AdminRequestFunction,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';
import type { CommonGoogleExistingOwnerFixtureRuntime } from '../scenarios/common-google-existing-owner.js';

import {
  runCommonSessionLogoutPreservation,
  type OwnedLogoutSession,
} from './common-session-logout-preservation.js';
import { withOwnedGoogleSession } from './common-social-account-target-driver.js';
import { withOwnedWechatNativeSession } from './owned-wechat-native-session.js';
import { withSelectedEmailCodeFixture } from './selected-email-code-fixture.js';

type Receiver = Readonly<{
  consume(): Promise<string | undefined>;
  deliveryStatus(): Promise<number>;
}>;
export type CommonSessionLogoutFixtureRuntime = Readonly<{
  google: CommonGoogleExistingOwnerFixtureRuntime;
  native: Pick<
    Parameters<typeof withOwnedWechatNativeSession>[0],
    | 'providerClientId'
    | 'providerClientSecret'
    | 'wechatSubject'
    | 'universalLink'
    | 'prepareProvider'
  >;
  withReceiver<Result>(
    delivery: 'accepted' | 'rejected',
    expectedNotification: boolean,
    use: (receiver: Receiver) => Promise<Result>
  ): Promise<Result>;
}>;
const fail = (): never => {
  throw new TypeError('Invalid Common logout target composition');
};
const object = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();

/** Restores the complete metadata object; this operation precedes session creation. */
export const withOwnedBackchannelApplication = async <Result>(
  request: Phase2AdminRequestFunction,
  clientId: string,
  use: () => Promise<Result>
): Promise<Result> => {
  const path = `applications/${encodeURIComponent(clientId)}`;
  const previous = object(
    object(
      await request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })
    ).oidcClientMetadata
  );
  const selected = {
    ...previous,
    backchannelLogoutUri: 'https://backchannel.aster.test:8443/backchannel-logout',
    backchannelLogoutSessionRequired: true,
  };
  try {
    await request({
      method: 'PATCH',
      path,
      body: { oidcClientMetadata: selected },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    const read = object(
      await request({ method: 'GET', path, expectedStatuses: [200], responseKind: 'object' })
    );
    if (!isDeepStrictEqual(read.oidcClientMetadata, selected)) {
      return fail();
    }
    return await use();
  } finally {
    await request({
      method: 'PATCH',
      path,
      body: { oidcClientMetadata: previous },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    const restored = object(
      await request({ method: 'GET', path, expectedStatuses: [200], responseKind: 'object' })
    );
    if (!isDeepStrictEqual(restored.oidcClientMetadata, previous)) {
      fail();
    }
  }
};

export const runCommonSessionLogoutForTarget = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    runtime: CommonSessionLogoutFixtureRuntime;
    jwks: Readonly<JSONWebKeySet>;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>
) => {
  const status = input.fixture.status ?? fail();
  if (input.signal.aborted) {
    return fail();
  }
  const requestFetch = input.fetch ?? fetch;
  const discovery = createCommonExperienceSession({
    target: input.target,
    clientId: status.client.id,
    fetch: requestFetch,
    signal: input.signal,
  });
  let issuer: string;
  try {
    const response = await discovery.request('/oidc/.well-known/openid-configuration', 'GET');
    const raw = response.getRecord().issuer;
    if (response.getStatus() !== 200 || typeof raw !== 'string') {
      return fail();
    }
    const parsed = new URL(raw);
    if (
      parsed.origin !== new URL(input.target.coreUrl).origin ||
      parsed.pathname !== '/oidc' ||
      parsed.search ||
      parsed.hash
    ) {
      return fail();
    }
    issuer = parsed.href.replace(/\/$/u, '');
  } finally {
    discovery.close();
  }
  const scope = `openid offline_access profile email ${input.target.label === 'oracle' ? 'urn:logto:scope:sessions' : 'urn:aster:scope:sessions'}`;
  const execute = async (request: Phase2AdminRequestFunction, lease: Phase2FixtureSecretLease) => {
    const delegated = createScopedPhase2Fixture(input.fixture, lease);
    const { fixture } = delegated;
    const nativeAttempt = { value: 0 };
    const configureApplication = async <Result>(clientId: string, use: () => Promise<Result>) =>
      withOwnedBackchannelApplication(request, clientId, use);
    try {
      return await runCommonSessionLogoutPreservation({
        target: input.target,
        jwks: input.jwks,
        fetch: requestFetch,
        runtime: {
          withAttempt: async ({ method, delivery, operation }, use) =>
            input.runtime.withReceiver(delivery, operation === 'rp', async (receiver) => {
              const observe = async (owner: OwnedLogoutSession) => use(owner, receiver);
              if (method === 'google') {
                return withOwnedGoogleSession({
                  target: input.target,
                  fixture,
                  request,
                  runtime: input.runtime.google,
                  expectedIssuer: issuer,
                  scope,
                  fetch: requestFetch,
                  getPassword: () => lease.getSubjectPassword?.() ?? fail(),
                  withApplication: configureApplication,
                  use: observe,
                });
              }
              if (method === 'wechat-native') {
                const namespace = `logout-wechat-native-${nativeAttempt.value++}`;
                return withOwnedWechatNativeSession(
                  {
                    target: input.target,
                    fixture,
                    managementRequest: request,
                    expectedIssuer: issuer,
                    fetch: requestFetch,
                    ...input.runtime.native,
                    namespace,
                    configureApplication,
                  },
                  observe
                );
              }
              return withSelectedEmailCodeFixture({
                fixture,
                request,
                browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
                use: async (identity) =>
                  configureApplication(status.client.id, async () => {
                    const takeCode = lease.takeVerificationCode ?? fail();
                    const session = await issuePublicIdentitySession(
                      input.target,
                      fixture,
                      createEmailCodeIdentityDriver({ email: identity.primaryEmail, takeCode }),
                      issuer,
                      requestFetch,
                      { scope }
                    );
                    return observe(
                      Object.freeze({
                        session,
                        subject: identity.id,
                        clientId: status.client.id,
                        issuer,
                        withCurrentProof: async <Result>(
                          useProof: (proofId: string) => Promise<Result>
                        ) => {
                          const inputProof = {
                            target: input.target,
                            bearer: session.access,
                            email: identity.primaryEmail,
                          };
                          const requested = await requestAccountEmailProof(
                            inputProof,
                            requestFetch
                          );
                          if (
                            requested.observation.status !== 201 ||
                            requested.observation.error !== 'none'
                          ) {
                            return fail();
                          }
                          const proofId = requested.lease.getVerificationRecordId();
                          const verified = await verifyAccountEmailProof(
                            {
                              ...inputProof,
                              code: await takeCode(identity.primaryEmail),
                              verificationRecordId: proofId,
                            },
                            requestFetch
                          );
                          if (verified.status !== 200 || verified.error !== 'none') {
                            return fail();
                          }
                          return useProof(proofId);
                        },
                      })
                    );
                  }),
              });
            }),
        },
      });
    } finally {
      delegated.revoke();
    }
  };
  return input.target.label === 'candidate'
    ? withPhase2AdminManagementBearer(
        input.target,
        input.fixture,
        async (bearer, lease) =>
          execute(createBearerPhase2AdminRequest(input.target, bearer, requestFetch), lease),
        { fetch: requestFetch }
      )
    : input.fixture.withSecretLease(async (lease) =>
        execute(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
      );
};
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
