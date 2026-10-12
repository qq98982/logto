/* eslint-disable max-lines, max-params, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Provider, Management, public OIDC, and Account proof lifetimes form one target boundary. */
import { isDeepStrictEqual } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { observeAccountSocialMutation, withAccountSocialProof } from '../clients/account-social.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  issuePublicAccountTokensForSubject,
  issuePublicIdentitySession,
  type IssuedPublicUserSession,
} from '../clients/user-token-issuance.js';
import { createWebSocialIdentityDriver } from '../clients/web-social-identity.js';
import {
  createBearerPhase2AdminRequest,
  createScopedPhase2Fixture,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';
import type { CommonGoogleExistingOwnerFixtureRuntime } from '../scenarios/common-google-existing-owner.js';
import type {
  CommonAccountSocialProjection,
  CommonGoogleConfiguredCollisionProjection,
} from '../scenarios/common-social-account.js';
import { commonSocialAccountScenarioIds } from '../scenarios/common-social-account.js';
import type { CommonWechatWebFixtureRuntime } from '../scenarios/common-wechat-web.js';

import { runCommonAccountSocial } from './common-account-social.js';
import { runCommonGoogleConfiguredCollision } from './common-google-configured-collision.js';
import { prepareGoogleProviderLease } from './google-provider-lease.js';
import {
  type AccountSocialProviderLease,
  withSelectedAccountSocialConnector,
} from './selected-account-social-connector-fixture.js';

type SocialProviderLease = AccountSocialProviderLease;
type AccountId = 'common.account.google-link' | 'common.account.wechat-link';
type CommonSocialScenarioId = (typeof commonSocialAccountScenarioIds)[number];
type CommonSocialProjection =
  | CommonAccountSocialProjection
  | CommonGoogleConfiguredCollisionProjection;
type Runtime = CommonGoogleExistingOwnerFixtureRuntime | CommonWechatWebFixtureRuntime;

const fail = (): never => {
  throw new TypeError('Invalid Common social Account target composition');
};
const assertAccountProviderCase = async (lease: SocialProviderLease): Promise<void> => {
  await lease.assertAccountProviderCase();
};
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();

export const runIndependentSocialCleanup = async (
  first: () => Promise<void>,
  second: () => Promise<void>
): Promise<void> => {
  const failures: Error[] = [];
  try {
    await first();
  } catch {
    failures.push(new TypeError('Owned social cleanup failed (first)'));
  }
  try {
    await second();
  } catch {
    failures.push(new TypeError('Owned social cleanup failed (second)'));
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, 'Owned social cleanup failed');
  }
};
const runtimeFor = (fixture: ProvisionedPhase2Fixture, provider: 'google' | 'wechat'): Runtime => {
  const value: unknown = Reflect.get(
    fixture,
    provider === 'google' ? 'commonGoogleExistingOwner' : 'commonWechatWeb'
  );
  return typeof value === 'object' && value !== null ? (value as Runtime) : fail();
};
const discoverIssuer = async (
  target: TargetConfig,
  requestFetch: typeof fetch
): Promise<string> => {
  const response = await requestFetch(
    new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
    { redirect: 'manual', signal: AbortSignal.timeout(10_000) }
  );
  const value =
    response.status === 200 && !response.redirected ? record(await response.json()) : fail();
  const issuer = typeof value.issuer === 'string' ? new URL(value.issuer) : fail();
  const core = new URL(target.coreUrl);
  return issuer.origin === core.origin && issuer.pathname === '/oidc'
    ? issuer.href.replace(/\/$/u, '')
    : fail();
};
/** The collision owner is task-owned; supported user deletion releases its identity. */
export const withOwnedSocialCollisionUser = async <Result>(
  request: Phase2AdminRequestFunction,
  use: (userId: string) => Promise<Result>
): Promise<Result> => {
  const created = record(
    await request({
      method: 'POST',
      path: 'users',
      body: {},
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })
  );
  const userId = typeof created.id === 'string' && created.id.length > 0 ? created.id : fail();
  try {
    return await use(userId);
  } finally {
    await request({
      method: 'DELETE',
      path: `users/${encodeURIComponent(userId)}`,
      expectedStatuses: [204, 404],
      responseKind: 'status',
    });
  }
};
const associate = async (
  request: Phase2AdminRequestFunction,
  userId: string,
  connectorId: string,
  provider: 'google' | 'wechat',
  subject: string,
  connectorData: Readonly<Record<string, unknown>>
): Promise<void> => {
  const identities = record(
    await request({
      method: 'POST',
      path: `users/${encodeURIComponent(userId)}/identities`,
      body: { connectorId, connectorData },
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );
  const identity = record(identities[provider]);
  if (identity.userId !== subject) {
    fail();
  }
};

const runAccount = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    lease: Phase2FixtureSecretLease;
    provider: 'google' | 'wechat';
    runtime: Runtime;
    expectedIssuer: string;
    fetch: typeof fetch;
  }>
): Promise<CommonAccountSocialProjection> => {
  const status = input.fixture.status ?? fail();
  const password = input.lease.getSubjectPassword?.() ?? fail();
  const subject =
    input.provider === 'google'
      ? (input.runtime as CommonGoogleExistingOwnerFixtureRuntime).provider.googleSubject
      : (input.runtime as CommonWechatWebFixtureRuntime).provider.wechatSubject;
  return input.runtime.withProviderCredentialLease(async (credentials) => {
    const clientId = credentials.getClientId();
    const clientSecret = credentials.getClientSecret();
    const prepareProvider = async (connectorId: string): Promise<SocialProviderLease> => {
      if (input.provider === 'wechat') {
        return (input.runtime as CommonWechatWebFixtureRuntime).prepareProvider({
          connectorId,
          clientId,
          clientSecret,
          targetOrigin: input.target.coreUrl,
          role: input.target.label,
          subject,
        });
      }
      const { provider } = input.runtime as CommonGoogleExistingOwnerFixtureRuntime;
      return prepareGoogleProviderLease({
        ...provider,
        clientId,
        clientSecret,
        connectorId,
        targetOrigin: input.target.coreUrl,
        role: input.target.label,
        googleSubject: subject,
        originalEmail: provider.originalOwnerEmail,
        changedEmail: provider.changedProviderEmail,
      });
    };
    return withSelectedAccountSocialConnector({
      fixture: input.fixture,
      request: input.request,
      browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
      provider: input.provider,
      connectorConfig:
        input.provider === 'google'
          ? { clientId, clientSecret }
          : { appId: clientId, appSecret: clientSecret },
      getPassword: () => password,
      prepareProvider,
      use: async ({ owner, connectorId, redirectUri, provider }) => {
        const ownerTokens = await issuePublicAccountTokensForSubject(
          input.target,
          input.fixture,
          { email: owner.primaryEmail, password },
          input.fetch,
          { includeIdentities: true }
        );
        const foreignTokens = await issuePublicAccountTokensForSubject(
          input.target,
          input.fixture,
          { username: status.user.username, password },
          input.fetch,
          { includeIdentities: true }
        );
        let exact = false;
        return runCommonAccountSocial(
          input.target,
          {
            provider: input.provider,
            ownerId: owner.id,
            socialSubject: subject,
            ownerPassword: password,
            ownerTokens,
            foreignTokens,
            foreignPassword: password,
            withDestinationProof: async (use) =>
              withAccountSocialProof(
                {
                  target: input.target,
                  bearer: ownerTokens.access,
                  connectorId,
                  redirectUri,
                  takeProviderCode: async () => provider.takeAccountCode(),
                },
                use,
                input.fetch
              ),
            withForeignOwnedDestinationProof: async (use) =>
              withOwnedSocialCollisionUser(input.request, async (foreignOwnerId) => {
                await associate(
                  input.request,
                  foreignOwnerId,
                  connectorId,
                  input.provider,
                  subject,
                  provider.associationData
                );
                return withAccountSocialProof(
                  {
                    target: input.target,
                    bearer: ownerTokens.access,
                    connectorId,
                    redirectUri,
                    takeProviderCode: async () => provider.takeForeignAccountCode(),
                  },
                  use,
                  input.fetch
                );
              }),
            observeLastMethod: async () => {
              await assertAccountProviderCase(provider);
              await provider.stop();
              const lastProvider = await prepareProvider(connectorId);
              let userId: string | undefined;
              try {
                const created = record(
                  await input.request({
                    method: 'POST',
                    path: 'users',
                    body: {},
                    expectedStatuses: [200, 201],
                    responseKind: 'object',
                  })
                );
                userId = typeof created.id === 'string' ? created.id : fail();
                await associate(
                  input.request,
                  userId,
                  connectorId,
                  input.provider,
                  subject,
                  lastProvider.associationData
                );
                const session = await issuePublicIdentitySession(
                  input.target,
                  input.fixture,
                  createWebSocialIdentityDriver({
                    connectorId,
                    redirectUri,
                    provider: input.provider,
                    takeProviderCode: async () => lastProvider.takeAccountCode(),
                  }),
                  input.expectedIssuer,
                  input.fetch
                );
                const result = await withAccountSocialProof(
                  {
                    target: input.target,
                    bearer: session.access,
                    connectorId,
                    redirectUri,
                    takeProviderCode: async () => lastProvider.takeForeignAccountCode(),
                  },
                  async (proof) =>
                    observeAccountSocialMutation(
                      {
                        target: input.target,
                        bearer: session.access,
                        provider: input.provider,
                        operation: 'unlink',
                        permissionId: proof.getVerificationRecordId(),
                      },
                      input.fetch
                    ),
                  input.fetch
                );
                await assertAccountProviderCase(lastProvider);
                exact = true;
                return result;
              } finally {
                await runIndependentSocialCleanup(
                  async () => lastProvider.stop(),
                  async () => {
                    if (!userId) {
                      return;
                    }
                    await input.request({
                      method: 'DELETE',
                      path: `users/${encodeURIComponent(userId)}`,
                      expectedStatuses: [204, 404],
                      responseKind: 'status',
                    });
                  }
                );
              }
            },
            providerRequestExact: () => exact,
          },
          input.fetch
        );
      },
    });
  });
};

const runCollision = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    lease: Phase2FixtureSecretLease;
    runtime: CommonGoogleExistingOwnerFixtureRuntime;
    expectedIssuer: string;
    fetch: typeof fetch;
  }>
): Promise<CommonGoogleConfiguredCollisionProjection> => {
  const status = input.fixture.status ?? fail();
  const providerConfig = input.runtime.provider;
  return input.runtime.withProviderCredentialLease(async (credentials) => {
    const clientId = credentials.getClientId();
    const clientSecret = credentials.getClientSecret();
    return withSelectedAccountSocialConnector({
      fixture: input.fixture,
      request: input.request,
      browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
      provider: 'google',
      connectorConfig: { clientId, clientSecret },
      getPassword: () => input.lease.getSubjectPassword?.() ?? fail(),
      prepareProvider: async (connectorId) =>
        prepareGoogleProviderLease({
          ...providerConfig,
          clientId,
          clientSecret,
          connectorId,
          targetOrigin: input.target.coreUrl,
          role: input.target.label,
          googleSubject: providerConfig.googleSubject,
          originalEmail: providerConfig.originalOwnerEmail,
          changedEmail: providerConfig.changedProviderEmail,
        }),
      use: async ({ owner: collision, connectorId, redirectUri, provider }) => {
        const takeOccupiedEmailControlCode: unknown = Reflect.get(
          provider,
          'takeOccupiedEmailControlCode'
        );
        const assertConfiguredCollisionProviderCase: unknown = Reflect.get(
          provider,
          'assertConfiguredCollisionProviderCase'
        );
        if (
          typeof takeOccupiedEmailControlCode !== 'function' ||
          typeof assertConfiguredCollisionProviderCase !== 'function'
        ) {
          return fail();
        }
        let originalId: string | undefined;
        const previous = record(
          await input.request({
            method: 'GET',
            path: 'sign-in-exp',
            expectedStatuses: [200],
            responseKind: 'object',
          })
        );
        const previousSocial = record(previous.socialSignIn);
        try {
          const original = record(
            await input.request({
              method: 'POST',
              path: 'users',
              body: {},
              expectedStatuses: [200, 201],
              responseKind: 'object',
            })
          );
          originalId = typeof original.id === 'string' ? original.id : fail();
          await associate(
            input.request,
            originalId,
            connectorId,
            'google',
            providerConfig.googleSubject,
            provider.associationData
          );
          await input.request({
            method: 'PATCH',
            path: `users/${encodeURIComponent(collision.id)}`,
            body: { primaryEmail: providerConfig.originalOwnerEmail },
            expectedStatuses: [200],
            responseKind: 'object',
          });
          await input.request({
            method: 'PATCH',
            path: 'sign-in-exp',
            body: {
              socialSignIn: { ...previousSocial, automaticAccountLinking: true },
            },
            expectedStatuses: [200],
            responseKind: 'object',
          });
          let identificationStatus = 0;
          const runConfiguredSignIn = async () => {
            try {
              await issuePublicIdentitySession(
                input.target,
                input.fixture,
                createWebSocialIdentityDriver({
                  connectorId,
                  redirectUri,
                  provider: 'google',
                  takeProviderCode: async () =>
                    (takeOccupiedEmailControlCode as () => Promise<string>)(),
                  observeIdentification: (status) => {
                    identificationStatus = status;
                  },
                }),
                input.expectedIssuer,
                input.fetch
              );
            } catch {
              // The configured collision is expected to stop before an OIDC callback is issued.
            }
            await (assertConfiguredCollisionProviderCase as () => Promise<void>)();
            return Object.freeze({
              status: identificationStatus,
              providerRequestExact: true,
            });
          };
          const read = async (id: string) =>
            input.request({
              method: 'GET',
              path: `users/${encodeURIComponent(id)}`,
              expectedStatuses: [200],
              responseKind: 'object',
            });
          return await runCommonGoogleConfiguredCollision({
            ownerId: originalId,
            googleSubject: providerConfig.googleSubject,
            readOriginalOwner: async () => read(originalId ?? fail()),
            readCollidingUser: async () => read(collision.id),
            runConfiguredSignIn,
          });
        } finally {
          await runIndependentSocialCleanup(
            async () => {
              await input.request({
                method: 'PATCH',
                path: 'sign-in-exp',
                body: { socialSignIn: previousSocial },
                expectedStatuses: [200],
                responseKind: 'object',
              });
              const restored = record(
                await input.request({
                  method: 'GET',
                  path: 'sign-in-exp',
                  expectedStatuses: [200],
                  responseKind: 'object',
                })
              );
              if (!isDeepStrictEqual(restored.socialSignIn, previousSocial)) {
                fail();
              }
            },
            async () => {
              if (originalId) {
                await input.request({
                  method: 'DELETE',
                  path: `users/${encodeURIComponent(originalId)}`,
                  expectedStatuses: [204, 404],
                  responseKind: 'status',
                });
              }
            }
          );
        }
      },
    });
  });
};

export const withOwnedGoogleSession = async <Result>(
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    runtime: CommonGoogleExistingOwnerFixtureRuntime;
    expectedIssuer: string;
    scope?: string;
    fetch?: typeof fetch;
    withApplication?<T>(clientId: string, use: () => Promise<T>): Promise<T>;
    getPassword(): string;
    use(
      value: Readonly<{
        session: IssuedPublicUserSession;
        subject: string;
        clientId: string;
        issuer: string;
        withCurrentProof<T>(use: (proofId: string) => Promise<T>): Promise<T>;
      }>
    ): Promise<Result>;
  }>
): Promise<Result> => {
  const status = input.fixture.status ?? fail();
  const requestFetch = input.fetch ?? fetch;
  const providerConfig = input.runtime.provider;
  return input.runtime.withProviderCredentialLease(async (credentials) => {
    const clientId = credentials.getClientId();
    const clientSecret = credentials.getClientSecret();
    return withSelectedAccountSocialConnector({
      fixture: input.fixture,
      request: input.request,
      browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
      provider: 'google',
      connectorConfig: { clientId, clientSecret },
      getPassword: input.getPassword,
      prepareProvider: async (connectorId) =>
        prepareGoogleProviderLease({
          ...providerConfig,
          clientId,
          clientSecret,
          connectorId,
          targetOrigin: input.target.coreUrl,
          role: input.target.label,
          googleSubject: providerConfig.googleSubject,
          originalEmail: providerConfig.originalOwnerEmail,
          changedEmail: providerConfig.changedProviderEmail,
        }),
      use: async ({ connectorId, redirectUri, provider }) => {
        let userId: string | undefined;
        try {
          const created = record(
            await input.request({
              method: 'POST',
              path: 'users',
              body: {},
              expectedStatuses: [200, 201],
              responseKind: 'object',
            })
          );
          userId = typeof created.id === 'string' ? created.id : fail();
          await associate(
            input.request,
            userId,
            connectorId,
            'google',
            providerConfig.googleSubject,
            provider.associationData
          );
          const ownerId = userId;
          const runSession = async () => {
            const session = await issuePublicIdentitySession(
              input.target,
              input.fixture,
              createWebSocialIdentityDriver({
                connectorId,
                redirectUri,
                provider: 'google',
                takeProviderCode: async () => provider.takeAccountCode(),
              }),
              input.expectedIssuer,
              requestFetch,
              input.scope ? { scope: input.scope } : {}
            );
            const result = await input.use(
              Object.freeze({
                session,
                subject: ownerId,
                clientId: status.client.id,
                issuer: input.expectedIssuer,
                withCurrentProof: async <T>(use: (proofId: string) => Promise<T>) =>
                  withAccountSocialProof(
                    {
                      target: input.target,
                      bearer: session.access,
                      connectorId,
                      redirectUri,
                      takeProviderCode: async () => provider.takeForeignAccountCode(),
                    },
                    async (proof) => use(proof.getVerificationRecordId()),
                    requestFetch
                  ),
              })
            );
            await provider.assertAccountProviderCase();
            return result;
          };
          return input.withApplication
            ? await input.withApplication(status.client.id, runSession)
            : await runSession();
        } finally {
          if (userId) {
            await input.request({
              method: 'DELETE',
              path: `users/${encodeURIComponent(userId)}`,
              expectedStatuses: [204, 404],
              responseKind: 'status',
            });
          }
        }
      },
    });
  });
};

export const runCommonSocialAccountForTarget = async (
  input: Readonly<{
    id: CommonSocialScenarioId;
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer?: Phase1BrowserGroupObserver;
    signal: AbortSignal;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
  }>
): Promise<CommonSocialProjection> => {
  if (
    input.signal.aborted ||
    !input.fixture.status ||
    !Array.isArray(input.jwks.keys) ||
    !(commonSocialAccountScenarioIds as readonly string[]).includes(input.id)
  ) {
    fail();
  }
  const collision = input.id === 'common.google.configured-collision';
  const id = input.id as AccountId;
  const provider = collision || id === 'common.account.google-link' ? 'google' : 'wechat';
  const runtime = runtimeFor(input.fixture, provider);
  const requestFetch = input.fetch ?? fetch;
  const expectedIssuer = await discoverIssuer(input.target, requestFetch);
  const execute = async (request: Phase2AdminRequestFunction, lease: Phase2FixtureSecretLease) => {
    const scope = createScopedPhase2Fixture(input.fixture, lease);
    try {
      return await (collision
        ? runCollision({
            target: input.target,
            fixture: scope.fixture,
            request,
            lease,
            runtime: runtime as CommonGoogleExistingOwnerFixtureRuntime,
            expectedIssuer,
            fetch: requestFetch,
          })
        : runAccount({
            target: input.target,
            fixture: scope.fixture,
            request,
            lease,
            provider,
            runtime,
            expectedIssuer,
            fetch: requestFetch,
          }));
    } finally {
      scope.revoke();
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
/* eslint-enable max-lines, max-params, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
