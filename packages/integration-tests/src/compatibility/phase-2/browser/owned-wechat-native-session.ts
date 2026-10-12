/* eslint-disable complexity, no-restricted-syntax, no-unsafe-finally, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal -- The selected Native application, connector, provider, identity and private proof share one compensated scope. */
import { randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import { createAccountPasswordProof } from '../clients/account-settings.js';
import {
  issuePublicNativeIdentitySession,
  type IssuedPublicUserSession,
} from '../clients/user-token-issuance.js';
import { createWechatNativeIdentityDriver } from '../clients/wechat-native-identity.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';
import {
  withSelectedNativeFixture,
  type Phase2FixturePublicWithSelectedNative,
} from '../selected-native-fixture.js';

const fail = (): never => {
  throw new TypeError('Invalid owned WeChat Native session');
};

export type OwnedWechatNativeProviderLease = Readonly<{
  associationData: Readonly<{ code: string }>;
  takeCode(): Promise<string>;
  stop(): Promise<void>;
}>;

export type OwnedWechatNativeSession = Readonly<{
  session: IssuedPublicUserSession;
  subject: string;
  clientId: string;
  issuer: string;
  withCurrentProof<Result>(use: (proofId: string) => Promise<Result>): Promise<Result>;
}>;

export const withOwnedWechatNativeSession = async <Result>(
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    managementRequest: Phase2AdminRequestFunction;
    providerClientId: string;
    providerClientSecret: string;
    universalLink: string;
    wechatSubject: string;
    expectedIssuer: string;
    namespace?: string;
    fetch?: typeof fetch;
    withNativeFixture?: typeof withSelectedNativeFixture;
    prepareProvider(connectorId: string): Promise<OwnedWechatNativeProviderLease>;
    configureApplication?<Value>(clientId: string, use: () => Promise<Value>): Promise<Value>;
  }>,
  use: (session: OwnedWechatNativeSession) => Promise<Result>
): Promise<Result> =>
  (input.withNativeFixture ?? withSelectedNativeFixture)(
    input.fixture,
    {
      request: input.managementRequest,
      target: input.target,
      namespace: input.namespace ?? 'owned-wechat-native',
    },
    async (
      fixture: ProvisionedPhase2Fixture & { public: Phase2FixturePublicWithSelectedNative }
    ) => {
      let connectorId: string | undefined;
      let provider: OwnedWechatNativeProviderLease | undefined;
      let primary: unknown;
      try {
        const connector = (await input.managementRequest({
          method: 'POST',
          path: 'connectors',
          body: {
            connectorId: 'wechat-native',
            config: {
              appId: input.providerClientId,
              appSecret: input.providerClientSecret,
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
        const owner = fixture.public.selectedNative.identity;
        const identities = (await input.managementRequest({
          method: 'POST',
          path: `users/${encodeURIComponent(owner.id)}/identities`,
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
        const runSession = async () => {
          const session = await issuePublicNativeIdentitySession(
            input.target,
            fixture,
            { identity: owner, withSecretLease: fixture.withSecretLease },
            {
              clientId: fixture.public.selectedNative.clientId,
              redirectUri: fixture.public.selectedNative.redirectUri,
              expectedIssuer: input.expectedIssuer,
              resourceIndicator: fixture.public.selectedNative.resource.indicator,
              resourceScope: 'session:exchange',
            },
            createWechatNativeIdentityDriver({
              connectorId: connectorId ?? fail(),
              redirectUri: fixture.public.selectedNative.redirectUri,
              state: randomBytes(24).toString('base64url'),
              appId: input.providerClientId,
              universalLink: input.universalLink,
              takeProviderCode: provider?.takeCode ?? fail,
            }),
            input.fetch,
            {
              scope: `openid offline_access profile ${input.target.label === 'oracle' ? 'urn:logto:scope:sessions' : 'urn:aster:scope:sessions'}`,
            }
          );
          return fixture.withSecretLease(async (secret) => {
            const password = secret.getSelectedNativePassword?.() ?? fail();
            return use(
              Object.freeze({
                session,
                subject: owner.id,
                clientId: fixture.public.selectedNative.clientId,
                issuer: input.expectedIssuer,
                withCurrentProof: async <Value>(operation: (proofId: string) => Promise<Value>) =>
                  createAccountPasswordProof(
                    { target: input.target, bearer: session.access, password },
                    async (proof) => operation(proof.getVerificationRecordId()),
                    input.fetch
                  ),
              })
            );
          });
        };
        return input.configureApplication
          ? await input.configureApplication(fixture.public.selectedNative.clientId, runSession)
          : await runSession();
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
            'Owned WeChat Native session cleanup failed'
          );
        }
      }
      throw primary ?? new TypeError('Owned WeChat Native session did not complete');
    }
  );
/* eslint-enable complexity, no-restricted-syntax, no-unsafe-finally, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-throw-literal */
