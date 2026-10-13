import { createHash, randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import {
  withSelectedWechatConnectorFixture,
  type SelectedWechatProviderLease,
  type SelectedWechatSmsConfiguration,
} from '../browser/selected-wechat-connector-fixture.js';
import type { SmsProviderLease } from '../browser/sms-provider-lease.js';
import { createCommonExperienceSession } from '../clients/common-experience.js';
import {
  assertWechatMiniPhoneCollision,
  prepareWechatMiniPhoneCollision,
  runWechatMiniExistingOwner,
  runWechatMiniCrossInteractionControl,
  runWechatMiniPhoneRegistration,
  runWechatMiniProviderControl,
  runWechatMiniProviderReplay,
  type WechatMiniProviderControlKind,
} from '../clients/wechat-mini-phone-registration.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonWechatMiniScenarioIds = Object.freeze([
  'common.wechat.mini',
  'common.wechat.mini-phone-registration',
] as const);
const fail = (): never => {
  throw new TypeError('Invalid Common WeChat Mini scenario');
};
const callback = 'box-ai-wechat-mini://callback';
const authorizationPath = (
  input: Readonly<{ clientId: string; resource: string; scope: string }>
) => {
  const verifier = randomBytes(32).toString('base64url');
  const query = new URLSearchParams({
    client_id: input.clientId,
    redirect_uri: callback,
    response_type: 'code',
    prompt: 'login consent',
    scope: `openid offline_access profile ${input.scope}`,
    resource: input.resource,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: randomBytes(24).toString('base64url'),
    nonce: randomBytes(24).toString('base64url'),
  });
  return `/oidc/auth?${query.toString()}`;
};

type Input = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  managementRequest: Phase2AdminRequestFunction;
  clientId: string;
  clientSecret: string;
  wechatSubject: string;
  ownerEmail: string;
  phone: string;
  smsConfiguration: SelectedWechatSmsConfiguration;
  fetch?: typeof fetch;
  prepareProvider: (
    connectorId: string
  ) => Promise<SelectedWechatProviderLease & Readonly<{ takeCode(): Promise<string> }>>;
  smsLease: SmsProviderLease;
}>;

const run = async (input: Input, registration: boolean) => {
  const status = input.fixture.status ?? fail();
  const providerReceiptRecipe = registration ? 'registration' : 'existing';
  return withSelectedWechatConnectorFixture({
    fixture: input.fixture,
    request: input.managementRequest,
    targetOrigin: input.target.coreUrl,
    browser: { clientId: status.client.id, redirectUri: callback },
    clientId: input.clientId,
    clientSecret: input.clientSecret,
    channel: 'mini',
    wechatSubject: input.wechatSubject,
    ownerEmail: input.ownerEmail,
    ...(registration
      ? {
          ownerMode: 'registration' as const,
          registrationPhone: input.phone,
          smsConfiguration: input.smsConfiguration,
        }
      : { ownerMode: 'existing' as const }),
    prepareConnector: input.prepareProvider,
    use: async ({ connectorId, provider }) => {
      const session = createCommonExperienceSession({
        target: input.target,
        clientId: status.client.id,
        ...(input.fetch && { fetch: input.fetch }),
      });
      try {
        const common = {
          session,
          authorizationPath: authorizationPath({
            clientId: status.client.id,
            resource: status.resource.indicator,
            scope: status.resource.scopeName,
          }),
          connectorId,
          providerRedirectUri: 'box-ai-wechat-mini://authorize',
          providerState: randomBytes(24).toString('base64url'),
          providerCode: await (provider.takeCode?.() ??
            Promise.reject(new TypeError('Missing Mini provider code lease'))),
        };
        const positive = registration
          ? await runWechatMiniPhoneRegistration({
              ...common,
              phone: input.phone,
              armPhoneCode: async () => input.smsLease.arm(input.phone, 'Register'),
              getPhoneCode: async () => input.smsLease.takeCode(input.phone, 'Register'),
              targetOrigin: input.target.coreUrl,
              applicationClientId: status.client.id,
              callbackScheme: 'box-ai-wechat-mini:',
            })
          : await runWechatMiniExistingOwner(common);
        const collision = registration
          ? await (async () => {
              const owners = async () => {
                const users: unknown = await input.managementRequest({
                  method: 'GET',
                  path: 'users',
                  query: { page: '1', page_size: '100' },
                  expectedStatuses: [200],
                  responseKind: 'array',
                });
                if (!Array.isArray(users)) {
                  return fail();
                }
                if (users.length >= 100) {
                  return fail();
                }
                return users
                  .filter(
                    (user) =>
                      typeof user === 'object' &&
                      user !== null &&
                      Object.getOwnPropertyDescriptor(user, 'primaryPhone')?.value === input.phone
                  )
                  .map((user) => Object.getOwnPropertyDescriptors(user));
              };
              const before = await owners();
              if (before.length !== 1) {
                return fail();
              }
              const collisionSession = createCommonExperienceSession({
                target: input.target,
                clientId: status.client.id,
                ...(input.fetch && { fetch: input.fetch }),
              });
              try {
                const phoneVerificationId = await prepareWechatMiniPhoneCollision({
                  ...common,
                  session: collisionSession,
                  providerCode: await (provider.takeCollisionCode?.() ??
                    Promise.reject(new TypeError('Missing Mini collision provider code lease'))),
                  phone: input.phone,
                  armPhoneCode: async () => input.smsLease.arm(input.phone, 'Register'),
                  getPhoneCode: async () => input.smsLease.takeCode(input.phone, 'Register'),
                  authorizationPath: authorizationPath({
                    clientId: status.client.id,
                    resource: status.resource.indicator,
                    scope: status.resource.scopeName,
                  }),
                });
                return await assertWechatMiniPhoneCollision({
                  session: collisionSession,
                  phoneVerificationId,
                  ownerBefore: before,
                  foreignOwnerBefore: before,
                  readOwner: owners,
                  readForeignOwner: owners,
                });
              } finally {
                collisionSession.close();
              }
            })()
          : undefined;
        const control = async (kind: WechatMiniProviderControlKind) => {
          const controlSession = createCommonExperienceSession({
            target: input.target,
            clientId: status.client.id,
            ...(input.fetch && { fetch: input.fetch }),
          });
          try {
            return await runWechatMiniProviderControl({
              ...common,
              session: controlSession,
              kind,
              providerCode: await (provider.takeControlCode?.(kind) ??
                Promise.reject(new TypeError('Missing Mini provider control lease'))),
            });
          } finally {
            controlSession.close();
          }
        };
        const noUnionId = await control('noUnionId');
        const invalidCode = await control('invalidCode');
        const malformedProvider = await control('malformedProvider');
        const replayFirst = createCommonExperienceSession({
          target: input.target,
          clientId: status.client.id,
          ...(input.fetch && { fetch: input.fetch }),
        });
        const replaySecond = createCommonExperienceSession({
          target: input.target,
          clientId: status.client.id,
          ...(input.fetch && { fetch: input.fetch }),
        });
        const crossOwner = createCommonExperienceSession({
          target: input.target,
          clientId: status.client.id,
          ...(input.fetch && { fetch: input.fetch }),
        });
        const crossForeign = createCommonExperienceSession({
          target: input.target,
          clientId: status.client.id,
          ...(input.fetch && { fetch: input.fetch }),
        });
        const [replay, crossInteraction] = await (async () => {
          try {
            return await Promise.all([
              runWechatMiniProviderReplay({
                ...common,
                firstSession: replayFirst,
                replaySession: replaySecond,
                firstAuthorizationPath: authorizationPath({
                  clientId: status.client.id,
                  resource: status.resource.indicator,
                  scope: status.resource.scopeName,
                }),
                replayAuthorizationPath: authorizationPath({
                  clientId: status.client.id,
                  resource: status.resource.indicator,
                  scope: status.resource.scopeName,
                }),
                providerCode: await (provider.takeControlCode?.('replay') ??
                  Promise.reject(new TypeError('Missing Mini provider replay lease'))),
              }),
              runWechatMiniCrossInteractionControl({
                ...common,
                ownerSession: crossOwner,
                foreignSession: crossForeign,
                ownerAuthorizationPath: authorizationPath({
                  clientId: status.client.id,
                  resource: status.resource.indicator,
                  scope: status.resource.scopeName,
                }),
                foreignAuthorizationPath: authorizationPath({
                  clientId: status.client.id,
                  resource: status.resource.indicator,
                  scope: status.resource.scopeName,
                }),
                providerCode: 'ownership-is-checked-before-provider-code',
              }),
            ]);
          } finally {
            replayFirst.close();
            replaySecond.close();
            crossOwner.close();
            crossForeign.close();
          }
        })();
        const providerObservation = provider.observation(providerReceiptRecipe);
        return Object.freeze({
          id: registration ? commonWechatMiniScenarioIds[1] : commonWechatMiniScenarioIds[0],
          projection: Object.freeze({
            ...positive,
            ...(collision && { collision }),
            noUnionId,
            invalidCode,
            malformedProvider,
            replay,
            crossInteraction,
            provider: providerObservation,
          }),
        });
      } finally {
        session.close();
      }
    },
  });
};

export const runCommonWechatMiniScenarioRow = async (input: Input) => run(input, false);
export const runCommonWechatMiniPhoneRegistrationScenarioRow = async (input: Input) =>
  run(input, true);
