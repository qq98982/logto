/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Scripted transport records the exact 13-call sequence. */
import type { CommonExperienceSession } from './common-experience.js';
import {
  runWechatMiniCrossInteractionControl,
  runWechatMiniPhoneRegistration,
  runWechatMiniProviderControl,
  runWechatMiniProviderReplay,
} from './wechat-mini-phone-registration.js';

test('executes the observed 13-call Mini phone registration contract', async () => {
  const statuses = [303, 204, 200, 200, 404, 204, 204, 200, 200, 204, 201, 200, 303];
  const calls: Array<{ path: string; body: unknown }> = [];
  const smsActions: string[] = [];
  let index = 0;
  const records: Record<number, Record<string, unknown>> = {
    2: {
      verificationId: 'social-id',
      authorizationUri: 'box-ai-wechat-mini://authorize',
    },
    4: { code: 'user.identity_not_exist' },
    7: { verificationId: 'phone-id' },
    11: { redirectTo: '/oidc/resume' },
  };
  const session = {
    request: async (path: string, _method: string, body?: unknown) => {
      const current = index++;
      calls.push({ path, body });
      return {
        getStatus: () => statuses[current]!,
        getRecord: () => Object.freeze(records[current] ?? {}),
        getLocation: () =>
          current === 12 ? 'box-ai-wechat-mini://callback?code=public' : undefined,
        toJSON: () => {
          throw new TypeError('redacted');
        },
      };
    },
    getCookieHeader: async () => '',
    close: () => {},
    toJSON: () => {
      throw new TypeError('redacted');
    },
  } as CommonExperienceSession;
  await expect(
    runWechatMiniPhoneRegistration({
      session,
      authorizationPath: '/oidc/auth',
      connectorId: 'mini',
      providerRedirectUri: 'box-ai-wechat-mini://provider',
      providerState: 'state',
      providerCode: 'code',
      phone: '15555550123',
      armPhoneCode: async () => {
        smsActions.push(`arm:${calls.length}`);
      },
      getPhoneCode: async () => '123456',
      callbackScheme: 'box-ai-wechat-mini:',
    })
  ).resolves.toEqual({
    calls: 13,
    registered: true,
    unionIdRequired: true,
    callbackScheme: 'box-ai-wechat-mini:',
  });
  expect(calls).toHaveLength(13);
  expect(smsActions).toEqual(['arm:7']);
  expect(calls[3]?.body).toEqual({ verificationId: 'social-id', connectorData: { code: 'code' } });
  expect(calls.map(({ path }) => path)).toEqual([
    '/oidc/auth',
    '/api/experience',
    '/api/experience/verification/social/mini/authorization-uri',
    '/api/experience/verification/social/mini/verify',
    '/api/experience/identification',
    '/api/experience/interaction-event',
    '/api/experience/profile',
    '/api/experience/verification/verification-code',
    '/api/experience/verification/verification-code/verify',
    '/api/experience/profile',
    '/api/experience/identification',
    '/api/experience/submit',
    '/oidc/resume',
  ]);
});

test.each([
  ['noUnionId', 400, 'connector.wechat_unionid_required'],
  ['invalidCode', 401, 'connector.social_auth_code_invalid'],
  ['malformedProvider', 400, 'connector.invalid_response'],
] as const)('publishes the exact Mini %s denial', async (kind, deniedStatus, error) => {
  const statuses = [303, 204, 200, deniedStatus];
  let index = 0;
  const session = {
    request: async () => {
      const current = index++;
      return {
        getStatus: () => statuses[current]!,
        getRecord: () =>
          current === 2
            ? {
                verificationId: 'social-id',
                authorizationUri: 'box-ai-wechat-mini://authorize',
              }
            : current === 3
              ? { code: error }
              : {},
        getLocation: () => {},
        toJSON: () => {
          throw new TypeError('redacted');
        },
      };
    },
    getCookieHeader: async () => '',
    close: () => {},
    toJSON: () => {
      throw new TypeError('redacted');
    },
  } as CommonExperienceSession;
  await expect(
    runWechatMiniProviderControl({
      session,
      authorizationPath: '/oidc/auth',
      connectorId: 'mini',
      providerRedirectUri: 'box-ai-wechat-mini://authorize',
      providerState: 'state',
      providerCode: 'control-code',
      kind,
    })
  ).resolves.toEqual({ status: deniedStatus, error, accepted: false });
});

const scriptedSession = (
  statuses: readonly number[],
  records: ReadonlyArray<Record<string, unknown>>
) => {
  let index = 0;
  return {
    request: async () => {
      const current = index++;
      return {
        getStatus: () => statuses[current]!,
        getRecord: () => records[current] ?? {},
        getLocation: () => {},
        toJSON: () => {
          throw new TypeError('redacted');
        },
      };
    },
    getCookieHeader: async () => '',
    close: () => {},
    toJSON: () => {
      throw new TypeError('redacted');
    },
  } as CommonExperienceSession;
};

test('proves Mini provider replay only after the same code succeeds once', async () => {
  const authorization = {
    verificationId: 'verification',
    authorizationUri: 'box-ai-wechat-mini://authorize',
  };
  await expect(
    runWechatMiniProviderReplay({
      firstSession: scriptedSession([303, 204, 200, 200], [{}, {}, authorization, {}]),
      replaySession: scriptedSession(
        [303, 204, 200, 401],
        [{}, {}, authorization, { code: 'connector.social_auth_code_invalid' }]
      ),
      firstAuthorizationPath: '/oidc/first',
      replayAuthorizationPath: '/oidc/replay',
      connectorId: 'mini',
      providerRedirectUri: 'box-ai-wechat-mini://authorize',
      providerState: 'state',
      providerCode: 'same-code',
    })
  ).resolves.toEqual({
    firstStatus: 200,
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
  });
});

test('rejects a Mini verification proof owned by another interaction', async () => {
  const authorization = {
    verificationId: 'owner-proof',
    authorizationUri: 'box-ai-wechat-mini://authorize',
  };
  await expect(
    runWechatMiniCrossInteractionControl({
      ownerSession: scriptedSession([303, 204, 200], [{}, {}, authorization]),
      foreignSession: scriptedSession(
        [303, 204, 200, 404],
        [
          {},
          {},
          { ...authorization, verificationId: 'foreign-proof' },
          {
            code: 'session.verification_session_not_found',
          },
        ]
      ),
      ownerAuthorizationPath: '/oidc/owner',
      foreignAuthorizationPath: '/oidc/foreign',
      connectorId: 'mini',
      providerRedirectUri: 'box-ai-wechat-mini://authorize',
      providerState: 'state',
      providerCode: 'unused',
    })
  ).resolves.toEqual({
    status: 404,
    error: 'session.verification_session_not_found',
    accepted: false,
  });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
