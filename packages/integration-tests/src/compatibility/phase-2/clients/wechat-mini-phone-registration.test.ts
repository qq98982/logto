/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function, max-params -- Scripted transport records the exact request sequence. */
import type { CommonExperienceSession } from './common-experience.js';
import {
  runWechatMiniCrossInteractionControl,
  runWechatMiniPhoneRegistration,
  runWechatMiniProviderControl,
  runWechatMiniProviderReplay,
} from './wechat-mini-phone-registration.js';

const registrationAuthorizationPath = '/oidc/auth?state=owned-state';
const validCallback =
  'box-ai-wechat-mini://callback?code=public&state=owned-state&iss=https%3A%2F%2Fcore.example%2Foidc';

test('completes Mini phone registration through consent and the bound callback', async () => {
  const statuses = [303, 204, 200, 200, 404, 204, 204, 200, 200, 204, 201, 200, 303, 200, 200, 303];
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
    14: { redirectTo: '/oidc/resume-after-consent' },
  };
  const session = {
    request: async (path: string, _method: string, body?: unknown) => {
      const current = index++;
      calls.push({ path, body });
      return {
        getStatus: () => statuses[current]!,
        getRecord: () => Object.freeze(records[current] ?? {}),
        getLocation: () =>
          current === 12
            ? 'https://core.example/consent?app_id=application-id'
            : current === 15
              ? validCallback
              : undefined,
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
      authorizationPath: registrationAuthorizationPath,
      connectorId: 'mini',
      providerRedirectUri: 'box-ai-wechat-mini://provider',
      providerState: 'state',
      providerCode: 'code',
      phone: '15555550123',
      targetOrigin: 'https://core.example/',
      applicationClientId: 'application-id',
      armPhoneCode: async () => {
        smsActions.push(`arm:${calls.length}`);
      },
      getPhoneCode: async () => '123456',
      callbackScheme: 'box-ai-wechat-mini:',
    })
  ).resolves.toEqual({
    calls: 16,
    registered: true,
    unionIdRequired: true,
    callbackScheme: 'box-ai-wechat-mini:',
  });
  expect(calls).toHaveLength(16);
  expect(smsActions).toEqual(['arm:7']);
  expect(calls[3]?.body).toEqual({ verificationId: 'social-id', connectorData: { code: 'code' } });
  expect(calls.map(({ path }) => path)).toEqual([
    '/oidc/auth?state=owned-state',
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
    '/api/interaction/consent',
    '/api/interaction/consent',
    '/oidc/resume-after-consent',
  ]);
  expect(calls[14]?.body).toEqual({});
});

test.each(['/oidc/auth', '/oidc/auth?state=one&state=two'])(
  'rejects an unbound Mini authorization path before transport: %s',
  async (authorizationPath) => {
    const session = {
      request: async () => {
        throw new TypeError('transport must not run');
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
        authorizationPath,
        connectorId: 'mini',
        providerRedirectUri: 'box-ai-wechat-mini://provider',
        providerState: 'state',
        providerCode: 'code',
        phone: '15555550123',
        targetOrigin: 'https://core.example/',
        applicationClientId: 'application-id',
        armPhoneCode: async () => {},
        getPhoneCode: async () => '123456',
        callbackScheme: 'box-ai-wechat-mini:',
      })
    ).rejects.toThrow('WeChat Mini phone registration failed: authorization-state');
  }
);

test.each([
  [
    'foreign consent',
    '/oidc/resume',
    'https://foreign.invalid/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    validCallback,
  ],
  [
    'relative consent',
    '/oidc/resume',
    '/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    validCallback,
  ],
  [
    'wrong consent application',
    '/oidc/resume',
    'https://core.example/consent?app_id=other',
    '/oidc/resume-after-consent',
    validCallback,
  ],
  [
    'extra consent query',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id&unexpected=true',
    '/oidc/resume-after-consent',
    validCallback,
  ],
  [
    'network-path submit continuation',
    '//common.invalid/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    validCallback,
  ],
  [
    'network-path consent continuation',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '//common.invalid/oidc/resume-after-consent',
    validCallback,
  ],
  [
    'wrong callback state',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    'box-ai-wechat-mini://callback?code=public&state=other&iss=https%3A%2F%2Fcore.example%2Foidc',
  ],
  [
    'wrong callback issuer',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    'box-ai-wechat-mini://callback?code=public&state=owned-state&iss=https%3A%2F%2Fforeign.example%2Foidc',
  ],
  [
    'callback port',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    'box-ai-wechat-mini://callback:444?code=public&state=owned-state&iss=https%3A%2F%2Fcore.example%2Foidc',
  ],
  [
    'extra callback query',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    `${validCallback}&extra=value`,
  ],
  [
    'unbounded callback code',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    `box-ai-wechat-mini://callback?code=${'x'.repeat(
      4097
    )}&state=owned-state&iss=https%3A%2F%2Fcore.example%2Foidc`,
  ],
  [
    'OAuth error',
    '/oidc/resume',
    'https://core.example/consent?app_id=application-id',
    '/oidc/resume-after-consent',
    'box-ai-wechat-mini://callback?error=access_denied&state=owned-state&iss=https%3A%2F%2Fcore.example%2Foidc',
  ],
] as const)(
  'rejects the %s redirect without completing Mini registration',
  async (_name, submitRedirectTo, consentLocation, consentRedirectTo, callbackLocation) => {
    const statuses = [
      303, 204, 200, 200, 404, 204, 204, 200, 200, 204, 201, 200, 303, 200, 200, 303,
    ];
    let index = 0;
    const session = {
      request: async () => {
        const current = index++;
        return {
          getStatus: () => statuses[current]!,
          getRecord: () =>
            current === 2
              ? { verificationId: 'social-id', authorizationUri: 'box-ai-wechat-mini://authorize' }
              : current === 4
                ? { code: 'user.identity_not_exist' }
                : current === 7
                  ? { verificationId: 'phone-id' }
                  : current === 11
                    ? { redirectTo: submitRedirectTo }
                    : current === 14
                      ? { redirectTo: consentRedirectTo }
                      : {},
          getLocation: () =>
            current === 12 ? consentLocation : current === 15 ? callbackLocation : undefined,
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
        authorizationPath: registrationAuthorizationPath,
        connectorId: 'mini',
        providerRedirectUri: 'box-ai-wechat-mini://provider',
        providerState: 'state',
        providerCode: 'code',
        phone: '15555550123',
        targetOrigin: 'https://core.example/',
        applicationClientId: 'application-id',
        armPhoneCode: async () => {},
        getPhoneCode: async () => '123456',
        callbackScheme: 'box-ai-wechat-mini:',
      })
    ).rejects.toThrow('WeChat Mini phone registration failed');
  }
);

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
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function, max-params */
