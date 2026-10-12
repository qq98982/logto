/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function, @typescript-eslint/no-unsafe-assignment -- Scripted transports record request order. */
import type { CommonExperienceSession } from './common-experience.js';
import {
  createWechatNativeIdentityDriver,
  runWechatNativeProviderControls,
} from './wechat-native-identity.js';

const response = (status: number, body?: unknown) =>
  new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: body === undefined ? undefined : { 'content-type': 'application/json' },
  });

test('identifies an existing WeChat Native owner with provider state and code-only callback data', async () => {
  const calls: Array<{ path: string; body: unknown }> = [];
  const replies = [
    response(204),
    response(200, {
      verificationId: 'social-id',
      authorizationUri:
        'wechat:?app_id=provider-app&state=owned-state&universal_link=https%3A%2F%2Fapp.example%2Fwechat%2F',
    }),
    response(200, { verificationId: 'social-id' }),
    response(204),
  ];
  const driver = createWechatNativeIdentityDriver({
    connectorId: 'native-instance',
    redirectUri: 'https://app.example/callback',
    state: 'owned-state',
    appId: 'provider-app',
    universalLink: 'https://app.example/wechat/',
    takeProviderCode: async () => 'provider-code',
  });
  await driver({
    request: async (path, _method, body) => {
      calls.push({ path, body });
      return replies[calls.length - 1]!;
    },
  });
  expect(calls[2]?.body).toEqual({
    verificationId: 'social-id',
    connectorData: { code: 'provider-code' },
  });
  expect(calls.map(({ path }) => path)).toEqual([
    '/api/experience',
    '/api/experience/verification/social/native-instance/authorization-uri',
    '/api/experience/verification/social/native-instance/verify',
    '/api/experience/identification',
  ]);
});
test('rejects a mismatched provider state before consuming the provider code', async () => {
  let codeReads = 0;
  const driver = createWechatNativeIdentityDriver({
    connectorId: 'native-instance',
    redirectUri: 'https://app.example/callback',
    state: 'owned-state',
    appId: 'provider-app',
    universalLink: 'https://app.example/wechat/',
    takeProviderCode: async () => {
      codeReads += 1;
      return 'provider-code';
    },
  });
  const replies = [
    response(204),
    response(200, {
      verificationId: 'social-id',
      authorizationUri:
        'wechat:?app_id=provider-app&state=wrong&universal_link=https%3A%2F%2Fapp.example%2Fwechat%2F',
    }),
  ];
  let index = 0;
  await expect(driver({ request: async () => replies[index++]! })).rejects.toThrow(
    'Invalid Common WeChat Native identity flow'
  );
  expect(codeReads).toBe(0);
});

test('rejects the unobserved weixin scheme before consuming the provider code', async () => {
  let codeReads = 0;
  const driver = createWechatNativeIdentityDriver({
    connectorId: 'native-instance',
    redirectUri: 'https://app.example/callback',
    state: 'owned-state',
    appId: 'provider-app',
    universalLink: 'https://app.example/wechat/',
    takeProviderCode: async () => {
      codeReads += 1;
      return 'provider-code';
    },
  });
  const replies = [
    response(204),
    response(200, {
      verificationId: 'social-id',
      authorizationUri:
        'weixin:?app_id=provider-app&state=owned-state&universal_link=https%3A%2F%2Fapp.example%2Fwechat%2F',
    }),
  ];
  let index = 0;
  await expect(driver({ request: async () => replies[index++]! })).rejects.toThrow(
    'Invalid Common WeChat Native identity flow'
  );
  expect(codeReads).toBe(0);
});

test('executes Native provider denials, consumed replay and cross-interaction ownership', async () => {
  const terminals = [
    { status: 200, body: {} },
    { status: 401, body: { code: 'connector.social_auth_code_invalid' } },
    { status: 200, body: {} },
    { status: 404, body: { code: 'session.verification_session_not_found' } },
    { status: 400, body: { code: 'connector.wechat_unionid_required' } },
    { status: 401, body: { code: 'connector.social_auth_code_invalid' } },
    { status: 400, body: { code: 'connector.invalid_response' } },
  ] as const;
  let sessionIndex = 0;
  const createSession = (): CommonExperienceSession => {
    const terminal = terminals[sessionIndex++]!;
    let call = 0;
    return {
      request: async (_path, _method, body) => {
        const current = call++;
        const state = Object.getOwnPropertyDescriptor(body ?? {}, 'state')?.value;
        const currentBody =
          current === 2
            ? {
                verificationId: `verification-${sessionIndex}`,
                authorizationUri: `wechat:?app_id=provider-app&state=${encodeURIComponent(String(state))}&universal_link=https%3A%2F%2Fapp.example%2Fwechat%2F`,
              }
            : current === 3
              ? terminal.body
              : {};
        return {
          getStatus: () =>
            current === 0 ? 303 : current === 1 ? 204 : current === 2 ? 200 : terminal.status,
          getRecord: () => currentBody,
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
  const controlCodes: string[] = [];
  await expect(
    runWechatNativeProviderControls({
      connectorId: 'native',
      redirectUri: 'https://app.example/callback',
      appId: 'provider-app',
      universalLink: 'https://app.example/wechat/',
      createSession,
      authorizationPath: () => '/oidc/auth',
      takeControlCode: async (kind) => {
        controlCodes.push(kind);
        return `code-${kind}`;
      },
    })
  ).resolves.toEqual({
    noUnionId: { status: 400, error: 'connector.wechat_unionid_required', accepted: false },
    invalidCode: { status: 401, error: 'connector.social_auth_code_invalid', accepted: false },
    malformedProvider: { status: 400, error: 'connector.invalid_response', accepted: false },
    replay: {
      firstStatus: 200,
      status: 401,
      error: 'connector.social_auth_code_invalid',
      accepted: false,
    },
    crossInteraction: {
      status: 404,
      error: 'session.verification_session_not_found',
      accepted: false,
    },
  });
  expect(controlCodes).toEqual(['replay', 'noUnionId', 'invalidCode', 'malformedProvider']);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function, @typescript-eslint/no-unsafe-assignment */
