/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions -- Route doubles capture forwarded browser requests. */
import { invokePlaywrightExternalAuthorizationCapability } from '../../phase-1/browser/playwright-session.js';

import { createWechatH5AuthorizationObserver } from './wechat-h5-authorization-observer.js';

test('rewrites the fixed H5 UI payload to the strict state-preserving connector contract', async () => {
  let providerLocation = '';
  let forwarded = '';
  const capability = createWechatH5AuthorizationObserver({
    connectorId: 'wechat-h5',
    clientId: 'owned-client',
    targetOrigin: 'https://core.example/',
    takeCode: async () => 'owned-code',
  });
  const authorization = new URL('https://open.weixin.qq.com/connect/oauth2/authorize');
  for (const [key, value] of Object.entries({
    appid: 'owned-client',
    redirect_uri: 'https://core.example/callback/wechat-h5',
    response_type: 'code',
    scope: 'snsapi_base',
    state: 'owned-state',
  })) {
    authorization.searchParams.set(key, value);
  }
  await expect(
    invokePlaywrightExternalAuthorizationCapability(capability, 'GET', authorization, {
      abort: async () => {},
      fulfill: async (response) => {
        providerLocation = response?.headers?.location ?? '';
      },
    })
  ).resolves.toBe(true);
  const response = { status: () => 200 };
  await expect(
    invokePlaywrightExternalAuthorizationCapability(
      capability,
      'POST',
      new URL('https://core.example/api/experience/verification/social/wechat-h5/verify'),
      {
        abort: async () => {},
        request: () =>
          ({
            postDataJSON: () => ({
              verificationId: 'owned-verification',
              connectorData: {
                code: 'owned-code',
                redirectUri: 'https://core.example/callback/wechat-h5',
                app_id: 'owned-client',
              },
            }),
          }) as never,
        fetch: async (options) => {
          forwarded = String(options?.postData);
          return response as never;
        },
        fulfill: async (options) => {
          expect(options?.response).toBe(response);
        },
      }
    )
  ).resolves.toBe(true);
  expect(JSON.parse(forwarded)).toEqual({
    verificationId: 'owned-verification',
    connectorData: { code: 'owned-code', state: 'owned-state' },
  });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions */
