/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function -- Capability tests capture the one fulfilled redirect and count secret-code reads. */
import { invokePlaywrightExternalAuthorizationCapability } from '../../phase-1/browser/playwright-session.js';

import { createWechatWebAuthorizationObserver } from './wechat-web-authorization-observer.js';

const providerUrl = (state = 'abcdefghijk') => {
  const url = new URL('https://open.weixin.qq.com/connect/qrconnect');
  url.searchParams.set('appid', 'owned-client');
  url.searchParams.set('redirect_uri', 'https://core.example/callback/wechat-main');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'snsapi_login');
  url.searchParams.set('state', state);
  return url;
};

test.each([
  ['missing-state', false, '/callback/wechat-main'],
  ['wrong-state', true, '/callback/wechat-main'],
  ['wrong-callback', true, '/callback/wrong-wechat-main'],
] as const)('keeps the correct retry proof private for %s', async (mode, hasState, pathname) => {
  let location: URL | undefined;
  const observer = createWechatWebAuthorizationObserver({
    connectorId: 'wechat-main',
    clientId: 'owned-client',
    targetOrigin: 'https://core.example/',
    callbackMode: mode,
    takeCode: async () => 'owned-provider-code',
  });
  await expect(
    invokePlaywrightExternalAuthorizationCapability(observer.capability, 'GET', providerUrl(), {
      abort: async () => {},
      fulfill: async (response) => {
        if (!response) {
          throw new TypeError('Missing WeChat redirect response');
        }
        location = new URL(response.headers?.location ?? '');
      },
    })
  ).resolves.toBe(true);
  expect(location?.pathname).toBe(pathname);
  expect(location?.searchParams.has('state')).toBe(hasState);
  expect(observer.observation()).toMatchObject({
    requestCount: 1,
    stateFormatValid: true,
    stateRoundTrip: false,
    fulfilledOnce: true,
  });
  const retry = new URL(observer.retryPath() ?? '', 'https://core.example');
  expect(retry.pathname).toBe('/callback/wechat-main');
  expect(retry.searchParams.get('code')).toBe('owned-provider-code');
  expect(retry.searchParams.get('state')).toBe('abcdefghijk');
});

test('rejects a partial provider authorization query without consuming a code', async () => {
  let codeReads = 0;
  const observer = createWechatWebAuthorizationObserver({
    connectorId: 'wechat-main',
    clientId: 'owned-client',
    targetOrigin: 'https://core.example/',
    takeCode: async () => {
      codeReads += 1;
      return 'owned-provider-code';
    },
  });
  const partial = providerUrl();
  partial.searchParams.delete('state');
  await expect(
    invokePlaywrightExternalAuthorizationCapability(observer.capability, 'GET', partial, {
      abort: async () => {},
      fulfill: async () => {},
    })
  ).resolves.toBe(false);
  expect(codeReads).toBe(0);
  expect(observer.observation().fulfilledOnce).toBe(false);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-empty-function */
