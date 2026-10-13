/* eslint-disable curly, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions -- Stateful one-use capability tests retain only safe observations. */
import { createServer } from 'node:http';
import { createRequire } from 'node:module';

import type { Browser, BrowserType } from '@playwright/test';

import type { TargetConfig } from '../../model.js';
import {
  createPlaywrightBrowserGroupObserver,
  invokePlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

import { createWechatAuthorizationObserver } from './wechat-authorization-observer.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

const withAuthorizationPage = async <Result>(
  authorization: (origin: string) => string,
  use: (origin: string) => Promise<Result>
): Promise<Result> => {
  const server = createServer((request, response) => {
    const address = server.address();
    if (!address || typeof address === 'string') {
      response.writeHead(500);
      response.end();
      return;
    }
    const origin = `http://127.0.0.1:${address.port}`;
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(
      request.url === '/start'
        ? `<button id="wechat">Wechat</button><script>document.querySelector('#wechat').onclick=()=>{location.href=${JSON.stringify(authorization(origin))}}</script>`
        : '<div id="callback">callback</div>'
    );
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Invalid test server');
  try {
    return await use(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }
};

const authorizationUrl = (entries: ReadonlyArray<readonly [string, string]>) => {
  const url = new URL('https://open.weixin.qq.com/connect/qrconnect');
  for (const [key, value] of entries) url.searchParams.append(key, value);
  return url;
};

const validEntries = [
  ['scope', 'snsapi_login'],
  ['state', 'abcDEF_123-'],
  ['response_type', 'code'],
  ['redirect_uri', 'https://core.example/callback/wechat-main'],
  ['appid', 'client-id'],
] as const;

test('fulfills one exact unordered Wechat authorization request and exposes only fixed facts', async () => {
  let gets = 0;
  const fulfilled: unknown[] = [];
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-main',
    clientId: 'client-id',
    channel: 'web',
    targetOrigin: 'https://core.example',
    takeCode: async () => {
      gets += 1;
      return 'private-code';
    },
  });
  const handled = await invokePlaywrightExternalAuthorizationCapability(
    observer.capability,
    'GET',
    authorizationUrl(validEntries),
    {
      abort: async () => {},
      fulfill: async (value) => {
        fulfilled.push(value);
      },
    }
  );
  expect(handled).toBe(true);
  expect(gets).toBe(1);
  expect(fulfilled).toHaveLength(1);
  expect(observer.observation()).toEqual({
    requestCount: 1,
    queryShapeExact: true,
    clientMatched: true,
    callbackMatched: true,
    responseTypeCode: true,
    scopeExact: true,
    stateFormatValid: true,
    stateRoundTrip: true,
    fulfilledOnce: true,
  });
  expect(JSON.stringify(observer.observation())).not.toMatch(
    /private-code|abcDEF_123-|client-id|wechat-main/u
  );
});

const rejectedCases: ReadonlyArray<
  Readonly<{
    name: string;
    method: string;
    entries: ReadonlyArray<readonly [string, string]>;
    base?: string;
  }>
> = [
  { name: 'method', method: 'POST', entries: validEntries },
  {
    name: 'host',
    method: 'GET',
    entries: validEntries,
    base: 'https://example.com/o/oauth2/v2/auth',
  },
  { name: 'duplicate', method: 'GET', entries: [...validEntries, ['state', 'second']] },
  { name: 'extra', method: 'GET', entries: [...validEntries, ['prompt', 'consent']] },
  {
    name: 'client',
    method: 'GET',
    entries: validEntries.map(([key, value]) => [key, key === 'appid' ? 'other' : value] as const),
  },
  {
    name: 'state',
    method: 'GET',
    entries: validEntries.map(([key, value]) => [key, key === 'state' ? '' : value] as const),
  },
  {
    name: 'callback',
    method: 'GET',
    entries: validEntries.map(
      ([key, value]) =>
        [key, key === 'redirect_uri' ? 'https://core.example/callback/other' : value] as const
    ),
  },
  {
    name: 'response',
    method: 'GET',
    entries: validEntries.map(
      ([key, value]) => [key, key === 'response_type' ? 'token' : value] as const
    ),
  },
  {
    name: 'scope',
    method: 'GET',
    entries: validEntries.map(
      ([key, value]) => [key, key === 'scope' ? 'openid email' : value] as const
    ),
  },
  {
    name: 'userinfo',
    method: 'GET',
    entries: validEntries,
    base: 'https://user@accounts.wechat.com/o/oauth2/v2/auth',
  },
  {
    name: 'fragment',
    method: 'GET',
    entries: validEntries,
    base: 'https://open.weixin.qq.com/connect/qrconnect#fragment',
  },
];

test.each(rejectedCases)(
  'rejects $name without consuming the code',
  async ({ method, entries, base }) => {
    let gets = 0;
    const observer = createWechatAuthorizationObserver({
      connectorId: 'wechat-main',
      clientId: 'client-id',
      channel: 'web',
      targetOrigin: 'https://core.example',
      takeCode: async () => {
        gets += 1;
        return 'private';
      },
    });
    const url = base ? new URL(base) : authorizationUrl(entries);
    const handled = await invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      method,
      url,
      { abort: async () => {}, fulfill: async () => {} }
    );
    expect(handled).toBe(false);
    expect(gets).toBe(0);
  }
);

test('keeps the external Wechat request denied when no capability is supplied', async () => {
  expect(
    await invokePlaywrightExternalAuthorizationCapability(
      undefined,
      'GET',
      authorizationUrl(validEntries),
      { abort: async () => {}, fulfill: async () => {} }
    )
  ).toBe(false);
});

test('rejects second use and consumes the private code only once', async () => {
  let gets = 0;
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-main',
    clientId: 'client-id',
    channel: 'web',
    targetOrigin: 'https://core.example',
    takeCode: async () => {
      gets += 1;
      return 'private-code';
    },
  });
  const route = { abort: async () => {}, fulfill: async () => {} };
  expect(
    await invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'GET',
      authorizationUrl(validEntries),
      route
    )
  ).toBe(true);
  expect(
    await invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'GET',
      authorizationUrl(validEntries),
      route
    )
  ).toBe(false);
  expect(gets).toBe(1);
});

test('does not expose a private getter failure', async () => {
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-main',
    clientId: 'client-id',
    channel: 'web',
    targetOrigin: 'https://core.example',
    takeCode: async () => {
      throw new Error('private getter value');
    },
  });
  await expect(
    invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'GET',
      authorizationUrl(validEntries),
      { abort: async () => {}, fulfill: async () => {} }
    )
  ).rejects.toThrow();
  expect(observer.observation().fulfilledOnce).toBe(false);
});

test('does not publish redirect success when fulfillment fails', async () => {
  let gets = 0;
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-main',
    clientId: 'client-id',
    channel: 'web',
    targetOrigin: 'https://core.example',
    takeCode: async () => {
      gets += 1;
      return 'private-code';
    },
  });
  await expect(
    invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'GET',
      authorizationUrl(validEntries),
      {
        abort: async () => {},
        fulfill: async () => {
          throw new Error('private fulfill');
        },
      }
    )
  ).rejects.toThrow();
  expect(gets).toBe(1);
  expect(observer.observation().fulfilledOnce).toBe(false);
  expect(observer.observation().stateRoundTrip).toBe(false);
  expect(
    await invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'GET',
      authorizationUrl(validEntries),
      { abort: async () => {}, fulfill: async () => {} }
    )
  ).toBe(false);
  expect(gets).toBe(1);
});

const browserAuthorization = (origin: string) =>
  authorizationUrl(
    validEntries.map(([key, value]) =>
      key === 'redirect_uri' ? ([key, `${origin}/callback/wechat-main`] as const) : [key, value]
    )
  ).href;

test('routes the real browser request through the existing guard and reaches the callback', async () => {
  await withAuthorizationPage(browserAuthorization, async (origin) => {
    const wechat = createWechatAuthorizationObserver({
      connectorId: 'wechat-main',
      clientId: 'client-id',
      channel: 'web',
      targetOrigin: origin,
      takeCode: async () => 'private-code',
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium, wechat.capability);
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${origin}/`,
      adminUrl: `${origin}/`,
    });
    await observer.runInFreshContext(
      'experience',
      new AbortController().signal,
      target,
      async (session) => {
        await session.navigate('open', 'core', '/start');
        await session.click('wechat', '#wechat');
        await session.waitForRoute('callback-route', 'core', ['/callback/wechat-main']);
        await session.expectText('callback', '#callback', 'callback');
      }
    );
    expect(wechat.observation().fulfilledOnce).toBe(true);
  });
});

test('admits the H5 authorization after Chromium removes its navigation fragment', async () => {
  await withAuthorizationPage(
    (origin) => {
      const url = new URL('https://open.weixin.qq.com/connect/oauth2/authorize');
      for (const [key, value] of Object.entries({
        appid: 'client-id',
        redirect_uri: `${origin}/callback/wechat-main`,
        response_type: 'code',
        scope: 'snsapi_userinfo',
        state: 'abcDEF_123-',
      })) {
        url.searchParams.set(key, value);
      }
      url.hash = 'wechat_redirect';
      return url.href;
    },
    async (origin) => {
      const wechat = createWechatAuthorizationObserver({
        connectorId: 'wechat-main',
        clientId: 'client-id',
        channel: 'h5',
        targetOrigin: origin,
        takeCode: async () => 'private-code',
      });
      const observer = createPlaywrightBrowserGroupObserver(chromium, wechat.capability);
      const target: TargetConfig = Object.freeze({
        label: 'oracle',
        coreUrl: `${origin}/`,
        adminUrl: `${origin}/`,
      });
      await observer.runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('open', 'core', '/start');
          await session.click('wechat', '#wechat');
          await session.waitForRoute('callback-route', 'core', ['/callback/wechat-main']);
        }
      );
      expect(wechat.observation().fulfilledOnce).toBe(true);
    }
  );
});

test('rejects a nonempty unexpected H5 authorization fragment', async () => {
  let gets = 0;
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-h5',
    clientId: 'owned-client',
    channel: 'h5',
    targetOrigin: 'https://core.example/',
    takeCode: async () => {
      gets += 1;
      return 'owned-code';
    },
  });
  const authorization = new URL(
    'https://open.weixin.qq.com/connect/oauth2/authorize?appid=owned-client&redirect_uri=https%3A%2F%2Fcore.example%2Fcallback%2Fwechat-h5&response_type=code&scope=snsapi_userinfo&state=abcdefghijk#unexpected'
  );
  await expect(
    invokePlaywrightExternalAuthorizationCapability(observer.capability, 'GET', authorization, {
      abort: async () => {},
      fulfill: async () => {},
    })
  ).resolves.toBe(false);
  expect(gets).toBe(0);
});

test.each([
  { name: 'provider state', extra: { state: 'abcdefghijk' } },
  { name: 'OIDC application', extra: { app_id: 'owned-oidc-client' } },
  {
    name: 'OIDC application with the WeChat callback marker',
    extra: { app_id: 'owned-oidc-client', wechat_redirect: '' },
  },
])(
  'rewrites the H5 fixed UI callback with bound $name to exact code and state',
  async ({ extra }) => {
    let forwarded = '';
    const observer = createWechatAuthorizationObserver({
      connectorId: 'wechat-h5',
      clientId: 'owned-client',
      oidcClientId: 'owned-oidc-client',
      channel: 'h5',
      targetOrigin: 'https://core.example/',
      takeCode: async () => 'owned-code',
    });
    const authorization = new URL(
      'https://open.weixin.qq.com/connect/oauth2/authorize?appid=owned-client&redirect_uri=https%3A%2F%2Fcore.example%2Fcallback%2Fwechat-h5&response_type=code&scope=snsapi_userinfo&state=abcdefghijk#wechat_redirect'
    );
    await invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'GET',
      authorization,
      {
        abort: async () => {},
        fulfill: async () => {},
      }
    );
    const apiResponse = { status: () => 200 };
    await expect(
      invokePlaywrightExternalAuthorizationCapability(
        observer.capability,
        'GET',
        new URL('https://core.example/api/experience/verification/social/wechat-h5/verify'),
        { abort: async () => {}, fulfill: async () => {} }
      )
    ).resolves.toBe(false);
    await expect(
      invokePlaywrightExternalAuthorizationCapability(
        observer.capability,
        'POST',
        new URL('https://core.example/api/experience/verification/social/wechat-h5/verify'),
        {
          abort: async () => {},
          request: () =>
            ({
              postData: () =>
                JSON.stringify({
                  verificationId: 'owned-verification',
                  connectorData: {
                    code: 'owned-code',
                    ...extra,
                    redirectUri: 'https://core.example/callback/wechat-h5',
                  },
                }),
            }) as never,
          fetch: async (options) => {
            forwarded = String(options?.postData);
            return apiResponse as never;
          },
          fulfill: async (options) => {
            expect(options?.response).toBe(apiResponse);
          },
        }
      )
    ).resolves.toBe(true);
    expect(JSON.parse(forwarded)).toEqual({
      verificationId: 'owned-verification',
      connectorData: { code: 'owned-code', state: 'abcdefghijk' },
    });
  }
);

test.each([
  {
    name: 'wrong OIDC application',
    verificationId: 'owned-verification',
    body: {
      code: 'owned-code',
      app_id: 'other-oidc-client',
      redirectUri: 'https://core.example/callback/wechat-h5',
    },
  },
  {
    name: 'provider id used as OIDC application',
    verificationId: 'owned-verification',
    body: {
      code: 'owned-code',
      app_id: 'owned-client',
      redirectUri: 'https://core.example/callback/wechat-h5',
    },
  },
  {
    name: 'nonempty WeChat callback marker',
    verificationId: 'owned-verification',
    body: {
      code: 'owned-code',
      app_id: 'owned-oidc-client',
      redirectUri: 'https://core.example/callback/wechat-h5',
      wechat_redirect: '1',
    },
  },
  {
    name: 'WeChat callback marker without the owned OIDC application',
    verificationId: 'owned-verification',
    body: {
      code: 'owned-code',
      redirectUri: 'https://core.example/callback/wechat-h5',
      wechat_redirect: '',
    },
  },
  {
    name: 'wrong state',
    verificationId: 'owned-verification',
    body: { code: 'owned-code', state: 'other-state' },
  },
  {
    name: 'wrong code',
    verificationId: 'owned-verification',
    body: { code: 'other-code', state: 'abcdefghijk' },
  },
  {
    name: 'wrong callback',
    verificationId: 'owned-verification',
    body: { code: 'owned-code', state: 'abcdefghijk', redirectUri: 'https://other.example/' },
  },
  {
    name: 'extra field',
    verificationId: 'owned-verification',
    body: { code: 'owned-code', state: 'abcdefghijk', extra: true },
  },
  {
    name: 'empty verification id',
    verificationId: '',
    body: { code: 'owned-code', state: 'abcdefghijk' },
  },
])('fails closed on H5 $name after owning callback state', async ({ body, verificationId }) => {
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-h5',
    clientId: 'owned-client',
    oidcClientId: 'owned-oidc-client',
    channel: 'h5',
    targetOrigin: 'https://core.example/',
    takeCode: async () => 'owned-code',
  });
  await invokePlaywrightExternalAuthorizationCapability(
    observer.capability,
    'GET',
    new URL(
      'https://open.weixin.qq.com/connect/oauth2/authorize?appid=owned-client&redirect_uri=https%3A%2F%2Fcore.example%2Fcallback%2Fwechat-h5&response_type=code&scope=snsapi_userinfo&state=abcdefghijk#wechat_redirect'
    ),
    { abort: async () => {}, fulfill: async () => {} }
  );
  let forwarded = false;
  await expect(
    invokePlaywrightExternalAuthorizationCapability(
      observer.capability,
      'POST',
      new URL('https://core.example/api/experience/verification/social/wechat-h5/verify'),
      {
        abort: async () => {},
        request: () =>
          ({
            postData: () => JSON.stringify({ verificationId, connectorData: body }),
          }) as never,
        fetch: async () => {
          forwarded = true;
          return {} as never;
        },
        fulfill: async () => {},
      }
    )
  ).rejects.toThrow('Invalid WeChat H5 verification body');
  expect(forwarded).toBe(false);
});

test('canonicalizes the strict H5 body to the same exact bytes', async () => {
  const observer = createWechatAuthorizationObserver({
    connectorId: 'wechat-h5',
    clientId: 'owned-client',
    channel: 'h5',
    targetOrigin: 'https://core.example/',
    takeCode: async () => 'owned-code',
  });
  await invokePlaywrightExternalAuthorizationCapability(
    observer.capability,
    'GET',
    new URL(
      'https://open.weixin.qq.com/connect/oauth2/authorize?appid=owned-client&redirect_uri=https%3A%2F%2Fcore.example%2Fcallback%2Fwechat-h5&response_type=code&scope=snsapi_userinfo&state=abcdefghijk#wechat_redirect'
    ),
    { abort: async () => {}, fulfill: async () => {} }
  );
  let forwarded = '';
  await invokePlaywrightExternalAuthorizationCapability(
    observer.capability,
    'POST',
    new URL('https://core.example/api/experience/verification/social/wechat-h5/verify'),
    {
      abort: async () => {},
      request: () =>
        ({
          postData: () =>
            JSON.stringify({
              verificationId: 'owned-verification',
              connectorData: { state: 'abcdefghijk', code: 'owned-code' },
            }),
        }) as never,
      fetch: async (options) => {
        forwarded = String(options?.postData);
        return {} as never;
      },
      fulfill: async () => {},
    }
  );
  expect(forwarded).toBe(
    '{"verificationId":"owned-verification","connectorData":{"code":"owned-code","state":"abcdefghijk"}}'
  );
});

test('keeps the real browser request denied without a capability', async () => {
  await withAuthorizationPage(browserAuthorization, async (origin) => {
    const observer = createPlaywrightBrowserGroupObserver(chromium);
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${origin}/`,
      adminUrl: `${origin}/`,
    });
    await expect(
      observer.runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('open', 'core', '/start');
          await session.click('wechat', '#wechat');
        }
      )
    ).rejects.toThrow();
  });
});

test('aborts the real browser request when the private code getter fails', async () => {
  await withAuthorizationPage(browserAuthorization, async (origin) => {
    const wechat = createWechatAuthorizationObserver({
      connectorId: 'wechat-main',
      clientId: 'client-id',
      channel: 'web',
      targetOrigin: origin,
      takeCode: async () => {
        throw new Error('private getter');
      },
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium, wechat.capability);
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${origin}/`,
      adminUrl: `${origin}/`,
    });
    await expect(
      observer.runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('open', 'core', '/start');
          await session.click('wechat', '#wechat');
        }
      )
    ).rejects.toThrow();
    expect(wechat.observation().fulfilledOnce).toBe(false);
  });
});
/* eslint-enable curly, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/consistent-type-assertions */
