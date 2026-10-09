/* eslint-disable max-lines, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Stateful one-use capability tests retain only safe observations. */
import { createServer } from 'node:http';
import { createRequire } from 'node:module';

import type { Browser, BrowserType } from '@playwright/test';

import type { TargetConfig } from '../../model.js';
import {
  createPlaywrightBrowserGroupObserver,
  invokePlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

import {
  createGoogleAuthorizationObserver,
  createGoogleAuthorizationWrongStateTestControl,
} from './google-authorization-observer.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

const withAuthorizationPage = async <Result>(
  authorization: (origin: string) => string,
  use: (origin: string) => Promise<Result>,
  callbackStatus = 200
): Promise<Result> => {
  const server = createServer((request, response) => {
    const address = server.address();
    if (!address || typeof address === 'string') {
      response.writeHead(500);
      response.end();
      return;
    }
    const origin = `http://127.0.0.1:${address.port}`;
    response.writeHead(request.url === '/start' ? 200 : callbackStatus, {
      'content-type': 'text/html',
    });
    response.end(
      request.url === '/start'
        ? `<button id="google">Google</button><script>document.querySelector('#google').onclick=()=>{location.href=${JSON.stringify(authorization(origin))}}</script>`
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
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  for (const [key, value] of entries) url.searchParams.append(key, value);
  return url;
};

const validEntries = [
  ['scope', 'openid profile email'],
  ['state', 'abcDEF_123-'],
  ['response_type', 'code'],
  ['redirect_uri', 'https://core.example/callback/google-main'],
  ['client_id', 'client-id'],
] as const;

test('fulfills one exact unordered Google authorization request and exposes only fixed facts', async () => {
  let gets = 0;
  const fulfilled: unknown[] = [];
  const observer = createGoogleAuthorizationObserver({
    connectorId: 'google-main',
    clientId: 'client-id',
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
    /private-code|abcDEF_123-|client-id|google-main/u
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
    entries: validEntries.map(
      ([key, value]) => [key, key === 'client_id' ? 'other' : value] as const
    ),
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
    base: 'https://user@accounts.google.com/o/oauth2/v2/auth',
  },
  {
    name: 'fragment',
    method: 'GET',
    entries: validEntries,
    base: 'https://accounts.google.com/o/oauth2/v2/auth#fragment',
  },
];

test.each(rejectedCases)(
  'rejects $name without consuming the code',
  async ({ method, entries, base }) => {
    let gets = 0;
    const observer = createGoogleAuthorizationObserver({
      connectorId: 'google-main',
      clientId: 'client-id',
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

test('keeps the external Google request denied when no capability is supplied', async () => {
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
  const observer = createGoogleAuthorizationObserver({
    connectorId: 'google-main',
    clientId: 'client-id',
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
  const observer = createGoogleAuthorizationObserver({
    connectorId: 'google-main',
    clientId: 'client-id',
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
  const observer = createGoogleAuthorizationObserver({
    connectorId: 'google-main',
    clientId: 'client-id',
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

test.each([
  ['abcDEF_123-', 'x'],
  ['abcDEF_123x', 'y'],
] as const)(
  'preserves the admitted state grammar while replacing the final %s suffix with %s',
  async (state, expectedSuffix) => {
    let location: string | undefined;
    const observer = createGoogleAuthorizationWrongStateTestControl({
      connectorId: 'google-main',
      clientId: 'client-id',
      targetOrigin: 'https://core.example',
      takeCode: async () => 'private-code',
    });
    const entries = validEntries.map(([key, value]) =>
      key === 'state' ? ([key, state] as const) : ([key, value] as const)
    );
    expect(
      await invokePlaywrightExternalAuthorizationCapability(
        observer.capability,
        'GET',
        authorizationUrl(entries),
        {
          abort: async () => {},
          fulfill: async (value) => {
            location = value?.headers?.location;
          },
        }
      )
    ).toBe(true);
    const returnedState = new URL(location ?? '').searchParams.get('state');
    expect(returnedState).toHaveLength(11);
    expect(returnedState).toMatch(/^[A-Za-z0-9_-]{11}$/u);
    expect(returnedState?.endsWith(expectedSuffix)).toBe(true);
    expect(returnedState).not.toBe(state);
    expect(observer.observation().stateRoundTrip).toBe(false);
  }
);

const browserAuthorization = (origin: string) =>
  authorizationUrl(
    validEntries.map(([key, value]) =>
      key === 'redirect_uri' ? ([key, `${origin}/callback/google-main`] as const) : [key, value]
    )
  ).href;

test('routes the real browser request through the existing guard and reaches the callback', async () => {
  await withAuthorizationPage(browserAuthorization, async (origin) => {
    const google = createGoogleAuthorizationObserver({
      connectorId: 'google-main',
      clientId: 'client-id',
      targetOrigin: origin,
      takeCode: async () => 'private-code',
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium, google.capability);
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
        await session.click('google', '#google');
        await session.waitForRoute('callback-route', 'core', ['/callback/google-main']);
        await session.expectText('callback', '#callback', 'callback');
      }
    );
    expect(google.observation().fulfilledOnce).toBe(true);
  });
});

test('routes one real browser request with a valid deliberately mismatched callback state', async () => {
  await withAuthorizationPage(
    browserAuthorization,
    async (origin) => {
      const google = createGoogleAuthorizationWrongStateTestControl({
        connectorId: 'google-main',
        clientId: 'client-id',
        targetOrigin: origin,
        takeCode: async () => 'private-code',
      });
      const observer = createPlaywrightBrowserGroupObserver(chromium, google.capability);
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
          await session.click('google', '#google');
          await session.waitForRoute('callback-route', 'core', ['/callback/google-main']);
          await expect(
            session.readExternalCallbackOutcome?.('wrong-state-outcome', '/callback/google-main')
          ).resolves.toEqual({ callbackAccepted: false, status: 400, error: 'unknown' });
        }
      );
      expect(google.observation()).toMatchObject({
        requestCount: 1,
        stateFormatValid: true,
        stateRoundTrip: false,
        fulfilledOnce: true,
      });
    },
    400
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
          await session.click('google', '#google');
        }
      )
    ).rejects.toThrow();
  });
});

test('aborts the real browser request when the private code getter fails', async () => {
  await withAuthorizationPage(browserAuthorization, async (origin) => {
    const google = createGoogleAuthorizationObserver({
      connectorId: 'google-main',
      clientId: 'client-id',
      targetOrigin: origin,
      takeCode: async () => {
        throw new Error('private getter');
      },
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium, google.capability);
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
          await session.click('google', '#google');
        }
      )
    ).rejects.toThrow();
    expect(google.observation().fulfilledOnce).toBe(false);
  });
});
/* eslint-enable max-lines, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
