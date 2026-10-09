import type { Browser, BrowserType, Route } from '@playwright/test';

import type { Phase1BrowserGroupObserver } from './contracts.js';
import {
  createPlaywrightBrowserGroupObserver,
  invokePlaywrightExternalAuthorizationCapability,
  isPlaywrightBrowserGroupObserver,
  registerPlaywrightExternalAuthorizationCapability,
  withPlaywrightExternalAuthorizationCapability,
} from './playwright-session.js';

const { jest } = import.meta;

const route: Pick<Route, 'abort' | 'fulfill'> = { abort: jest.fn(), fulfill: jest.fn() };

test('an absent or forged capability grants no external authorization', async () => {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  expect(await invokePlaywrightExternalAuthorizationCapability(undefined, 'GET', url, route)).toBe(
    false
  );
  expect(
    await invokePlaywrightExternalAuthorizationCapability(Object.freeze({}), 'GET', url, route)
  ).toBe(false);
});

test('only the registered handler decides its owned authorization request', async () => {
  const handler = jest.fn(
    async (method: string, url: URL) =>
      method === 'GET' && url.origin === 'https://accounts.google.com'
  );
  const capability = registerPlaywrightExternalAuthorizationCapability(handler);
  expect(Object.isFrozen(capability)).toBe(true);
  expect(
    await invokePlaywrightExternalAuthorizationCapability(
      capability,
      'GET',
      new URL('https://accounts.google.com/o/oauth2/v2/auth'),
      route
    )
  ).toBe(true);
  expect(
    await invokePlaywrightExternalAuthorizationCapability(
      capability,
      'POST',
      new URL('https://unselected.example.invalid'),
      route
    )
  ).toBe(false);
  expect(handler).toHaveBeenCalledTimes(2);
});

test('provider attachment rejects an unbranded observer or forged capability', () => {
  const browserType = { launch: jest.fn() } as unknown as Pick<BrowserType<Browser>, 'launch'>;
  const observer = createPlaywrightBrowserGroupObserver(browserType);
  const capability = registerPlaywrightExternalAuthorizationCapability(async () => false);
  expect(() =>
    withPlaywrightExternalAuthorizationCapability(
      Object.freeze({}) as Phase1BrowserGroupObserver,
      capability
    )
  ).toThrow('Invalid browser external authorization capability');
  expect(() => withPlaywrightExternalAuthorizationCapability(observer, Object.freeze({}))).toThrow(
    'Invalid browser external authorization capability'
  );
});

test('derived observers retain the branded launcher and request fresh context execution', async () => {
  const launch = jest.fn(async () => {
    throw new Error('owned-launch-attempt');
  });
  const browserType = { launch } as unknown as Pick<BrowserType<Browser>, 'launch'>;
  const observer = createPlaywrightBrowserGroupObserver(browserType);
  const capability = registerPlaywrightExternalAuthorizationCapability(async () => false);
  const derived = withPlaywrightExternalAuthorizationCapability(observer, capability);
  expect(Object.isFrozen(derived)).toBe(true);
  expect(isPlaywrightBrowserGroupObserver(derived)).toBe(true);
  expect(derived).not.toBe(observer);
  await expect(
    derived.runInFreshContext(
      'experience',
      AbortSignal.timeout(1000),
      {
        label: 'candidate',
        coreUrl: 'https://core.example.invalid',
        adminUrl: 'https://admin.example.invalid',
      },
      async () => 'context-used'
    )
  ).rejects.toThrow();
  expect(launch).toHaveBeenCalledTimes(1);
});
