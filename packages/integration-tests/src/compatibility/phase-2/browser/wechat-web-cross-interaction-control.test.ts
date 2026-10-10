/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Stateful localhost browser fixture proves exact replay and normal continuation. */
import { createServer } from 'node:http';
import { createRequire } from 'node:module';

import type { Browser, BrowserType } from '@playwright/test';

import type { TargetConfig } from '../../model.js';
import {
  createPlaywrightBrowserGroupObserver,
  invokePlaywrightExternalAuthorizationCapability,
  registerPlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

import { createWechatWebCrossInteractionTestControl } from './wechat-web-cross-interaction-control.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

test('replays the first successful social verification and releases it for normal UI continuation', async () => {
  let verifyCount = 0;
  let identificationCount = 0;
  let interactionCount = 0;
  const requestBodies: string[] = [];
  const clientHeaders: Array<string | undefined> = [];
  const cookieFacts: Array<
    Readonly<{
      interaction: boolean;
      signature: boolean;
      foreignInteraction: boolean;
      foreignSignature: boolean;
      extra: boolean;
      repaired: boolean;
    }>
  > = [];
  const server = createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(`<button id="go">go</button><div id="done"></div><script>
        document.cookie='_interaction=existing; Path=/';
        document.cookie='_interaction.sig=existing-signature; Path=/';
        document.cookie='extra=preserved; Path=/';
        document.querySelector('#go').onclick=async()=>{
          const first=await fetch('/api/experience/verification/social/wechat-web-main/verify',{
            method:'POST',headers:{'content-type':'application/json','aster-app-id':'browser'},
            body:JSON.stringify({verificationId:'private-id',connectorData:{code:'private-code'}})
          });
          const body=await first.json();
          await fetch('/api/experience/identification',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({verificationId:body.verificationId})});
          location.href='/complete';
        };
      </script>`);
      return;
    }
    if (request.url === '/complete') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<div id="done">continued</div>');
      return;
    }
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => {
      body += chunk;
    });
    request.on('end', () => {
      if (request.url === '/api/experience' && request.method === 'PUT') {
        interactionCount += 1;
        response.writeHead(204, {
          'set-cookie': [
            '_interaction=foreign; Path=/; HttpOnly',
            '_interaction.sig=foreign-signature; Path=/; HttpOnly',
          ],
        });
        response.end();
        return;
      }
      if (request.url?.endsWith('/verify')) {
        verifyCount += 1;
        requestBodies.push(body);
        const clientHeader = request.headers['aster-app-id'];
        clientHeaders.push(typeof clientHeader === 'string' ? clientHeader : undefined);
        const cookie = request.headers.cookie ?? '';
        cookieFacts.push({
          interaction: cookie.includes('_interaction=existing'),
          signature: cookie.includes('_interaction.sig=existing-signature'),
          foreignInteraction: cookie.includes('_interaction=foreign'),
          foreignSignature: cookie.includes('_interaction.sig=foreign-signature'),
          extra: cookie.includes('extra=preserved'),
          repaired: cookie.includes('proof=merged'),
        });
        if (verifyCount === 1) {
          response.writeHead(200, {
            'content-type': 'application/json',
            'set-cookie': 'proof=merged; Path=/; HttpOnly',
          });
          response.end(JSON.stringify({ verificationId: 'private-proof' }));
        } else {
          response.writeHead(404, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ code: 'session.verification_session_not_found' }));
        }
        return;
      }
      identificationCount += 1;
      response.writeHead(204);
      response.end();
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Invalid test server');
  }
  const origin = `http://127.0.0.1:${address.port}`;
  let ownerReads = 0;
  const control = createWechatWebCrossInteractionTestControl({
    authorization: registerPlaywrightExternalAuthorizationCapability(async () => false),
    targetOrigin: origin,
    connectorId: 'wechat-web-main',
    ownerSnapshot: async () => ({ id: 'owner', stable: true, read: ++ownerReads > 0 }),
  });
  const target: TargetConfig = { label: 'oracle', coreUrl: `${origin}/`, adminUrl: `${origin}/` };
  let runError: unknown;
  try {
    try {
      await createPlaywrightBrowserGroupObserver(chromium, control.capability).runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('open', 'core', '/');
          await session.click('go', '#go');
          await session.waitForRoute('complete-route', 'core', ['/complete']);
          await session.expectText('continued', '#done', 'continued');
        }
      );
    } catch (error: unknown) {
      runError = error;
    }
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }
  expect(requestBodies).toHaveLength(2);
  expect(requestBodies[0]).toBe(requestBodies[1]);
  expect(clientHeaders).toEqual(['browser', 'browser']);
  expect(cookieFacts).toEqual([
    {
      interaction: true,
      signature: true,
      foreignInteraction: false,
      foreignSignature: false,
      extra: true,
      repaired: false,
    },
    {
      interaction: false,
      signature: false,
      foreignInteraction: true,
      foreignSignature: true,
      extra: false,
      repaired: false,
    },
  ]);
  expect(interactionCount).toBe(1);
  expect(runError).toBeUndefined();
  expect(identificationCount).toBe(1);
  expect(control.observation()).toEqual({
    requestCount: 1,
    firstStatus: 200,
    firstOutcome: 'verified',
    secondStatus: 404,
    secondError: 'session.verification_session_not_found',
    secondAccepted: false,
    ownerPreserved: true,
  });
  await expect(
    invokePlaywrightExternalAuthorizationCapability(
      control.capability,
      'POST',
      new URL('/api/experience/verification/social/wechat-web-main/verify', origin),
      { abort: async () => {}, fulfill: async () => {} }
    )
  ).rejects.toThrow('Invalid WeChat Web cross-interaction control');
});

test('keeps a missing replay error code observationally unknown', async () => {
  let fetches = 0;
  const control = createWechatWebCrossInteractionTestControl({
    authorization: registerPlaywrightExternalAuthorizationCapability(async () => false),
    targetOrigin: 'https://core.example',
    connectorId: 'wechat-web-main',
    ownerSnapshot: async () => ({ owner: true }),
    foreignInteractionRequest: async () => Object.freeze({ status: 409, body: {} }),
  });
  await expect(
    invokePlaywrightExternalAuthorizationCapability(
      control.capability,
      'POST',
      new URL('https://core.example/api/experience/verification/social/wechat-web-main/verify'),
      {
        abort: async () => {},
        fulfill: async () => {},
        request: () =>
          ({
            allHeaders: async () => ({ cookie: '_interaction=private' }),
            postDataBuffer: () => Buffer.from('{}'),
          }) as never,
        fetch: async () => {
          fetches += 1;
          const body = Buffer.from(JSON.stringify({ verificationId: 'private-proof' }));
          const response: Awaited<
            ReturnType<
              NonNullable<
                Parameters<typeof invokePlaywrightExternalAuthorizationCapability>[3]['fetch']
              >
            >
          > = {
            status: () => 200,
            body: async () => body,
            headersArray: () => [],
          } as never;
          return response;
        },
      }
    )
  ).resolves.toBe(true);
  expect(control.observation()).toMatchObject({
    secondStatus: 409,
    secondError: 'none',
    secondAccepted: 'unknown',
  });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
