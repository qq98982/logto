import { createServer } from 'node:http';
import { createRequire } from 'node:module';

import type { Browser, BrowserType } from '@playwright/test';

import { createPlaywrightBrowserGroupObserver } from './playwright-session.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

test.each([
  { terminal: 'sign-in', verify: false, accepted: false },
  { terminal: 'consent', verify: false, accepted: true },
  { terminal: 'sign-in', verify: true, accepted: 'unknown' },
] as const)(
  'observes callback HTML200 then $terminal without inventing an HTTP rejection',
  async ({ terminal, verify, accepted }) => {
    const server = createServer((request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(
        request.method === 'POST'
          ? '{}'
          : `<script>window.addEventListener('load',async()=>{
            ${verify ? "await fetch('/api/experience/verification/social/google-owned/verify',{method:'POST'});" : ''}
            history.replaceState({},'',${JSON.stringify(`/${terminal}`)});
          });</script>`
      );
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Invalid owned callback server');
    }
    const origin = `http://127.0.0.1:${address.port}`;
    try {
      const observer = createPlaywrightBrowserGroupObserver(chromium);
      await observer.runInFreshContext(
        'experience',
        AbortSignal.timeout(20_000),
        { label: 'candidate', coreUrl: origin, adminUrl: origin },
        async (session) => {
          await session.navigate(
            'owned-social-callback',
            'core',
            '/callback/google-owned?code=fixture-code&state=fixture-state'
          );
          if (!session.readExternalCallbackOutcome) {
            throw new Error('Missing callback observation capability');
          }
          const outcome = await session.readExternalCallbackOutcome(
            'owned-social-outcome',
            '/callback/google-owned'
          );
          expect(outcome).toEqual({ callbackAccepted: accepted, status: 200, error: 'unknown' });
        }
      );
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
  }
);
