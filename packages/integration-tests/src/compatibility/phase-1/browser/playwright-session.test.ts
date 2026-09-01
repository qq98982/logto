/* eslint-disable complexity, max-lines, max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The real-browser adapter test owns ephemeral servers, exact protocol branches, isolation attempts, and only safe fact snapshots. */
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createRequire } from 'node:module';

import type { Browser, BrowserType } from '@playwright/test';

import type { TargetConfig } from '../../model.js';

import { createPlaywrightBrowserGroupObserver } from './playwright-session.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

const compact = (value: Record<string, unknown>) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const signed = (claims: Record<string, unknown>) =>
  `${compact({ alg: 'ES384' })}.${compact(claims)}.signature`;

const browserDocument = (
  adminOrigin: string,
  coreOrigin: string,
  state: string,
  verifier: string,
  challenge: string
) => `<!doctype html>
  <div id="config"></div><input id="field" />
  <div><div role="button">User Scopes</div><ul><li>Profile</li><li>Email</li></ul></div>
  <button id="emit">emit</button><button id="emit-string">string</button>
  <button id="requests">requests</button><button id="bad-requests">bad requests</button>
  <script>
    document.querySelector('#config').textContent = localStorage.getItem('profile-config');
    document.querySelector('#emit').onclick = () => console.log({ aud: 'runtime-api', scope: 'runtime-read' });
    document.querySelector('#emit-string').onclick = () => console.log('private-token');
    document.querySelector('#requests').onclick = async () => {
      const redirectUri = '${adminOrigin}/console/callback';
      const signIn = new URL('${adminOrigin}/oidc/auth');
      for (const [key, value] of [
        ['client_id', 'admin-console'],
        ['redirect_uri', redirectUri],
        ['code_challenge', '${challenge}'],
        ['code_challenge_method', 'S256'],
        ['state', '${state}'],
        ['response_type', 'code'],
        ['prompt', 'login consent'],
        ['scope', 'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all'],
        ['resource', 'https://default.logto.app/api'],
        ['resource', 'https://admin.logto.app/me'],
        ['resource', 'urn:logto:resource:organizations'],
      ]) signIn.searchParams.append(key, value);
      await fetch(signIn);
      const callback = new URL(redirectUri);
      callback.searchParams.append('code', 'private-code');
      callback.searchParams.append('state', '${state}');
      callback.searchParams.append('iss', '${adminOrigin}/oidc');
      await fetch(callback);
      await (await fetch('${adminOrigin}/api/.well-known/endpoints/default')).json();
      const initial = await (await fetch('${adminOrigin}/oidc/token', {
        method: 'POST',
        headers: {'content-type':'application/x-www-form-urlencoded'},
        body: new URLSearchParams([
          ['client_id', 'admin-console'],
          ['code', 'private-code'],
          ['code_verifier', '${verifier}'],
          ['redirect_uri', redirectUri],
          ['grant_type', 'authorization_code'],
        ]),
      })).json();
      await (await fetch('${adminOrigin}/api/my-account/', {
        headers: { authorization: 'Bearer ' + initial.access_token },
      })).json();
      const management = await (await fetch('${adminOrigin}/oidc/token', {
        method: 'POST',
        headers: {'content-type':'application/x-www-form-urlencoded'},
        body: new URLSearchParams([
          ['client_id', 'admin-console'],
          ['refresh_token', initial.refresh_token],
          ['grant_type', 'refresh_token'],
          ['resource', 'https://default.logto.app/api'],
        ]),
      })).json();
      await (await fetch('${adminOrigin}/oidc/token', {
        method: 'POST',
        headers: {'content-type':'application/x-www-form-urlencoded'},
        body: new URLSearchParams([
          ['client_id', 'admin-console'],
          ['refresh_token', management.refresh_token],
          ['grant_type', 'refresh_token'],
          ['organization_id', 't-default'],
        ]),
      })).json();
      const apiHeaders = {
        authorization: 'Bearer ' + management.access_token,
        'accept-language': 'en',
      };
      await (await fetch('${coreOrigin}/api/applications?page=1&page_size=20&isThirdParty=false', { headers: apiHeaders })).json();
      await (await fetch('${coreOrigin}/api/applications?page=1&page_size=20&isThirdParty=true', { headers: apiHeaders })).json();
      await (await fetch('${coreOrigin}/api/applications?page=1&page_size=1&isThirdParty=false&types=SAML', { headers: apiHeaders })).json();
      await (await fetch('${coreOrigin}/api/users?page=1&page_size=20', { headers: apiHeaders })).json();
    };
    document.querySelector('#bad-requests').onclick = async () => {
      const refresh = async (parent, resource) => (await fetch('${adminOrigin}/oidc/token', {
        method: 'POST',
        headers: {'content-type':'application/x-www-form-urlencoded'},
        body: new URLSearchParams([
          ['client_id', 'admin-console'],
          ['refresh_token', parent],
          ['grant_type', 'refresh_token'],
          ['resource', resource],
        ]),
      })).json();
      await refresh('private-refresh-2', 'https://case.example/missing');
      await refresh('private-refresh-2', 'https://case.example/duplicate');
      await refresh('private-refresh-2', 'https://case.example/access-equal');
      await refresh('private-unknown-parent', 'https://case.example/unknown-parent');
      await fetch('${adminOrigin}/api/.well-known/endpoints/default', {
        headers: { authorization: 'Bearer private-endpoint-value' },
      });
    };
  </script>`;

const readBody = async (request: IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => {
      body += chunk;
    });
    request.on('end', () => {
      resolve(body);
    });
    request.on('error', reject);
  });

const json = (
  response: ServerResponse,
  body: unknown,
  headers: Readonly<Record<string, string>> = {}
) => {
  response.writeHead(200, {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'authorization, content-type',
    'content-type': 'application/json',
    ...headers,
  });
  response.end(JSON.stringify(body));
};

const listen = async (
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>
) => {
  const server = createServer((request, response) => {
    void handler(request, response);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Synthetic browser server failed');
  }

  return Object.freeze({
    origin: `http://127.0.0.1:${address.port}`,
    close: async () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      }),
  });
};

describe('Phase 1 Playwright browser session adapter', () => {
  it('preloads configuration, projects console objects, and records safe network facts', async () => {
    const state = 's'.repeat(86);
    const verifier = 'v'.repeat(86);
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const core = await listen(async (request, response) => {
      const url = new URL(request.url ?? '/', 'http://core.invalid');

      if (request.method === 'OPTIONS') {
        response.writeHead(204, {
          'access-control-allow-origin': '*',
          'access-control-allow-headers': 'accept-language, authorization, content-type',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
        });
        response.end();
        return;
      }
      if (url.pathname === '/other') {
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end('<input id="field" />');
        return;
      }
      if (url.pathname === '/api/applications') {
        const thirdParty = url.searchParams.get('isThirdParty') === 'true';
        const saml = url.searchParams.get('types') === 'SAML';
        json(
          response,
          saml
            ? []
            : [
                {
                  id: thirdParty ? 'runtime-browser' : 'runtime-app',
                  name: thirdParty ? 'Runtime Browser' : 'Runtime App',
                },
              ],
          { 'total-number': saml ? '0' : '1' }
        );
        return;
      }
      if (url.pathname === '/api/users') {
        json(
          response,
          [
            {
              id: 'runtime-user',
              name: 'phase1-user',
              username: 'runtime-username',
              primaryEmail: 'runtime@example.com',
              lastSignInAt: null,
            },
          ],
          { 'total-number': '1' }
        );
        return;
      }
      response.writeHead(404);
      response.end();
    });
    const admin = await listen(async (request, response) => {
      const url = new URL(request.url ?? '/', 'http://admin.invalid');

      if (request.method === 'OPTIONS') {
        response.writeHead(204, {
          'access-control-allow-origin': '*',
          'access-control-allow-headers': 'accept-language, authorization, content-type',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
        });
        response.end();
        return;
      }
      if (url.pathname === '/demo-app') {
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end(browserDocument(admin.origin, core.origin, state, verifier, challenge));
        return;
      }
      if (url.pathname === '/oidc/auth') {
        response.writeHead(303, {
          'access-control-allow-origin': '*',
          location: '/sign-in',
        });
        response.end();
        return;
      }
      if (url.pathname === '/sign-in' || url.pathname === '/console/callback') {
        json(response, { continued: true });
        return;
      }
      if (url.pathname === '/api/.well-known/endpoints/default') {
        json(response, { user: `${core.origin}/` });
        return;
      }
      if (url.pathname === '/oidc/token') {
        const form = new URLSearchParams(await readBody(request));
        const organization = form.get('organization_id');
        const resource = form.get('resource');
        const responseCase = resource?.startsWith('https://case.example/')
          ? resource.slice('https://case.example/'.length)
          : undefined;
        const access =
          responseCase === 'access-equal'
            ? 'private-shared-credential'
            : organization
              ? signed({
                  iss: `${admin.origin}/oidc`,
                  sub: 'runtime-admin',
                  aud: 'urn:logto:organization:t-default',
                  client_id: 'admin-console',
                  scope: '',
                })
              : resource
                ? signed({
                    iss: `${admin.origin}/oidc`,
                    sub: 'runtime-admin',
                    aud: resource,
                    client_id: 'admin-console',
                    scope: 'all',
                  })
                : 'initial-opaque';
        const refresh =
          responseCase === 'missing'
            ? undefined
            : responseCase === 'duplicate'
              ? 'private-refresh-0'
              : responseCase === 'access-equal'
                ? access
                : responseCase === 'unknown-parent'
                  ? 'private-refresh-unknown'
                  : organization
                    ? 'private-refresh-2'
                    : resource
                      ? 'private-refresh-1'
                      : 'private-refresh-0';
        json(response, {
          access_token: access,
          ...(refresh ? { refresh_token: refresh } : {}),
          id_token: 'private-id',
          scope: organization
            ? ''
            : resource
              ? 'all'
              : 'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all',
        });
        return;
      }
      if (url.pathname === '/api/my-account/') {
        json(response, {
          id: 'runtime-admin',
          username: 'runtime-admin-name',
          primaryEmail: 'runtime-admin@example.com',
        });
        return;
      }
      response.writeHead(404);
      response.end();
    });
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${core.origin}/`,
      adminUrl: `${admin.origin}/`,
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium);

    try {
      const result = await observer.runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          const configuration = {
            appId: 'runtime-browser',
            prompt: 'login consent',
            scope: 'profile runtime-read',
            resource: 'runtime-api',
          };
          await session.preloadDemoConfiguration('preload', 'profile-config', configuration);
          await session.navigate('navigate', 'admin', '/demo-app');
          await session.waitForExactRoute('exact-route', 'admin', '/demo-app');
          await session.navigate('query-route', 'admin', '/demo-app?unexpected=1#fragment');
          await expect(
            session.assertExactRoute('reject-query-route', 'admin', '/demo-app')
          ).rejects.toMatchObject({ errorClass: 'evaluation' });
          await session.navigate('restore-route', 'admin', '/demo-app');
          await session.expectText('config', '#config', JSON.stringify(configuration));
          await session.expectText('scope-group', 'text="User Scopes"', 'User Scopes');
          await session.expectCount(
            'scope-items',
            'role=button[name="User Scopes"] >> xpath=following-sibling::ul/li',
            2
          );
          const projection = await session.clickAndObserveObject('console', '#emit', (value) => {
            if (value.aud !== 'runtime-api' || value.scope !== 'runtime-read') {
              throw new Error('Invalid console value');
            }
            return { audience: 'logical-api', permission: 'logical-read' };
          });
          await session.click('requests', '#requests');
          const facts = await session.waitForNetworkFacts(
            'network',
            (candidate) =>
              candidate.signIns.length === 1 &&
              candidate.callbacks.length === 1 &&
              candidate.endpointDiscoveries.length === 1 &&
              candidate.exchanges.length === 3 &&
              candidate.accountReads.length === 1 &&
              candidate.applicationReads.length === 3 &&
              candidate.userReads.length === 1
          );
          await session.click('bad-requests', '#bad-requests');
          const controlledFacts = await session.waitForNetworkFacts(
            'controlled-network',
            (candidate) =>
              candidate.exchanges.length === 7 && candidate.endpointDiscoveries.length === 2
          );

          return {
            controls: controlledFacts.exchanges.slice(3),
            endpointControl: controlledFacts.endpointDiscoveries[1],
            facts,
            projection,
          };
        }
      );

      expect(result.projection).toEqual({ audience: 'logical-api', permission: 'logical-read' });
      expect(result.facts.signIns).toEqual([
        expect.objectContaining({
          authority: 'admin',
          status: 303,
          queryShapeExact: true,
          clientId: 'admin-console',
          responseType: 'code',
          pkceMethod: 'S256',
          stateFormatValid: true,
          challengeFormatValid: true,
        }),
      ]);
      expect(result.facts.callbacks).toEqual([
        expect.objectContaining({
          authority: 'admin',
          path: '/console/callback',
          status: 200,
          queryShapeExact: true,
          stateMatches: true,
          codePresent: true,
        }),
      ]);
      expect(result.facts.endpointDiscoveries).toEqual([
        expect.objectContaining({
          authority: 'admin',
          status: 200,
          queryShapeExact: true,
          accessAbsent: true,
          userOriginMatchesCore: true,
        }),
      ]);
      expect(result.facts.exchanges.map(({ kind }) => kind).toSorted()).toEqual([
        'initial',
        'management',
        'organization',
      ]);
      expect(
        result.facts.exchanges.every(
          ({ authority, requestShapeExact, requestCorrelationValid, replacementFresh, clientId }) =>
            authority === 'admin' &&
            requestShapeExact &&
            requestCorrelationValid &&
            replacementFresh &&
            clientId === 'admin-console'
        )
      ).toBe(true);
      expect(result.facts.accountReads[0]).toMatchObject({
        authority: 'admin',
        queryShapeExact: true,
        accessMatchesInitial: true,
        status: 200,
      });
      expect(
        result.facts.applicationReads.every(
          ({
            authority,
            queryShapeExact,
            originMatches,
            languageMatches,
            accessMatchesManagement,
          }) =>
            authority === 'core' &&
            queryShapeExact &&
            originMatches &&
            languageMatches &&
            accessMatchesManagement
        )
      ).toBe(true);
      expect(result.facts.userReads[0]).toMatchObject({
        authority: 'core',
        queryShapeExact: true,
        originMatches: true,
        languageMatches: true,
        accessMatchesManagement: true,
        rows: [{ username: 'runtime-username', lastSignInState: 'never' }],
      });
      expect(
        result.controls.map(({ requestCorrelationValid, replacementFresh }) => ({
          requestCorrelationValid,
          replacementFresh,
        }))
      ).toEqual([
        { requestCorrelationValid: true, replacementFresh: false },
        { requestCorrelationValid: true, replacementFresh: false },
        { requestCorrelationValid: true, replacementFresh: false },
        { requestCorrelationValid: false, replacementFresh: true },
      ]);
      expect(result.endpointControl).toMatchObject({ accessAbsent: false });
      expect(JSON.stringify(result)).not.toMatch(/private-(?:code|refresh|id)|initial-opaque/u);
    } finally {
      await Promise.all([core.close(), admin.close()]);
    }
  });

  it('rejects non-object console output and off-route credential entry with fixed errors', async () => {
    const server = await listen((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(
        '<input id="field" /><button id="emit-string" onclick="console.log(\'private-token\')">emit</button>'
      );
    });
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${server.origin}/`,
      adminUrl: `${server.origin}/`,
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium);

    try {
      await observer.runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('other', 'core', '/other');
          await expect(
            session.fill('blocked-fill', '#field', 'private-password', {
              endpoint: 'core',
              paths: ['/demo-app'],
            })
          ).rejects.toMatchObject({ errorClass: 'evaluation', stepId: 'blocked-fill' });
          let error: unknown;
          try {
            await session.clickAndObserveObject('string', '#emit-string', (value) => value);
          } catch (error_: unknown) {
            error = error_;
          }
          expect(error).toMatchObject({ errorClass: 'console-event', stepId: 'string' });
          expect(`${String(error)} ${JSON.stringify(error)}`).not.toContain('private-token');
        }
      );
    } finally {
      await server.close();
    }
  });

  it.each([
    [
      'external HTTP',
      '<button id="attempt" onclick="fetch(\'http://127.0.0.1:1/private-token\').catch(() => {})">attempt</button>',
    ],
    [
      'an additional page',
      '<button id="attempt" onclick="window.open(\'about:blank\')">attempt</button>',
    ],
    [
      'a WebSocket',
      '<button id="attempt" onclick="new WebSocket(\'ws://127.0.0.1:1/private-token\')">attempt</button>',
    ],
  ])('fails the whole context after %s outbound attempt', async (_name, markup) => {
    const server = await listen((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(markup);
    });
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${server.origin}/`,
      adminUrl: `${server.origin}/`,
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium);

    try {
      const run = observer.runInFreshContext(
        'experience',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('guard-page', 'core', '/');
          await session.click('guard-attempt', '#attempt');
          await session.waitForNetworkFacts('guard-check', () => false);
        }
      );
      let error: unknown;

      try {
        await run;
      } catch (error_: unknown) {
        error = error_;
      }
      expect(error).toMatchObject({ errorClass: 'browser-process', stepId: 'experience' });
      expect(`${String(error)} ${JSON.stringify(error)}`).not.toContain('private-token');
    } finally {
      await server.close();
    }
  });

  it('starts the next real context without cookies, storage, or cache after a failed group', async () => {
    const server = await listen((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(`<!doctype html>
        <button id="seed" onclick="(async () => {
          document.cookie = 'phase1-private-cookie=present; path=/';
          localStorage.setItem('phase1-private-local', 'present');
          sessionStorage.setItem('phase1-private-session', 'present');
          const cache = await caches.open('phase1-private-cache');
          await cache.put('/phase1-private-entry', new Response('present'));
          console.log({ seeded: true });
        })()">seed</button>
        <button id="inspect" onclick="(async () => {
          const clean = document.cookie === '' &&
            localStorage.getItem('phase1-private-local') === null &&
            sessionStorage.getItem('phase1-private-session') === null &&
            (await caches.keys()).length === 0;
          console.log({ clean });
        })()">inspect</button>`);
    });
    const target: TargetConfig = Object.freeze({
      label: 'oracle',
      coreUrl: `${server.origin}/`,
      adminUrl: `${server.origin}/`,
    });
    const observer = createPlaywrightBrowserGroupObserver(chromium);

    try {
      await expect(
        observer.runInFreshContext(
          'experience',
          new AbortController().signal,
          target,
          async (session) => {
            await session.navigate('seed-state', 'core', '/');
            await session.clickAndObserveObject('seed-state', '#seed', (value) => {
              if (value.seeded !== true) {
                throw new Error('Synthetic state seed failed');
              }
              return { seeded: true };
            });
            throw new Error('Synthetic middle-flow failure');
          }
        )
      ).rejects.toMatchObject({ errorClass: 'browser-process' });

      const clean = await observer.runInFreshContext(
        'console',
        new AbortController().signal,
        target,
        async (session) => {
          await session.navigate('inspect-state', 'core', '/');
          return session.clickAndObserveObject('inspect-state', '#inspect', (value) => {
            if (value.clean !== true) {
              throw new Error('Browser context retained state');
            }
            return { clean: true };
          });
        }
      );

      expect(clean).toEqual({ clean: true });
    } finally {
      await server.close();
    }
  });
});

/* eslint-enable complexity, max-lines, max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
