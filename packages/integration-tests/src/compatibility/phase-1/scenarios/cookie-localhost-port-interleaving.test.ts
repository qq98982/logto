/* eslint-disable max-lines, complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- The focused localhost harness owns ephemeral servers, lifecycle controls, and browser-visible cookie authority without exposing cookie values. */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createRequire } from 'node:module';

import type { Browser, BrowserType } from '@playwright/test';

import { SymbolTable } from '../../symbol-table.js';
import { MemoryProtocolSecretStore } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runCookieLocalhostPortInterleaving } from './cookie-localhost-port-interleaving.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

type TenantRole = 'admin' | 'data';

type TenantServer = Readonly<{
  origin: string;
  observations: readonly string[];
  close(): Promise<void>;
}>;
type TenantServerOptions = Readonly<{
  poisonPageFetchBody?: boolean;
  leakEncodedCookieAttribute?: boolean;
  leakCookieCredentialHeader?: boolean;
  signInRedirectUrl?: string;
  registeredRedirectUri?: string;
  authorizationRedirectUri?: 'registered' | 'runtime';
}>;
type TenantServerFactory = (
  role: TenantRole,
  applicationId: string,
  options?: TenantServerOptions
) => Promise<TenantServer>;

const absentClientSecrets = new Map<string, string>();
const noClientSecret = (logicalId: string): string | undefined =>
  absentClientSecrets.get(logicalId);

const requestBody = async (request: IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];

    request.on('data', (chunk: Uint8Array | string) => {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    });
    request.once('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    request.once('error', reject);
  });

const cookieMap = (request: IncomingMessage): ReadonlyMap<string, string> =>
  new Map(
    (request.headers.cookie ?? '')
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf('=');

        return Object.freeze(
          separator < 1
            ? (['', ''] as const)
            : ([part.slice(0, separator), part.slice(separator + 1)] as const)
        );
      })
      .filter(([name]) => name.length > 0)
  );

const json = (response: ServerResponse, status: number, body: unknown): void => {
  response.statusCode = status;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.end(JSON.stringify(body));
};

const listen = async (
  role: TenantRole,
  applicationId: string,
  options: TenantServerOptions = {}
): Promise<TenantServer> => {
  const observations: string[] = [];
  let interactionSequence = 0;
  let activeSignature = '';
  let activeInteraction = '';
  const hasAuthority = (request: IncomingMessage): boolean => {
    const cookies = cookieMap(request);

    return (
      cookies.get('_interaction.sig') === activeSignature &&
      cookies.get('_interaction')?.includes(encodeURIComponent(applicationId)) === true &&
      request.headers['logto-app-id'] === applicationId
    );
  };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');

    if (request.method === 'GET' && url.pathname === '/oidc/auth') {
      const runtimeRedirectUri = `${origin}${role === 'admin' ? '/console/callback' : '/demo-app'}`;
      const registeredRedirectUri = options.registeredRedirectUri ?? runtimeRedirectUri;
      const expectedRedirectUri =
        options.authorizationRedirectUri === 'runtime' ? runtimeRedirectUri : registeredRedirectUri;

      if (url.searchParams.get('redirect_uri') !== expectedRedirectUri) {
        json(response, 400, { code: 'oidc.invalid_redirect_uri' });
        return;
      }
      interactionSequence += 1;
      activeInteraction = `${role}-interaction-${interactionSequence}`;
      activeSignature = `${role}-signature-${interactionSequence}`;
      const interaction = encodeURIComponent(
        JSON.stringify({ [applicationId]: activeInteraction, _legacy: activeInteraction })
      );

      response.statusCode = 303;
      response.setHeader('location', '/sign-in');
      const includeLeakCookie = Boolean(
        options.leakEncodedCookieAttribute ?? options.leakCookieCredentialHeader
      );
      response.setHeader('set-cookie', [
        `_interaction=${interaction}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`,
        `_interaction.sig=${activeSignature}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`,
        `_logto=${encodeURIComponent(JSON.stringify({ appId: applicationId }))}; Path=/; SameSite=Lax; Max-Age=600`,
        `_interaction_resume=${activeInteraction}; Path=/oidc/auth/${activeInteraction}; HttpOnly; SameSite=Lax; Max-Age=600`,
        `_interaction_resume.sig=${activeSignature}; Path=/oidc/auth/${activeInteraction}; HttpOnly; SameSite=Lax; Max-Age=600`,
        ...(includeLeakCookie
          ? [
              `_leak=${encodeURIComponent(encodeURIComponent('/browser-cookie-secret-private'))}; Path=/browser-cookie-secret-private; HttpOnly; SameSite=Lax; Max-Age=600`,
            ]
          : []),
      ]);
      if (options.leakCookieCredentialHeader) {
        response.setHeader('x-cookie-leak', '/browser-cookie-secret-private');
      }
      const redirectBody = 'Redirecting to <a href="/sign-in">/sign-in</a>.';
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.setHeader('content-length', String(Buffer.byteLength(redirectBody)));
      response.end(redirectBody);
      return;
    }

    if (request.method === 'GET' && url.pathname === '/sign-in') {
      if (options.signInRedirectUrl) {
        response.statusCode = 303;
        response.setHeader('location', options.signInRedirectUrl);
        response.end();
        return;
      }
      response.statusCode = 200;
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end(
        options.poisonPageFetchBody
          ? `<!doctype html><title>Sign in</title><script>
              const nativeFetch = window.fetch.bind(window);
              window.fetch = async (...args) => {
                const result = await nativeFetch(...args);
                return new Response(result.status === 204 ? null : '{"poisoned":true}', {
                  status: result.status,
                  statusText: result.statusText,
                  headers: result.headers,
                });
              };
            </script>`
          : '<!doctype html><title>Sign in</title>'
      );
      return;
    }

    if (request.method === 'PUT' && url.pathname === '/api/experience') {
      await requestBody(request);
      if (!hasAuthority(request)) {
        observations.push('prepare-rejected');
        json(response, 400, { code: 'session.not_found' });
        return;
      }
      observations.push('prepared');
      response.statusCode = 204;
      response.end();
      return;
    }

    if (request.method === 'POST' && url.pathname === '/api/experience/verification/password') {
      await requestBody(request);
      if (!hasAuthority(request)) {
        observations.push('finish-rejected');
        response.setHeader('set-cookie', '_interaction.sig=; Path=/; Max-Age=0; HttpOnly');
        json(response, 400, { code: 'session.not_found' });
        return;
      }
      observations.push('password-accepted');
      json(response, 200, { verificationId: `${role}-verification` });
      return;
    }

    if (request.method === 'POST' && url.pathname === '/api/experience/identification') {
      await requestBody(request);
      if (!hasAuthority(request)) {
        json(response, 400, { code: 'session.not_found' });
        return;
      }
      observations.push('identified');
      response.statusCode = 204;
      response.end();
      return;
    }

    if (request.method === 'POST' && url.pathname === '/api/experience/submit') {
      if (!hasAuthority(request)) {
        json(response, 400, { code: 'session.not_found' });
        return;
      }
      observations.push('submitted');
      json(response, 200, { redirectTo: `${origin}/oidc/auth/${activeInteraction}` });
      return;
    }

    response.statusCode = 404;
    response.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, 'localhost', resolve);
  });
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Failed to create localhost fixture server');
  }
  const origin = `http://localhost:${address.port}`;

  return Object.freeze({
    origin,
    observations,
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

const listenForeign = async (): Promise<
  Readonly<{ origin: string; passwordBodies: readonly string[]; close(): Promise<void> }>
> => {
  const passwordBodies: string[] = [];
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');

    if (request.method === 'GET' && url.pathname === '/sign-in') {
      response.statusCode = 200;
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<!doctype html><title>Foreign sign in</title>');
      return;
    }
    if (request.method === 'PUT' && url.pathname === '/api/experience') {
      await requestBody(request);
      response.statusCode = 204;
      response.end();
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/experience/verification/password') {
      passwordBodies.push(await requestBody(request));
      json(response, 400, { code: 'session.not_found' });
      return;
    }

    response.statusCode = 404;
    response.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, 'localhost', resolve);
  });
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Failed to create foreign fixture server');
  }

  return Object.freeze({
    origin: `http://localhost:${address.port}`,
    passwordBodies,
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

const createTenantServers = async (
  adminApplicationId: string,
  dataApplicationId: string,
  options: Readonly<{ admin?: TenantServerOptions; data?: TenantServerOptions }> = {},
  createServer: TenantServerFactory = listen
): Promise<Readonly<{ admin: TenantServer; data: TenantServer }>> => {
  const admin = await createServer('admin', adminApplicationId, options.admin);

  try {
    const data = await createServer('data', dataApplicationId, options.data);

    return Object.freeze({ admin, data });
  } catch (error: unknown) {
    await admin.close();
    throw error;
  }
};

const fixture = (
  adminApplicationId: string,
  dataApplicationId: string
): Phase1ScenarioRunContext['fixture'] =>
  ({
    public: {
      schemaVersion: 1,
      recipe: 'fullPhase1',
      allocations: [
        {
          allocationId: 'data-allocation',
          role: 'data',
          target: 'primary',
          isolation: {
            persistenceId: 'data-persistence',
            cookieKeyId: 'data-cookie-key',
            signingKeyId: 'data-signing-key',
          },
          entities: [
            { kind: 'tenant', logicalId: 'default', runtimeId: 'default' },
            { kind: 'user', logicalId: 'phase1-user', runtimeId: 'data-user-runtime' },
            {
              kind: 'application',
              logicalId: 'phase1-app',
              runtimeId: 'data-first-party-runtime',
            },
            {
              kind: 'application',
              logicalId: 'phase1-browser',
              runtimeId: dataApplicationId,
            },
          ],
        },
        {
          allocationId: 'admin-allocation',
          role: 'admin',
          target: 'primary',
          isolation: {
            persistenceId: 'admin-persistence',
            cookieKeyId: 'admin-cookie-key',
            signingKeyId: 'admin-signing-key',
          },
          entities: [
            { kind: 'tenant', logicalId: 'admin', runtimeId: 'admin' },
            { kind: 'user', logicalId: 'phase1-admin', runtimeId: 'admin-user-runtime' },
            {
              kind: 'application',
              logicalId: 'admin-console',
              runtimeId: adminApplicationId,
            },
          ],
        },
      ],
    },
    withSecretLease: async (use: (lease: never) => Promise<unknown>) =>
      use({
        getPassword: (logicalId: string) =>
          logicalId === 'phase1-admin' ? 'admin-password-private' : 'data-password-private',
        getClientSecret: noClientSecret,
        toJSON: () => {
          throw new TypeError('secret lease is not serializable');
        },
      } as never),
  }) as Phase1ScenarioRunContext['fixture'];

describe('cookie.localhost-port-interleaving', () => {
  it.each([
    [
      'matches same-host cross-port overwrite effects without cross-tenant authority',
      {},
      false,
      false,
    ],
    [
      'uses captured network response bodies despite a poisoned page fetch wrapper',
      { admin: { poisonPageFetchBody: true }, data: { poisonPageFetchBody: true } },
      false,
      false,
    ],
    [
      'uses the registered logical data redirect URI while browsing the runtime core origin',
      { data: { registeredRedirectUri: 'http://localhost:3001/demo-app' } },
      false,
      false,
    ],
    [
      'preserves the exact registered data redirect URI bytes',
      { data: { registeredRedirectUri: 'http://localhost:3001' } },
      false,
      false,
    ],
    [
      'rebinds the logical admin redirect path to the runtime admin origin',
      {
        admin: {
          registeredRedirectUri: 'http://localhost:3002/console/callback',
          authorizationRedirectUri: 'runtime',
        },
      },
      false,
      false,
    ],
    [
      'redacts a multi-encoded cookie credential copied into an attribute',
      { admin: { leakEncodedCookieAttribute: true } },
      false,
      false,
    ],
    [
      'rejects a decoded cookie credential copied into a response header',
      { admin: { leakCookieCredentialHeader: true } },
      true,
      false,
    ],
    ['blocks a cross-origin sign-in redirect before sending a password request', {}, false, true],
  ] as const)('%s', async (_name, serverOptions, expectLeakRejection, crossOriginRedirect) => {
    const adminApplicationId = 'admin-console';
    const dataApplicationId = 'data-client-runtime';
    const foreign = crossOriginRedirect ? await listenForeign() : undefined;
    const effectiveServerOptions: Readonly<{
      admin?: TenantServerOptions;
      data?: TenantServerOptions;
    }> = foreign ? { admin: { signInRedirectUrl: `${foreign.origin}/sign-in` } } : serverOptions;
    const { admin, data } = await createTenantServers(
      adminApplicationId,
      dataApplicationId,
      effectiveServerOptions
    ).catch(async (error: unknown) => {
      await foreign?.close();
      throw error;
    });

    try {
      const adminRedirectUri =
        effectiveServerOptions.admin?.registeredRedirectUri ?? `${admin.origin}/console/callback`;
      const dataRedirectUri =
        effectiveServerOptions.data?.registeredRedirectUri ?? `${data.origin}/demo-app`;
      const adminSymbols = new SymbolTable();
      const dataSymbols = new SymbolTable();
      adminSymbols.bind('application.admin-console', adminApplicationId);
      adminSymbols.bind('user.phase1-admin', 'admin-user-runtime');
      dataSymbols.bind('application.phase1-browser', dataApplicationId);
      dataSymbols.bind('user.phase1-user', 'data-user-runtime');
      const stores = {
        admin: new MemoryProtocolSecretStore(),
        data: new MemoryProtocolSecretStore(),
      };
      const provisioned = fixture(adminApplicationId, dataApplicationId);
      const context: Phase1ScenarioRunContext = {
        profile: {
          localhostCookiePortContract: {
            browserRule: 'same hostname cookies ignore TCP port',
            compatibilityRule: 'preserve cookie metadata',
            keyIsolation: 'distinct signing keys fail closed',
            interleavings: ['admin then data', 'data then admin'],
            requiredOutcome: 'no cross-tenant authority',
          },
          fixtures: {
            adminTenant: {
              id: 'admin',
              operator: { id: 'phase1-admin', username: 'phase1-admin' },
              application: {
                id: 'admin-console',
                oidcClientMetadata: { redirectUris: [adminRedirectUri] },
              },
            },
            dataTenant: {
              id: 'default',
              subject: { id: 'phase1-user', username: 'phase1-user' },
              applications: [
                {
                  id: 'phase1-browser',
                  isThirdParty: true,
                  oidcClientMetadata: { redirectUris: [dataRedirectUri] },
                },
              ],
              browserClientConfiguration: {
                localStorageValue: {
                  appId: 'phase1-browser',
                  prompt: 'login consent',
                  scope: 'profile email',
                },
              },
              resource: { scopes: [] },
            },
          },
          consoleAuthentication: {
            applicationId: adminApplicationId,
            redirectUri: adminRedirectUri,
            prompt: ['login'],
            effectiveScopes: ['openid', 'profile'],
            effectiveResources: [],
          },
          oidc: { authorizationPath: '/oidc/auth' },
        } as never,
        target: { label: 'oracle', coreUrl: `${data.origin}/`, adminUrl: `${admin.origin}/` },
        fixture: provisioned,
        signal: new AbortController().signal,
        protocol: {
          publicOidc: {} as never,
          publicSymbols: new SymbolTable(),
          forAllocation: (role) => {
            const store = stores[role === 'admin' ? 'admin' : 'data'];

            return {
              oidc: { store } as never,
              experience: { store } as never,
              consent: { store } as never,
              management: { store } as never,
              account: { store } as never,
              state: { store } as never,
            };
          },
          symbolsFor: (allocationId) =>
            allocationId === 'admin-allocation'
              ? adminSymbols
              : allocationId === 'data-allocation'
                ? dataSymbols
                : undefined,
        },
        projectFixtureState: async () => ({
          schemaVersion: 1,
          recipe: 'fullPhase1',
          allocations: [],
        }),
        projectScenarioState: async ({ stepId }) => {
          const semanticState =
            stepId === 'state'
              ? {
                  admin: { overwrittenAttempt: 'rejected', currentAttempt: 'success' },
                  data: { overwrittenAttempt: 'rejected', currentAttempt: 'success' },
                  crossTenantAuthority: false,
                }
              : { stepId };

          return {
            body: { stepId },
            semanticState,
            persistedState: { crossTenantMutation: false },
            generatedIds: {},
            sideEffects: { crossTenantMutation: false },
          } as never;
        },
      };

      if (expectLeakRejection) {
        await expect(
          runCookieLocalhostPortInterleaving(context, { browserType: chromium })
        ).rejects.toThrow(
          'Playwright observation failed: cookie.localhost-port-interleaving/admin-start/evaluation'
        );
        return;
      }
      if (crossOriginRedirect) {
        await expect(
          runCookieLocalhostPortInterleaving(context, { browserType: chromium })
        ).rejects.toThrow(
          'Playwright observation failed: cookie.localhost-port-interleaving/admin-start/navigation'
        );
        expect(foreign?.passwordBodies).toEqual([]);
        return;
      }
      const steps = await runCookieLocalhostPortInterleaving(context, { browserType: chromium });

      expect(steps.map(({ stepId }) => stepId)).toEqual([
        'admin-start',
        'data-start',
        'admin-finish',
        'data-finish',
        'data-start-reverse',
        'admin-start-reverse',
        'data-finish-reverse',
        'admin-finish-reverse',
        'state',
      ]);
      expect(steps.map(({ value }) => value.status)).toEqual([
        303, 303, 400, 200, 303, 303, 400, 200, 200,
      ]);
      expect(steps[2]?.value.error).toEqual({ error: 'invalid_request' });
      expect(steps[2]?.value.outcomes).toEqual([{ authority: 'rejected' }]);
      expect(steps[2]?.value.cookies.map(({ name }) => name)).toEqual(['_interaction.sig']);
      expect(steps[3]?.value.outcomes).toEqual([{ authority: 'accepted' }]);
      expect(steps[6]?.value.error).toEqual({ error: 'invalid_request' });
      expect(steps[6]?.value.outcomes).toEqual([{ authority: 'rejected' }]);
      expect(steps[7]?.value.outcomes).toEqual([{ authority: 'accepted' }]);
      expect(admin.observations).toEqual([
        'prepared',
        'finish-rejected',
        'prepared',
        'password-accepted',
        'identified',
        'submitted',
      ]);
      expect(data.observations).toEqual([
        'prepared',
        'password-accepted',
        'identified',
        'submitted',
        'prepared',
        'finish-rejected',
      ]);
      expect(steps[0]?.value.cookies.map(({ name }) => name)).toEqual([
        '_interaction',
        '_interaction.sig',
        '_logto',
        '_interaction_resume',
        '_interaction_resume.sig',
        ...('admin' in effectiveServerOptions &&
        effectiveServerOptions.admin?.leakEncodedCookieAttribute
          ? ['_leak']
          : []),
      ]);
      expect(steps[8]?.value.semanticState).toMatchObject({
        admin: { overwrittenAttempt: 'rejected', currentAttempt: 'success' },
        data: { overwrittenAttempt: 'rejected', currentAttempt: 'success' },
        crossTenantAuthority: false,
      });
      expect(JSON.stringify(steps)).not.toMatch(
        /admin-signature|data-signature|interaction-\d|password-private|verification|browser-cookie-secret-private/u
      );
    } finally {
      await Promise.all([admin.close(), data.close(), ...(foreign ? [foreign.close()] : [])]);
    }
  });

  it('closes the first server when the second server initialization fails', async () => {
    const close = import.meta.jest.fn(async (): Promise<void> => {
      // The lifecycle assertion only needs an observable close capability.
    });
    const createServer: TenantServerFactory = import.meta.jest.fn(async (role) => {
      if (role === 'data') {
        throw new Error('data initialization failed');
      }

      return { origin: 'http://localhost:3101', observations: [], close };
    });

    await expect(
      createTenantServers('admin-console', 'data-client', {}, createServer)
    ).rejects.toThrow('data initialization failed');
    expect(createServer).toHaveBeenCalledTimes(2);
    expect(close).toHaveBeenCalledTimes(1);
  });
});

/* eslint-enable max-lines, complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
