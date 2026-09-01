/* eslint-disable @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines -- Transport tests retain unknown rejections and record server-observed request/cookie state across the complete raw-client boundary. */
import { createServer, type Server } from 'node:http';

import { AccountClient } from './account.js';
import { ConsentClient } from './consent.js';
import { ExperienceClient } from './experience.js';
import { ManagementClient } from './management.js';
import { MemoryProtocolSecretStore, OidcClient, ProtocolClientError } from './oidc.js';
import { StateClient } from './state.js';

const fixture = (...roles: Array<'data' | 'admin' | 'foreign'>) => ({
  public: { allocations: roles.map((role) => ({ role })) },
});

const encodeAll = (value: string) =>
  Buffer.from(value, 'utf8')
    .toString('hex')
    .match(/.{2}/gu)
    ?.map((byte) => `%${byte}`)
    .join('') ?? '';

const listen = async (server: Server): Promise<number> => {
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve();
    });
  });
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('server unavailable');
  }

  return address.port;
};

const close = async (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });

describe('phase 1 raw protocol client', () => {
  it('reads public OIDC metadata from core with a none fixture and never selects credentials', async () => {
    const coreRequests: Array<Readonly<{ url: string; authorization?: string; cookie?: string }>> =
      [];
    const adminRequests: string[] = [];
    const coreServer = createServer((request, response) => {
      coreRequests.push({
        url: request.url ?? '',
        ...(typeof request.headers.authorization === 'string' && {
          authorization: request.headers.authorization,
        }),
        ...(typeof request.headers.cookie === 'string' && { cookie: request.headers.cookie }),
      });
      response.setHeader('content-type', 'application/json');
      response.setHeader('set-cookie', 'unexpected=private-response-cookie; Path=/; HttpOnly');
      response.end('{"issuer":"public"}');
    });
    const adminServer = createServer((request, response) => {
      adminRequests.push(request.url ?? '');
      response.end('unexpected');
    });
    const corePort = await listen(coreServer);
    const adminPort = await listen(adminServer);
    const coreUrl = `http://127.0.0.1:${corePort}/`;
    const store = new MemoryProtocolSecretStore();
    store.setCookie('interaction=private-cookie; Path=/; HttpOnly', new URL(coreUrl));
    store.setToken('management', 'private-management-token');
    const getCookieHeader = import.meta.jest.spyOn(store, 'getCookieHeader');
    const setCookie = import.meta.jest.spyOn(store, 'setCookie');
    const getToken = import.meta.jest.spyOn(store, 'getToken');
    const client = new OidcClient({
      target: {
        label: 'oracle',
        coreUrl,
        adminUrl: `http://127.0.0.1:${adminPort}/`,
      },
      fixture: fixture(),
      store,
      signal: new AbortController().signal,
    });

    try {
      await expect(
        client.request('discovery', 'oidc/.well-known/openid-configuration', {
          includeCookies: true,
        })
      ).resolves.toMatchObject({ status: 200, body: '{"issuer":"public"}' });
      await expect(
        client.request('reject-authorization', 'oidc/jwks', {
          headers: { authorization: 'Bearer caller-controlled' },
        })
      ).rejects.toBeInstanceOf(ProtocolClientError);

      expect(coreRequests).toEqual([{ url: '/oidc/.well-known/openid-configuration' }]);
      expect(adminRequests).toEqual([]);
      expect(getCookieHeader).not.toHaveBeenCalled();
      expect(setCookie).not.toHaveBeenCalled();
      expect(getToken).not.toHaveBeenCalled();
      expect(client.allocationRole).toBeUndefined();
    } finally {
      getCookieHeader.mockRestore();
      setCookie.mockRestore();
      getToken.mockRestore();
      await Promise.all([close(coreServer), close(adminServer)]);
    }
  });

  it('requires allocationRole exactly when the fixture contains an allocation', () => {
    const common = {
      target: {
        label: 'oracle' as const,
        coreUrl: 'http://127.0.0.1:3001/',
        adminUrl: 'http://127.0.0.1:3002/',
      },
      store: new MemoryProtocolSecretStore(),
      signal: new AbortController().signal,
    };

    expect(() => new OidcClient({ ...common, fixture: fixture('data') })).toThrow(
      'Invalid protocol fixture allocation'
    );
    expect(() => new OidcClient({ ...common, fixture: fixture(), allocationRole: 'data' })).toThrow(
      'Invalid protocol fixture allocation'
    );
  });

  it('keeps cookies and tokens memory-only and returns duplicate raw headers to the closure', async () => {
    const server = createServer((_request, response) => {
      response.setHeader('x-repeat', ['one', 'two']);
      response.setHeader('set-cookie', ['session=private-cookie; Path=/; HttpOnly']);
      response.end('{"ok":true}');
    });
    const port = await listen(server);
    const store = new MemoryProtocolSecretStore();
    const client = new OidcClient({
      target: {
        label: 'oracle',
        coreUrl: `http://127.0.0.1:${port}/`,
        adminUrl: `http://127.0.0.1:${port}/`,
      },
      fixture: fixture('data'),
      allocationRole: 'data',
      store,
      signal: new AbortController().signal,
    });

    try {
      const response = await client.request('probe', 'probe');
      expect(response.status).toBe(200);
      expect(response.headers.filter(([name]) => name === 'set-cookie')).toHaveLength(1);
      store.setToken('access', 'private-token');
      expect(() => JSON.stringify(store)).toThrow('Protocol secret store is not serializable');
      expect(() => {
        store.assertNoCredentialMaterial({ note: 'prefix private-cookie suffix' });
      }).toThrow('Protocol output contains credential material');
      expect(() => {
        store.assertNoCredentialMaterial({ note: 'prefix private-token suffix' });
      }).toThrow('Protocol output contains credential material');
      expect(() => {
        store.assertNoCredentialMaterial({ note: 'safe projection' });
      }).not.toThrow();
    } finally {
      await close(server);
    }
  });

  it('rejects bounded iterative URI and percent-normalized credential variants', () => {
    const store = new MemoryProtocolSecretStore();
    const secret = 'private:/password?value=%2f';
    store.registerSecret(secret);

    for (const leaked of [
      encodeURIComponent(secret),
      encodeURIComponent(encodeURIComponent(secret)),
      encodeAll(secret),
      encodeAll(secret).toLowerCase(),
      `prefix ${encodeAll(encodeURIComponent(secret))} suffix`,
    ]) {
      expect(() => {
        store.assertNoCredentialMaterial({ note: leaked });
      }).toThrow('Protocol output contains credential material');
    }
    expect(() => {
      store.assertNoCredentialMaterial({ note: 'safe projection' });
    }).not.toThrow();
  });

  it('keeps exact matching for oversized and malformed URI inputs without unbounded expansion', () => {
    const store = new MemoryProtocolSecretStore();
    const oversized = `private-${'x'.repeat(64 * 1024)}`;
    const malformed = 'private-\uD800';

    expect(() => {
      store.registerSecret(oversized);
    }).not.toThrow();
    expect(() => {
      store.registerSecret(malformed);
    }).not.toThrow();
    expect(() => {
      store.assertNoCredentialMaterial({ oversized });
    }).toThrow('Protocol output contains credential material');
    expect(() => {
      store.assertNoCredentialMaterial({ malformed });
    }).toThrow('Protocol output contains credential material');
  });

  it('shares a host cookie across ports while keeping it out of serializable state', async () => {
    const cookieSource = createServer((_request, response) => {
      response.setHeader('set-cookie', 'interaction=private-cookie; Path=/; HttpOnly');
      response.end('source');
    });
    let observedCookie: string | undefined;
    const cookieTarget = createServer((request, response) => {
      observedCookie = request.headers.cookie;
      response.end('target');
    });
    const sourcePort = await listen(cookieSource);
    const targetPort = await listen(cookieTarget);
    const store = new MemoryProtocolSecretStore();
    const createClient = (port: number) =>
      new OidcClient({
        target: {
          label: 'oracle',
          coreUrl: `http://127.0.0.1:${port}/`,
          adminUrl: `http://127.0.0.1:${port}/`,
        },
        fixture: fixture('data'),
        allocationRole: 'data',
        store,
        signal: new AbortController().signal,
      });

    try {
      await createClient(sourcePort).request('source', 'source');
      await createClient(targetPort).request('target', 'target');
      expect(observedCookie).toBe('interaction=private-cookie');
      expect(() => JSON.stringify(store)).toThrow('Protocol secret store is not serializable');
    } finally {
      await Promise.all([close(cookieSource), close(cookieTarget)]);
    }
  });

  it('derives fresh interaction cookie variants without exposing the source credentials', () => {
    const sourceUrl = new URL('http://source.example/consent');
    const targetUrl = new URL('http://target.example/api/interaction/consent');
    const source = new MemoryProtocolSecretStore();
    const peer = new MemoryProtocolSecretStore();
    source.setCookie('_interaction=source-private; Path=/; HttpOnly', sourceUrl);
    source.setCookie('_interaction.sig=source-signature-private; Path=/; HttpOnly', sourceUrl);
    peer.setCookie('_interaction=peer-private; Path=/; HttpOnly', sourceUrl);
    peer.setCookie('_interaction.sig=peer-signature-private; Path=/; HttpOnly', sourceUrl);

    const exact = source.deriveInteractionCookieStore(sourceUrl, targetUrl, 'exact');
    const partial = source.deriveInteractionCookieStore(sourceUrl, targetUrl, 'partial');
    const tampered = source.deriveInteractionCookieStore(sourceUrl, targetUrl, 'tampered');
    const spliced = source.deriveInteractionCookieStore(sourceUrl, targetUrl, 'spliced', peer);

    expect(() => source.deriveInteractionCookieStore(sourceUrl, targetUrl, 'spliced')).toThrow(
      'Invalid protocol cookie derivation'
    );
    expect(() =>
      source.deriveInteractionCookieStore(sourceUrl, targetUrl, 'spliced', source)
    ).toThrow('Invalid protocol cookie derivation');

    expect(exact.getCookieHeader(targetUrl)).toBe(
      '_interaction=source-private; _interaction.sig=source-signature-private'
    );
    expect(partial.getCookieHeader(targetUrl)).toBe('_interaction=source-private');
    expect(tampered.getCookieHeader(targetUrl)).toBe(
      '_interaction=source-private~; _interaction.sig=source-signature-private'
    );
    expect(spliced.getCookieHeader(targetUrl)).toBe(
      '_interaction=source-private; _interaction.sig=peer-signature-private'
    );
    expect(source.getCookieHeader(sourceUrl)).toBe(
      '_interaction=source-private; _interaction.sig=source-signature-private'
    );
    for (const derived of [exact, partial, tampered, spliced]) {
      expect(derived).not.toBe(source);
      expect(derived).not.toBe(peer);
      expect(() => JSON.stringify(derived)).toThrow('Protocol secret store is not serializable');
    }
  });

  it('rejects origin and namespace escapes before selecting or attaching credentials', async () => {
    const trustedRequests: Array<Readonly<Record<string, string | undefined>>> = [];
    const crossOriginRequests: Array<Readonly<Record<string, string | undefined>>> = [];
    const recordRequest = (requests: Array<Readonly<Record<string, string | undefined>>>) =>
      createServer((request, response) => {
        requests.push({
          url: request.url,
          authorization: request.headers.authorization,
          cookie: request.headers.cookie,
        });
        response.end('unexpected request');
      });
    const trustedServer = recordRequest(trustedRequests);
    const crossOriginServer = recordRequest(crossOriginRequests);
    const trustedPort = await listen(trustedServer);
    const crossOriginPort = await listen(crossOriginServer);
    const trustedUrl = `http://127.0.0.1:${trustedPort}/`;
    const store = new MemoryProtocolSecretStore();

    store.setCookie('interaction=private-cookie; Path=/; HttpOnly', new URL(trustedUrl));
    store.setToken('account', 'private-account-token');
    store.setToken('management', 'private-management-token');
    const getCookieHeader = import.meta.jest.spyOn(store, 'getCookieHeader');
    const getToken = import.meta.jest.spyOn(store, 'getToken');
    const options = {
      target: {
        label: 'oracle' as const,
        coreUrl: trustedUrl,
        adminUrl: trustedUrl,
      },
      fixture: fixture('data', 'admin'),
      store,
      signal: new AbortController().signal,
    };
    const dataOptions = { ...options, allocationRole: 'data' as const };
    const adminOptions = { ...options, allocationRole: 'admin' as const };
    const clients = [
      async (path: string) => new OidcClient(dataOptions).request('reject-path', path),
      async (path: string) =>
        new ExperienceClient(dataOptions).requestExperience('reject-path', path),
      async (path: string) => new ConsentClient(dataOptions).requestConsent('reject-path', path),
      async (path: string) => new AccountClient(adminOptions).requestAccount('reject-path', path),
      async (path: string) =>
        new ManagementClient(adminOptions).requestManagement('reject-path', path),
      async (path: string) => new StateClient(adminOptions).requestState('reject-path', path),
    ];
    const escapePaths = [
      `http://127.0.0.1:${crossOriginPort}/capture`,
      `//127.0.0.1:${crossOriginPort}/capture`,
      `http://user@127.0.0.1:${crossOriginPort}/capture`,
      `\\\\127.0.0.1:${crossOriginPort}\\capture`,
      '/capture',
      '../capture',
    ];

    try {
      const results = await Promise.all(
        clients.flatMap((request) =>
          escapePaths.map(async (path) => request(path).catch((error: unknown) => error))
        )
      );

      for (const result of results) {
        expect(result).toBeInstanceOf(ProtocolClientError);
        expect(String(result)).toBe(
          'ProtocolClientError: Protocol client operation failed: reject-path'
        );
      }
      expect(getCookieHeader).not.toHaveBeenCalled();
      expect(getToken).not.toHaveBeenCalled();
      expect(trustedRequests).toEqual([]);
      expect(crossOriginRequests).toEqual([]);
    } finally {
      getCookieHeader.mockRestore();
      getToken.mockRestore();
      await Promise.all([close(trustedServer), close(crossOriginServer)]);
    }
  });

  it('rejects authority and forwarding headers before selecting stored credentials', async () => {
    const store = new MemoryProtocolSecretStore();
    const target = {
      label: 'candidate' as const,
      coreUrl: 'http://127.0.0.1:1/',
      adminUrl: 'http://127.0.0.1:1/',
    };
    store.setCookie('interaction=private-cookie; Path=/; HttpOnly', new URL(target.coreUrl));
    store.setToken('account', 'private-account-token');
    store.setToken('management', 'private-management-token');
    const getCookieHeader = import.meta.jest.spyOn(store, 'getCookieHeader');
    const getToken = import.meta.jest.spyOn(store, 'getToken');
    const dataOptions = {
      target,
      fixture: fixture('data'),
      allocationRole: 'data' as const,
      store,
      signal: new AbortController().signal,
    };
    const adminOptions = {
      ...dataOptions,
      fixture: fixture('admin'),
      allocationRole: 'admin' as const,
    };

    try {
      await Promise.all(
        [
          new OidcClient(dataOptions).request('host', 'oidc/token', {
            headers: { Host: 'attacker.example' },
          }),
          new AccountClient(adminOptions).requestAccount('host', 'my-account/', {
            headers: { 'X-Forwarded-Host': 'attacker.example' },
          }),
          new ManagementClient(adminOptions).requestManagement('host', 'applications', {
            headers: { Forwarded: 'host=attacker.example' },
          }),
        ].map(async (request) => expect(request).rejects.toBeInstanceOf(ProtocolClientError))
      );
      expect(getCookieHeader).not.toHaveBeenCalled();
      expect(getToken).not.toHaveBeenCalled();
    } finally {
      getCookieHeader.mockRestore();
      getToken.mockRestore();
    }
  });

  it('converts transport errors to fixed operation/status diagnostics', async () => {
    const secret = 'private-request-body';
    const client = new OidcClient({
      target: {
        label: 'candidate',
        coreUrl: 'http://127.0.0.1:1/',
        adminUrl: 'http://127.0.0.1:1/',
      },
      fixture: fixture('data'),
      allocationRole: 'data',
      store: new MemoryProtocolSecretStore(),
      signal: AbortSignal.timeout(100),
    });

    const error = await client
      .request('token', 'oidc/token', { body: secret })
      .catch((error_) => error_);
    expect(error).toBeInstanceOf(ProtocolClientError);
    expect(String(error)).not.toContain(secret);
    const unsafeOperation = new ProtocolClientError(`Bearer ${secret}`);
    expect(String(unsafeOperation)).toBe(
      'ProtocolClientError: Protocol client operation failed: invalid-operation'
    );
    expect(JSON.stringify(unsafeOperation)).not.toContain(secret);

    const validationErrors = await Promise.all(
      [{ method: `GET ${secret}` }, { headers: [[`x-${secret}\n`, 'value']] as const }].map(
        async (unsafeOptions) =>
          client.request('validate', 'oidc/token', unsafeOptions).catch((error_: unknown) => error_)
      )
    );

    for (const validationError of validationErrors) {
      const rendered = `${String(validationError)} ${JSON.stringify(validationError)}`;

      expect(validationError).toBeInstanceOf(ProtocolClientError);
      expect(rendered).toContain('Protocol client operation failed: validate');
      expect(rendered).not.toContain(secret);
    }
  });

  it('routes each focused client and can explicitly observe an expected HTTP error response', async () => {
    const requests: Array<
      Readonly<{ url: string; host?: string; authorization?: string; cookie?: string }>
    > = [];
    const server = createServer((request, response) => {
      requests.push({
        url: request.url ?? '',
        ...(typeof request.headers.host === 'string' && { host: request.headers.host }),
        ...(typeof request.headers.authorization === 'string' && {
          authorization: request.headers.authorization,
        }),
        ...(typeof request.headers.cookie === 'string' && { cookie: request.headers.cookie }),
      });
      response.statusCode = request.url === '/oidc/error' ? 400 : 200;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ error: 'invalid_request' }));
    });
    const port = await listen(server);
    const store = new MemoryProtocolSecretStore();
    store.setToken('account', 'private-account-token');
    store.setToken('management', 'private-management-token');
    const options = {
      target: {
        label: 'oracle' as const,
        coreUrl: `http://127.0.0.1:${port}/`,
        adminUrl: `http://localhost:${port}/`,
      },
      fixture: fixture('data', 'admin'),
      store,
      signal: new AbortController().signal,
    };
    store.setCookie(
      'admin-session=private-admin-cookie; Path=/; HttpOnly',
      new URL(options.target.adminUrl)
    );
    const dataOptions = { ...options, allocationRole: 'data' as const };
    const adminOptions = { ...options, allocationRole: 'admin' as const };

    try {
      await new OidcClient(dataOptions).request('oidc', 'oidc/token');
      await new ExperienceClient(dataOptions).requestExperience('experience', 'experience');
      await new ConsentClient(dataOptions).requestConsent('consent', 'consent');
      await new ManagementClient(adminOptions).requestManagement('management', 'applications');
      await new AccountClient(adminOptions).requestAccount('account', 'my-account/');
      await new StateClient(adminOptions).requestState('state', 'roles');
      await new ManagementClient(adminOptions).requestManagement('preflight', 'applications', {
        method: 'OPTIONS',
        authenticated: false,
      });
      await expect(
        new ManagementClient(adminOptions).requestManagement('override', 'applications', {
          headers: { Authorization: 'Bearer caller-controlled' },
        })
      ).rejects.toBeInstanceOf(ProtocolClientError);
      await expect(
        new AccountClient(adminOptions).requestAccount('override', 'my-account/', {
          headers: { authorization: 'Bearer caller-controlled' },
        })
      ).rejects.toBeInstanceOf(ProtocolClientError);
      await expect(
        new OidcClient(dataOptions).request('expected-error', 'oidc/error')
      ).resolves.toMatchObject({ status: 400, body: '{"error":"invalid_request"}' });

      expect(requests.map(({ url }) => url)).toEqual([
        '/oidc/token',
        '/api/experience',
        '/api/interaction/consent',
        '/api/applications',
        '/api/my-account/',
        '/api/roles',
        '/api/applications',
        '/oidc/error',
      ]);
      expect(requests.slice(0, 3).every(({ host }) => host === `127.0.0.1:${port}`)).toBe(true);
      expect(requests.slice(3, 7).every(({ host }) => host === `localhost:${port}`)).toBe(true);
      expect(requests[3]?.authorization).toBe('Bearer private-management-token');
      expect(requests[4]?.authorization).toBe('Bearer private-account-token');
      expect(requests[5]?.authorization).toBe('Bearer private-management-token');
      expect(requests[6]?.authorization).toBeUndefined();
      expect(
        requests.slice(3, 6).every(({ cookie }) => cookie === 'admin-session=private-admin-cookie')
      ).toBe(true);
      expect(requests[6]?.cookie).toBeUndefined();
    } finally {
      await close(server);
    }
  });
});

/* eslint-enable @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines */
