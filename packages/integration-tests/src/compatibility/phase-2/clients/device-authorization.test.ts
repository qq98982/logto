/* eslint-disable max-lines, @silverhand/fp/no-mutating-methods -- The fetch double records exact private request bytes and consumes a bounded response queue. */
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';

import {
  createDeviceAuthorizationTransportLease,
  type DeviceAuthorizationRequest,
  type DeviceAuthorizationProjection,
} from './device-authorization.js';

const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});

const jsonResponse = (body: unknown, status = 200, headers: HeadersInit = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });

const cookieResponse = (setCookies: readonly string[]): Response => {
  const headers = new Headers({ 'content-type': 'text/plain' });
  for (const cookie of setCookies) {
    headers.append('set-cookie', cookie);
  }
  return new Response('', { status: 200, headers });
};

const authorizationBody = Object.freeze({
  device_code: 'private-device-code',
  user_code: 'BCDF-GHJK',
  verification_uri: 'https://candidate.example/device',
  verification_uri_complete: 'https://candidate.example/device?user_code=BCDF-GHJK',
  expires_in: 600,
  interval: 5,
});

const expectSanitized = (projection: DeviceAuthorizationProjection): void => {
  const rendered = JSON.stringify(projection);
  expect(rendered).not.toMatch(
    /private-(?:device|user|xsrf|cookie|secret|password|access|refresh|id-token)/u
  );
  expect(inspect(projection)).not.toMatch(
    /private-(?:device|user|xsrf|cookie|secret|password|access|refresh|id-token)/u
  );
};

describe('Phase 2 device authorization transport', () => {
  it('encodes organization and locale context in form and JSON requests within the closed bounds', async () => {
    const calls: RequestInit[] = [];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (_input, init) => {
        calls.push(init ?? {});
        return jsonResponse({ error: 'invalid_request' }, 400);
      }) as typeof fetch,
    });

    const form = await lease.requestAuthorization({
      encoding: 'form',
      fields: [
        ['client_id', 'device-client'],
        ['organization_id', 'phase2-org'],
        ['organization_id', 'phase2-org'],
        ['ui_locales', 'ja en'],
        ['ui_locales', 'en ja'],
      ],
    });
    const json = await lease.requestAuthorization({
      encoding: 'json',
      fields: {
        client_id: 'device-client',
        organization_id: 'phase2-org',
        ui_locales: 'ja en',
      },
    });

    expect((calls[0]?.body as URLSearchParams).getAll('organization_id')).toEqual([
      'phase2-org',
      'phase2-org',
    ]);
    expect((calls[0]?.body as URLSearchParams).getAll('ui_locales')).toEqual(['ja en', 'en ja']);
    expect(calls[1]?.body).toBe(
      '{"client_id":"device-client","organization_id":"phase2-org","ui_locales":"ja en"}'
    );
    for (const projection of [form, json]) {
      expectSanitized(projection);
    }

    const requestsBeforeRejection = calls.length;
    await expect(
      lease.requestAuthorization({
        encoding: 'form',
        fields: [['organization_id', 'x'.repeat(4097)]],
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-request)');
    await expect(
      lease.requestAuthorization({
        encoding: 'json',
        fields: { ui_locales: 'ja\u0000private-secret' },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-request)');
    await expect(
      lease.requestAuthorization({
        encoding: 'json',
        fields: { client_id: 'device-client', organization: 'phase2-org' },
      } as never)
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-request)');
    expect(calls).toHaveLength(requestsBeforeRejection);
  });

  it('encodes form duplicates, JSON objects and explicit raw negative requests', async () => {
    const calls: Array<readonly [string, RequestInit | undefined]> = [];
    const replies = [
      jsonResponse(
        { error: 'invalid_request', error_description: 'duplicate client_id rejected' },
        400
      ),
      jsonResponse({ error: 'invalid_request', error_description: 'JSON object rejected' }, 400),
      jsonResponse({ error: 'invalid_request', error_description: 'media type rejected' }, 400),
      jsonResponse(authorizationBody),
    ];
    const requestFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(input), init]);
      return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
    }) as typeof fetch;
    const lease = createDeviceAuthorizationTransportLease({ target, fetch: requestFetch });

    const duplicate = await lease.requestAuthorization({
      encoding: 'form',
      fields: [
        ['client_id', 'device-client'],
        ['client_id', 'device-client'],
        ['scope', 'openid'],
      ],
    });
    const json = await lease.requestAuthorization({
      encoding: 'json',
      fields: { client_id: 'device-client', scope: 'openid' },
    });
    const raw = await lease.requestAuthorization({
      encoding: 'raw',
      mediaType: 'text/plain',
      body: 'client_id=device-client&scope=openid',
      sensitiveFragments: [],
    });
    const form = await lease.requestAuthorization({
      encoding: 'form',
      fields: [
        ['client_id', 'device-client'],
        ['scope', 'openid'],
      ],
    });

    expect(calls.map(([url]) => url)).toEqual([
      'https://candidate.example/oidc/device/auth',
      'https://candidate.example/oidc/device/auth',
      'https://candidate.example/oidc/device/auth',
      'https://candidate.example/oidc/device/auth',
    ]);
    expect(calls.every(([, init]) => init?.method === 'POST' && init.redirect === 'manual')).toBe(
      true
    );
    expect((calls[0]?.[1]?.body as URLSearchParams).getAll('client_id')).toEqual([
      'device-client',
      'device-client',
    ]);
    expect(new Headers(calls[0]?.[1]?.headers).get('content-type')).toBe(
      'application/x-www-form-urlencoded'
    );
    expect(calls[1]?.[1]?.body).toBe('{"client_id":"device-client","scope":"openid"}');
    expect(new Headers(calls[1]?.[1]?.headers).get('content-type')).toBe('application/json');
    expect(calls[2]?.[1]?.body).toBe('client_id=device-client&scope=openid');
    expect(new Headers(calls[2]?.[1]?.headers).get('content-type')).toBe('text/plain');
    expect(form).toMatchObject({
      status: 200,
      contentType: 'application/json',
      keys: [
        'device_code',
        'expires_in',
        'interval',
        'user_code',
        'verification_uri',
        'verification_uri_complete',
      ],
      userCodeShape: {
        length: 9,
        groups: [4, 4],
        separator: '-',
        matchesReferencePattern: true,
      },
      deviceCodeShape: { length: 19 },
      expiresIn: 600,
      interval: 5,
      verificationUri: {
        origin: 'https://candidate.example',
        path: '/device',
        queryKeys: [],
      },
      verificationUriComplete: {
        origin: 'https://candidate.example',
        path: '/device',
        queryKeys: ['user_code'],
      },
    });
    expect(json.oauthError).toEqual({
      category: 'invalid_request',
      description: 'JSON object rejected',
    });
    expect(raw.oauthError).toEqual({
      category: undefined,
      description: undefined,
    });
    expect(duplicate.oauthError).toEqual({
      category: 'invalid_request',
      description: 'duplicate client_id rejected',
    });
    for (const projection of [duplicate, form, json, raw]) {
      expectSanitized(projection);
    }
  });

  it('rejects response bodies above the configured hard limit with redacted diagnostics', async () => {
    const lease = createDeviceAuthorizationTransportLease({
      target,
      maximumBodyBytes: 64,
      fetch: async () => jsonResponse({ padding: 'private-secret'.repeat(20) }),
    });

    await expect(
      lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', 'device-client']],
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-response)');
    await expect(
      lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', 'device-client']],
      })
    ).rejects.not.toThrow(/private-secret/u);
  });

  it('keeps browser cookies, user code and XSRF private across manual GET and POST redirects', async () => {
    const calls: Array<readonly [string, RequestInit | undefined]> = [];
    const replies = [
      jsonResponse(authorizationBody),
      new Response(
        '<title>Device Verification</title><form method="post" action="/oidc/device"><input name="xsrf" value="private-xsrf"><input name="user_code"><input name="confirm"></form><script>form.submit()</script>',
        {
          status: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'set-cookie': '_device_flow_xsrf=private-xsrf; Path=/; HttpOnly; SameSite=Lax',
          },
        }
      ),
      new Response(null, {
        status: 302,
        headers: { location: '/oidc/device?user_code=BCDF-GHJK' },
      }),
      new Response(null, {
        status: 303,
        headers: {
          location: '/oidc/device/success?result=confirmed',
          'set-cookie': '_device_flow_xsrf=; Path=/; Max-Age=0; HttpOnly',
        },
      }),
      new Response(null, {
        status: 303,
        headers: { location: '/oidc/device?error=access_denied&error_description=Device%20denied' },
      }),
    ];
    const requestFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(input), init]);
      return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
    }) as typeof fetch;
    const lease = createDeviceAuthorizationTransportLease({ target, fetch: requestFetch });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [
        ['client_id', 'device-client'],
        ['scope', 'openid'],
      ],
    });

    const start = await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    const shortcut = await lease.requestVerification({
      method: 'GET',
      path: '/device',
      userCode: { stored: 'user-code' },
    });
    const confirmed = await lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: {
        xsrf: { stored: 'xsrf' },
        user_code: { stored: 'user-code' },
        confirm: 'yes',
      },
    });
    const aborted = await lease.requestVerification({
      method: 'POST',
      path: '/device',
      fields: {
        xsrf: 'private-literal-xsrf',
        user_code: 'private-user-code',
        abort: 'yes',
      },
    });

    expect(start).toMatchObject({
      status: 200,
      contentType: 'text/html',
      headers: { 'cache-control': 'no-store' },
      cookies: [
        {
          name: '_device_flow_xsrf',
          options: ['httponly', 'path', 'samesite'],
        },
      ],
      experience: {
        title: 'Device Verification',
        formAction: { origin: 'https://candidate.example', path: '/oidc/device', queryKeys: [] },
        inputNames: ['confirm', 'user_code', 'xsrf'],
        autoSubmit: true,
      },
    });
    expect(shortcut).toMatchObject({
      status: 302,
      location: {
        origin: 'https://candidate.example',
        path: '/oidc/device',
        queryKeys: ['user_code'],
      },
    });
    expect(confirmed).toMatchObject({
      status: 303,
      cookies: [{ name: '_device_flow_xsrf', options: ['httponly', 'max-age', 'path'] }],
      location: {
        origin: 'https://candidate.example',
        path: '/oidc/device/success',
        queryKeys: ['result'],
      },
    });
    expect(aborted.oauthError).toEqual({
      category: 'access_denied',
      description: 'Device denied',
    });
    expect(calls).toHaveLength(5);
    expect(calls.slice(1).every(([, init]) => init?.redirect === 'manual')).toBe(true);
    expect(calls[2]?.[0]).toBe('https://candidate.example/device?user_code=BCDF-GHJK');
    expect(new Headers(calls[2]?.[1]?.headers).get('cookie')).toBe(
      '_device_flow_xsrf=private-xsrf'
    );
    expect(Object.fromEntries(calls[3]?.[1]?.body as URLSearchParams)).toEqual({
      xsrf: 'private-xsrf',
      user_code: 'BCDF-GHJK',
      confirm: 'yes',
    });
    expect(Object.fromEntries(calls[4]?.[1]?.body as URLSearchParams)).toEqual({
      xsrf: 'private-literal-xsrf',
      user_code: 'private-user-code',
      abort: 'yes',
    });
    for (const projection of [start, shortcut, confirmed, aborted]) {
      expectSanitized(projection);
    }
    expect(inspect(lease)).not.toMatch(/private-(?:device|xsrf|cookie|user)/u);
    expect(() => JSON.stringify(lease)).toThrow(
      'Invalid Phase 2 device authorization transport (lease)'
    );
  });

  it('applies Domain, Path, Secure, expiry and targeted deletion with no cookie value projection', async () => {
    const calls: RequestInit[] = [];
    const replies = [
      cookieResponse([
        'sid=private-root; Path=/; Secure; HttpOnly',
        'sid=private-oidc; Path=/oidc; Secure; HttpOnly',
        'domain=private-domain; Domain=candidate.example; Path=/',
        'expired=private-expired; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
      ]),
      cookieResponse(['sid=; Path=/; Max-Age=0; Secure']),
      cookieResponse(['sid=; Path=/oidc; Max-Age=0; Secure']),
      cookieResponse([]),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (_input, init) => {
        calls.push(init ?? {});
        return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });

    const set = await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    await lease.requestVerification({ method: 'GET', path: '/device' });
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });

    expect(set.cookies).toEqual([
      { name: 'domain', options: ['domain', 'path'] },
      { name: 'expired', options: ['expires', 'path'] },
      { name: 'sid', options: ['httponly', 'path', 'secure'] },
      { name: 'sid', options: ['httponly', 'path', 'secure'] },
    ]);
    expect(new Headers(calls[1]?.headers).get('cookie')).toBe(
      'sid=private-root; domain=private-domain'
    );
    expect(new Headers(calls[2]?.headers).get('cookie')).toBe(
      'sid=private-oidc; domain=private-domain'
    );
    expect(new Headers(calls[3]?.headers).get('cookie')).toBe('domain=private-domain');
    expect(JSON.stringify(set)).not.toMatch(/private-(?:root|oidc|domain|expired)/u);

    const insecureCalls: RequestInit[] = [];
    const insecureTarget = { ...target, coreUrl: 'http://candidate.example/' };
    const insecureReplies = [
      cookieResponse(['secure=private-secure; Path=/; Secure']),
      cookieResponse([]),
    ];
    const insecureLease = createDeviceAuthorizationTransportLease({
      target: insecureTarget,
      fetch: (async (_input, init) => {
        insecureCalls.push(init ?? {});
        return insecureReplies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });
    const secureProjection = await insecureLease.requestVerification({
      method: 'GET',
      path: '/device',
    });
    await insecureLease.requestVerification({ method: 'GET', path: '/device' });
    expect(new Headers(insecureCalls[1]?.headers).has('cookie')).toBe(false);
    expect(JSON.stringify(secureProjection)).not.toContain('private-secure');
  });

  it('retains a Path=/device XSRF value while keeping Cookie emission URL-aware', async () => {
    const calls: Array<readonly [string, RequestInit | undefined]> = [];
    const replies = [
      cookieResponse([
        '_aster_device_flow_xsrf=private-path-xsrf; Path=/device; HttpOnly; SameSite=Lax',
      ]),
      cookieResponse([]),
      new Response(null, { status: 303, headers: { location: '/oidc/device/success' } }),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (input, init) => {
        calls.push([String(input), init]);
        return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });

    const started = await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    await lease.requestVerification({ method: 'GET', path: '/device' });
    const posted = await lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: { xsrf: { stored: 'xsrf' }, confirm: 'yes' },
    });

    expect(started.cookies).toEqual([
      {
        name: '_aster_device_flow_xsrf',
        options: ['httponly', 'path', 'samesite'],
      },
    ]);
    expect(new Headers(calls[1]?.[1]?.headers).get('cookie')).toBe(
      '_aster_device_flow_xsrf=private-path-xsrf'
    );
    expect(new Headers(calls[2]?.[1]?.headers).has('cookie')).toBe(false);
    expect(Object.fromEntries(calls[2]?.[1]?.body as URLSearchParams)).toEqual({
      xsrf: 'private-path-xsrf',
      confirm: 'yes',
    });
    expect(posted.status).toBe(303);
    expect(JSON.stringify([started, posted])).not.toContain('private-path-xsrf');
  });

  it('polls with public, Basic and POST proof while dropping credentials on clear', async () => {
    const calls: Array<readonly [string, RequestInit | undefined]> = [];
    const replies = [
      jsonResponse(authorizationBody),
      jsonResponse(
        { error: 'authorization_pending', error_description: 'Authorization is pending.' },
        400
      ),
      jsonResponse({
        access_token: 'private-access',
        refresh_token: 'private-refresh',
        id_token: 'private-id-token',
        expires_in: 3600,
        token_type: 'Bearer',
      }),
      jsonResponse({ error: 'access_denied', error_description: 'Device grant denied.' }, 400),
      jsonResponse(
        {
          error: 'invalid_client',
          error_description: Buffer.from(
            'confidential%3A+client%2B%7E%25:private%3A+secret%2B%7E%25'
          ).toString('base64'),
        },
        401
      ),
    ];
    const requestFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(input), init]);
      return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
    }) as typeof fetch;
    const lease = createDeviceAuthorizationTransportLease({ target, fetch: requestFetch });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });

    const pending = await lease.pollToken({
      proof: { method: 'public', clientId: 'device-client' },
    });
    const issued = await lease.pollToken({
      proof: {
        method: 'basic',
        clientId: 'confidential: client+~%',
        clientSecret: 'private: secret+~%',
      },
    });
    const denied = await lease.pollToken({
      deviceCode: 'private-unknown-device-code',
      proof: {
        method: 'post',
        clientId: 'confidential-client',
        clientSecret: 'private-post-secret',
      },
    });
    const reflectedSecret = lease.pollToken({
      proof: {
        method: 'basic',
        clientId: 'confidential: client+~%',
        clientSecret: 'private: secret+~%',
      },
    });
    await expect(reflectedSecret).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (token-response)'
    );
    await expect(reflectedSecret).rejects.not.toThrow(/private-basic-secret/u);

    const publicForm = calls[1]?.[1]?.body as URLSearchParams;
    expect(Object.fromEntries(publicForm)).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: 'private-device-code',
      client_id: 'device-client',
    });
    expect(new Headers(calls[1]?.[1]?.headers).has('authorization')).toBe(false);
    const basicForm = calls[2]?.[1]?.body as URLSearchParams;
    expect(Object.fromEntries(basicForm)).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: 'private-device-code',
    });
    expect(new Headers(calls[2]?.[1]?.headers).get('authorization')).toBe(
      `Basic ${Buffer.from('confidential%3A+client%2B%7E%25:private%3A+secret%2B%7E%25').toString(
        'base64'
      )}`
    );
    const postForm = calls[3]?.[1]?.body as URLSearchParams;
    expect(Object.fromEntries(postForm)).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: 'private-unknown-device-code',
      client_id: 'confidential-client',
      client_secret: 'private-post-secret',
    });
    expect(calls.slice(1).every(([, init]) => init?.redirect === 'manual')).toBe(true);
    expect(pending.oauthError.category).toBe('authorization_pending');
    expect(issued.keys).toEqual([
      'access_token',
      'expires_in',
      'id_token',
      'refresh_token',
      'token_type',
    ]);
    expect(denied.oauthError.category).toBe('access_denied');
    for (const projection of [pending, issued, denied]) {
      expectSanitized(projection);
    }

    lease.clear();
    lease.clear();
    await expect(
      lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (cleared)');
    expect(calls).toHaveLength(5);
    expect(inspect(lease)).not.toMatch(
      /private-(?:device|user|basic|post|access|refresh|id-token)/u
    );
  });

  it('projects CORS and a structured nonsecret WWW-Authenticate challenge', async () => {
    const response = jsonResponse(
      { error: 'invalid_client', error_description: 'client authentication failed' },
      401,
      {
        'access-control-allow-origin': '*',
        'access-control-expose-headers': 'WWW-Authenticate',
        'www-authenticate':
          'Basic realm="https://candidate.example/oidc", error="invalid_client", error_description="client authentication failed"',
      }
    );
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: async () => response,
    });

    const projection = await lease.pollToken({
      deviceCode: 'private-device-code',
      proof: { method: 'public', clientId: 'device-client' },
    });

    expect(projection.headers).toEqual({
      'access-control-allow-origin': '*',
      'access-control-expose-headers': 'WWW-Authenticate',
    });
    expect(projection.challenge).toEqual({
      scheme: 'basic',
      parameters: {
        realm: '<target-issuer>',
        error: 'invalid_client',
        error_description: 'client authentication failed',
      },
    });
    expect(JSON.stringify(projection)).not.toContain('private-device-code');
  });

  it('rejects credential-bearing, secret-reflecting and malformed challenge headers', async () => {
    const replies = [
      jsonResponse({ error: 'invalid_client' }, 401, {
        'www-authenticate': `Basic ${Buffer.from('client:private-wire-secret').toString('base64')}`,
      }),
      jsonResponse({ error: 'invalid_client' }, 401, {
        'www-authenticate': 'Basic realm="private-challenge-secret"',
      }),
      jsonResponse({ error: 'invalid_client' }, 401, {
        'www-authenticate': 'Basic realm="https://candidate.example/oidc", token="value"',
      }),
      jsonResponse({ error: 'invalid_client' }, 401, {
        'access-control-allow-origin': 'private-cors-secret',
      }),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async () =>
        replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'))) as typeof fetch,
    });
    for (const secret of [
      'private-wire-secret',
      'private-challenge-secret',
      'private-malformed-secret',
      'private-cors-secret',
    ]) {
      const failure = lease.pollToken({
        deviceCode: secret,
        proof: { method: 'public', clientId: 'device-client' },
      });
      // eslint-disable-next-line no-await-in-loop -- Ordered replies cover distinct challenge failures.
      await expect(failure).rejects.toThrow(
        'Invalid Phase 2 device authorization transport (token-response)'
      );
      // eslint-disable-next-line no-await-in-loop -- The same rejected promise proves redaction.
      await expect(failure).rejects.not.toThrow(secret);
    }
  });

  it('captures codes only from complete unexpired 2xx authorization responses', async () => {
    const calls: Array<readonly [string, RequestInit | undefined]> = [];
    const injected = (suffix: string, expiresIn: unknown = 600) => ({
      device_code: `private-injected-device-${suffix}`,
      user_code: `INJECTED-${suffix}`,
      verification_uri: 'https://candidate.example/device',
      verification_uri_complete: 'https://candidate.example/device?user_code=INJECTED',
      ...(expiresIn === undefined ? {} : { expires_in: expiresIn }),
    });
    const pending = { error: 'authorization_pending', error_description: 'Pending.' };
    const replies = [
      jsonResponse(authorizationBody),
      jsonResponse(injected('verification')),
      jsonResponse(injected('token')),
      jsonResponse(pending, 400),
      jsonResponse(injected('error'), 400),
      jsonResponse(pending, 400),
      jsonResponse({ ...injected('incomplete'), user_code: undefined }),
      jsonResponse({
        device_code: 'private-injected-device-missing-expiry',
        user_code: 'INJECTED-missing-expiry',
        verification_uri: 'https://candidate.example/device',
        verification_uri_complete: 'https://candidate.example/device?user_code=INJECTED',
      }),
      jsonResponse(injected('zero', 0)),
      jsonResponse(injected('negative', -1)),
      jsonResponse(injected('fraction', 1.5)),
      jsonResponse(injected('oversized', 86_401)),
      jsonResponse(pending, 400),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (input, init) => {
        calls.push([String(input), init]);
        return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    await lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } });
    await lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    await lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } });
    for (const index of Array.from({ length: 6 }, (_unused, value) => value)) {
      // eslint-disable-next-line no-await-in-loop -- Ordered malformed authorizations preserve prior state.
      await expect(
        lease.requestAuthorization({
          encoding: 'form',
          fields: [['client_id', `invalid-${index}`]],
        })
      ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-response)');
    }
    await lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } });

    const pollBodies = calls
      .filter(([url]) => url.endsWith('/oidc/token'))
      .map(([, init]) => (init?.body as URLSearchParams).get('device_code'));
    expect(pollBodies).toEqual([
      'private-device-code',
      'private-device-code',
      'private-device-code',
      'private-device-code',
    ]);
  });

  it('drops stored authorization codes after their positive relative expiry', async () => {
    const calls: RequestInit[] = [];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (_input, init) => {
        calls.push(init ?? {});
        return jsonResponse({ ...authorizationBody, expires_in: 1 });
      }) as typeof fetch,
    });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 1100);
    });

    await expect(
      lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (token-request)');
    expect(calls).toHaveLength(1);
  });

  it('rejects partial, derived, case-folded and compact-JWT credential reflections', async () => {
    const rawLease = createDeviceAuthorizationTransportLease({
      target,
      fetch: async () =>
        jsonResponse(
          { error: 'invalid_request', error_description: 'reflected raw-secret suffix' },
          400
        ),
    });
    const raw = await rawLease.requestAuthorization({
      encoding: 'raw',
      mediaType: 'text/plain',
      body: 'credential=private-raw-secret',
      sensitiveFragments: ['raw-secret'],
    });
    expect(raw.oauthError).toEqual({ category: undefined, description: undefined });
    expect(JSON.stringify(raw)).not.toContain('raw-secret');

    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcml2YXRlIn0.abcdefghijklmnop';
    const jwtLease = createDeviceAuthorizationTransportLease({
      target,
      fetch: async () => jsonResponse({ error: 'invalid_request', error_description: jwt }, 400),
    });
    const jwtFailure = jwtLease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    await expect(jwtFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-response)'
    );
    await expect(jwtFailure).rejects.not.toThrow(jwt);

    const foldedLease = createDeviceAuthorizationTransportLease({
      target,
      fetch: async () =>
        jsonResponse(
          { error: 'invalid_client', error_description: 'PRIVATE-MIXED-SECRET rejected' },
          401
        ),
    });
    const foldedFailure = foldedLease.requestAuthorization({
      encoding: 'json',
      fields: {
        client_id: 'device-client',
        client_secret: 'private-mixed-secret',
      },
    });
    await expect(foldedFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-response)'
    );
    await expect(foldedFailure).rejects.not.toThrow(/private-mixed-secret/iu);
  });

  it('suppresses all raw response strings when sensitive fragments are omitted', async () => {
    const replies = [
      jsonResponse(
        { error: 'raw-secret', error_description: 'partially reflected raw-secret' },
        400,
        { 'cache-control': 'raw-secret' }
      ),
      new Response(
        '<title>raw-secret</title><form action="/raw-secret"><input name="raw-secret"></form>',
        { status: 400, headers: { 'content-type': 'text/html' } }
      ),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async () =>
        replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'))) as typeof fetch,
    });

    const json = await lease.requestAuthorization({
      encoding: 'raw',
      mediaType: 'text/plain',
      body: 'credential=private-raw-secret',
    });
    const html = await lease.requestAuthorization({
      encoding: 'raw',
      mediaType: 'text/plain',
      body: 'credential=private-raw-secret',
    });

    expect(json).toMatchObject({ status: 400, headers: {}, keys: [], oauthError: {} });
    expect(json.contentType).toBeUndefined();
    expect(json.location).toBeUndefined();
    expect(html.experience).toBeUndefined();
    expect(JSON.stringify([json, html])).not.toContain('raw-secret');
  });

  it('fails closed when declared fragments or derived variants exceed the operation bound', async () => {
    const fragmentsLease = createDeviceAuthorizationTransportLease({
      target,
      maximumSensitiveVariants: 5,
      fetch: async () => jsonResponse({ error: 'invalid_request' }, 400),
    });
    const fragmentsFailure = fragmentsLease.requestAuthorization({
      encoding: 'raw',
      mediaType: 'text/plain',
      body: 'body',
      sensitiveFragments: ['private-fragment-one', 'private-fragment-two'],
    });
    await expect(fragmentsFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-response)'
    );
    await expect(fragmentsFailure).rejects.not.toThrow(/private-fragment/u);

    const boundLease = createDeviceAuthorizationTransportLease({
      target,
      maximumSensitiveVariants: 1,
      fetch: async () => jsonResponse({ error: 'invalid_client' }, 401),
    });
    const boundFailure = boundLease.requestAuthorization({
      encoding: 'json',
      fields: { client_id: 'device-client', client_secret: 'private-bound-secret' },
    });
    await expect(boundFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-response)'
    );
    await expect(boundFailure).rejects.not.toThrow(/private-bound-secret/u);
  });

  it('drops per-operation request and response secrets instead of saturating across polls', async () => {
    const calls: RequestInit[] = [];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      maximumSensitiveVariants: 32,
      fetch: (async (_input, init) => {
        calls.push(init ?? {});
        if (calls.length === 1) {
          return jsonResponse(authorizationBody);
        }
        if (calls.length <= 13) {
          return jsonResponse({
            access_token: `private-ephemeral-token-${calls.length}`,
            expires_in: 60,
            token_type: 'Bearer',
          });
        }
        return jsonResponse(
          { error: 'invalid_client', error_description: 'PRIVATE-FINAL-REQUEST-SECRET' },
          401
        );
      }) as typeof fetch,
    });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    for (const index of Array.from({ length: 12 }, (_unused, value) => value)) {
      // eslint-disable-next-line no-await-in-loop -- Sequential polls exercise one lease lifetime.
      await lease.pollToken({
        proof: {
          method: 'post',
          clientId: 'confidential-client',
          clientSecret: `private-ephemeral-secret-${index}`,
        },
      });
    }
    const finalFailure = lease.pollToken({
      proof: {
        method: 'post',
        clientId: 'confidential-client',
        clientSecret: 'private-final-request-secret',
      },
    });
    await expect(finalFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (token-response)'
    );
    await expect(finalFailure).rejects.not.toThrow(/private-final-request-secret/iu);
  });

  it('drops replaced codes and expired or deleted cookie values from persistent redaction', async () => {
    const codeResponses = Array.from({ length: 8 }, (_unused, index) =>
      jsonResponse({
        ...authorizationBody,
        device_code: `private-replaced-device-${index}`,
        user_code: `PRIVATE-CODE-${index}`,
      })
    );
    const expiredResponses = Array.from({ length: 8 }, (_unused, index) =>
      cookieResponse([
        `expired_${index}=private-expired-${index}; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      ])
    );
    const deletedResponses = Array.from({ length: 8 }, (_unused, index) => [
      cookieResponse([`deleted_${index}=private-deleted-${index}; Path=/; HttpOnly`]),
      cookieResponse([`deleted_${index}=; Path=/; Max-Age=0; HttpOnly`]),
    ]).flat();
    const replies = [
      ...codeResponses,
      ...expiredResponses,
      ...deletedResponses,
      jsonResponse(
        { error: 'invalid_request', error_description: 'private-replaced-device-7 retained' },
        400
      ),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      maximumSensitiveVariants: 32,
      fetch: (async () =>
        replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'))) as typeof fetch,
    });
    for (const index of codeResponses.keys()) {
      // eslint-disable-next-line no-await-in-loop -- Ordered replacements exercise one live lease.
      await lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', `device-${index}`]],
      });
    }
    for (const index of expiredResponses.keys()) {
      // eslint-disable-next-line no-await-in-loop -- Ordered expiry exercises registry rebuilding.
      await lease.requestVerification({
        method: 'POST',
        path: '/device',
        fields: { confirm: String(index) },
      });
    }
    for (const index of deletedResponses.keys()) {
      // eslint-disable-next-line no-await-in-loop -- Set/delete pairs must use one cookie jar in order.
      await lease.requestVerification({
        method: 'POST',
        path: '/device',
        fields: { abort: String(index) },
      });
    }
    const liveCodeFailure = lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device']],
    });

    await expect(liveCodeFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-response)'
    );
    await expect(liveCodeFailure).rejects.not.toThrow(/private-replaced-device/u);
  });

  it('enforces verification body, GET URL and Basic header limits before fetch', async () => {
    const calls: string[] = [];
    const requestFetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return jsonResponse({ error: 'unexpected' }, 400);
    }) as typeof fetch;
    const bodyLease = createDeviceAuthorizationTransportLease({
      target,
      fetch: requestFetch,
      maximumRequestBodyBytes: 32,
    });
    await expect(
      bodyLease.requestVerification({
        method: 'POST',
        path: '/oidc/device',
        fields: { confirm: 'x'.repeat(32), abort: 'yes' },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (verification-request)');

    const urlLease = createDeviceAuthorizationTransportLease({
      target,
      fetch: requestFetch,
      maximumRequestUrlBytes: 48,
    });
    await expect(
      urlLease.requestVerification({
        method: 'GET',
        path: '/device',
        userCode: 'private-user-code-is-too-long',
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (verification-request)');

    const headerLease = createDeviceAuthorizationTransportLease({
      target,
      fetch: requestFetch,
      maximumRequestHeaderBytes: 96,
    });
    await expect(
      headerLease.pollToken({
        deviceCode: 'private-device-code',
        proof: {
          method: 'basic',
          clientId: 'confidential-client',
          clientSecret: 'private-secret-that-makes-the-header-too-large',
        },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (token-request)');
    expect(calls).toEqual([]);
  });

  it('rejects accessors, custom iterators, extra array properties and proxies without invoking them', async () => {
    const fetchCalls: string[] = [];
    const requestFetch = (async (input: RequestInfo | URL) => {
      fetchCalls.push(String(input));
      return jsonResponse({ error: 'unexpected' }, 400);
    }) as typeof fetch;
    const lease = createDeviceAuthorizationTransportLease({ target, fetch: requestFetch });
    const getterCalls: string[] = [];
    const accessor = Object.defineProperty({}, 'encoding', {
      enumerable: true,
      get: () => {
        getterCalls.push('called');
        throw new Error('private-getter-secret');
      },
    }) as DeviceAuthorizationRequest;
    const accessorFailure = lease.requestAuthorization(accessor);
    await expect(accessorFailure).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-request)'
    );
    await expect(accessorFailure).rejects.not.toThrow(/private-getter-secret/u);
    expect(getterCalls).toEqual([]);

    const targetGetterCalls: string[] = [];
    const accessorTarget = Object.defineProperty(
      { label: 'candidate', adminUrl: target.adminUrl },
      'coreUrl',
      {
        enumerable: true,
        get: () => {
          targetGetterCalls.push('called');
          throw new Error('private-target-getter-secret');
        },
      }
    );
    expect(() =>
      createDeviceAuthorizationTransportLease({ target: accessorTarget as TargetConfig })
    ).toThrow('Invalid Phase 2 device authorization transport (options)');
    expect(targetGetterCalls).toEqual([]);

    const iteratorCalls: string[] = [];
    const customFields = [['client_id', 'device-client']] as Array<[string, string]>;
    Object.defineProperty(customFields, Symbol.iterator, {
      *value() {
        iteratorCalls.push('called');
        yield ['client_id', 'private-iterator-secret'];
      },
    });
    await expect(
      lease.requestAuthorization({ encoding: 'form', fields: customFields } as never)
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-request)');
    expect(iteratorCalls).toEqual([]);

    const extraFields = [['client_id', 'device-client']];
    Object.defineProperty(extraFields, 'extra', {
      enumerable: true,
      value: 'private-extra-secret',
    });
    await expect(
      lease.requestAuthorization({ encoding: 'form', fields: extraFields } as never)
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-request)');

    const ownKeyCalls: string[] = [];
    const oversizedFields = Object.defineProperty([], 'length', { value: 1_000_000 });
    const proxyFields = new Proxy(oversizedFields, {
      ownKeys: () => {
        ownKeyCalls.push('called');
        throw new Error('private-proxy-secret');
      },
    });
    await expect(
      lease.requestAuthorization({ encoding: 'form', fields: proxyFields } as never)
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-request)');
    expect(ownKeyCalls).toEqual([]);
    expect(fetchCalls).toEqual([]);
  });

  it('fails closed on malformed JSON, text and redirect surfaces', async () => {
    const replies = [
      new Response('{not-json', { headers: { 'content-type': 'application/json' } }),
      new Response(new Uint8Array([0xff]), { headers: { 'content-type': 'text/plain' } }),
      new Response(null, { status: 302, headers: { location: 'http://[invalid' } }),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async () =>
        replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'))) as typeof fetch,
    });
    await expect(
      lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', 'device-client']],
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-response)');
    await expect(
      lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', 'device-client']],
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-response)');
    await expect(lease.requestVerification({ method: 'GET', path: '/device' })).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (verification-response)'
    );
  });

  it('best-effort cancels response bodies on every representative post-fetch rejection', async () => {
    const cancellations: string[] = [];
    const earlyFailure = (
      label: string,
      headers: HeadersInit,
      status = 200,
      cancellationThrows = false
    ): Response =>
      new Response(
        new ReadableStream<Uint8Array>({
          cancel: () => {
            cancellations.push(label);
            if (cancellationThrows) {
              throw new Error('private-cancellation-secret');
            }
          },
        }),
        { status, headers }
      );
    const malformedJson = new Response('{not-json', {
      headers: { 'content-type': 'application/json' },
    });
    if (!malformedJson.body) {
      throw new Error('missing malformed response body');
    }
    Object.defineProperty(malformedJson.body, 'cancel', {
      value: async () => {
        cancellations.push('parse');
      },
    });
    const replies = [
      earlyFailure('cookie', { 'set-cookie': '=invalid; Path=/' }, 200, true),
      earlyFailure('header', { authorization: 'private-header-secret' }),
      earlyFailure('content-type', { 'content-type': 'invalid' }),
      earlyFailure('location', { location: 'http://[invalid' }, 302),
      malformedJson,
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async () =>
        replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'))) as typeof fetch,
    });
    for (const label of ['cookie', 'header', 'content-type', 'location', 'parse']) {
      const failure = lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', `device-${label}`]],
      });
      // eslint-disable-next-line no-await-in-loop -- Ordered replies cover distinct rejection stages.
      await expect(failure).rejects.toThrow(
        'Invalid Phase 2 device authorization transport (authorization-response)'
      );
      // eslint-disable-next-line no-await-in-loop -- Cancellation failures must remain redacted.
      await expect(failure).rejects.not.toThrow(/private-(?:cancellation|header)-secret/u);
    }
    expect(cancellations).toEqual(['cookie', 'header', 'content-type', 'location', 'parse']);
  });

  it('rejects a second operation that could complete before the active request', async () => {
    const calls: string[] = [];
    const resolvers: Array<(response: Response) => void> = [];
    const firstResponse = new Promise<Response>((resolve) => {
      resolvers.push(resolve);
    });
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (input) => {
        calls.push(String(input));
        return calls.length === 1 ? firstResponse : cookieResponse([]);
      }) as typeof fetch,
    });
    const first = lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    const second = lease.requestVerification({ method: 'GET', path: '/device' });
    const resolve = resolvers[0];
    if (!resolve) {
      throw new Error('missing response resolver');
    }
    resolve(jsonResponse(authorizationBody));

    await expect(second).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (concurrent)'
    );
    await expect(first).resolves.toMatchObject({ status: 200 });
    expect(calls).toEqual(['https://candidate.example/oidc/device/auth']);
  });

  it('rolls back cookies and issued codes when late response parsing fails', async () => {
    const calls: RequestInit[] = [];
    const replies = [
      jsonResponse({ ...authorizationBody, expires_in: 'invalid-relative-expiry' }, 200, {
        'set-cookie': 'rollback=private-rollback-cookie; Path=/; HttpOnly',
      }),
      cookieResponse([]),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (_input, init) => {
        calls.push(init ?? {});
        return replies.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });

    await expect(
      lease.requestAuthorization({
        encoding: 'form',
        fields: [['client_id', 'device-client']],
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (authorization-response)');
    await expect(
      lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (token-request)');
    await lease.requestVerification({ method: 'GET', path: '/device' });

    expect(calls).toHaveLength(2);
    expect(new Headers(calls[1]?.headers).has('cookie')).toBe(false);
  });

  it('does not repopulate secrets when an in-flight response finishes after clear', async () => {
    const resolvers: Array<(response: Response) => void> = [];
    const signals: AbortSignal[] = [];
    const cancellations: string[] = [];
    const responsePromise = new Promise<Response>((resolve) => {
      resolvers.push(resolve);
    });
    const lease = createDeviceAuthorizationTransportLease({
      target,
      fetch: (async (_input, init) => {
        if (init?.signal) {
          signals.push(init.signal);
        }
        return responsePromise;
      }) as typeof fetch,
    });
    const request = lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });

    lease.clear();
    expect(signals[0]?.aborted).toBe(true);
    const resolve = resolvers[0];
    if (!resolve) {
      throw new Error('missing response resolver');
    }
    resolve(
      new Response(
        new ReadableStream<Uint8Array>({
          cancel: () => {
            cancellations.push('cleared');
          },
        }),
        { headers: { 'content-type': 'application/json' } }
      )
    );

    await expect(request).rejects.toThrow(
      'Invalid Phase 2 device authorization transport (authorization-response)'
    );
    await expect(
      lease.requestVerification({
        method: 'GET',
        path: '/device',
        userCode: { stored: 'user-code' },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization transport (cleared)');
    expect(cancellations).toEqual(['cleared']);
    expect(inspect(lease)).not.toMatch(/private-(?:device|user)/u);
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-mutating-methods */
