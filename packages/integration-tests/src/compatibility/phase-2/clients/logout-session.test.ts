/* eslint-disable @silverhand/fp/no-mutating-methods -- The local fetch double records two ordered calls and consumes a fixed response queue. */
import type { TargetConfig } from '../../model.js';

import { observeAccountSessionBoundary, observeLogoutSession } from './logout-session.js';

const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});

describe('logout session client', () => {
  it('keeps anonymous XSRF and cookies inside a confirmed flow', async () => {
    const calls: Array<readonly [RequestInfo | URL, RequestInit | undefined]> = [];
    const responses = [
      new Response(
        '<title>Sign Out</title><body onload="form.submit()"><form method="post" action="/oidc/session/end/confirm"><input name="xsrf" value="private-xsrf"><input name="logout" value="yes"></form></body>',
        {
          status: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'set-cookie': '_session=private-cookie; Path=/; HttpOnly',
          },
        }
      ),
      new Response('', {
        status: 303,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          location: '/oidc/session/end/success',
          'set-cookie': '_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        },
      }),
    ];
    const requestFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init]);
      return responses.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
    }) as typeof fetch;
    const projection = await observeLogoutSession(
      { target, method: 'GET', path: '/oidc/session/end', confirm: true },
      requestFetch
    );
    expect(projection.status).toBe(303);
    expect(projection.location?.path).toBe('/oidc/session/end/success');
    expect(projection.clearedCookieCount).toBe(1);
    expect(JSON.stringify(projection)).not.toMatch(/private-(?:xsrf|cookie)/u);
    const confirmation = calls[1]?.[1];
    expect(String(confirmation?.body)).toContain('xsrf=private-xsrf');
    expect(new Headers(confirmation?.headers).get('cookie')).toContain('_session=private-cookie');
  });

  it('projects Account authorization errors without returning bearer input', async () => {
    const requestFetch = (async () =>
      new Response(
        JSON.stringify({
          code: 'verification_record.permission_denied',
          message: 'Permission denied.',
        }),
        {
          status: 401,
          headers: { 'content-type': 'application/json; charset=utf-8' },
        }
      )) as typeof fetch;
    const projection = await observeAccountSessionBoundary(
      { target, kind: 'missing-verification', bearer: 'private-bearer' },
      requestFetch
    );
    expect(projection.body).toEqual({
      kind: 'error',
      error: null,
      description: null,
      code: 'verification_record.permission_denied',
    });
    expect(JSON.stringify(projection)).not.toContain('private-bearer');
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods */
