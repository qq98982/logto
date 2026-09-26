/* eslint-disable @silverhand/fp/no-mutating-methods -- The local fetch double records two ordered calls and consumes a fixed response queue. */
import type { TargetConfig } from '../../model.js';

import {
  observeAccountSessionBoundary,
  observeAccountSessionWorkflow,
  observeLogoutSession,
} from './logout-session.js';

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
        '<title>Submitting Callback</title><body onload="form.submit()"><form method="post" action="https://candidate.example/oidc/session/end/confirm"><input name="xsrf" value="private-xsrf"><input name="logout" value="yes"></form></body>',
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

  it('rejects an external confirmation action without sending the XSRF value', async () => {
    const calls: string[] = [];
    const requestFetch = (async () => {
      calls.push('request');
      return new Response(
        '<form method="post" action="https://attacker.example/collect"><input name="xsrf" value="private-xsrf"></form>',
        { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } }
      );
    }) as typeof fetch;

    await expect(
      observeLogoutSession(
        { target, method: 'GET', path: '/oidc/session/end', confirm: true },
        requestFetch
      )
    ).rejects.toThrow('Invalid Phase 2 logout session observation');
    expect(calls).toHaveLength(1);
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

  it('keeps verification and session identifiers inside one Account workflow', async () => {
    const requests: Array<readonly [string, RequestInit | undefined]> = [];
    const session = {
      payload: {
        exp: 2000,
        iat: 1000,
        uid: 'private-session',
        kind: 'Session',
        loginTs: 1000,
        accountId: 'private-account',
        authorizations: { 'private-client': {} },
      },
      clientId: 'private-client',
      accountId: 'private-account',
      expiresAt: 2_000_000,
      isCurrent: true,
    };
    const responses = [
      new Response(
        JSON.stringify({
          verificationRecordId: 'private-verification',
          expiresAt: '2026-09-27T00:10:00.000Z',
        }),
        { status: 201, headers: { 'content-type': 'application/json' } }
      ),
      new Response(JSON.stringify({ sessions: [session] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(null, { status: 204 }),
      new Response(JSON.stringify({ sessions: [{ ...session, isCurrent: false }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ];
    const requestFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push([String(input), init]);
      return responses.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
    }) as typeof fetch;

    const result = await observeAccountSessionWorkflow(
      { target, bearer: 'private-bearer', password: 'private-password' },
      requestFetch
    );

    expect(result.verification.body.kind).toBe('verification');
    expect(result.sessions.body).toMatchObject({ kind: 'sessions', currentCount: 1 });
    expect(result.deletion.status).toBe(204);
    expect(result.sessionsAfterDeletion.body).toMatchObject({
      kind: 'sessions',
      currentCount: 0,
    });
    expect(requests[2]?.[0]).toContain('/api/my-account/sessions/private-session');
    expect(new Headers(requests[1]?.[1]?.headers).get('aster-verification-id')).toBe(
      'private-verification'
    );
    expect(JSON.stringify(result)).not.toMatch(
      /private-(?:bearer|password|verification|session|account|client)/u
    );
  });

  it('uses the pinned oracle verification header only for the oracle target', async () => {
    const requests: RequestInit[] = [];
    const session = {
      payload: {
        exp: 2000,
        iat: 1000,
        uid: 'session',
        kind: 'Session',
        loginTs: 1000,
        accountId: 'account',
        authorizations: {},
      },
      clientId: null,
      accountId: 'account',
      expiresAt: 2_000_000,
      isCurrent: true,
    };
    const responses = [
      new Response(
        JSON.stringify({ verificationRecordId: 'verification', expiresAt: '2026-09-27T00:10:00Z' }),
        { status: 201, headers: { 'content-type': 'application/json' } }
      ),
      new Response(JSON.stringify({ sessions: [session] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(null, { status: 204 }),
      new Response(JSON.stringify({ sessions: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ];
    const requestFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(init ?? {});
      return responses.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
    }) as typeof fetch;

    await observeAccountSessionWorkflow(
      { target: { ...target, label: 'oracle' }, bearer: 'bearer', password: 'password' },
      requestFetch
    );

    expect(new Headers(requests[1]?.headers).get('logto-verification-id')).toBe('verification');
    expect(new Headers(requests[1]?.headers).has('aster-verification-id')).toBe(false);
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods */
