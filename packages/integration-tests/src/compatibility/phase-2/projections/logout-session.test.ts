import { compareLogoutSessionProjections, projectLogoutSessionResponse } from './logout-session.js';

const response = (body: string, init: ResponseInit = {}) => {
  const headers = new Headers(init.headers);
  headers.set('content-type', headers.get('content-type') ?? 'text/html; charset=utf-8');
  headers.set('cache-control', headers.get('cache-control') ?? 'no-store');
  return new Response(body, { ...init, headers });
};

describe('logout session projection', () => {
  it('retains stable confirmation semantics without XSRF or cookie values', () => {
    const raw = response(
      '<title>Sign Out</title><body onload="document.getElementById(\'form\').submit();"><form method="post" action="/oidc/session/end/confirm"><input name="xsrf" value="private-proof"></form></body>',
      { headers: { 'set-cookie': '_session=private-cookie; Path=/; HttpOnly' } }
    );
    const projection = projectLogoutSessionResponse('https://id.example/', raw, '');
    const withBody = projectLogoutSessionResponse(
      'https://id.example/',
      response('', { headers: raw.headers }),
      '<title>Sign Out</title><body onload="form.submit()"><form method="post"><input name="xsrf" value="private-proof"></form></body>'
    );
    expect(withBody.body).toEqual({
      kind: 'html',
      title: 'Sign Out',
      logoutForm: true,
      autoSubmit: true,
      success: false,
    });
    expect(JSON.stringify(withBody)).not.toContain('private-proof');
    expect(JSON.stringify(withBody)).not.toContain('private-cookie');
    expect(projection.body).toEqual({ kind: 'empty' });
  });

  it('normalizes locations and reports exact semantic differences', () => {
    const oracle = projectLogoutSessionResponse(
      'https://oracle.example/',
      response('', { status: 303, headers: { location: '/oidc/session/end/success?state=x' } }),
      ''
    );
    const candidate = projectLogoutSessionResponse(
      'https://candidate.example/',
      response('', { status: 303, headers: { location: '/oidc/session/end/success?state=y' } }),
      ''
    );
    expect(compareLogoutSessionProjections(oracle, candidate)).toEqual([]);
    expect(compareLogoutSessionProjections(oracle, { ...candidate, status: 302 })).toEqual([
      '/status',
    ]);
  });

  it('projects verification and session summaries without durable identifiers', () => {
    const verification = projectLogoutSessionResponse(
      'https://candidate.example/',
      response('', { status: 201, headers: { 'content-type': 'application/json' } }),
      JSON.stringify({
        verificationRecordId: 'private-verification',
        expiresAt: '2026-09-27T00:10:00.000Z',
      })
    );
    const sessions = projectLogoutSessionResponse(
      'https://candidate.example/',
      response('', { status: 200, headers: { 'content-type': 'application/json' } }),
      JSON.stringify({
        sessions: [
          {
            payload: {
              exp: 2000,
              iat: 1000,
              uid: 'private-session',
              kind: 'Session',
              loginTs: 1000,
              accountId: 'private-account',
              authorizations: { 'private-client': { grantId: 'private-grant' } },
            },
            clientId: 'private-client',
            accountId: 'private-account',
            expiresAt: 2_000_000,
            isCurrent: true,
          },
        ],
      })
    );

    expect(verification.body).toEqual({ kind: 'verification', expiresAt: true });
    expect(sessions.body).toEqual({
      kind: 'sessions',
      sessionCount: 1,
      currentCount: 1,
      clientCount: 1,
      clientCounts: [1],
    });
    expect(JSON.stringify({ verification, sessions })).not.toMatch(
      /private-(?:verification|session|account|client|grant)/u
    );
  });
});
