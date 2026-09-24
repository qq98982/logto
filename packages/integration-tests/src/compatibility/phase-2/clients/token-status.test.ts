/* eslint-disable unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Each mocked fetch assertion documents its named request contract in place; the call counter proves invalid targets cannot send credentials. */
import type { TargetConfig } from '../../model.js';

import { observeTokenStatus, type TokenStatusRequest } from './token-status.js';

const target: TargetConfig = {
  label: 'oracle',
  coreUrl: 'http://localhost:3312/',
  adminUrl: 'http://localhost:3412/',
};

const request: TokenStatusRequest = {
  target,
  kind: 'introspection',
  token: 'private-opaque-token',
  proof: { method: 'basic', clientId: 'owner-id', clientSecret: 'private-secret' },
  subjectId: 'subject-id',
  ownerClientId: 'owner-id',
  grant: 'unchanged',
};

const response = (body: unknown, status = 200, kind = 'introspection'): Response =>
  new Response(kind === 'revocation' && status === 200 ? '' : JSON.stringify(body), {
    status,
    headers: {
      'content-type':
        kind === 'revocation' && status === 200
          ? 'text/plain; charset=utf-8'
          : 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      ...(kind === 'introspection' ? { 'cache-control': 'no-store' } : {}),
    },
  });

describe('Phase 2 token-status HTTP client', () => {
  it('posts Basic proof to the requested endpoint and exposes only the inactive projection', async () => {
    const fetcher: typeof fetch = async (url, init) => {
      expect(String(url)).toBe('http://localhost:3312/oidc/token/introspection');
      expect(init?.method).toBe('POST');
      expect((init?.headers as Headers).get('authorization')).toBe(
        `Basic ${Buffer.from('owner-id:private-secret').toString('base64')}`
      );
      expect((init?.body as URLSearchParams).get('token')).toBe('private-opaque-token');
      return response({ active: false });
    };
    const result = await observeTokenStatus(request, fetcher);
    expect(result.body).toEqual({ active: false });
    expect(JSON.stringify(result)).not.toMatch(/private-secret|private-opaque-token|owner-id/u);
  });

  it('supports POST authentication without accidentally adding Basic proof', async () => {
    const fetcher: typeof fetch = async (_url, init) => {
      expect((init?.headers as Headers).has('authorization')).toBe(false);
      expect((init?.body as URLSearchParams).get('client_id')).toBe('owner-id');
      expect((init?.body as URLSearchParams).get('client_secret')).toBe('private-secret');
      return response(null, 200, 'revocation');
    };
    const result = await observeTokenStatus(
      {
        ...request,
        kind: 'revocation',
        proof: { method: 'post', clientId: 'owner-id', clientSecret: 'private-secret' },
      },
      fetcher
    );
    expect(result.body).toBeNull();
  });

  it('supports public authentication without a secret', async () => {
    const fetcher: typeof fetch = async (_url, init) => {
      expect((init?.headers as Headers).has('authorization')).toBe(false);
      expect((init?.body as URLSearchParams).get('client_id')).toBe('owner-id');
      expect((init?.body as URLSearchParams).get('client_secret')).toBeNull();
      return response(null, 200, 'revocation');
    };
    const result = await observeTokenStatus(
      { ...request, kind: 'revocation', proof: { method: 'public', clientId: 'owner-id' } },
      fetcher
    );
    expect(result.body).toBeNull();
  });

  it('keeps error status and challenge, and rejects credential-bearing output', async () => {
    const error = {
      code: 'oidc.invalid_client',
      error: 'invalid_client',
      message: 'An OIDC error occurred: oidc.invalid_client.',
      error_description: 'client authentication failed',
    };
    const fetcher: typeof fetch = async () => {
      const result = response(error, 401);
      result.headers.set(
        'www-authenticate',
        'Basic realm="http://localhost:3312/oidc", error="invalid_client", error_description="client authentication failed"'
      );
      return result;
    };
    const observed = await observeTokenStatus(request, fetcher);
    expect(observed.body).toEqual(error);
    await expect(
      observeTokenStatus(request, async () => response({ ...error, token: request.token }, 401))
    ).rejects.toThrow('Invalid Phase 2 token status');
  });

  it('rejects oversized bodies and unexpected credentials or redirects', async () => {
    await expect(
      observeTokenStatus(request, async () =>
        response({ active: false, padding: 'x'.repeat(17_000) })
      )
    ).rejects.toThrow();
    const cookie = response({ active: false });
    cookie.headers.set('set-cookie', 'session=private');
    await expect(observeTokenStatus(request, async () => cookie)).rejects.toThrow();
    await expect(
      observeTokenStatus(request, async () => new Response(null, { status: 302 }))
    ).rejects.toThrow();
  });

  it('rejects a non-root target before sending credentials', async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls += 1;
      return response({ active: false });
    };
    await expect(
      observeTokenStatus(
        { ...request, target: { ...target, coreUrl: 'http://localhost:3312/elsewhere/' } },
        fetcher
      )
    ).rejects.toThrow();
    expect(calls).toBe(0);
  });
});
/* eslint-enable unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
