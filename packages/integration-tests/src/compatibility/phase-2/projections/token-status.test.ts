import type { TargetConfig } from '../../model.js';

import { compareTokenStatus, projectTokenStatus } from './token-status.js';

const oracle: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://localhost:3312/',
  adminUrl: 'http://localhost:3412/',
});
const candidate: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'http://localhost:3322/',
  adminUrl: 'http://localhost:3422/',
});

const headers = (kind: 'introspection' | 'revocation', status = 200) => ({
  'content-type':
    kind === 'introspection' || status !== 200
      ? 'application/json; charset=utf-8'
      : 'text/plain; charset=utf-8',
  'access-control-allow-origin': '*',
  ...(kind === 'introspection' ? { 'cache-control': 'no-store' } : {}),
});

const input = (
  target: TargetConfig,
  kind: 'introspection' | 'revocation',
  body: unknown,
  status = 200
) => ({
  target,
  kind,
  body,
  status,
  headers: headers(kind, status),
  subjectId: 'subject-1',
  clientId: 'client-1',
  grant: 'unchanged' as const,
});

const active = (target: TargetConfig, iat = 1000) => ({
  active: true,
  sub: 'subject-1',
  client_id: 'client-1',
  iat,
  exp: iat + 3600,
  iss: new URL('oidc', target.coreUrl).href.replace(/\/$/u, ''),
  scope: 'openid profile',
  token_type: 'Bearer',
});

describe('token status black-box projection', () => {
  it('compares active introspection across distinct targets without publishing runtime identity', () => {
    const left = projectTokenStatus(input(oracle, 'introspection', active(oracle)));
    const right = projectTokenStatus(input(candidate, 'introspection', active(candidate, 2000)));
    expect(compareTokenStatus(left, right)).toEqual([]);
    expect(JSON.stringify(left)).not.toMatch(/subject-1|client-1|localhost|iat":1000/u);
    expect(left.body).toMatchObject({ active: true, exp: { afterIssuedAtSeconds: 3600 } });
  });

  it('retains status, scope, token kind and grant effects as material differences', () => {
    const left = projectTokenStatus(input(oracle, 'introspection', active(oracle)));
    const refresh = projectTokenStatus(
      input(candidate, 'introspection', {
        ...active(candidate),
        token_type: undefined,
      })
    );
    const changed = projectTokenStatus(
      input(candidate, 'introspection', {
        ...active(candidate),
        scope: 'openid',
      })
    );
    expect(compareTokenStatus(left, refresh)).toContain('/body');
    expect(compareTokenStatus(left, changed)).toContain('/body');
    expect(compareTokenStatus(left, { ...left, grant: 'revoked' })).toEqual(['/grant']);
    expect(compareTokenStatus(left, { ...left, status: 401 })).toEqual(['/status']);
    expect(
      compareTokenStatus(left, {
        ...left,
        headers: { ...left.headers, 'access-control-allow-origin': 'https://unapproved.example' },
      })
    ).toEqual(['/headers']);
  });

  it('projects inactive, empty revocation and explicit unsupported-token errors', () => {
    const inactive = projectTokenStatus(input(oracle, 'introspection', { active: false }));
    const revoked = projectTokenStatus(input(oracle, 'revocation', null));
    const rejected = projectTokenStatus(
      input(
        oracle,
        'introspection',
        {
          code: 'oidc.unsupported_token_type',
          error: 'unsupported_token_type',
          message: 'An OIDC error occurred: oidc.unsupported_token_type.',
          error_description:
            'Structured JWT Tokens cannot be introspected via the introspection_endpoint',
        },
        400
      )
    );
    expect(inactive.body).toEqual({ active: false });
    expect(revoked.body).toBeNull();
    expect(rejected.status).toBe(400);
    expect(compareTokenStatus(inactive, rejected)).toEqual(['/status', '/body']);
  });

  it('rejects token-bearing fields, unexpected claims and forged active ownership', () => {
    expect(() =>
      projectTokenStatus(
        input(oracle, 'introspection', {
          ...active(oracle),
          access_token: 'private bearer',
        })
      )
    ).toThrow();
    expect(() =>
      projectTokenStatus(
        input(oracle, 'introspection', {
          ...active(oracle),
          sub: 'other-user',
        })
      )
    ).toThrow();
    expect(() =>
      projectTokenStatus(
        input(oracle, 'introspection', {
          active: false,
          sub: 'subject-1',
        })
      )
    ).toThrow();
    expect(() => projectTokenStatus(input(oracle, 'revocation', { active: false }))).toThrow();
    expect(() =>
      projectTokenStatus({
        ...input(oracle, 'introspection', { active: false }),
        headers: { ...headers('introspection'), 'x-private-credential': 'secret' },
      })
    ).toThrow();
    expect(() =>
      projectTokenStatus({
        ...input(oracle, 'introspection', { active: false }),
        headers: { ...headers('introspection'), 'www-authenticate': 'Bearer private' },
      })
    ).toThrow();
  });
});
