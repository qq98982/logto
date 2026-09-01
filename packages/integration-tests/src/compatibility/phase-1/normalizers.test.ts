/* eslint-disable max-lines, @typescript-eslint/consistent-type-assertions -- The field-specific boundary matrix and hostile sparse-array fixture intentionally keep the twelve normalizers in one reviewable suite. */
import { calculateJwkThumbprint } from 'jose';

import { compareJson } from '../compare.js';
import { SymbolTable } from '../symbol-table.js';

import * as normalizers from './normalizers.js';
import {
  normalizeAuthChallenge,
  normalizeConcurrentOutcomes,
  normalizeHeaders,
  normalizeRedirect,
  normalizeResumeRedirect,
  normalizeTokenResponse,
} from './normalizers.js';

const context = () => ({
  target: {
    label: 'oracle' as const,
    coreUrl: 'https://oracle.example.com/',
    adminUrl: 'https://oracle-console.example.com/',
  },
  symbols: new SymbolTable(),
});

describe('phase 1 field-specific normalizers', () => {
  it('exports exactly the twelve reviewed named normalizers', () => {
    expect(Object.keys(normalizers).toSorted()).toEqual([
      'normalizeAuthChallenge',
      'normalizeClaims',
      'normalizeConcurrentOutcomes',
      'normalizeCookieContinuity',
      'normalizeDiscovery',
      'normalizeExperienceError',
      'normalizeHeaders',
      'normalizeLogicalFixtureIds',
      'normalizeOAuthError',
      'normalizeRedirect',
      'normalizeResumeRedirect',
      'normalizeTokenResponse',
    ]);
  });

  it('preserves duplicate headers while redacting Location and Set-Cookie credentials', () => {
    const normalized = normalizeHeaders(
      [
        ['X-Order', 'first'],
        ['x-order', 'second'],
        ['Location', 'https://client.example/callback?code=private-code&state=private-state'],
        ['Set-Cookie', 'interaction=private-cookie; Path=/; HttpOnly; SameSite=Lax'],
      ],
      context()
    );

    expect(normalized['x-order']).toEqual(['first', 'second']);
    expect(JSON.stringify(normalized)).not.toContain('private-code');
    expect(JSON.stringify(normalized)).not.toContain('private-state');
    expect(JSON.stringify(normalized)).not.toContain('private-cookie');
    expect(normalized.location).toHaveLength(1);
    expect(normalized['set-cookie']).toHaveLength(1);
  });

  it('keeps unknown header strings exact instead of replacing embedded fixture IDs', () => {
    const normalizationContext = context();
    normalizationContext.symbols.bind('fixture.user.subject', 'runtime-user-7f1a');

    expect(
      normalizeHeaders([['x-description', 'prefix runtime-user-7f1a suffix']], normalizationContext)
    ).toEqual({ 'x-description': ['prefix runtime-user-7f1a suffix'] });
  });

  it('preserves authentication challenge semantics while redacting only credentials', () => {
    const normalized = normalizeAuthChallenge(
      'Bearer realm="api", error="invalid_token", scope="read write", token="private-token", Basic realm="fallback,api"'
    );

    expect(normalized).toEqual({
      challenges: [
        {
          scheme: 'Bearer',
          format: 'parameters',
          parameters: [
            { name: 'realm', value: 'api', quoted: true },
            { name: 'error', value: 'invalid_token', quoted: true },
            { name: 'scope', value: 'read write', quoted: true },
            { name: 'token', value: '<redacted-auth-parameter>', quoted: true },
          ],
        },
        {
          scheme: 'Basic',
          format: 'parameters',
          parameters: [{ name: 'realm', value: 'fallback,api', quoted: true }],
        },
      ],
    });
    expect(JSON.stringify(normalized)).not.toContain('private-token');
    expect(normalizeAuthChallenge('Negotiate private-token68==')).toEqual({
      challenges: [
        {
          scheme: 'Negotiate',
          format: 'token68',
          parameters: ['<redacted-auth-token68>'],
        },
      ],
    });
  });

  it('projects redirects as an exact structured multimap', () => {
    expect(
      normalizeRedirect(
        'https://client.example/callback?scope=read&scope=write&code=first&code=second&state=secret',
        context()
      )
    ).toEqual({
      scheme: 'https',
      origin: 'https://client.example',
      path: '/callback',
      query: { scope: ['read', 'write'] },
      fragment: '',
      redactedParameters: [
        { component: 'query', name: 'code', count: 2 },
        { component: 'query', name: 'state', count: 1 },
      ],
    });
  });

  it('projects a one-time resume credential separately from its path template', () => {
    const projection = normalizeResumeRedirect(
      'https://oracle.example.com/oidc/auth/private-resume-credential',
      context()
    );

    expect(projection).toMatchObject({
      origin: 'https://oracle.example.com',
      path: '/oidc/auth/{one-time-resume-credential}',
      resumeCredential: '<redirect.resume-credential.1>',
    });
    expect(JSON.stringify(projection)).not.toContain('private-resume-credential');
  });

  it('derives RFC 7638 fingerprints and only symbolizes JWKS key IDs', async () => {
    const jwk = { kty: 'RSA', e: 'AQAB', n: 'public-modulus', kid: 'runtime-kid' } as const;
    const fingerprint = await calculateJwkThumbprint(jwk);
    const projection = normalizers.normalizeDiscovery(
      { issuer: 'https://issuer.example', kid: 'discovery-extra-kid', keys: [jwk] },
      context()
    );

    expect(projection).toEqual({
      issuer: 'https://issuer.example',
      kid: 'discovery-extra-kid',
      keys: [
        {
          e: 'AQAB',
          kid: '<signing-key.kid.1>',
          kty: 'RSA',
          n: 'public-modulus',
          publicKeyFingerprint: fingerprint,
        },
      ],
    });
  });

  it('redacts credential-bearing fragments while preserving ordinary fragment fields', () => {
    const projection = normalizeRedirect(
      'https://client.example/callback#code=private-code&scope=read',
      context()
    );

    expect(projection.fragment).toContain('scope=read');
    expect(projection.fragment).not.toContain('private-code');
    expect(projection.redactedParameters).toEqual([
      { component: 'fragment', name: 'code', count: 1 },
    ]);
  });

  it('distinguishes missing single and duplicate redirect credentials without their values', () => {
    const missing = normalizeRedirect('https://client.example/callback', context());
    const single = normalizeRedirect(
      'https://client.example/callback?code=private-a&state=private-state',
      context()
    );
    const duplicate = normalizeRedirect(
      'https://client.example/callback?code=private-a&code=private-b&state=private-state',
      context()
    );

    expect(single.redactedParameters).toEqual([
      { component: 'query', name: 'code', count: 1 },
      { component: 'query', name: 'state', count: 1 },
    ]);
    expect(duplicate.redactedParameters).toEqual([
      { component: 'query', name: 'code', count: 2 },
      { component: 'query', name: 'state', count: 1 },
    ]);
    expect(compareJson(missing, single)).not.toEqual([]);
    expect(compareJson(single, duplicate)).not.toEqual([]);
    expect(JSON.stringify([missing, single, duplicate])).not.toContain('private-');
  });

  it('rejects non-cookie metadata fields and preserves security attributes exactly', () => {
    expect(
      normalizers.normalizeCookieContinuity([
        {
          name: 'interaction',
          path: '/',
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
        },
      ])
    ).toEqual([
      {
        name: 'interaction',
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        extensions: [],
      },
    ]);
    expect(() =>
      normalizers.normalizeCookieContinuity([
        {
          name: 'interaction',
          httpOnly: true,
          secure: true,
          rawValue: 'private-cookie',
        } as never,
      ])
    ).toThrow('Invalid phase 1 cookie continuity');
  });

  it('uses 30-second timestamp bounds and preserves exact cookie expiry offsets', () => {
    const first = normalizers.normalizeClaims(
      { iat: 1000, exp: 4600, nbf: 900, created_at: 990 },
      context(),
      'access-token',
      { boundedTimestampPaths: ['/iat', '/exp'] }
    );
    const within = normalizers.normalizeClaims(
      { iat: 1030, exp: 4630, nbf: 900, created_at: 990 },
      context(),
      'access-token',
      { boundedTimestampPaths: ['/iat', '/exp'] }
    );
    const outside = normalizers.normalizeClaims(
      { iat: 1031, exp: 4631, nbf: 900, created_at: 990 },
      context(),
      'access-token',
      { boundedTimestampPaths: ['/iat', '/exp'] }
    );

    expect(first).toMatchObject({
      iat: { $timestamp: 1000, $toleranceSeconds: 30 },
      exp: { $timestamp: 4600, $toleranceSeconds: 30 },
      nbf: 900,
      created_at: 990,
      tokenLifetimeSeconds: 3600,
    });
    expect(compareJson(first, within)).toEqual([]);
    expect(compareJson(first, outside).map(({ path }) => path)).toEqual(['/exp', '/iat']);
    expect(
      compareJson(
        first,
        normalizers.normalizeClaims(
          { iat: 1000, exp: 4600, nbf: 900, created_at: 1020 },
          context(),
          'access-token',
          { boundedTimestampPaths: ['/iat', '/exp'] }
        )
      ).map(({ path }) => path)
    ).toEqual(['/created_at']);
    expect(
      normalizers.normalizeClaims(
        { created_at: 990, updated_at: 1000 },
        context(),
        'access-token',
        {
          profile: 'userinfo',
          boundedTimestampPaths: ['/created_at', '/updated_at'],
        }
      )
    ).toEqual({
      created_at: { $timestamp: 990, $toleranceSeconds: 30 },
      updated_at: { $timestamp: 1000, $toleranceSeconds: 30 },
    });
    expect(
      normalizers.normalizeCookieContinuity(
        [
          'interaction=value; Path=/; HttpOnly; Max-Age=3600; Expires=Thu, 01 Jan 1970 01:16:40 GMT',
        ],
        { responseDateSeconds: 1000 }
      )
    ).toEqual([
      {
        name: 'interaction',
        path: '/',
        httpOnly: true,
        secure: false,
        maxAge: 3600,
        extensions: [],
        expires: { $timestamp: 4600, $toleranceSeconds: 30 },
        expiryOffsetSeconds: 3600,
      },
    ]);
    expect(
      normalizeHeaders(
        [
          [
            'set-cookie',
            'interaction=value; Path=/; HttpOnly; Expires=Thu, 01 Jan 1970 01:16:40 GMT',
          ],
          ['date', 'Thu, 01 Jan 1970 00:16:40 GMT'],
        ],
        context()
      )['set-cookie']
    ).toEqual([
      {
        name: 'interaction',
        path: '/',
        httpOnly: true,
        secure: false,
        extensions: [],
        expires: { $timestamp: 4600, $toleranceSeconds: 30 },
        expiryOffsetSeconds: 3600,
      },
    ]);
    expect(() =>
      normalizers.normalizeCookieContinuity(
        ['interaction=value; Path=/; Expires=Thu, 01 Jan 1970 01:16:40 GMT'],
        { requireExpiryOffset: true }
      )
    ).toThrow('Invalid phase 1 cookie continuity');
  });

  it('preserves Set-Cookie occurrence order and unknown extension attributes', () => {
    expect(
      normalizers.normalizeCookieContinuity([
        'second=value; Path=/; Priority=High',
        'first=value; Path=/; Partitioned',
      ])
    ).toEqual([
      {
        name: 'second',
        path: '/',
        httpOnly: false,
        secure: false,
        extensions: [{ name: 'priority', value: 'High' }],
      },
      {
        name: 'first',
        path: '/',
        httpOnly: false,
        secure: false,
        extensions: [{ name: 'partitioned' }],
      },
    ]);
  });

  it('rejects cookie values reproduced by same-header or cross-header metadata', () => {
    expect(() =>
      normalizers.normalizeCookieContinuity([
        'first=private-cookie-value; Path=/',
        'second=other-value; Path=/private-cookie-value',
      ])
    ).toThrow('Invalid phase 1 cookie continuity');
    expect(() =>
      normalizeHeaders(
        [
          ['set-cookie', 'first=private-cookie-value; Path=/'],
          ['set-cookie', 'second=other-value; Priority=private-cookie-value'],
        ],
        context()
      )
    ).toThrow('Invalid phase 1 headers');
    for (const encodedPath of ['secret%2fvalue', 'secret%252Fvalue']) {
      expect(() =>
        normalizers.normalizeCookieContinuity([
          'first=secret/value; Path=/',
          `second=other-value; Path=/${encodedPath}`,
        ])
      ).toThrow('Invalid phase 1 cookie continuity');
    }
  });

  it('preserves OAuth error codes but redacts nested credential-shaped diagnostics', () => {
    expect(
      normalizers.normalizeOAuthError({
        error: 'invalid_grant',
        code: 'invalid_grant_code',
        detail: { message: 'callback?code=private-code' },
      })
    ).toEqual({
      error: 'invalid_grant',
      errorCode: 'invalid_grant_code',
      detail: { message: '<redacted-error-value>' },
    });
  });

  it('sorts concurrent semantic outcomes without mutating the input', () => {
    const input = [
      { kind: 'success', winner: 'b' },
      { kind: 'error', error: 'invalid_grant' },
      { kind: 'success', winner: 'a' },
    ];
    expect(normalizeConcurrentOutcomes(input, context())).toEqual([
      { error: 'invalid_grant', kind: 'error' },
      { kind: 'success', winner: 'b' },
      { kind: 'success', winner: 'a' },
    ]);
    expect(input).toEqual([
      { kind: 'success', winner: 'b' },
      { kind: 'error', error: 'invalid_grant' },
      { kind: 'success', winner: 'a' },
    ]);
  });

  it('never returns raw token response credentials', () => {
    const result = normalizeTokenResponse(
      {
        access_token: 'opaque-private-access-token',
        refresh_token: 'opaque-private-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'openid profile',
      },
      context(),
      { boundedClaimTimestampPaths: ['/iat', '/exp', '/auth_time'] }
    );
    const serialized = JSON.stringify(result);

    expect(result).toMatchObject({ tokenType: 'Bearer', expiresIn: 3600, scope: 'openid profile' });
    expect(serialized).not.toContain('opaque-private');
  });

  it('normalizes a structurally well-formed JWT once without dropping extensions', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'runtime-key' })).toString(
      'base64url'
    );
    const claims = Buffer.from(
      JSON.stringify({
        iss: 'https://issuer.example',
        aud: ['urn:api:b', 'urn:api:a'],
        scope: 'write read',
        iat: 1000,
        exp: 4600,
        auth_time: 950,
        nbf: 900,
        custom: 'exact',
      })
    ).toString('base64url');
    const compact = `${header}.${claims}.signature`;
    const result = normalizeTokenResponse(
      {
        access_token: compact,
        token_type: 'Bearer',
        scope: 'write read',
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      },
      context(),
      { boundedClaimTimestampPaths: ['/iat', '/exp', '/auth_time'] }
    );

    expect(result).toMatchObject({
      tokenType: 'Bearer',
      scope: 'write read',
      access: {
        format: 'jwt',
        header: { alg: 'RS256', kid: '<signing-key.kid.1>' },
        claims: {
          iss: 'https://issuer.example',
          aud: ['urn:api:b', 'urn:api:a'],
          scope: 'write read',
          iat: { $timestamp: 1000, $toleranceSeconds: 30 },
          exp: { $timestamp: 4600, $toleranceSeconds: 30 },
          auth_time: { $timestamp: 950, $toleranceSeconds: 30 },
          nbf: 900,
          custom: 'exact',
          tokenLifetimeSeconds: 3600,
        },
      },
      additionalFields: [
        {
          name: 'issued_token_type',
          value: 'urn:ietf:params:oauth:token-type:access_token',
        },
      ],
    });
  });

  it('rejects private JWK material in a token header', () => {
    const header = Buffer.from(
      JSON.stringify({ alg: 'HS256', jwk: { kty: 'oct', k: 'private-key-material' } })
    ).toString('base64url');
    const claims = Buffer.from(JSON.stringify({ sub: 'subject' })).toString('base64url');

    expect(() =>
      normalizeTokenResponse({ access_token: `${header}.${claims}.signature` }, context())
    ).toThrow('Invalid phase 1 token header');
  });
});

/* eslint-enable max-lines, @typescript-eslint/consistent-type-assertions */
