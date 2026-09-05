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
const rsaModulus = (fill: number, byteLength = 256) =>
  Buffer.alloc(byteLength, fill).toString('base64url');

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

  it('normalizes per-request core identifiers without changing ordinary headers', () => {
    expect(
      normalizeHeaders(
        [
          ['Logto-Core-Request-Id', 'request_id_00001'],
          ['logto-core-request-id', 'request-id-00002'],
          ['x-description', 'stable'],
        ],
        context()
      )
    ).toEqual({
      'logto-core-request-id': ['<per-request-id>', '<per-request-id>'],
      'x-description': ['stable'],
    });
    for (const invalid of ['', 'too-short', 'requestid00000001', 'invalid.value.00']) {
      expect(() => normalizeHeaders([['logto-core-request-id', invalid]], context())).toThrow(
        'Invalid phase 1 headers'
      );
    }
  });

  it('normalizes target Link origins while preserving header occurrences and parameters', () => {
    expect(
      normalizeHeaders(
        [
          ['Link', '<https://oracle.example.com/api/users?page=1>; rel="first"'],
          ['link', '<https://oracle.example.com/api/users?page=2>; rel="next"'],
          ['link', '<https://oracle-console.example.com/console>; rel="admin"'],
        ],
        context()
      )
    ).toEqual({
      link: [
        '<{target.core-origin}/api/users?page=1>; rel="first"',
        '<{target.core-origin}/api/users?page=2>; rel="next"',
        '<{target.admin-origin}/console>; rel="admin"',
      ],
    });
    for (const invalid of [
      '</api/users?page=1>; rel="first"',
      '<https://foreign.example/api/users?page=1>; rel="first"',
      '<https://user:password@oracle.example.com/api/users?page=1>; rel="first"',
      '<https://oracle.example.com/api/users?code=private>; rel="first"',
      '<https://oracle.example.com/api/users#state=private>; rel="first"',
      '<https://oracle.example.com:443/api/users>; rel="first"',
      '<ftp://oracle.example.com/api/users>; rel="first"',
      'rel="first"',
    ]) {
      expect(() => normalizeHeaders([['link', invalid]], context())).toThrow(
        'Invalid phase 1 headers'
      );
    }
  });

  it('normalizes only exact configured CORS origins', () => {
    expect(
      normalizeHeaders(
        [
          ['Access-Control-Allow-Origin', 'https://oracle.example.com'],
          ['access-control-allow-origin', 'https://oracle-console.example.com'],
          ['access-control-allow-origin', 'https://foreign.example'],
          ['access-control-allow-origin', '*'],
          ['access-control-allow-origin', 'null'],
        ],
        context()
      )
    ).toEqual({
      'access-control-allow-origin': [
        '<target.core-url>',
        '<target.admin-url>',
        'https://foreign.example',
        '*',
        'null',
      ],
    });
    for (const invalid of [
      'https://oracle.example.com/',
      'https://oracle.example.com/path',
      'https://oracle.example.com?query=value',
      'https://oracle.example.com#fragment',
      'https://user:password@oracle.example.com',
      'https://oracle.example.com:443',
      'not-an-origin',
    ]) {
      expect(() => normalizeHeaders([['access-control-allow-origin', invalid]], context())).toThrow(
        'Invalid phase 1 headers'
      );
    }
  });

  it('validates entity tags and binds them to the normalized body instead of raw runtime bytes', () => {
    const body = { id: '<user.subject>', roles: ['reader'] };
    const first = normalizeHeaders([['ETag', 'W/"40-runtime-one"']], context(), { body });
    const second = normalizeHeaders([['etag', 'W/"55-runtime-two"']], context(), { body });

    expect(first).toEqual(second);
    expect(first).toEqual({
      etag: [
        {
          weak: true,
          normalizedBodySha256: 'e104cb6776f4b62154952ab306db3d72fa06f28a4e3a2afad3eb328f706c1f66',
        },
      ],
    });
    expect(normalizeHeaders([['etag', '"40-runtime-one"']], context(), { body }).etag).toEqual([
      {
        weak: false,
        normalizedBodySha256: 'e104cb6776f4b62154952ab306db3d72fa06f28a4e3a2afad3eb328f706c1f66',
      },
    ]);
    for (const invalid of ['runtime-tag', 'W/runtime-tag', 'W/"unterminated', '"line\nbreak"']) {
      expect(() => normalizeHeaders([['etag', invalid]], context(), { body })).toThrow(
        'Invalid phase 1 headers'
      );
    }
    expect(() => normalizeHeaders([['etag', 'W/"valid-shape"']], context())).toThrow(
      'Invalid phase 1 headers'
    );

    const timestampBody = {
      createdAt: { $timestamp: 1000, $toleranceSeconds: 30 },
      id: '<user.subject>',
    };
    const withinTolerance = {
      createdAt: { $timestamp: 1005, $toleranceSeconds: 5 },
      id: '<user.subject>',
    };

    expect(compareJson(timestampBody, withinTolerance)).toEqual([]);
    expect(
      normalizeHeaders([['etag', 'W/"runtime-one"']], context(), { body: timestampBody })
    ).toEqual(
      normalizeHeaders([['etag', 'W/"runtime-two"']], context(), { body: withinTolerance })
    );
  });

  it('preserves authentication challenge semantics while redacting only credentials', () => {
    const normalized = normalizeAuthChallenge(
      'Bearer realm="api", error="invalid_token", scope="read write", token="private-token", Basic realm="fallback,api"',
      context()
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
    expect(normalizeAuthChallenge('Negotiate private-token68==', context())).toEqual({
      challenges: [
        {
          scheme: 'Negotiate',
          format: 'token68',
          parameters: ['<redacted-auth-token68>'],
        },
      ],
    });
    expect(
      normalizeAuthChallenge(
        'Bearer realm="https://oracle.example.com/oidc", error="invalid_token"',
        context()
      )
    ).toEqual({
      challenges: [
        {
          scheme: 'Bearer',
          format: 'parameters',
          parameters: [
            { name: 'realm', value: '<target.core-url>/oidc', quoted: true },
            { name: 'error', value: 'invalid_token', quoted: true },
          ],
        },
      ],
    });
    expect(
      normalizeAuthChallenge('Bearer realm="https://foreign.example/oidc"', context())
    ).toMatchObject({
      challenges: [
        {
          parameters: [{ name: 'realm', value: 'https://foreign.example/oidc', quoted: true }],
        },
      ],
    });
    expect(
      normalizeAuthChallenge('Bearer realm="https://oracle-console.example.com/oidc"', context())
    ).toMatchObject({
      challenges: [
        {
          parameters: [{ name: 'realm', value: '<target.admin-url>/oidc', quoted: true }],
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

  it('canonicalizes only configured target URLs and bound logical query values', () => {
    const normalizationContext = context();
    normalizationContext.symbols.bind('fixture.application', 'runtime-application');
    const projection = normalizeRedirect(
      'https://oracle.example.com/oidc/auth?app_id=runtime-application&client_id=runtime-application&iss=https%3A%2F%2Foracle.example.com%2Foidc&scope=openid',
      normalizationContext
    );

    expect(projection).toMatchObject({
      origin: '<target.core-url>',
      path: '/oidc/auth',
      query: {
        app_id: ['<fixture.application>'],
        client_id: ['runtime-application'],
        iss: ['<target.core-url>/oidc'],
        scope: ['openid'],
      },
    });
    expect(
      normalizeRedirect(
        'https://client.example/callback?iss=https%3A%2F%2Fforeign.example%2Foidc',
        normalizationContext
      ).query
    ).toEqual({ iss: ['https://foreign.example/oidc'] });
    expect(
      normalizers.normalizeClaims(
        {
          iss: 'https://oracle.example.com/oidc',
          aud: 'https://oracle.example.com/api',
          scope: 'read',
        },
        normalizationContext
      )
    ).toEqual({
      iss: '<target.core-url>/oidc',
      aud: 'https://oracle.example.com/api',
      scope: 'read',
    });
    expect(
      normalizers.normalizeClaims(
        { iss: 'https://foreign.example/oidc', aud: 'urn:api', scope: 'read' },
        normalizationContext
      )
    ).toEqual({ iss: 'https://foreign.example/oidc', aud: 'urn:api', scope: 'read' });
    for (const nearMiss of [
      'https://oracle.example.com.attacker.test/oidc',
      'http://oracle.example.com/oidc',
      'https://oracle.example.com:443/oidc',
      'https://oracle.example.com:444/oidc',
    ]) {
      expect(normalizers.normalizeClaims({ iss: nearMiss }, normalizationContext)).toEqual({
        iss: nearMiss,
      });
    }
    expect(() =>
      normalizers.normalizeClaims(
        { iss: 'https://oracle.example.com/oidc?token=private', aud: 'urn:api' },
        normalizationContext
      )
    ).toThrow('Invalid phase 1 credential-bearing URL');
  });

  it('normalizes only exact bound scope tokens while preserving order and spacing', () => {
    const normalizationContext = context();
    normalizationContext.symbols.bind('fixture.data.scope-name', 'runtime-scope-value');

    expect(
      normalizers.normalizeClaims(
        { scope: 'openid runtime-scope-value  profile' },
        normalizationContext
      )
    ).toEqual({ scope: 'openid <fixture.data.scope-name>  profile' });
    expect(
      normalizeTokenResponse(
        {
          access_token: 'opaque-private-access-token',
          scope: 'openid runtime-scope-value  profile',
        },
        normalizationContext
      ).scope
    ).toBe('openid <fixture.data.scope-name>  profile');
    expect(
      normalizers.normalizeClaims(
        { scope: 'openid prefixruntime-scope-value suffix' },
        normalizationContext
      )
    ).toEqual({ scope: 'openid prefixruntime-scope-value suffix' });
    expect(
      normalizers.normalizeClaims(
        { scope: 'openid https://resource.example/scope' },
        normalizationContext
      )
    ).toEqual({ scope: 'openid https://resource.example/scope' });
    expect(() =>
      normalizers.normalizeClaims(
        { scope: 'openid https://resource.example/scope?token=private' },
        normalizationContext
      )
    ).toThrow('Invalid phase 1 credential-bearing URL');
  });

  it('projects a one-time resume credential separately from its path template', () => {
    const projection = normalizeResumeRedirect(
      'https://oracle.example.com/oidc/auth/private-resume-credential',
      context()
    );

    expect(projection).toMatchObject({
      origin: '<target.core-url>',
      path: '/oidc/auth/{one-time-resume-credential}',
      resumeCredential: '<redirect.resume-credential.1>',
    });
    expect(JSON.stringify(projection)).not.toContain('private-resume-credential');
  });

  it('derives generated JWKS fingerprints while preserving exact public metadata', async () => {
    const first = normalizers.normalizeDiscovery(
      {
        issuer: 'https://issuer.example',
        kid: 'discovery-extra-kid',
        keys: [
          {
            kty: 'RSA',
            e: 'AQAB',
            n: rsaModulus(0x80),
            kid: 'first-runtime-kid',
            use: 'sig',
            alg: 'RS256',
          },
        ],
      },
      context()
    );
    const second = normalizers.normalizeDiscovery(
      {
        issuer: 'https://issuer.example',
        kid: 'discovery-extra-kid',
        keys: [
          {
            kty: 'RSA',
            e: 'AQAB',
            n: rsaModulus(0x81),
            kid: 'second-runtime-kid',
            use: 'sig',
            alg: 'RS256',
          },
        ],
      },
      context()
    );

    expect(first).toEqual({
      issuer: 'https://issuer.example',
      kid: 'discovery-extra-kid',
      keys: [
        {
          kid: '<signing-key.kid.1>',
          kty: 'RSA',
          use: 'sig',
          alg: 'RS256',
          e: 'AQAB',
          publicKeyBitLength: 2048,
          publicKeyFingerprint: '<signing-key.public-key-fingerprint.1>',
        },
      ],
    });
    expect(second).toEqual(first);
    expect(
      normalizers.normalizeDiscovery(
        {
          issuer: 'https://issuer.example',
          kid: 'discovery-extra-kid',
          keys: [
            {
              kty: 'RSA',
              e: 'AQAB',
              n: rsaModulus(0x82),
              kid: 'third-runtime-kid',
              use: 'sig',
              alg: 'PS256',
            },
          ],
        },
        context()
      )
    ).not.toEqual(first);
    const twoKeys = (reverse: boolean) => {
      const keys = [
        {
          kty: 'RSA',
          e: 'AQAB',
          n: rsaModulus(0x83),
          kid: 'ordered-runtime-kid-a',
          use: 'sig',
          alg: 'RS256',
        },
        {
          kty: 'RSA',
          e: 'AQAB',
          n: rsaModulus(0x84),
          kid: 'ordered-runtime-kid-b',
          use: 'sig',
          alg: 'RS256',
        },
      ];

      return normalizers.normalizeDiscovery(
        {
          issuer: 'https://issuer.example',
          kid: 'discovery-extra-kid',
          keys: reverse ? keys.toReversed() : keys,
        },
        context()
      );
    };
    const ordered = twoKeys(false);

    expect(ordered).not.toEqual(first);
    // A JWKS is a set keyed by `kid`; ordering independent keys with identical metadata is not semantic.
    expect(twoKeys(true)).toEqual(ordered);
    expect(
      normalizers.normalizeDiscovery(
        {
          issuer: 'https://issuer.example',
          kid: 'discovery-extra-kid',
          keys: [
            {
              kty: 'RSA',
              e: 'AQAB',
              n: rsaModulus(0x85, 128),
              kid: 'weak-runtime-kid',
              use: 'sig',
              alg: 'RS256',
            },
          ],
        },
        context()
      )
    ).not.toEqual(first);
    expect(
      normalizers.normalizeDiscovery(
        {
          issuer: 'https://issuer.example',
          kid: 'discovery-extra-kid',
          keys: [
            {
              kty: 'RSA',
              e: 'Aw',
              n: rsaModulus(0x80),
              kid: 'different-exponent-runtime-kid',
              use: 'sig',
              alg: 'RS256',
            },
          ],
        },
        context()
      )
    ).not.toEqual(first);
    const thumbprintKey = {
      kty: 'RSA',
      e: 'AQAB',
      n: rsaModulus(0x86),
      use: 'sig',
      alg: 'RS256',
    } as const;
    const thumbprint = await calculateJwkThumbprint(thumbprintKey);
    const thumbprintProjection = normalizers.normalizeDiscovery(
      { keys: [{ ...thumbprintKey, kid: thumbprint }] },
      context()
    );

    expect(thumbprintProjection.keys).toEqual([
      expect.objectContaining({
        kid: '<signing-key.kid.1>',
        publicKeyFingerprint: '<signing-key.public-key-fingerprint.1>',
      }),
    ]);
    const elliptic = normalizers.normalizeDiscovery(
      {
        keys: [
          {
            kty: 'EC',
            crv: 'P-384',
            x: 'ec-public-x',
            y: 'ec-public-y',
            kid: 'ec-runtime-kid',
            use: 'sig',
            alg: 'ES384',
          },
          {
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'okp-public-x',
            kid: 'okp-runtime-kid',
            use: 'sig',
            alg: 'EdDSA',
          },
        ],
      },
      context()
    );

    expect(elliptic.keys).toEqual([
      {
        alg: 'ES384',
        crv: 'P-384',
        kid: '<signing-key.kid.1>',
        kty: 'EC',
        publicKeyFingerprint: '<signing-key.public-key-fingerprint.1>',
        use: 'sig',
      },
      {
        alg: 'EdDSA',
        crv: 'Ed25519',
        kid: '<signing-key.kid.2>',
        kty: 'OKP',
        publicKeyFingerprint: '<signing-key.public-key-fingerprint.2>',
        use: 'sig',
      },
    ]);
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

  it('uses 30-second timestamp bounds and canonicalizes only epoch deletion expiry', () => {
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
        { created_at: 990_000, updated_at: 1_000_000 },
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
      normalizers.normalizeClaims(
        { created_at: 990_000, updated_at: 1_000_000 },
        context(),
        'id-token',
        { boundedTimestampPaths: ['/created_at', '/updated_at'] }
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
    expect(
      normalizeHeaders(
        [
          [
            'set-cookie',
            '_interaction.sig=; Path=/; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
          ],
          ['date', 'Thu, 01 Jan 1970 00:16:40 GMT'],
        ],
        context()
      )['set-cookie']
    ).toEqual([
      {
        name: '_interaction.sig',
        path: '/',
        httpOnly: true,
        secure: false,
        extensions: [],
        expires: { $timestamp: 0, $toleranceSeconds: 30 },
        expiredAtResponse: true,
      },
    ]);
    const normalizeCookieAtResponseDate = (expires: string) =>
      normalizeHeaders(
        [
          ['set-cookie', `interaction=value; Path=/; HttpOnly; Expires=${expires}`],
          ['date', 'Thu, 01 Jan 1970 00:16:40 GMT'],
        ],
        context()
      )['set-cookie'];

    expect(normalizeCookieAtResponseDate('Thu, 01 Jan 1970 00:16:39 GMT')).toEqual([
      {
        name: 'interaction',
        path: '/',
        httpOnly: true,
        secure: false,
        extensions: [],
        expires: { $timestamp: 999, $toleranceSeconds: 30 },
        expiryOffsetSeconds: -1,
      },
    ]);
    expect(normalizeCookieAtResponseDate('Thu, 01 Jan 1970 00:16:40 GMT')).toEqual([
      {
        name: 'interaction',
        path: '/',
        httpOnly: true,
        secure: false,
        extensions: [],
        expires: { $timestamp: 1000, $toleranceSeconds: 30 },
        expiryOffsetSeconds: 0,
      },
    ]);
    expect(normalizeCookieAtResponseDate('Thu, 01 Jan 1970 00:16:41 GMT')).toEqual([
      {
        name: 'interaction',
        path: '/',
        httpOnly: true,
        secure: false,
        extensions: [],
        expires: { $timestamp: 1001, $toleranceSeconds: 30 },
        expiryOffsetSeconds: 1,
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
