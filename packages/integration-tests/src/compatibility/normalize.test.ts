/* eslint-disable max-lines -- Integration coverage intentionally keeps all normalizer contracts in one focused suite. */
import { SignJWT, base64url } from 'jose';

import {
  normalizeJson,
  normalizeJwt,
  normalizeSetCookies,
  type NormalizationContext,
} from './normalize.js';
import { SymbolTable } from './symbol-table.js';

const createContext = (overrides: Partial<NormalizationContext> = {}): NormalizationContext => ({
  target: {
    label: 'oracle',
    coreUrl: 'https://core.example.com',
    adminUrl: 'https://admin.example.com',
  },
  symbols: new SymbolTable(),
  ...overrides,
});

const signJwt = async (claims: Record<string, unknown>, kid = 'runtime-kid') =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256', kid, typ: 'JWT' })
    .sign(new TextEncoder().encode('test-only-signing-key-with-sufficient-length'));

const createCompactJwt = (
  header: unknown,
  claims: unknown,
  signatureMarker = 'fixture-signature'
) =>
  [
    base64url.encode(JSON.stringify(header)),
    base64url.encode(JSON.stringify(claims)),
    base64url.encode(signatureMarker),
  ].join('.');

const getThrownMessage = (operation: () => unknown): string => {
  try {
    operation();
  } catch (error: unknown) {
    return error instanceof Error ? error.message : String(error);
  }

  throw new Error('Expected operation to throw');
};

describe('SymbolTable', () => {
  it('binds idempotently and exposes both lookup directions', () => {
    const symbols = new SymbolTable();

    expect(symbols.bind('user.primary', 'runtime-user')).toBe('user.primary');
    expect(symbols.bind('user.primary', 'runtime-user')).toBe('user.primary');
    expect(symbols.getRuntimeValue('user.primary')).toBe('runtime-user');
    expect(symbols.getLogicalName('runtime-user')).toBe('user.primary');
  });

  it('rejects empty bindings and conflicts in either direction', () => {
    const symbols = new SymbolTable();

    expect(() => symbols.bind('', 'runtime-user')).toThrow(/logical name.*non-empty/i);
    expect(() => symbols.bind('user.primary', '')).toThrow(/runtime value.*non-empty/i);
    symbols.bind('user.primary', 'runtime-user');
    expect(() => symbols.bind('user.primary', 'other-user')).toThrow(/already bound/i);
    expect(() => symbols.bind('user.secondary', 'runtime-user')).toThrow(/already bound/i);
  });

  it('allocates occurrence symbols only for unseen values and keeps counters per namespace', () => {
    const symbols = new SymbolTable();

    expect(symbols.bindOccurrence('id-token.jti', 'jti-a')).toBe('id-token.jti.1');
    expect(symbols.bindOccurrence('id-token.jti', 'jti-a')).toBe('id-token.jti.1');
    expect(symbols.bindOccurrence('id-token.jti', 'jti-b')).toBe('id-token.jti.2');
    expect(symbols.bindOccurrence('access-token.jti', 'jti-c')).toBe('access-token.jti.1');
  });

  it('skips prebound occurrence names without consuming a value binding', () => {
    const symbols = new SymbolTable();
    symbols.bind('id-token.jti.1', 'existing-jti');

    expect(symbols.bindOccurrence('id-token.jti', 'new-jti')).toBe('id-token.jti.2');
    expect(symbols.bindOccurrence('id-token.jti', 'new-jti')).toBe('id-token.jti.2');
  });

  it('keeps occurrence state local to each target table', () => {
    const oracle = new SymbolTable();
    const candidate = new SymbolTable();

    expect(oracle.bindOccurrence('id-token.sid', 'oracle-sid')).toBe('id-token.sid.1');
    expect(candidate.bindOccurrence('id-token.sid', 'candidate-sid')).toBe('id-token.sid.1');
  });

  it('replaces literal regex-like and overlapping values longest-first', () => {
    const symbols = new SymbolTable();

    symbols.bind('short', 'a.b');
    symbols.bind('long', 'a.b+c');
    symbols.bind('brackets', '[runtime]');

    expect(symbols.replace('a.b+c / a.b / [runtime] / axb')).toBe(
      '<long> / <short> / <brackets> / axb'
    );
  });

  it('does not replace runtime-like text introduced inside a placeholder', () => {
    const symbols = new SymbolTable();
    symbols.bind('logical.runtime', 'secret');
    symbols.bind('other', 'logical.runtime');

    expect(symbols.replace('secret')).toBe('<logical.runtime>');
  });
});

describe('normalizeJson', () => {
  it('replaces overlapping target URLs before replacing target-local symbols', () => {
    const context = createContext({
      target: {
        label: 'candidate',
        coreUrl: 'https://example.com',
        adminUrl: 'https://example.com/admin',
      },
    });
    context.symbols.bind('user.primary', 'runtime-user');

    expect(
      normalizeJson(
        {
          core: 'https://example.com/api/runtime-user',
          admin: 'https://example.com/admin/users/runtime-user',
        },
        context,
        []
      )
    ).toEqual({
      core: '<target.core-url>/api/<user.primary>',
      admin: '<target.admin-url>/users/<user.primary>',
    });
  });

  it('replaces URLs atomically only at URL boundaries before replacing symbols', () => {
    const context = createContext({
      target: {
        label: 'candidate',
        coreUrl: 'https://example.com',
        adminUrl: 'https://example.com/admin',
      },
    });
    context.symbols.bind('word.target', 'target');
    context.symbols.bind('word.angle-target', '<target');
    context.symbols.bind('url.business', 'https://example.com/admin');

    expect(
      normalizeJson(
        {
          evilSuffix: 'https://example.com.evil/path',
          differentPort: 'https://example.com:444/path',
          path: 'https://example.com/path',
          query: 'https://example.com?key=value',
          fragment: 'https://example.com#section',
          end: 'https://example.com',
          overlappingAdmin: 'https://example.com/admin/users',
          opaquePlaceholders: 'https://example.com/path target <target',
          urlBeforeSymbol: 'https://example.com/admin',
        },
        context,
        []
      )
    ).toEqual({
      evilSuffix: 'https://example.com.evil/path',
      differentPort: 'https://example.com:444/path',
      path: '<target.core-url>/path',
      query: '<target.core-url>?key=value',
      fragment: '<target.core-url>#section',
      end: '<target.core-url>',
      overlappingAdmin: '<target.admin-url>/users',
      opaquePlaceholders: '<target.core-url>/path <word.target> <word.angle-target>',
      urlBeforeSymbol: '<target.admin-url>',
    });
  });

  it('leaves one canonical configured trailing slash in the normalized observation', () => {
    const context = createContext({
      target: {
        label: 'candidate',
        coreUrl: 'https://slash.example/',
        adminUrl: 'https://slash.example/admin/',
      },
    });

    expect(
      normalizeJson(
        {
          exactRoot: 'https://slash.example/',
          rootWithoutSlash: 'https://slash.example',
          path: 'https://slash.example/api',
          query: 'https://slash.example/?key=value',
          queryWithoutSlash: 'https://slash.example?key=value',
          fragment: 'https://slash.example/#section',
          overlappingAdminRoot: 'https://slash.example/admin/',
          overlappingAdminPath: 'https://slash.example/admin/users',
          overlappingAdminQuery: 'https://slash.example/admin/?key=value',
          evilSuffix: 'https://slash.example.evil/path',
          differentPort: 'https://slash.example:444/path',
        },
        context,
        []
      )
    ).toEqual({
      exactRoot: '<target.core-url>/',
      rootWithoutSlash: '<target.core-url>',
      path: '<target.core-url>/api',
      query: '<target.core-url>/?key=value',
      queryWithoutSlash: '<target.core-url>?key=value',
      fragment: '<target.core-url>/#section',
      overlappingAdminRoot: '<target.admin-url>/',
      overlappingAdminPath: '<target.admin-url>/users',
      overlappingAdminQuery: '<target.admin-url>/?key=value',
      evilSuffix: 'https://slash.example.evil/path',
      differentPort: 'https://slash.example:444/path',
    });

    expect(
      normalizeJson(
        'https://duplicate.example/',
        createContext({
          target: {
            label: 'candidate',
            coreUrl: 'https://duplicate.example/',
            adminUrl: 'https://duplicate.example',
          },
        }),
        []
      )
    ).toBe('<target.core-url>/');
  });

  it('applies escaped JSON Pointer paths exactly and removes array elements deterministically', () => {
    const input = {
      'a/b': { '~key': 'remove', keep: 'value' },
      items: ['zero', 'remove-one', 'two', 'remove-three'],
    };

    expect(
      normalizeJson(input, createContext(), [
        { path: '/a~1b/~0key', strategy: 'drop' },
        { path: '/items/1', strategy: 'drop' },
        { path: '/items/3', strategy: 'drop' },
      ])
    ).toEqual({ 'a/b': { keep: 'value' }, items: ['zero', 'two'] });
  });

  it('marks timestamps and preserves authorization claims without heuristics', () => {
    expect(
      normalizeJson(
        { scope: 'read write', aud: 'https://api.example', iat: 100, exp: 3700 },
        createContext(),
        [
          { path: '/iat', strategy: 'timestamp', toleranceSeconds: 60 },
          { path: '/exp', strategy: 'timestamp', toleranceSeconds: 60 },
        ]
      )
    ).toEqual({
      scope: 'read write',
      aud: 'https://api.example',
      iat: { $timestamp: 100, $toleranceSeconds: 60 },
      exp: { $timestamp: 3700, $toleranceSeconds: 60 },
    });
  });

  it('preserves unchecked material fields exactly when no rules apply', () => {
    const materialClaims = {
      id: 'record-123',
      state: 'state-456',
      code: 'code-789',
      scope: 'read write',
      aud: 'urn:example:audience',
      iss: 'urn:example:issuer',
      sub: 'subject-value',
      role: 'admin',
      organization: { id: 'organization-1', name: 'Primary' },
    };

    expect(normalizeJson(materialClaims, createContext(), [])).toEqual(materialClaims);
  });

  it('derives durations from the untouched original input', () => {
    expect(
      normalizeJson({ startedAt: 100, finishedAt: 145 }, createContext(), [
        { path: '/startedAt', strategy: 'timestamp', toleranceSeconds: 5 },
        { path: '/finishedAt', strategy: 'duration-seconds', startPath: '/startedAt' },
      ])
    ).toEqual({
      startedAt: { $timestamp: 100, $toleranceSeconds: 5 },
      finishedAt: { $durationSeconds: 45 },
    });
  });

  it('supports the empty root pointer and keeps it distinct from an empty property pointer', () => {
    expect(
      normalizeJson(100, createContext(), [
        { path: '', strategy: 'timestamp', toleranceSeconds: 2 },
      ])
    ).toEqual({ $timestamp: 100, $toleranceSeconds: 2 });
    expect(
      normalizeJson(100, createContext(), [
        { path: '', strategy: 'duration-seconds', startPath: '' },
      ])
    ).toEqual({ $durationSeconds: 0 });
    expect(
      normalizeJson({ '': 100 }, createContext(), [
        { path: '/', strategy: 'timestamp', toleranceSeconds: 3 },
      ])
    ).toEqual({ '': { $timestamp: 100, $toleranceSeconds: 3 } });
    expect(() =>
      normalizeJson({ value: 1 }, createContext(), [{ path: '', strategy: 'drop' }])
    ).toThrow(/root cannot be dropped/i);
    expect(() =>
      normalizeJson(100, createContext(), [
        { path: '', strategy: 'timestamp', toleranceSeconds: 1 },
        { path: '', strategy: 'timestamp', toleranceSeconds: 2 },
      ])
    ).toThrow(/duplicate normalization rule/i);
  });

  it('recurses through deep arrays and objects without mutating input, context, or rules', () => {
    const input = { nested: [{ url: 'https://core.example.com/runtime-user', state: 'keep' }] };
    const rules = [{ path: '/nested/0/state', strategy: 'drop' as const }];
    const context = createContext();
    context.symbols.bind('user.primary', 'runtime-user');
    const inputSnapshot = structuredClone(input);
    const targetSnapshot = structuredClone(context.target);
    const rulesSnapshot = structuredClone(rules);

    expect(normalizeJson(input, context, rules)).toEqual({
      nested: [{ url: '<target.core-url>/<user.primary>' }],
    });
    expect(input).toEqual(inputSnapshot);
    expect(context.target).toEqual(targetSnapshot);
    expect(rules).toEqual(rulesSnapshot);
  });

  it.each([
    [{ path: 'not-absolute', strategy: 'drop' as const }, /absolute json pointer/i],
    [{ path: '/bad~2escape', strategy: 'drop' as const }, /json pointer escape/i],
    [{ path: '/missing', strategy: 'drop' as const }, /does not exist/i],
    [
      { path: '/value', strategy: 'timestamp' as const, toleranceSeconds: -1 },
      /tolerance.*non-negative/i,
    ],
    [
      { path: '/value', strategy: 'timestamp' as const, toleranceSeconds: Number.NaN },
      /tolerance.*finite/i,
    ],
  ])('rejects an invalid normalization rule %#', (rule, expectedError) => {
    expect(() => normalizeJson({ value: 1 }, createContext(), [rule])).toThrow(expectedError);
  });

  it('rejects strategies outside the closed normalization rule union at runtime', () => {
    expect(() =>
      Reflect.apply(normalizeJson, undefined, [
        { value: 1 },
        createContext(),
        [{ path: '/value', strategy: 'automatic' }],
      ])
    ).toThrow(/unknown normalization strategy/i);
  });

  it('rejects duplicate and ancestor-drop conflicts', () => {
    expect(() =>
      normalizeJson({ value: 1 }, createContext(), [
        { path: '/value', strategy: 'drop' },
        { path: '/value', strategy: 'timestamp', toleranceSeconds: 1 },
      ])
    ).toThrow(/duplicate.*\/value/i);
    expect(() =>
      normalizeJson({ value: { nested: 1 } }, createContext(), [
        { path: '/value', strategy: 'drop' },
        { path: '/value/nested', strategy: 'timestamp', toleranceSeconds: 1 },
      ])
    ).toThrow(/conflicting.*drop/i);
  });

  it('rejects invalid JSON and nonnumeric timestamp or duration sources', () => {
    expect(() => normalizeJson({ value: Number.POSITIVE_INFINITY }, createContext(), [])).toThrow(
      /json/i
    );
    expect(() =>
      normalizeJson({ value: '100' }, createContext(), [
        { path: '/value', strategy: 'timestamp', toleranceSeconds: 1 },
      ])
    ).toThrow(/timestamp.*finite number/i);
    expect(() =>
      normalizeJson({ start: '100', end: 110 }, createContext(), [
        { path: '/end', strategy: 'duration-seconds', startPath: '/start' },
      ])
    ).toThrow(/start path.*finite number/i);
  });
});

describe('normalizeSetCookies', () => {
  it('removes values while preserving canonical metadata and input order', () => {
    expect(
      normalizeSetCookies([
        'interaction="secret-like.value"; Path=/; HttpOnly; SameSite=lax',
        'session=another-secret; DOMAIN=example.com; secure; SAMESITE=STRICT; Max-Age=60',
      ])
    ).toEqual([
      { name: 'interaction', path: '/', httpOnly: true, secure: false, sameSite: 'Lax' },
      {
        name: 'session',
        domain: 'example.com',
        httpOnly: false,
        secure: true,
        sameSite: 'Strict',
        maxAge: 60,
      },
    ]);
  });

  it('normalizes valid expiry dates without exposing the cookie value', () => {
    expect(normalizeSetCookies(['name=top-secret; Expires=Wed, 21 Oct 2015 07:28:00 GMT'])).toEqual(
      [
        {
          name: 'name',
          httpOnly: false,
          secure: false,
          expires: '2015-10-21T07:28:00.000Z',
        },
      ]
    );
  });

  it.each([
    ['0', 'a numeric date shortcut'],
    ['Wed, 21 Oct 2015 07:28:00 UTC', 'non-IMF timezone grammar'],
    ['Mon, 31 Feb 2020 07:28:00 GMT', 'an impossible calendar date'],
    ['Wed, 21 Oct 2015 24:00:00 GMT', 'an invalid time'],
    ['Thu, 21 Oct 2015 07:28:00 GMT', 'a weekday mismatch'],
  ])('rejects invalid Expires case %# without echoing its value', (expiresValue) => {
    const message = getThrownMessage(() =>
      normalizeSetCookies([`name=private-cookie; Expires=${expiresValue}`])
    );

    expect(message).toMatch(/expires/i);
    expect(message).not.toContain(expiresValue);
  });

  it('keeps a valid Expires comma in one header and one cookie observation', () => {
    const normalized = normalizeSetCookies([
      'payload=value; Path=/observations; Secure; Expires=Wed, 21 Oct 2015 07:28:00 GMT',
    ]);

    expect(normalized).toHaveLength(1);
    expect(normalized).toEqual([
      {
        name: 'payload',
        path: '/observations',
        httpOnly: false,
        secure: true,
        expires: '2015-10-21T07:28:00.000Z',
      },
    ]);
  });

  it.each([
    ['header-marker', 'name=value\r\nheader-marker: injected', /control/i],
    ['pair-marker', 'pair-marker', /cookie-pair/i],
    ['name-marker', 'bad(name-marker=value', /cookie name/i],
    ['comma-marker', 'name=value,comma-marker', /cookie value/i],
    ['quote-marker', 'name="quote-marker', /cookie value/i],
    ['interior-marker', 'name=bad"interior-marker"value', /cookie value/i],
    ['control-marker', 'name=control-marker\u0000', /control/i],
    ['attribute-marker', 'name=value; bad(attribute-marker=value', /attribute name/i],
    ['same-site-marker', 'name=value; SameSite=same-site-marker', /samesite/i],
    ['max-age-marker', 'name=value; Max-Age=max-age-marker', /max-age/i],
    ['expires-marker', 'name=value; Expires=expires-marker', /expires/i],
    ['duplicate-marker', 'name=value; Path=/; pAtH=duplicate-marker', /duplicate/i],
    ['flag-marker', 'name=value; HttpOnly=flag-marker', /httponly/i],
  ])('rejects unsafe cookie class %# without echoing its marker', (marker, header, category) => {
    const message = getThrownMessage(() => normalizeSetCookies([header]));

    expect(message).toMatch(category);
    expect(message).not.toContain(marker);
  });

  it.each([
    'name="just-a-quote',
    'name=bad\\value',
    'name=value;',
    'name=value;; Extension=ok',
    'name=value; bad attribute=value',
    'name=value; \u00A0Secure',
    'name=value; Secure; secure',
  ])('rejects malformed cookie grammar case %#', (header) => {
    expect(() => normalizeSetCookies([header])).toThrow(/set-cookie/i);
  });

  it.each([
    ['name=value; SameSite=invalid', /samesite/i],
    ['name=value; Max-Age=1.5', /max-age/i],
    ['name=value; Max-Age=huge', /max-age/i],
    ['name=value; Expires=not-a-date', /expires/i],
  ])('rejects invalid known cookie metadata case %#', (header, expectedError) => {
    expect(() => normalizeSetCookies([header])).toThrow(expectedError);
  });
});

describe('normalizeJwt', () => {
  it('decodes observations, reuses business symbols, and allocates stable occurrences', async () => {
    const context = createContext();
    context.symbols.bind('user.primary', 'runtime-user');
    const token = await signJwt({
      sub: 'runtime-user',
      sid: 'runtime-sid',
      jti: 'runtime-jti',
      iat: 100,
      exp: 3700,
      auth_time: 90,
      nbf: 95,
      updated_at: 80,
      scope: 'read write',
      aud: 'https://api.example',
      iss: 'https://issuer.example',
      role: 'admin',
      roles: ['admin', 'auditor'],
      organization: 'primary',
      organizations: ['primary', 'secondary'],
    });

    const normalized = normalizeJwt(token, context, {
      tokenKind: 'id-token',
      timestampToleranceSeconds: 60,
    });

    expect(normalized).toEqual({
      header: { alg: 'HS256', kid: '<id-token.kid.1>', typ: 'JWT' },
      claims: {
        sub: '<user.primary>',
        sid: '<id-token.sid.1>',
        jti: '<id-token.jti.1>',
        iat: { $timestamp: 100, $toleranceSeconds: 60 },
        exp: { $timestamp: 3700, $toleranceSeconds: 60 },
        auth_time: { $timestamp: 90, $toleranceSeconds: 60 },
        nbf: { $timestamp: 95, $toleranceSeconds: 60 },
        updated_at: { $timestamp: 80, $toleranceSeconds: 60 },
        scope: 'read write',
        aud: 'https://api.example',
        iss: 'https://issuer.example',
        role: 'admin',
        roles: ['admin', 'auditor'],
        organization: 'primary',
        organizations: ['primary', 'secondary'],
        tokenLifetimeSeconds: 3600,
      },
    });
    expect(context.symbols.getLogicalName('runtime-sid')).toBe('id-token.sid.1');
    expect(context.symbols.getLogicalName('runtime-jti')).toBe('id-token.jti.1');

    expect(
      normalizeJwt(token, context, {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 60,
      })
    ).toEqual(normalized);
    expect(JSON.stringify(normalized)).not.toContain(token);
    expect(normalized).not.toHaveProperty('signature');
  });

  it('supports explicit nested identifier and time claim paths', async () => {
    const token = await signJwt({ custom: { subject: 'custom-user', issued: 200 } });

    expect(
      normalizeJwt(token, createContext(), {
        tokenKind: 'access-token',
        timestampToleranceSeconds: 10,
        identifierClaimPaths: ['/custom/subject'],
        timeClaimPaths: ['/custom/issued'],
      })
    ).toEqual({
      header: { alg: 'HS256', kid: '<access-token.kid.1>', typ: 'JWT' },
      claims: {
        custom: {
          subject: '<access-token.custom.subject.1>',
          issued: { $timestamp: 200, $toleranceSeconds: 10 },
        },
      },
    });
  });

  it('rejects malformed tokens and invalid identifier or configured time claim types', async () => {
    const malformedToken = 'raw-secret-like-malformed-token';
    const malformedMessage = getThrownMessage(() =>
      normalizeJwt(malformedToken, createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    );
    expect(malformedMessage).toMatch(/jwt/i);
    expect(malformedMessage).not.toContain(malformedToken);

    const invalidIdentifier = await signJwt({ sub: 42 });
    expect(() =>
      normalizeJwt(invalidIdentifier, createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    ).toThrow(/identifier.*\/sub.*string/i);

    const invalidConfiguredIdentifier = await signJwt({ custom: { subject: 42 } });
    expect(() =>
      normalizeJwt(invalidConfiguredIdentifier, createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
        identifierClaimPaths: ['/custom/subject'],
      })
    ).toThrow(/identifier.*\/custom\/subject.*string/i);

    const invalidTime = await signJwt({ customTime: 'now' });
    expect(() =>
      normalizeJwt(invalidTime, createContext(), {
        tokenKind: 'access-token',
        timestampToleranceSeconds: 10,
        timeClaimPaths: ['/customTime'],
      })
    ).toThrow(/time claim.*\/customtime.*finite number/i);
  });

  it.each([-1, Number.POSITIVE_INFINITY, Number.NaN])(
    'rejects invalid JWT timestamp tolerance %p',
    async (timestampToleranceSeconds) => {
      const token = await signJwt({ sub: 'runtime-user' });

      expect(() =>
        normalizeJwt(token, createContext(), {
          tokenKind: 'id-token',
          timestampToleranceSeconds,
        })
      ).toThrow(/timestamp tolerance.*(?:non-negative|finite)/i);
    }
  );

  it.each([
    [{ tokenKind: 'refresh-token', timestampToleranceSeconds: 10 }, /tokenkind/i],
    [
      {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
        identifierClaimPaths: '/custom/subject',
      },
      /identifierclaimpaths.*array of strings/i,
    ],
    [
      {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
        identifierClaimPaths: ['/custom/subject', 42],
      },
      /identifierclaimpaths.*array of strings/i,
    ],
    [
      {
        tokenKind: 'access-token',
        timestampToleranceSeconds: 10,
        timeClaimPaths: { first: '/custom/time' },
      },
      /timeclaimpaths.*array of strings/i,
    ],
  ])('rejects invalid runtime JWT options %# before decoding', (options, expectedError) => {
    expect(() =>
      Reflect.apply(normalizeJwt, undefined, ['not-a-compact-token', createContext(), options])
    ).toThrow(expectedError);
  });

  it('rejects a derived lifetime collision without overwriting the material claim', async () => {
    const token = await signJwt({
      iat: 100,
      exp: 3700,
      tokenLifetimeSeconds: 3600,
    });
    const message = getThrownMessage(() =>
      normalizeJwt(token, createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    );

    expect(message).toMatch(/tokenlifetimeseconds/i);
    expect(message).not.toContain(token);
    expect(message).not.toContain('3600');
  });

  it('preserves an existing lifetime claim when a lifetime cannot be derived', async () => {
    const token = await signJwt({ iat: 100, tokenLifetimeSeconds: 'custom-lifetime' });

    expect(
      normalizeJwt(token, createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      }).claims
    ).toEqual({
      iat: { $timestamp: 100, $toleranceSeconds: 10 },
      tokenLifetimeSeconds: 'custom-lifetime',
    });
  });

  it('rejects non-object protected headers and claims payloads', () => {
    expect(() =>
      normalizeJwt(createCompactJwt([], { sub: 'runtime-user' }), createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    ).toThrow(/jwt|header|object/i);
    expect(() =>
      normalizeJwt(createCompactJwt({ alg: 'none' }, []), createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    ).toThrow(/jwt|claims|object/i);
  });

  it('decodes without verifying and never exposes corrupt signature material', async () => {
    const signedToken = await signJwt({ scope: 'read', aud: 'urn:api' });
    const [protectedHeaderSegment, claimsSegment] = signedToken.split('.');
    const signatureMarker = 'deliberately-corrupt-signature-marker';
    const signatureSegment = base64url.encode(signatureMarker);
    const corruptToken = `${protectedHeaderSegment}.${claimsSegment}.${signatureSegment}`;

    const normalized = normalizeJwt(corruptToken, createContext(), {
      tokenKind: 'access-token',
      timestampToleranceSeconds: 10,
    });
    const serialized = JSON.stringify(normalized);

    expect(normalized).toEqual({
      header: { alg: 'HS256', kid: '<access-token.kid.1>', typ: 'JWT' },
      claims: { scope: 'read', aud: 'urn:api' },
    });
    expect(serialized).not.toContain(signatureSegment);
    expect(serialized).not.toContain(signatureMarker);
  });
});
/* eslint-enable max-lines */
