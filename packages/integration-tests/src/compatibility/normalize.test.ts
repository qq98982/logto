import { SignJWT } from 'jose';

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
        'interaction="secret-like;value"; Path=/; HttpOnly; SameSite=lax',
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
    ['name=value; SameSite=invalid', /samesite/i],
    ['name=value; Max-Age=1.5', /max-age/i],
    ['name=value; Max-Age=huge', /max-age/i],
    ['name=value; Expires=not-a-date', /expires/i],
  ])('rejects invalid known cookie metadata in %s', (header, expectedError) => {
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
      scope: 'read write',
      aud: 'https://api.example',
      role: ['admin'],
      organization: 'primary',
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
        scope: 'read write',
        aud: 'https://api.example',
        role: ['admin'],
        organization: 'primary',
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
    expect(() =>
      normalizeJwt('not-a-compact-token', createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    ).toThrow(/jwt/i);

    const invalidIdentifier = await signJwt({ sub: 42 });
    expect(() =>
      normalizeJwt(invalidIdentifier, createContext(), {
        tokenKind: 'id-token',
        timestampToleranceSeconds: 10,
      })
    ).toThrow(/identifier.*\/sub.*string/i);

    const invalidTime = await signJwt({ customTime: 'now' });
    expect(() =>
      normalizeJwt(invalidTime, createContext(), {
        tokenKind: 'access-token',
        timestampToleranceSeconds: 10,
        timeClaimPaths: ['/customTime'],
      })
    ).toThrow(/time claim.*\/customtime.*finite number/i);
  });
});
