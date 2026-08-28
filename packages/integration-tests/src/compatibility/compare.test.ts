import { compareJson } from './compare.js';

const timestampMarker = (timestamp: number, tolerance: number) => ({
  $timestamp: timestamp,
  $toleranceSeconds: tolerance,
});

describe('compareJson', () => {
  it('returns no differences for equal nested JSON values', () => {
    expect(
      compareJson(
        { status: 200, body: { id: '<user.primary>', enabled: true }, values: [null, 1] },
        { status: 200, body: { id: '<user.primary>', enabled: true }, values: [null, 1] }
      )
    ).toEqual([]);
  });

  it('reports every material difference at its precise JSON Pointer path', () => {
    const oracle = {
      response: { status: 200, headers: { location: '/consent' } },
      claims: { sub: '<user.primary>', scope: 'read' },
    };
    const candidate = {
      response: { status: 401, headers: { location: '/error' } },
      claims: { sub: '<user.primary>', scope: 'write' },
    };

    expect(compareJson(oracle, candidate)).toEqual([
      { path: '/claims/scope', oracle: 'read', candidate: 'write' },
      {
        path: '/response/headers/location',
        oracle: '/consent',
        candidate: '/error',
      },
      { path: '/response/status', oracle: 200, candidate: 401 },
    ]);
  });

  it('reports root primitive and root type differences at the empty path', () => {
    expect(compareJson('oracle', 'candidate')).toEqual([
      { path: '', oracle: 'oracle', candidate: 'candidate' },
    ]);
    expect(compareJson({ value: 1 }, [1])).toEqual([
      { path: '', oracle: { value: 1 }, candidate: [1] },
    ]);
  });

  it('uses deterministic binary key order independent of insertion order', () => {
    const oracle = { z: 0, a: 0, B: 0, ä: 0 };
    const candidate = { ä: 1, B: 1, a: 1, z: 1 };

    expect(compareJson(oracle, candidate).map(({ path }) => path)).toEqual([
      '/B',
      '/a',
      '/z',
      '/ä',
    ]);
  });

  it('escapes pointer segments and safely handles prototype-sensitive own keys', () => {
    const oracle = Object.fromEntries<unknown>([
      ['__proto__', 'oracle-prototype'],
      ['a/b', { '~key': 1 }],
      ['constructor', 'oracle-constructor'],
    ]);
    const candidate = Object.fromEntries<unknown>([
      ['__proto__', 'candidate-prototype'],
      ['a/b', { '~key': 2 }],
      ['constructor', 'candidate-constructor'],
    ]);

    expect(compareJson(oracle, candidate)).toEqual([
      {
        path: '/__proto__',
        oracle: 'oracle-prototype',
        candidate: 'candidate-prototype',
      },
      { path: '/a~1b/~0key', oracle: 1, candidate: 2 },
      {
        path: '/constructor',
        oracle: 'oracle-constructor',
        candidate: 'candidate-constructor',
      },
    ]);
  });

  it('preserves array order and reports missing elements by original index', () => {
    expect(compareJson(['first', 'second', null], ['second', 'first', null, 'extra'])).toEqual([
      { path: '/0', oracle: 'first', candidate: 'second' },
      { path: '/1', oracle: 'second', candidate: 'first' },
      { path: '/3', candidate: 'extra' },
    ]);

    expect(compareJson([0, 1, 2], [0])).toEqual([
      { path: '/1', oracle: 1 },
      { path: '/2', oracle: 2 },
    ]);
  });

  it('distinguishes missing object properties from explicit null', () => {
    expect(compareJson({ missingInCandidate: null }, { missingInOracle: null })).toEqual([
      { path: '/missingInCandidate', oracle: null },
      { path: '/missingInOracle', candidate: null },
    ]);
  });

  it('caps every displayed string while leaving paths unchanged', () => {
    const longKey = `key/${'k'.repeat(600)}`;
    const differences = compareJson(
      { [longKey]: { nested: 'o'.repeat(800) } },
      { [longKey]: ['c'.repeat(800)] }
    );

    expect(differences).toHaveLength(1);
    expect(differences[0]?.path).toBe(`/${longKey.replace('/', '~1')}`);
    expect(typeof (differences[0]?.oracle as { nested: unknown }).nested).toBe('string');
    expect(typeof (differences[0]?.candidate as unknown[])[0]).toBe('string');
    expect((differences[0]?.oracle as { nested: string }).nested.length).toBe(500);
    expect(((differences[0]?.candidate as string[])[0] ?? '').length).toBe(500);
    expect((differences[0]?.oracle as { nested: string }).nested).toBe(
      `${'o'.repeat(486)}...[truncated]`
    );
    expect((differences[0]?.candidate as string[])[0]).toBe(`${'c'.repeat(486)}...[truncated]`);
  });

  it('does not mutate either input when creating display values', () => {
    const oracle = { value: 'o'.repeat(700), nested: [{ keep: true }] };
    const candidate = { value: 'c'.repeat(700), nested: 'different-type' };
    const beforeOracle = structuredClone(oracle);
    const beforeCandidate = structuredClone(candidate);

    compareJson(oracle, candidate);

    expect(oracle).toEqual(beforeOracle);
    expect(candidate).toEqual(beforeCandidate);
  });

  it.each([
    [Number.POSITIVE_INFINITY, 1],
    [{ nested: Number.NaN }, {}],
    [new Date(), {}],
    [{}, /not-json/],
    [undefined, null],
  ])('rejects non-JSON input %#', (oracle, candidate) => {
    expect(() => compareJson(oracle, candidate)).toThrow('Comparison input must be faithful JSON');
  });

  it('compares timestamp markers at exact, boundary, and over-tolerance deltas', () => {
    expect(compareJson(timestampMarker(100, 5), timestampMarker(100, 5))).toEqual([]);
    expect(compareJson(timestampMarker(100, 5), timestampMarker(104, 5))).toEqual([]);
    expect(compareJson(timestampMarker(100, 5), timestampMarker(105, 5))).toEqual([]);
    expect(compareJson(timestampMarker(100, 5), timestampMarker(106, 5))).toEqual([
      {
        path: '',
        oracle: timestampMarker(100, 5),
        candidate: timestampMarker(106, 5),
      },
    ]);
  });

  it('uses the smaller tolerance declared by the two timestamp markers', () => {
    const oracle = { $timestamp: 100, $toleranceSeconds: 10 };
    const candidate = { $timestamp: 106, $toleranceSeconds: 5 };

    expect(compareJson(oracle, candidate)).toEqual([{ path: '', oracle, candidate }]);
    expect(
      compareJson(
        { $timestamp: 100, $toleranceSeconds: 10 },
        { $timestamp: 105, $toleranceSeconds: 5 }
      )
    ).toEqual([]);
  });

  it('applies exact timestamp-marker tolerance at a nested marker path', () => {
    expect(
      compareJson(
        { observation: { createdAt: timestampMarker(100, 5) } },
        { observation: { createdAt: timestampMarker(104, 5) } }
      )
    ).toEqual([]);
    expect(
      compareJson(
        { observation: { createdAt: timestampMarker(100, 5) } },
        { observation: { createdAt: timestampMarker(106, 5) } }
      )
    ).toEqual([
      {
        path: '/observation/createdAt',
        oracle: timestampMarker(100, 5),
        candidate: timestampMarker(106, 5),
      },
    ]);
  });

  it('uses ordinary object comparison for one-sided and malformed timestamp markers', () => {
    expect(
      compareJson(
        { $timestamp: 100, $toleranceSeconds: 5 },
        { $timestamp: 104, $toleranceSeconds: -1 }
      )
    ).toEqual([
      { path: '/$timestamp', oracle: 100, candidate: 104 },
      { path: '/$toleranceSeconds', oracle: 5, candidate: -1 },
    ]);

    expect(
      compareJson(
        { $timestamp: 100, $toleranceSeconds: 5 },
        { $timestamp: 100, $toleranceSeconds: 5, extra: true }
      )
    ).toEqual([{ path: '/extra', candidate: true }]);

    expect(
      compareJson(
        { $timestamp: 100, $toleranceSeconds: 5 },
        { $timestamp: '100', $toleranceSeconds: 5 }
      )
    ).toEqual([{ path: '/$timestamp', oracle: 100, candidate: '100' }]);
  });

  it('does not apply timestamp semantics to duration or other ordinary objects', () => {
    expect(compareJson({ $durationSeconds: 5 }, { $durationSeconds: 6 })).toEqual([
      { path: '/$durationSeconds', oracle: 5, candidate: 6 },
    ]);
  });
});
