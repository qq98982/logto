import { compareJson } from '../compare.js';

import { isBoundedTimestampEnvelope } from './bounded-timestamp.js';

const marker = (timestamp: number, tolerance: number) => ({
  $timestamp: timestamp,
  $toleranceSeconds: tolerance,
});

describe('Phase 1 bounded timestamp contract', () => {
  it('matches the immutable comparator at exact, boundary, and over-tolerance deltas', () => {
    const oracle = marker(100, 5);

    expect(isBoundedTimestampEnvelope(oracle)).toBe(true);
    expect(isBoundedTimestampEnvelope(marker(105, 5))).toBe(true);
    expect(compareJson(oracle, marker(105, 5))).toEqual([]);
    expect(compareJson(oracle, marker(106, 5))).toHaveLength(1);
  });

  it.each([
    null,
    [],
    { $timestamp: 100 },
    { $timestamp: 100, $toleranceSeconds: -1 },
    { $timestamp: 100, $toleranceSeconds: 5, extra: true },
    { $timestamp: '100', $toleranceSeconds: 5 },
  ])('rejects the same malformed envelope shape %#', (value) => {
    expect(isBoundedTimestampEnvelope(value)).toBe(false);
    expect(compareJson(value, marker(100, 5))).not.toEqual([]);
  });
});
