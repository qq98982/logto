import { describe, expect, it } from 'vitest';

import { isManagementApi } from './management-api.js';

describe('isManagementApi', () => {
  it.each([
    ['urn:aster:resource:management', true],
    ['urn:aster:resource:management:tenant-a', true],
    ['urn:aster:resource:management:tenant%3Aa', true],
    ['urn:aster:resource:management:tenant%3a', false],
    ['urn:aster:resource:management:tenant:path', false],
    ['urn:aster:resource:management:tenant%ZZ', false],
    ['urn:aster:resource:account', false],
    ['https://default.logto.app/api', false],
  ] as const)('classifies %s as %s', (indicator, expected) => {
    expect(isManagementApi(indicator)).toBe(expected);
  });
});
