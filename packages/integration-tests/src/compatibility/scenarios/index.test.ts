import { assertSafeScenarioEvidenceId } from '../evidence.js';

import { defaultCompatibilityScenarios } from './index.js';

describe('default compatibility scenario registry', () => {
  it('is the sole frozen registry with exact safe unique IDs', () => {
    const ids = defaultCompatibilityScenarios.map(({ id }) => id);

    expect(ids).toEqual(['discovery', 'password-code']);
    expect(Object.isFrozen(defaultCompatibilityScenarios)).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
    expect(() => {
      for (const id of ids) {
        assertSafeScenarioEvidenceId(id);
      }
    }).not.toThrow();
  });
});
