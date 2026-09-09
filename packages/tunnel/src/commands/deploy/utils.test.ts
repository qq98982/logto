import { describe, expect, it } from 'vitest';

import { getManagementApiResourceFromEndpointUri } from './utils.js';

describe('deploy resource resolution', () => {
  it.each([
    ['https://tenant-a.logto.app', 'urn:aster:resource:management:tenant-a'],
    ['http://localhost:3001', 'urn:aster:resource:management'],
  ])('uses the shared Aster Management resource for %s', (endpoint, expected) => {
    expect(getManagementApiResourceFromEndpointUri(new URL(endpoint))).toBe(expected);
  });
});
