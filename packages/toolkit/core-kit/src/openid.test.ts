import { describe, expect, it } from 'vitest';

import { UserScope } from './openid.js';

describe('Aster user scopes', () => {
  it('uses the Aster session scope without a legacy alias', () => {
    expect(UserScope.Sessions).toBe('urn:aster:scope:sessions');
    expect(Object.values(UserScope)).not.toContain('urn:logto:scope:sessions');
  });
});
