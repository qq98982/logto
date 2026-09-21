import { describe, expect, it } from 'vitest';

import {
  ReservedResource,
  UserScope,
  buildOrganizationUrn,
  getOrganizationIdFromUrn,
  organizationUrnPrefix,
} from './openid.js';

describe('Aster user scopes', () => {
  it('uses the Aster session scope without a legacy alias', () => {
    expect(UserScope.Sessions).toBe('urn:aster:scope:sessions');
    expect(Object.values(UserScope)).not.toContain('urn:logto:scope:sessions');
  });

  it('uses Aster organization resources, scopes, and audiences without legacy aliases', () => {
    expect(ReservedResource.Organization).toBe('urn:aster:resource:organizations');
    expect(UserScope.Organizations).toBe('urn:aster:scope:organizations');
    expect(UserScope.OrganizationRoles).toBe('urn:aster:scope:organization_roles');
    expect(organizationUrnPrefix).toBe('urn:aster:organization:');
    expect(buildOrganizationUrn('organization-id')).toBe('urn:aster:organization:organization-id');
    expect(getOrganizationIdFromUrn('urn:aster:organization:organization-id')).toBe(
      'organization-id'
    );
    expect(() => getOrganizationIdFromUrn('urn:logto:organization:organization-id')).toThrow(
      'Invalid organization URN.'
    );
    expect(Object.values(ReservedResource)).not.toContain('urn:logto:resource:organizations');
    expect(Object.values(UserScope)).not.toContain('urn:logto:scope:organizations');
    expect(Object.values(UserScope)).not.toContain('urn:logto:scope:organization_roles');
  });
});
