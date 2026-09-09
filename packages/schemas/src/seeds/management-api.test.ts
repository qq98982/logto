import { describe, expect, it } from 'vitest';

import {
  createAdminData,
  createAdminDataInAdminTenant,
  createMeApiInAdminTenant,
  createPreConfiguredManagementApiAccessRole,
  defaultManagementApi,
  getManagementApiResourceIndicator,
} from './management-api.js';

describe('Management and Account API seed data', () => {
  it('preserves the released helper while returning Aster resource indicators', () => {
    expect(getManagementApiResourceIndicator('default')).toBe('urn:aster:resource:management');
    expect(getManagementApiResourceIndicator('tenant-a')).toBe(
      'urn:aster:resource:management:tenant-a'
    );
    expect(getManagementApiResourceIndicator('admin', 'me')).toBe('urn:aster:resource:account');
    expect(getManagementApiResourceIndicator('default', 'custom:path')).toBe(
      'urn:aster:resource:management:default:custom%3Apath'
    );
  });

  it('uses Aster values for the fixed default Management API seed', () => {
    expect(defaultManagementApi.resource).toMatchObject({
      indicator: 'urn:aster:resource:management',
      name: 'Aster Management API',
    });
    expect(defaultManagementApi.role.description).toBe(
      'Internal admin role for Aster tenant default.'
    );
  });

  it('uses Aster values for tenant Management API seeds', () => {
    expect(createAdminData('tenant-a').resource).toMatchObject({
      indicator: 'urn:aster:resource:management:tenant-a',
      name: 'Aster Management API',
    });
    expect(createAdminDataInAdminTenant('tenant-a').resource).toMatchObject({
      indicator: 'urn:aster:resource:management:tenant-a',
      name: 'Aster Management API for tenant tenant-a',
    });
  });

  it('uses Aster values for the Account API and preconfigured access role', () => {
    expect(createMeApiInAdminTenant().resource).toMatchObject({
      indicator: 'urn:aster:resource:account',
      name: 'Aster Account API',
    });
    expect(createPreConfiguredManagementApiAccessRole('default')).toMatchObject({
      name: 'Aster Management API access',
      description: 'This default role grants access to the Aster Management API.',
    });
  });

  it('does not emit upstream resource domains or seed labels', () => {
    const seedData = [
      defaultManagementApi,
      createAdminData('tenant-a'),
      createAdminDataInAdminTenant('tenant-a'),
      createMeApiInAdminTenant(),
      createPreConfiguredManagementApiAccessRole('default'),
    ];
    const serialized = JSON.stringify(seedData);

    expect(serialized).not.toContain('.logto.app/');
    expect(serialized).not.toContain('Logto Management API');
    expect(serialized).not.toContain('Logto Me API');
  });
});
