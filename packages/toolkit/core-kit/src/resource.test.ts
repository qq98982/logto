import { describe, expect, it } from 'vitest';

import {
  accountApiResourceIndicator,
  buildManagementApiResourceIndicator,
  isAsterReservedResourceIndicator,
  isManagementApiResourceIndicator,
  managementApiResourceIndicator,
} from './resource.js';

const builderCases = [
  {
    name: 'default Management API',
    tenantId: 'default',
    path: 'api',
    expected: 'urn:aster:resource:management',
    management: true,
  },
  {
    name: 'tenant Management API',
    tenantId: 'tenant-a',
    path: 'api',
    expected: 'urn:aster:resource:management:tenant-a',
    management: true,
  },
  {
    name: 'tenant ID with a colon',
    tenantId: 'tenant:a',
    path: 'api',
    expected: 'urn:aster:resource:management:tenant%3Aa',
    management: true,
  },
  {
    name: 'JavaScript encodeURIComponent punctuation',
    tenantId: "a!~*'()",
    path: 'api',
    expected: "urn:aster:resource:management:a!~*'()",
    management: true,
  },
  {
    name: 'percent, space, slash, and Unicode tenant ID',
    tenantId: '% space/é',
    path: 'api',
    expected: 'urn:aster:resource:management:%25%20space%2F%C3%A9',
    management: true,
  },
  {
    name: 'reserved delimiters in a tenant ID',
    tenantId: ';/?&=+#$,@',
    path: 'api',
    expected: 'urn:aster:resource:management:%3B%2F%3F%26%3D%2B%23%24%2C%40',
    management: true,
  },
  {
    name: 'Account API',
    tenantId: 'admin',
    path: 'me',
    expected: 'urn:aster:resource:account',
    management: false,
  },
  {
    name: 'generic path',
    tenantId: 'default',
    path: 'custom:path',
    expected: 'urn:aster:resource:management:default:custom%3Apath',
    management: false,
  },
  {
    name: 'Unicode tenant and generic path',
    tenantId: '路径',
    path: '% /é!',
    expected: 'urn:aster:resource:management:%E8%B7%AF%E5%BE%84:%25%20%2F%C3%A9!',
    management: false,
  },
] as const;

describe('Aster resource indicators', () => {
  it('uses fixed Aster Management and Account resource constants', () => {
    expect(managementApiResourceIndicator).toBe('urn:aster:resource:management');
    expect(accountApiResourceIndicator).toBe('urn:aster:resource:account');
  });

  it.each(builderCases)(
    'builds and classifies the $name resource',
    ({ tenantId, path, expected, management }) => {
      const indicator = buildManagementApiResourceIndicator(tenantId, path);

      expect(indicator).toBe(expected);
      expect(isManagementApiResourceIndicator(indicator)).toBe(management);
      expect(isAsterReservedResourceIndicator(indicator)).toBe(true);
    }
  );

  it('uses the API path when the path is omitted', () => {
    expect(buildManagementApiResourceIndicator('default')).toBe(managementApiResourceIndicator);
    expect(buildManagementApiResourceIndicator('tenant-a')).toBe(
      'urn:aster:resource:management:tenant-a'
    );
  });

  it('rejects empty tenant IDs and paths', () => {
    expect(() => buildManagementApiResourceIndicator('')).toThrow(TypeError);
    expect(() => buildManagementApiResourceIndicator('default', '')).toThrow(TypeError);
  });

  it.each([
    ['urn:aster:resource:management:', false, true],
    ['urn:aster:resource:management:tenant:path', false, true],
    ['urn:aster:resource:management:tenant%ZZ', false, true],
    ['urn:aster:resource:management:tenant%', false, true],
    ['urn:aster:resource:management:%FF', false, true],
    ['urn:aster:resource:management:tenant%3a', false, true],
    ['urn:aster:resource:management:tenant+name', false, true],
    ['urn:aster:resource:account', false, true],
    ['urn:aster:resource:organizations', false, true],
    ['urn:aster:resource:account:extra', false, false],
    ['https://api.example.com/urn:aster:resource:management:tenant', false, false],
  ] as const)(
    'classifies %s without authorizing malformed or unrelated values',
    (indicator, management, reserved) => {
      expect(isManagementApiResourceIndicator(indicator)).toBe(management);
      expect(isAsterReservedResourceIndicator(indicator)).toBe(reserved);
    }
  );
});
