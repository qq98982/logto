import { SymbolTable } from '../symbol-table.js';

import {
  createPhase1NormalizationContext,
  phase1ImplementationForProfile,
  projectPhase1ProfileForImplementation,
} from './native-surface-profile.js';
import { asterNativeSurfaceContract } from './native-surface.js';
import type { Phase1Profile } from './profile-types.js';

const profileFixture = (): Phase1Profile => {
  const { markers } = asterNativeSurfaceContract;

  return {
    schemaVersion: 2,
    asterNativeSurface: structuredClone(asterNativeSurfaceContract),
    fixtures: {
      adminTenant: {
        resources: [
          { indicator: markers.managementResource.candidate, scopes: ['all'] },
          { indicator: markers.accountResource.candidate, scopes: ['all'] },
          {
            indicator: markers.organizationResource.candidate,
            scopes: [markers.organizationScope.candidate, markers.organizationRoleScope.candidate],
          },
        ],
      },
      dataTenant: {
        subject: { name: 'Logto may appear in user-controlled text' },
        resource: { indicator: 'https://api.example.com' },
        browserClientConfiguration: {
          localStorageKey: markers.demoConfigStorageKey.candidate,
          localStorageValue: { resource: 'https://api.example.com' },
        },
      },
    },
    consoleAuthentication: {
      configuredResources: [
        markers.managementResource.candidate,
        markers.accountResource.candidate,
      ],
      effectiveResources: [
        markers.managementResource.candidate,
        markers.accountResource.candidate,
        markers.organizationResource.candidate,
      ],
      configuredScopes: [
        'profile',
        markers.organizationScope.candidate,
        markers.organizationRoleScope.candidate,
      ],
      effectiveScopes: [
        'openid',
        'offline_access',
        'profile',
        markers.organizationScope.candidate,
        markers.organizationRoleScope.candidate,
      ],
    },
    consoleOrganizationTokenRequest: {
      form: { resource: null },
      requiredAccessTokenProjection: {
        aud: `${markers.organizationAudiencePrefix.candidate}t-default`,
      },
    },
    oidc: {
      scopesSupported: [
        'openid',
        markers.organizationScope.candidate,
        markers.organizationRoleScope.candidate,
        markers.sessionScope.candidate,
      ],
    },
    consoleReadRequests: [
      { authorization: null },
      { authorization: { resource: markers.managementResource.candidate } },
    ],
    consoleAccountRequests: [{ authorization: { resource: markers.accountResource.candidate } }],
  } as unknown as Phase1Profile;
};

describe('Aster target-specific profile projection', () => {
  it('returns the validated candidate profile without rewriting it', () => {
    const profile = profileFixture();
    const normalization = createPhase1NormalizationContext(
      profile,
      {
        label: 'candidate',
        coreUrl: 'https://candidate.example',
        adminUrl: 'https://admin.example',
      },
      new SymbolTable()
    );

    expect(phase1ImplementationForProfile(profile)).toBe('candidate');
    expect(normalization.nativeSurfaceImplementation).toBe('candidate');
    expect(projectPhase1ProfileForImplementation(profile, 'candidate')).toBe(profile);
  });

  it('projects only approved product-owned fields for the oracle adapter', () => {
    const oracle = projectPhase1ProfileForImplementation(profileFixture(), 'oracle');
    const normalization = createPhase1NormalizationContext(
      oracle,
      { label: 'oracle', coreUrl: 'https://oracle.example', adminUrl: 'https://admin.example' },
      new SymbolTable()
    );

    expect(phase1ImplementationForProfile(oracle)).toBe('oracle');
    expect(normalization.nativeSurfaceImplementation).toBe('oracle');
    expect(oracle.fixtures.adminTenant.resources).toEqual([
      { indicator: 'https://default.logto.app/api', scopes: ['all'] },
      { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
      {
        indicator: 'urn:logto:resource:organizations',
        scopes: ['urn:logto:scope:organizations', 'urn:logto:scope:organization_roles'],
      },
    ]);
    expect(oracle.fixtures.dataTenant.browserClientConfiguration.localStorageKey).toBe(
      'logto:demo-app:dev:config'
    );
    expect(oracle.consoleAuthentication.effectiveResources).toEqual([
      'https://default.logto.app/api',
      'https://admin.logto.app/me',
      'urn:logto:resource:organizations',
    ]);
    expect(oracle.consoleAuthentication.effectiveScopes).toEqual([
      'openid',
      'offline_access',
      'profile',
      'urn:logto:scope:organizations',
      'urn:logto:scope:organization_roles',
    ]);
    expect(oracle.oidc.scopesSupported).toEqual([
      'openid',
      'urn:logto:scope:organizations',
      'urn:logto:scope:organization_roles',
      'urn:logto:scope:sessions',
    ]);
    expect(oracle.consoleOrganizationTokenRequest.requiredAccessTokenProjection.aud).toBe(
      'urn:logto:organization:t-default'
    );
    expect(oracle.consoleReadRequests[1]?.authorization?.resource).toBe(
      'https://default.logto.app/api'
    );
    expect(oracle.consoleAccountRequests[0]?.authorization.resource).toBe(
      'https://admin.logto.app/me'
    );
    expect(oracle.fixtures.dataTenant.resource.indicator).toBe('https://api.example.com');
    expect(oracle.fixtures.dataTenant.subject.name).toBe(
      'Logto may appear in user-controlled text'
    );
    expect(Object.isFrozen(oracle)).toBe(true);
    expect(Object.isFrozen(oracle.fixtures.adminTenant.resources[0])).toBe(true);
  });

  it('rejects profiles without one unambiguous native-surface implementation', () => {
    const candidate = profileFixture();
    const mixed: Phase1Profile = {
      ...candidate,
      fixtures: {
        ...candidate.fixtures,
        dataTenant: {
          ...candidate.fixtures.dataTenant,
          browserClientConfiguration: {
            ...candidate.fixtures.dataTenant.browserClientConfiguration,
            localStorageKey: 'logto:demo-app:dev:config',
          },
        },
      },
    };

    expect(() => phase1ImplementationForProfile(mixed)).toThrow(
      'Invalid Phase 1 native surface profile'
    );
    expect(() => phase1ImplementationForProfile({ fixtures: {} } as Phase1Profile)).toThrow(
      'Invalid Phase 1 native surface profile'
    );
  });
});
