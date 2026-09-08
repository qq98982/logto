/* eslint-disable @silverhand/fp/no-mutation -- Each table case mutates one isolated profile field. */
import { asterNativeSurfaceContract } from '../native-surface.js';
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

import { assertNativeSurfaceSemantics } from './native-surface.js';

type MutableMarker = { match: string; reference: string; candidate: string };
type MutableSurface = {
  legacyAliases: boolean;
  projectionPolicy: {
    direction: string;
    unlistedDifferences: string;
    securityOutcomes: string;
  };
  markers: Record<string, MutableMarker>;
};

const mutableSurface = (): MutableSurface =>
  JSON.parse(JSON.stringify(asterNativeSurfaceContract)) as MutableSurface;

const profileFixture = () => {
  const surface = mutableSurface();
  const { markers } = surface;

  return {
    schemaVersion: 2,
    asterNativeSurface: surface,
    fixtures: {
      adminTenant: {
        resources: [
          { indicator: markers.managementResource?.candidate, scopes: ['all'] },
          { indicator: markers.accountResource?.candidate, scopes: ['all'] },
          {
            indicator: markers.organizationResource?.candidate,
            scopes: [
              markers.organizationScope?.candidate,
              markers.organizationRoleScope?.candidate,
            ],
          },
        ],
        tenantOrganization: { id: 't-default' },
      },
      dataTenant: {
        resource: { indicator: 'https://api.example.com' },
        browserClientConfiguration: {
          localStorageKey: markers.demoConfigStorageKey?.candidate,
          localStorageValue: { resource: 'https://api.example.com' },
        },
      },
    },
    consoleAuthentication: {
      configuredResources: [
        markers.managementResource?.candidate,
        markers.accountResource?.candidate,
      ],
      effectiveResources: [
        markers.managementResource?.candidate,
        markers.accountResource?.candidate,
        markers.organizationResource?.candidate,
      ],
      configuredScopes: [
        'profile',
        markers.organizationScope?.candidate,
        markers.organizationRoleScope?.candidate,
        'all',
      ],
      effectiveScopes: [
        'openid',
        'offline_access',
        'profile',
        markers.organizationScope?.candidate,
        markers.organizationRoleScope?.candidate,
        'all',
      ],
    },
    consoleOrganizationTokenRequest: {
      requiredAccessTokenProjection: {
        aud: `${markers.organizationAudiencePrefix?.candidate}t-default`,
      },
    },
    oidc: {
      scopesSupported: [
        'openid',
        markers.organizationScope?.candidate,
        markers.organizationRoleScope?.candidate,
      ],
    },
    consoleReadRequests: Array.from({ length: 4 }, () => ({
      authorization: { resource: markers.managementResource?.candidate },
    })),
    interactionOperations: [
      {
        requiredProjection: {
          missingResourceScopes: [{ resource: { indicator: 'https://api.example.com' } }],
        },
      },
      { requiredPersistedOutcome: { resource: 'https://api.example.com' } },
    ],
  };
};

const expectFailure = (
  mutate: (profile: ReturnType<typeof profileFixture>) => void,
  pointer: string
) => {
  const profile = profileFixture();
  mutate(profile);

  expect(() => {
    assertNativeSurfaceSemantics(profile as unknown as Phase1Profile);
  }).toThrow(Phase1ProfileValidationError);
  try {
    assertNativeSurfaceSemantics(profile as unknown as Phase1Profile);
  } catch (error: unknown) {
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 semantics',
      stage: 'semantic',
      pointers: [pointer],
      rules: ['native-surface'],
    });
  }
};

describe('Phase 1 native-surface semantics', () => {
  it('accepts the exact Aster candidate fixture namespace', () => {
    expect(() => {
      assertNativeSurfaceSemantics(profileFixture() as unknown as Phase1Profile);
    }).not.toThrow();
  });

  it.each([
    [
      '/asterNativeSurface/markers/requestIdHeader/candidate',
      (profile: ReturnType<typeof profileFixture>) => {
        profile.asterNativeSurface.markers.requestIdHeader!.candidate = 'changed-request-id';
      },
    ],
    [
      '/fixtures/adminTenant/resources/0/indicator',
      (profile: ReturnType<typeof profileFixture>) => {
        profile.fixtures.adminTenant.resources[0]!.indicator = 'https://default.logto.app/api';
      },
    ],
    [
      '/fixtures/dataTenant/browserClientConfiguration/localStorageKey',
      (profile: ReturnType<typeof profileFixture>) => {
        profile.fixtures.dataTenant.browserClientConfiguration.localStorageKey =
          'logto:demo-app:dev:config';
      },
    ],
    [
      '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/aud',
      (profile: ReturnType<typeof profileFixture>) => {
        profile.consoleOrganizationTokenRequest.requiredAccessTokenProjection.aud =
          'urn:logto:organization:t-default';
      },
    ],
    [
      '/consoleReadRequests/0/authorization/resource',
      (profile: ReturnType<typeof profileFixture>) => {
        profile.consoleReadRequests[0]!.authorization.resource = 'https://default.logto.app/api';
      },
    ],
    [
      '/fixtures/dataTenant/resource/indicator',
      (profile: ReturnType<typeof profileFixture>) => {
        profile.fixtures.dataTenant.resource.indicator = 'urn:aster:resource:management';
      },
    ],
  ])('rejects a namespace mismatch at %s', (pointer, mutate) => {
    expectFailure(mutate, pointer);
  });
});

/* eslint-enable @silverhand/fp/no-mutation */
