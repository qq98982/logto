/* eslint-disable max-lines, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression -- The fixture matrix applies one reference mutation per named contract. */
import { asterNativeSurfaceContract } from '../native-surface.js';
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

import { assertFixtureSemantics } from './fixtures.js';

const required = <Value>(value: Value | undefined): Value => {
  if (value === undefined) {
    throw new Error('Synthetic fixture profile is incomplete');
  }

  return value;
};

const expectSemanticFailure = (profile: Phase1Profile, pointer: string) => {
  try {
    assertFixtureSemantics(profile);
    throw new Error('Expected semantic validation to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 semantics',
      stage: 'semantic',
      pointers: [pointer],
      rules: ['fixture-reference'],
    });
  }
};

const fixtureProfile = () =>
  ({
    asterNativeSurface: structuredClone(asterNativeSurfaceContract),
    uiSource: {
      consoleTree: 'console-tree',
      experienceTree: 'experience-tree',
      demoAppTree: 'demo-tree',
    },
    uiAssetContracts: [
      { application: 'experience-user', tenant: 'data', sourceTreeField: 'experienceTree' },
      { application: 'experience-admin', tenant: 'admin', sourceTreeField: 'experienceTree' },
      { application: 'demo-app', sourceTreeField: 'demoAppTree' },
      { application: 'console', sourceTreeField: 'consoleTree' },
    ],
    routing: { userEndpoint: 'https://data.example', adminEndpoint: 'https://admin.example' },
    fixtures: {
      adminTenant: {
        id: 'admin',
        operator: {
          id: 'operator',
          username: 'operator-name',
          primaryEmail: 'operator@example.test',
        },
        application: {
          id: 'console-client',
          oidcClientMetadata: { redirectUris: ['https://admin.example/console/callback'] },
        },
        resources: [
          { indicator: 'https://data.example/api', scopes: ['all'] },
          { indicator: 'https://admin.example/me', scopes: ['all'] },
          {
            indicator: 'urn:logto:resource:organizations',
            scopes: ['urn:logto:scope:organizations'],
          },
        ],
        tenantOrganization: {
          id: 'organization',
          memberUserIds: ['operator'],
          scopes: ['manage'],
          organizationRoles: [
            { id: 'organization-role', scopeNames: ['manage'], userIds: ['operator'] },
          ],
        },
      },
      dataTenant: {
        id: 'data',
        subject: {
          id: 'subject',
          username: 'subject-name',
          name: 'Subject',
          primaryEmail: 'subject@example.test',
          primaryPhone: '+15555550100',
          applicationId: null,
        },
        applications: [
          {
            id: 'first-party',
            name: 'First Party',
            type: 'SPA',
            isThirdParty: false,
            oidcClientMetadata: { redirectUris: ['https://data.example/callback'] },
            customClientMetadata: {},
          },
          {
            id: 'browser-client',
            name: 'Browser Client',
            type: 'SPA',
            isThirdParty: true,
            oidcClientMetadata: { redirectUris: ['https://data.example/callback'] },
            customClientMetadata: {},
            userConsentScopes: ['profile', 'email'],
            resourceConsentScopes: ['scope-id'],
          },
        ],
        resource: {
          id: 'resource-id',
          name: 'Resource',
          indicator: 'https://resource.example',
          scopes: [{ id: 'scope-id', name: 'read:data', description: 'Read data' }],
        },
        resourceScopeRole: {
          scopeIds: ['scope-id'],
          userIds: ['subject'],
        },
        browserClientConfiguration: {
          localStorageValue: {
            appId: 'browser-client',
            scope: 'profile email read:data',
            resource: 'https://resource.example',
          },
        },
      },
    },
    consoleAuthentication: {
      endpoint: 'https://admin.example',
      issuer: 'https://admin.example/oidc',
      managementDataTenant: 'data',
      applicationId: 'console-client',
      redirectUri: 'https://admin.example/console/callback',
      configuredResources: ['https://data.example/api', 'https://admin.example/me'],
    },
    consoleOrganizationTokenRequest: {
      form: {
        client_id: 'console-client',
        organization_id: 'organization',
        resource: null,
        scope: null,
      },
      requiredAccessTokenProjection: {
        iss: 'https://admin.example/oidc',
        sub: 'operator',
        aud: 'urn:aster:organization:organization',
        client_id: 'console-client',
      },
    },
    consoleReadRequests: [
      {
        path: '/api/applications',
        requiredProjection: [
          {
            id: 'first-party',
            name: 'First Party',
            type: 'SPA',
            isThirdParty: false,
            customClientMetadata: {},
          },
        ],
      },
      {
        path: '/api/users',
        requiredProjection: [
          {
            id: 'subject',
            username: 'subject-name',
            name: 'Subject',
            primaryEmail: 'subject@example.test',
            primaryPhone: '+15555550100',
            avatar: null,
            applicationId: null,
            lastSignInAt: null,
            isSuspended: false,
            hasPassword: true,
          },
        ],
      },
    ],
    consoleAccountRequests: [
      {
        requiredProjection: {
          id: 'operator',
          username: 'operator-name',
          primaryEmail: 'operator@example.test',
        },
      },
    ],
    interactionOperations: [
      {
        method: 'GET',
        requiredProjection: {
          application: { id: 'browser-client', name: 'Browser Client' },
          user: {
            id: 'subject',
            username: 'subject-name',
            name: 'Subject',
            primaryEmail: 'subject@example.test',
            primaryPhone: '+15555550100',
          },
          organizations: [],
          missingOIDCScope: ['profile', 'email'],
          missingResourceScopes: [
            {
              resource: {
                id: 'resource-id',
                name: 'Resource',
                indicator: 'https://resource.example',
              },
              scopes: [{ id: 'scope-id', name: 'read:data', description: 'Read data' }],
            },
          ],
          redirectUri: 'https://data.example/callback',
        },
      },
      {
        method: 'POST',
        requiredPersistedOutcome: {
          applicationId: 'browser-client',
          userId: 'subject',
          oidcScopes: ['profile', 'email'],
          resource: 'https://resource.example',
          resourceScopes: ['read:data'],
          userFirstConsentedApplicationId: 'browser-client',
          sessionExtension: {
            accountId: 'subject',
            clientId: 'browser-client',
            lastSubmission:
              'exact normalized login submission from the same authorization transaction',
          },
        },
      },
    ],
  }) as unknown as Phase1Profile;

type FixtureMutation = Readonly<{
  name: string;
  pointer: string;
  mutate: (profile: Phase1Profile) => void;
}>;

const fixtureMutations: readonly FixtureMutation[] = [
  {
    name: 'organization member user',
    pointer: '/fixtures/adminTenant/tenantOrganization/memberUserIds/0',
    mutate: (profile) => {
      (profile.fixtures.adminTenant.tenantOrganization.memberUserIds as string[])[0] = 'missing';
    },
  },
  {
    name: 'organization role scope',
    pointer: '/fixtures/adminTenant/tenantOrganization/organizationRoles/0/scopeNames/0',
    mutate: (profile) => {
      (
        required(profile.fixtures.adminTenant.tenantOrganization.organizationRoles.at(0))
          .scopeNames as string[]
      )[0] = 'missing';
    },
  },
  {
    name: 'resource role scope id',
    pointer: '/fixtures/dataTenant/resourceScopeRole/scopeIds/0',
    mutate: (profile) => {
      (profile.fixtures.dataTenant.resourceScopeRole.scopeIds as string[])[0] = 'missing';
    },
  },
  {
    name: 'resource role user id',
    pointer: '/fixtures/dataTenant/resourceScopeRole/userIds/0',
    mutate: (profile) => {
      (profile.fixtures.dataTenant.resourceScopeRole.userIds as string[])[0] = 'missing';
    },
  },
  {
    name: 'third-party consent scope id',
    pointer: '/fixtures/dataTenant/applications/1/resourceConsentScopes/0',
    mutate: (profile) => {
      const application = required(profile.fixtures.dataTenant.applications.at(1));

      if (application.isThirdParty) {
        (application.resourceConsentScopes as string[])[0] = 'missing';
      }
    },
  },
  {
    name: 'browser local-storage application',
    pointer: '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/appId',
    mutate: (profile) => {
      (
        profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue as {
          appId: string;
        }
      ).appId = 'missing';
    },
  },
  {
    name: 'browser local-storage resource',
    pointer: '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/resource',
    mutate: (profile) => {
      (
        profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue as {
          resource: string;
        }
      ).resource = 'https://missing.example';
    },
  },
  {
    name: 'browser local-storage scope',
    pointer: '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/scope',
    mutate: (profile) => {
      (
        profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue as {
          scope: string;
        }
      ).scope = 'profile missing';
    },
  },
  {
    name: 'Console application',
    pointer: '/consoleAuthentication/applicationId',
    mutate: (profile) => {
      (profile.consoleAuthentication as { applicationId: string }).applicationId = 'missing';
    },
  },
  {
    name: 'Console redirect',
    pointer: '/consoleAuthentication/redirectUri',
    mutate: (profile) => {
      (profile.consoleAuthentication as { redirectUri: string }).redirectUri =
        'https://admin.example/missing';
    },
  },
  {
    name: 'organization token organization',
    pointer: '/consoleOrganizationTokenRequest/form/organization_id',
    mutate: (profile) => {
      (
        profile.consoleOrganizationTokenRequest.form as { organization_id: string }
      ).organization_id = 'missing';
    },
  },
  {
    name: 'Consent GET application',
    pointer: '/interactionOperations/0/requiredProjection/application/id',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        (operation.requiredProjection.application as { id: string }).id = 'missing';
      }
    },
  },
  {
    name: 'Consent GET resource scope',
    pointer: '/interactionOperations/0/requiredProjection/missingResourceScopes/0/scopes/0/id',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        (
          required(
            required(operation.requiredProjection.missingResourceScopes.at(0)).scopes.at(0)
          ) as { id: string }
        ).id = 'missing';
      }
    },
  },
  {
    name: 'Consent persisted resource scope',
    pointer: '/interactionOperations/1/requiredPersistedOutcome/resourceScopes/0',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredPersistedOutcome.resourceScopes as string[])[0] = 'missing';
      }
    },
  },
  {
    name: 'UI source tree assignment',
    pointer: '/uiAssetContracts/3/sourceTreeField',
    mutate: (profile) => {
      (profile.uiAssetContracts[3] as { sourceTreeField: string }).sourceTreeField =
        'experienceTree';
    },
  },
  {
    name: 'Consent GET application name',
    pointer: '/interactionOperations/0/requiredProjection/application/name',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        (operation.requiredProjection.application as { name: string }).name = 'Wrong';
      }
    },
  },
  ...(['id', 'username', 'name', 'primaryEmail', 'primaryPhone'] as const).map((field) => ({
    name: `Consent GET user ${field}`,
    pointer: `/interactionOperations/0/requiredProjection/user/${field}`,
    mutate: (profile: Phase1Profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        (operation.requiredProjection.user as unknown as Record<string, unknown>)[field] = 'wrong';
      }
    },
  })),
  {
    name: 'Consent GET unknown organization',
    pointer: '/interactionOperations/0/requiredProjection/organizations/0',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        (operation.requiredProjection.organizations as string[]).push('unknown-organization');
      }
    },
  },
  {
    name: 'Consent GET OIDC scope order',
    pointer: '/interactionOperations/0/requiredProjection/missingOIDCScope/0',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        const scopes = operation.requiredProjection.missingOIDCScope as string[];
        [scopes[0], scopes[1]] = ['email', 'profile'];
      }
    },
  },
  ...(
    [
      ['id', 'missing'],
      ['name', 'Wrong'],
      ['indicator', 'https://wrong.example'],
    ] as const
  ).map(([field, value]) => ({
    name: `Consent GET resource ${field}`,
    pointer: `/interactionOperations/0/requiredProjection/missingResourceScopes/0/resource/${field}`,
    mutate: (profile: Phase1Profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        const missing = required(operation.requiredProjection.missingResourceScopes.at(0));
        (missing.resource as unknown as Record<string, unknown>)[field] = value;
      }
    },
  })),
  ...(
    [
      ['name', 'wrong:scope'],
      ['description', 'Wrong'],
    ] as const
  ).map(([field, value]) => ({
    name: `Consent GET resource scope ${field}`,
    pointer: `/interactionOperations/0/requiredProjection/missingResourceScopes/0/scopes/0/${field}`,
    mutate: (profile: Phase1Profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        const missing = required(operation.requiredProjection.missingResourceScopes.at(0));
        (required(missing.scopes.at(0)) as unknown as Record<string, unknown>)[field] = value;
      }
    },
  })),
  {
    name: 'Consent GET redirect URI',
    pointer: '/interactionOperations/0/requiredProjection/redirectUri',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        (operation.requiredProjection as { redirectUri: string }).redirectUri =
          'https://wrong.example/callback';
      }
    },
  },
  ...(
    [
      ['applicationId', 'missing'],
      ['userId', 'missing'],
      ['resource', 'https://wrong.example'],
      ['userFirstConsentedApplicationId', 'missing'],
    ] as const
  ).map(([field, value]) => ({
    name: `Consent persisted ${field}`,
    pointer: `/interactionOperations/1/requiredPersistedOutcome/${field}`,
    mutate: (profile: Phase1Profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredPersistedOutcome as unknown as Record<string, unknown>)[field] = value;
      }
    },
  })),
  {
    name: 'Consent persisted OIDC scope order',
    pointer: '/interactionOperations/1/requiredPersistedOutcome/oidcScopes/0',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        const scopes = operation.requiredPersistedOutcome.oidcScopes as string[];
        [scopes[0], scopes[1]] = ['email', 'profile'];
      }
    },
  },
  ...(
    [
      ['accountId', 'missing'],
      ['clientId', 'missing'],
      ['lastSubmission', 'wrong submission'],
    ] as const
  ).map(([field, value]) => ({
    name: `Consent session extension ${field}`,
    pointer: `/interactionOperations/1/requiredPersistedOutcome/sessionExtension/${field}`,
    mutate: (profile: Phase1Profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredPersistedOutcome.sessionExtension as unknown as Record<string, unknown>)[
          field
        ] = value;
      }
    },
  })),
  ...(
    [
      ['name', 'Wrong'],
      ['type', 'Native'],
      ['isThirdParty', true],
    ] as const
  ).map(([field, value]) => ({
    name: `Console application projection ${field}`,
    pointer: `/consoleReadRequests/0/requiredProjection/0/${field}`,
    mutate: (profile: Phase1Profile) => {
      const request = required(profile.consoleReadRequests.at(0));

      if (request.path === '/api/applications') {
        (required(request.requiredProjection.at(0)) as unknown as Record<string, unknown>)[field] =
          value;
      }
    },
  })),
  {
    name: 'Console application custom metadata',
    pointer: '/consoleReadRequests/0/requiredProjection/0/customClientMetadata',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(0));

      if (request.path === '/api/applications') {
        (
          required(request.requiredProjection.at(0)) as unknown as {
            customClientMetadata: Record<string, unknown>;
          }
        ).customClientMetadata = { unexpected: true };
      }
    },
  },
  ...(
    [
      ['avatar', 'https://avatar.example'],
      ['lastSignInAt', 1],
      ['isSuspended', true],
      ['hasPassword', false],
    ] as const
  ).map(([field, value]) => ({
    name: `Console user projection ${field}`,
    pointer: `/consoleReadRequests/1/requiredProjection/0/${field}`,
    mutate: (profile: Phase1Profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/users') {
        (required(request.requiredProjection.at(0)) as unknown as Record<string, unknown>)[field] =
          value;
      }
    },
  })),
  {
    name: 'Consent client selected by first third-party order instead of browser config',
    pointer: '/interactionOperations/0/requiredProjection/application/id',
    mutate: (profile) => {
      const applications = profile.fixtures.dataTenant.applications as unknown as Array<
        Record<string, unknown>
      >;
      applications.splice(1, 0, {
        id: 'decoy-client',
        name: 'Decoy Client',
        type: 'SPA',
        isThirdParty: true,
        oidcClientMetadata: { redirectUris: ['https://data.example/callback'] },
        customClientMetadata: {},
        userConsentScopes: ['profile', 'email'],
        resourceConsentScopes: ['scope-id'],
      });
      const getOperation = required(profile.interactionOperations.at(0));
      const postOperation = required(profile.interactionOperations.at(1));

      if (getOperation.method === 'GET') {
        (getOperation.requiredProjection.application as { id: string; name: string }).id =
          'decoy-client';
        (getOperation.requiredProjection.application as { id: string; name: string }).name =
          'Decoy Client';
      }

      if (postOperation.method === 'POST') {
        (
          postOperation.requiredPersistedOutcome as unknown as {
            applicationId: string;
            userFirstConsentedApplicationId: string;
          }
        ).applicationId = 'decoy-client';
        (
          postOperation.requiredPersistedOutcome as unknown as {
            userFirstConsentedApplicationId: string;
          }
        ).userFirstConsentedApplicationId = 'decoy-client';
        (postOperation.requiredPersistedOutcome.sessionExtension as { clientId: string }).clientId =
          'decoy-client';
      }
    },
  },
];

describe('Phase 1 fixture semantics', () => {
  it('accepts compact fixtures whose references all resolve', () => {
    expect(() => assertFixtureSemantics(fixtureProfile())).not.toThrow();
  });

  it.each(fixtureMutations)('rejects a mutated $name at the exact pointer', (mutation) => {
    const profile = fixtureProfile();
    mutation.mutate(profile);
    expectSemanticFailure(profile, mutation.pointer);
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression */
