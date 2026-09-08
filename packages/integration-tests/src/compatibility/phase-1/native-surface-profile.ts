import type { TargetConfig } from '../model.js';
import type { NormalizationContext } from '../normalize.js';
import type { SymbolTable } from '../symbol-table.js';

import { cloneAndDeepFreeze } from './model.js';
import { asterNativeSurfaceContract, type Phase1Implementation } from './native-surface.js';
import type { Phase1NativeSurfaceMarkerId, Phase1Profile } from './profile-types.js';

const resourceMarkerIds = Object.freeze([
  'managementResource',
  'accountResource',
  'organizationResource',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);

const scopeMarkerIds = Object.freeze([
  'organizationScope',
  'organizationRoleScope',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const recordField = (
  value: unknown,
  key: string
): Readonly<Record<string, unknown>> | undefined => {
  const nested = isRecord(value) ? value[key] : undefined;

  return isRecord(nested) ? nested : undefined;
};

const arrayField = (value: unknown, key: string): readonly unknown[] => {
  const nested = isRecord(value) ? value[key] : undefined;

  return Array.isArray(nested) ? nested : [];
};

const failNativeSurfaceProfile = (): never => {
  throw new TypeError('Invalid Phase 1 native surface profile');
};

const projectCandidateConfigurationValue = (
  profile: Readonly<Phase1Profile>,
  markerId: Phase1NativeSurfaceMarkerId,
  value: string
): string => {
  const marker = profile.asterNativeSurface.markers[markerId];
  const matches =
    marker.match === 'exact' ? value === marker.candidate : value.startsWith(marker.candidate);

  if (!matches) {
    throw new TypeError('Invalid Phase 1 native surface configuration');
  }

  return marker.match === 'exact'
    ? marker.reference
    : `${marker.reference}${value.slice(marker.candidate.length)}`;
};

const projectKnownExactValue = (
  profile: Readonly<Phase1Profile>,
  markerIds: readonly Phase1NativeSurfaceMarkerId[],
  value: string
): string => {
  for (const markerId of markerIds) {
    const marker = profile.asterNativeSurface.markers[markerId];

    if (value === marker.candidate) {
      return marker.reference;
    }
    if (value === marker.reference) {
      throw new TypeError('Invalid Phase 1 native surface configuration');
    }
  }

  return value;
};

export const phase1ImplementationForProfile = (
  profile: Readonly<Phase1Profile>
): Phase1Implementation => {
  const observed = new Set<Phase1Implementation>();
  const observe = (markerId: Phase1NativeSurfaceMarkerId, value: unknown): void => {
    if (typeof value !== 'string') {
      return;
    }
    const marker = asterNativeSurfaceContract.markers[markerId];
    const referenceMatches =
      marker.match === 'exact' ? value === marker.reference : value.startsWith(marker.reference);
    const candidateMatches =
      marker.match === 'exact' ? value === marker.candidate : value.startsWith(marker.candidate);

    if (referenceMatches) {
      observed.add('oracle');
    }
    if (candidateMatches) {
      observed.add('candidate');
    }
  };
  const observeCollection = (markerId: Phase1NativeSurfaceMarkerId, value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) {
        observe(markerId, item);
      }
    }
  };

  const fixtures = recordField(profile, 'fixtures');
  const adminTenant = recordField(fixtures, 'adminTenant');
  const dataTenant = recordField(fixtures, 'dataTenant');
  const browserClientConfiguration = recordField(dataTenant, 'browserClientConfiguration');
  const consoleAuthentication = recordField(profile, 'consoleAuthentication');
  const organizationTokenRequest = recordField(profile, 'consoleOrganizationTokenRequest');
  const requiredAccessTokenProjection = recordField(
    organizationTokenRequest,
    'requiredAccessTokenProjection'
  );
  const oidc = recordField(profile, 'oidc');

  observe('demoConfigStorageKey', browserClientConfiguration?.localStorageKey);
  for (const rawResource of arrayField(adminTenant, 'resources')) {
    const resource = isRecord(rawResource) ? rawResource : undefined;

    observe('managementResource', resource?.indicator);
    observe('accountResource', resource?.indicator);
    observe('organizationResource', resource?.indicator);
    observeCollection('organizationScope', resource?.scopes);
    observeCollection('organizationRoleScope', resource?.scopes);
  }
  for (const value of [
    consoleAuthentication?.configuredResources,
    consoleAuthentication?.effectiveResources,
  ]) {
    observeCollection('managementResource', value);
    observeCollection('accountResource', value);
    observeCollection('organizationResource', value);
  }
  for (const value of [
    consoleAuthentication?.configuredScopes,
    consoleAuthentication?.effectiveScopes,
    oidc?.scopesSupported,
  ]) {
    observeCollection('organizationScope', value);
    observeCollection('organizationRoleScope', value);
  }
  observe('organizationAudiencePrefix', requiredAccessTokenProjection?.aud);
  for (const rawRequest of arrayField(profile, 'consoleReadRequests')) {
    const authorization = recordField(rawRequest, 'authorization');

    observe('managementResource', authorization?.resource);
  }
  for (const rawRequest of arrayField(profile, 'consoleAccountRequests')) {
    const authorization = recordField(rawRequest, 'authorization');

    observe('accountResource', authorization?.resource);
  }

  if (observed.size !== 1) {
    return failNativeSurfaceProfile();
  }
  const [implementation] = observed;

  return implementation ?? failNativeSurfaceProfile();
};

export const createPhase1NormalizationContext = (
  profile: Readonly<Phase1Profile>,
  target: TargetConfig,
  symbols: SymbolTable
): NormalizationContext =>
  Object.freeze({
    target,
    symbols,
    nativeSurfaceImplementation: phase1ImplementationForProfile(profile),
  });

export const projectPhase1ProfileForImplementation = (
  profile: Readonly<Phase1Profile>,
  implementation: Phase1Implementation
): Readonly<Phase1Profile> => {
  if (implementation === 'candidate') {
    return profile;
  }

  return cloneAndDeepFreeze<Phase1Profile>({
    ...profile,
    fixtures: {
      ...profile.fixtures,
      adminTenant: {
        ...profile.fixtures.adminTenant,
        resources: profile.fixtures.adminTenant.resources.map((resource) => ({
          ...resource,
          indicator: projectKnownExactValue(profile, resourceMarkerIds, resource.indicator),
          scopes: resource.scopes.map((scope) =>
            projectKnownExactValue(profile, scopeMarkerIds, scope)
          ),
        })),
      },
      dataTenant: {
        ...profile.fixtures.dataTenant,
        browserClientConfiguration: {
          ...profile.fixtures.dataTenant.browserClientConfiguration,
          localStorageKey: projectCandidateConfigurationValue(
            profile,
            'demoConfigStorageKey',
            profile.fixtures.dataTenant.browserClientConfiguration.localStorageKey
          ),
        },
      },
    },
    consoleAuthentication: {
      ...profile.consoleAuthentication,
      configuredResources: profile.consoleAuthentication.configuredResources.map((resource) =>
        projectKnownExactValue(profile, resourceMarkerIds, resource)
      ),
      effectiveResources: profile.consoleAuthentication.effectiveResources.map((resource) =>
        projectKnownExactValue(profile, resourceMarkerIds, resource)
      ),
      configuredScopes: profile.consoleAuthentication.configuredScopes.map((scope) =>
        projectKnownExactValue(profile, scopeMarkerIds, scope)
      ),
      effectiveScopes: profile.consoleAuthentication.effectiveScopes.map((scope) =>
        projectKnownExactValue(profile, scopeMarkerIds, scope)
      ),
    },
    consoleOrganizationTokenRequest: {
      ...profile.consoleOrganizationTokenRequest,
      form: {
        ...profile.consoleOrganizationTokenRequest.form,
        resource:
          profile.consoleOrganizationTokenRequest.form.resource === null
            ? null
            : projectKnownExactValue(
                profile,
                resourceMarkerIds,
                profile.consoleOrganizationTokenRequest.form.resource
              ),
      },
      requiredAccessTokenProjection: {
        ...profile.consoleOrganizationTokenRequest.requiredAccessTokenProjection,
        aud: projectCandidateConfigurationValue(
          profile,
          'organizationAudiencePrefix',
          profile.consoleOrganizationTokenRequest.requiredAccessTokenProjection.aud
        ),
      },
    },
    oidc: {
      ...profile.oidc,
      scopesSupported: profile.oidc.scopesSupported.map((scope) =>
        projectKnownExactValue(profile, scopeMarkerIds, scope)
      ),
    },
    consoleReadRequests: profile.consoleReadRequests.map((request) =>
      request.authorization === null
        ? request
        : {
            ...request,
            authorization: {
              ...request.authorization,
              resource: projectKnownExactValue(
                profile,
                resourceMarkerIds,
                request.authorization.resource
              ),
            },
          }
    ),
    consoleAccountRequests: profile.consoleAccountRequests.map((request) => ({
      ...request,
      authorization: {
        ...request.authorization,
        resource:
          request.authorization.resource === null
            ? null
            : projectKnownExactValue(profile, resourceMarkerIds, request.authorization.resource),
      },
    })),
  });
};
