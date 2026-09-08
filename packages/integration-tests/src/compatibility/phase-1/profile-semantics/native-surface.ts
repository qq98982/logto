/* eslint-disable no-restricted-syntax -- Ordered contract checks return the first stable profile pointer. */
import {
  assertCandidateNativeSurfaceValue,
  asterNativeSurfaceContract,
  phase1NativeSurfaceMarkerIds,
} from '../native-surface.js';
import type {
  Phase1NativeSurface,
  Phase1NativeSurfaceMarkerId,
  Phase1Profile,
} from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

const fail = (pointer: string): never => {
  throw new Phase1ProfileValidationError('semantic', [pointer], ['native-surface']);
};

const assertEqual = (actual: unknown, expected: unknown, pointer: string): void => {
  if (actual !== expected) {
    fail(pointer);
  }
};

const assertExactStrings = (
  actual: readonly string[],
  expected: readonly string[],
  pointer: string
): void => {
  const difference = Array.from(
    { length: Math.max(actual.length, expected.length) },
    (_, index) => index
  ).find((index) => actual[index] !== expected[index]);

  if (difference !== undefined) {
    fail(`${pointer}/${difference}`);
  }
};

const assertCandidateAt = (
  profile: Phase1Profile,
  markerId: Phase1NativeSurfaceMarkerId,
  value: string,
  pointer: string
): void => {
  try {
    assertCandidateNativeSurfaceValue(profile, markerId, value);
  } catch {
    fail(pointer);
  }
};

const assertContract = (profile: Phase1Profile): void => {
  const runtimeProfile = profile as unknown as Readonly<{
    schemaVersion?: unknown;
    asterNativeSurface?: Phase1NativeSurface;
  }>;

  if (runtimeProfile.schemaVersion !== 2) {
    fail('/schemaVersion');
  }
  const surface = runtimeProfile.asterNativeSurface ?? fail('/asterNativeSurface');
  assertEqual(surface.legacyAliases, false, '/asterNativeSurface/legacyAliases');
  assertEqual(
    surface.projectionPolicy.direction,
    asterNativeSurfaceContract.projectionPolicy.direction,
    '/asterNativeSurface/projectionPolicy/direction'
  );
  assertEqual(
    surface.projectionPolicy.unlistedDifferences,
    asterNativeSurfaceContract.projectionPolicy.unlistedDifferences,
    '/asterNativeSurface/projectionPolicy/unlistedDifferences'
  );
  assertEqual(
    surface.projectionPolicy.securityOutcomes,
    asterNativeSurfaceContract.projectionPolicy.securityOutcomes,
    '/asterNativeSurface/projectionPolicy/securityOutcomes'
  );
  const actualIds = Object.keys(surface.markers);

  if (
    actualIds.length !== phase1NativeSurfaceMarkerIds.length ||
    actualIds.some(
      (id) => !phase1NativeSurfaceMarkerIds.includes(id as Phase1NativeSurfaceMarkerId)
    )
  ) {
    fail('/asterNativeSurface/markers');
  }

  for (const markerId of phase1NativeSurfaceMarkerIds) {
    const actual = surface.markers[markerId];
    const expected = asterNativeSurfaceContract.markers[markerId];
    const pointer = `/asterNativeSurface/markers/${markerId}`;

    assertEqual(actual.match, expected.match, `${pointer}/match`);
    assertEqual(actual.reference, expected.reference, `${pointer}/reference`);
    assertEqual(actual.candidate, expected.candidate, `${pointer}/candidate`);
  }
};

const assertCandidateFixtureValues = (profile: Phase1Profile): void => {
  const { markers } = profile.asterNativeSurface;
  const { resources } = profile.fixtures.adminTenant;
  const resourceMarkers = [
    'managementResource',
    'accountResource',
    'organizationResource',
  ] as const satisfies readonly Phase1NativeSurfaceMarkerId[];

  if (resources.length !== resourceMarkers.length) {
    fail(`/fixtures/adminTenant/resources/${Math.min(resources.length, resourceMarkers.length)}`);
  }
  for (const [index, markerId] of resourceMarkers.entries()) {
    const resource = resources[index] ?? fail(`/fixtures/adminTenant/resources/${index}`);
    assertCandidateAt(
      profile,
      markerId,
      resource.indicator,
      `/fixtures/adminTenant/resources/${index}/indicator`
    );
  }
  assertExactStrings(
    resources[2]?.scopes ?? [],
    [markers.organizationScope.candidate, markers.organizationRoleScope.candidate],
    '/fixtures/adminTenant/resources/2/scopes'
  );
  assertCandidateAt(
    profile,
    'demoConfigStorageKey',
    profile.fixtures.dataTenant.browserClientConfiguration.localStorageKey,
    '/fixtures/dataTenant/browserClientConfiguration/localStorageKey'
  );
  assertExactStrings(
    profile.consoleAuthentication.configuredResources,
    [markers.managementResource.candidate, markers.accountResource.candidate],
    '/consoleAuthentication/configuredResources'
  );
  assertExactStrings(
    profile.consoleAuthentication.effectiveResources,
    [
      markers.managementResource.candidate,
      markers.accountResource.candidate,
      markers.organizationResource.candidate,
    ],
    '/consoleAuthentication/effectiveResources'
  );
  assertExactStrings(
    profile.consoleAuthentication.configuredScopes.filter((scope) => scope.startsWith('urn:')),
    [markers.organizationScope.candidate, markers.organizationRoleScope.candidate],
    '/consoleAuthentication/configuredScopes'
  );
  assertExactStrings(
    profile.consoleAuthentication.effectiveScopes.filter((scope) => scope.startsWith('urn:')),
    [markers.organizationScope.candidate, markers.organizationRoleScope.candidate],
    '/consoleAuthentication/effectiveScopes'
  );
  assertExactStrings(
    profile.oidc.scopesSupported.filter((scope) => scope.startsWith('urn:')),
    [
      markers.organizationScope.candidate,
      markers.organizationRoleScope.candidate,
      markers.sessionScope.candidate,
    ],
    '/oidc/scopesSupported'
  );
  assertCandidateAt(
    profile,
    'organizationAudiencePrefix',
    profile.consoleOrganizationTokenRequest.requiredAccessTokenProjection.aud,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/aud'
  );
  assertEqual(
    profile.consoleOrganizationTokenRequest.requiredAccessTokenProjection.aud,
    `${markers.organizationAudiencePrefix.candidate}${profile.fixtures.adminTenant.tenantOrganization.id}`,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/aud'
  );

  for (const [index, { authorization }] of profile.consoleReadRequests.entries()) {
    if (authorization) {
      assertCandidateAt(
        profile,
        'managementResource',
        authorization.resource,
        `/consoleReadRequests/${index}/authorization/resource`
      );
    }
  }
};

const assertCustomResourceSeparation = (profile: Phase1Profile): void => {
  const { indicator: custom } = profile.fixtures.dataTenant.resource;
  const { markers } = profile.asterNativeSurface;
  const reserved = new Set(
    [markers.managementResource, markers.accountResource, markers.organizationResource].flatMap(
      ({ reference, candidate }) => [reference, candidate]
    )
  );

  if (reserved.has(custom)) {
    fail('/fixtures/dataTenant/resource/indicator');
  }
};

export const assertNativeSurfaceSemantics = (profile: Phase1Profile): void => {
  assertContract(profile);
  assertCandidateFixtureValues(profile);
  assertCustomResourceSeparation(profile);
};

/* eslint-enable no-restricted-syntax */
