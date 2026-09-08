import type {
  Phase1NativeSurface,
  Phase1NativeSurfaceMarker,
  Phase1NativeSurfaceMarkerId,
  Phase1Profile,
} from './profile-types.js';

export type Phase1Implementation = 'oracle' | 'candidate';

export const phase1NativeSurfaceMarkerIds = Object.freeze([
  'productName',
  'sharedExperienceCookie',
  'sharedExperienceCookieSignature',
  'generatedCookiePrefix',
  'applicationIdHeader',
  'requestIdHeader',
  'nativeScheme',
  'demoConfigStorageKey',
  'redirectContextStoragePrefix',
  'adminConsoleStoragePrefix',
  'experienceLocaleStorageKey',
  'consoleLocaleStorageKey',
  'ssrGlobal',
  'nativeSdkGlobal',
  'domPrefix',
  'managementResource',
  'accountResource',
  'organizationResource',
  'organizationScope',
  'organizationRoleScope',
  'organizationAudiencePrefix',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);

const marker = (
  match: Phase1NativeSurfaceMarker['match'],
  reference: string,
  candidate: string
): Phase1NativeSurfaceMarker => Object.freeze({ match, reference, candidate });

export const asterNativeSurfaceContract = Object.freeze({
  legacyAliases: false,
  projectionPolicy: Object.freeze({
    direction: 'reference-to-candidate',
    unlistedDifferences: 'fail',
    securityOutcomes: 'exact',
  }),
  markers: Object.freeze({
    productName: marker('exact', 'Logto', 'Aster'),
    sharedExperienceCookie: marker('exact', '_logto', '_aster'),
    sharedExperienceCookieSignature: marker('exact', '_logto.sig', '_aster.sig'),
    generatedCookiePrefix: marker('prefix', '_logto_', '_aster_'),
    applicationIdHeader: marker('exact', 'logto-app-id', 'aster-app-id'),
    requestIdHeader: marker('exact', 'logto-core-request-id', 'aster-core-request-id'),
    nativeScheme: marker('prefix', 'logto://', 'aster://'),
    demoConfigStorageKey: marker('exact', 'logto:demo-app:dev:config', 'aster:demo-app:dev:config'),
    redirectContextStoragePrefix: marker(
      'prefix',
      'logto:redirect-context:fallback:',
      'aster:redirect-context:fallback:'
    ),
    adminConsoleStoragePrefix: marker('prefix', 'logto:admin_console:', 'aster:admin_console:'),
    experienceLocaleStorageKey: marker('exact', 'i18nextLogtoUiLng', 'i18nextAsterUiLng'),
    consoleLocaleStorageKey: marker('exact', 'i18nextLogtoAcLng', 'i18nextAsterAcLng'),
    ssrGlobal: marker('exact', 'logtoSsr', 'asterSsr'),
    nativeSdkGlobal: marker('exact', 'logtoNativeSdk', 'asterNativeSdk'),
    domPrefix: marker('prefix', 'logto_', 'aster_'),
    managementResource: marker(
      'exact',
      'https://default.logto.app/api',
      'urn:aster:resource:management'
    ),
    accountResource: marker('exact', 'https://admin.logto.app/me', 'urn:aster:resource:account'),
    organizationResource: marker(
      'exact',
      'urn:logto:resource:organizations',
      'urn:aster:resource:organizations'
    ),
    organizationScope: marker(
      'exact',
      'urn:logto:scope:organizations',
      'urn:aster:scope:organizations'
    ),
    organizationRoleScope: marker(
      'exact',
      'urn:logto:scope:organization_roles',
      'urn:aster:scope:organization_roles'
    ),
    organizationAudiencePrefix: marker(
      'prefix',
      'urn:logto:organization:',
      'urn:aster:organization:'
    ),
  }),
} as const satisfies Phase1NativeSurface);

const failMarker = (): never => {
  throw new TypeError('Invalid Phase 1 native surface marker');
};

const getMarker = (
  profile: Readonly<Phase1Profile>,
  markerId: Phase1NativeSurfaceMarkerId
): Phase1NativeSurfaceMarker => {
  if (!phase1NativeSurfaceMarkerIds.includes(markerId)) {
    return failMarker();
  }

  return profile.asterNativeSurface.markers[markerId];
};

const matches = (markerValue: Phase1NativeSurfaceMarker, expected: string, value: string) =>
  markerValue.match === 'exact' ? value === expected : value.startsWith(expected);

const projectObservedValue = (
  markerValue: Phase1NativeSurfaceMarker,
  implementation: Phase1Implementation,
  value: string
): string => {
  const expected = implementation === 'oracle' ? markerValue.reference : markerValue.candidate;

  if (!matches(markerValue, expected, value)) {
    throw new TypeError(`Invalid Phase 1 ${implementation} native surface`);
  }
  if (implementation === 'candidate') {
    return value;
  }
  if (markerValue.match === 'exact') {
    return markerValue.candidate;
  }

  return `${markerValue.candidate}${value.slice(markerValue.reference.length)}`;
};

export const projectNativeSurfaceObservation = (
  implementation: Phase1Implementation,
  markerId: Phase1NativeSurfaceMarkerId,
  value: string
): string => {
  if (!phase1NativeSurfaceMarkerIds.includes(markerId)) {
    return failMarker();
  }

  return projectObservedValue(asterNativeSurfaceContract.markers[markerId], implementation, value);
};

export const nativeSurfaceValue = (
  profile: Readonly<Phase1Profile>,
  implementation: Phase1Implementation,
  markerId: Phase1NativeSurfaceMarkerId
): string => {
  const value = getMarker(profile, markerId);

  return implementation === 'oracle' ? value.reference : value.candidate;
};

export const projectOracleNativeSurfaceValue = (
  profile: Readonly<Phase1Profile>,
  markerId: Phase1NativeSurfaceMarkerId,
  value: string
): string => projectObservedValue(getMarker(profile, markerId), 'oracle', value);

export const assertCandidateNativeSurfaceValue = (
  profile: Readonly<Phase1Profile>,
  markerId: Phase1NativeSurfaceMarkerId,
  value: string
): void => {
  projectObservedValue(getMarker(profile, markerId), 'candidate', value);
};
