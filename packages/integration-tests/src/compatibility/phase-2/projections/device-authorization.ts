/* eslint-disable complexity, max-lines, max-params, no-control-regex, no-restricted-syntax, @typescript-eslint/ban-types, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This is the single public boundary for a hostile multi-step device flow and its verified token semantics. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';

import type { TargetConfig } from '../../model.js';
import { containsCompactJwt } from '../clients/client-credentials.js';

export type DeviceAuthorizationUrlProjection = Readonly<{
  origin: string;
  path: string;
  queryKeys: readonly string[];
}>;

export type DeviceAuthorizationCookieProjection = Readonly<{
  name: string;
  options: readonly string[];
  clearing: boolean;
}>;

export type DeviceAuthorizationChallengeProjection = Readonly<{
  scheme: string;
  parameters: Readonly<Record<string, string>>;
}>;

export type DeviceAuthorizationProjection = Readonly<{
  status: number;
  contentType: string | undefined;
  headers: Readonly<Record<string, string>>;
  keys: readonly string[];
  cookies: readonly DeviceAuthorizationCookieProjection[];
  challenge: DeviceAuthorizationChallengeProjection | undefined;
  location: DeviceAuthorizationUrlProjection | undefined;
  oauthError: Readonly<{ category: string | undefined; description: string | undefined }>;
  userCodeShape:
    | Readonly<{
        length: number;
        groups: readonly number[];
        separator: string | undefined;
        matchesReferencePattern: boolean;
      }>
    | undefined;
  deviceCodeShape: Readonly<{ length: number }> | undefined;
  expiresIn: number | undefined;
  interval: number | undefined;
  verificationUri: DeviceAuthorizationUrlProjection | undefined;
  verificationUriComplete: DeviceAuthorizationUrlProjection | undefined;
  experience:
    | Readonly<{
        title: string | undefined;
        formAction: DeviceAuthorizationUrlProjection | undefined;
        inputNames: readonly string[];
        autoSubmit: boolean;
      }>
    | undefined;
}>;

export type DeviceLifecycleKind =
  | 'verification-success'
  | 'experience-open'
  | 'password-verification'
  | 'identification'
  | 'experience-submit'
  | 'consent-read'
  | 'consent-write'
  | 'resume'
  | 'refresh'
  | 'userinfo'
  | 'introspection'
  | 'revocation'
  | 'logout-open'
  | 'logout-confirm'
  | 'oidc-discovery'
  | 'oauth-discovery';

type DeviceLifecycleCommonProjection = Readonly<{
  kind: DeviceLifecycleKind;
  status: number;
  contentType: string | undefined;
  headers: Readonly<Record<string, string>>;
  cookies: readonly DeviceAuthorizationCookieProjection[];
  challenge: DeviceAuthorizationChallengeProjection | undefined;
  location: DeviceAuthorizationUrlProjection | undefined;
  oauthError: Readonly<{ category: string | undefined; description: string | undefined }>;
}>;

export type DeviceLifecycleFactsByKind = Readonly<{
  'verification-success': Readonly<{ marker: 'device-success'; shell: 'experience-app' }>;
  'experience-open': Readonly<{ marker: 'experience-opened' }>;
  'password-verification': Readonly<{ marker: 'password-verified' }>;
  identification: Readonly<{ marker: 'subject-identified' }>;
  'experience-submit': Readonly<{
    marker: 'experience-submitted';
    redirect: DeviceAuthorizationUrlProjection;
  }>;
  'consent-read': Readonly<{
    marker: 'consent-presented';
    redirectUriAbsent: boolean;
    missingOidcScopes: readonly string[];
    missingResourceScopeCount: number;
  }>;
  'consent-write': Readonly<{
    marker: 'consent-recorded';
    redirect: DeviceAuthorizationUrlProjection;
  }>;
  resume:
    | Readonly<{ marker: 'consent-redirect'; stage: 'after-experience-submit' }>
    | Readonly<{ marker: 'device-success-redirect'; stage: 'after-consent-write' }>;
  refresh:
    | Readonly<{ marker: 'oauth-error' }>
    | Readonly<{
        marker: 'tokens-refreshed';
        tokenType: 'Bearer';
        expiresIn: number;
        refreshRotated: true;
        idTokenIssued: boolean;
        scopes?: readonly string[];
      }>;
  userinfo:
    | Readonly<{ marker: 'oauth-error' }>
    | Readonly<{
        marker: 'userinfo';
        subject: '<subject>';
        keys: readonly string[];
        emailVerified?: boolean;
        phoneNumberVerified?: boolean;
      }>;
  introspection:
    | Readonly<{ marker: 'oauth-error' }>
    | Readonly<{ marker: 'introspection'; active: false }>
    | Readonly<{
        marker: 'introspection';
        active: true;
        subject: '<subject>';
        clientId: '<client>';
        issuer: '<target-issuer>';
        issuedAt: '<issued-at>';
        lifetimeSeconds: number;
        scopes: readonly string[];
        tokenType?: 'Bearer';
      }>;
  revocation: Readonly<{ marker: 'revoked' }> | Readonly<{ marker: 'oauth-error' }>;
  'logout-open':
    | Readonly<{
        marker: 'logout-confirmation';
        title: string | undefined;
        formAction: DeviceAuthorizationUrlProjection;
        inputNames: readonly string[];
      }>
    | Readonly<{ marker: 'logout-finished' }>;
  'logout-confirm': Readonly<{ marker: 'logout-finished' }>;
  'oidc-discovery': Readonly<{
    marker: 'oidc-discovery';
    issuer: '<target-issuer>';
    endpoints: Readonly<Record<string, DeviceAuthorizationUrlProjection>>;
    keys: readonly string[];
  }>;
  'oauth-discovery': Readonly<{
    marker: 'oauth-discovery';
    issuer: '<target-issuer>';
    endpoints: Readonly<Record<string, DeviceAuthorizationUrlProjection>>;
    keys: readonly string[];
  }>;
}>;

export type DeviceLifecycleProjection = {
  readonly [Kind in DeviceLifecycleKind]: DeviceLifecycleCommonProjection &
    Readonly<{ kind: Kind; facts: DeviceLifecycleFactsByKind[Kind] }>;
}[DeviceLifecycleKind];

export type DeviceVerifiedJwtProjection = Readonly<{
  format: 'verified-jwt';
  header: Readonly<{
    algorithm: '<verified-signing-algorithm>';
    keyId: '<verified-key>';
    type?: 'at+jwt' | 'JWT';
  }>;
  claims: Readonly<{
    claimKeys: readonly string[];
    claimTypes: Readonly<Record<string, DeviceJwtClaimType>>;
    issuer: '<target-issuer>';
    audience: readonly string[];
    subject: '<subject>';
    clientId?: '<client>';
    scopes?: readonly string[];
    resource?: string;
    organizationId?: string;
    jwtId?: '<opaque-id>';
    organizations?: Readonly<{
      count: number;
      expectedOrganizationMember?: true;
    }>;
    issuedAt: '<issued-at>';
    lifetimeSeconds: number;
  }>;
  signature: Readonly<{ verified: true }>;
}>;

export type DeviceJwtClaimType =
  | 'string'
  | 'number'
  | 'boolean'
  | 'string-array'
  | 'address'
  | 'null';

export type DeviceCredentialProjection = Readonly<{
  access: DeviceVerifiedJwtProjection | Readonly<{ format: 'opaque'; present: true }>;
  id: DeviceVerifiedJwtProjection | undefined;
  refresh: Readonly<{ format: 'opaque'; present: true; rotated: boolean | undefined }> | undefined;
}>;

export type DeviceCredentialProjectionInput = Readonly<{
  target: TargetConfig;
  jwks: JSONWebKeySet;
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  previousRefreshToken?: string;
  expected: Readonly<{
    clientId: string;
    subjectId: string;
    audience: string;
    scopes?: readonly string[];
    resource?: string;
    organizationId?: string;
  }>;
}>;

const diagnostic = 'Invalid Phase 2 device authorization projection';
const fieldNamePattern = /^[A-Za-z][A-Za-z0-9_.~-]{0,127}$/u;
const mediaTypePattern = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/u;
const forbiddenKeyPattern =
  /^(?:authorization|proxy.?authorization|cookie|set.?cookie|password|client.?secret|access.?token|refresh.?token|id.?token|device.?code|user.?code|xsrf|verification.?id|redirect.?to)$/iu;
const credentialPattern = /\b(?:basic|bearer)\s+[A-Za-z0-9._~+/-]+=*/iu;
const selectedHeaderNames = new Set([
  'access-control-allow-origin',
  'access-control-expose-headers',
  'cache-control',
  'pragma',
  'referrer-policy',
  'x-content-type-options',
]);
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const accessClaimNames = new Set([
  'iss',
  'aud',
  'sub',
  'client_id',
  'scope',
  'resource',
  'organization_id',
  'iat',
  'exp',
  'jti',
]);
const idTokenClaimNames = new Set([
  'iss',
  'aud',
  'sub',
  'iat',
  'exp',
  'nbf',
  'auth_time',
  'sid',
  'jti',
  'client_id',
  'acr',
  'amr',
  'name',
  'picture',
  'username',
  'email',
  'email_verified',
  'phone_number',
  'phone_number_verified',
  'family_name',
  'given_name',
  'middle_name',
  'nickname',
  'preferred_username',
  'profile',
  'website',
  'gender',
  'birthdate',
  'zoneinfo',
  'locale',
  'address',
  'created_at',
  'updated_at',
  'roles',
  'organizations',
  'organization_roles',
  'organization_id',
  'permissions',
]);
const numericClaimNames = new Set(['iat', 'exp', 'nbf', 'auth_time', 'created_at', 'updated_at']);
const booleanClaimNames = new Set(['email_verified', 'phone_number_verified']);
const nullableProfileClaimNames = new Set([
  'name',
  'picture',
  'username',
  'email',
  'phone_number',
  'family_name',
  'given_name',
  'middle_name',
  'nickname',
  'preferred_username',
  'profile',
  'website',
  'gender',
  'birthdate',
  'zoneinfo',
  'locale',
]);
const stringArrayClaimNames = new Set([
  'aud',
  'amr',
  'roles',
  'organizations',
  'organization_roles',
  'permissions',
]);
const addressClaimNames = new Set([
  'formatted',
  'street_address',
  'locality',
  'region',
  'postal_code',
  'country',
]);
const opaqueJwtIdPattern = /^[A-Za-z0-9._~-]{8,512}$/u;
const topProjectionKeys = new Set([
  'status',
  'contentType',
  'headers',
  'keys',
  'cookies',
  'challenge',
  'location',
  'oauthError',
  'userCodeShape',
  'deviceCodeShape',
  'expiresIn',
  'interval',
  'verificationUri',
  'verificationUriComplete',
  'experience',
]);
const lifecycleProjectionKeys = new Set([
  'kind',
  'status',
  'contentType',
  'headers',
  'cookies',
  'challenge',
  'location',
  'oauthError',
  'facts',
]);
const lifecycleKinds = new Set<DeviceLifecycleKind>([
  'verification-success',
  'experience-open',
  'password-verification',
  'identification',
  'experience-submit',
  'consent-read',
  'consent-write',
  'resume',
  'refresh',
  'userinfo',
  'introspection',
  'revocation',
  'logout-open',
  'logout-confirm',
  'oidc-discovery',
  'oauth-discovery',
]);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !descriptor.enumerable
    ) {
      return fail();
    }
  }
  return value as Record<string, unknown>;
};

const exactRecord = (value: unknown, keys: ReadonlySet<string>): Record<string, unknown> => {
  const source = record(value);
  const names = Object.keys(source);
  if (names.length !== keys.size || names.some((key) => !keys.has(key))) {
    return fail();
  }
  return source;
};

const exactRecordWithOptional = (
  value: unknown,
  required: ReadonlySet<string>,
  optional: ReadonlySet<string>
): Record<string, unknown> => {
  const source = record(value);
  const names = Object.keys(source);
  if (
    [...required].some((key) => !names.includes(key)) ||
    names.some((key) => !required.has(key) && !optional.has(key))
  ) {
    return fail();
  }
  return source;
};

const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const snapshotDenseArray = (value: unknown, maximum = 128): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return fail();
  }
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as Record<
    PropertyKey,
    PropertyDescriptor
  >;
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor?.value as unknown;
  if (
    typeof length !== 'number' ||
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > maximum ||
    Reflect.ownKeys(value).length !== length + 1
  ) {
    return fail();
  }
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !descriptor.enumerable
    ) {
      return fail();
    }
    snapshot.push(descriptor.value as unknown);
  }
  return Object.freeze(snapshot);
};

const inspectPublicEvidence = (
  value: unknown,
  seen = new Set<object>(),
  depth = 0,
  parentKey = ''
): void => {
  if (depth > 12) {
    fail();
  }
  if (typeof value === 'string') {
    if (
      Buffer.byteLength(value) > 16 * 1024 ||
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value) ||
      /private-(?:secret|password|token|cookie|code|xsrf)/iu.test(value) ||
      credentialPattern.test(value) ||
      containsCompactJwt(value)
    ) {
      fail();
    }
    return;
  }
  if (
    value === undefined ||
    value === null ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return;
  }
  if (typeof value !== 'object' || nodeTypes.isProxy(value) || seen.has(value)) {
    fail();
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (const nested of snapshotDenseArray(value)) {
      inspectPublicEvidence(nested, seen, depth + 1, parentKey);
    }
    return;
  }
  const source = record(value);
  if (Object.keys(source).length > 128) {
    fail();
  }
  for (const [key, nested] of Object.entries(source)) {
    if (forbiddenKeyPattern.test(key)) {
      fail();
    }
    inspectPublicEvidence(nested, seen, depth + 1, key);
  }
};

export const assertDeviceAuthorizationEvidenceIsSanitized = (value: unknown): void => {
  inspectPublicEvidence(value);
};

const assertStatus = (value: unknown): void => {
  if (!Number.isSafeInteger(value) || Number(value) < 100 || Number(value) > 599) {
    fail();
  }
};

const assertStringArray = (value: unknown): void => {
  if (snapshotDenseArray(value).some((entry) => typeof entry !== 'string')) {
    fail();
  }
};

const sortedUniqueStrings = (
  value: unknown,
  maximum: number,
  valid: (entry: string) => boolean = () => true
): readonly string[] => {
  const snapshot = snapshotDenseArray(value, maximum);
  if (snapshot.some((entry) => typeof entry !== 'string' || !valid(entry))) {
    return fail();
  }
  const entries = snapshot as string[];
  if (
    new Set(entries).size !== entries.length ||
    !isDeepStrictEqual(
      entries,
      [...entries].sort((left, right) => left.localeCompare(right))
    )
  ) {
    return fail();
  }
  return entries;
};

const assertUrlProjection = (value: unknown): void => {
  const source = exactRecord(value, new Set(['origin', 'path', 'queryKeys']));
  let origin: URL;
  try {
    origin = new URL(String(source.origin));
  } catch {
    return fail();
  }
  if (
    typeof source.origin !== 'string' ||
    typeof source.path !== 'string' ||
    !source.path.startsWith('/') ||
    Buffer.byteLength(source.path) > 8192 ||
    /[\u0000-\u001F\u007F?#]/u.test(source.path) ||
    !['http:', 'https:'].includes(origin.protocol) ||
    origin.origin !== source.origin ||
    origin.username.length > 0 ||
    origin.password.length > 0 ||
    origin.pathname !== '/' ||
    origin.search.length > 0 ||
    origin.hash.length > 0
  ) {
    fail();
  }
  sortedUniqueStrings(source.queryKeys, 64, (entry) => fieldNamePattern.test(entry));
};

const assertOptionalPositiveInteger = (value: unknown): void => {
  if (
    value !== undefined &&
    (!Number.isSafeInteger(value) || Number(value) <= 0 || Number(value) > 86_400)
  ) {
    fail();
  }
};

const assertAuthorizationProjectionFields = (source: Record<string, unknown>): void => {
  sortedUniqueStrings(own(source, 'keys'), 32, (entry) => fieldNamePattern.test(entry));
  const userCodeShape = own(source, 'userCodeShape');
  if (userCodeShape !== undefined) {
    const shape = exactRecord(
      userCodeShape,
      new Set(['length', 'groups', 'separator', 'matchesReferencePattern'])
    );
    const groups = snapshotDenseArray(shape.groups, 32);
    const groupLengths = groups.map((group) =>
      Number.isSafeInteger(group) ? Number(group) : fail()
    );
    if (
      !Number.isSafeInteger(shape.length) ||
      Number(shape.length) <= 0 ||
      Number(shape.length) > 4096 ||
      groups.length === 0 ||
      groupLengths.some((group) => group <= 0 || group > 4096) ||
      (shape.separator !== undefined && shape.separator !== '-') ||
      (shape.separator === undefined && groups.length !== 1) ||
      typeof shape.matchesReferencePattern !== 'boolean' ||
      groupLengths.reduce((sum, group) => sum + group, 0) +
        (shape.separator === undefined ? 0 : groups.length - 1) !==
        shape.length ||
      (shape.matchesReferencePattern &&
        !(shape.length === 9 && shape.separator === '-' && isDeepStrictEqual(groupLengths, [4, 4])))
    ) {
      fail();
    }
  }
  const deviceCodeShape = own(source, 'deviceCodeShape');
  if (deviceCodeShape !== undefined) {
    const shape = exactRecord(deviceCodeShape, new Set(['length']));
    if (
      !Number.isSafeInteger(shape.length) ||
      Number(shape.length) <= 0 ||
      Number(shape.length) > 4096
    ) {
      fail();
    }
  }
  assertOptionalPositiveInteger(own(source, 'expiresIn'));
  assertOptionalPositiveInteger(own(source, 'interval'));
  for (const key of ['verificationUri', 'verificationUriComplete'] as const) {
    const url = own(source, key);
    if (url !== undefined) {
      assertUrlProjection(url);
    }
  }
  const experience = own(source, 'experience');
  if (experience !== undefined) {
    const projected = exactRecord(
      experience,
      new Set(['title', 'formAction', 'inputNames', 'autoSubmit'])
    );
    if (
      (projected.title !== undefined &&
        (typeof projected.title !== 'string' || Buffer.byteLength(projected.title) > 256)) ||
      typeof projected.autoSubmit !== 'boolean'
    ) {
      fail();
    }
    if (projected.formAction !== undefined) {
      assertUrlProjection(projected.formAction);
    }
    sortedUniqueStrings(projected.inputNames, 32, (entry) => fieldNamePattern.test(entry));
  }
};

const assertMarkerOnly = (facts: Record<string, unknown>, marker: string): void => {
  if (exactRecord(facts, new Set(['marker'])).marker !== marker) {
    fail();
  }
};

const assertLifecycleFacts = (kind: DeviceLifecycleKind, value: unknown): void => {
  const facts = record(value);
  const { marker } = facts;
  if (marker === 'oauth-error') {
    if (!['refresh', 'userinfo', 'introspection', 'revocation'].includes(kind)) {
      fail();
    }
    assertMarkerOnly(facts, 'oauth-error');
    return;
  }
  switch (kind) {
    case 'verification-success': {
      const source = exactRecord(facts, new Set(['marker', 'shell']));
      if (source.marker !== 'device-success' || source.shell !== 'experience-app') {
        fail();
      }

      break;
    }
    case 'experience-open': {
      assertMarkerOnly(facts, 'experience-opened');

      break;
    }
    case 'password-verification': {
      assertMarkerOnly(facts, 'password-verified');

      break;
    }
    case 'identification': {
      assertMarkerOnly(facts, 'subject-identified');

      break;
    }
    case 'experience-submit':
    case 'consent-write': {
      const source = exactRecord(facts, new Set(['marker', 'redirect']));
      if (
        source.marker !==
        (kind === 'experience-submit' ? 'experience-submitted' : 'consent-recorded')
      ) {
        fail();
      }
      assertUrlProjection(source.redirect);

      break;
    }
    case 'consent-read': {
      const source = exactRecord(
        facts,
        new Set(['marker', 'redirectUriAbsent', 'missingOidcScopes', 'missingResourceScopeCount'])
      );
      if (
        source.marker !== 'consent-presented' ||
        typeof source.redirectUriAbsent !== 'boolean' ||
        !Number.isSafeInteger(source.missingResourceScopeCount) ||
        Number(source.missingResourceScopeCount) < 0
      ) {
        fail();
      }
      assertStringArray(source.missingOidcScopes);

      break;
    }
    case 'resume': {
      const source = exactRecord(facts, new Set(['marker', 'stage']));
      if (
        (source.stage === 'after-experience-submit' && source.marker !== 'consent-redirect') ||
        (source.stage === 'after-consent-write' && source.marker !== 'device-success-redirect') ||
        !['after-experience-submit', 'after-consent-write'].includes(String(source.stage))
      ) {
        fail();
      }

      break;
    }
    case 'refresh': {
      const source = exactRecordWithOptional(
        facts,
        new Set(['marker', 'tokenType', 'expiresIn', 'refreshRotated', 'idTokenIssued']),
        new Set(['scopes'])
      );
      if (
        source.marker !== 'tokens-refreshed' ||
        source.tokenType !== 'Bearer' ||
        !Number.isSafeInteger(source.expiresIn) ||
        Number(source.expiresIn) <= 0 ||
        source.refreshRotated !== true ||
        typeof source.idTokenIssued !== 'boolean'
      ) {
        fail();
      }
      if (source.scopes !== undefined) {
        assertStringArray(source.scopes);
      }

      break;
    }
    case 'userinfo': {
      const source = exactRecordWithOptional(
        facts,
        new Set(['marker', 'subject', 'keys']),
        new Set(['emailVerified', 'phoneNumberVerified'])
      );
      if (
        source.marker !== 'userinfo' ||
        source.subject !== '<subject>' ||
        (source.emailVerified !== undefined && typeof source.emailVerified !== 'boolean') ||
        (source.phoneNumberVerified !== undefined &&
          typeof source.phoneNumberVerified !== 'boolean')
      ) {
        fail();
      }
      assertStringArray(source.keys);

      break;
    }
    case 'introspection': {
      if (facts.active === false) {
        const source = exactRecord(facts, new Set(['marker', 'active']));
        if (source.marker !== 'introspection') {
          fail();
        }
        return;
      }
      const source = exactRecordWithOptional(
        facts,
        new Set([
          'marker',
          'active',
          'subject',
          'clientId',
          'issuer',
          'issuedAt',
          'lifetimeSeconds',
          'scopes',
        ]),
        new Set(['tokenType'])
      );
      if (
        source.marker !== 'introspection' ||
        source.active !== true ||
        source.subject !== '<subject>' ||
        source.clientId !== '<client>' ||
        source.issuer !== '<target-issuer>' ||
        source.issuedAt !== '<issued-at>' ||
        !Number.isSafeInteger(source.lifetimeSeconds) ||
        Number(source.lifetimeSeconds) <= 0 ||
        (source.tokenType !== undefined && source.tokenType !== 'Bearer')
      ) {
        fail();
      }
      assertStringArray(source.scopes);

      break;
    }
    case 'revocation': {
      assertMarkerOnly(facts, 'revoked');

      break;
    }
    case 'logout-open': {
      if (marker === 'logout-finished') {
        assertMarkerOnly(facts, 'logout-finished');
        return;
      }
      const source = exactRecord(facts, new Set(['marker', 'title', 'formAction', 'inputNames']));
      if (
        source.marker !== 'logout-confirmation' ||
        (source.title !== undefined && typeof source.title !== 'string')
      ) {
        fail();
      }
      assertUrlProjection(source.formAction);
      assertStringArray(source.inputNames);

      break;
    }
    case 'logout-confirm': {
      assertMarkerOnly(facts, 'logout-finished');

      break;
    }
    case 'oidc-discovery':
    case 'oauth-discovery': {
      const source = exactRecord(facts, new Set(['marker', 'issuer', 'endpoints', 'keys']));
      if (source.marker !== kind || source.issuer !== '<target-issuer>') {
        fail();
      }
      const endpoints = exactRecord(
        source.endpoints,
        new Set([
          'authorization_endpoint',
          'token_endpoint',
          'jwks_uri',
          'userinfo_endpoint',
          'device_authorization_endpoint',
          'introspection_endpoint',
          'revocation_endpoint',
          'end_session_endpoint',
        ])
      );
      for (const endpoint of Object.values(endpoints)) {
        assertUrlProjection(endpoint);
      }
      assertStringArray(source.keys);

      break;
    }
  }
};

const assertCommonProjectionFields = (source: Record<string, unknown>): void => {
  assertStatus(own(source, 'status'));
  const contentType = own(source, 'contentType');
  if (
    contentType !== undefined &&
    (typeof contentType !== 'string' || !mediaTypePattern.test(contentType))
  ) {
    fail();
  }
  const headers = record(own(source, 'headers'));
  if (
    Object.entries(headers).some(
      ([name, value]) =>
        !selectedHeaderNames.has(name) ||
        typeof value !== 'string' ||
        Buffer.byteLength(value) > 4096
    )
  ) {
    fail();
  }
  const oauthError = exactRecord(own(source, 'oauthError'), new Set(['category', 'description']));
  if (
    (oauthError.category !== undefined &&
      (typeof oauthError.category !== 'string' || Buffer.byteLength(oauthError.category) > 256)) ||
    (oauthError.description !== undefined &&
      (typeof oauthError.description !== 'string' ||
        Buffer.byteLength(oauthError.description) > 2048))
  ) {
    fail();
  }
  const location = own(source, 'location');
  if (location !== undefined) {
    assertUrlProjection(location);
  }
  const challengeValue = own(source, 'challenge');
  if (challengeValue !== undefined) {
    const challenge = exactRecord(challengeValue, new Set(['scheme', 'parameters']));
    if (
      typeof challenge.scheme !== 'string' ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/u.test(challenge.scheme)
    ) {
      fail();
    }
    const parameters = record(challenge.parameters);
    const allowedParameters = new Set(['realm', 'error', 'error_description', 'scope']);
    if (
      Object.entries(parameters).some(
        ([name, value]) =>
          !allowedParameters.has(name) ||
          typeof value !== 'string' ||
          Buffer.byteLength(value) > 2048
      )
    ) {
      fail();
    }
  }
  const cookiesValue = own(source, 'cookies');
  const cookies = snapshotDenseArray(cookiesValue, 32);
  for (const cookie of cookies) {
    const projected = exactRecord(cookie, new Set(['name', 'options', 'clearing']));
    if (
      typeof projected.name !== 'string' ||
      !/^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(projected.name) ||
      typeof projected.clearing !== 'boolean'
    ) {
      fail();
    }
    sortedUniqueStrings(projected.options, 32, (entry) =>
      /^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(entry)
    );
  }
};

export const publishDeviceAuthorizationProjection = (
  value: DeviceAuthorizationProjection
): DeviceAuthorizationProjection => {
  const source = exactRecord(value, topProjectionKeys);
  assertCommonProjectionFields(source);
  assertAuthorizationProjectionFields(source);
  assertDeviceAuthorizationEvidenceIsSanitized(source);
  return value;
};

export const publishDeviceLifecycleProjection = (
  value: DeviceLifecycleProjection
): DeviceLifecycleProjection => {
  const source = exactRecord(value, lifecycleProjectionKeys);
  if (!lifecycleKinds.has(own(source, 'kind') as DeviceLifecycleKind)) {
    fail();
  }
  assertCommonProjectionFields(source);
  assertLifecycleFacts(own(source, 'kind') as DeviceLifecycleKind, own(source, 'facts'));
  assertDeviceAuthorizationEvidenceIsSanitized(source);
  return value;
};

const snapshotPublicJwks = (value: unknown, targetLabel: TargetConfig['label']): JSONWebKeySet => {
  const source = exactRecord(value, new Set(['keys']));
  const keys = snapshotDenseArray(own(source, 'keys'), 16);
  if (keys.length === 0) {
    return fail();
  }
  const snapshot = keys.map((entry) => {
    const raw = record(entry);
    if (Object.keys(raw).some((name) => privateJwkMembers.has(name.toLowerCase()))) {
      return fail();
    }
    const validateCommon = (key: Record<string, unknown>): readonly string[] | undefined => {
      if (
        key.use !== 'sig' ||
        typeof key.kid !== 'string' ||
        !/^[A-Za-z0-9._~-]{1,256}$/u.test(key.kid)
      ) {
        return fail();
      }
      if (key.key_ops === undefined) {
        return undefined;
      }
      const operations = sortedUniqueStrings(key.key_ops, 4, (operation) => operation === 'verify');
      return operations.length === 1 ? operations : fail();
    };
    if (raw.kty === 'EC') {
      const key = exactRecordWithOptional(
        raw,
        new Set(['kty', 'crv', 'x', 'y', 'alg', 'use', 'kid']),
        new Set(['key_ops'])
      );
      if (
        key.crv !== 'P-384' ||
        key.alg !== 'ES384' ||
        typeof key.x !== 'string' ||
        typeof key.y !== 'string' ||
        !/^[A-Za-z0-9_-]{64}$/u.test(key.x) ||
        !/^[A-Za-z0-9_-]{64}$/u.test(key.y)
      ) {
        return fail();
      }
      const keyOperations = validateCommon(key);
      return Object.freeze({
        kty: key.kty,
        crv: key.crv,
        x: key.x,
        y: key.y,
        alg: key.alg,
        use: key.use,
        kid: key.kid,
        ...(keyOperations === undefined ? {} : { key_ops: keyOperations }),
      });
    }
    if (targetLabel !== 'oracle' || raw.kty !== 'RSA') {
      return fail();
    }
    const key = exactRecordWithOptional(
      raw,
      new Set(['kty', 'n', 'e', 'alg', 'use', 'kid']),
      new Set(['key_ops'])
    );
    if (
      key.alg !== 'RS256' ||
      typeof key.n !== 'string' ||
      typeof key.e !== 'string' ||
      !/^[A-Za-z0-9_-]{256,1024}$/u.test(key.n) ||
      !/^[A-Za-z0-9_-]{2,8}$/u.test(key.e)
    ) {
      return fail();
    }
    const keyOperations = validateCommon(key);
    return Object.freeze({
      kty: key.kty,
      n: key.n,
      e: key.e,
      alg: key.alg,
      use: key.use,
      kid: key.kid,
      ...(keyOperations === undefined ? {} : { key_ops: keyOperations }),
    });
  });
  return Object.freeze({ keys: Object.freeze(snapshot) }) as unknown as JSONWebKeySet;
};

const boundedSecret = (value: unknown): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= 16 * 1024 &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

const exactStrings = (value: unknown): readonly string[] => {
  const snapshot = snapshotDenseArray(value, 64);
  if (
    snapshot.some((item) => typeof item !== 'string' || item.length === 0 || item.length > 1024)
  ) {
    return fail();
  }
  const entries = snapshot as string[];
  if (new Set(entries).size !== entries.length) {
    return fail();
  }
  return Object.freeze([...entries].sort());
};

const audiences = (value: JWTPayload['aud']): readonly string[] =>
  exactStrings(typeof value === 'string' ? [value] : value);

const claimStringArray = (value: unknown): readonly string[] => {
  const values = exactStrings(value);
  if (values.length > 128) {
    return fail();
  }
  for (const entry of values) {
    boundedSecret(entry);
  }
  return values;
};

const claimType = (name: string, value: unknown): DeviceJwtClaimType => {
  if (value === null) {
    return nullableProfileClaimNames.has(name) ? 'null' : fail();
  }
  if (name === 'address') {
    const address = record(value);
    if (
      Object.keys(address).length > addressClaimNames.size ||
      Object.keys(address).some((key) => !addressClaimNames.has(key)) ||
      Object.values(address).some(
        (entry) => typeof entry !== 'string' || boundedSecret(entry) !== entry
      )
    ) {
      return fail();
    }
    return 'address';
  }
  if (name === 'aud') {
    if (typeof value === 'string') {
      boundedSecret(value);
      return 'string';
    }
    claimStringArray(value);
    return 'string-array';
  }
  if (stringArrayClaimNames.has(name)) {
    claimStringArray(value);
    return 'string-array';
  }
  if (numericClaimNames.has(name)) {
    if (!Number.isSafeInteger(value)) {
      return fail();
    }
    return 'number';
  }
  if (booleanClaimNames.has(name)) {
    if (typeof value !== 'boolean') {
      return fail();
    }
    return 'boolean';
  }
  boundedSecret(value);
  return 'string';
};

const verifyJwt = async (
  compact: string,
  jwks: ReturnType<typeof createLocalJWKSet>,
  issuer: string,
  expected: DeviceCredentialProjectionInput['expected'],
  audience: string,
  accessSemantics: boolean,
  targetLabel: TargetConfig['label']
): Promise<DeviceVerifiedJwtProjection> => {
  const observedAtSeconds = Math.floor(Date.now() / 1000);
  let verified: Awaited<ReturnType<typeof jwtVerify>>;
  try {
    verified = await jwtVerify(compact, jwks, {
      issuer,
      audience,
      algorithms: targetLabel === 'candidate' ? ['ES384'] : ['RS256', 'ES384'],
    });
  } catch {
    return fail();
  }
  const { protectedHeader, payload } = verified;
  const header = accessSemantics
    ? exactRecord(protectedHeader, new Set(['alg', 'kid', 'typ']))
    : exactRecordWithOptional(protectedHeader, new Set(['alg', 'kid']), new Set(['typ']));
  const claimKeys = Object.keys(payload).sort((left, right) => left.localeCompare(right));
  const allowedClaimNames = accessSemantics ? accessClaimNames : idTokenClaimNames;
  if (claimKeys.some((name) => !allowedClaimNames.has(name))) {
    return fail();
  }
  const claimTypes = Object.freeze(
    Object.fromEntries(claimKeys.map((name) => [name, claimType(name, payload[name])]))
  ) as Readonly<Record<string, DeviceJwtClaimType>>;
  if (
    !(
      (targetLabel === 'candidate' && header.alg === 'ES384') ||
      (targetLabel === 'oracle' && ['RS256', 'ES384'].includes(String(header.alg)))
    ) ||
    typeof header.kid !== 'string' ||
    !/^[A-Za-z0-9._~-]{1,256}$/u.test(header.kid) ||
    (accessSemantics
      ? header.typ !== 'at+jwt'
      : header.typ !== undefined && header.typ !== 'JWT') ||
    payload.iss !== issuer ||
    payload.sub !== expected.subjectId ||
    !Number.isSafeInteger(payload.iat) ||
    !Number.isSafeInteger(payload.exp) ||
    Number(payload.iat) < observedAtSeconds - 60 ||
    Number(payload.iat) > observedAtSeconds + 1 ||
    Number(payload.exp) <= observedAtSeconds ||
    Number(payload.exp) <= Number(payload.iat) ||
    Number(payload.exp) - Number(payload.iat) > 86_400
  ) {
    return fail();
  }
  const tokenAudiences = audiences(payload.aud);
  const clientId = payload.client_id;
  if (
    (accessSemantics && clientId !== expected.clientId) ||
    (!accessSemantics && clientId !== undefined && clientId !== expected.clientId)
  ) {
    return fail();
  }
  const rawScopes = payload.scope;
  const scopes =
    rawScopes === undefined
      ? undefined
      : typeof rawScopes === 'string'
        ? exactStrings(rawScopes.split(' '))
        : fail();
  if (
    accessSemantics &&
    expected.scopes !== undefined &&
    !isDeepStrictEqual(scopes, exactStrings(expected.scopes))
  ) {
    return fail();
  }
  const { resource } = payload;
  const organizationId = payload.organization_id;
  const jwtId = payload.jti;
  if (jwtId !== undefined && (typeof jwtId !== 'string' || !opaqueJwtIdPattern.test(jwtId))) {
    return fail();
  }
  const organizationsValue = payload.organizations;
  const organizations =
    organizationsValue === undefined ? undefined : claimStringArray(organizationsValue);
  if (
    organizations !== undefined &&
    expected.organizationId !== undefined &&
    !organizations.includes(expected.organizationId)
  ) {
    return fail();
  }
  if (!accessSemantics && expected.organizationId !== undefined && organizations === undefined) {
    return fail();
  }
  if (
    (accessSemantics && expected.resource !== undefined && resource !== expected.resource) ||
    (accessSemantics &&
      expected.organizationId !== undefined &&
      organizationId !== expected.organizationId) ||
    (resource !== undefined && typeof resource !== 'string') ||
    (organizationId !== undefined && typeof organizationId !== 'string')
  ) {
    return fail();
  }
  const projection = Object.freeze({
    format: 'verified-jwt' as const,
    header: Object.freeze({
      algorithm: '<verified-signing-algorithm>' as const,
      keyId: '<verified-key>' as const,
      ...(header.typ === undefined ? {} : { type: header.typ as 'at+jwt' | 'JWT' }),
    }),
    claims: Object.freeze({
      claimKeys: Object.freeze(claimKeys),
      claimTypes,
      issuer: '<target-issuer>' as const,
      audience: tokenAudiences,
      subject: '<subject>' as const,
      ...(clientId === undefined ? {} : { clientId: '<client>' as const }),
      ...(scopes === undefined ? {} : { scopes }),
      ...(resource === undefined ? {} : { resource }),
      ...(organizationId === undefined ? {} : { organizationId }),
      ...(jwtId === undefined ? {} : { jwtId: '<opaque-id>' as const }),
      ...(organizations === undefined
        ? {}
        : {
            organizations: Object.freeze({
              count: organizations.length,
              ...(expected.organizationId === undefined
                ? {}
                : { expectedOrganizationMember: true as const }),
            }),
          }),
      issuedAt: '<issued-at>' as const,
      lifetimeSeconds: Number(payload.exp) - Number(payload.iat),
    }),
    signature: Object.freeze({ verified: true as const }),
  });
  assertDeviceAuthorizationEvidenceIsSanitized(projection);
  return projection;
};

export const projectDeviceCredentials = async (
  input: DeviceCredentialProjectionInput
): Promise<DeviceCredentialProjection> => {
  const source = exactRecordWithOptional(
    input,
    new Set(['target', 'jwks', 'accessToken', 'expected']),
    new Set(['refreshToken', 'idToken', 'previousRefreshToken'])
  );
  const target = exactRecord(own(source, 'target'), new Set(['label', 'coreUrl', 'adminUrl']));
  if (
    !['oracle', 'candidate'].includes(String(target.label)) ||
    typeof target.coreUrl !== 'string' ||
    typeof target.adminUrl !== 'string'
  ) {
    return fail();
  }
  const expectedSource = exactRecordWithOptional(
    own(source, 'expected'),
    new Set(['clientId', 'subjectId', 'audience']),
    new Set(['scopes', 'resource', 'organizationId'])
  );
  const expected = Object.freeze({
    clientId: boundedSecret(expectedSource.clientId),
    subjectId: boundedSecret(expectedSource.subjectId),
    audience: boundedSecret(expectedSource.audience),
    ...(expectedSource.scopes === undefined ? {} : { scopes: exactStrings(expectedSource.scopes) }),
    ...(expectedSource.resource === undefined
      ? {}
      : { resource: boundedSecret(expectedSource.resource) }),
    ...(expectedSource.organizationId === undefined
      ? {}
      : { organizationId: boundedSecret(expectedSource.organizationId) }),
  });
  const issuer = new URL('/oidc', target.coreUrl).href.replace(/\/$/u, '');
  const accessToken = boundedSecret(own(source, 'accessToken'));
  const refreshValue = own(source, 'refreshToken');
  const refreshToken = refreshValue === undefined ? undefined : boundedSecret(refreshValue);
  const idTokenValue = own(source, 'idToken');
  const idToken = idTokenValue === undefined ? undefined : boundedSecret(idTokenValue);
  const previousValue = own(source, 'previousRefreshToken');
  const previousRefreshToken =
    previousValue === undefined ? undefined : boundedSecret(previousValue);
  if (refreshToken === undefined && previousRefreshToken !== undefined) {
    return fail();
  }
  if (refreshToken !== undefined && containsCompactJwt(refreshToken)) {
    return fail();
  }
  const targetLabel = target.label as TargetConfig['label'];
  const localJwks = createLocalJWKSet(snapshotPublicJwks(own(source, 'jwks'), targetLabel));
  const access =
    expected.resource === undefined
      ? containsCompactJwt(accessToken)
        ? fail()
        : Object.freeze({ format: 'opaque' as const, present: true as const })
      : await verifyJwt(
          accessToken,
          localJwks,
          issuer,
          expected,
          expected.audience,
          true,
          targetLabel
        );
  const id =
    idToken === undefined
      ? undefined
      : await verifyJwt(
          idToken,
          localJwks,
          issuer,
          expected,
          expected.clientId,
          false,
          targetLabel
        );
  const projection = Object.freeze({
    access,
    id,
    refresh:
      refreshToken === undefined
        ? undefined
        : Object.freeze({
            format: 'opaque' as const,
            present: true as const,
            rotated:
              previousRefreshToken === undefined
                ? undefined
                : previousRefreshToken !== refreshToken,
          }),
  });
  assertDeviceAuthorizationEvidenceIsSanitized(projection);
  return projection;
};

const assertVerifiedJwtProjection = (value: unknown, accessSemantics: boolean): void => {
  const source = exactRecord(value, new Set(['format', 'header', 'claims', 'signature']));
  if (source.format !== 'verified-jwt') {
    fail();
  }
  const header = exactRecordWithOptional(
    source.header,
    new Set(['algorithm', 'keyId']),
    new Set(['type'])
  );
  if (
    header.algorithm !== '<verified-signing-algorithm>' ||
    header.keyId !== '<verified-key>' ||
    (accessSemantics
      ? header.type !== 'at+jwt'
      : header.type !== undefined && header.type !== 'JWT')
  ) {
    fail();
  }
  const claims = exactRecordWithOptional(
    source.claims,
    new Set([
      'claimKeys',
      'claimTypes',
      'issuer',
      'audience',
      'subject',
      'issuedAt',
      'lifetimeSeconds',
    ]),
    new Set(['clientId', 'scopes', 'resource', 'organizationId', 'jwtId', 'organizations'])
  );
  if (
    claims.issuer !== '<target-issuer>' ||
    claims.subject !== '<subject>' ||
    claims.issuedAt !== '<issued-at>' ||
    !Number.isSafeInteger(claims.lifetimeSeconds) ||
    Number(claims.lifetimeSeconds) <= 0 ||
    (claims.clientId !== undefined && claims.clientId !== '<client>') ||
    (claims.resource !== undefined && typeof claims.resource !== 'string') ||
    (claims.organizationId !== undefined && typeof claims.organizationId !== 'string') ||
    (claims.jwtId !== undefined && claims.jwtId !== '<opaque-id>')
  ) {
    fail();
  }
  assertStringArray(claims.claimKeys);
  const claimKeys = claims.claimKeys as string[];
  if (
    !isDeepStrictEqual(
      claimKeys,
      [...claimKeys].sort((left, right) => left.localeCompare(right))
    ) ||
    new Set(claimKeys).size !== claimKeys.length ||
    claimKeys.some((name) => !(accessSemantics ? accessClaimNames : idTokenClaimNames).has(name)) ||
    (accessSemantics
      ? ['iss', 'aud', 'sub', 'client_id', 'resource', 'iat', 'exp'].some(
          (name) => !claimKeys.includes(name)
        )
      : ['iss', 'aud', 'sub', 'iat', 'exp'].some((name) => !claimKeys.includes(name)))
  ) {
    fail();
  }
  const projectedTypes = exactRecord(claims.claimTypes, new Set(claimKeys));
  for (const [name, type] of Object.entries(projectedTypes)) {
    const expectedTypes: readonly DeviceJwtClaimType[] =
      name === 'aud'
        ? ['string', 'string-array']
        : name === 'address'
          ? ['address']
          : stringArrayClaimNames.has(name)
            ? ['string-array']
            : numericClaimNames.has(name)
              ? ['number']
              : booleanClaimNames.has(name)
                ? ['boolean']
                : nullableProfileClaimNames.has(name)
                  ? ['string', 'null']
                  : ['string'];
    if (!expectedTypes.includes(type as DeviceJwtClaimType)) {
      fail();
    }
  }
  if (
    Object.hasOwn(claims, 'clientId') !== claimKeys.includes('client_id') ||
    Object.hasOwn(claims, 'scopes') !== claimKeys.includes('scope') ||
    Object.hasOwn(claims, 'resource') !== claimKeys.includes('resource') ||
    Object.hasOwn(claims, 'organizationId') !== claimKeys.includes('organization_id') ||
    Object.hasOwn(claims, 'jwtId') !== claimKeys.includes('jti') ||
    Object.hasOwn(claims, 'organizations') !== claimKeys.includes('organizations')
  ) {
    fail();
  }
  assertStringArray(claims.audience);
  if (claims.scopes !== undefined) {
    assertStringArray(claims.scopes);
  }
  if (claims.organizations !== undefined) {
    const organizations = exactRecordWithOptional(
      claims.organizations,
      new Set(['count']),
      new Set(['expectedOrganizationMember'])
    );
    if (
      !Number.isSafeInteger(organizations.count) ||
      Number(organizations.count) < 0 ||
      (organizations.expectedOrganizationMember !== undefined &&
        organizations.expectedOrganizationMember !== true)
    ) {
      fail();
    }
  }
  const signature = exactRecord(source.signature, new Set(['verified']));
  if (signature.verified !== true) {
    fail();
  }
};

const assertCredentialProjection = (value: unknown): void => {
  const source = exactRecord(value, new Set(['access', 'id', 'refresh']));
  const access = record(source.access);
  if (access.format === 'opaque') {
    const opaque = exactRecord(access, new Set(['format', 'present']));
    if (opaque.present !== true) {
      fail();
    }
  } else {
    assertVerifiedJwtProjection(access, true);
  }
  if (source.id !== undefined) {
    assertVerifiedJwtProjection(source.id, false);
  }
  if (source.refresh !== undefined) {
    const refresh = exactRecord(source.refresh, new Set(['format', 'present', 'rotated']));
    if (
      refresh.format !== 'opaque' ||
      refresh.present !== true ||
      (refresh.rotated !== undefined && typeof refresh.rotated !== 'boolean')
    ) {
      fail();
    }
  }
  assertDeviceAuthorizationEvidenceIsSanitized(source);
};

const assertProjection = (value: unknown): void => {
  const source = record(value);
  if (Object.hasOwn(source, 'kind')) {
    publishDeviceLifecycleProjection(value as DeviceLifecycleProjection);
  } else if (Object.hasOwn(source, 'keys')) {
    publishDeviceAuthorizationProjection(value as DeviceAuthorizationProjection);
  } else {
    assertCredentialProjection(value);
  }
};

const collectDifferences = (
  left: unknown,
  right: unknown,
  path: string,
  differences: string[]
): void => {
  if (isDeepStrictEqual(left, right)) {
    return;
  }
  if (
    typeof left !== 'object' ||
    left === null ||
    typeof right !== 'object' ||
    right === null ||
    Array.isArray(left) !== Array.isArray(right)
  ) {
    differences.push(path || '/');
    return;
  }
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  const keys = [...new Set([...leftKeys, ...rightKeys])].sort();
  for (const key of keys) {
    if (!leftKeys.includes(key) || !rightKeys.includes(key)) {
      differences.push(`${path}/${key}`);
    } else {
      collectDifferences(
        (left as Record<string, unknown>)[key],
        (right as Record<string, unknown>)[key],
        `${path}/${key}`,
        differences
      );
    }
  }
};

export const compareDeviceAuthorizationProjections = (
  oracle: DeviceAuthorizationProjection | DeviceLifecycleProjection | DeviceCredentialProjection,
  candidate: DeviceAuthorizationProjection | DeviceLifecycleProjection | DeviceCredentialProjection
): readonly string[] => {
  assertProjection(oracle);
  assertProjection(candidate);
  const differences: string[] = [];
  collectDifferences(oracle, candidate, '', differences);
  return Object.freeze([...new Set(differences)].sort());
};

/* eslint-enable complexity, max-lines, max-params, no-control-regex, no-restricted-syntax, @typescript-eslint/ban-types, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
