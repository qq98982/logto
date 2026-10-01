/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, no-restricted-syntax, prefer-destructuring, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types -- This exact-byte file identity, schema, closed registries, and deep-freeze boundary are intentionally cohesive and never handle unpinned JSON. */
import { createHash, timingSafeEqual } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import { Ajv2020, type AnySchema } from 'ajv/dist/2020.js';

const maximumInputBytes = 1024 * 1024;
const expectedProfileSha256 = '99172f76481c6af8d929fc00aa84360162b1f5d2d385437b8f0ae432191d8ccd';
const expectedSchemaSha256 = 'a5706d026940dee59fd2566601f7e5d04472c507ccbdfa862b1acb41ec6d1c8c';
export const phase2ExpectedBaseAcceptance = Object.freeze({
  recordCommit: 'f6dcacc04226511d36547b08aaee600208c39c6d',
  recordPath: 'compatibility/phase-1-acceptance/phase-1-accepted.md',
  recordSha256: 'e31b5f6635cdcddcca319a6020dcba6325ab4ac86840aff09965f296f6b7a386',
  runtimeSourceCommit: '2132b4d9f537c618013c5c76542fbf8e325c19d9',
  harnessCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
  profileSha256: '5212b72090d1c9ab1956c07da652629af1312a9784f8a513028e5e297801fcf7',
});

export type Phase2BaseAcceptance = typeof phase2ExpectedBaseAcceptance;
export const phase2ExpectedProfileAuthority = Object.freeze({
  profileSha256: expectedProfileSha256,
  schemaSha256: expectedSchemaSha256,
  baseAcceptance: phase2ExpectedBaseAcceptance,
});

const differentialScenarioIds = [
  'client-credentials.basic-explicit-resource',
  'client-credentials.post-explicit-resource',
  'client-credentials.default-resource',
  'client-credentials.resource-no-scope',
  'client-credentials.resource-partial-scope',
  'client-credentials.organization-empty-scope',
  'client-credentials.organization-scope',
  'client-credentials.organization-resource-scope',
  'client-credentials.unknown-client-basic',
  'client-credentials.unknown-client-post',
  'client-credentials.wrong-secret-basic',
  'client-credentials.wrong-secret-post',
  'client-credentials.mixed-authentication',
  'client-credentials.missing-target',
  'client-credentials.unknown-resource',
  'client-credentials.unassociated-organization',
  'client-credentials.duplicate-resource',
  'client-credentials.duplicate-scope-name',
  'client-credentials.malformed-scope-whitespace',
  'client-credentials.unsupported-parameter',
  'token-status.public-access-active',
  'token-status.public-refresh-active',
  'token-status.access-wrong-hint-active',
  'token-status.refresh-no-hint-active',
  'token-status.resource-jwt-introspection-rejected',
  'token-status.resource-jwt-revocation-rejected',
  'token-status.consumed-refresh-active',
  'token-status.rotated-refresh-active',
  'token-status.consumed-refresh-revoked',
  'token-status.rotated-refresh-inactive',
  'token-status.original-access-inactive',
  'token-status.unknown-token-inactive',
  'token-status.no-auth-rejected',
  'token-status.owner-access-revoked',
  'token-status.owner-access-inactive',
  'token-status.owner-refresh-inactive',
  'token-status.missing-token-rejected',
  'token-status.duplicate-token-rejected',
  'token-status.dotted-unknown-inactive',
  'token-status.unknown-extension-inactive',
  'token-status.no-auth-precedes-missing-token',
  'token-status.confidential-basic-access-active',
  'token-status.confidential-post-access-active',
  'token-status.confidential-wrong-secret-rejected',
  'token-status.confidential-public-cross-client-inactive',
  'token-status.confidential-public-cross-client-revoked',
  'token-status.confidential-owner-after-cross-client-active',
  'logout.anonymous-get',
  'logout.anonymous-post',
  'logout.anonymous-confirmed',
  'logout.duplicate-client',
  'logout.unknown-client',
  'logout.unauthoritative-redirect',
  'logout.unregistered-redirect',
  'logout.success-page',
  'account-sessions.missing-verification',
  'account-sessions.wrong-password',
  'logout.authenticated-get',
  'logout.authenticated-confirmed',
  'logout.offline-refresh-active',
  'logout.authenticated-declined',
  'logout.offline-refresh-active-after-decline',
  'logout.confirm-missing-session',
  'logout.confirm-xsrf-mismatch',
  'logout.confirm-replay',
  'logout.confirm-cross-cookie',
  'account-sessions.password-verification',
  'account-sessions.list-current',
  'account-sessions.delete-current',
  'account-sessions.list-zero-current',
  'device-authorization.urlencoded-success',
  'device-authorization.json-object-success',
  'device-authorization.missing-client',
  'device-authorization.unknown-client',
  'device-authorization.ineligible-web-client',
  'device-authorization.confidential-client',
  'device-authorization.public-client-basic-rejected',
  'device-authorization.public-client-secret-post-rejected',
  'device-authorization.missing-device-grant',
  'device-authorization.explicit-resource',
  'device-authorization.unknown-resource',
  'device-authorization.organization',
  'device-authorization.unassociated-organization',
  'device-authorization.absent-scope',
  'device-authorization.empty-scope',
  'device-authorization.unknown-scope',
  'device-authorization.duplicate-client',
  'device-authorization.duplicate-resource',
  'device-authorization.duplicate-scope',
  'device-authorization.malformed-form',
  'device-authorization.malformed-json',
  'device-authorization.unsupported-parameter',
  'device-authorization.unknown-extension',
  'device-authorization.ui-locales',
  'device-authorization.json-array-rejected',
  'device-authorization.text-body-rejected',
  'device-authorization.query-only-rejected',
  'device-verification.shortcut-redirect',
  'device-verification.manual-entry',
  'device-verification.complete-url-entry',
  'device-verification.missing-code',
  'device-verification.malformed-code',
  'device-verification.unknown-code',
  'device-verification.expired-code',
  'device-verification.already-used-code',
  'device-verification.invalid-xsrf',
  'device-verification.cross-cookie-xsrf',
  'device-verification.abort',
  'device-verification.confirmation',
  'device-verification.confirmed-sign-in-redirect',
  'device-token.pending-poll',
  'device-token.in-flight-poll',
  'device-consent.first-party-matching-grant-required',
  'device-consent.third-party-redirect-absent',
  'device-token.denied-poll',
  'device-consent.approval',
  'device-verification.success-page',
  'device-verification.completed-cookie-cleanup',
  'device-token.openid-issuance',
  'device-token.id-token-signature-and-claims',
  'device-token.userinfo',
  'device-token.offline-refresh-rotation',
  'device-token.offline-refresh-after-logout',
  'device-token.resource-authority',
  'device-token.organization-authority',
  'device-token.refresh-resource-selection',
  'device-token.refresh-organization-selection',
  'device-token.session-bound-expiry',
  'device-token.client-mismatch',
  'device-token.unknown-code',
  'device-token.expired-code',
  'device-token.consumed-replay',
  'device-token.concurrent-reference-multi-winner',
  'device-token-status.access-introspection',
  'device-token-status.access-revocation',
  'device-token-status.refresh-introspection',
  'device-token-status.refresh-revocation',
  'device-discovery.oidc',
  'device-discovery.oauth',
  'custom-jwt.management-missing-get',
  'custom-jwt.management-missing-delete',
  'custom-jwt.management-put',
  'custom-jwt.management-get',
  'custom-jwt.management-list',
  'custom-jwt.management-patch',
  'custom-jwt.management-patch-missing-script',
  'custom-jwt.management-patch-nonstring-script',
  'custom-jwt.management-test',
  'custom-jwt.management-unknown-token-type',
  'custom-jwt.management-delete',
  'custom-jwt.m2m-success',
  'custom-jwt.m2m-deny',
  'custom-jwt.m2m-throw-block',
  'custom-jwt.m2m-throw-open',
  'custom-jwt.m2m-protected-claims',
  'custom-jwt.user-initial-resource',
  'custom-jwt.user-refresh-context',
  'custom-jwt.user-old-refresh-after-rotation',
  'custom-jwt.user-refresh-deny',
  'custom-jwt.user-refresh-throw-block',
  'custom-jwt.user-refresh-throw-open-retry',
  'custom-jwt.device-resource-refresh-context',
  'custom-jwt.fetch-get-text',
  'custom-jwt.fetch-get-json',
  'custom-jwt.fetch-post',
  'custom-jwt.fetch-not-found',
  'custom-jwt.fetch-redirect',
  'custom-jwt.fetch-reset-connection',
] as const;
const deviceOperationIds = [
  'device.authorize',
  'device.open-shortcut',
  'device.open-verification',
  'device.submit-verification',
  'device.submit-password',
  'device.read-consent',
  'device.submit-consent',
  'device.resume-consent',
  'device.open-success',
  'device.poll-token',
  'device.rotate-refresh',
  'device.introspect-token',
  'device.revoke-token',
  'device.request-userinfo',
  'device.open-logout',
  'device.confirm-logout',
  'device.discover-oidc',
  'device.discover-oauth',
] as const;
const candidateInvariantIds = [
  'client-credentials.cross-tenant-authority-rejected',
  'client-credentials.request-role-write-rejected',
  'client-credentials.signing-failure-rolls-back',
  'client-credentials.user-authority-unchanged',
  'logout-session.verification-storage-closed',
  'device-authorization.forced-rls-isolation',
  'device-authorization.credentials-digest-only',
  'device-authorization.cross-tenant-lookup-rejected',
  'device-authorization.transition-failure-rolls-back',
  'device-token.concurrent-poll-one-winner',
  'device-token.consumed-replay-revokes-grant',
  'device-authorization.expired-cleanup-bounded',
  'device-evidence.secret-material-absent',
  'custom-jwt.storage-confidential-forced-rls',
  'custom-jwt.blocking-refresh-rolls-back',
  'custom-jwt.fetch-policy-boundary',
] as const;
const stillAbsentDiscoveryFields = ['registration_endpoint'] as const;
const endpointFieldsAppend = [
  'introspection_endpoint',
  'revocation_endpoint',
  'end_session_endpoint',
  'device_authorization_endpoint',
] as const;
const scopesSupportedAppend = ['urn:aster:scope:sessions'] as const;

export type Phase2DifferentialScenarioId = (typeof differentialScenarioIds)[number];
export type Phase2DeviceOperationId = (typeof deviceOperationIds)[number];
export type Phase2CandidateInvariantId = (typeof candidateInvariantIds)[number];
export type Phase2StillAbsentDiscoveryField = (typeof stillAbsentDiscoveryFields)[number];

export type Phase2ProfilePaths = Readonly<{
  profilePath: string;
  schemaPath: string;
}>;

export type Phase2ProfileRegistries = Readonly<{
  profileSha256: string;
  schemaSha256: string;
  baseAcceptance: Phase2BaseAcceptance;
  deviceOperations: readonly Phase2DeviceOperationId[];
  differentialScenarios: readonly Phase2DifferentialScenarioId[];
  candidateInvariantScenarios: readonly Phase2CandidateInvariantId[];
  discovery: Readonly<{
    grantTypesSupportedAppend: readonly [
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ];
    endpointFieldsAppend: typeof endpointFieldsAppend;
    scopesSupportedAppend: typeof scopesSupportedAppend;
    stillAbsent: readonly Phase2StillAbsentDiscoveryField[];
  }>;
}>;

export class Phase2ProfileValidationError extends Error {
  constructor() {
    super('Invalid Phase 2 profile');
    this.name = 'Phase2ProfileValidationError';
    this.stack = this.message;
  }
}

const fail = (): never => {
  throw new Phase2ProfileValidationError();
};

const fixedHashEquals = (actual: string, expected: string): boolean => {
  const actualBytes = Buffer.from(actual, 'hex');
  const expectedBytes = Buffer.from(expected, 'hex');
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
};

const readExactFile = async (filePath: string): Promise<Uint8Array> => {
  if (!path.isAbsolute(filePath) || path.resolve(filePath) !== filePath) {
    return fail();
  }
  const before = await lstat(filePath).catch(fail);
  if (before.isSymbolicLink() || !before.isFile() || before.size > maximumInputBytes) {
    return fail();
  }
  if ((await realpath(filePath).catch(fail)) !== filePath) {
    return fail();
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const openedBefore = await handle.stat();
    if (
      !openedBefore.isFile() ||
      openedBefore.size > maximumInputBytes ||
      openedBefore.dev !== before.dev ||
      openedBefore.ino !== before.ino
    ) {
      return fail();
    }
    const bytes = new Uint8Array(openedBefore.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead <= 0) {
        return fail();
      }
      offset += bytesRead;
    }
    const [openedAfter, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]);
    if (
      openedAfter.dev !== openedBefore.dev ||
      openedAfter.ino !== openedBefore.ino ||
      openedAfter.size !== openedBefore.size ||
      openedAfter.mtimeMs !== openedBefore.mtimeMs ||
      pathAfter.isSymbolicLink() ||
      pathAfter.dev !== openedBefore.dev ||
      pathAfter.ino !== openedBefore.ino ||
      pathAfter.size !== openedBefore.size ||
      pathAfter.mtimeMs !== openedBefore.mtimeMs
    ) {
      return fail();
    }
    return bytes;
  } finally {
    await handle.close();
  }
};

const parseExactJson = (bytes: Uint8Array): unknown => {
  try {
    return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return fail();
  }
};

const deepFreeze = <Value>(value: Value, seen = new WeakSet<object>()): Readonly<Value> => {
  if (typeof value !== 'object' || value === null) {
    return value;
  }
  if (seen.has(value)) {
    return fail();
  }
  seen.add(value);
  for (const child of Object.values(value)) {
    deepFreeze(child, seen);
  }
  return Object.freeze(value);
};

const exactArray = <Value extends readonly string[]>(value: unknown, expected: Value): Value => {
  if (
    !Array.isArray(value) ||
    value.length !== expected.length ||
    value.some((entry, index) => entry !== expected[index])
  ) {
    return fail();
  }
  return value as unknown as Value;
};

export const loadPhase2Profile = async ({
  profilePath,
  schemaPath,
}: Phase2ProfilePaths): Promise<Phase2ProfileRegistries> => {
  if (profilePath === schemaPath) {
    return fail();
  }
  const [profileBytes, schemaBytes] = await Promise.all([
    readExactFile(profilePath),
    readExactFile(schemaPath),
  ]);
  const profileHash = createHash('sha256').update(profileBytes).digest('hex');
  const schemaHash = createHash('sha256').update(schemaBytes).digest('hex');
  if (
    !fixedHashEquals(profileHash, expectedProfileSha256) ||
    !fixedHashEquals(schemaHash, expectedSchemaSha256)
  ) {
    return fail();
  }
  const profile = parseExactJson(profileBytes);
  const schema = parseExactJson(schemaBytes) as AnySchema;
  try {
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    if (!validate(profile)) {
      return fail();
    }
  } catch (error: unknown) {
    if (error instanceof Phase2ProfileValidationError) {
      throw error;
    }
    return fail();
  }
  if (typeof profile !== 'object' || profile === null || Array.isArray(profile)) {
    return fail();
  }
  const document = profile as Record<string, unknown>;
  if (JSON.stringify(document.baseAcceptance) !== JSON.stringify(phase2ExpectedBaseAcceptance)) {
    return fail();
  }
  const discovery = document.discovery;
  if (typeof discovery !== 'object' || discovery === null || Array.isArray(discovery)) {
    return fail();
  }
  const discoveryRecord = discovery as Record<string, unknown>;
  const registries: Phase2ProfileRegistries = {
    profileSha256: profileHash,
    schemaSha256: schemaHash,
    baseAcceptance: phase2ExpectedBaseAcceptance,
    deviceOperations: exactArray(document.deviceOperations, deviceOperationIds),
    differentialScenarios: exactArray(document.differentialScenarios, differentialScenarioIds),
    candidateInvariantScenarios: exactArray(
      document.candidateInvariantScenarios,
      candidateInvariantIds
    ),
    discovery: {
      grantTypesSupportedAppend: exactArray(discoveryRecord.grantTypesSupportedAppend, [
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
      ] as const),
      endpointFieldsAppend: exactArray(discoveryRecord.endpointFieldsAppend, endpointFieldsAppend),
      scopesSupportedAppend: exactArray(
        discoveryRecord.scopesSupportedAppend,
        scopesSupportedAppend
      ),
      stillAbsent: exactArray(discoveryRecord.stillAbsent, stillAbsentDiscoveryFields),
    },
  };
  return deepFreeze(registries) as Phase2ProfileRegistries;
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, no-restricted-syntax, prefer-destructuring, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types */
