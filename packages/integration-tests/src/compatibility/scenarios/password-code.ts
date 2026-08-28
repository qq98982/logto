/* eslint-disable max-lines -- The vertical scenario keeps its normalization and operation order in one reviewable boundary. */
import { demoAppApplicationId, InteractionEvent } from '@logto/schemas';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import { ExperienceClient } from '#src/client/experience/index.js';
import { identifyUserWithUsernamePassword } from '#src/helpers/experience/username-password.js';

import { jsonValueGuard, type Observation } from '../model.js';
import type { JsonObject, JsonValue, NormalizationContext } from '../normalize.js';
import { normalizeJson, normalizeJwt, normalizeSetCookies } from '../normalize.js';
import type { CompatibilityScenario, ScenarioContext } from '../scenario.js';
import { replaceLiteralCandidates, SymbolTable } from '../symbol-table.js';
import type { TargetClient } from '../target-client.js';

const fixture = Object.freeze({
  username: 'aster_phase0_password_user',
  password: 'Aster_phase0_password_42',
});

const userTimestampFields = new Set(['createdAt', 'updatedAt', 'lastSignInAt']);
const providerJwtTimestampFields = new Set(['iat', 'exp', 'auth_time', 'nbf']);
// Core's OIDC scope mapping passes User.createdAt/updatedAt epoch milliseconds through directly.
const userClaimTimestampFields = new Set(['created_at', 'updated_at']);
const ephemeralClaimFields = new Set([
  'nonce',
  'code',
  'state',
  'verification_id',
  'verificationId',
]);
const credentialFieldKeys = new Set([
  'password',
  'passwordhash',
  'passworddigest',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'clientsecret',
  'apikey',
  'secret',
  'cookie',
  'authorization',
]);
const nestedEphemeralFieldKeys = new Set([
  'nonce',
  'code',
  'state',
  'verificationid',
  'authorizationcode',
]);
const managementUserFields = new Set([
  'id',
  'username',
  'primaryEmail',
  'primaryPhone',
  'name',
  'avatar',
  'lastSignInAt',
  'createdAt',
  'updatedAt',
  'applicationId',
  'isSuspended',
  'hasPassword',
  'hasSecurityVerificationMethod',
  'passwordAlgorithm',
]);
const protocolClaimFields = [
  'iss',
  'sub',
  'aud',
  'iat',
  'exp',
  'nbf',
  'auth_time',
  'sid',
  'jti',
  'client_id',
  'scope',
  'acr',
  'amr',
] as const;
const profileClaimFields = [
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
] as const;
const authorizationClaimFields = [
  'roles',
  'organizations',
  'organization_data',
  'organization_roles',
  'organization_id',
  'permissions',
  'custom_data',
  'identities',
  'sso_identities',
] as const;
const jwtClaimFields = new Set([
  ...protocolClaimFields,
  ...profileClaimFields,
  ...authorizationClaimFields,
]);
const userInfoClaimFields = new Set(['sub', ...profileClaimFields, ...authorizationClaimFields]);
const jwtHeaderFields = new Set(['alg', 'kid', 'typ', 'cty']);
const setValuedClaimFields = new Set([
  'aud',
  'amr',
  'roles',
  'organizations',
  'organization_roles',
  'permissions',
  'organization_data',
  'sso_identities',
]);
const minimumSensitiveSubstringLength = 8;
const emptySensitiveValues: ReadonlySet<string> = new Set();
const safeCookieValuePlaceholder = 'aster-redacted';

type ExperienceClientBoundary = Pick<
  ExperienceClient,
  | 'rawCookies'
  | 'initSession'
  | 'initInteraction'
  | 'submitInteraction'
  | 'processSession'
  | 'getIdToken'
  | 'getAccessToken'
  | 'clearAccessToken'
>;

export type PasswordCodeScenarioDependencies = {
  createExperienceClient: (
    config: { endpoint: string; appId: string; persistAccessToken: false },
    api: TargetClient['experience']
  ) => ExperienceClientBoundary;
  identifyUserWithUsernamePassword: (
    client: ExperienceClientBoundary,
    username: string,
    password: string
  ) => Promise<unknown>;
};

const defaultDependencies: PasswordCodeScenarioDependencies = {
  createExperienceClient: (config, api) => new ExperienceClient(config, api),
  // The production helper requires the concrete client; the public dependency remains structural
  // so scenario tests do not need a network-capable SDK client.
  identifyUserWithUsernamePassword: async (client, username, password) =>
    // eslint-disable-next-line no-restricted-syntax
    identifyUserWithUsernamePassword(client as ExperienceClient, username, password),
};

const isJsonValue = (value: unknown): value is JsonValue => jsonValueGuard.safeParse(value).success;

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value) && isJsonValue(value);

const timestampMarker = (milliseconds: number): JsonObject => ({
  $timestamp: Math.floor(milliseconds / 1000),
  $toleranceSeconds: 60,
});

const secondsTimestampMarker = (seconds: number): JsonObject => ({
  $timestamp: seconds,
  $toleranceSeconds: 60,
});

const assertSafeEvidenceField = (propertyName: string, message: string) => {
  const canonicalName = propertyName.replaceAll(/[_-]/g, '').toLowerCase();

  if (credentialFieldKeys.has(canonicalName)) {
    throw new TypeError(message);
  }

  if (nestedEphemeralFieldKeys.has(canonicalName)) {
    throw new TypeError(message);
  }
};

const assertNoKnownSensitiveValue = (
  value: JsonValue,
  knownSensitiveValues: ReadonlySet<string>,
  message: string
): void => {
  if (typeof value === 'string') {
    for (const sensitiveValue of knownSensitiveValues) {
      if (
        value === sensitiveValue ||
        (sensitiveValue.length >= minimumSensitiveSubstringLength && value.includes(sensitiveValue))
      ) {
        throw new TypeError(message);
      }
    }

    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoKnownSensitiveValue(item, knownSensitiveValues, message);
    }

    return;
  }

  if (isJsonObject(value)) {
    for (const [key, nestedValue] of Object.entries(value)) {
      assertNoKnownSensitiveValue(key, knownSensitiveValues, message);
      assertNoKnownSensitiveValue(nestedValue, knownSensitiveValues, message);
    }
  }
};

export const projectUserForObservation = (
  value: unknown,
  knownSensitiveValues: ReadonlySet<string> = emptySensitiveValues
): JsonObject => {
  const parsed = jsonValueGuard.safeParse(value);

  if (!parsed.success || !isJsonObject(value)) {
    throw new TypeError('Invalid management user projection');
  }

  assertSafeEvidenceValue(value, 'Invalid management user projection');
  assertNoKnownSensitiveValue(value, knownSensitiveValues, 'Invalid management user projection');

  const projected = Object.fromEntries(
    Object.entries(value).flatMap(([key, nestedValue]) => {
      if (!managementUserFields.has(key)) {
        return [];
      }

      if (userTimestampFields.has(key)) {
        if (nestedValue === null && key === 'lastSignInAt') {
          return [[key, null]];
        }

        if (typeof nestedValue !== 'number' || !Number.isFinite(nestedValue)) {
          throw new TypeError('Invalid management user projection');
        }

        return [[key, timestampMarker(nestedValue)]];
      }

      return [[key, cloneEvidenceValue(nestedValue, 'Invalid management user projection')]];
    })
  );
  const { profile, customData, identities } = value;

  if (!isJsonObject(profile) || !isJsonObject(customData) || !isJsonObject(identities)) {
    throw new TypeError('Invalid management user projection');
  }

  return {
    ...projected,
    profileIsEmpty: Object.keys(profile).length === 0,
    customDataIsEmpty: Object.keys(customData).length === 0,
    identityTargets: Object.keys(identities).toSorted(),
  };
};

const fixedOperation = async <Result>(message: string, operation: () => Promise<Result>) => {
  try {
    return await operation();
  } catch {
    throw new Error(message);
  }
};

const requireNonemptyString = (value: unknown, message: string): string => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(message);
  }

  return value;
};

const bindJwtIdentifiers = (
  header: JsonObject,
  claims: JsonObject,
  context: NormalizationContext,
  tokenKind: 'id-token' | 'access-token'
) => {
  const { kid } = header;

  if (kid !== undefined) {
    if (typeof kid !== 'string' || kid.length === 0) {
      throw new TypeError('Invalid token observation');
    }

    context.symbols.bindOccurrence(`${tokenKind}.kid`, kid);
  }

  for (const claim of ['sub', 'sid', 'jti'] as const) {
    const identifier = claims[claim];

    if (identifier !== undefined) {
      if (typeof identifier !== 'string') {
        throw new TypeError('Invalid token observation');
      }

      context.symbols.bindOccurrence(`${tokenKind}.${claim}`, identifier);
    }
  }
};

const compareText = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);

const canonicalizeObjectKeys = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeObjectKeys(item));
  }

  if (isJsonObject(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .toSorted(([left], [right]) => compareText(left, right))
        .map(([key, nestedValue]) => [key, canonicalizeObjectKeys(nestedValue)])
    );
  }

  return value;
};

const sortByNormalizedValue = (
  values: readonly JsonValue[],
  context: NormalizationContext
): JsonValue[] =>
  values
    .map((value, index) => ({
      value,
      index,
      key: JSON.stringify(canonicalizeObjectKeys(normalizeJson(value, context, []))),
    }))
    .toSorted((left, right) => compareText(left.key, right.key) || left.index - right.index)
    .map(({ value }) => value);

const canonicalizeClaimValue = (
  key: string,
  value: JsonValue,
  context: NormalizationContext,
  message: string
): JsonValue => {
  if (key === 'scope') {
    if (typeof value !== 'string') {
      throw new TypeError(message);
    }

    return sortByNormalizedValue(
      value.split(/\s+/u).filter((scope) => scope.length > 0),
      context
    ).join(' ');
  }

  if (setValuedClaimFields.has(key) && Array.isArray(value)) {
    return sortByNormalizedValue(value, context).map((item) => cloneEvidenceValue(item, message));
  }

  return cloneEvidenceValue(value, message);
};

type ClaimProjectionOptions = {
  allowedFields: ReadonlySet<string>;
  context: NormalizationContext;
  knownSensitiveValues: ReadonlySet<string>;
  message: string;
};

const projectClaimsForObservation = (
  claims: JsonObject,
  { allowedFields, context, knownSensitiveValues, message }: ClaimProjectionOptions
): JsonObject => {
  const transformed = Object.fromEntries(
    Object.entries(claims).flatMap(([key, value]) => {
      if (ephemeralClaimFields.has(key)) {
        return [];
      }

      assertSafeEvidenceField(key, message);

      if (!allowedFields.has(key)) {
        return [];
      }

      assertSafeEvidenceValue(value, message);
      assertNoKnownSensitiveValue(value, knownSensitiveValues, message);

      if (providerJwtTimestampFields.has(key)) {
        if (typeof value !== 'number' || !Number.isFinite(value)) {
          throw new TypeError(message);
        }

        return [[key, secondsTimestampMarker(value)]];
      }

      if (userClaimTimestampFields.has(key)) {
        if (typeof value !== 'number' || !Number.isFinite(value)) {
          throw new TypeError(message);
        }

        return [[key, timestampMarker(value)]];
      }

      return [[key, canonicalizeClaimValue(key, value, context, message)]];
    })
  );
  const issuedAt = allowedFields === jwtClaimFields ? claims.iat : undefined;
  const expiresAt = allowedFields === jwtClaimFields ? claims.exp : undefined;

  if (typeof issuedAt === 'number' && typeof expiresAt === 'number') {
    if (Object.hasOwn(claims, 'tokenLifetimeSeconds')) {
      throw new TypeError(message);
    }

    return { ...transformed, tokenLifetimeSeconds: expiresAt - issuedAt };
  }

  return transformed;
};

const cloneEvidenceValue = (value: JsonValue, message: string): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => cloneEvidenceValue(item, message));
  }

  if (isJsonObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [
        key,
        cloneEvidenceValue(nestedValue, message),
      ])
    );
  }

  return value;
};

const assertSafeEvidenceValue = (value: JsonValue, message: string): void => {
  if (Array.isArray(value)) {
    for (const item of value) {
      assertSafeEvidenceValue(item, message);
    }

    return;
  }

  if (!isJsonObject(value)) {
    return;
  }

  for (const [key, nestedValue] of Object.entries(value)) {
    assertSafeEvidenceField(key, message);
    assertSafeEvidenceValue(nestedValue, message);
  }
};

type SensitiveValueTracker = {
  values: Set<string>;
  observedValues: JsonValue[];
};

const registerSensitiveValue = (
  tracker: SensitiveValueTracker,
  value: unknown,
  message: string
) => {
  if (typeof value !== 'string') {
    return;
  }

  if (value.length === 0) {
    return;
  }

  tracker.values.add(value);

  for (const observedValue of tracker.observedValues) {
    assertNoKnownSensitiveValue(observedValue, tracker.values, message);
  }
};

const collectExtractedSensitiveValues = (
  value: JsonValue,
  tracker: SensitiveValueTracker,
  message: string
): void => {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectExtractedSensitiveValues(item, tracker, message);
    }

    return;
  }

  if (!isJsonObject(value)) {
    return;
  }

  for (const [key, nestedValue] of Object.entries(value)) {
    const canonicalName = key.replaceAll(/[_-]/g, '').toLowerCase();

    if (nestedEphemeralFieldKeys.has(canonicalName) && typeof nestedValue === 'string') {
      registerSensitiveValue(tracker, nestedValue, message);
    }

    collectExtractedSensitiveValues(nestedValue, tracker, message);
  }
};

const registerCookieValues = (
  headers: readonly string[],
  tracker: SensitiveValueTracker,
  message: string
) => {
  for (const header of headers) {
    const cookiePair = header.split(';', 1)[0];
    const separator = cookiePair?.indexOf('=') ?? -1;

    if (cookiePair === undefined || separator < 1) {
      throw new TypeError(message);
    }

    const rawValue = cookiePair.slice(separator + 1);
    const unquotedValue =
      rawValue.startsWith('"') && rawValue.endsWith('"') ? rawValue.slice(1, -1) : rawValue;
    registerSensitiveValue(tracker, rawValue, message);
    registerSensitiveValue(tracker, unquotedValue, message);
  }
};

type ParsedCookieForRedaction = {
  name: string;
  attributes: string;
  candidates: string[];
};

const redactSetCookieValues = (headers: readonly string[]): string[] => {
  const parsedHeaders = headers.map((header): ParsedCookieForRedaction => {
    const hasAsciiControl = Array.from(header).some((character) => {
      const codePoint = character.codePointAt(0);

      return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
    });

    if (hasAsciiControl) {
      throw new TypeError('Cookie normalization failed');
    }

    const attributeSeparator = header.indexOf(';');
    const cookiePair = attributeSeparator < 0 ? header : header.slice(0, attributeSeparator);
    const pairSeparator = cookiePair.indexOf('=');
    const name = pairSeparator < 0 ? '' : cookiePair.slice(0, pairSeparator);

    if (pairSeparator <= 0 || name.length === 0) {
      throw new TypeError('Cookie normalization failed');
    }

    const rawValue = cookiePair.slice(pairSeparator + 1);
    const unquotedValue =
      rawValue.startsWith('"') && rawValue.endsWith('"') ? rawValue.slice(1, -1) : rawValue;
    const attributes = attributeSeparator < 0 ? '' : header.slice(attributeSeparator);
    const candidates = [...new Set([rawValue, unquotedValue])]
      .filter((candidate) => candidate.length > 0)
      .toSorted((left, right) => right.length - left.length);

    return { name, attributes, candidates };
  });
  const candidates = parsedHeaders
    .flatMap(({ candidates: values }) => values)
    .filter((candidate, index, values) => values.indexOf(candidate) === index)
    .toSorted((left, right) => right.length - left.length);

  for (const candidate of candidates) {
    if (
      safeCookieValuePlaceholder === candidate ||
      (candidate.length >= minimumSensitiveSubstringLength &&
        safeCookieValuePlaceholder.includes(candidate))
    ) {
      throw new TypeError('Cookie normalization failed');
    }
  }

  const shortCandidates = candidates.filter(
    (candidate) => candidate.length < minimumSensitiveSubstringLength
  );

  const replacements = candidates
    .filter((candidate) => candidate.length >= minimumSensitiveSubstringLength)
    .map((source) => ({ source, replacement: safeCookieValuePlaceholder }));

  return parsedHeaders.map(({ name, attributes }) => {
    const redactedAttributes = attributes
      .split(';')
      .map((segment) => {
        const separator = segment.indexOf('=');

        if (separator < 0) {
          return segment;
        }

        const prefix = segment.slice(0, separator + 1);
        const value = segment.slice(separator + 1);

        if (shortCandidates.some((candidate) => value.includes(candidate))) {
          throw new TypeError('Cookie normalization failed');
        }

        return prefix + replaceLiteralCandidates(value, [replacements]);
      })
      .join(';');

    return `${name}=${safeCookieValuePlaceholder}${redactedAttributes}`;
  });
};

const registerRedirectSensitiveValues = (
  redirectTo: string,
  tracker: SensitiveValueTracker,
  message: string
) => {
  try {
    const url = new URL(redirectTo);

    for (const [key, value] of url.searchParams) {
      const canonicalName = key.replaceAll(/[_-]/g, '').toLowerCase();

      if (nestedEphemeralFieldKeys.has(canonicalName)) {
        registerSensitiveValue(tracker, value, message);
      }
    }
  } catch {
    throw new Error(message);
  }
};

const observeSafely = (
  context: ScenarioContext,
  tracker: SensitiveValueTracker,
  observation: Observation,
  message: string
) => {
  if (!isJsonValue(observation.value)) {
    throw new TypeError(message);
  }

  assertNoKnownSensitiveValue(observation.value, tracker.values, message);
  // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- Late secrets must rescan all earlier local observations.
  tracker.observedValues.push(observation.value);
  context.observe(observation);
};

const projectUserInfoForObservation = (
  value: unknown,
  context: NormalizationContext,
  tracker: SensitiveValueTracker
): JsonObject => {
  if (!isJsonObject(value)) {
    throw new Error('Userinfo read failed');
  }

  collectExtractedSensitiveValues(value, tracker, 'Userinfo read failed');

  return projectClaimsForObservation(value, {
    allowedFields: userInfoClaimFields,
    context,
    knownSensitiveValues: tracker.values,
    message: 'Userinfo read failed',
  });
};

const normalizeJwtForSingleRunnerPass = (
  compactToken: string,
  context: NormalizationContext,
  tokenKind: 'id-token' | 'access-token',
  tracker: SensitiveValueTracker
) => {
  const headerResult = jsonValueGuard.safeParse(decodeProtectedHeader(compactToken));
  const claimsResult = jsonValueGuard.safeParse(decodeJwt(compactToken));

  if (
    !headerResult.success ||
    !claimsResult.success ||
    !isJsonObject(headerResult.data) ||
    !isJsonObject(claimsResult.data)
  ) {
    throw new TypeError('Invalid token observation');
  }

  collectExtractedSensitiveValues(claimsResult.data, tracker, 'Invalid token observation');

  // Validate with the shared JWT contract in an isolated symbol table, then expose decoded JSON
  // for the runner's single target/symbol normalization pass.
  normalizeJwt(
    compactToken,
    { target: context.target, symbols: new SymbolTable() },
    { tokenKind, timestampToleranceSeconds: 60 }
  );

  const header = Object.fromEntries(
    Object.entries(headerResult.data).filter(([key]) => jwtHeaderFields.has(key))
  );
  const claims = claimsResult.data;
  bindJwtIdentifiers(header, claims, context, tokenKind);

  return {
    header,
    claims: projectClaimsForObservation(claims, {
      allowedFields: jwtClaimFields,
      context,
      knownSensitiveValues: tracker.values,
      message: 'Invalid token observation',
    }),
  };
};

type OpaqueAccessTokenClassification = {
  format: 'opaque';
  observation: Observation;
};

type JwtAccessTokenClassification = {
  format: 'jwt';
  headerObservation: Observation;
  claimsObservation: Observation;
};

type AccessTokenClassification = OpaqueAccessTokenClassification | JwtAccessTokenClassification;

const classifyAccessToken = (
  token: string,
  context: NormalizationContext,
  tracker: SensitiveValueTracker
): AccessTokenClassification => {
  try {
    decodeProtectedHeader(token);
  } catch {
    return {
      format: 'opaque',
      observation: {
        stepId: 'access-token',
        kind: 'semantic-state',
        value: { format: 'opaque', characterCount: token.length },
      },
    };
  }

  const normalized = normalizeJwtForSingleRunnerPass(token, context, 'access-token', tracker);

  return {
    format: 'jwt',
    headerObservation: {
      stepId: 'access-token.header',
      kind: 'jwt-header',
      value: normalized.header,
    },
    claimsObservation: {
      stepId: 'access-token.claims',
      kind: 'jwt-claims',
      value: normalized.claims,
    },
  };
};

const runPasswordCode = async (
  context: ScenarioContext,
  dependencies: PasswordCodeScenarioDependencies
) => {
  const targetOrigin = new URL(context.target.coreUrl).origin;
  const sensitiveTracker: SensitiveValueTracker = {
    values: new Set([fixture.password]),
    observedValues: [],
  };
  await fixedOperation('Set sign-in experience failed', async () =>
    context.client.setUsernamePasswordExperience()
  );
  const createdUser = await fixedOperation('Create user failed', async () =>
    context.client.createUser(fixture)
  );
  const userId = requireNonemptyString(createdUser.id, 'Create user failed');
  context.symbols.bind('user.primary', userId);
  observeSafely(
    context,
    sensitiveTracker,
    {
      stepId: 'management.user.created',
      kind: 'semantic-state',
      value: projectUserForObservation(createdUser, sensitiveTracker.values),
    },
    'Invalid management user projection'
  );

  const experienceClient = await fixedOperation('Start interaction failed', async () =>
    dependencies.createExperienceClient(
      {
        endpoint: targetOrigin,
        appId: demoAppApplicationId,
        persistAccessToken: false,
      },
      context.client.experience
    )
  );
  await fixedOperation('Start interaction failed', async () => {
    await experienceClient.initSession(`${targetOrigin}/demo-app`);
    await experienceClient.initInteraction({ interactionEvent: InteractionEvent.SignIn });
  });
  registerCookieValues(
    experienceClient.rawCookies,
    sensitiveTracker,
    'Cookie normalization failed'
  );
  const cookieMetadata = await fixedOperation('Cookie normalization failed', async () =>
    normalizeSetCookies(redactSetCookieValues(experienceClient.rawCookies))
  );
  observeSafely(
    context,
    sensitiveTracker,
    {
      stepId: 'interaction.cookies',
      kind: 'cookie-metadata',
      value: cookieMetadata,
    },
    'Cookie normalization failed'
  );
  const identificationResult = await fixedOperation('Identify user failed', async () =>
    dependencies.identifyUserWithUsernamePassword(
      experienceClient,
      fixture.username,
      fixture.password
    )
  );

  if (!isJsonValue(identificationResult)) {
    throw new Error('Identify user failed');
  }

  collectExtractedSensitiveValues(identificationResult, sensitiveTracker, 'Identify user failed');
  const { redirectTo } = await fixedOperation('Submit interaction failed', async () =>
    experienceClient.submitInteraction()
  );
  registerCookieValues(experienceClient.rawCookies, sensitiveTracker, 'Submit interaction failed');
  registerRedirectSensitiveValues(redirectTo, sensitiveTracker, 'Process session failed');
  await fixedOperation('Process session failed', async () =>
    experienceClient.processSession(redirectTo)
  );
  registerCookieValues(experienceClient.rawCookies, sensitiveTracker, 'Process session failed');

  const idToken = requireNonemptyString(
    await fixedOperation('ID token read failed', async () => experienceClient.getIdToken()),
    'ID token read failed'
  );
  registerSensitiveValue(sensitiveTracker, idToken, 'ID token normalization failed');
  const normalizedIdToken = await fixedOperation('ID token normalization failed', async () =>
    normalizeJwtForSingleRunnerPass(idToken, context, 'id-token', sensitiveTracker)
  );
  observeSafely(
    context,
    sensitiveTracker,
    { stepId: 'id-token.header', kind: 'jwt-header', value: normalizedIdToken.header },
    'ID token normalization failed'
  );
  observeSafely(
    context,
    sensitiveTracker,
    { stepId: 'id-token.claims', kind: 'jwt-claims', value: normalizedIdToken.claims },
    'ID token normalization failed'
  );

  const accessToken = requireNonemptyString(
    await fixedOperation('Access token read failed', async () => experienceClient.getAccessToken()),
    'Access token read failed'
  );
  registerSensitiveValue(sensitiveTracker, accessToken, 'Access token normalization failed');
  const classifiedAccessToken = await fixedOperation(
    'Access token normalization failed',
    async () => classifyAccessToken(accessToken, context, sensitiveTracker)
  );
  if (classifiedAccessToken.format === 'jwt') {
    observeSafely(
      context,
      sensitiveTracker,
      classifiedAccessToken.headerObservation,
      'Access token normalization failed'
    );
    observeSafely(
      context,
      sensitiveTracker,
      classifiedAccessToken.claimsObservation,
      'Access token normalization failed'
    );
  } else {
    observeSafely(
      context,
      sensitiveTracker,
      classifiedAccessToken.observation,
      'Access token normalization failed'
    );
  }

  const userInfo = projectUserInfoForObservation(
    await fixedOperation('Userinfo read failed', async () =>
      context.client.getUserInfo(accessToken)
    ),
    context,
    sensitiveTracker
  );
  observeSafely(
    context,
    sensitiveTracker,
    { stepId: 'userinfo', kind: 'semantic-state', value: userInfo },
    'Userinfo read failed'
  );
  await fixedOperation('Access token cache clear failed', async () =>
    experienceClient.clearAccessToken()
  );
  const refreshedAccessToken = requireNonemptyString(
    await fixedOperation('Access token refresh failed', async () =>
      experienceClient.getAccessToken()
    ),
    'Access token refresh failed'
  );

  if (refreshedAccessToken === accessToken) {
    throw new Error('Access token refresh failed');
  }

  registerSensitiveValue(sensitiveTracker, refreshedAccessToken, 'Access token refresh failed');
  const refreshedTokenContext = {
    target: context.target,
    symbols: new SymbolTable(),
  } satisfies NormalizationContext;
  const classifiedRefreshedAccessToken = await fixedOperation(
    'Access token refresh failed',
    async () => classifyAccessToken(refreshedAccessToken, refreshedTokenContext, sensitiveTracker)
  );
  observeSafely(
    context,
    sensitiveTracker,
    {
      stepId: 'access-token-refresh',
      kind: 'semantic-state',
      value: { obtainedAfterCacheClear: true, format: classifiedRefreshedAccessToken.format },
    },
    'Access token refresh failed'
  );

  const finalUser = await fixedOperation('Read user failed', async () =>
    context.client.getUser(userId)
  );
  observeSafely(
    context,
    sensitiveTracker,
    {
      stepId: 'management.user.final',
      kind: 'semantic-state',
      value: projectUserForObservation(finalUser, sensitiveTracker.values),
    },
    'Invalid management user projection'
  );
  await fixedOperation('Delete user failed', async () => context.client.deleteUser(userId));
  observeSafely(
    context,
    sensitiveTracker,
    { stepId: 'management.user.deleted', kind: 'semantic-state', value: { deleted: true } },
    'Delete user failed'
  );
};

export const createPasswordCodeScenario = (
  dependencies: Partial<PasswordCodeScenarioDependencies> = {}
) =>
  ({
    id: 'password-code',
    run: async (context) => runPasswordCode(context, { ...defaultDependencies, ...dependencies }),
  }) satisfies CompatibilityScenario;

export default createPasswordCodeScenario();
/* eslint-enable max-lines */
