/* eslint-disable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The closed one-way exception table uses local cursor/rebinding state to keep every observed HTTP compatibility path explicit and auditable. */
import { isDeepStrictEqual } from 'node:util';

import type { JsonObject, JsonValue } from '../../normalize.js';
import { assertPhase1EvidenceIsSanitized, omitVerifiedIdTokenEmailPair } from '../evidence.js';
import type { Phase1DifferentialScenarioId } from '../model.js';

type ProjectionPair = Readonly<{ oracle: Readonly<JsonObject>; candidate: Readonly<JsonObject> }>;
type HeaderRule = Readonly<{
  scenarioId: Phase1DifferentialScenarioId;
  pointer: string;
}>;
type CacheRule = HeaderRule & Readonly<{ value: readonly string[] }>;

const noStore = Object.freeze(['no-store']);
const noCache = Object.freeze(['no-cache, max-age=0, must-revalidate']);
const headerPointer = (stepId: string, name: string): string =>
  `/steps/${stepId}/value/headers/${name}`;
const nestedHeaderPointer = (stepId: string, branch: string, name: string): string =>
  `/steps/${stepId}/value/body/${branch}/headers/${name}`;

const cacheRules = Object.freeze([
  {
    scenarioId: 'account.admin-operator-read',
    pointer: headerPointer('account', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'authorization.password-pkce-consent',
    pointer: headerPointer('submit', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'authorization.password-pkce-consent',
    pointer: headerPointer('consent-get', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'cookie.localhost-port-interleaving',
    pointer: headerPointer('admin-finish-reverse', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'cookie.localhost-port-interleaving',
    pointer: headerPointer('data-finish', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'cors.management-list',
    pointer: headerPointer('applications-get', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'cors.management-list',
    pointer: headerPointer('users-get', 'cache-control'),
    value: noStore,
  },
  {
    scenarioId: 'discovery.config',
    pointer: headerPointer('oauth-discovery', 'cache-control'),
    value: noCache,
  },
  {
    scenarioId: 'discovery.config',
    pointer: headerPointer('oidc-discovery', 'cache-control'),
    value: noCache,
  },
  ...[
    'get-absent',
    'get-foreign',
    'get-partial',
    'get-replayed',
    'get-spliced',
    'get-tampered',
    'post-absent',
    'post-foreign',
    'post-partial',
    'post-replayed',
    'post-spliced',
    'post-tampered',
  ].map((stepId) => ({
    scenarioId: 'interaction.consent-session-boundary' as const,
    pointer: headerPointer(stepId, 'cache-control'),
    value: noStore,
  })),
  {
    scenarioId: 'interaction.consent-session-boundary',
    pointer: headerPointer('get-valid-b', 'cache-control'),
    value: noStore,
  },
  ...['first-party', 'saml', 'third-party'].map((stepId) => ({
    scenarioId: 'management.application-read' as const,
    pointer: headerPointer(stepId, 'cache-control'),
    value: noStore,
  })),
  {
    scenarioId: 'management.user-read',
    pointer: headerPointer('users', 'cache-control'),
    value: noStore,
  },
  ...['missing-scope', 'wrong-audience', 'wrong-issuer'].map((stepId) => ({
    scenarioId: 'token.issuer-audience-scope-rejected' as const,
    pointer: nestedHeaderPointer(stepId, 'management', 'cache-control'),
    value: noStore,
  })),
] satisfies readonly CacheRule[]);

const omittedStrongEtagRules = Object.freeze([
  { scenarioId: 'account.admin-operator-read', pointer: headerPointer('account', 'etag') },
  ...['authorize', 'callback', 'consent-get', 'resume'].map((stepId) => ({
    scenarioId: 'authorization.password-pkce-consent' as const,
    pointer: headerPointer(stepId, 'etag'),
  })),
  {
    scenarioId: 'authorization.password-pkce-consent',
    pointer: '/steps/submit/value/outcomes/0/response/headers/etag',
  },
  { scenarioId: 'authorization.pkce-method-rejected', pointer: headerPointer('authorize', 'etag') },
  {
    scenarioId: 'authorization.redirect-uri-rejected',
    pointer: headerPointer('authorize', 'etag'),
  },
  {
    scenarioId: 'console.admin-auth-resource-refresh',
    pointer: headerPointer('authorize', 'etag'),
  },
  ...['admin-start', 'admin-start-reverse', 'data-start', 'data-start-reverse'].map((stepId) => ({
    scenarioId: 'cookie.localhost-port-interleaving' as const,
    pointer: headerPointer(stepId, 'etag'),
  })),
  ...['jwks', 'oauth-discovery', 'oidc-discovery'].map((stepId) => ({
    scenarioId: 'discovery.config' as const,
    pointer: headerPointer(stepId, 'etag'),
  })),
  {
    scenarioId: 'interaction.consent-session-boundary',
    pointer: headerPointer('get-valid-b', 'etag'),
  },
  ...['missing-scope', 'wrong-audience', 'wrong-issuer'].map((stepId) => ({
    scenarioId: 'token.issuer-audience-scope-rejected' as const,
    pointer: nestedHeaderPointer(stepId, 'userinfo', 'etag'),
  })),
  { scenarioId: 'userinfo.openid', pointer: headerPointer('userinfo', 'etag') },
] satisfies readonly HeaderRule[]);

const weakenedEtagRules = Object.freeze([
  ...['applications-get', 'users-get'].map((stepId) => ({
    scenarioId: 'cors.management-list' as const,
    pointer: headerPointer(stepId, 'etag'),
  })),
  ...['first-party', 'saml', 'third-party'].map((stepId) => ({
    scenarioId: 'management.application-read' as const,
    pointer: headerPointer(stepId, 'etag'),
  })),
  { scenarioId: 'management.user-read', pointer: headerPointer('users', 'etag') },
] satisfies readonly HeaderRule[]);

const missing = Symbol('missing');
const arrayIndexPattern = /^(?:0|[1-9]\d*)$/u;
const digestPattern = /^[0-9a-f]{64}$/u;

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const pointerSegments = (pointer: string): readonly string[] => {
  if (!pointer.startsWith('/')) {
    return [];
  }

  return Object.freeze(
    pointer
      .slice(1)
      .split('/')
      .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'))
  );
};

const valueAt = (root: unknown, pointer: string): unknown | typeof missing => {
  let value = root;

  for (const segment of pointerSegments(pointer)) {
    if (Array.isArray(value)) {
      if (!arrayIndexPattern.test(segment) || Number(segment) >= value.length) {
        return missing;
      }
      value = value[Number(segment)];
      continue;
    }
    if (!isRecord(value) || !Object.hasOwn(value, segment)) {
      return missing;
    }
    value = value[segment];
  }

  return value;
};

const deleteAt = (root: JsonValue, segments: readonly string[]): JsonValue => {
  const [segment, ...rest] = segments;

  if (segment === undefined) {
    return root;
  }
  if (Array.isArray(root)) {
    if (!arrayIndexPattern.test(segment) || Number(segment) >= root.length) {
      return root;
    }
    const index = Number(segment);
    const child = root[index];

    if (child === undefined) {
      return root;
    }
    const projected = deleteAt(child, rest);

    return projected === child
      ? root
      : root.map((value, candidateIndex) => (candidateIndex === index ? projected : value));
  }
  if (!isRecord(root) || !Object.hasOwn(root, segment)) {
    return root;
  }
  if (rest.length === 0) {
    return Object.freeze(
      Object.fromEntries(Object.entries(root).filter(([key]) => key !== segment)) as JsonObject
    );
  }
  const child = root[segment] as JsonValue;
  const projected = deleteAt(child, rest);

  return projected === child
    ? root
    : (Object.freeze({ ...root, [segment]: projected }) as JsonObject);
};

const replaceAt = (
  root: JsonValue,
  segments: readonly string[],
  replacement: JsonValue
): JsonValue => {
  const [segment, ...rest] = segments;

  if (segment === undefined) {
    return replacement;
  }
  if (Array.isArray(root)) {
    if (!arrayIndexPattern.test(segment) || Number(segment) >= root.length) {
      return root;
    }
    const index = Number(segment);
    const child = root[index];

    if (child === undefined) {
      return root;
    }
    const projected = replaceAt(child, rest, replacement);

    return projected === child
      ? root
      : root.map((value, candidateIndex) => (candidateIndex === index ? projected : value));
  }
  if (!isRecord(root) || !Object.hasOwn(root, segment)) {
    return root;
  }
  const child = root[segment] as JsonValue;
  const projected = replaceAt(child, rest, replacement);

  return projected === child
    ? root
    : (Object.freeze({ ...root, [segment]: projected }) as JsonObject);
};

const withoutHeader = (headers: Readonly<Record<string, unknown>>, name: string): JsonObject =>
  Object.freeze(
    Object.fromEntries(Object.entries(headers).filter(([key]) => key !== name)) as JsonObject
  );

const projectTransportHeaders = (
  oracle: Readonly<Record<string, unknown>>,
  candidate: Readonly<Record<string, unknown>>
): Readonly<{
  oracle: Readonly<Record<string, unknown>>;
  candidate: Readonly<Record<string, unknown>>;
}> => {
  const projectPair =
    isDeepStrictEqual(oracle.connection, ['keep-alive']) &&
    isDeepStrictEqual(oracle['keep-alive'], ['timeout=5']) &&
    !Object.hasOwn(candidate, 'connection') &&
    !Object.hasOwn(candidate, 'keep-alive');
  const projectedOracle = projectPair
    ? withoutHeader(withoutHeader(oracle, 'connection'), 'keep-alive')
    : oracle;

  return Object.freeze({ oracle: projectedOracle, candidate });
};

const projectTransport = (
  oracle: JsonValue,
  candidate: JsonValue
): Readonly<{ oracle: JsonValue; candidate: JsonValue }> => {
  if (Array.isArray(oracle) && Array.isArray(candidate) && oracle.length === candidate.length) {
    const pairs = oracle.map((value, index) =>
      projectTransport(value, candidate[index] as JsonValue)
    );
    const oracleChanged = pairs.some((pair, index) => pair.oracle !== oracle[index]);
    const candidateChanged = pairs.some((pair, index) => pair.candidate !== candidate[index]);

    return Object.freeze({
      oracle: oracleChanged ? pairs.map(({ oracle: value }) => value) : oracle,
      candidate: candidateChanged ? pairs.map(({ candidate: value }) => value) : candidate,
    });
  }
  if (!isRecord(oracle) || !isRecord(candidate)) {
    return Object.freeze({ oracle, candidate });
  }
  let projectedOracle: Readonly<Record<string, unknown>> = oracle;
  let projectedCandidate: Readonly<Record<string, unknown>> = candidate;
  const oracleHeaders = oracle.headers;
  const candidateHeaders = candidate.headers;

  if (isRecord(oracleHeaders) && isRecord(candidateHeaders)) {
    const headers = projectTransportHeaders(oracleHeaders, candidateHeaders);

    if (headers.oracle !== oracleHeaders) {
      projectedOracle = Object.freeze({ ...projectedOracle, headers: headers.oracle });
    }
  }
  for (const key of Object.keys(oracle)) {
    if (key === 'headers' || !Object.hasOwn(candidate, key)) {
      continue;
    }
    const oracleValue = projectedOracle[key];
    const candidateValue = projectedCandidate[key];

    if (oracleValue === undefined || candidateValue === undefined) {
      continue;
    }
    const pair = projectTransport(oracleValue as JsonValue, candidateValue as JsonValue);

    if (pair.oracle !== oracleValue) {
      projectedOracle = Object.freeze({ ...projectedOracle, [key]: pair.oracle });
    }
    if (pair.candidate !== candidateValue) {
      projectedCandidate = Object.freeze({ ...projectedCandidate, [key]: pair.candidate });
    }
  }

  return Object.freeze({
    oracle: projectedOracle as JsonObject,
    candidate: projectedCandidate as JsonObject,
  });
};

const strongEtag = (
  value: unknown
): value is readonly [Readonly<{ weak: false; normalizedBodySha256: string }>] =>
  Array.isArray(value) &&
  value.length === 1 &&
  isRecord(value[0]) &&
  Object.keys(value[0]).length === 2 &&
  value[0].weak === false &&
  typeof value[0].normalizedBodySha256 === 'string' &&
  digestPattern.test(value[0].normalizedBodySha256);

const weakEtag = (
  value: unknown
): value is readonly [Readonly<{ weak: true; normalizedBodySha256: string }>] =>
  Array.isArray(value) &&
  value.length === 1 &&
  isRecord(value[0]) &&
  Object.keys(value[0]).length === 2 &&
  value[0].weak === true &&
  typeof value[0].normalizedBodySha256 === 'string' &&
  digestPattern.test(value[0].normalizedBodySha256);

const cacheClosed = (value: unknown): boolean =>
  isDeepStrictEqual(value, noStore) || isDeepStrictEqual(value, noCache);

const emailPairSteps = Object.freeze([
  { scenarioId: 'token.code-reuse-rejected', stepId: 'first-exchange' },
  { scenarioId: 'token.refresh-rotation', stepId: 'refresh-token' },
] as const satisfies ReadonlyArray<
  Readonly<{
    scenarioId: Phase1DifferentialScenarioId;
    stepId: string;
  }>
>);

const verifiedTokenArray = (tokens: unknown): tokens is readonly unknown[] => {
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return false;
  }
  try {
    assertPhase1EvidenceIsSanitized({ tokens });

    return true;
  } catch {
    return false;
  }
};

const emailAuthority = (
  root: JsonObject,
  stepId: string
):
  | Readonly<{
      idClaims: Readonly<Record<string, unknown>>;
      userinfo: Readonly<Record<string, unknown>>;
      scope: string;
    }>
  | undefined => {
  const value = valueAt(root, `/steps/${stepId}/value`);

  if (!isRecord(value) || !verifiedTokenArray(value.tokens) || !isRecord(value.body)) {
    return undefined;
  }
  const { tokens, body } = value;
  const accessIndex = tokens.findIndex((token) => isRecord(token) && token.kind === 'access');
  const idIndex = tokens.findIndex((token) => isRecord(token) && token.kind === 'id');
  const access = tokens[accessIndex];
  const id = tokens[idIndex];
  const { scope } = body;

  if (
    accessIndex < 0 ||
    idIndex < 0 ||
    tokens.filter((token) => isRecord(token) && token.kind === 'access').length !== 1 ||
    tokens.filter((token) => isRecord(token) && token.kind === 'id').length !== 1 ||
    !isRecord(access) ||
    access.format !== 'opaque' ||
    !isRecord(id) ||
    id.format !== 'jwt' ||
    id.signatureVerified !== true ||
    !isRecord(id.claims) ||
    !isRecord(body.access) ||
    body.access.$observation !== accessIndex ||
    !isRecord(body.id) ||
    body.id.$observation !== idIndex ||
    body.tokenType !== 'Bearer' ||
    typeof scope !== 'string' ||
    !['openid', 'email'].every((required) => scope.split(' ').includes(required))
  ) {
    return undefined;
  }
  const { outcomes } = value;
  const outcome: unknown =
    Array.isArray(outcomes) && outcomes.length === 1 ? outcomes[0] : undefined;
  const response =
    isRecord(outcome) && outcome.kind === 'userinfo-email' ? outcome.response : undefined;
  const userinfo = isRecord(response) && response.status === 200 ? response.body : undefined;

  if (
    !isRecord(userinfo) ||
    typeof id.claims.sub !== 'string' ||
    userinfo.sub !== id.claims.sub ||
    !(
      (typeof userinfo.email === 'string' && userinfo.email.length > 0) ||
      userinfo.email === null
    ) ||
    typeof userinfo.email_verified !== 'boolean'
  ) {
    return undefined;
  }

  return Object.freeze({ idClaims: id.claims, userinfo, scope });
};

const projectEmailPair = (
  scenarioId: Phase1DifferentialScenarioId,
  oracle: Readonly<JsonObject>,
  candidate: Readonly<JsonObject>
): Readonly<JsonObject> => {
  const rule = emailPairSteps.find(({ scenarioId: registered }) => registered === scenarioId);

  if (!rule) {
    return oracle;
  }
  const reference = emailAuthority(oracle, rule.stepId);
  const actual = emailAuthority(candidate, rule.stepId);

  if (!reference || !actual || reference.scope !== actual.scope) {
    return oracle;
  }
  const { idClaims: referenceClaims, userinfo: referenceUserinfo } = reference;
  const { idClaims: actualClaims, userinfo: actualUserinfo } = actual;

  if (
    !Object.hasOwn(referenceClaims, 'email') ||
    !Object.hasOwn(referenceClaims, 'email_verified') ||
    !(
      (typeof referenceClaims.email === 'string' && referenceClaims.email.length > 0) ||
      referenceClaims.email === null
    ) ||
    typeof referenceClaims.email_verified !== 'boolean' ||
    referenceClaims.email !== referenceUserinfo.email ||
    referenceClaims.email_verified !== referenceUserinfo.email_verified ||
    !isDeepStrictEqual(referenceUserinfo, actualUserinfo) ||
    referenceClaims.sub !== actualClaims.sub ||
    Object.hasOwn(actualClaims, 'email') ||
    Object.hasOwn(actualClaims, 'email_verified')
  ) {
    return oracle;
  }
  const tokens = valueAt(oracle, `/steps/${rule.stepId}/value/tokens`);
  const idIndex = Array.isArray(tokens)
    ? tokens.findIndex((token) => isRecord(token) && token.kind === 'id')
    : -1;

  if (idIndex < 0) {
    return oracle;
  }
  const derivedTokens = omitVerifiedIdTokenEmailPair(tokens as readonly JsonValue[], idIndex);

  return replaceAt(
    oracle,
    pointerSegments(`/steps/${rule.stepId}/value/tokens`),
    derivedTokens as JsonValue
  ) as Readonly<JsonObject>;
};

export const projectPhase1HttpCompatibility = (
  scenarioId: Phase1DifferentialScenarioId,
  oracleInput: Readonly<JsonObject>,
  candidateInput: Readonly<JsonObject>
): ProjectionPair => {
  const transport = projectTransport(oracleInput, candidateInput);
  let oracle = transport.oracle as Readonly<JsonObject>;
  let candidate = transport.candidate as Readonly<JsonObject>;

  for (const rule of cacheRules) {
    if (
      rule.scenarioId === scenarioId &&
      valueAt(oracle, rule.pointer) === missing &&
      isDeepStrictEqual(valueAt(candidate, rule.pointer), rule.value)
    ) {
      candidate = deleteAt(candidate, pointerSegments(rule.pointer)) as Readonly<JsonObject>;
    }
  }
  for (const rule of omittedStrongEtagRules) {
    if (
      rule.scenarioId === scenarioId &&
      strongEtag(valueAt(oracle, rule.pointer)) &&
      valueAt(candidate, rule.pointer) === missing &&
      cacheClosed(valueAt(candidateInput, rule.pointer.replace(/\/etag$/u, '/cache-control')))
    ) {
      oracle = deleteAt(oracle, pointerSegments(rule.pointer)) as Readonly<JsonObject>;
    }
  }
  for (const rule of weakenedEtagRules) {
    if (rule.scenarioId !== scenarioId) {
      continue;
    }
    const oracleEtag = valueAt(oracle, rule.pointer);
    const candidateEtag = valueAt(candidate, rule.pointer);

    if (
      strongEtag(oracleEtag) &&
      weakEtag(candidateEtag) &&
      oracleEtag[0].normalizedBodySha256 === candidateEtag[0].normalizedBodySha256
    ) {
      oracle = replaceAt(
        oracle,
        pointerSegments(rule.pointer),
        candidateEtag as unknown as JsonValue
      ) as Readonly<JsonObject>;
    }
  }

  oracle = projectEmailPair(scenarioId, oracle, candidate);

  return Object.freeze({ oracle, candidate });
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
