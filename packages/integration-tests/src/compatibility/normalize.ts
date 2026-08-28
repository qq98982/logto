/* eslint-disable max-lines */
import { decodeJwt, decodeProtectedHeader } from 'jose';

import { jsonValueGuard, targetConfigGuard, type TargetConfig } from './model.js';
import { SymbolTable } from './symbol-table.js';

export type NormalizationRule =
  | { path: string; strategy: 'drop' }
  | { path: string; strategy: 'timestamp'; toleranceSeconds: number }
  | { path: string; strategy: 'duration-seconds'; startPath: string };

export type NormalizationContext = {
  target: TargetConfig;
  symbols: SymbolTable;
};

export type JsonValue =
  | string
  | number
  | boolean
  // eslint-disable-next-line @typescript-eslint/ban-types -- JSON null is distinct from undefined.
  | null
  | JsonValue[]
  | JsonObject;

/* eslint-disable @typescript-eslint/consistent-indexed-object-style, @typescript-eslint/consistent-type-definitions -- An interface permits recursive JSON values. */
export interface JsonObject {
  [key: string]: JsonValue;
}
/* eslint-enable @typescript-eslint/consistent-indexed-object-style, @typescript-eslint/consistent-type-definitions */

export type CookieMetadata = {
  name: string;
  path?: string;
  domain?: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  maxAge?: number;
  expires?: string;
};

export type JwtNormalizationOptions = {
  tokenKind: 'id-token' | 'access-token';
  timestampToleranceSeconds: number;
  identifierClaimPaths?: readonly string[];
  timeClaimPaths?: readonly string[];
};

export type NormalizedJwt = {
  header: Record<string, JsonValue>;
  claims: Record<string, JsonValue>;
};

type ParsedRule = {
  rule: NormalizationRule;
  segments: readonly string[];
  key: string;
};

type PathLookup = { found: false } | { found: true; value: JsonValue };

const dropped = Symbol('dropped');
const pointerIndexPattern = /^(?:0|[1-9]\d*)$/;
const cookieNamePattern = /^[\w!#$%&'*+.^`|~-]+$/;
const normalizationStrategies = new Set<string>(['drop', 'timestamp', 'duration-seconds']);

const isJsonObject = (value: JsonValue): value is Record<string, JsonValue> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const parseJsonValue = (value: unknown, description: string): JsonValue => {
  const result = jsonValueGuard.safeParse(value);

  if (!result.success || !isJsonValue(value)) {
    throw new TypeError(`${description} must be a faithful JSON value`);
  }

  return value;
};

const isJsonValue = (value: unknown): value is JsonValue => jsonValueGuard.safeParse(value).success;

const parseJsonPointer = (pointer: string, description = 'Rule path'): string[] => {
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) {
    throw new TypeError(`${description} must be an absolute JSON Pointer`);
  }

  return pointer
    .slice(1)
    .split('/')
    .map((encodedSegment) => {
      if (/~(?:[^01]|$)/.test(encodedSegment)) {
        throw new TypeError(`${description} contains an invalid JSON Pointer escape`);
      }

      return encodedSegment.replaceAll('~1', '/').replaceAll('~0', '~');
    });
};

const pathKey = (segments: readonly string[]) => JSON.stringify(segments);

const isPathPrefix = (prefix: readonly string[], path: readonly string[]) =>
  prefix.length < path.length && prefix.every((segment, index) => segment === path[index]);

const parseRules = (rules: readonly NormalizationRule[]): ParsedRule[] => {
  const parsedRules = rules.map((rule): ParsedRule => {
    if (!normalizationStrategies.has(rule.strategy)) {
      throw new TypeError(`Unknown normalization strategy at ${rule.path}`);
    }

    const segments = parseJsonPointer(rule.path);
    const key = pathKey(segments);

    if (rule.strategy === 'timestamp') {
      if (!Number.isFinite(rule.toleranceSeconds)) {
        throw new TypeError('Timestamp tolerance must be finite');
      }

      if (rule.toleranceSeconds < 0) {
        throw new TypeError('Timestamp tolerance must be non-negative');
      }
    } else if (rule.strategy === 'duration-seconds') {
      parseJsonPointer(rule.startPath, 'Duration start path');
    }

    return { rule, segments, key };
  });
  const seen = new Set<string>();

  for (const { key, rule } of parsedRules) {
    if (seen.has(key)) {
      throw new Error(`Duplicate normalization rule path: ${rule.path}`);
    }

    seen.add(key);
  }

  for (const dropRule of parsedRules.filter(({ rule }) => rule.strategy === 'drop')) {
    const descendant = parsedRules.find(({ segments }) =>
      isPathPrefix(dropRule.segments, segments)
    );

    if (descendant) {
      throw new Error(
        `Conflicting drop rule at ${dropRule.rule.path}: descendant rule ${descendant.rule.path} cannot apply`
      );
    }
  }

  return parsedRules;
};

const lookupPath = (root: JsonValue, segments: readonly string[]): PathLookup => {
  const [segment, ...remaining] = segments;

  if (segment === undefined) {
    return { found: true, value: root };
  }

  if (Array.isArray(root)) {
    if (!pointerIndexPattern.test(segment)) {
      return { found: false };
    }

    const index = Number(segment);
    const value = root[index];

    return !Number.isSafeInteger(index) || value === undefined
      ? { found: false }
      : lookupPath(value, remaining);
  }

  if (!isJsonObject(root) || !Object.hasOwn(root, segment)) {
    return { found: false };
  }

  const value = root[segment];

  return value === undefined ? { found: false } : lookupPath(value, remaining);
};

const normalizeString = (value: string, context: NormalizationContext) => {
  const replacements = Array.from([
    { runtimeValue: context.target.coreUrl, placeholder: '<target.core-url>', order: 0 },
    { runtimeValue: context.target.adminUrl, placeholder: '<target.admin-url>', order: 1 },
  ]).toSorted(
    (left, right) =>
      right.runtimeValue.length - left.runtimeValue.length || left.order - right.order
  );
  const withStableUrls = replacements.reduce(
    (result, { runtimeValue, placeholder }) => result.replaceAll(runtimeValue, placeholder),
    value
  );

  return context.symbols.replace(withStableUrls);
};

const applyRule = (
  original: JsonValue,
  parsedRule: ParsedRule,
  originalRoot: JsonValue
): JsonValue | typeof dropped => {
  const { rule } = parsedRule;

  if (rule.strategy === 'drop') {
    return dropped;
  }

  if (typeof original !== 'number' || !Number.isFinite(original)) {
    const description = rule.strategy === 'timestamp' ? 'Timestamp' : 'Duration source';

    throw new TypeError(`${description} at ${rule.path} must be a finite number`);
  }

  if (rule.strategy === 'timestamp') {
    return { $timestamp: original, $toleranceSeconds: rule.toleranceSeconds };
  }

  const startSegments = parseJsonPointer(rule.startPath, 'Duration start path');
  const start = lookupPath(originalRoot, startSegments);

  if (!start.found) {
    throw new Error(`Duration start path ${rule.startPath} does not exist`);
  }

  if (typeof start.value !== 'number' || !Number.isFinite(start.value)) {
    throw new TypeError(`Duration start path ${rule.startPath} must select a finite number`);
  }

  const duration = original - start.value;

  if (!Number.isFinite(duration)) {
    throw new TypeError(`Duration at ${rule.path} must be finite`);
  }

  return { $durationSeconds: duration };
};

export const normalizeJson = (
  value: unknown,
  context: NormalizationContext,
  rules: readonly NormalizationRule[]
): JsonValue => {
  const original = parseJsonValue(value, 'Normalization input');
  targetConfigGuard.parse(context.target);

  if (!(context.symbols instanceof SymbolTable)) {
    throw new TypeError('Normalization context must contain a SymbolTable');
  }

  const parsedRules = parseRules(rules);
  const rulesByPath = new Map(parsedRules.map((parsedRule) => [parsedRule.key, parsedRule]));
  const appliedRules = new Set<string>();

  const visit = (current: JsonValue, segments: readonly string[]): JsonValue | typeof dropped => {
    const key = pathKey(segments);
    const parsedRule = rulesByPath.get(key);

    if (parsedRule) {
      appliedRules.add(key);

      return applyRule(current, parsedRule, original);
    }

    if (typeof current === 'string') {
      return normalizeString(current, context);
    }

    if (Array.isArray(current)) {
      return current.flatMap((item, index) => {
        const normalized = visit(item, [...segments, String(index)]);

        return normalized === dropped ? [] : [normalized];
      });
    }

    if (isJsonObject(current)) {
      return Object.fromEntries(
        Object.entries(current).flatMap(([property, propertyValue]) => {
          const normalized = visit(propertyValue, [...segments, property]);

          return normalized === dropped ? [] : [[property, normalized]];
        })
      );
    }

    return current;
  };

  const normalized = visit(original, []);
  const unappliedRule = parsedRules.find(({ key }) => !appliedRules.has(key));

  if (unappliedRule) {
    throw new Error(`Normalization rule path ${unappliedRule.rule.path} does not exist`);
  }

  if (normalized === dropped) {
    throw new Error('The JSON document root cannot be dropped');
  }

  return normalized;
};

type CookieScanState = {
  segments: readonly string[];
  start: number;
  quoted: boolean;
  escaped: boolean;
};

const scanCookieCharacter = (
  header: string,
  state: CookieScanState,
  index: number
): CookieScanState => {
  const character = header[index];

  if (state.escaped) {
    return { ...state, escaped: false };
  }

  if (state.quoted && character === '\\') {
    return { ...state, escaped: true };
  }

  if (character === '"') {
    return { ...state, quoted: !state.quoted };
  }

  return character === ';' && !state.quoted
    ? {
        ...state,
        segments: [...state.segments, header.slice(state.start, index).trim()],
        start: index + 1,
      }
    : state;
};

const splitCookieSegments = (header: string): string[] => {
  const finalState = Array.from(
    { length: header.length },
    (_, index) => index
  ).reduce<CookieScanState>((state, index) => scanCookieCharacter(header, state, index), {
    segments: [],
    start: 0,
    quoted: false,
    escaped: false,
  } satisfies CookieScanState);

  if (finalState.quoted || finalState.escaped) {
    throw new TypeError('Set-Cookie header contains an unterminated quoted value');
  }

  return [...finalState.segments, header.slice(finalState.start).trim()];
};

const splitAttribute = (segment: string): [string, string | undefined] => {
  const separator = segment.indexOf('=');

  return separator < 0
    ? [segment.trim(), undefined]
    : [segment.slice(0, separator).trim(), segment.slice(separator + 1).trim()];
};

const assertUniqueAttribute = (seen: Set<string>, attribute: string) => {
  if (seen.has(attribute)) {
    throw new TypeError(`Duplicate Set-Cookie attribute: ${attribute}`);
  }

  seen.add(attribute);
};

type KnownCookieAttribute =
  | 'path'
  | 'domain'
  | 'httponly'
  | 'secure'
  | 'samesite'
  | 'max-age'
  | 'expires';

const knownCookieAttributes = new Set<string>([
  'path',
  'domain',
  'httponly',
  'secure',
  'samesite',
  'max-age',
  'expires',
]);

const isKnownCookieAttribute = (attribute: string): attribute is KnownCookieAttribute =>
  knownCookieAttributes.has(attribute);

const requireAttributeValue = (attribute: string, value: string | undefined): string => {
  if (value === undefined || value.length === 0) {
    throw new TypeError(`${attribute} must have a non-empty value`);
  }

  return value;
};

const normalizeSameSite = (value: string): NonNullable<CookieMetadata['sameSite']> => {
  switch (value.toLowerCase()) {
    case 'strict': {
      return 'Strict';
    }
    case 'lax': {
      return 'Lax';
    }
    case 'none': {
      return 'None';
    }
    default: {
      throw new TypeError(`Invalid SameSite value: ${value}`);
    }
  }
};

const normalizeMaxAge = (value: string): number => {
  if (!/^-?\d+$/.test(value)) {
    throw new TypeError(`Invalid Max-Age value: ${value}`);
  }

  const maxAge = Number(value);

  if (!Number.isSafeInteger(maxAge)) {
    throw new TypeError(`Invalid Max-Age value: ${value}`);
  }

  return maxAge;
};

const normalizeExpires = (value: string): string => {
  const expires = new Date(value);

  if (Number.isNaN(expires.getTime())) {
    throw new TypeError(`Invalid Expires value: ${value}`);
  }

  return expires.toISOString();
};

const parseKnownCookieAttribute = (
  attribute: KnownCookieAttribute,
  rawName: string,
  attributeValue: string | undefined
): Partial<CookieMetadata> => {
  if (attribute === 'httponly' || attribute === 'secure') {
    if (attributeValue !== undefined) {
      throw new TypeError(`${rawName} must not have a value`);
    }

    return attribute === 'httponly' ? { httpOnly: true } : { secure: true };
  }

  const value = requireAttributeValue(rawName, attributeValue);

  switch (attribute) {
    case 'path': {
      return { path: value };
    }
    case 'domain': {
      return { domain: value };
    }
    case 'samesite': {
      return { sameSite: normalizeSameSite(value) };
    }
    case 'max-age': {
      return { maxAge: normalizeMaxAge(value) };
    }
    case 'expires': {
      return { expires: normalizeExpires(value) };
    }
  }
};

const normalizeSetCookie = (header: string): CookieMetadata => {
  const [cookiePair, ...attributeSegments] = splitCookieSegments(header);
  const [name, cookieValue] = splitAttribute(cookiePair ?? '');

  if (!cookieNamePattern.test(name) || cookieValue === undefined) {
    throw new TypeError('Set-Cookie header must begin with a valid cookie name and value');
  }

  const seen = new Set<string>();

  return attributeSegments.reduce<CookieMetadata>(
    (metadata, segment) => {
      if (segment.length === 0) {
        throw new TypeError('Set-Cookie header contains an empty attribute');
      }

      const [rawName, attributeValue] = splitAttribute(segment);
      const attribute = rawName.toLowerCase();

      if (!cookieNamePattern.test(rawName)) {
        throw new TypeError(`Invalid Set-Cookie attribute name: ${rawName}`);
      }

      if (!isKnownCookieAttribute(attribute)) {
        return metadata;
      }

      assertUniqueAttribute(seen, attribute);

      return { ...metadata, ...parseKnownCookieAttribute(attribute, rawName, attributeValue) };
    },
    { name, httpOnly: false, secure: false }
  );
};

export const normalizeSetCookies = (setCookieHeaders: readonly string[]): CookieMetadata[] => {
  return setCookieHeaders.map((header) => {
    if (typeof header !== 'string') {
      throw new TypeError('Each Set-Cookie header must be a string');
    }

    return normalizeSetCookie(header);
  });
};

const standardIdentifierClaims = ['sub', 'sid', 'jti'] as const;
const standardTimeClaims = ['iat', 'exp', 'auth_time', 'nbf', 'updated_at'] as const;

const escapeLogicalSegment = (segment: string) =>
  segment.replaceAll('~', '~0').replaceAll('.', '~2');

const identifierNamespace = (tokenKind: JwtNormalizationOptions['tokenKind'], segments: string[]) =>
  `${tokenKind}.${segments.map((segment) => escapeLogicalSegment(segment)).join('.')}`;

const bindIdentifier = (
  root: JsonValue,
  path: string,
  context: NormalizationContext,
  tokenKind: JwtNormalizationOptions['tokenKind']
) => {
  const segments = parseJsonPointer(path, 'Identifier claim path');
  const identifier = lookupPath(root, segments);

  if (!identifier.found) {
    return;
  }

  if (typeof identifier.value !== 'string') {
    throw new TypeError(`Identifier claim ${path} must be a string`);
  }

  context.symbols.bindOccurrence(identifierNamespace(tokenKind, segments), identifier.value);
};

const collectPresentTimeRules = (
  claims: JsonValue,
  options: JwtNormalizationOptions
): NormalizationRule[] => {
  const paths = [
    ...standardTimeClaims.map((claim) => `/${claim}`),
    ...(options.timeClaimPaths ?? []),
  ];
  const seen = new Set<string>();

  return paths.flatMap((path): NormalizationRule[] => {
    const segments = parseJsonPointer(path, 'Time claim path');
    const key = pathKey(segments);

    if (seen.has(key)) {
      return [];
    }

    seen.add(key);
    const claim = lookupPath(claims, segments);

    if (!claim.found) {
      return [];
    }

    if (typeof claim.value !== 'number' || !Number.isFinite(claim.value)) {
      throw new TypeError(`Time claim ${path} must be a finite number`);
    }

    return [
      {
        path,
        strategy: 'timestamp',
        toleranceSeconds: options.timestampToleranceSeconds,
      },
    ];
  });
};

const asJsonObject = (value: unknown, description: string): Record<string, JsonValue> => {
  const json = parseJsonValue(value, description);

  if (!isJsonObject(json)) {
    throw new TypeError(`${description} must be a JSON object`);
  }

  return json;
};

const decodeCompactJwt = (compactToken: string) => {
  try {
    return {
      decodedHeader: decodeProtectedHeader(compactToken),
      decodedClaims: decodeJwt(compactToken),
    };
  } catch {
    throw new TypeError('Malformed compact JWT');
  }
};

const validateJwtOptions = (options: JwtNormalizationOptions) => {
  if (!Number.isFinite(options.timestampToleranceSeconds)) {
    throw new TypeError('JWT timestamp tolerance must be finite');
  }

  if (options.timestampToleranceSeconds < 0) {
    throw new TypeError('JWT timestamp tolerance must be non-negative');
  }
};

const bindJwtIdentifiers = (
  header: JsonObject,
  claims: JsonObject,
  context: NormalizationContext,
  options: JwtNormalizationOptions
) => {
  bindIdentifier(header, '/kid', context, options.tokenKind);

  for (const claim of standardIdentifierClaims) {
    bindIdentifier(claims, `/${claim}`, context, options.tokenKind);
  }

  for (const path of options.identifierClaimPaths ?? []) {
    bindIdentifier(claims, path, context, options.tokenKind);
  }
};

const getTokenLifetime = (claims: JsonObject): number | undefined => {
  const issuedAt = claims.iat;
  const expiresAt = claims.exp;

  if (
    typeof issuedAt !== 'number' ||
    !Number.isFinite(issuedAt) ||
    typeof expiresAt !== 'number' ||
    !Number.isFinite(expiresAt)
  ) {
    return undefined;
  }

  const tokenLifetimeSeconds = expiresAt - issuedAt;

  if (!Number.isFinite(tokenLifetimeSeconds)) {
    throw new TypeError('JWT token lifetime must be finite');
  }

  return tokenLifetimeSeconds;
};

export const normalizeJwt = (
  compactToken: string,
  context: NormalizationContext,
  options: JwtNormalizationOptions
): NormalizedJwt => {
  validateJwtOptions(options);

  const { decodedHeader, decodedClaims } = decodeCompactJwt(compactToken);
  const header = asJsonObject(decodedHeader, 'JWT protected header');
  const claims = asJsonObject(decodedClaims, 'JWT claims');

  bindJwtIdentifiers(header, claims, context, options);

  const timeRules = collectPresentTimeRules(claims, options);
  const normalizedHeader = normalizeJson(header, context, []);
  const normalizedClaims = normalizeJson(claims, context, timeRules);

  if (!isJsonObject(normalizedHeader) || !isJsonObject(normalizedClaims)) {
    throw new TypeError('Normalized JWT observations must be JSON objects');
  }

  const tokenLifetimeSeconds = getTokenLifetime(claims);

  return {
    header: normalizedHeader,
    claims:
      tokenLifetimeSeconds === undefined
        ? normalizedClaims
        : { ...normalizedClaims, tokenLifetimeSeconds },
  };
};

/* eslint-enable max-lines */
