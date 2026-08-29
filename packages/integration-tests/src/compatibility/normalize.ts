/* eslint-disable max-lines -- Compatibility normalization primitives share recursive JSON, cookie, and JWT contracts. */
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { z } from 'zod';

import { jsonValueGuard, targetConfigGuard, type TargetConfig } from './model.js';
import {
  replaceLiteralCandidates,
  SymbolTable,
  type LiteralReplacementCandidate,
} from './symbol-table.js';

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

const jwtNormalizationOptionsGuard = z
  .object({
    tokenKind: z.enum(['id-token', 'access-token']),
    timestampToleranceSeconds: z.number().finite().nonnegative(),
    identifierClaimPaths: z.array(z.string()).optional(),
    timeClaimPaths: z.array(z.string()).optional(),
  })
  .strict();

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
const cookieExpiresPattern =
  /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/;
const cookieWeekdays: readonly string[] = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const cookieMonths: readonly string[] = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];
const cookieOctetRanges: ReadonlyArray<readonly [number, number]> = [
  [33, 33],
  [35, 43],
  [45, 58],
  [60, 91],
  [93, 126],
];

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
  if (pointer === '') {
    return [];
  }

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

const isUrlBoundary = (sourceValue: string, endIndex: number) => {
  const nextCharacter = sourceValue[endIndex];

  return (
    nextCharacter === undefined ||
    nextCharacter === '/' ||
    nextCharacter === '?' ||
    nextCharacter === '#'
  );
};

const removeSingleTrailingSlash = (value: string) =>
  value.endsWith('/') ? value.slice(0, -1) : value;

const normalizeString = (value: string, context: NormalizationContext) => {
  const urlCandidates: LiteralReplacementCandidate[] = [
    { source: context.target.coreUrl, replacement: '<target.core-url>' },
    { source: context.target.adminUrl, replacement: '<target.admin-url>' },
  ]
    .map(({ source, replacement }) => ({
      source: removeSingleTrailingSlash(source),
      replacement,
      isMatch: isUrlBoundary,
    }))
    .filter(
      (candidate, index, candidates) =>
        candidates.findIndex(({ source }) => source === candidate.source) === index
    );

  return replaceLiteralCandidates(value, [
    urlCandidates,
    context.symbols.getReplacementCandidates(),
  ]);
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

const trimAsciiSpaces = (value: string) => value.replaceAll(/^ +| +$/g, '');

const splitAttribute = (segment: string): [string, string | undefined] => {
  const separator = segment.indexOf('=');

  return separator < 0
    ? [trimAsciiSpaces(segment), undefined]
    : [trimAsciiSpaces(segment.slice(0, separator)), trimAsciiSpaces(segment.slice(separator + 1))];
};

const assertUniqueAttribute = (seen: Set<string>, attribute: string) => {
  if (seen.has(attribute)) {
    throw new TypeError('Duplicate Set-Cookie known attribute');
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
    throw new TypeError(`Invalid Set-Cookie ${attribute} attribute`);
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
      throw new TypeError('Invalid Set-Cookie SameSite attribute');
    }
  }
};

const normalizeMaxAge = (value: string): number => {
  if (!/^-?\d+$/.test(value)) {
    throw new TypeError('Invalid Set-Cookie Max-Age attribute');
  }

  const maxAge = Number(value);

  if (!Number.isSafeInteger(maxAge)) {
    throw new TypeError('Invalid Set-Cookie Max-Age attribute');
  }

  return maxAge;
};

type ParsedCookieExpires = {
  weekday: string;
  dayText: string;
  monthIndex: number;
  yearText: string;
  hourText: string;
  minuteText: string;
  secondText: string;
  day: number;
  year: number;
  hour: number;
  minute: number;
  second: number;
};

const requireExpiresMatchPart = (part: string | undefined): string => {
  if (part === undefined) {
    throw new TypeError('Invalid Expires attribute: expected canonical IMF-fixdate');
  }

  return part;
};

const parseCookieExpires = (value: string): ParsedCookieExpires => {
  const match = cookieExpiresPattern.exec(value);

  if (!match) {
    throw new TypeError('Invalid Expires attribute: expected canonical IMF-fixdate');
  }

  const weekday = requireExpiresMatchPart(match[1]);
  const dayText = requireExpiresMatchPart(match[2]);
  const month = requireExpiresMatchPart(match[3]);
  const yearText = requireExpiresMatchPart(match[4]);
  const hourText = requireExpiresMatchPart(match[5]);
  const minuteText = requireExpiresMatchPart(match[6]);
  const secondText = requireExpiresMatchPart(match[7]);
  const day = Number(dayText);
  const monthIndex = cookieMonths.indexOf(month);
  const year = Number(yearText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);

  if (monthIndex < 0 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    throw new TypeError('Invalid Expires attribute: date or time component is out of range');
  }

  return {
    weekday,
    dayText,
    monthIndex,
    yearText,
    hourText,
    minuteText,
    secondText,
    day,
    year,
    hour,
    minute,
    second,
  };
};

const isConsistentCookieExpires = (expires: Date, parsed: ParsedCookieExpires) =>
  !Number.isNaN(expires.getTime()) &&
  expires.getUTCFullYear() === parsed.year &&
  expires.getUTCMonth() === parsed.monthIndex &&
  expires.getUTCDate() === parsed.day &&
  expires.getUTCHours() === parsed.hour &&
  expires.getUTCMinutes() === parsed.minute &&
  expires.getUTCSeconds() === parsed.second &&
  cookieWeekdays[expires.getUTCDay()] === parsed.weekday;

const normalizeExpires = (value: string): string => {
  const parsed = parseCookieExpires(value);
  const expires = new Date(
    `${parsed.yearText}-${String(parsed.monthIndex + 1).padStart(2, '0')}-${parsed.dayText}T${parsed.hourText}:${parsed.minuteText}:${parsed.secondText}Z`
  );

  if (!isConsistentCookieExpires(expires, parsed)) {
    throw new TypeError('Invalid Expires attribute: date or weekday is inconsistent');
  }

  return expires.toISOString();
};

const parseKnownCookieAttribute = (
  attribute: KnownCookieAttribute,
  attributeValue: string | undefined
): Partial<CookieMetadata> => {
  if (attribute === 'httponly' || attribute === 'secure') {
    if (attributeValue !== undefined) {
      throw new TypeError(`Invalid Set-Cookie ${attribute} attribute`);
    }

    return attribute === 'httponly' ? { httpOnly: true } : { secure: true };
  }

  const value = requireAttributeValue(attribute, attributeValue);

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

const hasAsciiControl = (value: string) =>
  [...value].some((character) => {
    const codePoint = character.codePointAt(0);

    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });

const isCookieOctet = (character: string) => {
  const codePoint = character.codePointAt(0);

  return (
    codePoint !== undefined &&
    cookieOctetRanges.some(([minimum, maximum]) => codePoint >= minimum && codePoint <= maximum)
  );
};

const isValidCookieValue = (value: string) => {
  const framedByQuotes = value.startsWith('"') || value.endsWith('"');

  if (framedByQuotes && (value.length < 2 || !(value.startsWith('"') && value.endsWith('"')))) {
    return false;
  }

  const octets = framedByQuotes ? value.slice(1, -1) : value;

  return [...octets].every((character) => isCookieOctet(character));
};

type ParsedCookiePair = {
  name: string;
  attributeSegments: readonly string[];
};

const parseCookiePair = (header: string): ParsedCookiePair => {
  if (hasAsciiControl(header)) {
    throw new TypeError('Invalid Set-Cookie header: ASCII control character');
  }

  const attributeSeparator = header.indexOf(';');
  const cookiePair = attributeSeparator < 0 ? header : header.slice(0, attributeSeparator);
  const attributeSegments =
    attributeSeparator < 0 ? [] : header.slice(attributeSeparator + 1).split(';');
  const pairSeparator = cookiePair.indexOf('=');

  if (pairSeparator <= 0) {
    throw new TypeError('Invalid Set-Cookie cookie-pair');
  }

  const name = cookiePair.slice(0, pairSeparator);
  const cookieValue = cookiePair.slice(pairSeparator + 1);

  if (!cookieNamePattern.test(name)) {
    throw new TypeError('Invalid Set-Cookie cookie name');
  }

  if (!isValidCookieValue(cookieValue)) {
    throw new TypeError('Invalid Set-Cookie cookie value');
  }

  return { name, attributeSegments };
};

const normalizeSetCookie = (header: string): CookieMetadata => {
  const { name, attributeSegments } = parseCookiePair(header);

  const seen = new Set<string>();

  return attributeSegments.reduce<CookieMetadata>(
    (metadata, segment) => {
      if (segment.length === 0) {
        throw new TypeError('Invalid Set-Cookie attribute');
      }

      const [rawName, attributeValue] = splitAttribute(segment);
      const attribute = rawName.toLowerCase();

      if (!cookieNamePattern.test(rawName)) {
        throw new TypeError('Invalid Set-Cookie attribute name');
      }

      if (!isKnownCookieAttribute(attribute)) {
        return metadata;
      }

      assertUniqueAttribute(seen, attribute);

      return { ...metadata, ...parseKnownCookieAttribute(attribute, attributeValue) };
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

const parseJwtNormalizationOptions = (value: unknown): JwtNormalizationOptions => {
  const result = jwtNormalizationOptionsGuard.safeParse(value);

  if (result.success) {
    return result.data;
  }

  switch (result.error.issues.at(0)?.path.at(0)) {
    case 'tokenKind': {
      throw new TypeError('Invalid JWT normalization options: tokenKind must be a supported kind');
    }
    case 'timestampToleranceSeconds': {
      throw new TypeError('JWT timestamp tolerance must be a finite non-negative number');
    }
    case 'identifierClaimPaths': {
      throw new TypeError(
        'Invalid JWT normalization options: identifierClaimPaths must be an array of strings'
      );
    }
    case 'timeClaimPaths': {
      throw new TypeError(
        'Invalid JWT normalization options: timeClaimPaths must be an array of strings'
      );
    }
    default: {
      throw new TypeError('Invalid JWT normalization options');
    }
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

  if (Object.hasOwn(claims, 'tokenLifetimeSeconds')) {
    throw new TypeError(
      'JWT claims must not define tokenLifetimeSeconds when token lifetime is derived'
    );
  }

  const tokenLifetimeSeconds = expiresAt - issuedAt;

  if (!Number.isFinite(tokenLifetimeSeconds)) {
    throw new TypeError('JWT token lifetime must be finite');
  }

  return tokenLifetimeSeconds;
};

/**
 * Decodes a compact JWT for compatibility observation only. This deliberately performs NO
 * signature, authenticity, or integrity verification and must never be used for authorization.
 */
export const normalizeJwt = (
  compactToken: string,
  context: NormalizationContext,
  options: JwtNormalizationOptions
): NormalizedJwt => {
  const parsedOptions = parseJwtNormalizationOptions(options);

  const { decodedHeader, decodedClaims } = decodeCompactJwt(compactToken);
  const header = asJsonObject(decodedHeader, 'JWT protected header');
  const claims = asJsonObject(decodedClaims, 'JWT claims');
  const tokenLifetimeSeconds = getTokenLifetime(claims);

  bindJwtIdentifiers(header, claims, context, parsedOptions);

  const timeRules = collectPresentTimeRules(claims, parsedOptions);
  const normalizedHeader = normalizeJson(header, context, []);
  const normalizedClaims = normalizeJson(claims, context, timeRules);

  if (!isJsonObject(normalizedHeader) || !isJsonObject(normalizedClaims)) {
    throw new TypeError('Normalized JWT observations must be JSON objects');
  }

  return {
    header: normalizedHeader,
    claims:
      tokenLifetimeSeconds === undefined
        ? normalizedClaims
        : { ...normalizedClaims, tokenLifetimeSeconds },
  };
};

/* eslint-enable max-lines */
