/* eslint-disable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The twelve reviewed field-specific normalizers use guarded JSON narrowing, RFC-style header cursors, and one local header accumulator. */
import { createHash } from 'node:crypto';

import { decodeJwt, decodeProtectedHeader } from 'jose';
import { z } from 'zod';

import { assertEvidenceIsSanitized } from '../evidence.js';
import { jsonValueGuard } from '../model.js';
import {
  normalizeSetCookies,
  type CookieMetadata,
  type JsonObject,
  type JsonValue,
  type NormalizationContext,
} from '../normalize.js';

import { isBoundedTimestampEnvelope } from './bounded-timestamp.js';
import {
  asterNativeSurfaceContract,
  projectNativeSurfaceObservation,
  type Phase1Implementation,
} from './native-surface.js';
import { isValidProfileTimestamp } from './profile-timestamps.js';
import type { Phase1NativeSurfaceMarkerId } from './profile-types.js';

const credentialKeyPattern =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|id[_-]?token|code|state|session|resume|interaction|nonce|code[_-]?verifier|code[_-]?challenge|verification[_-]?(?:id|credential|token|code))$/iu;
const isPhase1CredentialKey = (value: string): boolean => credentialKeyPattern.test(value);
const ephemeralCredentialKeyPattern =
  /^(?:state|session|resume|interaction|nonce|code[_-]?verifier|code[_-]?challenge|verification[_-]?(?:id|credential|token|code))$/iu;
const authCredentialParameterPattern =
  /^(?:authorization|proxy-authorization|cookie|access[_-]?token|refresh[_-]?token|id[_-]?token|token|credential|password|private[_-]?key|api[_-]?key|signature)$/iu;
const authTokenPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+/u;
const headerTokenPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const authToken68Pattern = /^[A-Za-z0-9._~+/-]+={0,}$/u;
const coreRequestIdPattern = /^[A-Za-z0-9_-]{16}$/u;
const entityTagPattern = /^(W\/)?"[\u0021\u0023-\u007E\u0080-\u00FF]*"$/u;
const redirectCredentialKeyPattern =
  /(?:^|[_-])(?:code|state|token|credential|session|interaction|resume|verification|nonce)(?:$|[_-])/iu;
const boundedTimestampToleranceSeconds = 30;
const nativeSurfaceImplementation = (
  value: Readonly<{ nativeSurfaceImplementation?: Phase1Implementation }>
): Phase1Implementation => {
  const { nativeSurfaceImplementation: implementation } = value;

  if (implementation !== 'oracle' && implementation !== 'candidate') {
    throw new TypeError('Invalid Phase 1 native surface context');
  }

  return implementation;
};
const markerMatchesEitherSide = (
  marker: Readonly<{ match: 'exact' | 'prefix'; reference: string; candidate: string }>,
  value: string
): boolean =>
  marker.match === 'exact'
    ? value === marker.reference || value === marker.candidate
    : value.startsWith(marker.reference) || value.startsWith(marker.candidate);
const projectRequestIdHeaderName = (name: string, context: NormalizationContext): string => {
  const marker = asterNativeSurfaceContract.markers.requestIdHeader;

  return markerMatchesEitherSide(marker, name)
    ? projectNativeSurfaceObservation(nativeSurfaceImplementation(context), 'requestIdHeader', name)
    : name;
};
const cookieMarkerIds = Object.freeze([
  'sharedExperienceCookieSignature',
  'sharedExperienceCookie',
  'generatedCookiePrefix',
] as const);
const projectCookieName = (name: string, implementation?: Phase1Implementation): string => {
  for (const markerId of cookieMarkerIds) {
    const marker = asterNativeSurfaceContract.markers[markerId];

    if (markerMatchesEitherSide(marker, name)) {
      if (!implementation) {
        throw new TypeError('Invalid Phase 1 native surface context');
      }
      return projectNativeSurfaceObservation(implementation, markerId, name);
    }
  }

  return name;
};
const resourceAudienceMarkerIds = Object.freeze([
  'managementResource',
  'accountResource',
  'organizationResource',
  'organizationAudiencePrefix',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);
const nativeScopeMarkerIds = Object.freeze([
  'organizationScope',
  'organizationRoleScope',
  'sessionScope',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);
const projectKnownNativeSurfaceValue = (
  value: string,
  markerIds: readonly Phase1NativeSurfaceMarkerId[],
  context: NormalizationContext
): string => {
  for (const markerId of markerIds) {
    const marker = asterNativeSurfaceContract.markers[markerId];

    if (markerMatchesEitherSide(marker, value)) {
      return projectNativeSurfaceObservation(nativeSurfaceImplementation(context), markerId, value);
    }
  }

  return value;
};
const allowedJwtTimestampFields = new Set(['iat', 'exp', 'auth_time', 'created_at', 'updated_at']);
const allowedUserInfoTimestampFields = new Set(['created_at', 'updated_at']);
const entityTimestampFields = new Set([
  'createdAt',
  'created_at',
  'updatedAt',
  'updated_at',
  'lastSignInAt',
]);
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const redirectCredentialFragmentPattern =
  /(?:^|[?&#])(?:code|state|token|credential|session|interaction|resume|verification|nonce)=/iu;
const cookieMetadataGuard = z
  .object({
    name: z.string().min(1),
    path: z.string().optional(),
    domain: z.string().optional(),
    httpOnly: z.boolean(),
    secure: z.boolean(),
    sameSite: z.enum(['Strict', 'Lax', 'None']).optional(),
    maxAge: z.number().finite().optional(),
    expires: z.string().optional(),
    extensions: z
      .array(z.object({ name: z.string().min(1), value: z.string().optional() }).strict())
      .optional(),
  })
  .strict();

export type Phase1RedirectProjection = Readonly<{
  scheme: string;
  origin: string;
  path: string;
  query: Readonly<Record<string, readonly JsonValue[]>>;
  fragment: string;
  redactedParameters: ReadonlyArray<
    Readonly<{ component: 'query' | 'fragment'; name: string; count: number }>
  >;
  resumeCredential?: string;
}>;

export type Phase1HeaderMultimap = Readonly<Record<string, readonly JsonValue[]>>;
export type Phase1CookieMetadata = Omit<CookieMetadata, 'expires'> &
  Readonly<{
    extensions: ReadonlyArray<Readonly<{ name: string; value?: string }>>;
    expires?: Readonly<{ $timestamp: number; $toleranceSeconds: 30 }>;
    expiryOffsetSeconds?: number;
    expiredAtResponse?: true;
  }>;

const fixedFailure = (message: string): never => {
  throw new TypeError(message);
};

const parseJson = (value: unknown, message: string): JsonValue => {
  if (!jsonValueGuard.safeParse(value).success) {
    return fixedFailure(message);
  }

  return value as JsonValue;
};

const isObject = (value: JsonValue): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const compareText = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);

const stableJson = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => stableJson(item));
  }
  if (isObject(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .toSorted(([left], [right]) => compareText(left, right))
        .map(([key, nested]) => [key, stableJson(nested)])
    );
  }

  return value;
};

const stableEntityTagJson = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => stableEntityTagJson(item));
  }
  if (isObject(value)) {
    const keys = Object.keys(value).toSorted(compareText);

    if (isBoundedTimestampEnvelope(value)) {
      // This marker is hash-input-only for ETag stabilization and must never enter a projection.
      return { $boundedTimestamp: true };
    }

    return Object.fromEntries(
      keys.map((key) => [key, stableEntityTagJson(value[key] as JsonValue)])
    );
  }

  return value;
};

const bindGenerated = (namespace: string, value: string, context: NormalizationContext) =>
  `<${context.symbols.bindOccurrence(namespace, value)}>`;

const normalizeRedirectOrigin = (url: URL, context: NormalizationContext): string => {
  const coreOrigin = new URL(context.target.coreUrl).origin;
  const adminOrigin = new URL(context.target.adminUrl).origin;

  if (url.origin === coreOrigin) {
    return '<target.core-url>';
  }
  if (url.origin === adminOrigin) {
    return '<target.admin-url>';
  }

  return url.origin;
};

const assertCredentialFreeUrl = (url: URL): void => {
  if (
    url.username.length > 0 ||
    url.password.length > 0 ||
    Array.from(url.searchParams.keys()).some((key) => redirectCredentialKeyPattern.test(key)) ||
    redirectCredentialFragmentPattern.test(url.hash)
  ) {
    fixedFailure('Invalid phase 1 credential-bearing URL');
  }
};

const assertCredentialFreeUrlValue = (value: string): void => {
  try {
    assertCredentialFreeUrl(new URL(value));
  } catch (error: unknown) {
    if (error instanceof TypeError && error.message === 'Invalid phase 1 credential-bearing URL') {
      throw error;
    }
    // Ordinary non-URL header values remain exact.
  }
};

const normalizeConfiguredTargetUrl = (value: string, context: NormalizationContext): string => {
  const url = (() => {
    try {
      return new URL(value);
    } catch {}
  })();

  if (!url) {
    return value;
  }
  assertCredentialFreeUrl(url);
  const normalizedOrigin = normalizeRedirectOrigin(url, context);
  const suffix = value.slice(url.origin.length);
  const hasExactOriginBoundary =
    value.startsWith(url.origin) &&
    (suffix.length === 0 ||
      suffix.startsWith('/') ||
      suffix.startsWith('?') ||
      suffix.startsWith('#'));

  return hasExactOriginBoundary &&
    (normalizedOrigin === '<target.core-url>' || normalizedOrigin === '<target.admin-url>')
    ? `${normalizedOrigin}${suffix}`
    : value;
};

const normalizeCorsOrigin = (value: string, context: NormalizationContext): string => {
  if (value === '*' || value === 'null') {
    return value;
  }

  const url = (() => {
    try {
      return new URL(value);
    } catch {}
  })();

  if (
    !url ||
    value !== url.origin ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    return fixedFailure('Invalid phase 1 CORS origin');
  }

  return normalizeRedirectOrigin(url, context);
};

const normalizeCoreRequestId = (value: string): JsonValue =>
  coreRequestIdPattern.test(value)
    ? '<per-request-id>'
    : fixedFailure('Invalid phase 1 request ID');

const splitLinkHeaderValues = (value: string): readonly string[] => {
  const result: string[] = [];
  let start = 0;
  let insideTarget = false;
  let insideQuote = false;
  let escaped = false;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];

    if (escaped) {
      escaped = false;
      continue;
    }
    if (insideQuote) {
      if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        insideQuote = false;
      }
      continue;
    }
    if (character === '"') {
      insideQuote = true;
      continue;
    }
    if (character === '<') {
      if (insideTarget) {
        return fixedFailure('Invalid phase 1 Link header');
      }
      insideTarget = true;
      continue;
    }
    if (character === '>') {
      if (!insideTarget) {
        return fixedFailure('Invalid phase 1 Link header');
      }
      insideTarget = false;
      continue;
    }
    if (character === ',' && !insideTarget) {
      const entry = value.slice(start, index).trim();

      if (entry.length === 0) {
        return fixedFailure('Invalid phase 1 Link header');
      }
      result.push(entry);
      start = index + 1;
    }
  }
  const entry = value.slice(start).trim();

  if (insideTarget || insideQuote || escaped || entry.length === 0) {
    return fixedFailure('Invalid phase 1 Link header');
  }
  result.push(entry);

  return Object.freeze(result);
};

const normalizeLinkValue = (value: string, context: NormalizationContext): string => {
  if (!/<[^>]*>/u.test(value)) {
    return fixedFailure('Invalid phase 1 Link header');
  }

  return value.replaceAll(/<([^>]*)>/gu, (_match, target: string) => {
    const url = (() => {
      try {
        return new URL(target);
      } catch {
        return fixedFailure('Invalid phase 1 Link header');
      }
    })();
    const normalizedOrigin = normalizeRedirectOrigin(url, context);
    const originToken =
      normalizedOrigin === '<target.core-url>'
        ? '{target.core-origin}'
        : normalizedOrigin === '<target.admin-url>'
          ? '{target.admin-origin}'
          : undefined;

    if (
      !originToken ||
      !['http:', 'https:'].includes(url.protocol) ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      Array.from(url.searchParams.keys()).some((key) => redirectCredentialKeyPattern.test(key)) ||
      redirectCredentialFragmentPattern.test(url.hash) ||
      !target.startsWith(`${url.origin}/`)
    ) {
      return fixedFailure('Invalid phase 1 Link header');
    }

    return `<${originToken}${target.slice(url.origin.length)}>`;
  });
};

const normalizeLinkHeader = (value: string, context: NormalizationContext): readonly string[] =>
  Object.freeze(splitLinkHeaderValues(value).map((entry) => normalizeLinkValue(entry, context)));

const normalizeVaryHeader = (value: string): string | undefined => {
  const fields = value.split(',').map((field) => field.trim());

  if (fields.length === 0 || fields.some((field) => !headerTokenPattern.test(field))) {
    return fixedFailure('Invalid phase 1 Vary header');
  }
  const semantic = fields.filter((field) => field.toLowerCase() !== 'accept-encoding');

  return semantic.length === 0 ? undefined : semantic.join(', ');
};

type JsonPointerPattern = readonly string[];

const parseBoundedTimestampPaths = (
  paths: readonly string[],
  allowedTerminalFields: ReadonlySet<string>,
  failure: string
): readonly JsonPointerPattern[] =>
  paths.map((pointer) => {
    if (!pointer.startsWith('/') || pointer.length < 2) {
      return fixedFailure(failure);
    }
    const segments = pointer
      .slice(1)
      .split('/')
      .map((segment) => {
        if (/~(?:[^01]|$)/u.test(segment)) {
          return fixedFailure(failure);
        }

        return segment.replaceAll('~1', '/').replaceAll('~0', '~');
      });
    const terminal = segments.at(-1);

    if (!terminal || !allowedTerminalFields.has(terminal)) {
      return fixedFailure(failure);
    }

    return Object.freeze(segments);
  });

const matchesPointerPattern = (path: readonly string[], pattern: JsonPointerPattern): boolean =>
  path.length === pattern.length &&
  pattern.every((segment, index) => segment === '*' || segment === path[index]);

const normalizeExactLogicalJson = (
  value: JsonValue,
  context: NormalizationContext,
  path: readonly string[] = [],
  timestampPatterns: readonly JsonPointerPattern[] = []
): JsonValue => {
  if (typeof value === 'string') {
    try {
      const url = new URL(value);

      assertCredentialFreeUrl(url);
    } catch (error: unknown) {
      if (
        error instanceof TypeError &&
        error.message === 'Invalid phase 1 credential-bearing URL'
      ) {
        throw error;
      }
      // Ordinary non-URL strings stay exact.
    }
    const logicalName = context.symbols.getLogicalName(value);

    return logicalName ? `<${logicalName}>` : value;
  }
  if (
    typeof value === 'number' &&
    timestampPatterns.some((pattern) => matchesPointerPattern(path, pattern))
  ) {
    if (!Number.isFinite(value)) {
      return fixedFailure('Invalid phase 1 bounded timestamp');
    }
    const terminal = path.at(-1);
    const timestamp =
      terminal && entityTimestampFields.has(terminal) ? Math.floor(value / 1000) : value;

    return { $timestamp: timestamp, $toleranceSeconds: boundedTimestampToleranceSeconds };
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      normalizeExactLogicalJson(item, context, [...path, String(index)], timestampPatterns)
    );
  }
  if (isObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [
        key,
        normalizeExactLogicalJson(nested, context, [...path, key], timestampPatterns),
      ])
    );
  }

  return value;
};

const normalizeBoundScopeTokens = (value: string, context: NormalizationContext): string => {
  if (value.length === 0) {
    return value;
  }

  return value
    .split(' ')
    .map((scope) => {
      assertCredentialFreeUrlValue(scope);
      const projected = projectKnownNativeSurfaceValue(scope, nativeScopeMarkerIds, context);
      const logicalName = context.symbols.getLogicalName(projected);

      return logicalName ? `<${logicalName}>` : projected;
    })
    .join(' ');
};

const normalizeAudience = (value: JsonValue, context: NormalizationContext): JsonValue => {
  const normalizeItem = (item: string): string => {
    const projected = projectKnownNativeSurfaceValue(item, resourceAudienceMarkerIds, context);

    if (projected !== item) {
      return projected;
    }
    const normalized = normalizeExactLogicalJson(item, context, ['aud']);

    return typeof normalized === 'string' ? normalized : fixedFailure('Invalid phase 1 claims');
  };

  if (typeof value === 'string') {
    return normalizeItem(value);
  }
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value.map((item) => normalizeItem(item));
  }

  return fixedFailure('Invalid phase 1 claims');
};

const credentialParameterCounts = <Component extends 'query' | 'fragment'>(
  entries: ReadonlyArray<readonly [string, string]>,
  component: Component
) =>
  Object.entries(
    entries.reduce<Record<string, number>>(
      (counts, [key]) =>
        redirectCredentialKeyPattern.test(key)
          ? { ...counts, [key]: (counts[key] ?? 0) + 1 }
          : counts,
      {}
    )
  )
    .toSorted(([left], [right]) => compareText(left, right))
    .map(([name, count]) => Object.freeze({ component, name, count }));

const normalizeFragment = (
  fragment: string
): Readonly<{
  value: string;
  redactedParameters: ReadonlyArray<
    Readonly<{ component: 'fragment'; name: string; count: number }>
  >;
}> => {
  if (fragment.length === 0) {
    return Object.freeze({ value: '', redactedParameters: [] });
  }
  if (!fragment.includes('=') || !redirectCredentialFragmentPattern.test(`#${fragment}`)) {
    return Object.freeze({ value: fragment, redactedParameters: [] });
  }
  const entries = Array.from(new URLSearchParams(fragment).entries());

  return Object.freeze({
    value: entries
      .filter(([key]) => !redirectCredentialKeyPattern.test(key))
      .map(([key, rawValue]) => `${encodeURIComponent(key)}=${encodeURIComponent(rawValue)}`)
      .join('&'),
    redactedParameters: credentialParameterCounts(entries, 'fragment'),
  });
};

export const normalizeRedirect = (
  value: string,
  context: NormalizationContext,
  options: Readonly<{ targetOrigin?: 'exact' | 'symbol'; allowResumePath?: boolean }> = {}
): Phase1RedirectProjection => {
  try {
    const url = new URL(value);

    if (url.username.length > 0 || url.password.length > 0) {
      return fixedFailure('Invalid phase 1 redirect');
    }
    if (url.pathname.startsWith('/oidc/auth/') && !options.allowResumePath) {
      return fixedFailure('Invalid phase 1 redirect');
    }
    const rawQueryEntries = Array.from(url.searchParams.entries());
    const queryEntries = rawQueryEntries.reduce<Record<string, JsonValue[]>>(
      (result, [key, rawValue]) => {
        if (redirectCredentialKeyPattern.test(key)) {
          return result;
        }
        const normalizedKey = key;
        const existing = result[normalizedKey] ?? [];
        const normalizedValue = (() => {
          if (key === 'app_id') {
            return normalizeExactLogicalJson(rawValue, context, [key]);
          }
          if (key === 'iss') {
            const normalizedIssuer = normalizeExactLogicalJson(rawValue, context, [key]);

            return typeof normalizedIssuer === 'string'
              ? normalizeConfiguredTargetUrl(normalizedIssuer, context)
              : fixedFailure('Invalid phase 1 redirect');
          }

          return rawValue;
        })();

        return { ...result, [normalizedKey]: [...existing, normalizedValue] };
      },
      {}
    );
    const fragment = normalizeFragment(url.hash.slice(1));

    return Object.freeze({
      scheme: url.protocol.slice(0, -1).toLowerCase(),
      origin: options.targetOrigin === 'exact' ? url.origin : normalizeRedirectOrigin(url, context),
      path: url.pathname,
      query: Object.freeze(
        Object.fromEntries(
          Object.entries(queryEntries)
            .toSorted(([left], [right]) => compareText(left, right))
            .map(([key, values]) => [key, Object.freeze(values)])
        )
      ),
      fragment: fragment.value,
      redactedParameters: Object.freeze([
        ...credentialParameterCounts(rawQueryEntries, 'query'),
        ...fragment.redactedParameters,
      ]),
    });
  } catch {
    return fixedFailure('Invalid phase 1 redirect');
  }
};

export const normalizeResumeRedirect = (
  value: string,
  context: NormalizationContext
): Phase1RedirectProjection => {
  const projection = normalizeRedirect(value, context, {
    allowResumePath: true,
    targetOrigin: 'symbol',
  });
  const prefix = '/oidc/auth/';
  const { origin } = new URL(value);
  const targetOrigins = new Set([
    new URL(context.target.coreUrl).origin,
    new URL(context.target.adminUrl).origin,
  ]);

  if (!projection.path.startsWith(prefix) || !targetOrigins.has(origin)) {
    return fixedFailure('Invalid phase 1 resume redirect');
  }
  const encodedCredential = projection.path.slice(prefix.length);
  const credential = (() => {
    try {
      return decodeURIComponent(encodedCredential);
    } catch {
      return fixedFailure('Invalid phase 1 resume redirect');
    }
  })();
  const hasControlCharacter = [...credential].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;

    return codePoint < 32 || codePoint === 127;
  });

  if (
    credential.length === 0 ||
    credential.includes('/') ||
    credential.includes('\\') ||
    hasControlCharacter
  ) {
    return fixedFailure('Invalid phase 1 resume redirect');
  }

  return Object.freeze({
    ...projection,
    path: `${prefix}{one-time-resume-credential}`,
    resumeCredential: bindGenerated('redirect.resume-credential', credential, context),
  });
};

type HeaderInput =
  | Headers
  | Readonly<Record<string, string | readonly string[]>>
  | ReadonlyArray<readonly [string, string]>;

const headerPairs = (input: HeaderInput): ReadonlyArray<readonly [string, string]> => {
  if (Array.isArray(input)) {
    return input.map(([name, value]) => [name, value]);
  }
  if (input instanceof Headers) {
    const ordinary = Array.from(input.entries()).filter(([name]) => name !== 'set-cookie');
    const getSetCookie = Reflect.get(input, 'getSetCookie');
    const setCookies =
      typeof getSetCookie === 'function'
        ? Reflect.apply(getSetCookie, input, []).map((value) => ['set-cookie', value] as const)
        : [];

    return [...ordinary, ...setCookies];
  }

  return Object.entries(input).flatMap(([name, value]) =>
    Array.isArray(value)
      ? value.map((item) => [name, item] as const)
      : [[name, value as string] as const]
  );
};

type AuthChallengeCursor = { value: string; offset: number };

const skipAuthWhitespace = (cursor: AuthChallengeCursor): void => {
  while (cursor.value[cursor.offset] === ' ' || cursor.value[cursor.offset] === '\t') {
    cursor.offset += 1;
  }
};

const readAuthToken = (cursor: AuthChallengeCursor): string => {
  const token = authTokenPattern.exec(cursor.value.slice(cursor.offset))?.[0];

  if (!token) {
    return fixedFailure('Invalid phase 1 authentication challenge');
  }
  cursor.offset += token.length;

  return token;
};

const isInvalidAuthQuotedCharacter = (character: string): boolean => {
  const code = character.codePointAt(0) ?? 0;

  return (code < 32 && code !== 9) || code === 127;
};

const readAuthQuotedValue = (cursor: AuthChallengeCursor): string => {
  cursor.offset += 1;
  const result: string[] = [];

  while (cursor.offset < cursor.value.length) {
    const character = cursor.value[cursor.offset];

    if (character === '"') {
      cursor.offset += 1;
      return result.join('');
    }
    if (character === '\\') {
      cursor.offset += 1;
      const escaped = cursor.value[cursor.offset];

      if (escaped === undefined || isInvalidAuthQuotedCharacter(escaped)) {
        return fixedFailure('Invalid phase 1 authentication challenge');
      }
      result.push(escaped);
      cursor.offset += 1;
      continue;
    }
    if (character === undefined || isInvalidAuthQuotedCharacter(character)) {
      return fixedFailure('Invalid phase 1 authentication challenge');
    }
    result.push(character);
    cursor.offset += 1;
  }

  return fixedFailure('Invalid phase 1 authentication challenge');
};

const sanitizeAuthParameter = (
  name: string,
  value: string,
  context: NormalizationContext
): string => {
  if (authCredentialParameterPattern.test(name)) {
    return '<redacted-auth-parameter>';
  }
  try {
    const normalized =
      name.toLowerCase() === 'realm' ? normalizeConfiguredTargetUrl(value, context) : value;
    assertEvidenceIsSanitized({ value: normalized });
    return normalized;
  } catch {
    return '<redacted-auth-parameter>';
  }
};

const readAuthParameter = (
  cursor: AuthChallengeCursor,
  context: NormalizationContext
): JsonObject => {
  const name = readAuthToken(cursor);
  skipAuthWhitespace(cursor);
  if (cursor.value[cursor.offset] !== '=') {
    return fixedFailure('Invalid phase 1 authentication challenge');
  }
  cursor.offset += 1;
  skipAuthWhitespace(cursor);
  const quoted = cursor.value[cursor.offset] === '"';
  const rawValue = quoted ? readAuthQuotedValue(cursor) : readAuthToken(cursor);

  return Object.freeze({ name, value: sanitizeAuthParameter(name, rawValue, context), quoted });
};

const nextAuthItemIsParameter = (cursor: AuthChallengeCursor): boolean => {
  const originalOffset = cursor.offset;

  try {
    readAuthToken(cursor);
    skipAuthWhitespace(cursor);
    return cursor.value[cursor.offset] === '=';
  } finally {
    cursor.offset = originalOffset;
  }
};

const readAuthParameters = (
  cursor: AuthChallengeCursor,
  context: NormalizationContext
): JsonValue[] => {
  const parameters: JsonValue[] = [];

  while (cursor.offset < cursor.value.length) {
    parameters.push(readAuthParameter(cursor, context));
    skipAuthWhitespace(cursor);
    if (cursor.offset === cursor.value.length) {
      break;
    }
    if (cursor.value[cursor.offset] !== ',') {
      return fixedFailure('Invalid phase 1 authentication challenge');
    }
    cursor.offset += 1;
    skipAuthWhitespace(cursor);
    if (!nextAuthItemIsParameter(cursor)) {
      break;
    }
  }

  return parameters;
};

export const normalizeAuthChallenge = (value: string, context: NormalizationContext): JsonValue => {
  if (typeof value !== 'string' || value.length === 0) {
    return fixedFailure('Invalid phase 1 authentication challenge');
  }
  const cursor: AuthChallengeCursor = { value, offset: 0 };
  const challenges: JsonValue[] = [];

  while (cursor.offset < value.length) {
    const scheme = readAuthToken(cursor);
    const separatorOffset = cursor.offset;
    skipAuthWhitespace(cursor);
    const hadSeparator = cursor.offset > separatorOffset;

    if (cursor.offset === value.length || value[cursor.offset] === ',') {
      challenges.push(Object.freeze({ scheme, format: 'parameters', parameters: [] }));
      if (value[cursor.offset] === ',') {
        cursor.offset += 1;
        skipAuthWhitespace(cursor);
        if (cursor.offset === value.length) {
          return fixedFailure('Invalid phase 1 authentication challenge');
        }
      }
      continue;
    }
    if (!hadSeparator) {
      return fixedFailure('Invalid phase 1 authentication challenge');
    }
    const itemEnd = value.indexOf(',', cursor.offset);
    const firstItem = value.slice(cursor.offset, itemEnd < 0 ? value.length : itemEnd).trim();

    if (authToken68Pattern.test(firstItem)) {
      challenges.push(
        Object.freeze({
          scheme,
          format: 'token68',
          parameters: ['<redacted-auth-token68>'],
        })
      );
      cursor.offset = itemEnd < 0 ? value.length : itemEnd + 1;
      skipAuthWhitespace(cursor);
      if (cursor.offset === value.length && itemEnd >= 0) {
        return fixedFailure('Invalid phase 1 authentication challenge');
      }
      continue;
    }
    challenges.push(
      Object.freeze({
        scheme,
        format: 'parameters',
        parameters: readAuthParameters(cursor, context),
      })
    );
  }

  return Object.freeze({ challenges });
};

const normalizeDateHeader = (value: string): JsonValue => {
  const milliseconds = Date.parse(value);

  if (!Number.isFinite(milliseconds)) {
    return fixedFailure('Invalid phase 1 Date header');
  }

  return {
    $timestamp: Math.floor(milliseconds / 1000),
    $toleranceSeconds: boundedTimestampToleranceSeconds,
  };
};

const normalizeContentLength = (value: string, bodyByteLength?: number): JsonValue => {
  const parsed = bodyByteLength ?? Number(value);

  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    return fixedFailure('Invalid phase 1 Content-Length header');
  }

  return parsed;
};

const normalizeEntityTag = (value: string, body: JsonValue | undefined): JsonValue => {
  if (!entityTagPattern.test(value) || value.length > 1024 || body === undefined) {
    return fixedFailure('Invalid phase 1 ETag header');
  }
  assertEvidenceIsSanitized({ entityTag: value });

  return Object.freeze({
    weak: value.startsWith('W/'),
    normalizedBodySha256: createHash('sha256')
      .update(JSON.stringify(stableEntityTagJson(body)))
      .digest('hex'),
  });
};

type CookieMetadataWithExtensions = CookieMetadata &
  Readonly<{
    extensions?: ReadonlyArray<Readonly<{ name: string; value?: string }>>;
  }>;

const knownCookieAttributeNames = new Set([
  'path',
  'domain',
  'httponly',
  'secure',
  'samesite',
  'max-age',
  'expires',
]);

const rawCookieValue = (header: string): string => {
  const attributeSeparator = header.indexOf(';');
  const pair = attributeSeparator < 0 ? header : header.slice(0, attributeSeparator);
  const separator = pair.indexOf('=');
  const value = separator < 0 ? '' : pair.slice(separator + 1);

  return value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
};

const assertCookieValuesAbsent = (value: JsonValue, cookieValues: readonly string[]): void => {
  const credentials = cookieValues.filter((cookieValue) => cookieValue.length > 0);
  const revealsCredential = (metadata: string): boolean => {
    if (credentials.some((credential) => metadata.includes(credential))) {
      return true;
    }
    const decoded = metadata.replaceAll(/%([\dA-F]{2})/giu, (_match, hex: string) =>
      String.fromCodePoint(Number.parseInt(hex, 16))
    );

    return decoded !== metadata && revealsCredential(decoded);
  };
  const collides = (nested: JsonValue): boolean => {
    if (typeof nested === 'string') {
      return revealsCredential(nested);
    }
    if (typeof nested === 'number') {
      return revealsCredential(String(nested));
    }
    if (Array.isArray(nested)) {
      return nested.some((item) => collides(item));
    }
    if (isObject(nested)) {
      return Object.values(nested).some((item) => collides(item));
    }

    return false;
  };

  if (collides(value)) {
    fixedFailure('Invalid phase 1 cookie continuity');
  }
};

const normalizeRawSetCookie = (header: string): CookieMetadataWithExtensions => {
  const metadata =
    normalizeSetCookies([header])[0] ?? fixedFailure('Invalid phase 1 Set-Cookie header');
  const separator = header.indexOf(';');
  const segments = separator < 0 ? [] : header.slice(separator + 1).split(';');
  const extensions = segments.flatMap((segment) => {
    const trimmed = segment.trim();
    const valueSeparator = trimmed.indexOf('=');
    const rawName = (valueSeparator < 0 ? trimmed : trimmed.slice(0, valueSeparator)).trim();
    const name = rawName.toLowerCase();

    if (knownCookieAttributeNames.has(name)) {
      return [];
    }

    return [
      Object.freeze({
        name,
        ...(valueSeparator < 0 ? {} : { value: trimmed.slice(valueSeparator + 1).trim() }),
      }),
    ];
  });

  return Object.freeze({ ...metadata, extensions: Object.freeze(extensions) });
};

const normalizeCookieMetadata = (
  cookie: CookieMetadataWithExtensions,
  responseDateSeconds: number | undefined,
  implementation?: Phase1Implementation
): Phase1CookieMetadata => {
  const { expires, ...metadata } = cookie;
  const completeMetadata = {
    ...metadata,
    name: projectCookieName(metadata.name, implementation),
    extensions: Object.freeze([...(metadata.extensions ?? [])]),
  };

  if (expires === undefined) {
    return Object.freeze(completeMetadata);
  }
  const expirationSeconds = Date.parse(expires) / 1000;

  if (!Number.isFinite(expirationSeconds)) {
    return fixedFailure('Invalid phase 1 cookie continuity');
  }

  return Object.freeze({
    ...completeMetadata,
    expires: Object.freeze({
      $timestamp: expirationSeconds,
      $toleranceSeconds: boundedTimestampToleranceSeconds,
    }),
    ...(responseDateSeconds === undefined
      ? {}
      : expirationSeconds === 0 && expirationSeconds <= responseDateSeconds
        ? { expiredAtResponse: true as const }
        : { expiryOffsetSeconds: expirationSeconds - responseDateSeconds }),
  });
};

const normalizeHeadersValue = (
  input: HeaderInput,
  context: NormalizationContext,
  options: Readonly<{ bodyByteLength?: number; body?: JsonValue }> = {}
): Phase1HeaderMultimap => {
  try {
    const result: Record<string, JsonValue[]> = {};
    const pairs = headerPairs(input);
    const cookieValues = pairs
      .filter(([name]) => name.toLowerCase() === 'set-cookie')
      .map(([, value]) => rawCookieValue(value));
    const responseDates = pairs
      .filter(([name]) => name.toLowerCase() === 'date')
      .map(([, value]) => Date.parse(value) / 1000);
    const responseDateSeconds =
      responseDates.length === 1 && Number.isFinite(responseDates[0])
        ? responseDates[0]
        : undefined;

    for (const [rawName, rawValue] of pairs) {
      if (typeof rawName !== 'string' || typeof rawValue !== 'string') {
        return fixedFailure('Invalid phase 1 headers');
      }
      const name = projectRequestIdHeaderName(rawName.toLowerCase(), context);
      if (name === 'vary') {
        const value = normalizeVaryHeader(rawValue);

        if (value !== undefined) {
          result[name] = [...(result[name] ?? []), value];
        }
        continue;
      }
      if (name === 'link') {
        result[name] = [...(result[name] ?? []), ...normalizeLinkHeader(rawValue, context)];
        continue;
      }
      const value: JsonValue =
        name === 'access-control-allow-origin'
          ? normalizeCorsOrigin(rawValue, context)
          : name === 'set-cookie'
            ? parseJson(
                normalizeCookieMetadata(
                  normalizeRawSetCookie(rawValue),
                  responseDateSeconds,
                  context.nativeSurfaceImplementation
                ),
                'Invalid phase 1 Set-Cookie header'
              )
            : name === 'location'
              ? parseJson(
                  (() => {
                    try {
                      return normalizeResumeRedirect(rawValue, context);
                    } catch {
                      return normalizeRedirect(rawValue, context);
                    }
                  })(),
                  'Invalid phase 1 Location header'
                )
              : name === 'date'
                ? normalizeDateHeader(rawValue)
                : name === 'content-length'
                  ? normalizeContentLength(rawValue, options.bodyByteLength)
                  : name === 'etag'
                    ? normalizeEntityTag(rawValue, options.body)
                    : name === asterNativeSurfaceContract.markers.requestIdHeader.candidate
                      ? normalizeCoreRequestId(rawValue)
                      : name === 'www-authenticate' || name === 'proxy-authenticate'
                        ? normalizeAuthChallenge(rawValue, context)
                        : isPhase1CredentialKey(name)
                          ? '<redacted-header-value>'
                          : rawValue;
      result[name] = [...(result[name] ?? []), value];
    }

    const normalized = Object.freeze(
      Object.fromEntries(
        Object.entries(result)
          .toSorted(([left], [right]) => compareText(left, right))
          .map(([name, values]) => [name, Object.freeze(values)])
      )
    );
    assertCookieValuesAbsent(parseJson(normalized, 'Invalid phase 1 headers'), cookieValues);

    return normalized;
  } catch {
    return fixedFailure('Invalid phase 1 headers');
  }
};

export const normalizeHeaders = Object.freeze(
  // eslint-disable-next-line @silverhand/fp/no-mutating-assign -- Keep the credential classifier attached to the existing reviewed normalizer export instead of widening the exact module authority surface.
  Object.assign(normalizeHeadersValue, {
    isCredentialKey: isPhase1CredentialKey,
    assertCredentialFreeUrlValue,
  })
);

const normalizeClaimObject = (
  claims: JsonObject,
  context: NormalizationContext,
  options: Readonly<{
    tokenKind: 'id-token' | 'access-token';
    profile: 'jwt' | 'userinfo';
    boundedPaths: readonly string[];
  }>
): JsonObject => {
  const { tokenKind, profile, boundedPaths } = options;
  const allowedFields =
    profile === 'userinfo' ? allowedUserInfoTimestampFields : allowedJwtTimestampFields;
  const timestampPatterns = parseBoundedTimestampPaths(
    boundedPaths,
    allowedFields,
    'Invalid phase 1 claims'
  );

  if (timestampPatterns.some((pattern) => pattern.length !== 1)) {
    return fixedFailure('Invalid phase 1 claims');
  }
  const timestampFields = new Set(timestampPatterns.map(([field]) => field));
  const normalized = Object.fromEntries(
    Object.entries(claims).flatMap(([key, rawValue]) => {
      if (ephemeralCredentialKeyPattern.test(key)) {
        return [];
      }
      if (isPhase1CredentialKey(key)) {
        return fixedFailure('Invalid phase 1 claims');
      }
      if (timestampFields.has(key)) {
        if (typeof rawValue !== 'number' || !Number.isFinite(rawValue)) {
          return fixedFailure('Invalid phase 1 claims');
        }
        const profileTimestamp = allowedUserInfoTimestampFields.has(key);
        const profileImplementation =
          profileTimestamp && (profile === 'userinfo' || tokenKind === 'id-token')
            ? nativeSurfaceImplementation(context)
            : undefined;

        if (
          profileImplementation !== undefined &&
          !isValidProfileTimestamp(rawValue, profileImplementation)
        ) {
          return fixedFailure('Invalid phase 1 claims');
        }
        const timestamp =
          profileTimestamp && profileImplementation !== 'candidate'
            ? Math.floor(rawValue / 1000)
            : rawValue;

        return [
          [
            key,
            {
              $timestamp: timestamp,
              $toleranceSeconds: boundedTimestampToleranceSeconds,
            },
          ],
        ];
      }
      if (['sid', 'jti'].includes(key) && typeof rawValue === 'string') {
        return [[key, bindGenerated(`${tokenKind}.${key}`, rawValue, context)]];
      }
      if (key === 'iss' && typeof rawValue === 'string') {
        const normalizedIssuer = normalizeExactLogicalJson(rawValue, context, [key]);

        return typeof normalizedIssuer === 'string'
          ? [[key, normalizeConfiguredTargetUrl(normalizedIssuer, context)]]
          : fixedFailure('Invalid phase 1 claims');
      }
      if (key === 'aud') {
        return [[key, normalizeAudience(rawValue, context)]];
      }
      if (key === 'scope' && typeof rawValue === 'string') {
        return [[key, normalizeBoundScopeTokens(rawValue, context)]];
      }

      return [[key, stableJson(normalizeExactLogicalJson(rawValue, context, [key]))]];
    })
  );

  if (
    profile === 'jwt' &&
    typeof claims.iat === 'number' &&
    Number.isFinite(claims.iat) &&
    typeof claims.exp === 'number' &&
    Number.isFinite(claims.exp)
  ) {
    if (Object.hasOwn(claims, 'tokenLifetimeSeconds')) {
      return fixedFailure('Invalid phase 1 claims');
    }
    normalized.tokenLifetimeSeconds = claims.exp - claims.iat;
  }

  return normalized;
};

export const normalizeClaims = (
  value: unknown,
  context: NormalizationContext,
  tokenKind: 'id-token' | 'access-token' = 'access-token',
  options: Readonly<{
    profile?: 'jwt' | 'userinfo';
    boundedTimestampPaths?: readonly string[];
  }> = {}
): JsonObject => {
  const parsed = parseJson(value, 'Invalid phase 1 claims');

  if (!isObject(parsed)) {
    return fixedFailure('Invalid phase 1 claims');
  }

  return normalizeClaimObject(parsed, context, {
    tokenKind,
    profile: options.profile ?? 'jwt',
    boundedPaths: options.boundedTimestampPaths ?? [],
  });
};

export const normalizeConcurrentOutcomes = (
  value: unknown,
  context: NormalizationContext
): readonly JsonValue[] => {
  const parsed = parseJson(value, 'Invalid phase 1 concurrent outcomes');

  if (!Array.isArray(parsed)) {
    return fixedFailure('Invalid phase 1 concurrent outcomes');
  }
  const outcomes = parsed.map((item) => stableJson(normalizeExactLogicalJson(item, context)));
  const keyed = outcomes.map((outcome) => {
    if (!isObject(outcome) || typeof outcome.kind !== 'string' || outcome.kind.length === 0) {
      return fixedFailure('Invalid phase 1 concurrent outcomes');
    }

    return { kind: outcome.kind, outcome };
  });

  return Object.freeze(
    keyed
      .toSorted((left, right) => compareText(left.kind, right.kind))
      .map(({ outcome }) => outcome)
  );
};

export const normalizeCookieContinuity = (
  value: unknown,
  options: Readonly<{
    responseDateSeconds?: number;
    requireExpiryOffset?: boolean;
    nativeSurfaceImplementation?: Phase1Implementation;
  }> = {}
): readonly Phase1CookieMetadata[] => {
  try {
    if (!Array.isArray(value)) {
      return fixedFailure('Invalid phase 1 cookie continuity');
    }
    const cookies = value.every((item) => typeof item === 'string')
      ? value.map((header) => normalizeRawSetCookie(header))
      : z.array(cookieMetadataGuard).parse(parseJson(value, 'Invalid phase 1 cookie continuity'));
    const normalized = Object.freeze(
      cookies.map((cookie) =>
        normalizeCookieMetadata(
          cookie,
          options.responseDateSeconds,
          options.nativeSurfaceImplementation
        )
      )
    );
    if (
      options.requireExpiryOffset === true &&
      options.responseDateSeconds === undefined &&
      cookies.some((cookie) => cookie.expires !== undefined && cookie.maxAge === undefined)
    ) {
      return fixedFailure('Invalid phase 1 cookie continuity');
    }
    const cookieValues = value.every((item) => typeof item === 'string')
      ? value.map((header) => rawCookieValue(header))
      : [];
    assertCookieValuesAbsent(
      parseJson(normalized, 'Invalid phase 1 cookie continuity'),
      cookieValues
    );

    return normalized;
  } catch {
    return fixedFailure('Invalid phase 1 cookie continuity');
  }
};

export const normalizeDiscovery = (value: unknown, context: NormalizationContext): JsonObject => {
  const parsed = parseJson(value, 'Invalid phase 1 discovery');

  if (!isObject(parsed)) {
    return fixedFailure('Invalid phase 1 discovery');
  }
  const normalized = (() => {
    if (!Object.hasOwn(parsed, 'scopes_supported')) {
      return parsed;
    }
    const scopes = parsed.scopes_supported;

    if (!Array.isArray(scopes) || !scopes.every((scope) => typeof scope === 'string')) {
      return fixedFailure('Invalid phase 1 discovery');
    }

    return {
      ...parsed,
      scopes_supported: scopes.map((scope) =>
        projectKnownNativeSurfaceValue(scope, nativeScopeMarkerIds, context)
      ),
    };
  })();

  if (!Object.hasOwn(normalized, 'keys')) {
    return stableJson(normalized) as JsonObject;
  }
  if (!Array.isArray(normalized.keys)) {
    return fixedFailure('Invalid phase 1 discovery');
  }
  const thumbprintMembers = Object.freeze({
    EC: ['crv', 'kty', 'x', 'y'],
    OKP: ['crv', 'kty', 'x'],
    RSA: ['e', 'kty', 'n'],
  } as const);
  const keys = normalized.keys.map((rawKey) => {
    if (!isObject(rawKey) || Object.hasOwn(rawKey, 'publicKeyFingerprint')) {
      return fixedFailure('Invalid phase 1 discovery');
    }
    const { kty } = rawKey;

    if (typeof kty !== 'string' || !(kty in thumbprintMembers)) {
      return fixedFailure('Invalid phase 1 discovery');
    }
    if (Object.keys(rawKey).some((key) => privateJwkMembers.has(key))) {
      return fixedFailure('Invalid phase 1 discovery');
    }
    const members = thumbprintMembers[kty as keyof typeof thumbprintMembers];
    const canonical = Object.fromEntries(
      members.map((member) => {
        const memberValue = rawKey[member];

        return typeof memberValue === 'string' && memberValue.length > 0
          ? [member, memberValue]
          : fixedFailure('Invalid phase 1 discovery');
      })
    );
    const { kid } = rawKey;

    if (kid !== undefined && typeof kid !== 'string') {
      return fixedFailure('Invalid phase 1 discovery');
    }

    const keyMaterialMembers = new Set<string>(
      kty === 'EC' ? ['x', 'y'] : kty === 'OKP' ? ['x'] : ['n']
    );
    const publicMetadata = Object.fromEntries(
      Object.entries(rawKey).filter(([member]) => !keyMaterialMembers.has(member))
    );
    const publicKeyBitLength = (() => {
      if (kty !== 'RSA') {
        return;
      }
      const modulus = rawKey.n;

      if (typeof modulus !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(modulus)) {
        return fixedFailure('Invalid phase 1 discovery');
      }
      const bytes = Buffer.from(modulus, 'base64url');
      const leading = bytes[0];

      if (
        bytes.length === 0 ||
        leading === undefined ||
        leading === 0 ||
        bytes.toString('base64url') !== modulus
      ) {
        return fixedFailure('Invalid phase 1 discovery');
      }

      return (bytes.length - 1) * 8 + Math.floor(Math.log2(leading)) + 1;
    })();
    const fingerprint = createHash('sha256').update(JSON.stringify(canonical)).digest('base64url');

    return {
      ...publicMetadata,
      ...(kid === undefined ? {} : { kid: bindGenerated('signing-key.kid', kid, context) }),
      ...(publicKeyBitLength === undefined ? {} : { publicKeyBitLength }),
      publicKeyFingerprint: bindGenerated(
        'signing-key.public-key-fingerprint',
        `public-key-fingerprint:${fingerprint}`,
        context
      ),
    };
  });

  return stableJson({ ...normalized, keys }) as JsonObject;
};

const normalizeError = (value: unknown, message: string): JsonObject => {
  const parsed = parseJson(value, message);

  if (!isObject(parsed)) {
    return fixedFailure(message);
  }

  const redact = (nested: JsonValue, key = ''): JsonValue => {
    if (isPhase1CredentialKey(key)) {
      return '<redacted-error-field>';
    }
    if (typeof nested === 'string') {
      try {
        assertEvidenceIsSanitized({ value: nested });
        return redirectCredentialFragmentPattern.test(nested) ? '<redacted-error-value>' : nested;
      } catch {
        return '<redacted-error-value>';
      }
    }
    if (Array.isArray(nested)) {
      return nested.map((item) => redact(item));
    }
    if (isObject(nested)) {
      return Object.fromEntries(
        Object.entries(nested).flatMap(([nestedKey, item]) => {
          if (ephemeralCredentialKeyPattern.test(nestedKey)) {
            return [];
          }

          return nestedKey === 'code'
            ? [['errorCode', redact(item)]]
            : [[nestedKey, redact(item, nestedKey)]];
        })
      );
    }
    return nested;
  };

  return Object.fromEntries(
    Object.entries(parsed).flatMap(([key, nested]) => {
      if (ephemeralCredentialKeyPattern.test(key)) {
        return [];
      }

      return key === 'code' ? [['errorCode', redact(nested)]] : [[key, redact(nested, key)]];
    })
  );
};

export const normalizeExperienceError = (value: unknown): JsonObject =>
  normalizeError(value, 'Invalid phase 1 experience error');

export const normalizeOAuthError = (value: unknown): JsonObject =>
  normalizeError(value, 'Invalid phase 1 OAuth error');

export const normalizeLogicalFixtureIds = (
  value: unknown,
  context: NormalizationContext,
  options: Readonly<{ boundedTimestampPaths?: readonly string[] }> = {}
): JsonValue => {
  const timestampPatterns = parseBoundedTimestampPaths(
    options.boundedTimestampPaths ?? [],
    entityTimestampFields,
    'Invalid phase 1 fixture IDs'
  );

  return stableJson(
    normalizeExactLogicalJson(
      parseJson(value, 'Invalid phase 1 fixture IDs'),
      context,
      [],
      timestampPatterns
    )
  );
};

const normalizeCompactToken = (
  token: string,
  context: NormalizationContext,
  tokenKind: 'id-token' | 'access-token',
  boundedTimestampPaths: readonly string[]
): JsonValue => {
  // Signature verification is enforced by the token projector before this pure decoder runs.
  if (token.split('.').length !== 3) {
    return { format: 'opaque', characterCount: token.length };
  }
  const decodedHeader = (() => {
    try {
      return decodeProtectedHeader(token);
    } catch {
      return null;
    }
  })();

  if (decodedHeader === null) {
    return { format: 'opaque', characterCount: token.length };
  }
  const header = parseJson(decodedHeader, 'Invalid phase 1 token header');

  if (!isObject(header)) {
    return fixedFailure('Invalid phase 1 token header');
  }
  if (
    header.jwk !== undefined &&
    (!isObject(header.jwk) || Object.keys(header.jwk).some((key) => privateJwkMembers.has(key)))
  ) {
    return fixedFailure('Invalid phase 1 token header');
  }
  try {
    const normalizedHeader = Object.fromEntries(
      Object.entries(header).map(([key, rawValue]) => [
        key,
        key === 'kid' && typeof rawValue === 'string'
          ? bindGenerated('signing-key.kid', rawValue, context)
          : stableJson(normalizeExactLogicalJson(rawValue, context, [key])),
      ])
    );

    return {
      format: 'jwt',
      header: normalizedHeader,
      claims: normalizeClaims(decodeJwt(token), context, tokenKind, { boundedTimestampPaths }),
    };
  } catch {
    return fixedFailure('Invalid phase 1 token response');
  }
};

const tokenCredentialFieldPattern =
  /(?:secret|password|credential|assertion|authorization|cookie|code|state|session|token|nonce|verifier|challenge)$/iu;

const redactedTokenField = (name: string, value: JsonValue): JsonObject => ({
  name,
  present: true,
  ...(typeof value === 'string' ? { characterCount: value.length } : {}),
});

export const normalizeTokenResponse = (
  value: unknown,
  context: NormalizationContext,
  options: Readonly<{ boundedClaimTimestampPaths?: readonly string[] }> = {}
): JsonObject => {
  const parsed = parseJson(value, 'Invalid phase 1 token response');

  if (!isObject(parsed)) {
    return fixedFailure('Invalid phase 1 token response');
  }
  const normalized: JsonObject = {};
  const additionalFields: JsonValue[] = [];

  for (const [key, rawValue] of Object.entries(parsed)) {
    switch (key) {
      case 'access_token': {
        if (typeof rawValue !== 'string' || rawValue.length === 0) {
          return fixedFailure('Invalid phase 1 token response');
        }
        normalized.access = normalizeCompactToken(
          rawValue,
          context,
          'access-token',
          options.boundedClaimTimestampPaths ?? []
        );
        break;
      }
      case 'id_token': {
        if (typeof rawValue !== 'string' || rawValue.length === 0) {
          return fixedFailure('Invalid phase 1 token response');
        }
        normalized.id = normalizeCompactToken(
          rawValue,
          context,
          'id-token',
          options.boundedClaimTimestampPaths ?? []
        );
        break;
      }
      case 'refresh_token': {
        if (typeof rawValue !== 'string' || rawValue.length === 0) {
          return fixedFailure('Invalid phase 1 token response');
        }
        normalized.refresh = { present: true, characterCount: rawValue.length };
        break;
      }
      case 'token_type': {
        if (typeof rawValue !== 'string') {
          return fixedFailure('Invalid phase 1 token response');
        }
        normalized.tokenType = rawValue;
        break;
      }
      case 'expires_in': {
        if (typeof rawValue !== 'number' || !Number.isFinite(rawValue)) {
          return fixedFailure('Invalid phase 1 token response');
        }
        normalized.expiresIn = rawValue;
        break;
      }
      case 'scope': {
        if (typeof rawValue !== 'string') {
          return fixedFailure('Invalid phase 1 token response');
        }
        normalized.scope = normalizeBoundScopeTokens(rawValue, context);
        break;
      }
      default: {
        additionalFields.push(
          tokenCredentialFieldPattern.test(key)
            ? redactedTokenField(key, rawValue)
            : {
                name: key,
                value: stableJson(normalizeExactLogicalJson(rawValue, context, [key])),
              }
        );
      }
    }
  }
  if (additionalFields.length > 0) {
    normalized.additionalFields = additionalFields;
  }

  return normalized;
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
