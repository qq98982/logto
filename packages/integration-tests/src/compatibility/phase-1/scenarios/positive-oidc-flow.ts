/* eslint-disable max-lines, complexity, no-restricted-syntax, no-control-regex, @typescript-eslint/ban-types, max-params -- The reviewed positive authorization flow keeps one cookie jar, secret lease, redirect validator, bounded validation expressions, and ordered projection list in a single auditable boundary. */
import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue, NormalizationContext } from '../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimePhone,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { createPhase1NormalizationContext } from '../native-surface-profile.js';
import { normalizeLogicalFixtureIds, normalizeOAuthError } from '../normalizers.js';
import {
  projectAuthorizationObservation,
  projectConsentObservation,
  projectRedirectObservation,
  projectSemanticStateObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from '../projections/index.js';

import {
  exchangePositiveAuthorizationCodeRequest,
  projectRejectedPositiveAuthorizationCodeRequest,
  type PositiveOidcTokenGrant,
  withPositiveOidcAuthorizationCodeRequest,
} from './positive-oidc-token.js';

const scenarioId = 'authorization.password-pkce-consent';
const jsonContentType = 'application/json';
const codeVerifierPattern = /^[A-Za-z0-9._~-]{43,128}$/u;

export type PositiveOidcFlowRandomSource = Readonly<{
  codeVerifier(): string;
  state(): string;
}>;

type PositiveOidcAuthorizationCredentials = Readonly<{
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  resource?: string;
}>;

export type PositiveOidcAuthorizationGrant = Readonly<{ toJSON(): never }>;

class PositiveOidcAuthorizationGrantAuthority implements PositiveOidcAuthorizationGrant {
  constructor(credentials: PositiveOidcAuthorizationCredentials) {
    authorizationGrantCredentials.set(this, Object.freeze({ ...credentials }));
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError('Phase 1 authorization grant is not serializable');
  }
}

const authorizationGrantCredentials = new WeakMap<
  PositiveOidcAuthorizationGrant,
  PositiveOidcAuthorizationCredentials
>();

Object.freeze(PositiveOidcAuthorizationGrantAuthority.prototype);

const createPositiveOidcAuthorizationGrant = (
  credentials: PositiveOidcAuthorizationCredentials
): PositiveOidcAuthorizationGrant => new PositiveOidcAuthorizationGrantAuthority(credentials);

const readPositiveOidcAuthorizationGrant = (
  grant: PositiveOidcAuthorizationGrant
): PositiveOidcAuthorizationCredentials => {
  const credentials = authorizationGrantCredentials.get(grant);

  if (!credentials) {
    throw new TypeError('Invalid Phase 1 authorization grant');
  }

  return credentials;
};

const revokePositiveOidcAuthorizationGrant = (grant: PositiveOidcAuthorizationGrant): void => {
  authorizationGrantCredentials.delete(grant);
};

export const assertPositiveOidcAuthorizationGrantActive = (
  grant: PositiveOidcAuthorizationGrant
): void => {
  readPositiveOidcAuthorizationGrant(grant);
};

export const withSyntheticPositiveOidcAuthorizationGrant = async <Result>(
  input: Readonly<{ clientId: string; redirectUri: string; resource?: string }>,
  consume: (grant: PositiveOidcAuthorizationGrant) => Promise<Result>
): Promise<Result> => {
  const grant = createPositiveOidcAuthorizationGrant({
    ...input,
    code: randomBytes(32).toString('base64url'),
    codeVerifier: randomBytes(48).toString('base64url'),
  });

  try {
    return await consume(grant);
  } finally {
    revokePositiveOidcAuthorizationGrant(grant);
  }
};

export type PositiveOidcAuthorizationCodeResponseOptions = Readonly<{
  verifier?: 'correct' | 'mismatch';
  operation?: string;
}>;

const mismatchedVerifier = (value: string): string =>
  `${value.startsWith('x') ? 'y' : 'x'}${value.slice(1)}`;

const positiveOidcAuthorizationCodeRequest = (
  grant: PositiveOidcAuthorizationGrant,
  options: PositiveOidcAuthorizationCodeResponseOptions = {}
) => {
  const credentials = readPositiveOidcAuthorizationGrant(grant);
  const verifier =
    options.verifier === 'mismatch'
      ? mismatchedVerifier(credentials.codeVerifier)
      : credentials.codeVerifier;

  return Object.freeze({
    operation: options.operation ?? 'token-authorization-code',
    clientId: credentials.clientId,
    code: credentials.code,
    verifier,
    redirectUri: credentials.redirectUri,
    ...(credentials.resource === undefined ? {} : { resource: credentials.resource }),
  });
};

export const exchangePositiveAuthorizationCode = async (
  context: Phase1ScenarioRunContext,
  grant: PositiveOidcAuthorizationGrant,
  options: PositiveOidcAuthorizationCodeResponseOptions = {}
): Promise<PositiveOidcTokenGrant> => {
  return withPositiveOidcAuthorizationCodeRequest(
    context,
    positiveOidcAuthorizationCodeRequest(grant, options),
    async (request) => exchangePositiveAuthorizationCodeRequest(context, request)
  );
};

export const projectRejectedPositiveAuthorizationCode = async (
  context: Phase1ScenarioRunContext,
  grant: PositiveOidcAuthorizationGrant,
  options: PositiveOidcAuthorizationCodeResponseOptions,
  readState: () => Promise<Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>>,
  normalizationContext: NormalizationContext
): Promise<Phase1HttpProjection> => {
  return withPositiveOidcAuthorizationCodeRequest(
    context,
    positiveOidcAuthorizationCodeRequest(grant, options),
    async (request) =>
      projectRejectedPositiveAuthorizationCodeRequest(
        context,
        request,
        readState,
        normalizationContext
      )
  );
};

export type PositiveOidcFlowOptions = Readonly<{
  random?: PositiveOidcFlowRandomSource;
  includeResource?: boolean;
  captureSteps?: boolean;
  expectOidcConsentAlreadyGranted?: boolean;
}>;

export type PositiveOidcAuthorizationRequestOptions = Readonly<{
  random?: PositiveOidcFlowRandomSource;
  includeResource?: boolean;
  includeState?: boolean;
  redirectUri?: string;
  codeChallengeMethod?: string;
  operation?: string;
}>;

export type PositiveOidcFlowOutput<Result> = Readonly<{
  steps: readonly Phase1ScenarioStepResult[];
  result: Result;
}>;

const defaultRandomSource: PositiveOidcFlowRandomSource = Object.freeze({
  codeVerifier: () => randomBytes(48).toString('base64url'),
  state: () => randomBytes(32).toString('base64url'),
});

const requireText = (value: unknown, diagnostic: string): string => {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new Error(diagnostic);
  }

  return value;
};

const requireJsonObject = (value: string, diagnostic: string): JsonObject => {
  try {
    const parsed: unknown = JSON.parse(value);

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      Array.isArray(parsed) ||
      !jsonValueGuard.safeParse(parsed).success
    ) {
      throw new TypeError('invalid JSON object');
    }

    return parsed as JsonObject;
  } catch {
    throw new Error(diagnostic);
  }
};

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

const requireEmptyBody = (value: string, diagnostic: string): null => {
  if (value.length > 0) {
    throw new Error(diagnostic);
  }

  return null;
};

const headerValues = (
  headers: ReadonlyArray<readonly [string, string]>,
  name: string
): readonly string[] =>
  headers.filter(([candidate]) => candidate.toLowerCase() === name).map(([, value]) => value);

const requireStatus = <Response extends Readonly<{ status: number }>>(
  response: Response,
  expected: number,
  diagnostic: string
): Response => {
  if (response.status !== expected) {
    throw new Error(diagnostic);
  }

  return response;
};

const requireJsonContentType = (
  headers: ReadonlyArray<readonly [string, string]>,
  diagnostic: string
): void => {
  const values = headerValues(headers, 'content-type').map(
    (value) => value.split(';', 1)[0]?.trim().toLowerCase() ?? ''
  );

  if (values.length !== 1 || values[0] !== jsonContentType) {
    throw new Error(diagnostic);
  }
};

const requireLocation = (
  headers: ReadonlyArray<readonly [string, string]>,
  baseUrl: string,
  diagnostic: string
): string => {
  const locations = headerValues(headers, 'location');

  if (locations.length !== 1 || !locations[0]) {
    throw new Error(diagnostic);
  }
  try {
    const url = new URL(locations[0], baseUrl);

    if (url.username.length > 0 || url.password.length > 0) {
      throw new TypeError('credential-bearing location');
    }

    return url.href;
  } catch {
    throw new Error(diagnostic);
  }
};

export const absolutePositiveOidcLocationHeaders = (
  headers: ReadonlyArray<readonly [string, string]>,
  baseUrl: string,
  diagnostic: string
): ReadonlyArray<readonly [string, string]> => {
  const absolute = requireLocation(headers, baseUrl, diagnostic);

  return Object.freeze(
    headers.map(([name, value]) =>
      name.toLowerCase() === 'location'
        ? Object.freeze([name, absolute] as const)
        : Object.freeze([name, value] as const)
    )
  );
};

const replaceLocationHeader = (
  headers: ReadonlyArray<readonly [string, string]>,
  location: string
): ReadonlyArray<readonly [string, string]> =>
  Object.freeze(
    headers.map(([name, value]) =>
      Object.freeze([name, name.toLowerCase() === 'location' ? location : value] as const)
    )
  );

const htmlEscape = (value: string): string =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

export const normalizePositiveOidcRedirectBody = (
  body: string,
  headers: ReadonlyArray<readonly [string, string]>,
  resolvedLocation: string,
  diagnostic: string
): JsonValue => {
  if (body.length === 0) {
    return null;
  }
  const [rawLocation] = headerValues(headers, 'location');

  if (!rawLocation) {
    throw new Error(diagnostic);
  }
  const decodedLocation = (() => {
    try {
      return decodeURI(rawLocation);
    } catch {
      return rawLocation;
    }
  })();
  const candidates = [rawLocation, decodedLocation, resolvedLocation]
    .flatMap((value) => [value, htmlEscape(value)])
    .filter((value, index, values) => value.length > 0 && values.indexOf(value) === index)
    .toSorted((left, right) => right.length - left.length);
  const normalized = candidates.reduce(
    (value, candidate) => value.replaceAll(candidate, '<response-location>'),
    body
  );

  if (normalized === body) {
    throw new Error(diagnostic);
  }

  return normalized;
};

type ParsedSetCookie = Readonly<{
  name: string;
  rawValue: string;
  unquotedValue: string;
  attributes: string;
}>;

const parseSetCookieHeader = (header: string): ParsedSetCookie => {
  if (/[\u0000-\u001F\u007F]/u.test(header)) {
    throw new Error('Phase 1 response cookie is invalid');
  }
  const attributeOffset = header.indexOf(';');
  const pair = attributeOffset < 0 ? header : header.slice(0, attributeOffset);
  const attributes = attributeOffset < 0 ? '' : header.slice(attributeOffset);
  const separator = pair.indexOf('=');

  if (separator < 1) {
    throw new Error('Phase 1 response cookie is invalid');
  }
  const name = pair.slice(0, separator);
  const rawValue = pair.slice(separator + 1).trim();
  const unquotedValue =
    rawValue.startsWith('"') && rawValue.endsWith('"') ? rawValue.slice(1, -1) : rawValue;

  return Object.freeze({ name, rawValue, unquotedValue, attributes });
};

const maximumCookieCredentialDecodeDepth = 6;

const decodedCredentialCandidates = (
  value: string,
  remainingDepth = maximumCookieCredentialDecodeDepth
): readonly string[] => {
  const decoded = decodeCookiePercentLayer(value);

  return remainingDepth === 0 || decoded === value
    ? [value]
    : [value, ...decodedCredentialCandidates(decoded, remainingDepth - 1)];
};

const revealsCookieCredential = (value: string, credentials: readonly string[]): boolean => {
  const candidates = credentials
    .flatMap((credential) => decodedCredentialCandidates(credential))
    .filter(
      (credential, index, values) => credential.length > 0 && values.indexOf(credential) === index
    );

  return decodedCredentialCandidates(value).some((decoded) =>
    candidates.some((credential) => decoded.includes(credential))
  );
};

/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The bounded percent decoder uses local cursors and arrays to preserve exact raw attribute spans in one linear pass per decode layer. */
type MappedCookieAttributeCharacter = Readonly<{
  value: string;
  start: number;
  end: number;
}>;

type CookieAttributeSpan = Readonly<{ start: number; end: number }>;

const percentHexDigitPattern = /^[\dA-F]$/iu;
const strictUtf8Decoder = new TextDecoder('utf8', { fatal: true });

const createMappedCookieAttributeCharacters = (
  value: string
): readonly MappedCookieAttributeCharacter[] => {
  const result: MappedCookieAttributeCharacter[] = [];
  let offset = 0;

  while (offset < value.length) {
    const codePoint = value.codePointAt(offset);

    if (codePoint === undefined) {
      throw new Error('Phase 1 response cookie is invalid');
    }
    const character = String.fromCodePoint(codePoint);
    result.push(Object.freeze({ value: character, start: offset, end: offset + character.length }));
    offset += character.length;
  }

  return Object.freeze(result);
};

const isPercentTripletAt = (
  characters: readonly MappedCookieAttributeCharacter[],
  index: number
): boolean =>
  characters[index]?.value === '%' &&
  percentHexDigitPattern.test(characters[index + 1]?.value ?? '') &&
  percentHexDigitPattern.test(characters[index + 2]?.value ?? '');

type PercentTriplet = Readonly<{
  byte: number;
  characters: readonly [
    MappedCookieAttributeCharacter,
    MappedCookieAttributeCharacter,
    MappedCookieAttributeCharacter,
  ];
}>;

const readPercentTripletRun = (
  characters: readonly MappedCookieAttributeCharacter[],
  start: number
): Readonly<{ next: number; triplets: readonly PercentTriplet[] }> => {
  const triplets: PercentTriplet[] = [];
  let index = start;

  while (isPercentTripletAt(characters, index)) {
    const first = characters[index];
    const high = characters[index + 1];
    const low = characters[index + 2];

    if (!first || !high || !low) {
      throw new Error('Phase 1 response cookie is invalid');
    }
    triplets.push(
      Object.freeze({
        byte: Number.parseInt(`${high.value}${low.value}`, 16),
        characters: Object.freeze([first, high, low] as const),
      })
    );
    index += 3;
  }

  return Object.freeze({ next: index, triplets: Object.freeze(triplets) });
};

const utf8SequenceLength = (lead: number): number => {
  if (lead <= 0x7f) {
    return 1;
  }
  if (lead >= 0xc2 && lead <= 0xdf) {
    return 2;
  }
  if (lead >= 0xe0 && lead <= 0xef) {
    return 3;
  }
  if (lead >= 0xf0 && lead <= 0xf4) {
    return 4;
  }

  return 0;
};

const decodePercentTripletRun = (
  triplets: readonly PercentTriplet[]
): Readonly<{ characters: readonly MappedCookieAttributeCharacter[]; changed: boolean }> => {
  const result: MappedCookieAttributeCharacter[] = [];
  let changed = false;
  let offset = 0;

  while (offset < triplets.length) {
    const first = triplets[offset];

    if (!first) {
      throw new Error('Phase 1 response cookie is invalid');
    }
    const sequenceLength = utf8SequenceLength(first.byte);
    const sequence = triplets.slice(offset, offset + sequenceLength);
    const last = sequence.at(-1);
    let decoded: string | undefined;

    if (sequenceLength > 0 && sequence.length === sequenceLength && last) {
      try {
        const value = strictUtf8Decoder.decode(Uint8Array.from(sequence.map(({ byte }) => byte)));

        if ([...value].length === 1) {
          decoded = value;
        }
      } catch {
        // Preserve the invalid triplet and continue with the next byte in the same run.
      }
    }
    if (decoded === undefined || !last) {
      result.push(...first.characters);
      offset += 1;
      continue;
    }
    result.push(
      Object.freeze({
        value: decoded,
        start: first.characters[0].start,
        end: last.characters[2].end,
      })
    );
    changed = true;
    offset += sequenceLength;
  }

  return Object.freeze({ characters: Object.freeze(result), changed });
};

const decodeMappedCookieAttributeCharacters = (
  characters: readonly MappedCookieAttributeCharacter[]
): readonly MappedCookieAttributeCharacter[] | undefined => {
  const result: MappedCookieAttributeCharacter[] = [];
  let changed = false;
  let index = 0;

  while (index < characters.length) {
    if (!isPercentTripletAt(characters, index)) {
      const character = characters[index];

      if (!character) {
        throw new Error('Phase 1 response cookie is invalid');
      }
      result.push(character);
      index += 1;
      continue;
    }
    const run = readPercentTripletRun(characters, index);
    const decoded = decodePercentTripletRun(run.triplets);

    result.push(...decoded.characters);
    changed ||= decoded.changed;
    index = run.next;
  }

  return changed ? Object.freeze(result) : undefined;
};

const decodeCookiePercentLayer = (value: string): string => {
  const decoded = decodeMappedCookieAttributeCharacters(
    createMappedCookieAttributeCharacters(value)
  );

  return decoded?.map((character) => character.value).join('') ?? value;
};

const createMappedCookieAttributeViews = (
  value: string
): ReadonlyArray<readonly MappedCookieAttributeCharacter[]> => {
  const views: Array<readonly MappedCookieAttributeCharacter[]> = [
    createMappedCookieAttributeCharacters(value),
  ];

  for (const _depth of Array.from({ length: maximumCookieCredentialDecodeDepth })) {
    const current = views.at(-1);

    if (!current) {
      throw new Error('Phase 1 response cookie is invalid');
    }
    const decoded = decodeMappedCookieAttributeCharacters(current);

    if (!decoded) {
      break;
    }
    views.push(decoded);
  }

  return Object.freeze(views);
};

const findCredentialSpans = (
  attributes: string,
  candidates: readonly string[]
): readonly CookieAttributeSpan[] => {
  const matches: CookieAttributeSpan[] = [];

  for (const characters of createMappedCookieAttributeViews(attributes)) {
    const offsets = new Map<number, number>();
    let text = '';

    for (const [index, character] of characters.entries()) {
      offsets.set(text.length, index);
      text += character.value;
    }
    offsets.set(text.length, characters.length);

    for (const candidate of candidates) {
      let searchOffset = 0;

      while (searchOffset <= text.length - candidate.length) {
        const found = text.indexOf(candidate, searchOffset);

        if (found < 0) {
          break;
        }
        const startIndex = offsets.get(found);
        const endIndex = offsets.get(found + candidate.length);
        const first = startIndex === undefined ? undefined : characters[startIndex];
        const last = endIndex === undefined ? undefined : characters[endIndex - 1];

        if (!first || !last) {
          throw new Error('Phase 1 response cookie is invalid');
        }
        if (candidate.length < 8) {
          throw new Error('Phase 1 response cookie is invalid');
        }
        matches.push(Object.freeze({ start: first.start, end: last.end }));
        searchOffset = found + candidate.length;
      }
    }
  }
  const ordered = matches.toSorted(
    (left, right) => left.start - right.start || right.end - left.end
  );
  const merged: CookieAttributeSpan[] = [];

  for (const match of ordered) {
    const previous = merged.at(-1);

    if (previous && match.start < previous.end) {
      merged[merged.length - 1] = Object.freeze({
        start: previous.start,
        end: Math.max(previous.end, match.end),
      });
    } else {
      merged.push(match);
    }
  }

  return Object.freeze(merged);
};

const sanitizeCookieAttributes = (attributes: string, credentials: readonly string[]): string => {
  const candidates = credentials
    .flatMap((credential) => decodedCredentialCandidates(credential))
    .filter(
      (credential, index, values) => credential.length > 0 && values.indexOf(credential) === index
    )
    .toSorted((left, right) => right.length - left.length);
  const matches = findCredentialSpans(attributes, candidates);

  if (matches.length === 0) {
    return attributes;
  }
  const sanitized = matches
    .toReversed()
    .reduce(
      (value, { start, end }) =>
        `${value.slice(0, start)}aster-cookie-attribute-value${value.slice(end)}`,
      attributes
    );

  if (revealsCookieCredential(sanitized, credentials)) {
    throw new Error('Phase 1 response cookie is invalid');
  }

  return sanitized;
};
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */

export const sanitizeSetCookieHeaders = (
  headers: ReadonlyArray<readonly [string, string]>,
  attributeCredentials: readonly string[] = []
): ReadonlyArray<readonly [string, string]> => {
  const parsedCookies = headers
    .filter(([name]) => name.toLowerCase() === 'set-cookie')
    .map(([, value]) => parseSetCookieHeader(value));
  const credentials = parsedCookies
    .flatMap(({ rawValue, unquotedValue }) => [rawValue, unquotedValue])
    .concat(attributeCredentials)
    .filter((value, index, values) => value.length > 0 && values.indexOf(value) === index)
    .toSorted((left, right) => right.length - left.length);

  const sanitized = Object.freeze(
    headers.map(([name, value]) => {
      if (name.toLowerCase() !== 'set-cookie') {
        return Object.freeze([name, value] as const);
      }
      const parsed = parseSetCookieHeader(value);
      const safeAttributes = sanitizeCookieAttributes(parsed.attributes, credentials);

      return Object.freeze([
        name,
        `${parsed.name}=aster-cookie-pair-value${safeAttributes}`,
      ] as const);
    })
  );

  if (
    sanitized.some(([name, value]) =>
      name.toLowerCase() === 'set-cookie' ? revealsCookieCredential(value, credentials) : false
    )
  ) {
    throw new Error('Phase 1 response cookie is invalid');
  }

  return sanitized;
};

const relativeOidcResumePath = (
  value: unknown,
  targetCoreUrl: string,
  diagnostic: string
): Readonly<{ path: string; credential: string }> => {
  try {
    const raw = requireText(value, diagnostic);
    const url = new URL(raw);
    const expectedOrigin = new URL(targetCoreUrl).origin;
    const segments = url.pathname.split('/');

    if (
      url.origin !== expectedOrigin ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      url.search.length > 0 ||
      url.hash.length > 0 ||
      segments.length !== 4 ||
      segments[1] !== 'oidc' ||
      segments[2] !== 'auth' ||
      !segments[3]
    ) {
      throw new TypeError('invalid resume URL');
    }
    const credential = decodeURIComponent(segments[3]);

    if (
      credential.length === 0 ||
      credential.includes('/') ||
      credential.includes('\\') ||
      /[\u0000-\u001F\u007F]/u.test(credential)
    ) {
      throw new TypeError('invalid resume credential');
    }

    return Object.freeze({ path: `oidc/auth/${segments[3]}`, credential });
  } catch {
    throw new Error(diagnostic);
  }
};

const jsonHeaders = Object.freeze([Object.freeze(['content-type', jsonContentType] as const)]);

const normalizationContext = (
  context: Phase1ScenarioRunContext,
  allocationId: string
): NormalizationContext => {
  const symbols = context.protocol.symbolsFor(allocationId);

  if (!symbols) {
    throw new Error('Phase 1 data allocation symbols are unavailable');
  }
  const { dataTenant } = context.profile.fixtures;
  const thirdParty = dataTenant.applications.find(({ isThirdParty }) => isThirdParty);
  const scope = dataTenant.resource.scopes[0];

  if (!thirdParty || !scope) {
    throw new Error('Phase 1 data fixture profile is invalid');
  }
  const bindings = [
    [
      'fixture.data.username',
      getPhase1FixtureRuntimeUsername(dataTenant.subject.username, allocationId),
    ],
    [
      'fixture.data.email',
      getPhase1FixtureRuntimeEmail(dataTenant.subject.primaryEmail, allocationId),
    ],
    ['fixture.data.phone', getPhase1FixtureRuntimePhone(allocationId)],
    ['fixture.data.application-name', getPhase1FixtureRuntimeText(thirdParty.name, allocationId)],
    [
      'fixture.data.resource-name',
      getPhase1FixtureRuntimeText(dataTenant.resource.name, allocationId),
    ],
    [
      'fixture.data.resource-indicator',
      getPhase1FixtureRuntimeResourceIndicator(dataTenant.resource.indicator, allocationId),
    ],
    ['fixture.data.scope-name', getPhase1FixtureRuntimeText(scope.name, allocationId)],
  ] as const;

  for (const [logicalName, runtimeValue] of bindings) {
    symbols.bind(logicalName, runtimeValue);
  }

  return createPhase1NormalizationContext(context.profile, context.target, symbols);
};

export const positiveOidcAuthorizationNormalizationContext = (
  context: Phase1ScenarioRunContext
): NormalizationContext => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');

  if (!allocation) {
    throw new Error('Phase 1 data allocation is unavailable');
  }

  return normalizationContext(context, allocation.allocationId);
};

const stateInput = async (context: Phase1ScenarioRunContext, stepId: string) =>
  context.projectScenarioState({ scenarioId, stepId, fixture: context.fixture });

const rawObservation = (
  response: Readonly<{
    status: number;
    headers: ReadonlyArray<readonly [string, string]>;
  }>,
  body: JsonValue,
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>,
  overrides: Partial<RawHttpObservation> = {},
  cookieAttributeCredentials: readonly string[] = []
): RawHttpObservation => ({
  ...state,
  status: response.status,
  headers: sanitizeSetCookieHeaders(response.headers, cookieAttributeCredentials),
  body,
  ...overrides,
});

const step = (stepId: string, value: Phase1HttpProjection): Phase1ScenarioStepResult =>
  Object.freeze({ stepId, value });

const requireThirdPartyApplication = (context: Phase1ScenarioRunContext) => {
  const configuration = context.profile.fixtures.dataTenant.browserClientConfiguration;
  const logicalApplicationId = configuration.localStorageValue.appId;
  const application = context.profile.fixtures.dataTenant.applications.find(
    ({ id }) => id === logicalApplicationId
  );

  if (!application?.isThirdParty) {
    throw new Error('Phase 1 consent application is invalid');
  }
  const { redirectUris } = application.oidcClientMetadata;
  const [redirectUri] = redirectUris;

  if (redirectUris.length !== 1 || !redirectUri) {
    throw new Error('Phase 1 consent redirect URI is invalid');
  }

  return Object.freeze({ application, redirectUri });
};

const authorizationRequestPath = (
  context: Phase1ScenarioRunContext,
  clientId: string,
  redirectUri: string,
  challenge: string,
  state: string | undefined,
  codeChallengeMethod: string,
  resource: Readonly<{ indicator: string; scopeName: string }> | undefined
): string => {
  const { authorizationPath } = context.profile.oidc;

  if (!authorizationPath.startsWith('/') || authorizationPath.slice(1).startsWith('/')) {
    throw new Error('Phase 1 authorization path is invalid');
  }
  const configured =
    context.profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue;
  const resourceScopeNames = new Set(
    context.profile.fixtures.dataTenant.resource.scopes.map(({ name }) => name)
  );
  const configuredScopes = configured.scope
    .split(/\s+/u)
    .filter(Boolean)
    .filter((scope) => !resourceScopeNames.has(scope));
  const scopes = Array.from(
    new Set([
      'openid',
      'offline_access',
      'profile',
      ...configuredScopes,
      ...(resource ? [resource.scopeName] : []),
    ])
  );
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: codeChallengeMethod,
    response_type: 'code',
    prompt: configured.prompt,
    scope: scopes.join(' '),
  });

  if (state !== undefined) {
    query.append('state', state);
  }

  if (resource) {
    query.append('resource', resource.indicator);
  }

  return `${authorizationPath.slice(1)}?${query.toString()}`;
};

const preparePositiveOidcAuthorization = (
  context: Phase1ScenarioRunContext,
  includeResource: boolean
) => {
  const { application, redirectUri } = requireThirdPartyApplication(context);
  const dataAllocation = context.fixture.public.allocations.find(({ role }) => role === 'data');

  if (!dataAllocation) {
    throw new Error('Phase 1 data allocation is unavailable');
  }
  const clientId = getPhase1FixtureRuntimeId(
    context.fixture.public,
    dataAllocation.allocationId,
    'application',
    application.id
  );
  const userId = getPhase1FixtureRuntimeId(
    context.fixture.public,
    dataAllocation.allocationId,
    'user',
    context.profile.fixtures.dataTenant.subject.id
  );
  const clients = context.protocol.forAllocation('data');
  const { store } = clients.oidc;

  if (clients.experience.store !== store || clients.consent.store !== store) {
    throw new Error('Phase 1 authorization clients do not share one secret store');
  }
  const resource = (() => {
    if (!includeResource) {
      return;
    }
    const fixtureResource = context.profile.fixtures.dataTenant.resource;
    const scope = fixtureResource.scopes[0];

    if (!scope) {
      throw new Error('Phase 1 authorization resource is invalid');
    }
    const runtimeResourceId = getPhase1FixtureRuntimeId(
      context.fixture.public,
      dataAllocation.allocationId,
      'resource',
      fixtureResource.id
    );
    const runtimeScopeId = getPhase1FixtureRuntimeId(
      context.fixture.public,
      dataAllocation.allocationId,
      'scope',
      scope.id
    );

    return Object.freeze({
      id: runtimeResourceId,
      indicator: getPhase1FixtureRuntimeResourceIndicator(
        fixtureResource.indicator,
        dataAllocation.allocationId
      ),
      name: getPhase1FixtureRuntimeText(fixtureResource.name, dataAllocation.allocationId),
      scopeId: runtimeScopeId,
      scopeName: getPhase1FixtureRuntimeText(scope.name, dataAllocation.allocationId),
      scopeDescription: scope.description,
    });
  })();

  return Object.freeze({
    application,
    redirectUri,
    dataAllocation,
    clientId,
    userId,
    clients,
    store,
    resource,
    projectionContext: normalizationContext(context, dataAllocation.allocationId),
  });
};

const requestPositiveOidcAuthorization = async (
  context: Phase1ScenarioRunContext,
  options: PositiveOidcAuthorizationRequestOptions = {}
) => {
  const prepared = preparePositiveOidcAuthorization(context, options.includeResource !== false);
  const random = options.random ?? defaultRandomSource;
  const codeVerifier = requireText(random.codeVerifier(), 'Phase 1 PKCE verifier is invalid');
  const expectedState =
    options.includeState === false
      ? undefined
      : requireText(random.state(), 'Phase 1 authorization state is invalid');

  if (!codeVerifierPattern.test(codeVerifier)) {
    throw new Error('Phase 1 PKCE verifier is invalid');
  }
  prepared.store.registerSecret(codeVerifier);
  if (expectedState !== undefined) {
    prepared.store.registerSecret(expectedState);
  }
  const challenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const requestedRedirectUri = options.redirectUri ?? prepared.redirectUri;
  const response = await prepared.clients.oidc.request(
    options.operation ?? 'authorization-start',
    authorizationRequestPath(
      context,
      prepared.clientId,
      requestedRedirectUri,
      challenge,
      expectedState,
      options.codeChallengeMethod ?? 'S256',
      prepared.resource
    ),
    { includeCookies: true }
  );

  return Object.freeze({
    ...prepared,
    response,
    requestedRedirectUri,
    codeVerifier,
    expectedState,
  });
};

export const projectPositiveOidcRedirectUriRejection = async (
  context: Phase1ScenarioRunContext,
  options: PositiveOidcAuthorizationRequestOptions,
  readState: () => ReturnType<Phase1ScenarioRunContext['projectScenarioState']>
): Promise<Phase1HttpProjection> => {
  const authorization = await requestPositiveOidcAuthorization(context, options);
  const { response, projectionContext } = authorization;
  const issuer = new URL(context.profile.oidc.issuerPath, context.target.coreUrl).href.replace(
    /\/$/u,
    ''
  );
  const expectedBody = {
    code: 'oidc.invalid_redirect_uri',
    message: "`redirect_uri` did not match any of the client's registered `redirect_uris`.",
    error: 'invalid_redirect_uri',
    error_description: "redirect_uri did not match any of the client's registered redirect_uris",
    iss: issuer,
  };
  const body = requireJsonObject(response.body, 'Phase 1 rejected redirect response is invalid');

  if (
    response.status !== 400 ||
    !isDeepStrictEqual(headerValues(response.headers, 'content-type'), [
      'application/json; charset=utf-8',
    ]) ||
    headerValues(response.headers, 'location').length > 0 ||
    headerValues(response.headers, 'set-cookie').length > 0 ||
    !isDeepStrictEqual(body, expectedBody)
  ) {
    throw new Error('Phase 1 rejected redirect response is invalid');
  }
  const state = await readState();

  return projectAuthorizationObservation(
    {
      ...state,
      status: response.status,
      headers: response.headers,
      body: normalizeOAuthError(body),
    },
    projectionContext
  );
};

export const projectPositiveOidcPkceMethodRejection = async (
  context: Phase1ScenarioRunContext,
  options: PositiveOidcAuthorizationRequestOptions,
  readState: () => ReturnType<Phase1ScenarioRunContext['projectScenarioState']>
): Promise<Phase1HttpProjection> => {
  const authorization = await requestPositiveOidcAuthorization(context, options);
  const { response, projectionContext, redirectUri, expectedState } = authorization;
  const locations = headerValues(response.headers, 'location');
  const [location] = locations;
  const issuer = new URL(context.profile.oidc.issuerPath, context.target.coreUrl).href.replace(
    /\/$/u,
    ''
  );

  if (expectedState === undefined || !location) {
    throw new Error('Phase 1 rejected PKCE method response is invalid');
  }
  const callback = new URL(location);
  const registered = new URL(redirectUri);
  const callbackKeys = [...callback.searchParams.keys()];
  const invalid =
    response.status !== 303 ||
    !isDeepStrictEqual(headerValues(response.headers, 'content-type'), [
      'text/html; charset=utf-8',
    ]) ||
    locations.length !== 1 ||
    headerValues(response.headers, 'set-cookie').length > 0 ||
    callback.origin !== registered.origin ||
    callback.pathname !== registered.pathname ||
    callback.hash !== registered.hash ||
    !isDeepStrictEqual(callbackKeys, ['error', 'error_description', 'state', 'iss']) ||
    callback.searchParams.get('error') !== 'invalid_request' ||
    callback.searchParams.get('error_description') !==
      'not supported value of code_challenge_method' ||
    callback.searchParams.get('state') !== expectedState ||
    callback.searchParams.get('iss') !== issuer;

  if (invalid) {
    throw new Error('Phase 1 rejected PKCE method response is invalid');
  }
  const state = await readState();

  return projectAuthorizationObservation(
    {
      ...state,
      status: response.status,
      headers: absolutePositiveOidcLocationHeaders(
        response.headers,
        redirectUri,
        'Phase 1 rejected PKCE method response is invalid'
      ),
      body: normalizePositiveOidcRedirectBody(
        response.body,
        response.headers,
        callback.href,
        'Phase 1 rejected PKCE method response is invalid'
      ),
      redirect: callback.href,
    },
    projectionContext
  );
};

const requireConsentBridge = (location: string, targetCoreUrl: string, clientId: string): void => {
  const url = new URL(location);

  if (
    url.origin !== new URL(targetCoreUrl).origin ||
    url.pathname !== '/consent' ||
    url.hash.length > 0 ||
    url.searchParams.getAll('app_id').length !== 1 ||
    url.searchParams.get('app_id') !== clientId ||
    Array.from(url.searchParams.keys()).some((key) => key !== 'app_id')
  ) {
    throw new Error('Phase 1 consent bridge redirect is invalid');
  }
};

const requireCallback = (
  location: string,
  redirectUri: string,
  expectedState: string,
  expectedIssuer: string
): string => {
  const callback = new URL(location);
  const registered = new URL(redirectUri);
  const codes = callback.searchParams.getAll('code');
  const states = callback.searchParams.getAll('state');
  const issuers = callback.searchParams.getAll('iss');

  if (
    callback.origin !== registered.origin ||
    callback.pathname !== registered.pathname ||
    callback.hash !== registered.hash ||
    codes.length !== 1 ||
    !codes[0] ||
    states.length !== 1 ||
    states[0] !== expectedState ||
    issuers.length !== 1 ||
    issuers[0] !== expectedIssuer ||
    callback.searchParams.has('error')
  ) {
    throw new Error('Phase 1 authorization callback is invalid');
  }

  return codes[0];
};

const assertFinalAuthorizationState = (
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>,
  input: Readonly<{
    application: Readonly<{ userConsentScopes: readonly string[] }>;
    clientId: string;
    userId: string;
    resource: Readonly<{ indicator: string; scopeName: string }> | undefined;
  }>
): void => {
  const { semanticState, persistedState, sideEffects } = state;

  if (
    !isJsonObject(semanticState) ||
    !isJsonObject(semanticState.session) ||
    semanticState.session.accountId !== input.userId ||
    semanticState.session.clientId !== input.clientId ||
    typeof semanticState.session.updatedAt !== 'number' ||
    !Number.isFinite(semanticState.session.updatedAt) ||
    !input.resource ||
    !isDeepStrictEqual(persistedState, {
      grant: {
        applicationId: input.clientId,
        userId: input.userId,
        oidcScopes: input.application.userConsentScopes,
        resource: input.resource.indicator,
        resourceScopes: [input.resource.scopeName],
      },
      userFirstConsentedApplicationId: input.clientId,
      sessionExtension: {
        accountId: input.userId,
        clientId: input.clientId,
        lastSubmission: { login: { accountId: input.userId } },
      },
    }) ||
    !isDeepStrictEqual(sideEffects, { consentPersisted: true })
  ) {
    throw new Error('Phase 1 authorization persisted state is invalid');
  }
};

export const withPositiveOidcFlow = async <Result>(
  context: Phase1ScenarioRunContext,
  options: PositiveOidcFlowOptions,
  consume: (grant: PositiveOidcAuthorizationGrant) => Promise<Result>
): Promise<PositiveOidcFlowOutput<Result>> =>
  context.fixture.withSecretLease(async (lease) => {
    const authorization = await requestPositiveOidcAuthorization(context, {
      random: options.random,
      includeResource: options.includeResource,
    });
    const {
      application,
      redirectUri,
      dataAllocation,
      clientId,
      userId,
      clients,
      store,
      resource,
      projectionContext,
      codeVerifier,
      expectedState,
    } = authorization;
    if (expectedState === undefined) {
      throw new Error('Phase 1 authorization state is invalid');
    }
    const capture = async (
      stepId: string,
      project: (
        state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>
      ) => Phase1HttpProjection
    ): Promise<Phase1ScenarioStepResult | undefined> =>
      options.captureSteps === false
        ? undefined
        : step(stepId, project(await stateInput(context, stepId)));
    const authorizeResponse = requireStatus(
      authorization.response,
      303,
      'Phase 1 authorization start failed'
    );
    const authorizeLocation = requireLocation(
      authorizeResponse.headers,
      context.target.coreUrl,
      'Phase 1 authorization start redirect is invalid'
    );

    const authorizeUrl = new URL(authorizeLocation);

    if (
      authorizeUrl.origin !== new URL(context.target.coreUrl).origin ||
      authorizeUrl.pathname !== '/sign-in' ||
      authorizeUrl.hash.length > 0
    ) {
      throw new Error('Phase 1 authorization start redirect is invalid');
    }
    const authorizeStep = await capture('authorize', (state) =>
      projectAuthorizationObservation(
        rawObservation(
          {
            ...authorizeResponse,
            headers: absolutePositiveOidcLocationHeaders(
              authorizeResponse.headers,
              context.target.coreUrl,
              'Phase 1 authorization start redirect is invalid'
            ),
          },
          normalizePositiveOidcRedirectBody(
            authorizeResponse.body,
            authorizeResponse.headers,
            authorizeLocation,
            'Phase 1 authorization start body is invalid'
          ),
          state,
          { redirect: authorizeLocation }
        ),
        projectionContext
      )
    );

    const bootstrapResponse = requireStatus(
      await clients.experience.requestExperience('experience-bootstrap', 'experience', {
        method: 'PUT',
        headers: jsonHeaders,
        body: JSON.stringify({ interactionEvent: 'SignIn' }),
      }),
      204,
      'Phase 1 experience bootstrap failed'
    );
    const bootstrapStep = await capture('experience-bootstrap', (state) =>
      projectAuthorizationObservation(
        rawObservation(
          bootstrapResponse,
          requireEmptyBody(bootstrapResponse.body, 'Phase 1 experience bootstrap body is invalid'),
          state
        ),
        projectionContext
      )
    );

    const password = lease.getPassword(context.profile.fixtures.dataTenant.subject.id);
    store.registerSecret(password);
    const passwordResponse = requireStatus(
      await clients.experience.requestExperience(
        'experience-password',
        'experience/verification/password',
        {
          method: 'POST',
          headers: jsonHeaders,
          body: JSON.stringify({
            identifier: {
              type: 'username',
              value: getPhase1FixtureRuntimeUsername(
                context.profile.fixtures.dataTenant.subject.username,
                dataAllocation.allocationId
              ),
            },
            password,
          }),
        }
      ),
      200,
      'Phase 1 password verification failed'
    );
    requireJsonContentType(passwordResponse.headers, 'Phase 1 password response is invalid');
    const passwordBody = requireJsonObject(
      passwordResponse.body,
      'Phase 1 password response is invalid'
    );
    const verificationId = requireText(
      passwordBody.verificationId,
      'Phase 1 password response is invalid'
    );
    store.registerSecret(verificationId);
    const passwordStep = await capture('password', (state) =>
      projectAuthorizationObservation(
        rawObservation(passwordResponse, { verificationRecordCreated: true }, state),
        projectionContext
      )
    );

    const identifyResponse = requireStatus(
      await clients.experience.requestExperience(
        'experience-identify',
        'experience/identification',
        {
          method: 'POST',
          headers: jsonHeaders,
          body: JSON.stringify({ verificationId }),
        }
      ),
      204,
      'Phase 1 user identification failed'
    );
    const identifyStep = await capture('identify', (state) =>
      projectAuthorizationObservation(
        rawObservation(
          identifyResponse,
          requireEmptyBody(identifyResponse.body, 'Phase 1 identification body is invalid'),
          state
        ),
        projectionContext
      )
    );

    const submitResponse = requireStatus(
      await clients.experience.requestExperience('experience-submit', 'experience/submit', {
        method: 'POST',
      }),
      200,
      'Phase 1 interaction submission failed'
    );
    requireJsonContentType(submitResponse.headers, 'Phase 1 interaction submission is invalid');
    const submitBody = requireJsonObject(
      submitResponse.body,
      'Phase 1 interaction submission is invalid'
    );
    const bridge = relativeOidcResumePath(
      submitBody.redirectTo,
      context.target.coreUrl,
      'Phase 1 interaction resume redirect is invalid'
    );
    store.registerSecret(bridge.credential);
    const bridgeResponse = requireStatus(
      await clients.oidc.request('authorization-consent-bridge', bridge.path),
      303,
      'Phase 1 consent bridge failed'
    );
    const bridgeLocation = requireLocation(
      bridgeResponse.headers,
      context.target.coreUrl,
      'Phase 1 consent bridge redirect is invalid'
    );
    requireConsentBridge(bridgeLocation, context.target.coreUrl, clientId);
    const submitStep = await capture('submit', (state) => {
      const projectedBridgeLocation = projectionContext.symbols.replace(bridgeLocation);
      const bridgeProjection = projectAuthorizationObservation(
        rawObservation(
          {
            ...bridgeResponse,
            headers: replaceLocationHeader(
              absolutePositiveOidcLocationHeaders(
                bridgeResponse.headers,
                context.target.coreUrl,
                'Phase 1 consent bridge redirect is invalid'
              ),
              projectedBridgeLocation
            ),
          },
          normalizePositiveOidcRedirectBody(
            bridgeResponse.body,
            bridgeResponse.headers,
            bridgeLocation,
            'Phase 1 consent bridge body is invalid'
          ),
          state,
          { redirect: projectedBridgeLocation },
          [bridge.credential]
        ),
        projectionContext
      );

      return projectConsentObservation(
        rawObservation(submitResponse, submitBody, state, {
          outcomes: [
            ...(state.outcomes ?? []),
            { kind: 'unobserved-consent-bridge', response: bridgeProjection },
          ],
        }),
        projectionContext
      );
    });

    const consentGetResponse = requireStatus(
      await clients.consent.requestConsent('consent-get', 'consent', { method: 'GET' }),
      200,
      'Phase 1 consent read failed'
    );
    requireJsonContentType(consentGetResponse.headers, 'Phase 1 consent response is invalid');
    const consentGetBody = requireJsonObject(
      consentGetResponse.body,
      'Phase 1 consent response is invalid'
    );
    const missingOidcScopesMatch = options.expectOidcConsentAlreadyGranted
      ? consentGetBody.missingOIDCScope === undefined ||
        isDeepStrictEqual(consentGetBody.missingOIDCScope, [])
      : isDeepStrictEqual(consentGetBody.missingOIDCScope, application.userConsentScopes);

    if (
      (consentGetBody.application as JsonObject | undefined)?.id !== clientId ||
      (consentGetBody.user as JsonObject | undefined)?.id !== userId ||
      consentGetBody.redirectUri !== redirectUri ||
      !missingOidcScopesMatch ||
      !isDeepStrictEqual(
        consentGetBody.missingResourceScopes,
        resource
          ? [
              {
                resource: {
                  id: resource.id,
                  name: resource.name,
                  indicator: resource.indicator,
                },
                scopes: [
                  {
                    id: resource.scopeId,
                    name: resource.scopeName,
                    description: resource.scopeDescription,
                  },
                ],
              },
            ]
          : []
      )
    ) {
      throw new Error('Phase 1 consent response is invalid');
    }
    const consentGetStep = await capture('consent-get', (state) =>
      projectConsentObservation(
        rawObservation(
          consentGetResponse,
          normalizeLogicalFixtureIds(consentGetBody, projectionContext),
          state
        ),
        projectionContext
      )
    );

    const consentPostResponse = requireStatus(
      await clients.consent.requestConsent('consent-post', 'consent', {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({}),
      }),
      200,
      'Phase 1 consent submission failed'
    );
    requireJsonContentType(consentPostResponse.headers, 'Phase 1 consent submission is invalid');
    const consentPostBody = requireJsonObject(
      consentPostResponse.body,
      'Phase 1 consent submission is invalid'
    );
    const resume = relativeOidcResumePath(
      consentPostBody.redirectTo,
      context.target.coreUrl,
      'Phase 1 consent resume redirect is invalid'
    );
    store.registerSecret(resume.credential);
    const consentPostStep = await capture('consent-post', (state) =>
      projectConsentObservation(
        rawObservation(consentPostResponse, consentPostBody, state),
        projectionContext
      )
    );

    const resumeResponse = requireStatus(
      await clients.oidc.request('authorization-resume', resume.path),
      303,
      'Phase 1 authorization resume failed'
    );
    const callbackLocation = requireLocation(
      resumeResponse.headers,
      redirectUri,
      'Phase 1 authorization callback is invalid'
    );
    const code = requireCallback(
      callbackLocation,
      redirectUri,
      expectedState,
      new URL(context.profile.oidc.issuerPath, context.target.coreUrl).href.replace(/\/$/u, '')
    );
    store.registerSecret(code);
    const resumeStep = await capture('resume', (state) =>
      projectAuthorizationObservation(
        rawObservation(
          {
            ...resumeResponse,
            headers: absolutePositiveOidcLocationHeaders(
              resumeResponse.headers,
              redirectUri,
              'Phase 1 authorization callback is invalid'
            ),
          },
          normalizePositiveOidcRedirectBody(
            resumeResponse.body,
            resumeResponse.headers,
            callbackLocation,
            'Phase 1 authorization resume body is invalid'
          ),
          state,
          { redirect: callbackLocation },
          [resume.credential]
        ),
        projectionContext
      )
    );
    const callbackStep = await capture('callback', (state) =>
      projectRedirectObservation(
        rawObservation(
          {
            ...resumeResponse,
            headers: absolutePositiveOidcLocationHeaders(
              resumeResponse.headers,
              redirectUri,
              'Phase 1 authorization callback is invalid'
            ),
          },
          callbackLocation,
          state,
          {},
          [resume.credential]
        ),
        projectionContext
      )
    );
    const stateStep = await capture('state', (state) => {
      assertFinalAuthorizationState(state, {
        application,
        clientId,
        userId,
        resource,
      });

      return projectSemanticStateObservation(
        {
          ...state,
          status: 200,
          headers: [],
        },
        projectionContext,
        { scenarioId, stepId: 'state' }
      );
    });
    const safeSteps = Object.freeze(
      [
        authorizeStep,
        bootstrapStep,
        passwordStep,
        identifyStep,
        submitStep,
        consentGetStep,
        consentPostStep,
        resumeStep,
        callbackStep,
        stateStep,
      ].filter((value): value is Phase1ScenarioStepResult => value !== undefined)
    );

    store.assertNoCredentialMaterial(safeSteps);
    const result = await (async () => {
      const grant = createPositiveOidcAuthorizationGrant({
        clientId,
        code,
        codeVerifier,
        redirectUri,
        ...(resource === undefined ? {} : { resource: resource.indicator }),
      });

      try {
        const consumed = await consume(grant);
        store.assertNoCredentialMaterial(consumed);

        return consumed;
      } catch {
        throw new Error('Phase 1 authorization consumer failed');
      } finally {
        revokePositiveOidcAuthorizationGrant(grant);
      }
    })();

    return Object.freeze({ steps: safeSteps, result });
  });

/* eslint-enable max-lines, complexity, no-restricted-syntax, no-control-regex, @typescript-eslint/ban-types, max-params */
