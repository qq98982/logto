/* eslint-disable max-lines, complexity, @typescript-eslint/ban-types, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Faithful JSON uses explicit null, guarded Zod narrowing, and local ordered URL lifting at this publication boundary. */
import { isDeepStrictEqual, MIMEType } from 'node:util';

import { z } from 'zod';

import { assertEvidenceIsSanitized } from '../../evidence.js';
import { jsonValueGuard } from '../../model.js';
import type { JsonValue, NormalizationContext } from '../../normalize.js';
import { assertPhase1EvidenceIsSanitized } from '../evidence.js';
import type { Phase1DifferentialScenarioId } from '../model.js';
import {
  normalizeCookieContinuity,
  normalizeHeaders,
  normalizeLogicalFixtureIds,
  normalizeRedirect,
  normalizeResumeRedirect,
  type Phase1CookieMetadata,
  type Phase1HeaderMultimap,
  type Phase1RedirectProjection,
} from '../normalizers.js';
import { phase1ScenarioContracts } from '../scenario-contracts.js';

export type Phase1ProjectionCoordinates = Readonly<{
  scenarioId: Phase1DifferentialScenarioId;
  stepId: string;
}>;

export type RawHttpObservation = Readonly<{
  status: number;
  headers: ReadonlyArray<readonly [string, string]>;
  body: unknown;
  semanticState: unknown;
  sideEffects: unknown;
  error?: unknown;
  redirect?: string;
  resumeRedirect?: string;
  urls?: readonly string[];
  generatedIds?: unknown;
  persistedState?: unknown;
  outcomes?: unknown;
}>;

export type Phase1MediaType = Readonly<{
  type: string;
  subtype: string;
  parameters: Readonly<Record<string, readonly string[]>>;
}>;

export type Phase1HttpProjection = Readonly<{
  status: number;
  mediaType: Phase1MediaType | null;
  error: JsonValue | null;
  headers: Phase1HeaderMultimap;
  body: JsonValue;
  redirect: Phase1RedirectProjection | null;
  cookies: readonly Phase1CookieMetadata[];
  urls: readonly Phase1RedirectProjection[];
  tokens: readonly JsonValue[];
  generatedIds: JsonValue;
  persistedState: JsonValue;
  semanticState: JsonValue;
  sideEffects: JsonValue;
  outcomes: readonly JsonValue[];
}>;

export const phase1CookieMetadataGuard = z
  .object({
    name: z.string().min(1),
    path: z.string().optional(),
    domain: z.string().optional(),
    httpOnly: z.boolean(),
    secure: z.boolean(),
    sameSite: z.enum(['Strict', 'Lax', 'None']).optional(),
    maxAge: z.number().finite().optional(),
    expires: z
      .object({
        $timestamp: z.number().finite(),
        $toleranceSeconds: z.literal(30),
      })
      .strict()
      .optional(),
    expiryOffsetSeconds: z.number().finite().optional(),
    extensions: z.array(
      z.object({ name: z.string().min(1), value: z.string().optional() }).strict()
    ),
  })
  .strict();
export const phase1CookieMetadataArrayGuard = z.array(phase1CookieMetadataGuard);
const phase1BoundedTimestampGuard = z
  .object({
    $timestamp: z.number().finite(),
    $toleranceSeconds: z.literal(30),
  })
  .strict();
const phase1RedirectParameterGuard = z
  .object({
    component: z.enum(['query', 'fragment']),
    name: z.string().min(1),
    count: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();
const phase1RedirectProjectionGuard = z
  .object({
    scheme: z.string().min(1),
    origin: z.string().min(1),
    path: z.string(),
    query: z.record(z.array(z.string()).min(1)),
    fragment: z.string(),
    redactedParameters: z.array(phase1RedirectParameterGuard),
    resumeCredential: z.string().min(1).optional(),
  })
  .strict();
const phase1AuthParameterGuard = z
  .object({
    name: z.string().min(1),
    value: z.string(),
    quoted: z.boolean(),
  })
  .strict();
const phase1AuthChallengeGuard = z
  .object({
    scheme: z.string().min(1),
    format: z.enum(['parameters', 'token68']),
    parameters: z.array(jsonValueGuard),
  })
  .strict()
  .superRefine((challenge, context) => {
    const valid =
      challenge.format === 'token68'
        ? challenge.parameters.length === 1 && challenge.parameters[0] === '<redacted-auth-token68>'
        : challenge.parameters.every(
            (parameter) => phase1AuthParameterGuard.safeParse(parameter).success
          );

    if (!valid) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Invalid normalized authentication challenge',
      });
    }
  });
const phase1AuthChallengesGuard = z
  .object({ challenges: z.array(phase1AuthChallengeGuard).min(1) })
  .strict();
const phase1EntityTagGuard = z
  .object({
    weak: z.boolean(),
    normalizedBodySha256: z.string().regex(/^[0-9a-f]{64}$/u),
  })
  .strict();
const normalizedHeaderNamePattern = /^[!#$%&'*+.^_`|~0-9a-z-]+$/u;
export const phase1HeaderMultimapGuard = z
  .record(z.array(jsonValueGuard).min(1))
  .superRefine((headers, context) => {
    const names = Object.keys(headers);
    const sortedNames = names.toSorted();

    if (
      names.some((name) => !normalizedHeaderNamePattern.test(name)) ||
      names.some((name, index) => name !== sortedNames[index])
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid normalized headers' });
    }

    for (const [name, values] of Object.entries(headers)) {
      const valid = values.every((value) => {
        if (name === 'set-cookie') {
          return phase1CookieMetadataGuard.safeParse(value).success;
        }
        if (name === 'date') {
          return phase1BoundedTimestampGuard.safeParse(value).success;
        }
        if (name === 'content-length') {
          return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
        }
        if (name === 'etag') {
          return phase1EntityTagGuard.safeParse(value).success;
        }
        if (name === 'location') {
          return phase1RedirectProjectionGuard.safeParse(value).success;
        }
        if (name === 'www-authenticate' || name === 'proxy-authenticate') {
          return phase1AuthChallengesGuard.safeParse(value).success;
        }
        if (normalizeHeaders.isCredentialKey(name)) {
          return value === '<redacted-header-value>';
        }

        return typeof value === 'string';
      });

      if (!valid) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Invalid normalized header value',
          path: [name],
        });
      }
    }
  });
const phase1MediaTypeGuard = z
  .object({
    type: z.string().min(1),
    subtype: z.string().min(1),
    parameters: z.record(z.array(z.string()).min(1)),
  })
  .strict();
export const phase1HttpProjectionGuard = z
  .object({
    status: z.number().int().min(100).max(599),
    mediaType: phase1MediaTypeGuard.nullable(),
    error: jsonValueGuard,
    headers: phase1HeaderMultimapGuard,
    body: jsonValueGuard,
    redirect: phase1RedirectProjectionGuard.nullable(),
    cookies: phase1CookieMetadataArrayGuard,
    urls: z.array(phase1RedirectProjectionGuard),
    tokens: z.array(jsonValueGuard),
    generatedIds: jsonValueGuard,
    persistedState: jsonValueGuard,
    semanticState: jsonValueGuard,
    sideEffects: jsonValueGuard,
    outcomes: z.array(jsonValueGuard),
  })
  .strict()
  .superRefine((projection, context) => {
    if (!isDeepStrictEqual(projection.headers['set-cookie'] ?? [], projection.cookies)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Normalized cookie projections do not match',
        path: ['cookies'],
      });
    }
  });

const credentialFieldPattern =
  /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|cookie|set[_-]?cookie|password|secret|private[_-]?key)$/iu;
const allowedMetadataFields = new Set(['cookies', 'set-cookie', 'tokenType', 'resumeCredential']);
const exactUrlFields = new Set(['iss', 'issuer']);
const isStructuredRedirect = (value: JsonValue): boolean =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  typeof value.scheme === 'string' &&
  typeof value.origin === 'string' &&
  typeof value.path === 'string' &&
  typeof value.fragment === 'string' &&
  Array.isArray(value.redactedParameters);

export const boundedTimestampPathsFor = (
  coordinates: Phase1ProjectionCoordinates | undefined,
  surfacePath: readonly string[],
  allowedFields: ReadonlySet<string>
): readonly string[] => {
  if (!coordinates) {
    return [];
  }
  const contract = phase1ScenarioContracts.find(({ id }) => id === coordinates.scenarioId);

  if (!contract?.orderedSteps.some(({ id }) => id === coordinates.stepId)) {
    throw new TypeError('Invalid phase 1 projection coordinates');
  }
  return Object.freeze(
    contract.explicitNormalizablePointers
      .flatMap((pointer) => {
        const segments = pointer.split('/').slice(1);
        const step = segments[1];
        const projectionPath = segments.slice(3);

        if (
          segments[0] !== 'steps' ||
          (step !== '*' && step !== coordinates.stepId) ||
          !surfacePath.every((segment, index) => projectionPath[index] === segment)
        ) {
          return [];
        }
        const relative = projectionPath.slice(surfacePath.length);
        const terminal = relative.at(-1);

        return terminal && allowedFields.has(terminal) ? [`/${relative.join('/')}`] : [];
      })
      .filter((path, index, paths) => paths.indexOf(path) === index)
  );
};

const inspectProjection = (value: JsonValue): void => {
  if (typeof value === 'string') {
    assertEvidenceIsSanitized({ value });
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      inspectProjection(item);
    }
    return;
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, nested] of Object.entries(value)) {
      if (credentialFieldPattern.test(key) && !allowedMetadataFields.has(key)) {
        throw new TypeError('Invalid phase 1 projection');
      }
      inspectProjection(nested);
    }
  }
};

export const requireProjectionJson = (value: unknown, diagnostic: string): JsonValue => {
  const parsed = jsonValueGuard.safeParse(value);

  if (!parsed.success) {
    throw new TypeError(diagnostic);
  }
  const result = parsed.data as JsonValue;
  const source = value as JsonValue;

  try {
    inspectProjection(source);
    assertPhase1EvidenceIsSanitized(source);
  } catch {
    throw new TypeError(diagnostic);
  }

  return result;
};

const projectMediaType = (headers: RawHttpObservation['headers']): Phase1MediaType | null => {
  const values = headers
    .filter(([name]) => name.toLowerCase() === 'content-type')
    .map(([, value]) => value);

  if (values.length === 0) {
    return null;
  }
  if (values.length !== 1 || !values[0]) {
    throw new TypeError('Invalid phase 1 HTTP projection');
  }
  const mediaType = new MIMEType(values[0]);

  return Object.freeze({
    type: mediaType.type,
    subtype: mediaType.subtype,
    parameters: Object.freeze(
      Object.fromEntries(
        Array.from(mediaType.params.entries())
          .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([name, value]) => [name, Object.freeze([value])])
      )
    ),
  });
};

const liftBodyUrls = (
  input: JsonValue,
  context: NormalizationContext,
  additionalUrls: readonly string[]
): Readonly<{ body: JsonValue; urls: readonly Phase1RedirectProjection[] }> => {
  const urls = additionalUrls.map((value) =>
    normalizeRedirect(value, context, { targetOrigin: 'symbol' })
  );
  const visit = (value: JsonValue, field = ''): JsonValue => {
    if (typeof value === 'string') {
      let url: URL;

      try {
        url = new URL(value);
      } catch {
        return value;
      }
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        if (exactUrlFields.has(field) && (url.search.length > 0 || url.hash.length > 0)) {
          throw new TypeError('Invalid phase 1 HTTP projection');
        }
        const index = urls.length;
        urls.push(normalizeRedirect(value, context, { targetOrigin: 'symbol' }));
        return exactUrlFields.has(field) ? value : { $url: index };
      }
    }
    if (isStructuredRedirect(value)) {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((item) => visit(item, field));
    }
    if (typeof value === 'object' && value !== null) {
      return Object.fromEntries(
        Object.entries(value).map(([key, nested]) => [key, visit(nested, key)])
      );
    }

    return value;
  };

  return Object.freeze({ body: visit(input), urls: Object.freeze(urls) });
};

export const projectHttpObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => {
  try {
    if (!Number.isSafeInteger(value.status) || value.status < 100 || value.status > 599) {
      throw new TypeError('Invalid phase 1 HTTP projection');
    }
    const rawBody = requireProjectionJson(value.body, 'Invalid phase 1 HTTP projection');
    const lifted = liftBodyUrls(rawBody, context, value.urls ?? []);
    const body = requireProjectionJson(lifted.body, 'Invalid phase 1 HTTP projection');
    const error = requireProjectionJson(
      value.error === value.body ? body : (value.error ?? (value.status >= 400 ? body : null)),
      'Invalid phase 1 HTTP projection'
    );
    const outcomeValue = requireProjectionJson(
      value.outcomes ?? [],
      'Invalid phase 1 HTTP projection'
    );

    if (!Array.isArray(outcomeValue)) {
      throw new TypeError('Invalid phase 1 HTTP projection');
    }
    const semanticState = requireProjectionJson(
      normalizeLogicalFixtureIds(value.semanticState, context),
      'Invalid phase 1 HTTP projection'
    );
    const persistedState = requireProjectionJson(
      normalizeLogicalFixtureIds(value.persistedState ?? value.semanticState, context),
      'Invalid phase 1 HTTP projection'
    );
    const generatedIds = requireProjectionJson(
      normalizeLogicalFixtureIds(value.generatedIds ?? {}, context),
      'Invalid phase 1 HTTP projection'
    );
    const sideEffects = requireProjectionJson(
      normalizeLogicalFixtureIds(value.sideEffects, context),
      'Invalid phase 1 HTTP projection'
    );
    const headers = normalizeHeaders(value.headers, context, {
      bodyByteLength: Buffer.byteLength(JSON.stringify(body)),
      body,
    });
    const setCookies = value.headers
      .filter(([name]) => name.toLowerCase() === 'set-cookie')
      .map(([, headerValue]) => headerValue);
    const locations = value.headers
      .filter(([name]) => name.toLowerCase() === 'location')
      .map(([, headerValue]) => headerValue);
    const responseDates = value.headers
      .filter(([name]) => name.toLowerCase() === 'date')
      .map(([, headerValue]) => Date.parse(headerValue) / 1000);

    if (
      locations.length > 1 ||
      responseDates.some((date) => !Number.isFinite(date)) ||
      (value.redirect !== undefined &&
        locations[0] !== undefined &&
        value.redirect !== locations[0]) ||
      (value.resumeRedirect !== undefined &&
        locations[0] !== undefined &&
        value.resumeRedirect !== locations[0])
    ) {
      throw new TypeError('Invalid phase 1 HTTP projection');
    }
    const redirect = value.resumeRedirect ?? value.redirect ?? locations[0];
    const projection = Object.freeze({
      status: value.status,
      mediaType: projectMediaType(value.headers),
      error,
      headers,
      body,
      redirect: redirect
        ? (() => {
            try {
              return normalizeResumeRedirect(redirect, context);
            } catch {
              return normalizeRedirect(redirect, context);
            }
          })()
        : null,
      cookies: normalizeCookieContinuity(setCookies, {
        ...(responseDates.length === 1 && responseDates[0] !== undefined
          ? { responseDateSeconds: responseDates[0] }
          : {}),
        requireExpiryOffset: true,
      }),
      urls: lifted.urls,
      tokens: Object.freeze([]),
      generatedIds,
      persistedState,
      semanticState,
      sideEffects,
      outcomes: Object.freeze(outcomeValue),
    });
    requireProjectionJson(projection, 'Invalid phase 1 HTTP projection');

    return projection;
  } catch {
    throw new TypeError('Invalid phase 1 HTTP projection');
  }
};

export const projectLogicalHttpObservation = (
  value: RawHttpObservation,
  context: NormalizationContext,
  options: Readonly<{ boundedTimestampPaths?: readonly string[] }> = {}
): Phase1HttpProjection =>
  projectHttpObservation(
    { ...value, body: normalizeLogicalFixtureIds(value.body, context, options) },
    context
  );

/* eslint-enable max-lines, complexity, @typescript-eslint/ban-types, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
