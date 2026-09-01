/* eslint-disable max-lines, complexity, @typescript-eslint/ban-types, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Faithful JSON uses explicit null, guarded Zod narrowing, and local ordered URL lifting at this publication boundary. */
import { MIMEType } from 'node:util';

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
