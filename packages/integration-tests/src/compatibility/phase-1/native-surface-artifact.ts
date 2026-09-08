/* eslint-disable no-restricted-syntax -- The public generic preserves the projected JSON object's compile-time shape after a closed traversal. */
import { types as nodeTypes } from 'node:util';

import type { JsonObject, JsonValue } from '../normalize.js';

import { cloneAndDeepFreeze } from './model.js';
import {
  asterNativeSurfaceContract,
  projectNativeSurfaceObservation,
  type Phase1Implementation,
} from './native-surface.js';
import type { Phase1NativeSurfaceMarkerId } from './profile-types.js';

const maximumDepth = 64;
const maximumArrayLength = 4096;
const projectionFailure = 'Invalid Phase 1 native surface artifact';
const candidateFailure = 'Invalid Phase 1 candidate native surface artifact';
type GraphNode = Readonly<Record<string, unknown>> | readonly unknown[];
type ProjectionState = Readonly<{
  implementation: Phase1Implementation;
  ancestors: WeakSet<GraphNode>;
}>;

const failProjection = (): never => {
  throw new TypeError(projectionFailure);
};

const failCandidate = (): never => {
  throw new TypeError(candidateFailure);
};

const assertDepth = (depth: number): void => {
  if (depth > maximumDepth) {
    failProjection();
  }
};

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  !nodeTypes.isProxy(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const requireRecord = (value: unknown): Readonly<Record<string, unknown>> =>
  isRecord(value) ? value : failProjection();

const requireArray = (value: unknown): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    value.length > maximumArrayLength ||
    Object.keys(value).length !== value.length
  ) {
    return failProjection();
  }

  return value;
};

const recordEntries = (
  value: Readonly<Record<string, unknown>>
): Array<readonly [string, unknown]> => {
  const keys = Reflect.ownKeys(value);

  if (
    keys.some((key) => typeof key !== 'string') ||
    keys.some((key) => {
      const descriptor =
        typeof key === 'string' ? Object.getOwnPropertyDescriptor(value, key) : undefined;

      return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
    })
  ) {
    return failProjection();
  }

  return Object.entries(value);
};

const withNode = <Value extends JsonValue>(
  value: GraphNode,
  state: ProjectionState,
  project: () => Value
): Value => {
  if (state.ancestors.has(value)) {
    return failProjection();
  }
  state.ancestors.add(value);

  try {
    return project();
  } finally {
    state.ancestors.delete(value);
  }
};

const markerMatchesEitherSide = (markerId: Phase1NativeSurfaceMarkerId, value: string): boolean => {
  const marker = asterNativeSurfaceContract.markers[markerId];

  return marker.match === 'exact'
    ? value === marker.reference || value === marker.candidate
    : value.startsWith(marker.reference) || value.startsWith(marker.candidate);
};

const projectMarker = (
  markerIds: readonly Phase1NativeSurfaceMarkerId[],
  value: string,
  implementation: Phase1Implementation
): string => {
  for (const markerId of markerIds) {
    if (markerMatchesEitherSide(markerId, value)) {
      return projectNativeSurfaceObservation(implementation, markerId, value);
    }
  }

  return value;
};

const resourceMarkerIds = Object.freeze([
  'managementResource',
  'accountResource',
  'organizationResource',
  'organizationAudiencePrefix',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);
const scopeMarkerIds = Object.freeze([
  'organizationScope',
  'organizationRoleScope',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);
const cookieMarkerIds = Object.freeze([
  'sharedExperienceCookieSignature',
  'sharedExperienceCookie',
  'generatedCookiePrefix',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);
const headerMarkerIds = Object.freeze([
  'applicationIdHeader',
  'requestIdHeader',
] as const satisfies readonly Phase1NativeSurfaceMarkerId[]);
const scopeFieldNames = new Set(['scope', 'scopes', 'responseScope', 'scopes_supported']);
const controlledFieldMarkerIds: Readonly<Record<string, readonly Phase1NativeSurfaceMarkerId[]>> =
  Object.freeze({
    resource: resourceMarkerIds,
    audience: resourceMarkerIds,
    indicator: resourceMarkerIds,
    localStorageKey: ['demoConfigStorageKey'],
    productName: ['productName'],
    nativeScheme: ['nativeScheme'],
    globalName: ['ssrGlobal', 'nativeSdkGlobal'],
  });

const projectScopeText = (value: string, implementation: Phase1Implementation): string =>
  value.replaceAll(/\S+/gu, (token) => projectMarker(scopeMarkerIds, token, implementation));

function projectArray(
  value: unknown,
  state: ProjectionState,
  depth: number,
  projectItem: (item: unknown) => JsonValue
): JsonValue[] {
  assertDepth(depth);
  const array = requireArray(value);

  return withNode(array, state, () => Array.from(array, projectItem));
}

function projectStringCollection(
  value: unknown,
  markerIds: readonly Phase1NativeSurfaceMarkerId[],
  state: ProjectionState,
  depth: number
): JsonValue {
  assertDepth(depth);

  if (typeof value === 'string') {
    return projectMarker(markerIds, value, state.implementation);
  }
  if (Array.isArray(value)) {
    return projectArray(value, state, depth, (item) =>
      typeof item === 'string'
        ? projectMarker(markerIds, item, state.implementation)
        : projectValue(item, state, depth + 1)
    );
  }

  return projectValue(value, state, depth);
}

function projectScopeValue(value: unknown, state: ProjectionState, depth: number): JsonValue {
  assertDepth(depth);

  if (typeof value === 'string') {
    return projectScopeText(value, state.implementation);
  }
  if (Array.isArray(value)) {
    return projectArray(value, state, depth, (item) =>
      typeof item === 'string'
        ? projectScopeText(item, state.implementation)
        : projectValue(item, state, depth + 1)
    );
  }

  return projectValue(value, state, depth);
}

function projectHeaders(value: unknown, state: ProjectionState, depth: number): JsonObject {
  assertDepth(depth);
  const headers = requireRecord(value);

  return withNode(headers, state, () => {
    const pairs = recordEntries(headers).map(
      ([name, nested]) =>
        [
          projectMarker(headerMarkerIds, name.toLowerCase(), state.implementation),
          projectValue(nested, state, depth + 1),
        ] as const
    );

    if (new Set(pairs.map(([name]) => name)).size !== pairs.length) {
      return failProjection();
    }

    return Object.fromEntries(pairs);
  });
}

function projectCookies(value: unknown, state: ProjectionState, depth: number): JsonValue[] {
  return projectArray(value, state, depth, (rawCookie) => {
    const cookie = requireRecord(rawCookie);
    const name = typeof cookie.name === 'string' ? cookie.name : failProjection();

    return withNode(cookie, state, () =>
      Object.fromEntries(
        recordEntries(cookie).map(([key, nested]) => [
          key,
          key === 'name'
            ? projectMarker(cookieMarkerIds, name, state.implementation)
            : projectField(key, nested, state, depth + 1),
        ])
      )
    );
  });
}

function projectClaims(value: unknown, state: ProjectionState, depth: number): JsonObject {
  assertDepth(depth);
  const claims = requireRecord(value);

  return withNode(claims, state, () =>
    Object.fromEntries(
      recordEntries(claims).map(([key, nested]) => [
        key,
        key === 'aud'
          ? projectStringCollection(nested, resourceMarkerIds, state, depth + 1)
          : key === 'scope'
            ? projectScopeValue(nested, state, depth + 1)
            : projectField(key, nested, state, depth + 1),
      ])
    )
  );
}

function projectField(
  key: string,
  value: unknown,
  state: ProjectionState,
  depth: number
): JsonValue {
  if (key === 'headers') {
    return projectHeaders(value, state, depth);
  }
  if (key === 'cookies') {
    return projectCookies(value, state, depth);
  }
  if (key === 'claims') {
    return projectClaims(value, state, depth);
  }
  if (scopeFieldNames.has(key)) {
    return projectScopeValue(value, state, depth);
  }
  const markerIds = controlledFieldMarkerIds[key];

  return markerIds
    ? projectStringCollection(value, markerIds, state, depth)
    : projectValue(value, state, depth);
}

function projectValue(value: unknown, state: ProjectionState, depth: number): JsonValue {
  assertDepth(depth);

  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : failProjection();
  }
  if (Array.isArray(value)) {
    return projectArray(value, state, depth, (item) => projectValue(item, state, depth + 1));
  }
  const record = requireRecord(value);

  return withNode(record, state, () =>
    Object.fromEntries(
      recordEntries(record).map(([key, nested]) => [
        key,
        projectField(key, nested, state, depth + 1),
      ])
    )
  );
}

export const projectNativeSurfaceArtifact = <Value extends JsonValue>(
  value: Value,
  implementation: Phase1Implementation
): Readonly<Value> => {
  try {
    const projected = projectValue(value, { implementation, ancestors: new WeakSet() }, 0);

    return cloneAndDeepFreeze(projected) as Readonly<Value>;
  } catch {
    return failProjection();
  }
};

export const assertCandidateNativeSurfaceArtifact = (value: unknown): void => {
  try {
    projectNativeSurfaceArtifact(value as JsonValue, 'candidate');
  } catch {
    failCandidate();
  }
};

/* eslint-enable no-restricted-syntax */
