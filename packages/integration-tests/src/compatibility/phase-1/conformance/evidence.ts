/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods -- The evidence boundary validates and hashes the exact downstream assembler contract. */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import { assertPhase1EvidenceIsSanitized } from '../evidence.js';
import { cloneAndDeepFreeze, snapshotClosedDataGraph } from '../model.js';

import {
  phase1ConformanceAdapterControlIds,
  assertValidatedPhase1ConformanceRunResult,
  type Phase1ConformanceMode,
  type Phase1ConformanceRunResult,
} from './runner.js';

export type Phase1ConformanceEvidenceProvenance = Readonly<{
  harnessCommit: string;
  profileSha256: string;
  schemaSha256: string;
  imageDigest: string;
}>;

export type Phase1ConformanceProjectionEnvelope = Readonly<{
  label: string;
  projectionSha256: string;
  value: Readonly<JsonObject>;
}>;

export type Phase1ConformanceEvidence = Readonly<{
  schemaVersion: 1;
  mode: Phase1ConformanceMode;
  provenance: Phase1ConformanceEvidenceProvenance;
  sanitizerSuccess: true;
  adapterControls: ReadonlyArray<
    Readonly<{
      id: string;
      detected: true;
      result: Phase1ConformanceProjectionEnvelope;
    }>
  >;
  officialResultIds: readonly string[];
  planResults: ReadonlyArray<
    Readonly<{
      planId: string;
      resultId: string;
      resultSha256: string;
      result: Phase1ConformanceProjectionEnvelope;
    }>
  >;
}>;

const diagnostic = 'Invalid phase 1 conformance evidence';
const sha256Pattern = /^[0-9a-f]{64}$/u;
const gitObjectPattern = /^[0-9a-f]{40}$/u;
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;
const resultIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const planIds = Object.freeze([
  'oidcc-basic-certification-test-plan',
  'oidcc-config-certification-test-plan',
] as const);
const expectedVariants = Object.freeze({
  'oidcc-basic-certification-test-plan': Object.freeze({
    serverMetadata: 'discovery',
    clientRegistration: 'static_client',
    responseType: 'code',
    responseMode: 'default',
    clientAuthTypes: Object.freeze(['client_secret_basic', 'client_secret_post']),
  }),
  'oidcc-config-certification-test-plan': Object.freeze({
    clientRegistration: 'static_client',
    serverMetadata: 'discovery',
  }),
});

const bytewiseCompare = (left: string, right: string): number =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

const canonicalValue = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalValue(item));
  }
  if (typeof value !== 'object' || value === null) {
    return value;
  }
  const result = Object.create(null) as Record<string, JsonValue>;

  for (const key of Object.keys(value).toSorted(bytewiseCompare)) {
    Object.defineProperty(result, key, {
      configurable: false,
      enumerable: true,
      value: canonicalValue(value[key] as JsonValue),
      writable: false,
    });
  }

  return result;
};

export const hashCanonicalConformanceJson = (value: unknown): string => {
  try {
    const snapshot = snapshotClosedDataGraph<unknown>(value);

    if (snapshot === undefined || !jsonValueGuard.safeParse(snapshot).success) {
      throw new TypeError(diagnostic);
    }

    return createHash('sha256')
      .update(`${JSON.stringify(canonicalValue(snapshot as JsonValue))}\n`, 'utf8')
      .digest('hex');
  } catch {
    throw new TypeError(diagnostic);
  }
};

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const exactKeys = (value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean => {
  const actual = Reflect.ownKeys(value);

  return (
    actual.length === keys.length &&
    actual.every((key) => typeof key === 'string' && keys.includes(key))
  );
};

const requireProjection = (value: unknown): Readonly<JsonObject> => {
  const snapshot = snapshotClosedDataGraph<JsonObject>(value);

  if (
    snapshot === undefined ||
    Array.isArray(snapshot) ||
    !jsonValueGuard.safeParse(snapshot).success
  ) {
    throw new TypeError(diagnostic);
  }
  assertPhase1EvidenceIsSanitized(snapshot);

  return snapshot;
};

const projectionEnvelope = (
  label: 'adapter-control' | 'official-plan-result',
  value: unknown
): Phase1ConformanceProjectionEnvelope => {
  const projection = requireProjection(value);

  return cloneAndDeepFreeze({
    label,
    projectionSha256: hashCanonicalConformanceJson(projection),
    value: projection,
  });
};

const requireProvenance = (value: unknown): Phase1ConformanceEvidenceProvenance => {
  const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);

  if (
    !snapshot ||
    Array.isArray(snapshot) ||
    !exactKeys(snapshot, ['harnessCommit', 'profileSha256', 'schemaSha256', 'imageDigest']) ||
    typeof snapshot.harnessCommit !== 'string' ||
    !gitObjectPattern.test(snapshot.harnessCommit) ||
    typeof snapshot.profileSha256 !== 'string' ||
    !sha256Pattern.test(snapshot.profileSha256) ||
    typeof snapshot.schemaSha256 !== 'string' ||
    !sha256Pattern.test(snapshot.schemaSha256) ||
    typeof snapshot.imageDigest !== 'string' ||
    !imageDigestPattern.test(snapshot.imageDigest)
  ) {
    throw new TypeError(diagnostic);
  }

  return cloneAndDeepFreeze({
    harnessCommit: snapshot.harnessCommit,
    profileSha256: snapshot.profileSha256,
    schemaSha256: snapshot.schemaSha256,
    imageDigest: snapshot.imageDigest,
  });
};

export const createPhase1ConformanceEvidence = (
  input: Phase1ConformanceRunResult,
  provenanceInput: Phase1ConformanceEvidenceProvenance
): Phase1ConformanceEvidence => {
  try {
    assertValidatedPhase1ConformanceRunResult(input);
    const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(input);

    if (
      !snapshot ||
      Array.isArray(snapshot) ||
      !exactKeys(snapshot, ['schemaVersion', 'mode', 'adapterControls', 'officialResults']) ||
      snapshot.schemaVersion !== 1 ||
      !['review-candidate', 'mirror-control', 'runtime-candidate'].includes(
        String(snapshot.mode)
      ) ||
      !Array.isArray(snapshot.adapterControls) ||
      !Array.isArray(snapshot.officialResults)
    ) {
      throw new TypeError(diagnostic);
    }
    const mode = snapshot.mode as Phase1ConformanceMode;
    const provenance = requireProvenance(provenanceInput);
    const adapterControls = snapshot.adapterControls.map((value) => {
      if (
        !isRecord(value) ||
        !exactKeys(value, ['id', 'projection']) ||
        typeof value.id !== 'string'
      ) {
        throw new TypeError(diagnostic);
      }

      return cloneAndDeepFreeze({
        id: value.id,
        detected: true as const,
        result: projectionEnvelope('adapter-control', value.projection),
      });
    });
    const planResults = snapshot.officialResults.map((value) => {
      if (
        !isRecord(value) ||
        !exactKeys(value, ['planId', 'resultId', 'status', 'variant', 'result']) ||
        typeof value.planId !== 'string' ||
        !planIds.includes(value.planId as (typeof planIds)[number]) ||
        typeof value.resultId !== 'string' ||
        !resultIdPattern.test(value.resultId) ||
        planIds.includes(value.resultId as (typeof planIds)[number]) ||
        value.status !== 'PASSED' ||
        !isDeepStrictEqual(
          value.variant,
          expectedVariants[value.planId as keyof typeof expectedVariants]
        )
      ) {
        throw new TypeError(diagnostic);
      }
      const result = projectionEnvelope('official-plan-result', value.result);

      return cloneAndDeepFreeze({
        planId: value.planId,
        resultId: value.resultId,
        resultSha256: result.projectionSha256,
        result,
      });
    });
    const sortedAdapterControls = adapterControls.toSorted((left, right) =>
      bytewiseCompare(left.id, right.id)
    );
    const sortedPlanResults = planResults.toSorted((left, right) =>
      bytewiseCompare(left.planId, right.planId)
    );
    const adapterIds = sortedAdapterControls.map(({ id }) => id);
    const officialResultIds = sortedPlanResults
      .map(({ resultId }) => resultId)
      .toSorted(bytewiseCompare);

    if (
      JSON.stringify(adapterIds) !== JSON.stringify(phase1ConformanceAdapterControlIds) ||
      new Set(officialResultIds).size !== officialResultIds.length ||
      (mode === 'runtime-candidate'
        ? sortedPlanResults.length !== planIds.length ||
          !planIds.every((id) => sortedPlanResults.some(({ planId }) => planId === id))
        : sortedPlanResults.length > 0)
    ) {
      throw new TypeError(diagnostic);
    }
    const evidence = cloneAndDeepFreeze({
      schemaVersion: 1 as const,
      mode,
      provenance,
      sanitizerSuccess: true as const,
      adapterControls: sortedAdapterControls,
      officialResultIds,
      planResults: sortedPlanResults,
    });

    assertPhase1EvidenceIsSanitized(evidence);

    return evidence;
  } catch {
    throw new TypeError(diagnostic);
  }
};

/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods */
