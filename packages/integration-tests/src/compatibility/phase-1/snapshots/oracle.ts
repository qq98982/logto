/* eslint-disable no-restricted-syntax, @typescript-eslint/no-unnecessary-boolean-literal-compare -- Snapshot construction validates one exact closed cross-registry set. */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import { isBoundedTimestampEnvelope } from '../bounded-timestamp.js';
import { canonicalBrowserFlows } from '../browser/index.js';
import { assertSerializedPhase1ArtifactEvidenceIsSanitized } from '../evidence.js';
import {
  cloneAndDeepFreeze,
  differentialScenarioIds,
  oracleCommit,
  snapshotClosedDataGraph,
} from '../model.js';

export const oracleSnapshotIds = Object.freeze([
  ...differentialScenarioIds.map((id) => `scenario:${id}` as const),
  ...canonicalBrowserFlows.map(({ id }) => `browser:${id}` as const),
]);

export type OracleSnapshotInput = Readonly<{
  recordOracle: boolean;
  referenceCommit: string;
  imageDigest: string;
  harnessClean: boolean;
  sanitizerSuccess: boolean;
  projections: ReadonlyArray<
    Readonly<{
      id: string;
      value: Readonly<JsonObject>;
    }>
  >;
}>;

export type OracleSnapshotSet = Readonly<{
  schemaVersion: 1;
  referenceCommit: typeof oracleCommit;
  imageDigest: string;
  sanitizerSuccess: true;
  snapshots: ReadonlyArray<
    Readonly<{
      id: string;
      projectionSha256: string;
      value: Readonly<JsonObject>;
    }>
  >;
}>;

const diagnostic = 'Invalid phase 1 oracle snapshot';
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;

const bytewiseCompare = (left: string, right: string): number =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

const snapshotTimestampMarker = '$boundedTimestamp';

const hasInvalidSnapshotTimestampMarker = (
  value: JsonValue,
  allowCanonicalMarker: boolean
): boolean => {
  if (Array.isArray(value)) {
    return value.some((item) => hasInvalidSnapshotTimestampMarker(item, allowCanonicalMarker));
  }
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  if (Object.hasOwn(value, snapshotTimestampMarker)) {
    const marker = value[snapshotTimestampMarker];

    return (
      !allowCanonicalMarker ||
      Object.keys(value).length !== 1 ||
      typeof marker !== 'number' ||
      !Number.isFinite(marker) ||
      marker < 0
    );
  }

  return Object.values(value).some((nested) =>
    hasInvalidSnapshotTimestampMarker(nested, allowCanonicalMarker)
  );
};

const canonicalSnapshotValue = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalSnapshotValue(item));
  }
  if (typeof value !== 'object' || value === null) {
    return value;
  }
  if (isBoundedTimestampEnvelope(value)) {
    return { [snapshotTimestampMarker]: value.$toleranceSeconds };
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, nested]) => [key, canonicalSnapshotValue(nested)])
  );
};

const canonicalValue = (value: JsonValue): JsonValue => {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalValue(item));
  }
  if (typeof value !== 'object' || value === null) {
    return value;
  }

  return Object.fromEntries(
    Object.keys(value)
      .toSorted(bytewiseCompare)
      .map((key) => [key, canonicalValue(value[key] as JsonValue)])
  );
};

const projectionHash = (value: Readonly<JsonObject>): string =>
  createHash('sha256')
    .update(`${JSON.stringify(canonicalValue(value as JsonValue))}\n`, 'utf8')
    .digest('hex');

const hasExactSnapshotKeys = (value: unknown): boolean =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Reflect.ownKeys(value).length === 3 &&
  Reflect.has(value, 'id') &&
  Reflect.has(value, 'projectionSha256') &&
  Reflect.has(value, 'value');

const buildOracleSnapshotSet = (
  input: OracleSnapshotInput,
  allowCanonicalTimestampMarkers: boolean
): OracleSnapshotSet => {
  try {
    if (
      !input.recordOracle ||
      input.referenceCommit !== oracleCommit ||
      !imageDigestPattern.test(input.imageDigest) ||
      !input.harnessClean ||
      input.sanitizerSuccess !== true ||
      input.projections.length !== oracleSnapshotIds.length
    ) {
      throw new TypeError(diagnostic);
    }
    const snapshots = input.projections
      .map(({ id, value }) => {
        if (!jsonValueGuard.safeParse(value).success || Array.isArray(value)) {
          throw new TypeError(diagnostic);
        }
        assertSerializedPhase1ArtifactEvidenceIsSanitized(value);
        if (hasInvalidSnapshotTimestampMarker(value, allowCanonicalTimestampMarkers)) {
          throw new TypeError(diagnostic);
        }
        const canonicalProjection = canonicalSnapshotValue(value);

        if (
          typeof canonicalProjection !== 'object' ||
          canonicalProjection === null ||
          Array.isArray(canonicalProjection)
        ) {
          throw new TypeError(diagnostic);
        }
        assertSerializedPhase1ArtifactEvidenceIsSanitized(canonicalProjection);

        return cloneAndDeepFreeze({
          id,
          projectionSha256: projectionHash(canonicalProjection),
          value: canonicalProjection,
        });
      })
      .toSorted((left, right) => bytewiseCompare(left.id, right.id));

    if (
      new Set(snapshots.map(({ id }) => id)).size !== oracleSnapshotIds.length ||
      snapshots.some(({ id }, index) => id !== oracleSnapshotIds.toSorted(bytewiseCompare)[index])
    ) {
      throw new TypeError(diagnostic);
    }

    return cloneAndDeepFreeze({
      schemaVersion: 1 as const,
      referenceCommit: oracleCommit,
      imageDigest: input.imageDigest,
      sanitizerSuccess: true as const,
      snapshots,
    });
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const createOracleSnapshotSet = (input: OracleSnapshotInput): OracleSnapshotSet =>
  buildOracleSnapshotSet(input, false);

export const assertOracleSnapshotSet = (value: unknown): OracleSnapshotSet => {
  try {
    const parsed = snapshotClosedDataGraph<Record<string, unknown>>(value);

    if (
      !parsed ||
      Array.isArray(parsed) ||
      Reflect.ownKeys(parsed).length !== 5 ||
      parsed.schemaVersion !== 1 ||
      !Array.isArray(parsed.snapshots) ||
      parsed.snapshots.some((item) => !hasExactSnapshotKeys(item))
    ) {
      throw new TypeError(diagnostic);
    }
    const snapshotSet = parsed as unknown as OracleSnapshotSet;
    const reconstructed = buildOracleSnapshotSet(
      {
        recordOracle: true,
        referenceCommit: snapshotSet.referenceCommit,
        imageDigest: snapshotSet.imageDigest,
        harnessClean: true,
        sanitizerSuccess: snapshotSet.sanitizerSuccess,
        projections: snapshotSet.snapshots,
      },
      true
    );

    if (
      snapshotSet.snapshots.some(
        (snapshot, index) =>
          snapshot.projectionSha256 !== reconstructed.snapshots[index]?.projectionSha256 ||
          !isDeepStrictEqual(snapshot.value, reconstructed.snapshots[index]?.value)
      )
    ) {
      throw new TypeError(diagnostic);
    }

    return reconstructed;
  } catch {
    throw new TypeError(diagnostic);
  }
};

/* eslint-enable no-restricted-syntax, @typescript-eslint/no-unnecessary-boolean-literal-compare */
