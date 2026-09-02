/* eslint-disable no-restricted-syntax, @typescript-eslint/no-unnecessary-boolean-literal-compare -- Snapshot construction validates one exact closed cross-registry set. */
import { createHash } from 'node:crypto';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
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

export const createOracleSnapshotSet = (input: OracleSnapshotInput): OracleSnapshotSet => {
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

        return cloneAndDeepFreeze({ id, projectionSha256: projectionHash(value), value });
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
    const reconstructed = createOracleSnapshotSet({
      recordOracle: true,
      referenceCommit: snapshotSet.referenceCommit,
      imageDigest: snapshotSet.imageDigest,
      harnessClean: true,
      sanitizerSuccess: snapshotSet.sanitizerSuccess,
      projections: snapshotSet.snapshots,
    });

    if (
      snapshotSet.snapshots.some(
        (snapshot, index) =>
          snapshot.projectionSha256 !== reconstructed.snapshots[index]?.projectionSha256
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
