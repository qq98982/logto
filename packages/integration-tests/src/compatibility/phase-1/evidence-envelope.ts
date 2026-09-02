/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods -- Canonical JSON hashing recursively walks the complete closed evidence graph. */
import { createHash } from 'node:crypto';

import { jsonValueGuard } from '../model.js';
import type { JsonObject, JsonValue } from '../normalize.js';

import {
  assertPhase1EvidenceIsSanitized,
  snapshotPhase1EvidencePreservingVerifiedTokens,
} from './evidence.js';
import { cloneAndDeepFreeze, snapshotClosedDataGraph } from './model.js';

export type Phase1EvidenceProvenance = Readonly<{
  harnessCommit: string;
  profileSha256: string;
  schemaSha256: string;
  imageDigest: string;
}>;

export type Phase1ProjectionEnvelope<Label extends string = string> = Readonly<{
  label: Label;
  projectionSha256: string;
  value: Readonly<JsonObject>;
}>;

const diagnostic = 'Invalid phase 1 evidence envelope';
const commitPattern = /^[0-9a-f]{40}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;
const labelPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

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

const exactKeys = (
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[]
): boolean => {
  const keys = Reflect.ownKeys(value);

  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === 'string' && expected.includes(key))
  );
};

export const hashCanonicalPhase1Json = (value: unknown): string => {
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

export const createPhase1EvidenceProvenance = (value: unknown): Phase1EvidenceProvenance => {
  try {
    const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);

    if (
      !snapshot ||
      Array.isArray(snapshot) ||
      !exactKeys(snapshot, ['harnessCommit', 'profileSha256', 'schemaSha256', 'imageDigest']) ||
      typeof snapshot.harnessCommit !== 'string' ||
      !commitPattern.test(snapshot.harnessCommit) ||
      typeof snapshot.profileSha256 !== 'string' ||
      !sha256Pattern.test(snapshot.profileSha256) ||
      typeof snapshot.schemaSha256 !== 'string' ||
      !sha256Pattern.test(snapshot.schemaSha256) ||
      typeof snapshot.imageDigest !== 'string' ||
      !imageDigestPattern.test(snapshot.imageDigest)
    ) {
      throw new TypeError(diagnostic);
    }
    const provenance = cloneAndDeepFreeze({
      harnessCommit: snapshot.harnessCommit,
      profileSha256: snapshot.profileSha256,
      schemaSha256: snapshot.schemaSha256,
      imageDigest: snapshot.imageDigest,
    });

    assertPhase1EvidenceIsSanitized(provenance);

    return provenance;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const createPhase1ProjectionEnvelope = <Label extends string>(
  label: Label,
  value: unknown
): Phase1ProjectionEnvelope<Label> => {
  try {
    assertPhase1EvidenceIsSanitized(value);
    const snapshot = snapshotPhase1EvidencePreservingVerifiedTokens<JsonObject>(value);

    if (
      !labelPattern.test(label) ||
      Array.isArray(snapshot) ||
      !jsonValueGuard.safeParse(snapshot).success
    ) {
      throw new TypeError(diagnostic);
    }
    assertPhase1EvidenceIsSanitized(snapshot);
    const envelope = snapshotPhase1EvidencePreservingVerifiedTokens<
      Phase1ProjectionEnvelope<Label>
    >({
      label,
      projectionSha256: hashCanonicalPhase1Json(snapshot),
      value: snapshot,
    });

    assertPhase1EvidenceIsSanitized(envelope);

    return envelope;
  } catch {
    throw new TypeError(diagnostic);
  }
};

/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-mutating-methods */
