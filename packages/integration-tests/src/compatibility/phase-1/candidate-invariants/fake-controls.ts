/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-non-null-assertion, complexity, no-restricted-syntax -- The fake executor applies one closed JSON-pointer fault to a private mutable clone, then emits only frozen candidate-local evidence. */
import { isDeepStrictEqual } from 'node:util';

import { z } from 'zod';

import { jsonValueGuard } from '../../model.js';
import type { JsonValue } from '../../normalize.js';
import {
  candidateInvariantScenarioIds,
  oracleCommit,
  phase0HarnessCommit,
  snapshotClosedDataGraph,
  type CandidateInvariantContract,
  type CandidateInvariantScenarioId,
} from '../model.js';

import {
  assertCandidateInvariantProjectionIsSanitized,
  createCandidateInvariantEvidence,
  type CandidateInvariantDifference,
  type CandidateInvariantEvidence,
} from './evidence.js';
import { getCandidateInvariantContract } from './index.js';

const absolutePointerPattern = /^(?:\/(?:[^~]|~[01])*)+$/u;
const arrayIndexPattern = /^(?:0|[1-9]\d*)$/u;
const forbiddenPointerSegments = new Set(['__proto__', 'constructor', 'prototype']);
const missing = Symbol('missing-candidate-control-value');
const diagnostic = 'Invalid phase 1 candidate invariant fake control';

const positiveInputGuard = z.object({ variant: z.literal('positive') }).strict();
const faultGuard = z
  .object({
    operation: z.enum(['add', 'replace']),
    path: z.string().regex(absolutePointerPattern).max(512),
    value: jsonValueGuard,
  })
  .strict();
const negativeInputGuard = z.object({ variant: z.literal('negative'), fault: faultGuard }).strict();

type MutableJson = JsonValue;

const decodePointer = (pointer: string): readonly string[] => {
  if (!absolutePointerPattern.test(pointer) || pointer.length > 512) {
    throw new TypeError(diagnostic);
  }
  const segments = pointer
    .slice(1)
    .split('/')
    .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'));

  if (segments.some((segment) => forbiddenPointerSegments.has(segment))) {
    throw new TypeError(diagnostic);
  }

  return segments;
};

const mutableClone = (value: unknown): MutableJson =>
  JSON.parse(JSON.stringify(value)) as MutableJson;

const isRecord = (value: unknown): value is Record<string, MutableJson> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const readPointer = (
  root: MutableJson,
  segments: readonly string[]
): JsonValue | typeof missing => {
  let cursor: MutableJson = root;

  for (const segment of segments) {
    if (Array.isArray(cursor)) {
      if (!arrayIndexPattern.test(segment)) {
        return missing;
      }
      const index = Number(segment);

      if (index >= cursor.length) {
        return missing;
      }
      cursor = cursor[index]!;
    } else if (isRecord(cursor)) {
      if (!Object.hasOwn(cursor, segment)) {
        return missing;
      }
      cursor = cursor[segment]!;
    } else {
      return missing;
    }
  }

  return cursor;
};

const createIntermediateContainer = (nextSegment: string): MutableJson =>
  arrayIndexPattern.test(nextSegment) ? [] : {};

const applyFault = (
  source: JsonValue,
  fault: z.infer<typeof faultGuard>
): Readonly<{ before: JsonValue | typeof missing; projection: JsonValue }> => {
  const segments = decodePointer(fault.path);
  const beforeSource = mutableClone(source);
  const before = readPointer(beforeSource, segments);
  const projection = mutableClone(source);
  let cursor: MutableJson = projection;

  for (const [index, segment] of segments.slice(0, -1).entries()) {
    const nextSegment = segments[index + 1]!;

    if (Array.isArray(cursor)) {
      if (!arrayIndexPattern.test(segment)) {
        throw new TypeError(diagnostic);
      }
      const arrayIndex = Number(segment);

      if (arrayIndex === cursor.length && fault.operation === 'add') {
        cursor.push(createIntermediateContainer(nextSegment));
      }
      if (arrayIndex >= cursor.length) {
        throw new TypeError(diagnostic);
      }
      cursor = cursor[arrayIndex]!;
    } else if (isRecord(cursor)) {
      if (!Object.hasOwn(cursor, segment) && fault.operation === 'add') {
        cursor[segment] = createIntermediateContainer(nextSegment);
      }
      const child = cursor[segment];

      if (child === undefined) {
        throw new TypeError(diagnostic);
      }
      cursor = child;
    } else {
      throw new TypeError(diagnostic);
    }
  }

  const leaf = segments.at(-1)!;
  const value = mutableClone(fault.value);

  if (Array.isArray(cursor)) {
    if (!arrayIndexPattern.test(leaf)) {
      throw new TypeError(diagnostic);
    }
    const arrayIndex = Number(leaf);

    if (fault.operation === 'add') {
      if (arrayIndex !== cursor.length) {
        throw new TypeError(diagnostic);
      }
      cursor.push(value);
    } else {
      if (arrayIndex >= cursor.length) {
        throw new TypeError(diagnostic);
      }
      cursor[arrayIndex] = value;
    }
  } else if (isRecord(cursor)) {
    const exists = Object.hasOwn(cursor, leaf);

    if ((fault.operation === 'add' && exists) || (fault.operation === 'replace' && !exists)) {
      throw new TypeError(diagnostic);
    }
    cursor[leaf] = value;
  } else {
    throw new TypeError(diagnostic);
  }

  const snapshot = snapshotClosedDataGraph<JsonValue>(projection);

  if (snapshot === undefined) {
    throw new TypeError(diagnostic);
  }

  return Object.freeze({ before, projection: snapshot as JsonValue });
};

const differenceFor = (
  pointer: string,
  before: JsonValue | typeof missing,
  projection: JsonValue
): CandidateInvariantDifference => {
  const actual = readPointer(mutableClone(projection), decodePointer(pointer));

  if (actual === missing) {
    throw new TypeError(diagnostic);
  }
  if (before !== missing && isDeepStrictEqual(before, actual)) {
    throw new TypeError(diagnostic);
  }

  return Object.freeze({
    path: pointer,
    ...(before === missing ? {} : { expected: before }),
    actual,
  });
};

const executeContract = (contract: CandidateInvariantContract): CandidateInvariantEvidence => {
  try {
    const safeContract = snapshotClosedDataGraph<CandidateInvariantContract>(contract);

    if (
      safeContract === undefined ||
      !positiveInputGuard.safeParse(safeContract.positiveControl.input).success
    ) {
      throw new TypeError(diagnostic);
    }
    const negativeInput = negativeInputGuard.parse(safeContract.negativeControl.input);
    const pointer = safeContract.negativeControl.expectedDifferencePointer;

    if (pointer === null || negativeInput.fault.path !== pointer) {
      throw new TypeError(diagnostic);
    }
    const positiveSnapshot = snapshotClosedDataGraph<JsonValue>(
      safeContract.positiveControl.expectedProjection
    );

    if (positiveSnapshot === undefined) {
      throw new TypeError(diagnostic);
    }
    const positive = positiveSnapshot as JsonValue;
    assertCandidateInvariantProjectionIsSanitized(positive);
    const negative = applyFault(positive, negativeInput.fault);

    assertCandidateInvariantProjectionIsSanitized(negative.projection);
    if (!isDeepStrictEqual(negative.projection, safeContract.negativeControl.expectedProjection)) {
      throw new TypeError(diagnostic);
    }
    const difference = differenceFor(pointer, negative.before, negative.projection);
    const evidence = createCandidateInvariantEvidence({
      scenarioId: safeContract.id,
      provenance: { referenceCommit: oracleCommit, harnessCommit: phase0HarnessCommit },
      candidate: { outcome: positive },
      positiveControl: { passed: true, differences: [] },
      negativeControl: { passed: true, differences: [difference] },
    });

    if (
      evidence.positiveControl.differences.length > 0 ||
      evidence.negativeControl.differences.length !== 1 ||
      evidence.negativeControl.differences[0]?.path !== pointer
    ) {
      throw new TypeError(diagnostic);
    }

    return evidence;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runCandidateInvariantFakeControls = (
  id: CandidateInvariantScenarioId
): CandidateInvariantEvidence => {
  try {
    return executeContract(getCandidateInvariantContract(id));
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const runAllCandidateInvariantFakeControls = (): readonly CandidateInvariantEvidence[] =>
  Object.freeze(candidateInvariantScenarioIds.map((id) => runCandidateInvariantFakeControls(id)));

export const runCandidateInvariantFakeControlsForTesting = (
  contract: CandidateInvariantContract
): CandidateInvariantEvidence => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }

  return executeContract(contract);
};

export const applyCandidateInvariantFaultForTesting = (
  source: JsonValue,
  fault: unknown
): JsonValue => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }

  try {
    assertCandidateInvariantProjectionIsSanitized(source);
    const result = applyFault(source, faultGuard.parse(fault));
    assertCandidateInvariantProjectionIsSanitized(result.projection);

    return result.projection;
  } catch {
    throw new TypeError(diagnostic);
  }
};

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-non-null-assertion, complexity, no-restricted-syntax */
