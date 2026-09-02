/* Candidate-only evidence owns recursive forbidden-vocabulary checks and fixed redacted construction. */
import { z } from 'zod';

import { assertEvidenceIsSanitized } from '../../evidence.js';
import { jsonValueGuard } from '../../model.js';
import type { JsonValue } from '../../normalize.js';
import {
  candidateInvariantNegativeControlPointers,
  candidateInvariantScenarioIds,
  candidateInvariantScenarioIdGuard,
  oracleCommit,
  phase0HarnessCommit,
  snapshotClosedDataGraph,
} from '../model.js';

const absolutePointerPattern = /^(?:\/(?:[^~]|~[01])*)+$/u;
const forbiddenProjectionKeys = new Set([
  'oracle',
  'candidate',
  'differences',
  'compare',
  'oraclecomparison',
]);
const forbiddenEphemeralProjectionKeys = new Set([
  'code',
  'state',
  'nonce',
  'codeverifier',
  'codechallenge',
  'verificationid',
  'verificationcredential',
  'verificationtoken',
]);
const privateJwkMemberNames = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const safeBooleanMetadataKeys = new Set(['tokensigning', 'cookiesealing', 'cookieverification']);

const normalizeKey = (key: string) => key.replaceAll(/[_\s-]/gu, '').toLowerCase();
const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isSafeCodeState = (value: unknown): boolean =>
  isRecord(value) &&
  Object.keys(value).length === 1 &&
  Object.keys(value)[0] === 'consumed' &&
  typeof value.consumed === 'boolean';

const containsPrivateJwk = (value: unknown): boolean => {
  if (Array.isArray(value)) {
    return value.some((item) => containsPrivateJwk(item));
  }
  if (!isRecord(value)) {
    return false;
  }

  if (
    typeof value.kty === 'string' &&
    Object.keys(value).some((member) => privateJwkMemberNames.has(member))
  ) {
    return true;
  }

  return Object.entries(value).some(
    ([key, nested]) =>
      (normalizeKey(key) === 'jwk' &&
        (!isRecord(nested) ||
          Object.keys(nested).some((member) => privateJwkMemberNames.has(member)))) ||
      containsPrivateJwk(nested)
  );
};

const assertGenericEvidenceSafety = (value: unknown): void => {
  if (typeof value === 'string') {
    assertEvidenceIsSanitized({ value });
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      assertGenericEvidenceSafety(item);
    }
    return;
  }
  if (!isRecord(value)) {
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeKey(key);

    assertEvidenceIsSanitized({
      [safeBooleanMetadataKeys.has(normalized) ? 'metadata' : key]: null,
    });
    assertGenericEvidenceSafety(nested);
  }
};

const containsForbiddenProjectionStructure = (value: unknown): boolean => {
  if (Array.isArray(value)) {
    return value.some((item) => containsForbiddenProjectionStructure(item));
  }
  if (!isRecord(value)) {
    return false;
  }

  return Object.entries(value).some(([key, nested]) => {
    const normalized = normalizeKey(key);

    return (
      forbiddenProjectionKeys.has(normalized) ||
      (forbiddenEphemeralProjectionKeys.has(normalized) &&
        !(normalized === 'code' && isSafeCodeState(nested))) ||
      (safeBooleanMetadataKeys.has(normalized) && typeof nested !== 'boolean') ||
      containsForbiddenProjectionStructure(nested)
    );
  });
};

export const candidateInvariantProjectionGuard = jsonValueGuard.superRefine((value, context) => {
  if (containsForbiddenProjectionStructure(value) || containsPrivateJwk(value)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Candidate-only projection structure is invalid',
    });
  }
});

const candidateDifferenceGuard = z
  .object({
    path: z.string().regex(absolutePointerPattern).max(512),
    expected: candidateInvariantProjectionGuard.optional(),
    actual: candidateInvariantProjectionGuard.optional(),
  })
  .strict()
  .superRefine(({ expected, actual }, context) => {
    if (expected === undefined && actual === undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'Difference must contain a value' });
    }
  });

const provenanceGuard = z
  .object({
    referenceCommit: z.literal(oracleCommit),
    harnessCommit: z.literal(phase0HarnessCommit),
  })
  .strict();

const positiveControlGuard = z
  .object({
    passed: z.literal(true),
    differences: z.array(candidateDifferenceGuard).length(0),
  })
  .strict();

const negativeControlGuard = z
  .object({
    passed: z.literal(true),
    differences: z.array(candidateDifferenceGuard).length(1),
  })
  .strict();

export const candidateInvariantEvidenceGuard = z
  .object({
    schemaVersion: z.literal(1),
    evidenceKind: z.literal('candidate-invariant'),
    scenarioId: candidateInvariantScenarioIdGuard,
    provenance: provenanceGuard,
    candidate: z.object({ outcome: candidateInvariantProjectionGuard }).strict(),
    positiveControl: positiveControlGuard,
    negativeControl: negativeControlGuard,
  })
  .strict()
  .superRefine(({ scenarioId, negativeControl }, context) => {
    const scenarioIndex = candidateInvariantScenarioIds.indexOf(scenarioId);
    const expectedPointer = candidateInvariantNegativeControlPointers[scenarioIndex];

    if (!expectedPointer || negativeControl.differences[0]?.path !== expectedPointer) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['negativeControl', 'differences', 0, 'path'],
        message: 'Negative control pointer does not match the candidate invariant',
      });
    }
  });

export type CandidateInvariantEvidence = z.infer<typeof candidateInvariantEvidenceGuard>;

const diagnostic = 'Invalid phase 1 candidate invariant evidence';

export const assertCandidateInvariantProjectionIsSanitized = (value: unknown): void => {
  try {
    const snapshot = snapshotClosedDataGraph<unknown>(value);

    if (snapshot === undefined || !candidateInvariantProjectionGuard.safeParse(snapshot).success) {
      throw new TypeError(diagnostic);
    }
    assertGenericEvidenceSafety(snapshot);
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const createCandidateInvariantEvidence = (
  input: Omit<CandidateInvariantEvidence, 'schemaVersion' | 'evidenceKind'>
): CandidateInvariantEvidence => {
  try {
    const snapshot = snapshotClosedDataGraph<unknown>({
      schemaVersion: 1,
      evidenceKind: 'candidate-invariant',
      ...input,
    });

    if (snapshot === undefined) {
      throw new TypeError(diagnostic);
    }
    assertGenericEvidenceSafety(snapshot);
    const parsed = candidateInvariantEvidenceGuard.safeParse(snapshot);

    if (!parsed.success) {
      throw new TypeError(diagnostic);
    }
    const result = snapshotClosedDataGraph<CandidateInvariantEvidence>(parsed.data);

    if (result === undefined) {
      throw new TypeError(diagnostic);
    }
    assertGenericEvidenceSafety(result);

    return result;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export type CandidateInvariantDifference = Readonly<{
  path: string;
  expected?: JsonValue;
  actual?: JsonValue;
}>;
