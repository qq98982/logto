/* eslint-disable no-restricted-syntax, no-use-extend-native/no-use-extend-native -- The closed recursive comparator snapshots plain response records and deduplicates their keys. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2DifferentialScenarioId } from '../profile.js';

const approvedScenario = 'verification-code.failed-delivery-preserves-current';
const oracleMessage =
  'Error occurred in connector: {"message":"Message failed: 550 controlled rejection"}';
const candidateMessage = 'The email service could not accept the message.';
const oracleData = Object.freeze({ message: 'Message failed: 550 controlled rejection' });

const record = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

const differences = (left: unknown, right: unknown, pointer = ''): readonly string[] => {
  if (isDeepStrictEqual(left, right)) {
    return Object.freeze([]);
  }
  const leftRecord = record(left);
  const rightRecord = record(right);
  if (leftRecord && rightRecord) {
    return Object.freeze(
      [...new Set([...Object.keys(leftRecord), ...Object.keys(rightRecord)])]
        .toSorted()
        .flatMap((key) =>
          differences(
            leftRecord[key],
            rightRecord[key],
            `${pointer}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`
          )
        )
    );
  }
  return Object.freeze([pointer || '/']);
};

export const compareVerificationCodeProjections = (
  oracle: unknown,
  candidate: unknown,
  scenarioId: Phase2DifferentialScenarioId
): readonly string[] => {
  if (scenarioId !== approvedScenario) {
    return differences(oracle, candidate);
  }
  const source = record(oracle);
  const failed = record(source?.failed);
  if (
    !source ||
    !failed ||
    failed.status !== 400 ||
    failed.outcome !== 'error' ||
    failed.error !== 'connector.general' ||
    failed.message !== oracleMessage ||
    !isDeepStrictEqual(failed.data, oracleData)
  ) {
    return differences(oracle, candidate);
  }
  const mapped = Object.freeze({
    ...source,
    failed: Object.freeze(
      Object.fromEntries(
        Object.entries({ ...failed, message: candidateMessage }).filter(([key]) => key !== 'data')
      )
    ),
  });
  return differences(mapped, candidate);
};
/* eslint-enable no-restricted-syntax, no-use-extend-native/no-use-extend-native */
