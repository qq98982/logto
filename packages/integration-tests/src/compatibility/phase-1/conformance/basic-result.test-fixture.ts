/* eslint-disable no-restricted-syntax -- The fixture indexes a closed condition map from the fixed module registry. */
import {
  phase1BasicModuleNames,
  phase1BasicScreenshotReviewConditions,
  type Phase1BasicAcceptedResult,
} from './basic-result.js';

const hash = (value: number): string => value.toString(16).padStart(64, '0');

export const createPhase1BasicAcceptedResultFixture = (
  reviewedNames: ReadonlyArray<keyof typeof phase1BasicScreenshotReviewConditions> = [
    'oidcc-prompt-login',
    'oidcc-max-age-1',
    'oidcc-ensure-registered-redirect-uri',
  ]
): Phase1BasicAcceptedResult => {
  const reviewed = new Set<string>(reviewedNames);
  const modules = phase1BasicModuleNames.map((testName, index) => {
    const needsReview = reviewed.has(testName);
    const ordinal = index + 1;

    return {
      testId: `T${String(ordinal).padStart(14, '0')}`,
      testName,
      status: 'FINISHED' as const,
      result: needsReview ? ('REVIEW' as const) : ('PASSED' as const),
      conditionLogSha256: hash(ordinal),
      review: needsReview
        ? {
            placeholderId: `P${String(ordinal).padStart(9, '0')}`,
            conditionId:
              phase1BasicScreenshotReviewConditions[
                testName as keyof typeof phase1BasicScreenshotReviewConditions
              ],
            imageSha256: hash(100 + ordinal),
            reviewRecordSha256: hash(200 + ordinal),
            reviewer: 'gpt-5.6-sol',
            decision: 'APPROVE' as const,
          }
        : null,
    };
  });

  return {
    outcome: 'accepted',
    moduleCount: 35,
    passedModuleCount: modules.filter(({ result }) => result === 'PASSED').length,
    reviewedModuleCount: modules.filter(({ result }) => result === 'REVIEW').length,
    modules,
  };
};

/* eslint-enable no-restricted-syntax */
