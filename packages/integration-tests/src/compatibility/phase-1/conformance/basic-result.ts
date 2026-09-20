/* eslint-disable complexity, no-restricted-syntax, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The fixed Basic plan result must preserve the terminal's explicit null review branch while deriving counts through one stateful validation pass. */
import { exactArtifactKeys, isArtifactRecord } from '../artifact-contract.js';

export const phase1BasicModuleNames = Object.freeze([
  'oidcc-server',
  'oidcc-response-type-missing',
  'oidcc-userinfo-get',
  'oidcc-userinfo-post-header',
  'oidcc-userinfo-post-body',
  'oidcc-ensure-request-without-nonce-succeeds-for-code-flow',
  'oidcc-scope-profile',
  'oidcc-scope-email',
  'oidcc-scope-address',
  'oidcc-scope-phone',
  'oidcc-scope-all',
  'oidcc-alternate-happy-flow',
  'oidcc-display-page',
  'oidcc-display-popup',
  'oidcc-prompt-login',
  'oidcc-prompt-none-not-logged-in',
  'oidcc-prompt-none-logged-in',
  'oidcc-max-age-1',
  'oidcc-max-age-10000',
  'oidcc-ensure-request-with-unknown-parameter-succeeds',
  'oidcc-id-token-hint',
  'oidcc-login-hint',
  'oidcc-ui-locales',
  'oidcc-claims-locales',
  'oidcc-ensure-request-with-acr-values-succeeds',
  'oidcc-codereuse',
  'oidcc-codereuse-30seconds',
  'oidcc-ensure-registered-redirect-uri',
  'oidcc-ensure-post-request-succeeds',
  'oidcc-server-client-secret-post',
  'oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported',
  'oidcc-claims-essential',
  'oidcc-ensure-request-object-with-redirect-uri',
  'oidcc-refresh-token',
  'oidcc-ensure-request-with-valid-pkce-succeeds',
] as const);

export const phase1BasicScreenshotReviewConditions = Object.freeze({
  'oidcc-response-type-missing': 'ExpectResponseTypeMissingErrorPage',
  'oidcc-prompt-login': 'ExpectSecondLoginPage',
  'oidcc-max-age-1': 'ExpectSecondLoginPage',
  'oidcc-ensure-registered-redirect-uri': 'ExpectRedirectUriErrorPage',
  'oidcc-ensure-request-object-with-redirect-uri': 'ExpectRedirectUriErrorPage',
} as const);

const mandatoryScreenshotModules: ReadonlySet<string> = new Set([
  'oidcc-prompt-login',
  'oidcc-max-age-1',
  'oidcc-ensure-registered-redirect-uri',
]);

type Phase1BasicModuleName = (typeof phase1BasicModuleNames)[number];
type Phase1BasicReviewedModuleName = keyof typeof phase1BasicScreenshotReviewConditions;

export type Phase1BasicScreenshotReview = Readonly<{
  placeholderId: string;
  conditionId: (typeof phase1BasicScreenshotReviewConditions)[Phase1BasicReviewedModuleName];
  imageSha256: string;
  reviewRecordSha256: string;
  reviewer: string;
  decision: 'APPROVE';
}>;

export type Phase1BasicModuleResult = Readonly<{
  testId: string;
  testName: Phase1BasicModuleName;
  status: 'FINISHED';
  result: 'PASSED' | 'REVIEW';
  conditionLogSha256: string;
  review: Phase1BasicScreenshotReview | null;
}>;

export type Phase1BasicAcceptedResult = Readonly<{
  outcome: 'accepted';
  moduleCount: 35;
  passedModuleCount: number;
  reviewedModuleCount: number;
  modules: readonly Phase1BasicModuleResult[];
}>;

const diagnostic = 'Invalid phase 1 Basic conformance result';
const sha256Pattern = /^[0-9a-f]{64}$/u;
const testIdPattern = /^[A-Za-z0-9]{15}$/u;
const placeholderIdPattern = /^[A-Za-z0-9]{10}$/u;
const reviewerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

export const requirePhase1BasicAcceptedResult = (value: unknown): Phase1BasicAcceptedResult => {
  if (
    !isArtifactRecord(value) ||
    !exactArtifactKeys(value, [
      'outcome',
      'moduleCount',
      'passedModuleCount',
      'reviewedModuleCount',
      'modules',
    ]) ||
    value.outcome !== 'accepted' ||
    value.moduleCount !== phase1BasicModuleNames.length ||
    !Number.isSafeInteger(value.passedModuleCount) ||
    !Number.isSafeInteger(value.reviewedModuleCount) ||
    !Array.isArray(value.modules) ||
    value.modules.length !== phase1BasicModuleNames.length
  ) {
    return fail();
  }

  const testIds = new Set<string>();
  const placeholderIds = new Set<string>();
  const reviewRecordHashes = new Set<string>();
  let passedModuleCount = 0;
  let reviewedModuleCount = 0;

  for (const [index, candidate] of value.modules.entries()) {
    if (
      !isArtifactRecord(candidate) ||
      !exactArtifactKeys(candidate, [
        'testId',
        'testName',
        'status',
        'result',
        'conditionLogSha256',
        'review',
      ]) ||
      typeof candidate.testId !== 'string' ||
      !testIdPattern.test(candidate.testId) ||
      testIds.has(candidate.testId) ||
      typeof candidate.testName !== 'string' ||
      candidate.testName !== phase1BasicModuleNames[index] ||
      candidate.status !== 'FINISHED' ||
      typeof candidate.conditionLogSha256 !== 'string' ||
      !sha256Pattern.test(candidate.conditionLogSha256)
    ) {
      return fail();
    }
    testIds.add(candidate.testId);

    if (candidate.result === 'PASSED') {
      if (candidate.review !== null || mandatoryScreenshotModules.has(candidate.testName)) {
        return fail();
      }
      passedModuleCount += 1;
      continue;
    }
    if (candidate.result !== 'REVIEW' || !isArtifactRecord(candidate.review)) {
      return fail();
    }

    const expectedCondition =
      phase1BasicScreenshotReviewConditions[candidate.testName as Phase1BasicReviewedModuleName];
    const { review } = candidate;
    if (
      expectedCondition === undefined ||
      !exactArtifactKeys(review, [
        'placeholderId',
        'conditionId',
        'imageSha256',
        'reviewRecordSha256',
        'reviewer',
        'decision',
      ]) ||
      typeof review.placeholderId !== 'string' ||
      !placeholderIdPattern.test(review.placeholderId) ||
      review.conditionId !== expectedCondition ||
      typeof review.imageSha256 !== 'string' ||
      !sha256Pattern.test(review.imageSha256) ||
      typeof review.reviewRecordSha256 !== 'string' ||
      !sha256Pattern.test(review.reviewRecordSha256) ||
      typeof review.reviewer !== 'string' ||
      !reviewerPattern.test(review.reviewer) ||
      review.decision !== 'APPROVE' ||
      placeholderIds.has(review.placeholderId) ||
      reviewRecordHashes.has(review.reviewRecordSha256)
    ) {
      return fail();
    }
    placeholderIds.add(review.placeholderId);
    reviewRecordHashes.add(review.reviewRecordSha256);
    reviewedModuleCount += 1;
  }

  if (
    value.passedModuleCount !== passedModuleCount ||
    value.reviewedModuleCount !== reviewedModuleCount ||
    passedModuleCount + reviewedModuleCount !== phase1BasicModuleNames.length
  ) {
    return fail();
  }

  return value as Phase1BasicAcceptedResult;
};

/* eslint-enable complexity, no-restricted-syntax, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
