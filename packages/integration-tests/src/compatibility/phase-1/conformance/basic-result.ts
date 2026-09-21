/* eslint-disable max-lines, complexity, no-restricted-syntax, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The fixed Basic plan result keeps its registry, closed proof schemas and counts in one validation boundary. */
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

export type Phase1BasicAbsentField = Readonly<{ present: false; type: 'missing' }>;
type UnsupportedField =
  | Phase1BasicAbsentField
  | Readonly<{
      present: true;
      type: 'boolean';
      value: false;
    }>;
type OptionalProofCommon = Readonly<{
  schemaVersion: 1;
  planInstanceId: string;
  testId: string;
  conditionLogSha256: string;
  infoSha256: string;
  discoveryResponseSha256: string;
  requestSha256: string;
  responseSha256: string;
  conditionCount: number;
  conditionEvidence: ReadonlyArray<
    Readonly<{
      id: string | null;
      source: string;
      result: 'SUCCESS' | 'INFO' | 'WARNING' | 'SKIPPED' | 'FINISHED' | null;
    }>
  >;
}>;
type VerifiedIssuance = Readonly<{
  responseSha256: string;
  compactSha256: string;
  verificationKeySha256: string;
  algorithm: 'RS256';
  responseScope: 'openid';
  acr: Phase1BasicAbsentField;
  amr: Phase1BasicAbsentField;
}>;

export type Phase1BasicOptionalResultProof = OptionalProofCommon &
  (
    | Readonly<{
        kind: 'acr-values-unsupported';
        discovery: Readonly<{ acrValuesSupported: Phase1BasicAbsentField }>;
        request: Readonly<{ scope: 'openid'; acrValues: '1 2' }>;
        issued: VerifiedIssuance;
      }>
    | Readonly<{
        kind: 'request-object-unsupported';
        discovery: Readonly<{ requestParameterSupported: UnsupportedField }>;
        request: Readonly<{
          method: 'GET';
          scope: 'openid';
          requestObjectSha256: string;
          outerRedirectSha256: string;
          outerCorrelation: Phase1BasicAbsentField;
        }>;
        rejection: Readonly<{
          httpStatus: 303;
          responseMode: 'query';
          error: 'request_not_supported';
          returnedFields: readonly ['error', 'iss'];
          callbackSha256: string;
          issuerSha256: string;
          returnedCorrelation: Phase1BasicAbsentField;
        }>;
        issued: null;
      }>
    | Readonly<{
        kind: 'claims-parameter-unsupported';
        discovery: Readonly<{
          claimsParameterSupported: Readonly<{ present: true; type: 'boolean'; value: false }>;
        }>;
        request: Readonly<{
          scope: 'openid';
          claims: Readonly<{ userinfo: Readonly<{ name: Readonly<{ essential: true }> }> }>;
        }>;
        issued: VerifiedIssuance & Readonly<{ name: Phase1BasicAbsentField }>;
        userInfo: Readonly<{
          responseSha256: string;
          source: 'CallUserInfoEndpoint';
          name: Phase1BasicAbsentField;
        }>;
      }>
  );

export type Phase1BasicModuleResult = Readonly<{
  testId: string;
  testName: Phase1BasicModuleName;
  status: 'FINISHED';
  result: 'PASSED' | 'REVIEW' | 'WARNING' | 'SKIPPED';
  conditionLogSha256: string;
  review: Phase1BasicScreenshotReview | null;
  exception: Phase1BasicOptionalResultProof | null;
}>;

export type Phase1BasicAcceptedResult = Readonly<{
  outcome: 'accepted';
  moduleCount: 35;
  passedModuleCount: number;
  reviewedModuleCount: number;
  exceptionModuleCount: number;
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

const missingField = (value: unknown): boolean =>
  isArtifactRecord(value) &&
  exactArtifactKeys(value, ['present', 'type']) &&
  value.present === false &&
  value.type === 'missing';
const falseField = (value: unknown): boolean =>
  isArtifactRecord(value) &&
  exactArtifactKeys(value, ['present', 'type', 'value']) &&
  value.present === true &&
  value.type === 'boolean' &&
  value.value === false;
const digest = (value: unknown): boolean => typeof value === 'string' && sha256Pattern.test(value);
const warningSuccessSources = [
  'GetDynamicServerConfiguration',
  'BuildPlainRedirectToAuthorizationEndpoint',
  'CallTokenEndpointAndReturnFullResponse',
  'ExtractIdTokenFromTokenResponse',
  'ValidateIdToken',
  'ValidateIdTokenStandardClaims',
  'ValidateIdTokenNonce',
  'ValidateIdTokenSignature',
  'CheckForSubjectInIdToken',
  'CheckStateInAuthorizationResponse',
] as const;
const requestObjectSuccessSources = [
  'GetDynamicServerConfiguration',
  'BuildRequestObjectByValueRedirectToAuthorizationEndpoint',
  'SerializeRequestObjectWithNullAlgorithm',
  'ExtractImplicitHashToCallbackResponse',
] as const;
const userInfoSuccessSources = [
  'CallUserInfoEndpoint',
  'ExtractUserInfoFromUserInfoEndpointResponse',
  'EnsureIdTokenDoesNotContainName',
  'VerifyUserInfoAndIdTokenInTokenEndpointSameSub',
  'ValidateUserInfoStandardClaims',
  'EnsureUserInfoContainsSub',
] as const;

const requireOptionalProof = (
  module: Readonly<Record<string, unknown>>,
  expectedPlanInstanceId?: string
): string => {
  const proof = module.exception;
  const acr = module.testName === phase1BasicModuleNames[24];
  const requestObject = module.testName === phase1BasicModuleNames[30];
  const claims = module.testName === phase1BasicModuleNames[31];
  const expectedKind = acr
    ? 'acr-values-unsupported'
    : requestObject
      ? 'request-object-unsupported'
      : 'claims-parameter-unsupported';
  if (
    (!acr && !requestObject && !claims) ||
    module.review !== null ||
    module.result !== (requestObject ? 'SKIPPED' : 'WARNING') ||
    !isArtifactRecord(proof) ||
    !exactArtifactKeys(proof, [
      'schemaVersion',
      'kind',
      'planInstanceId',
      'testId',
      'conditionLogSha256',
      'infoSha256',
      'discoveryResponseSha256',
      'requestSha256',
      'responseSha256',
      'conditionCount',
      'conditionEvidence',
      'discovery',
      'request',
      'issued',
      ...(requestObject ? ['rejection'] : []),
      ...(claims ? ['userInfo'] : []),
    ]) ||
    proof.schemaVersion !== 1 ||
    proof.kind !== expectedKind ||
    proof.testId !== module.testId ||
    proof.conditionLogSha256 !== module.conditionLogSha256 ||
    typeof proof.planInstanceId !== 'string' ||
    !/^[A-Za-z0-9]{13}$/u.test(proof.planInstanceId) ||
    (expectedPlanInstanceId !== undefined && proof.planInstanceId !== expectedPlanInstanceId) ||
    !['infoSha256', 'discoveryResponseSha256', 'requestSha256', 'responseSha256'].every((key) =>
      digest(proof[key])
    ) ||
    typeof proof.conditionCount !== 'number' ||
    !Number.isSafeInteger(proof.conditionCount) ||
    proof.conditionCount < 1 ||
    proof.conditionCount > 10_000 ||
    !Array.isArray(proof.conditionEvidence) ||
    proof.conditionEvidence.length > 32 ||
    proof.conditionEvidence.length > proof.conditionCount ||
    !isArtifactRecord(proof.discovery) ||
    !isArtifactRecord(proof.request)
  ) {
    return fail();
  }

  const successSources = requestObject
    ? [...requestObjectSuccessSources]
    : [...warningSuccessSources, ...(claims ? userInfoSuccessSources : [])];
  const finding = acr
    ? 'ValidateIdTokenACRClaimAgainstAcrValuesRequest'
    : claims
      ? 'EnsureUserInfoContainsName'
      : module.testName;
  const expectedRows = [
    ...successSources.map((source) => [source, 'SUCCESS']),
    [finding, requestObject ? 'SKIPPED' : 'WARNING'],
    [module.testName, 'FINISHED'],
  ];
  if (proof.conditionEvidence.length !== expectedRows.length) {
    return fail();
  }
  const rowIds = new Set<string>();
  for (const entry of proof.conditionEvidence) {
    if (
      !isArtifactRecord(entry) ||
      !exactArtifactKeys(entry, ['id', 'source', 'result']) ||
      typeof entry.id !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/u.test(entry.id) ||
      rowIds.has(entry.id) ||
      !expectedRows.some(([source, result]) => entry.source === source && entry.result === result)
    ) {
      return fail();
    }
    rowIds.add(entry.id);
  }
  for (const [source, result] of expectedRows) {
    if (
      proof.conditionEvidence.filter(
        (entry: unknown) =>
          isArtifactRecord(entry) && entry.source === source && entry.result === result
      ).length !== 1
    ) {
      return fail();
    }
  }
  const { request } = proof;
  const { discovery } = proof;
  if (requestObject) {
    const { rejection } = proof;
    if (
      !exactArtifactKeys(discovery, ['requestParameterSupported']) ||
      (!missingField(discovery.requestParameterSupported) &&
        !falseField(discovery.requestParameterSupported)) ||
      !exactArtifactKeys(request, [
        'method',
        'scope',
        'requestObjectSha256',
        'outerRedirectSha256',
        'outerCorrelation',
      ]) ||
      request.method !== 'GET' ||
      request.scope !== 'openid' ||
      !digest(request.requestObjectSha256) ||
      !digest(request.outerRedirectSha256) ||
      !missingField(request.outerCorrelation) ||
      proof.issued !== null ||
      !isArtifactRecord(rejection) ||
      !exactArtifactKeys(rejection, [
        'httpStatus',
        'responseMode',
        'error',
        'returnedFields',
        'callbackSha256',
        'issuerSha256',
        'returnedCorrelation',
      ]) ||
      rejection.httpStatus !== 303 ||
      rejection.responseMode !== 'query' ||
      rejection.error !== 'request_not_supported' ||
      !Array.isArray(rejection.returnedFields) ||
      rejection.returnedFields.length !== 2 ||
      rejection.returnedFields[0] !== 'error' ||
      rejection.returnedFields[1] !== 'iss' ||
      !digest(rejection.callbackSha256) ||
      rejection.callbackSha256 !== request.outerRedirectSha256 ||
      !digest(rejection.issuerSha256) ||
      !missingField(rejection.returnedCorrelation)
    ) {
      return fail();
    }
    return proof.planInstanceId;
  }
  const { issued } = proof;
  if (
    !isArtifactRecord(issued) ||
    !exactArtifactKeys(issued, [
      'responseSha256',
      'compactSha256',
      'verificationKeySha256',
      'algorithm',
      'responseScope',
      'acr',
      'amr',
      ...(claims ? ['name'] : []),
    ]) ||
    !['responseSha256', 'compactSha256', 'verificationKeySha256'].every((key) =>
      digest(issued[key])
    ) ||
    issued.algorithm !== 'RS256' ||
    issued.responseScope !== 'openid' ||
    !missingField(issued.acr) ||
    !missingField(issued.amr) ||
    request.scope !== 'openid'
  ) {
    return fail();
  }
  if (acr) {
    if (
      !exactArtifactKeys(discovery, ['acrValuesSupported']) ||
      !missingField(discovery.acrValuesSupported) ||
      !exactArtifactKeys(request, ['scope', 'acrValues']) ||
      request.acrValues !== '1 2'
    ) {
      return fail();
    }
  } else {
    const { userInfo } = proof;
    if (
      !exactArtifactKeys(discovery, ['claimsParameterSupported']) ||
      !falseField(discovery.claimsParameterSupported) ||
      !exactArtifactKeys(request, ['scope', 'claims']) ||
      !isArtifactRecord(request.claims) ||
      !exactArtifactKeys(request.claims, ['userinfo']) ||
      !isArtifactRecord(request.claims.userinfo) ||
      !exactArtifactKeys(request.claims.userinfo, ['name']) ||
      !isArtifactRecord(request.claims.userinfo.name) ||
      !exactArtifactKeys(request.claims.userinfo.name, ['essential']) ||
      request.claims.userinfo.name.essential !== true ||
      !missingField(issued.name) ||
      !isArtifactRecord(userInfo) ||
      !exactArtifactKeys(userInfo, ['responseSha256', 'source', 'name']) ||
      !digest(userInfo.responseSha256) ||
      userInfo.source !== 'CallUserInfoEndpoint' ||
      !missingField(userInfo.name)
    ) {
      return fail();
    }
  }
  return proof.planInstanceId;
};

export const requirePhase1BasicAcceptedResult = (
  value: unknown,
  expectedPlanInstanceId?: string
): Phase1BasicAcceptedResult => {
  if (
    !isArtifactRecord(value) ||
    !exactArtifactKeys(value, [
      'outcome',
      'moduleCount',
      'passedModuleCount',
      'reviewedModuleCount',
      'exceptionModuleCount',
      'modules',
    ]) ||
    value.outcome !== 'accepted' ||
    value.moduleCount !== phase1BasicModuleNames.length ||
    !Number.isSafeInteger(value.passedModuleCount) ||
    !Number.isSafeInteger(value.reviewedModuleCount) ||
    !Number.isSafeInteger(value.exceptionModuleCount) ||
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
  let exceptionModuleCount = 0;
  let proofPlanInstanceId = expectedPlanInstanceId;

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
        'exception',
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

    if (candidate.result === 'WARNING' || candidate.result === 'SKIPPED') {
      proofPlanInstanceId = requireOptionalProof(candidate, proofPlanInstanceId);
      exceptionModuleCount += 1;
      continue;
    }
    if (candidate.exception !== null) {
      return fail();
    }

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
    value.exceptionModuleCount !== exceptionModuleCount ||
    passedModuleCount + reviewedModuleCount + exceptionModuleCount !== phase1BasicModuleNames.length
  ) {
    return fail();
  }

  return value as Phase1BasicAcceptedResult;
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
