/* eslint-disable no-restricted-syntax -- The fixture indexes a closed condition map from the fixed module registry. */
import {
  phase1BasicModuleNames,
  phase1BasicScreenshotReviewConditions,
  type Phase1BasicAcceptedResult,
  type Phase1BasicOptionalResultProof,
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
      exception: null,
    };
  });

  return {
    outcome: 'accepted',
    moduleCount: 35,
    passedModuleCount: modules.filter(({ result }) => result === 'PASSED').length,
    reviewedModuleCount: modules.filter(({ result }) => result === 'REVIEW').length,
    exceptionModuleCount: 0,
    modules,
  };
};

export const createPhase1BasicOptionalAcceptedResultFixture = (
  planInstanceId = 'A'.repeat(13)
): Phase1BasicAcceptedResult => {
  const base = createPhase1BasicAcceptedResultFixture();
  const missing = { present: false, type: 'missing' } as const;
  const unsupported = { present: true, type: 'boolean', value: false } as const;
  const modules = base.modules.map((module, index) => {
    if (![24, 30, 31].includes(index)) {
      return module;
    }
    const skipped = index === 30;
    const warning =
      index === 24
        ? 'ValidateIdTokenACRClaimAgainstAcrValuesRequest'
        : 'EnsureUserInfoContainsName';
    const successSources = skipped
      ? [
          'GetDynamicServerConfiguration',
          'BuildRequestObjectByValueRedirectToAuthorizationEndpoint',
          'SerializeRequestObjectWithNullAlgorithm',
          'ExtractImplicitHashToCallbackResponse',
        ]
      : [
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
          ...(index === 31
            ? [
                'CallUserInfoEndpoint',
                'ExtractUserInfoFromUserInfoEndpointResponse',
                'EnsureIdTokenDoesNotContainName',
                'VerifyUserInfoAndIdTokenInTokenEndpointSameSub',
                'ValidateUserInfoStandardClaims',
                'EnsureUserInfoContainsSub',
              ]
            : []),
        ];
    const common = {
      schemaVersion: 1 as const,
      planInstanceId,
      testId: module.testId,
      conditionLogSha256: module.conditionLogSha256,
      infoSha256: hash(300 + index),
      discoveryResponseSha256: hash(400 + index),
      requestSha256: hash(500 + index),
      responseSha256: hash(600 + index),
      conditionCount: successSources.length + 2,
      conditionEvidence: [
        ...successSources.map((source, ordinal) => ({
          id: `row-${index}-${ordinal}`,
          source,
          result: 'SUCCESS' as const,
        })),
        {
          id: `finding-${index}`,
          source: skipped ? module.testName : warning,
          result: skipped ? ('SKIPPED' as const) : ('WARNING' as const),
        },
        { id: `finished-${index}`, source: module.testName, result: 'FINISHED' as const },
      ],
    };
    const issued = {
      responseSha256: hash(700 + index),
      compactSha256: hash(800 + index),
      verificationKeySha256: hash(900 + index),
      algorithm: 'RS256' as const,
      responseScope: 'openid' as const,
      acr: missing,
      amr: missing,
    };
    const exception: Phase1BasicOptionalResultProof =
      index === 24
        ? {
            ...common,
            kind: 'acr-values-unsupported',
            discovery: { acrValuesSupported: missing },
            request: { scope: 'openid', acrValues: '1 2' },
            issued,
          }
        : skipped
          ? {
              ...common,
              kind: 'request-object-unsupported',
              discovery: { requestParameterSupported: unsupported },
              request: {
                method: 'GET',
                scope: 'openid',
                requestObjectSha256: hash(1000 + index),
                outerRedirectSha256: hash(1100 + index),
                outerCorrelation: missing,
              },
              rejection: {
                httpStatus: 303,
                responseMode: 'query',
                error: 'request_not_supported',
                returnedFields: ['error', 'iss'],
                callbackSha256: hash(1100 + index),
                issuerSha256: hash(1200 + index),
                returnedCorrelation: missing,
              },
              issued: null,
            }
          : {
              ...common,
              kind: 'claims-parameter-unsupported',
              discovery: { claimsParameterSupported: unsupported },
              request: { scope: 'openid', claims: { userinfo: { name: { essential: true } } } },
              issued: { ...issued, name: missing },
              userInfo: {
                responseSha256: hash(1300 + index),
                source: 'CallUserInfoEndpoint',
                name: missing,
              },
            };
    return { ...module, result: skipped ? ('SKIPPED' as const) : ('WARNING' as const), exception };
  });
  return {
    ...base,
    passedModuleCount: base.passedModuleCount - 3,
    exceptionModuleCount: 3,
    modules,
  };
};

/* eslint-enable no-restricted-syntax */
