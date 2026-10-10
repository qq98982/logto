import {
  commonWechatWebScenarioIds,
  compareCommonWechatWebProjections,
  describeCommonWechatWebFailure,
  describeCommonWechatWebProjectionDifference,
  projectCommonWechatCrossInteraction,
  runCommonWechatControlForTesting,
} from './common-wechat-web.js';

const projection = () => ({
  channel: 'web',
  existingOwner: true,
  subjectPreserved: true,
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  refreshRotated: true,
  provider: {
    setupRequests: 1,
    browserRequests: 1,
    providerRedirectExact: true,
    exchangeExact: true,
    userinfoExact: true,
    unionIdStable: true,
  },
  noUnionId: {
    status: 400,
    error: 'connector.wechat_unionid_required',
    accepted: false,
    ownerPreserved: true,
  },
  invalidCode: {
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
    ownerPreserved: true,
  },
  replay: {
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
    ownerPreserved: true,
  },
  malformedProvider: {
    status: 400,
    error: 'connector.invalid_response',
    accepted: false,
    ownerPreserved: true,
  },
  crossInteraction: {
    status: 404,
    error: 'session.verification_session_not_found',
    accepted: false,
    ownerPreserved: true,
  },
  missingState: {
    status: 0,
    error: 'none',
    accepted: false,
    ownerPreserved: true,
    statePreserved: true,
    proofPreserved: true,
    correctRetryAccepted: true,
  },
  wrongState: {
    status: 0,
    error: 'none',
    accepted: false,
    ownerPreserved: true,
    statePreserved: true,
    proofPreserved: true,
    correctRetryAccepted: true,
  },
  wrongCallback: {
    status: 0,
    error: 'none',
    accepted: false,
    ownerPreserved: true,
    statePreserved: true,
    proofPreserved: true,
    correctRetryAccepted: true,
  },
});

test('publishes the canonical Common row id and accepts only identical exact projections', () => {
  expect(commonWechatWebScenarioIds).toEqual(['common.wechat.web']);
  expect(compareCommonWechatWebProjections(projection(), projection())).toEqual([]);
  expect(
    compareCommonWechatWebProjections(projection(), {
      ...projection(),
      provider: { ...projection().provider, unionIdStable: false },
    })
  ).toEqual(['/projection']);
  const changedStatus = {
    ...projection(),
    noUnionId: { ...projection().noUnionId, status: 401 },
  };
  expect(compareCommonWechatWebProjections(projection(), changedStatus)).toEqual(['/projection']);
  expect(describeCommonWechatWebProjectionDifference(projection(), changedStatus)).toEqual({
    field: 'no-union-id-status',
    oracle: 400,
    candidate: 401,
  });
  expect(describeCommonWechatWebProjectionDifference(projection(), projection())).toBeUndefined();
});

test('describes only finite closed failure stages without leaking arbitrary messages', () => {
  expect(
    describeCommonWechatWebFailure(
      new TypeError('Common WeChat Web failed: callback-callback-state')
    )
  ).toBe('callback-callback-state');
  expect(
    describeCommonWechatWebFailure(
      new TypeError('Common Wechat existing-owner target failed: fixture-stop-provider')
    )
  ).toBe('fixture-stop-provider');
  expect(
    describeCommonWechatWebFailure(
      new TypeError('Common Wechat existing-owner target failed: controls-wrong-callback')
    )
  ).toBe('controls-wrong-callback');
  expect(
    describeCommonWechatWebFailure(
      new TypeError('Common Wechat existing-owner target failed: context-control-response')
    )
  ).toBe('context-control-response');
  expect(
    describeCommonWechatWebFailure(
      new TypeError('Common Wechat existing-owner target failed: context-positive-provider')
    )
  ).toBe('context-positive-provider');
  expect(
    describeCommonWechatWebFailure(
      new TypeError('Common Wechat existing-owner target failed: context-positive-consent-state')
    )
  ).toBe('context-positive-consent-state');
  const consentTuple =
    'consent-route-other-social-verify-400-not-applicable-connector-general-auth-111111100-state-unavailable';
  expect(
    describeCommonWechatWebFailure(new TypeError(`Common WeChat Web failed: ${consentTuple}`))
  ).toBe(consentTuple);
  expect(describeCommonWechatWebFailure(new TypeError('private token secret'))).toBeUndefined();
  expect(
    describeCommonWechatWebFailure({ message: 'Common WeChat Web failed: profile' })
  ).toBeUndefined();
});

test.each([
  'user.identity_not_exist',
  'user.missing_profile',
  'session.verification_session_not_found',
  'session.interaction_not_found',
  'session.invalid_credentials',
  'user.suspended',
  'user.sign_in_method_not_enabled',
  'session.identity_conflict',
  'user.email_already_in_use',
  'verification_record.permission_denied',
  'guard.invalid_input',
  'connector.general',
  'connector.wechat_unionid_required',
  'connector.social_auth_code_invalid',
  'connector.invalid_response',
  'unknown',
  'none',
] as const)('retains the exact closed consent tuple code %s', (code) => {
  const normalized = code.replaceAll('.', '-');
  const stage = `consent-route-other-social-verify-400-not-applicable-${normalized}-auth-111111100-state-unavailable`;
  expect(describeCommonWechatWebFailure(new TypeError(`Common WeChat Web failed: ${stage}`))).toBe(
    stage
  );
});

test('retains the control identity when the inner browser error is rewritten', async () => {
  await expect(
    runCommonWechatControlForTesting('missing-state', async () => {
      throw new TypeError(
        'Common Wechat existing-owner target failed: context-positive-consent-complete'
      );
    })
  ).rejects.toThrow('Common Wechat existing-owner target failed: controls-missing-state');

  await expect(
    runCommonWechatControlForTesting('wrong-state', async () => ({ accepted: false }), {
      accepted: false,
      correctRetryAccepted: true,
    })
  ).rejects.toThrow('Common Wechat existing-owner target failed: controls-wrong-state');
});

test('projects complete cross-interaction proof into the public control shape', () => {
  expect(
    projectCommonWechatCrossInteraction({
      requestCount: 2,
      firstStatus: 200,
      firstOutcome: 'verified',
      secondStatus: 404,
      secondError: 'session.verification_session_not_found',
      secondAccepted: false,
      ownerPreserved: true,
    })
  ).toEqual(projection().crossInteraction);
});
