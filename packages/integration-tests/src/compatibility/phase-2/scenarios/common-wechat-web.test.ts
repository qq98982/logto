import {
  commonWechatWebScenarioIds,
  compareCommonWechatWebProjections,
  describeCommonWechatWebFailure,
  describeCommonWechatWebProjectionDifference,
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
  expect(describeCommonWechatWebFailure(new TypeError('private token secret'))).toBeUndefined();
  expect(
    describeCommonWechatWebFailure({ message: 'Common WeChat Web failed: profile' })
  ).toBeUndefined();
});
