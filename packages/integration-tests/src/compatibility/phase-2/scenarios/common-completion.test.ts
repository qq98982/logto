import { assertClientCredentialsEvidenceIsSanitized } from '../projections/client-credentials.js';
import { assertDeviceAuthorizationEvidenceIsSanitized } from '../projections/device-authorization.js';

import {
  commonCompletionScenarioIds,
  compareCommonCompletionProjections,
} from './common-completion.js';
import { commonAccountSocialExpectedProjection } from './common-social-account.js';
import {
  projectCommonWechatFamilyProjection,
  projectRawCommonWechatFamilyProjection,
} from './common-wechat-family.js';

const providerDenial = (status: 400 | 401, error: string) => ({ status, error, accepted: false });

test('keeps the approved final fourteen rows in their exact append order', () => {
  expect(commonCompletionScenarioIds).toHaveLength(14);
  expect(new Set(commonCompletionScenarioIds).size).toBe(14);
  expect(commonCompletionScenarioIds[0]).toBe('common.password.policy');
  expect(commonCompletionScenarioIds[13]).toBe('common.session.logout-preservation');
});
test('refuses a same-target false success, wrong provider, and extra private wrapper', () => {
  const expected = commonAccountSocialExpectedProjection('google');
  expect(
    compareCommonCompletionProjections('common.account.google-link', expected, expected)
  ).toEqual([]);
  for (const hostile of [
    { ...expected, profileLinked: false },
    commonAccountSocialExpectedProjection('wechat'),
    { ...expected, privateToken: 'synthetic-private-canary' },
  ]) {
    expect(
      compareCommonCompletionProjections('common.account.google-link', hostile, hostile)
    ).toEqual(['/projection']);
  }
});

test('publishes H5 evidence only when no owner setup request preceded registration', () => {
  const projection = {
    channel: 'h5',
    newOwner: true,
    identityCreated: true,
    verifiedPhone: true,
    phoneOnlyFulfillment: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    refreshRotated: true,
    provider: {
      setupRequests: 0,
      browserRequests: 1,
      providerRedirectExact: true,
      exchangeExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  };
  expect(compareCommonCompletionProjections('common.wechat.h5', projection, projection)).toEqual(
    []
  );
  const precreatedOwner = {
    ...projection,
    provider: { ...projection.provider, setupRequests: 1 },
  };
  expect(
    compareCommonCompletionProjections('common.wechat.h5', precreatedOwner, precreatedOwner)
  ).toEqual(['/projection']);
});

test('publishes Mini phone registration only for the zero-setup provider recipe', () => {
  const provider = {
    setupRequests: 0,
    browserRequests: 1,
    providerRedirectExact: true,
    exchangeExact: true,
    userinfoExact: true,
    unionIdStable: true,
  };
  const projection = {
    calls: 16,
    registered: true,
    unionIdRequired: true,
    callbackScheme: 'box-ai-wechat-mini:',
    collision: {
      status: 422,
      error: 'user.phone_already_in_use',
      partialOwnerCreated: false,
      ownersPreserved: true,
    },
    noUnionId: { status: 400, error: 'connector.wechat_unionid_required', accepted: false },
    invalidCode: { status: 401, error: 'connector.social_auth_code_invalid', accepted: false },
    malformedProvider: { status: 400, error: 'connector.invalid_response', accepted: false },
    replay: {
      firstStatus: 200,
      status: 401,
      error: 'connector.social_auth_code_invalid',
      accepted: false,
    },
    crossInteraction: {
      status: 404,
      error: 'session.verification_session_not_found',
      accepted: false,
    },
    provider,
  };
  expect(
    compareCommonCompletionProjections(
      'common.wechat.mini-phone-registration',
      projection,
      projection
    )
  ).toEqual([]);
  const precreated = { ...projection, provider: { ...provider, setupRequests: 1 } };
  expect(
    compareCommonCompletionProjections(
      'common.wechat.mini-phone-registration',
      precreated,
      precreated
    )
  ).toEqual(['/projection']);
});

test('publishes Mini evidence as a closed plain projection after exact validation', () => {
  const inheritedControl = Object.create(
    { privateValue: 'not-owned' },
    {
      status: { enumerable: true, value: 400 },
      error: { enumerable: true, value: 'connector.wechat_unionid_required' },
      accepted: { enumerable: true, value: false },
    }
  ) as Record<string, unknown>;
  const projection = {
    calls: 5,
    existingOwner: true,
    unionIdRequired: true,
    noUnionId: inheritedControl,
    invalidCode: { status: 401, error: 'connector.social_auth_code_invalid', accepted: false },
    malformedProvider: { status: 400, error: 'connector.invalid_response', accepted: false },
    replay: {
      firstStatus: 200,
      status: 401,
      error: 'connector.social_auth_code_invalid',
      accepted: false,
    },
    crossInteraction: {
      status: 404,
      error: 'session.verification_session_not_found',
      accepted: false,
    },
    provider: {
      setupRequests: 1,
      browserRequests: 1,
      providerRedirectExact: true,
      exchangeExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  };
  const published = projectCommonWechatFamilyProjection('common.wechat.mini', projection);
  expect(Object.getPrototypeOf(published.noUnionId)).toBe(Object.prototype);
  expect(published).toEqual(projection);
  expect(JSON.parse(JSON.stringify(published))).toEqual(published);
  expect(Reflect.has(published.noUnionId as Record<string, unknown>, 'privateValue')).toBe(false);
});

test('publishes every WeChat channel with exact schemas accepted by both generic sanitizers', () => {
  const controls = {
    noUnionId: providerDenial(400, 'connector.wechat_unionid_required'),
    invalidCode: providerDenial(401, 'connector.social_auth_code_invalid'),
    malformedProvider: providerDenial(400, 'connector.invalid_response'),
    replay: {
      firstStatus: 200,
      status: 401,
      error: 'connector.social_auth_code_invalid',
      accepted: false,
    },
    crossInteraction: {
      status: 404,
      error: 'session.verification_session_not_found',
      accepted: false,
    },
  };
  const provider = {
    providerRedirectExact: true,
    exchangeExact: true,
    userinfoExact: true,
    unionIdStable: true,
  };
  const projections = [
    projectCommonWechatFamilyProjection('common.wechat.h5', {
      channel: 'h5',
      newOwner: true,
      identityCreated: true,
      verifiedPhone: true,
      phoneOnlyFulfillment: true,
      callback: 'state-issuer-code-bound',
      pkce: 'S256',
      refreshRotated: true,
      provider: { setupRequests: 0, browserRequests: 1, ...provider },
    }),
    projectCommonWechatFamilyProjection('common.wechat.mini', {
      calls: 5,
      existingOwner: true,
      unionIdRequired: true,
      ...controls,
      provider: { setupRequests: 1, browserRequests: 1, ...provider },
    }),
    projectCommonWechatFamilyProjection('common.wechat.mini-phone-registration', {
      calls: 16,
      registered: true,
      unionIdRequired: true,
      callbackScheme: 'box-ai-wechat-mini:',
      collision: {
        status: 422,
        error: 'user.phone_already_in_use',
        partialOwnerCreated: false,
        ownersPreserved: true,
      },
      ...controls,
      provider: { setupRequests: 0, browserRequests: 1, ...provider },
    }),
    projectCommonWechatFamilyProjection('common.wechat.native', {
      applicationType: 'Native',
      firstParty: true,
      pkce: 'S256',
      stateNonceDistinct: true,
      issuerBound: true,
      discoverySameOrigin: true,
      jwksSameOrigin: true,
      userinfoEndpoint: '/oidc/me',
      idTokenAlgorithm: 'ES384',
      expectedSubject: true,
      resourceToken: 'jwt',
      resourceScope: 'session:exchange',
      resourceTtlSeconds: 300,
      profileToken: 'opaque',
      profileSubject: true,
      resourceRefresh: 'jwt',
      resourceRefreshTtlSeconds: 300,
      targetOwnedCleanup: true,
      ...controls,
      provider,
    }),
  ];
  for (const projection of projections) {
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized(projection);
    }).not.toThrow();
    expect(() => {
      assertDeviceAuthorizationEvidenceIsSanitized(projection);
    }).not.toThrow();
  }
  expect(() =>
    projectCommonWechatFamilyProjection('common.wechat.mini', {
      ...projections[1],
      provider: {
        ...(projections[1]?.provider as Record<string, unknown>),
        authorizationExact: true,
      },
    })
  ).toThrow('Invalid Common WeChat family scenario');
});

test.each([
  ['common.wechat.mini', 1],
  ['common.wechat.mini-phone-registration', 0],
] as const)('maps the raw %s provider receipt to exact public facts', (id, setupRequests) => {
  const publicProjection = projectCommonWechatFamilyProjection(id, {
    ...(id === 'common.wechat.mini'
      ? { calls: 5, existingOwner: true, unionIdRequired: true }
      : {
          calls: 16,
          registered: true,
          unionIdRequired: true,
          callbackScheme: 'box-ai-wechat-mini:',
          collision: {
            status: 422,
            error: 'user.phone_already_in_use',
            partialOwnerCreated: false,
            ownersPreserved: true,
          },
        }),
    noUnionId: providerDenial(400, 'connector.wechat_unionid_required'),
    invalidCode: providerDenial(401, 'connector.social_auth_code_invalid'),
    malformedProvider: providerDenial(400, 'connector.invalid_response'),
    replay: {
      firstStatus: 200,
      status: 401,
      error: 'connector.social_auth_code_invalid',
      accepted: false,
    },
    crossInteraction: {
      status: 404,
      error: 'session.verification_session_not_found',
      accepted: false,
    },
    provider: {
      setupRequests,
      browserRequests: 1,
      providerRedirectExact: true,
      exchangeExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  });
  const raw = {
    ...publicProjection,
    provider: {
      setupRequests,
      browserRequests: 1,
      authorizationExact: true,
      tokenExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  };
  const result = projectRawCommonWechatFamilyProjection(id, raw);
  expect(result).toEqual(publicProjection);
  expect(() => {
    assertClientCredentialsEvidenceIsSanitized(result);
  }).not.toThrow();
  expect(() => {
    assertDeviceAuthorizationEvidenceIsSanitized(result);
  }).not.toThrow();
});

test('maps the raw Native provider receipt and rejects false or expanded proof', () => {
  const publicProjection = {
    applicationType: 'Native',
    firstParty: true,
    pkce: 'S256',
    stateNonceDistinct: true,
    issuerBound: true,
    discoverySameOrigin: true,
    jwksSameOrigin: true,
    userinfoEndpoint: '/oidc/me',
    idTokenAlgorithm: 'ES384',
    expectedSubject: true,
    resourceToken: 'jwt',
    resourceScope: 'session:exchange',
    resourceTtlSeconds: 300,
    profileToken: 'opaque',
    profileSubject: true,
    resourceRefresh: 'jwt',
    resourceRefreshTtlSeconds: 300,
    targetOwnedCleanup: true,
    noUnionId: providerDenial(400, 'connector.wechat_unionid_required'),
    invalidCode: providerDenial(401, 'connector.social_auth_code_invalid'),
    malformedProvider: providerDenial(400, 'connector.invalid_response'),
    replay: {
      firstStatus: 200,
      status: 401,
      error: 'connector.social_auth_code_invalid',
      accepted: false,
    },
    crossInteraction: {
      status: 404,
      error: 'session.verification_session_not_found',
      accepted: false,
    },
    provider: {
      providerRedirectExact: true,
      exchangeExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  };
  const raw = {
    ...publicProjection,
    provider: {
      authorizationExact: true,
      tokenExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  };
  const result = projectRawCommonWechatFamilyProjection('common.wechat.native', raw);
  expect(result).toEqual(publicProjection);
  expect(() => {
    assertClientCredentialsEvidenceIsSanitized(result);
  }).not.toThrow();
  expect(() => {
    assertDeviceAuthorizationEvidenceIsSanitized(result);
  }).not.toThrow();
  for (const provider of [
    { ...raw.provider, authorizationExact: false },
    { ...raw.provider, privateProviderToken: 'private-value' },
  ]) {
    expect(() =>
      projectRawCommonWechatFamilyProjection('common.wechat.native', { ...raw, provider })
    ).toThrow('Invalid Common WeChat family scenario');
  }
});
