import nock from 'nock';
import { PassThrough } from 'node:stream';
import { inspect } from 'node:util';
import { gzipSync } from 'node:zlib';

import { ConnectorError, ConnectorErrorCodes, ConnectorPlatform } from '@logto/connector-kit';

import { accessTokenEndpoint, authorizationEndpoint, userInfoEndpoint } from './constant.js';
import createConnector from './index.js';

const requestTimeout = 5000;
const maxResponseBytes = 16 * 1024;

const appId = 'wx0123456789abcdef';
const appSecret = '0123456789abcdef0123456789abcdef';
const code = 'oauth-code-sensitive';
const state = 'oauth-state-sensitive';
const accessToken = 'provider-access-token-sensitive';
const openId = 'provider-openid-sensitive';
const unionId = 'provider-unionid-sensitive';
const avatar = 'https://example.test/avatar.png';
const nickname = 'WeChat user';
const validConfig = Object.freeze({ appId, appSecret });

const getConfig = vi.fn().mockResolvedValue(validConfig);

const authorizationPayload = {
  state,
  redirectUri: 'https://auth.example.test/callback/wechat',
  connectorId: 'connector-id',
  connectorFactoryId: 'wechat-h5',
  jti: 'jti',
  headers: {},
};

const callback = { code, state };
const accessTokenEndpointUrl = new URL(accessTokenEndpoint);
const userInfoEndpointUrl = new URL(userInfoEndpoint);
const tokenQuery = {
  appid: appId,
  secret: appSecret,
  code,
  grant_type: 'authorization_code',
};
const userInfoQuery = {
  access_token: accessToken,
  openid: openId,
};

const validTokenResponse = {
  access_token: accessToken,
  expires_in: 7200,
  refresh_token: 'provider-refresh-token-sensitive',
  openid: openId,
  scope: 'snsapi_userinfo',
};

const validUserInfoResponse = {
  openid: openId,
  nickname,
  sex: 0,
  province: '',
  city: '',
  country: '',
  headimgurl: avatar,
  privilege: [],
  unionid: unionId,
};

const mockTokenResponse = (
  statusCode = 200,
  body: nock.Body = validTokenResponse,
  headers: nock.ReplyHeaders = {}
) =>
  nock(accessTokenEndpointUrl.origin)
    .matchHeader('accept-encoding', 'identity')
    .get(accessTokenEndpointUrl.pathname)
    .query(tokenQuery)
    .reply(statusCode, body, headers);

const mockUserInfoResponse = (
  statusCode = 200,
  body: nock.Body = validUserInfoResponse,
  headers: nock.ReplyHeaders = {}
) =>
  nock(userInfoEndpointUrl.origin)
    .matchHeader('accept-encoding', 'identity')
    .get(userInfoEndpointUrl.pathname)
    .query(userInfoQuery)
    .reply(statusCode, body, headers);

const getUserInfo = async (data: unknown = callback) => {
  const connector = await createConnector({ getConfig });

  return connector.getUserInfo(data, vi.fn());
};

const expectDataFreeConnectorError = async (
  promise: Promise<unknown>,
  errorCode: ConnectorErrorCodes
): Promise<ConnectorError> => {
  try {
    await promise;
  } catch (error: unknown) {
    expect(error).toStrictEqual(new ConnectorError(errorCode));
    expect((error as ConnectorError).data).toBeUndefined();

    return error as ConnectorError;
  }

  throw new Error(`Expected connector error ${errorCode}`);
};

const getErrorDebugRepresentations = (error: ConnectorError) =>
  [
    error.message,
    error.stack,
    String(error),
    JSON.stringify(error),
    inspect(error, { depth: 10, showHidden: true }),
  ].join('\n');

afterEach(() => {
  nock.cleanAll();
  vi.clearAllMocks();
  getConfig.mockResolvedValue(validConfig);
});

describe('metadata and configuration', () => {
  it('exposes Official Account metadata and exactly two configuration fields', async () => {
    const connector = await createConnector({ getConfig });

    expect(connector.metadata).toMatchObject({
      id: 'wechat-h5',
      target: 'wechat',
      platform: ConnectorPlatform.Universal,
      name: {
        en: 'WeChat Official Account',
        'zh-CN': '微信公众号',
      },
      logo: './logo.svg',
      logoDark: null,
      readme: './README.md',
    });
    expect(connector.metadata.formItems?.map(({ key }) => key)).toEqual(['appId', 'appSecret']);
  });

  it('accepts the exact AppID grammar and AppSecret length boundaries', async () => {
    const connector = await createConnector({ getConfig });

    expect(connector.configGuard.safeParse(validConfig).success).toBe(true);
    expect(connector.configGuard.safeParse({ appId, appSecret: 'A1'.repeat(8) }).success).toBe(
      true
    );
    expect(connector.configGuard.safeParse({ appId, appSecret: 'A1'.repeat(64) }).success).toBe(
      true
    );
  });

  it.each([
    ['a short AppID', { appId: 'wx0123456789abcde', appSecret }],
    ['a non-hex AppID', { appId: 'wx0123456789abcdeg', appSecret }],
    ['an uppercase prefix', { appId: 'WX0123456789abcdef', appSecret }],
    ['an unknown field', { ...validConfig, extra: 'not-allowed' }],
    ['spaces', { appId, appSecret: ' '.repeat(16) }],
    ['an embedded space', { appId, appSecret: 'Abcdefghijklmno p' }],
    ['a newline', { appId, appSecret: 'Abcdefghijklmnop\n' }],
    ['a NUL control character', { appId, appSecret: 'Abcdefghijklmnop\0' }],
    ['a short AppSecret', { appId, appSecret: 'A1'.repeat(7) }],
    ['a long AppSecret', { appId, appSecret: `A${'1'.repeat(128)}` }],
  ])('rejects configuration with %s', async (_, config) => {
    const connector = await createConnector({ getConfig });

    expect(connector.configGuard.safeParse(config).success).toBe(false);
  });
});

describe('getAuthorizationUri', () => {
  it('returns the exact WeChat Official Account authorization URI', async () => {
    const connector = await createConnector({ getConfig });

    const result = await connector.getAuthorizationUri(authorizationPayload, vi.fn());

    expect(result).toBe(
      `${authorizationEndpoint}?appid=${appId}&redirect_uri=https%3A%2F%2Fauth.example.test%2Fcallback%2Fwechat&response_type=code&scope=snsapi_userinfo&state=${state}#wechat_redirect`
    );
    expect(getConfig).toHaveBeenCalledExactlyOnceWith('wechat-h5');
  });

  it('does not put credentials or unrelated authorization payload fields in the URI', async () => {
    const connector = await createConnector({ getConfig });

    const result = await connector.getAuthorizationUri(authorizationPayload, vi.fn());

    for (const excluded of [
      appSecret,
      authorizationPayload.connectorId,
      authorizationPayload.jti,
    ]) {
      expect(result).not.toContain(excluded);
    }
    expect([...new URL(result).searchParams.keys()]).toEqual([
      'appid',
      'redirect_uri',
      'response_type',
      'scope',
      'state',
    ]);
  });

  it.each([
    ['HTTP', 'http://auth.example.test/callback'],
    ['provider credentials', 'https://user:password@auth.example.test/callback'],
    ['a root path', 'https://auth.example.test/'],
    ['no path', 'https://auth.example.test'],
    ['a relative path', '/callback'],
    ['a malformed value', 'not a URI'],
  ])('rejects a callback URI using %s', async (_, redirectUri) => {
    const connector = await createConnector({ getConfig });

    await expectDataFreeConnectorError(
      connector.getAuthorizationUri({ ...authorizationPayload, redirectUri }, vi.fn()),
      ConnectorErrorCodes.InvalidRequestParameters
    );
  });

  it('validates configuration before constructing the URI', async () => {
    getConfig.mockResolvedValueOnce({ appId: 'invalid', appSecret });
    const connector = await createConnector({ getConfig });

    await expect(
      connector.getAuthorizationUri(authorizationPayload, vi.fn())
    ).rejects.toMatchObject({ code: ConnectorErrorCodes.InvalidConfig });
  });
});

describe('callback validation', () => {
  it.each([
    ['missing code', { state }],
    ['an empty code', { code: '', state }],
    ['an oversized code', { code: 'x'.repeat(257), state }],
    ['missing state', { code }],
    ['an empty state', { code, state: '' }],
    ['an oversized state', { code, state: 'x'.repeat(1025) }],
    ['an additional field', { code, state, extra: 'not-allowed' }],
  ])('rejects a callback with %s before contacting the provider', async (_, data) => {
    await expectDataFreeConnectorError(
      getUserInfo(data),
      ConnectorErrorCodes.InvalidRequestParameters
    );
    expect(nock.pendingMocks()).toEqual([]);
  });

  it('validates configuration before contacting the provider', async () => {
    getConfig.mockResolvedValueOnce({ appId: 'invalid', appSecret });

    await expect(getUserInfo()).rejects.toMatchObject({ code: ConnectorErrorCodes.InvalidConfig });
    expect(nock.pendingMocks()).toEqual([]);
  });
});

describe('provider exchange', () => {
  it('returns only sanitized profile fields keyed by UnionID', async () => {
    const tokenScope = mockTokenResponse();
    const userInfoScope = mockUserInfoResponse();

    const result = await getUserInfo();

    expect(result).toStrictEqual({ id: unionId, name: nickname, avatar, rawData: {} });
    const serialized = JSON.stringify(result);
    for (const excluded of [appSecret, code, state, accessToken, openId]) {
      expect(serialized).not.toContain(excluded);
    }
    expect(tokenScope.isDone()).toBe(true);
    expect(userInfoScope.isDone()).toBe(true);
  });

  it.each([
    ['omits UnionID', undefined],
    ['returns an empty UnionID', ''],
    ['returns a whitespace UnionID', '   '],
  ])('throws a data-free typed error when user info %s', async (_description, unionIdOverride) => {
    mockTokenResponse();
    const { unionid: _unionId, ...withoutUnionId } = validUserInfoResponse;
    mockUserInfoResponse(
      200,
      unionIdOverride === undefined
        ? withoutUnionId
        : { ...validUserInfoResponse, unionid: unionIdOverride }
    );

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.WeChatUnionIdRequired);
  });

  it('never falls back to OpenID when UnionID is absent', async () => {
    mockTokenResponse();
    const { unionid: _, ...withoutUnionId } = validUserInfoResponse;
    mockUserInfoResponse(200, withoutUnionId);

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.WeChatUnionIdRequired);
  });

  it('maps a token provider error to a data-free invalid-code error', async () => {
    mockTokenResponse(200, { errcode: 40_029, errmsg: `${code}:${appSecret}` });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.SocialAuthCodeInvalid);
  });

  it('maps a user-info provider error to a data-free invalid-token error', async () => {
    mockTokenResponse();
    mockUserInfoResponse(200, { errcode: 40_001, errmsg: `${accessToken}:${openId}` });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.SocialAccessTokenInvalid);
  });

  it('rejects unknown token response fields', async () => {
    mockTokenResponse(200, { ...validTokenResponse, unexpected: appSecret });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('rejects unknown user-info response fields', async () => {
    mockTokenResponse();
    mockUserInfoResponse(200, { ...validUserInfoResponse, unexpected: accessToken });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('rejects malformed token JSON', async () => {
    mockTokenResponse(200, '{not-json');

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('rejects malformed user-info JSON', async () => {
    mockTokenResponse();
    mockUserInfoResponse(200, '{not-json');

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('rejects an otherwise valid non-2xx token response before user info', async () => {
    mockTokenResponse(502, validTokenResponse);
    const userInfoScope = mockUserInfoResponse();

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    expect(userInfoScope.isDone()).toBe(false);
  });

  it('rejects an otherwise valid non-2xx user-info response', async () => {
    mockTokenResponse();
    mockUserInfoResponse(502, validUserInfoResponse);

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('does not follow token redirects', async () => {
    const redirected = nock('https://redirected.example.test')
      .get('/token')
      .reply(200, validTokenResponse);
    mockTokenResponse(302, undefined, { Location: 'https://redirected.example.test/token' });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    expect(redirected.isDone()).toBe(false);
  });

  it('does not follow user-info redirects', async () => {
    const redirected = nock('https://redirected.example.test')
      .get('/userinfo')
      .reply(200, validUserInfoResponse);
    mockTokenResponse();
    mockUserInfoResponse(302, undefined, {
      Location: 'https://redirected.example.test/userinfo',
    });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    expect(redirected.isDone()).toBe(false);
  });

  it('cancels a chunked token response promptly when transferred bytes exceed 16 KiB', async () => {
    const tailDelay = 1500;
    const promptRejectionLimit = 1000;
    const tailObserved = vi.fn();
    const responseStream = new PassThrough();
    const tailTimer = setTimeout(() => {
      tailObserved();
      responseStream.end(' ');
    }, tailDelay);
    responseStream.write(JSON.stringify(validTokenResponse));
    responseStream.write(' '.repeat(maxResponseBytes));
    mockTokenResponse(200, responseStream, { 'Content-Type': 'application/json' });
    const userInfoScope = mockUserInfoResponse();
    const startedAt = Date.now();

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);

    const elapsed = Date.now() - startedAt;
    clearTimeout(tailTimer);
    responseStream.destroy();
    expect(elapsed).toBeLessThan(promptRejectionLimit);
    expect(tailObserved).not.toHaveBeenCalled();
    expect(userInfoScope.isDone()).toBe(false);
  }, 3000);

  it(
    'rejects an otherwise valid token response delayed beyond five seconds',
    async () => {
      nock(accessTokenEndpointUrl.origin)
        .matchHeader('accept-encoding', 'identity')
        .get(accessTokenEndpointUrl.pathname)
        .query(tokenQuery)
        .delayConnection(requestTimeout + 100)
        .reply(200, validTokenResponse);
      const userInfoScope = mockUserInfoResponse();

      await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
      expect(userInfoScope.isDone()).toBe(false);
    },
    requestTimeout + 3000
  );

  it('rejects an otherwise valid gzip token response when decompression is disabled', async () => {
    const compressedBody = gzipSync(JSON.stringify(validTokenResponse));
    mockTokenResponse(200, compressedBody, {
      'Content-Encoding': 'gzip',
      'Content-Type': 'application/json',
    });
    const userInfoScope = mockUserInfoResponse();

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    expect(userInfoScope.isDone()).toBe(false);
  });

  it('does not retry a failed provider request', async () => {
    const requestHandler = vi.fn(() => [502, {}] as const);
    nock(accessTokenEndpointUrl.origin)
      .get(accessTokenEndpointUrl.pathname)
      .query(tokenQuery)
      .times(2)
      .reply(requestHandler);

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    expect(requestHandler).toHaveBeenCalledOnce();
  });

  it('does not expose callback, credential, or provider values in error representations', async () => {
    mockTokenResponse();
    mockUserInfoResponse(200, {
      ...validUserInfoResponse,
      unexpected: `${appId}:${appSecret}:${code}:${state}:${accessToken}:${openId}:${unionId}`,
    });

    const error = await expectDataFreeConnectorError(
      getUserInfo(),
      ConnectorErrorCodes.InvalidResponse
    );
    const representations = getErrorDebugRepresentations(error);

    for (const sensitive of [appId, appSecret, code, state, accessToken, openId, unionId]) {
      expect(representations).not.toContain(sensitive);
    }
  });
});
