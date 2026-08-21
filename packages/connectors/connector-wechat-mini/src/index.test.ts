import nock from 'nock';
import { inspect } from 'node:util';
import { gzipSync } from 'node:zlib';

import { ConnectorError, ConnectorErrorCodes } from '@logto/connector-kit';

import createConnector from './index.js';

const authorizationMarker = 'box-ai-wechat-mini://authorize';
const sessionEndpoint = 'https://api.weixin.qq.com/sns/jscode2session';
const requestTimeout = 5000;
const maxResponseBytes = 16 * 1024;

const appId = 'wx0123456789abcdef';
const appSecret = '0123456789abcdef0123456789abcdef';
const code = 'mini-program-code-sensitive';
const openId = 'provider-openid-sensitive';
const unionId = 'provider-unionid-sensitive';
const sessionKey = 'provider-session-key-sensitive';
const validConfig = Object.freeze({ appId, appSecret });

const getConfig = vi.fn().mockResolvedValue(validConfig);

const authorizationPayload = {
  state: 'state',
  redirectUri: 'https://example.test/callback',
  connectorId: 'connector-id',
  connectorFactoryId: 'wechat-mini',
  jti: 'jti',
  headers: {},
};

const sessionEndpointUrl = new URL(sessionEndpoint);
const expectedQuery = {
  appid: appId,
  secret: appSecret,
  js_code: code,
  grant_type: 'authorization_code',
};

const mockSessionResponse = (statusCode: number, body: nock.Body = {}) =>
  nock(sessionEndpointUrl.origin)
    .get(sessionEndpointUrl.pathname)
    .query(expectedQuery)
    .reply(statusCode, body);

const getUserInfo = async (data?: unknown) => {
  const connector = await createConnector({ getConfig });

  return connector.getUserInfo(data === undefined ? { code } : data, vi.fn());
};

const expectDataFreeConnectorError = async (
  promise: Promise<unknown>,
  code: ConnectorErrorCodes
): Promise<ConnectorError> => {
  try {
    await promise;
  } catch (error: unknown) {
    expect(error).toStrictEqual(new ConnectorError(code));
    expect((error as ConnectorError).data).toBeUndefined();

    return error as ConnectorError;
  }

  throw new Error(`Expected connector error ${code}`);
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
  it('exposes the WeChat Mini Program metadata and exact configuration fields', async () => {
    const connector = await createConnector({ getConfig });

    expect(connector.metadata).toMatchObject({
      id: 'wechat-mini',
      target: 'wechat',
      platform: null,
      name: {
        en: 'WeChat Mini Program',
        'zh-CN': '微信小程序',
      },
      logo: './logo.svg',
      logoDark: null,
      readme: './README.md',
    });
    expect(connector.metadata.description).toEqual({
      en: 'Sign in with a WeChat Mini Program.',
      'zh-CN': '使用微信小程序登录。',
    });
    expect(connector.metadata.formItems?.map(({ key }) => key)).toEqual(['appId', 'appSecret']);
  });

  it('accepts a valid AppID and ASCII alphanumeric AppSecret boundaries', async () => {
    const connector = await createConnector({ getConfig });

    expect(connector.configGuard.safeParse(validConfig).success).toBe(true);
    expect(connector.configGuard.safeParse({ appId, appSecret: 'A1'.repeat(8) }).success).toBe(
      true
    );
    expect(connector.configGuard.safeParse({ appId, appSecret: 'A1'.repeat(64) }).success).toBe(
      true
    );

    for (const config of [
      { appId: 'wx0123456789abcde', appSecret },
      { appId: 'wx0123456789abcdeg', appSecret },
      { appId: 'WX0123456789abcdef', appSecret },
      { ...validConfig, extra: 'not-allowed' },
    ]) {
      expect(connector.configGuard.safeParse(config).success).toBe(false);
    }
  });

  it.each([
    ['spaces', ' '.repeat(16)],
    ['an embedded space', 'Abcdefghijklmno p'],
    ['a newline', 'Abcdefghijklmnop\n'],
    ['a NUL control character', 'Abcdefghijklmnop\0'],
    ['fewer than 16 characters', 'A1'.repeat(7)],
    ['more than 128 characters', `A${'1'.repeat(128)}`],
  ])('rejects an AppSecret containing %s', async (_, invalidAppSecret) => {
    const connector = await createConnector({ getConfig });

    expect(connector.configGuard.safeParse({ appId, appSecret: invalidAppSecret }).success).toBe(
      false
    );
  });

  it('loads and validates configuration before returning the authorization marker', async () => {
    const connector = await createConnector({ getConfig });

    await expect(connector.getAuthorizationUri(authorizationPayload, vi.fn())).resolves.toBe(
      authorizationMarker
    );
    expect(getConfig).toHaveBeenCalledExactlyOnceWith('wechat-mini');

    getConfig.mockResolvedValueOnce({ appId: 'invalid', appSecret });
    await expect(
      connector.getAuthorizationUri(authorizationPayload, vi.fn())
    ).rejects.toMatchObject({
      code: ConnectorErrorCodes.InvalidConfig,
    });
  });
});

describe('getUserInfo', () => {
  it('returns only the UnionID and an empty rawData object', async () => {
    const scope = mockSessionResponse(200, {
      openid: openId,
      unionid: unionId,
      session_key: sessionKey,
    });

    const result = await getUserInfo();

    expect(result).toStrictEqual({ id: unionId, rawData: {} });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(openId);
    expect(serialized).not.toContain(sessionKey);
    expect(serialized).not.toContain(appSecret);
    expect(scope.isDone()).toBe(true);
  });

  it.each([
    ['omits UnionID', {}],
    ['returns an empty UnionID', { unionid: '' }],
  ])('throws a data-free typed error when the provider %s', async (_, response) => {
    mockSessionResponse(200, { openid: openId, session_key: sessionKey, ...response });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.WeChatUnionIdRequired);
  });

  it('maps a nonzero provider errcode to a data-free invalid-code error', async () => {
    mockSessionResponse(200, {
      errcode: 40_029,
      errmsg: `invalid ${code} for ${appSecret}`,
    });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.SocialAuthCodeInvalid);
  });

  it.each([
    ['missing code', {}],
    ['empty code', { code: '' }],
    ['oversized code', { code: 'x'.repeat(257) }],
    ['non-string code', { code: 123 }],
    ['additional callback field', { code, state: 'not-allowed' }],
  ])('rejects a callback with %s before contacting the provider', async (_, callback) => {
    await expectDataFreeConnectorError(
      getUserInfo(callback),
      ConnectorErrorCodes.InvalidRequestParameters
    );
    expect(nock.pendingMocks()).toEqual([]);
  });

  it('rejects malformed JSON with a safe data-free error', async () => {
    mockSessionResponse(200, '{not-json');

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('rejects a response larger than 16 KiB with a safe data-free error', async () => {
    const oversizedResponse = JSON.stringify({ unionid: 'x'.repeat(maxResponseBytes) });
    expect(Buffer.byteLength(oversizedResponse)).toBeGreaterThan(maxResponseBytes);
    mockSessionResponse(200, oversizedResponse);

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('rejects a small gzip body that expands beyond 16 KiB without exposing its contents', async () => {
    const sensitivePrefix = `${appId}:${appSecret}:${code}:${openId}:${unionId}:${sessionKey}`;
    const decompressedBody = JSON.stringify({
      unionid: `${sensitivePrefix}${'x'.repeat(maxResponseBytes * 4)}`,
    });
    const compressedBody = gzipSync(decompressedBody);
    expect(compressedBody.byteLength).toBeLessThan(maxResponseBytes);
    expect(Buffer.byteLength(decompressedBody)).toBeGreaterThan(maxResponseBytes);

    const scope = nock(sessionEndpointUrl.origin)
      .matchHeader('accept-encoding', 'identity')
      .get(sessionEndpointUrl.pathname)
      .query(expectedQuery)
      .reply(200, compressedBody, {
        'Content-Encoding': 'gzip',
        'Content-Type': 'application/json',
      });

    const error = await expectDataFreeConnectorError(
      getUserInfo(),
      ConnectorErrorCodes.InvalidResponse
    );
    const debugRepresentations = getErrorDebugRepresentations(error);

    for (const sensitiveValue of [appId, appSecret, code, openId, unionId, sessionKey]) {
      expect(debugRepresentations).not.toContain(sensitiveValue);
    }
    expect(scope.isDone()).toBe(true);
  });

  it('does not automatically decompress a provider gzip response', async () => {
    const compressedBody = gzipSync(JSON.stringify({ unionid: unionId }));
    nock(sessionEndpointUrl.origin)
      .get(sessionEndpointUrl.pathname)
      .query(expectedQuery)
      .reply(200, compressedBody, {
        'Content-Encoding': 'gzip',
        'Content-Type': 'application/json',
      });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it(
    'stops a provider request after five seconds with a safe data-free error',
    async () => {
      nock(sessionEndpointUrl.origin)
        .get(sessionEndpointUrl.pathname)
        .query(expectedQuery)
        .delayConnection(requestTimeout + 100)
        .reply(200, { unionid: unionId });

      await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    },
    requestTimeout + 3000
  );

  it('rejects non-2xx responses with a safe data-free error', async () => {
    mockSessionResponse(502, `${appSecret}:${code}:${openId}:${unionId}:${sessionKey}`);

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
  });

  it('does not follow provider redirects', async () => {
    const redirectedEndpoint = nock('https://redirected.example.test')
      .get('/session')
      .reply(200, { unionid: unionId });
    nock(sessionEndpointUrl.origin)
      .get(sessionEndpointUrl.pathname)
      .query(expectedQuery)
      .reply(302, undefined, { Location: 'https://redirected.example.test/session' });

    await expectDataFreeConnectorError(getUserInfo(), ConnectorErrorCodes.InvalidResponse);
    expect(redirectedEndpoint.isDone()).toBe(false);
  });

  it('does not expose provider identifiers or request credentials in error representations', async () => {
    mockSessionResponse(200, {
      openid: openId,
      unionid: unionId,
      session_key: sessionKey,
      unexpected: `${appId}:${appSecret}:${code}`,
    });

    const error = await expectDataFreeConnectorError(
      getUserInfo(),
      ConnectorErrorCodes.InvalidResponse
    );
    const debugRepresentations = getErrorDebugRepresentations(error);

    for (const sensitiveValue of [appId, appSecret, code, openId, unionId, sessionKey]) {
      expect(debugRepresentations).not.toContain(sensitiveValue);
    }
  });
});
