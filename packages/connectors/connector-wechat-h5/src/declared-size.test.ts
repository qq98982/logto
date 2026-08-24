import { ConnectorError, ConnectorErrorCodes } from '@logto/connector-kit';

import createConnector from './index.js';

const gotGet = vi.hoisted(() => vi.fn());

vi.mock('got', () => ({ got: { get: gotGet } }));

type DownloadProgress = {
  total?: number;
  transferred: number;
};

type MockResponse = {
  statusCode: number;
  rawBody: Uint8Array;
  body: unknown;
  headers: Record<string, string>;
};

const maxResponseBytes = 16 * 1024;
const appId = 'wx0123456789abcdef';
const appSecret = '0123456789abcdef0123456789abcdef';
const accessToken = 'provider-access-token-sensitive';
const openId = 'provider-openid-sensitive';
const unionId = 'provider-unionid-sensitive';

const createMockRequest = (response: MockResponse, transferred: number) => {
  const cancel = vi.fn();
  const on = vi.fn(
    async (_event: 'downloadProgress', listener: (value: DownloadProgress) => void) => {
      const contentLength = response.headers['content-length'];
      listener({
        total: contentLength === undefined ? undefined : Number(contentLength),
        transferred,
      });

      if (cancel.mock.calls.length > 0) {
        throw new Error('Request cancelled');
      }

      return response;
    }
  );

  return { cancel, on };
};

afterEach(() => {
  gotGet.mockReset();
});

it('rejects a small valid token body whose declared Content-Length exceeds 16 KiB', async () => {
  const tokenBody = {
    access_token: accessToken,
    expires_in: 7200,
    refresh_token: 'provider-refresh-token-sensitive',
    openid: openId,
    scope: 'snsapi_userinfo',
  };
  const tokenRawBody = Buffer.from(JSON.stringify(tokenBody));
  const declaredLength = maxResponseBytes + 1;
  expect(tokenRawBody.byteLength).toBeLessThan(maxResponseBytes);

  const tokenRequest = createMockRequest(
    {
      statusCode: 200,
      rawBody: tokenRawBody,
      body: tokenBody,
      headers: { 'content-length': String(declaredLength) },
    },
    0
  );
  const userInfoBody = { unionid: unionId };
  const userInfoRawBody = Buffer.from(JSON.stringify(userInfoBody));
  const userInfoRequest = createMockRequest(
    {
      statusCode: 200,
      rawBody: userInfoRawBody,
      body: userInfoBody,
      headers: { 'content-length': String(userInfoRawBody.byteLength) },
    },
    userInfoRawBody.byteLength
  );
  gotGet.mockReturnValueOnce(tokenRequest).mockReturnValueOnce(userInfoRequest);
  const connector = await createConnector({
    getConfig: vi.fn().mockResolvedValue({ appId, appSecret }),
  });

  await expect(
    connector.getUserInfo({ code: 'oauth-code-sensitive', state: 'oauth-state-sensitive' }, vi.fn())
  ).rejects.toStrictEqual(new ConnectorError(ConnectorErrorCodes.InvalidResponse));
  expect(tokenRequest.cancel).toHaveBeenCalledOnce();
  expect(gotGet).toHaveBeenCalledOnce();
});
