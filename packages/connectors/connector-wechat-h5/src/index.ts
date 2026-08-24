import { got } from 'got';

import type {
  CreateConnector,
  GetAuthorizationUri,
  GetConnectorConfig,
  GetUserInfo,
  SocialConnector,
} from '@logto/connector-kit';
import {
  ConnectorError,
  ConnectorErrorCodes,
  ConnectorType,
  validateConfig,
} from '@logto/connector-kit';

import {
  accessTokenEndpoint,
  authorizationEndpoint,
  defaultMetadata,
  defaultTimeout,
  maxResponseBytes,
  scope,
  userInfoEndpoint,
} from './constant.js';
import {
  accessTokenResponseGuard,
  authorizationCallbackGuard,
  userInfoResponseGuard,
  wechatH5ConfigGuard,
} from './types.js';

const invalidResponse = () => new ConnectorError(ConnectorErrorCodes.InvalidResponse);

const requestJson = async (
  endpoint: string,
  searchParams: Record<string, string>
): Promise<unknown> => {
  const request = got.get<unknown>(endpoint, {
    headers: {
      'accept-encoding': 'identity',
    },
    searchParams,
    timeout: { request: defaultTimeout },
    decompress: false,
    followRedirect: false,
    throwHttpErrors: false,
    retry: { limit: 0 },
    responseType: 'json',
  });

  try {
    const response = await request.on('downloadProgress', ({ total, transferred }) => {
      if (transferred > maxResponseBytes || (total !== undefined && total > maxResponseBytes)) {
        request.cancel();
      }
    });

    if (
      response.statusCode < 200 ||
      response.statusCode >= 300 ||
      response.rawBody.byteLength > maxResponseBytes
    ) {
      throw invalidResponse();
    }

    return response.body;
  } catch {
    throw invalidResponse();
  }
};

const parseRedirectUri = (redirectUri: string) => {
  try {
    const parsed = new URL(redirectUri);

    if (
      parsed.protocol !== 'https:' ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.pathname === '/'
    ) {
      throw new Error('Invalid callback URI');
    }

    return redirectUri;
  } catch {
    throw new ConnectorError(ConnectorErrorCodes.InvalidRequestParameters);
  }
};

const getAuthorizationUri =
  (getConfig: GetConnectorConfig): GetAuthorizationUri =>
  async ({ redirectUri, state }) => {
    const config = await getConfig(defaultMetadata.id);
    validateConfig(config, wechatH5ConfigGuard);

    const queryParameters = new URLSearchParams({
      appid: config.appId,
      redirect_uri: parseRedirectUri(redirectUri),
      response_type: 'code',
      scope,
      state,
    });

    return `${authorizationEndpoint}?${queryParameters.toString()}#wechat_redirect`;
  };

const getUserInfo =
  (getConfig: GetConnectorConfig): GetUserInfo =>
  async (data) => {
    const callbackResult = authorizationCallbackGuard.safeParse(data);

    if (!callbackResult.success) {
      throw new ConnectorError(ConnectorErrorCodes.InvalidRequestParameters);
    }

    const config = await getConfig(defaultMetadata.id);
    validateConfig(config, wechatH5ConfigGuard);

    const tokenBody = await requestJson(accessTokenEndpoint, {
      appid: config.appId,
      secret: config.appSecret,
      code: callbackResult.data.code,
      grant_type: 'authorization_code',
    });
    const tokenResult = accessTokenResponseGuard.safeParse(tokenBody);

    if (!tokenResult.success) {
      throw invalidResponse();
    }

    const { access_token: accessToken, openid, errcode: tokenErrcode } = tokenResult.data;

    if (tokenErrcode !== undefined && tokenErrcode !== 0) {
      throw new ConnectorError(ConnectorErrorCodes.SocialAuthCodeInvalid);
    }

    if (!accessToken || !openid) {
      throw invalidResponse();
    }

    const userInfoBody = await requestJson(userInfoEndpoint, {
      access_token: accessToken,
      openid,
    });
    const userInfoResult = userInfoResponseGuard.safeParse(userInfoBody);

    if (!userInfoResult.success) {
      throw invalidResponse();
    }

    const { errcode: userInfoErrcode, headimgurl, nickname, unionid } = userInfoResult.data;

    if (userInfoErrcode !== undefined && userInfoErrcode !== 0) {
      throw new ConnectorError(ConnectorErrorCodes.SocialAccessTokenInvalid);
    }

    if (!unionid?.trim()) {
      throw new ConnectorError(ConnectorErrorCodes.WeChatUnionIdRequired);
    }

    return {
      id: unionid,
      name: nickname,
      avatar: headimgurl,
      rawData: {},
    };
  };

const createConnector: CreateConnector<SocialConnector> = async ({ getConfig }) => ({
  metadata: defaultMetadata,
  type: ConnectorType.Social,
  configGuard: wechatH5ConfigGuard,
  getAuthorizationUri: getAuthorizationUri(getConfig),
  getUserInfo: getUserInfo(getConfig),
});

export default createConnector;
