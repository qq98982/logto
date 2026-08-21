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
  authorizationMarker,
  defaultMetadata,
  defaultTimeout,
  maxResponseBytes,
  sessionEndpoint,
} from './constant.js';
import {
  authorizationCallbackGuard,
  sessionResponseGuard,
  wechatMiniConfigGuard,
} from './types.js';
import type { WechatMiniConfig } from './types.js';

const invalidResponse = () => new ConnectorError(ConnectorErrorCodes.InvalidResponse);

const requestSession = async (code: string, config: WechatMiniConfig): Promise<unknown> => {
  const request = got.get<unknown>(sessionEndpoint, {
    headers: {
      'accept-encoding': 'identity',
    },
    searchParams: {
      appid: config.appId,
      secret: config.appSecret,
      js_code: code,
      grant_type: 'authorization_code',
    },
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

const parseSessionResponse = (responseBody: unknown) => {
  const result = sessionResponseGuard.safeParse(responseBody);

  if (!result.success) {
    throw invalidResponse();
  }

  return result.data;
};

const getAuthorizationUri =
  (getConfig: GetConnectorConfig): GetAuthorizationUri =>
  async () => {
    const config = await getConfig(defaultMetadata.id);
    validateConfig(config, wechatMiniConfigGuard);

    return authorizationMarker;
  };

const getUserInfo =
  (getConfig: GetConnectorConfig): GetUserInfo =>
  async (data) => {
    const callbackResult = authorizationCallbackGuard.safeParse(data);

    if (!callbackResult.success) {
      throw new ConnectorError(ConnectorErrorCodes.InvalidRequestParameters);
    }

    const config = await getConfig(defaultMetadata.id);
    validateConfig(config, wechatMiniConfigGuard);

    const responseBody = await requestSession(callbackResult.data.code, config);
    const { errcode, unionid } = parseSessionResponse(responseBody);

    if (errcode !== undefined && errcode !== 0) {
      throw new ConnectorError(ConnectorErrorCodes.SocialAuthCodeInvalid);
    }

    if (!unionid) {
      throw new ConnectorError(ConnectorErrorCodes.WeChatUnionIdRequired);
    }

    return { id: unionid, rawData: {} };
  };

const createConnector: CreateConnector<SocialConnector> = async ({ getConfig }) => ({
  metadata: defaultMetadata,
  type: ConnectorType.Social,
  configGuard: wechatMiniConfigGuard,
  getAuthorizationUri: getAuthorizationUri(getConfig),
  getUserInfo: getUserInfo(getConfig),
});

export default createConnector;
