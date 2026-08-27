import type { ConnectorMetadata } from '@logto/connector-kit';
import { ConnectorConfigFormItemType, ConnectorPlatform } from '@logto/connector-kit';

export const authorizationEndpoint = 'https://open.weixin.qq.com/connect/oauth2/authorize';
export const accessTokenEndpoint = 'https://api.weixin.qq.com/sns/oauth2/access_token';
export const userInfoEndpoint = 'https://api.weixin.qq.com/sns/userinfo';
export const scope = 'snsapi_userinfo';
export const defaultTimeout = 5000;
export const maxResponseBytes = 16 * 1024;

export const defaultMetadata: ConnectorMetadata = {
  id: 'wechat-h5',
  target: 'wechat',
  platform: ConnectorPlatform.Universal,
  name: {
    en: 'WeChat Official Account',
    'zh-CN': '微信公众号',
  },
  logo: './logo.svg',
  logoDark: null,
  description: {
    en: 'Sign in through a WeChat Official Account.',
    'zh-CN': '通过微信公众号登录。',
  },
  readme: './README.md',
  formItems: [
    {
      key: 'appId',
      label: 'App ID',
      required: true,
      type: ConnectorConfigFormItemType.Text,
      placeholder: '<app-id>',
    },
    {
      key: 'appSecret',
      label: 'App Secret',
      required: true,
      type: ConnectorConfigFormItemType.Text,
      placeholder: '<app-secret>',
    },
  ],
};
