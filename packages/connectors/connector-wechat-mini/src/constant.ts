import type { ConnectorMetadata } from '@logto/connector-kit';
import { ConnectorConfigFormItemType } from '@logto/connector-kit';

export const authorizationMarker = 'box-ai-wechat-mini://authorize';
export const sessionEndpoint = 'https://api.weixin.qq.com/sns/jscode2session';
export const defaultTimeout = 5000;
export const maxResponseBytes = 16 * 1024;

export const defaultMetadata: ConnectorMetadata = {
  id: 'wechat-mini',
  target: 'wechat',
  platform: null,
  name: {
    en: 'WeChat Mini Program',
    'zh-CN': '微信小程序',
  },
  logo: './logo.svg',
  logoDark: null,
  description: {
    en: 'Sign in with a WeChat Mini Program.',
    'zh-CN': '使用微信小程序登录。',
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
