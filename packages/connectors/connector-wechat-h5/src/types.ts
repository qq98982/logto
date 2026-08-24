import { z } from 'zod';

const wechatAppSecretRegex = /^[\dA-Za-z]{16,128}$/;

export const wechatH5ConfigGuard = z
  .object({
    // eslint-disable-next-line unicorn/better-regex -- Keep the provider's AppID grammar explicit.
    appId: z.string().regex(/^wx[0-9a-f]{16}$/),
    appSecret: z.string().regex(wechatAppSecretRegex),
  })
  .strict();

export type WechatH5Config = z.infer<typeof wechatH5ConfigGuard>;

export const authorizationCallbackGuard = z
  .object({
    code: z.string().min(1).max(256),
    state: z.string().min(1).max(1024),
  })
  .strict();

export const accessTokenResponseGuard = z
  .object({
    access_token: z.string().min(1).max(2048).optional(),
    expires_in: z.number().int().nonnegative().optional(),
    refresh_token: z.string().min(1).max(2048).optional(),
    openid: z.string().min(1).max(256).optional(),
    scope: z.string().max(256).optional(),
    unionid: z.string().max(256).optional(),
    errcode: z.number().int().optional(),
    errmsg: z.string().max(256).optional(),
  })
  .strict();

export const userInfoResponseGuard = z
  .object({
    openid: z.string().max(256).optional(),
    nickname: z.string().max(256).optional(),
    sex: z.number().int().optional(),
    province: z.string().max(256).optional(),
    city: z.string().max(256).optional(),
    country: z.string().max(256).optional(),
    headimgurl: z.string().max(2048).optional(),
    privilege: z.array(z.string().max(256)).max(256).optional(),
    unionid: z.string().max(256).optional(),
    errcode: z.number().int().optional(),
    errmsg: z.string().max(256).optional(),
  })
  .strict();
