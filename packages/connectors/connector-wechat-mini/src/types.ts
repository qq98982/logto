import { z } from 'zod';

// Keep the opaque credential bounded and ASCII-only so whitespace, controls, and unbounded query
// values never reach the provider request.
const wechatAppSecretRegex = /^[\dA-Za-z]{16,128}$/;

export const wechatMiniConfigGuard = z
  .object({
    // eslint-disable-next-line unicorn/better-regex -- Keep the provider's AppID grammar explicit.
    appId: z.string().regex(/^wx[0-9a-f]{16}$/),
    appSecret: z.string().regex(wechatAppSecretRegex),
  })
  .strict();

export type WechatMiniConfig = z.infer<typeof wechatMiniConfigGuard>;

export const authorizationCallbackGuard = z
  .object({
    code: z.string().min(1).max(256),
  })
  .strict();

export const sessionResponseGuard = z
  .object({
    openid: z.string().optional(),
    unionid: z.string().optional(),
    session_key: z.string().optional(),
    errcode: z.number().int().optional(),
    errmsg: z.string().max(256).optional(),
  })
  .strict();
