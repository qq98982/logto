import { z } from 'zod';

export enum CaptchaType {
  Aliyun = 'AliyunCaptcha',
  RecaptchaEnterprise = 'RecaptchaEnterprise',
  Turnstile = 'Turnstile',
}

export enum CaptchaPolicyScope {
  Interaction = 'Interaction',
  PhoneVerificationCode = 'PhoneVerificationCode',
}

export enum RecaptchaEnterpriseMode {
  Invisible = 'invisible',
  Checkbox = 'checkbox',
}

export const turnstileConfigGuard = z.object({
  type: z.literal(CaptchaType.Turnstile),
  siteKey: z.string(),
  secretKey: z.string(),
});

export type TurnstileConfig = z.infer<typeof turnstileConfigGuard>;

export const recaptchaEnterpriseConfigGuard = z.object({
  type: z.literal(CaptchaType.RecaptchaEnterprise),
  siteKey: z.string(),
  secretKey: z.string(),
  projectId: z.string(),
  domain: z.string().optional(),
  mode: z.nativeEnum(RecaptchaEnterpriseMode).optional(),
});

export type RecaptchaEnterpriseConfig = z.infer<typeof recaptchaEnterpriseConfigGuard>;

// Box AI contract bounds limit stored configuration and authentication payloads; they are not Alibaba limits.
const aliyunIdentifierMinLength = 1;
const aliyunIdentifierMaxLength = 128;
const aliyunCredentialMinLength = 16;
const aliyunCredentialMaxLength = 256;
// eslint-disable-next-line unicorn/better-regex -- Keep the provider identifier grammar explicit.
const aliyunIdentifierRegex = /^[A-Za-z0-9_-]+$/;
const aliyunIdentifierGuard = z
  .string()
  .min(aliyunIdentifierMinLength)
  .max(aliyunIdentifierMaxLength)
  .regex(aliyunIdentifierRegex);
const unicodeControlCharacterRegex = /\p{Cc}/u;
const aliyunCredentialGuard = z
  .string()
  .min(aliyunCredentialMinLength)
  .max(aliyunCredentialMaxLength)
  .refine((value) => !unicodeControlCharacterRegex.test(value));

export const aliyunCaptchaConfigGuard = z
  .object({
    type: z.literal(CaptchaType.Aliyun),
    region: z.literal('cn'),
    prefix: aliyunIdentifierGuard,
    sceneId: aliyunIdentifierGuard,
    accessKeyId: aliyunCredentialGuard,
    accessKeySecret: aliyunCredentialGuard,
  })
  .strict();

export type AliyunCaptchaConfig = z.infer<typeof aliyunCaptchaConfigGuard>;

export const captchaConfigGuard = z.discriminatedUnion('type', [
  turnstileConfigGuard,
  recaptchaEnterpriseConfigGuard,
  aliyunCaptchaConfigGuard,
]);

export type CaptchaConfig = z.infer<typeof captchaConfigGuard>;
