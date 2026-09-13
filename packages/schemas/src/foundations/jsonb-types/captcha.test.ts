import { describe, expect, it } from 'vitest';

import {
  fullSignInExperienceGuard,
  type FullSignInExperience,
} from '../../types/sign-in-experience.js';

import {
  aliyunCaptchaConfigGuard,
  captchaConfigGuard,
  CaptchaPolicyScope,
  CaptchaType,
  RecaptchaEnterpriseMode,
} from './captcha.js';

const validAliyunConfig = {
  type: CaptchaType.Aliyun,
  region: 'cn',
  prefix: 'p',
  sceneId: 's'.repeat(128),
  accessKeyId: 'i'.repeat(16),
  accessKeySecret: 's'.repeat(256),
} as const;

describe('aliyunCaptchaConfigGuard', () => {
  it('accepts a bounded mainland China configuration', () => {
    expect(aliyunCaptchaConfigGuard.parse(validAliyunConfig)).toEqual(validAliyunConfig);
  });

  it('includes Alibaba in the provider union', () => {
    expect(captchaConfigGuard.parse(validAliyunConfig)).toEqual(validAliyunConfig);
  });

  it.each([
    {
      type: CaptchaType.Turnstile,
      siteKey: 'turnstile-site-key',
      secretKey: 'turnstile-secret-key',
    },
    {
      type: CaptchaType.RecaptchaEnterprise,
      siteKey: 'recaptcha-site-key',
      secretKey: 'recaptcha-secret-key',
      projectId: 'recaptcha-project-id',
      domain: 'captcha.example.com',
      mode: RecaptchaEnterpriseMode.Invisible,
    },
  ])('preserves the existing stored provider configuration %p', (config) => {
    expect(captchaConfigGuard.parse(config)).toEqual(config);
  });

  it.each([
    ['a non-mainland region', { ...validAliyunConfig, region: 'sgp' }],
    ['an empty prefix', { ...validAliyunConfig, prefix: '' }],
    ['an overlong prefix', { ...validAliyunConfig, prefix: 'p'.repeat(129) }],
    ['an unsafe scene ID', { ...validAliyunConfig, sceneId: '../other' }],
    ['an overlong scene ID', { ...validAliyunConfig, sceneId: 's'.repeat(129) }],
    ['a short access key ID', { ...validAliyunConfig, accessKeyId: 'i'.repeat(15) }],
    ['a long access key secret', { ...validAliyunConfig, accessKeySecret: 's'.repeat(257) }],
    [
      'a control character in the access key ID',
      { ...validAliyunConfig, accessKeyId: `id${'i'.repeat(14)}\n` },
    ],
    [
      'a control character in the access key secret',
      { ...validAliyunConfig, accessKeySecret: `secret${'s'.repeat(10)}\0` },
    ],
    [
      'a C1 control character in the access key ID',
      { ...validAliyunConfig, accessKeyId: `id${'i'.repeat(14)}\u0085` },
    ],
    [
      'a C1 control character in the access key secret',
      { ...validAliyunConfig, accessKeySecret: `secret${'s'.repeat(10)}\u0085` },
    ],
    ['an unknown endpoint', { ...validAliyunConfig, endpoint: 'https://example.com' }],
  ])('rejects %s', (_, value) => {
    expect(aliyunCaptchaConfigGuard.safeParse(value).success).toBe(false);
  });
});

describe('CaptchaPolicyScope', () => {
  it('contains exactly the interaction and phone verification code scopes in order', () => {
    expect(Object.values(CaptchaPolicyScope)).toEqual([
      CaptchaPolicyScope.Interaction,
      CaptchaPolicyScope.PhoneVerificationCode,
    ]);
  });
});

describe('public Alibaba captcha configuration', () => {
  type PublicCaptchaConfig = NonNullable<FullSignInExperience['captchaConfig']>;

  const publicConfig = {
    type: CaptchaType.Aliyun,
    region: 'cn',
    prefix: 'public-prefix',
    sceneId: 'public_scene',
  } as const satisfies PublicCaptchaConfig;

  const publicCaptchaConfigGuard = fullSignInExperienceGuard.shape.captchaConfig.unwrap();

  it('accepts exactly the four public fields', () => {
    expect(publicCaptchaConfigGuard.parse(publicConfig)).toEqual(publicConfig);
  });

  it.each([
    { type: CaptchaType.Turnstile, siteKey: 'turnstile-site-key' },
    {
      type: CaptchaType.RecaptchaEnterprise,
      siteKey: 'recaptcha-site-key',
      domain: 'captcha.example.com',
      mode: RecaptchaEnterpriseMode.Invisible,
    },
  ])('preserves the existing public provider shape %p', (config) => {
    expect(publicCaptchaConfigGuard.parse(config)).toEqual(config);
  });

  it.each([
    ['accessKeyId', { ...publicConfig, accessKeyId: 'i'.repeat(16) }],
    ['accessKeySecret', { ...publicConfig, accessKeySecret: 's'.repeat(16) }],
  ])('rejects the private %s field', (_, value) => {
    expect(publicCaptchaConfigGuard.safeParse(value).success).toBe(false);
  });

  it('excludes both credentials from the public type', () => {
    const configWithAccessKeyId: PublicCaptchaConfig = {
      ...publicConfig,
      // @ts-expect-error -- Alibaba access key IDs are private configuration.
      accessKeyId: 'i'.repeat(16),
    };
    const configWithAccessKeySecret: PublicCaptchaConfig = {
      ...publicConfig,
      // @ts-expect-error -- Alibaba access key secrets are private configuration.
      accessKeySecret: 's'.repeat(16),
    };

    expect([configWithAccessKeyId, configWithAccessKeySecret]).toHaveLength(2);
  });
});
