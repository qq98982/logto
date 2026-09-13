import { CaptchaPolicyScope, CaptchaType, RecaptchaEnterpriseMode } from '@logto/schemas';

import { captchaProviders } from './CreateCaptchaForm/constants';
import { buildCaptchaConfig, normalizeCaptchaPolicy } from './utils';

const allFields = {
  siteKey: 'site-key',
  secretKey: 'secret-key',
  projectId: 'project-id',
  domain: 'recaptcha.net',
  mode: RecaptchaEnterpriseMode.Checkbox,
  prefix: 'prefix',
  sceneId: 'scene-id',
  accessKeyId: 'access-key-id-value',
  accessKeySecret: 'access-key-secret-value',
};

describe('CAPTCHA provider configuration', () => {
  it('offers Alibaba CAPTCHA with its required fields', () => {
    expect(captchaProviders.find(({ type }) => type === CaptchaType.Aliyun)).toMatchObject({
      type: CaptchaType.Aliyun,
      requiredFields: [
        { field: 'prefix' },
        { field: 'sceneId' },
        { field: 'accessKeyId' },
        { field: 'accessKeySecret' },
      ],
    });
  });

  it('builds an exact Alibaba config without fields from browser CAPTCHA providers', () => {
    expect(buildCaptchaConfig(CaptchaType.Aliyun, allFields)).toEqual({
      type: CaptchaType.Aliyun,
      region: 'cn',
      prefix: 'prefix',
      sceneId: 'scene-id',
      accessKeyId: 'access-key-id-value',
      accessKeySecret: 'access-key-secret-value',
    });
  });

  it('keeps Turnstile configuration exact', () => {
    expect(buildCaptchaConfig(CaptchaType.Turnstile, allFields)).toEqual({
      type: CaptchaType.Turnstile,
      siteKey: 'site-key',
      secretKey: 'secret-key',
    });
  });

  it('keeps reCAPTCHA Enterprise configuration exact', () => {
    expect(buildCaptchaConfig(CaptchaType.RecaptchaEnterprise, allFields)).toEqual({
      type: CaptchaType.RecaptchaEnterprise,
      siteKey: 'site-key',
      secretKey: 'secret-key',
      projectId: 'project-id',
      domain: 'recaptcha.net',
      mode: RecaptchaEnterpriseMode.Checkbox,
    });
  });

  it('preserves an explicitly empty reCAPTCHA domain', () => {
    expect(
      buildCaptchaConfig(CaptchaType.RecaptchaEnterprise, { ...allFields, domain: '' })
    ).toEqual({
      type: CaptchaType.RecaptchaEnterprise,
      siteKey: 'site-key',
      secretKey: 'secret-key',
      projectId: 'project-id',
      domain: '',
      mode: RecaptchaEnterpriseMode.Checkbox,
    });
  });
});

describe('CAPTCHA policy normalization', () => {
  it('defaults a missing scope to all protected interactions', () => {
    expect(normalizeCaptchaPolicy({ enabled: true })).toEqual({
      enabled: true,
      scope: CaptchaPolicyScope.Interaction,
    });
  });

  it('preserves the selected phone verification code scope', () => {
    expect(
      normalizeCaptchaPolicy({
        enabled: false,
        scope: CaptchaPolicyScope.PhoneVerificationCode,
      })
    ).toEqual({
      enabled: false,
      scope: CaptchaPolicyScope.PhoneVerificationCode,
    });
  });
});
