import {
  CaptchaPolicyScope,
  CaptchaType,
  type CaptchaConfig,
  type CaptchaPolicy,
} from '@logto/schemas';

import { type CaptchaFormType } from './types';

export const buildCaptchaConfig = (type: CaptchaType, data: CaptchaFormType): CaptchaConfig => {
  switch (type) {
    case CaptchaType.Aliyun: {
      return {
        type,
        region: 'cn',
        prefix: data.prefix,
        sceneId: data.sceneId,
        accessKeyId: data.accessKeyId,
        accessKeySecret: data.accessKeySecret,
      };
    }
    case CaptchaType.RecaptchaEnterprise: {
      return {
        type,
        siteKey: data.siteKey,
        secretKey: data.secretKey,
        projectId: data.projectId,
        ...(data.domain === undefined ? {} : { domain: data.domain }),
        ...(data.mode && { mode: data.mode }),
      };
    }
    case CaptchaType.Turnstile: {
      return {
        type,
        siteKey: data.siteKey,
        secretKey: data.secretKey,
      };
    }
  }
};

export const normalizeCaptchaPolicy = (policy: CaptchaPolicy): Required<CaptchaPolicy> => ({
  enabled: policy.enabled ?? false,
  scope: policy.scope ?? CaptchaPolicyScope.Interaction,
});
