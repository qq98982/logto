import CaptchaClient, { VerifyIntelligentCaptchaRequest } from '@alicloud/captcha20230305';
import { $OpenApiUtil } from '@alicloud/openapi-core';
import * as $dara from '@darabonba/typescript';
import {
  type AliyunCaptchaConfig,
  CaptchaType,
  RecaptchaEnterpriseMode,
  type CaptchaProvider,
  type RecaptchaEnterpriseConfig,
  type TurnstileConfig,
} from '@logto/schemas';
import ky from 'ky';
import { z } from 'zod';

import { type LogEntry } from '#src/middleware/koa-audit-log.js';

function isRecaptchaEnterprise(
  config: CaptchaProvider['config']
): config is RecaptchaEnterpriseConfig {
  return config.type === CaptchaType.RecaptchaEnterprise;
}

function isTurnstile(config: CaptchaProvider['config']): config is TurnstileConfig {
  return config.type === CaptchaType.Turnstile;
}

function isAliyun(config: CaptchaProvider['config']): config is AliyunCaptchaConfig {
  return config.type === CaptchaType.Aliyun;
}

type AliyunCaptchaVerification = {
  success?: boolean;
  verifyResult?: boolean;
  verifyCode?: string;
};

export type VerifyAliyunCaptcha = (
  config: AliyunCaptchaConfig,
  captchaToken: string
) => Promise<AliyunCaptchaVerification | undefined>;

const AliyunCaptchaClient = CaptchaClient.default;
// The no-retry 5-second provider budget stays below the hosted auth request budget;
// timeout failures are audited without provider details and fail closed.
const aliyunCaptchaConnectTimeout = 2000;
const aliyunCaptchaReadTimeout = 3000;

const verifyAliyunCaptchaWithSdk: VerifyAliyunCaptcha = async (config, captchaToken) => {
  const client = new AliyunCaptchaClient(
    new $OpenApiUtil.Config({
      accessKeyId: config.accessKeyId,
      accessKeySecret: config.accessKeySecret,
      endpoint: 'captcha.cn-shanghai.aliyuncs.com',
      regionId: 'cn-shanghai',
      retryOptions: new $dara.RetryOptions({ retryable: false }),
    })
  );
  const request = new VerifyIntelligentCaptchaRequest({
    captchaVerifyParam: captchaToken,
    sceneId: config.sceneId,
  });
  const runtime = new $dara.RuntimeOptions({
    connectTimeout: aliyunCaptchaConnectTimeout,
    readTimeout: aliyunCaptchaReadTimeout,
  });
  const { body } = await client.verifyIntelligentCaptchaWithOptions(request, runtime);

  return {
    success: body?.success,
    verifyResult: body?.result?.verifyResult,
    verifyCode: body?.result?.verifyCode,
  };
};

const aliyunCaptchaResponseGuard = z.object({
  success: z.boolean(),
  verifyResult: z.boolean(),
  verifyCode: z.string().regex(/^[A-Z]\d{3}$/),
});
const maximumAliyunCaptchaTokenBytes = 16 * 1024;

export class CaptchaValidator {
  constructor(
    private readonly captchaProvider: CaptchaProvider,
    private readonly log: LogEntry,
    private readonly verifyAliyunCaptcha: VerifyAliyunCaptcha = verifyAliyunCaptchaWithSdk
  ) {}

  public async verifyCaptcha(captchaToken: string): Promise<boolean> {
    const { config } = this.captchaProvider;

    if (isRecaptchaEnterprise(config)) {
      return this.verifyRecaptchaEnterprise(config, captchaToken);
    }

    if (isTurnstile(config)) {
      return this.verifyTurnstile(config, captchaToken);
    }

    if (isAliyun(config)) {
      return this.verifyAliyun(config, captchaToken);
    }

    throw new Error('Invalid captcha provider');
  }

  private async verifyAliyun(config: AliyunCaptchaConfig, captchaToken: string) {
    const provider = CaptchaType.Aliyun;

    if (
      captchaToken.length === 0 ||
      Buffer.byteLength(captchaToken, 'utf8') > maximumAliyunCaptchaTokenBytes
    ) {
      this.log.append({ provider, success: false });

      return false;
    }

    try {
      const { success, verifyResult, verifyCode } = aliyunCaptchaResponseGuard.parse(
        await this.verifyAliyunCaptcha(config, captchaToken)
      );
      const accepted = success && verifyResult && verifyCode === 'T001';

      this.log.append({ provider, success: accepted, verifyResult, verifyCode });

      return accepted;
    } catch {
      this.log.append({ provider, success: false });

      return false;
    }
  }

  private async verifyTurnstile(config: TurnstileConfig, captchaToken: string) {
    try {
      const result = await ky
        .post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            secret: config.secretKey,
            response: captchaToken,
          }),
        })
        .json();

      const responseGuard = z.object({
        success: z.boolean(),
        'error-codes': z.array(z.string()).optional(),
      });

      const response = responseGuard.parse(result);

      this.log.append({
        success: response.success,
        errorMessage: response['error-codes']?.join(', '),
      });

      return response.success;
    } catch {
      this.log.append({
        success: false,
        errorMessage: 'Failed to get the result from Cloudflare Turnstile',
      });

      return false;
    }
  }

  private async verifyRecaptchaEnterprise(config: RecaptchaEnterpriseConfig, captchaToken: string) {
    try {
      const result = await ky
        .post(
          `https://recaptchaenterprise.googleapis.com/v1/projects/${config.projectId}/assessments?key=${config.secretKey}`,
          {
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              event: {
                token: captchaToken,
                siteKey: config.siteKey,
                // We can't decide the action here, because the interaction event may change after the user interaction.
                // So we use a fixed action here.
                expectedAction: 'interaction',
              },
            }),
          }
        )
        .json();

      const responseGuard = z.object({
        tokenProperties: z.object({
          valid: z.boolean(),
        }),
        riskAnalysis: z.object({
          score: z.number(),
        }),
      });

      const {
        tokenProperties: { valid },
        riskAnalysis: { score },
      } = responseGuard.parse(result);

      // For checkbox mode, only check if the token is valid (skip score threshold)
      // Checkbox challenges are interactive and provide binary pass/fail
      const isCheckboxMode = config.mode === RecaptchaEnterpriseMode.Checkbox;
      // TODO: customize the score threshold
      const success = isCheckboxMode ? valid : valid && score >= 0.5;

      this.log.append({
        success,
        score,
        mode: config.mode ?? RecaptchaEnterpriseMode.Invisible,
      });

      return success;
    } catch {
      this.log.append({
        success: false,
        errorMessage: 'Failed to get the result from Google Recaptcha Enterprise',
      });

      return false;
    }
  }
}
