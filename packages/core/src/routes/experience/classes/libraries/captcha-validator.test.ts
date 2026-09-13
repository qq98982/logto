import { CaptchaType, type CaptchaProvider } from '@logto/schemas';

import { type LogEntry } from '#src/middleware/koa-audit-log.js';

import type {
  CaptchaValidator as CaptchaValidatorType,
  VerifyAliyunCaptcha,
} from './captcha-validator.js';

const { jest } = import.meta;

const verifyIntelligentCaptchaWithOptions = jest.fn();
const MockConfig = jest.fn((values: Record<string, unknown>) => values);
const MockRequest = jest.fn((values: Record<string, unknown>) => values);
const MockRetryOptions = jest.fn((values: Record<string, unknown>) => values);
const MockRuntimeOptions = jest.fn((values: Record<string, unknown>) => values);
const MockCaptchaClient = jest.fn(() => ({ verifyIntelligentCaptchaWithOptions }));

jest.unstable_mockModule('@alicloud/captcha20230305', () => ({
  default: { default: MockCaptchaClient },
  VerifyIntelligentCaptchaRequest: MockRequest,
}));
jest.unstable_mockModule('@alicloud/openapi-core', () => ({
  $OpenApiUtil: { Config: MockConfig },
}));
jest.unstable_mockModule('@darabonba/typescript', () => ({
  RetryOptions: MockRetryOptions,
  RuntimeOptions: MockRuntimeOptions,
}));

const { CaptchaValidator } = await import('./captcha-validator.js');

const accessKeyId = 'test_access_key_id';
const accessKeySecret = 'test_access_key_secret';
const aliyunConfig = {
  type: CaptchaType.Aliyun,
  region: 'cn',
  prefix: 'test_prefix',
  sceneId: 'test_scene',
  accessKeyId,
  accessKeySecret,
} as const;
const aliyunProvider: CaptchaProvider = {
  id: 'aliyun_captcha_provider',
  tenantId: 'fake_tenant',
  createdAt: Date.now(),
  updatedAt: Date.now(),
  config: aliyunConfig,
};

const createValidator = (verifyAliyunCaptcha: VerifyAliyunCaptcha) => {
  const append = jest.fn();
  const log = { append } as unknown as LogEntry;
  const validator: CaptchaValidatorType = new CaptchaValidator(
    aliyunProvider,
    log,
    verifyAliyunCaptcha
  );

  return { append, validator, verifyAliyunCaptcha };
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe('Alibaba CAPTCHA validation', () => {
  it('calls the SDK with closed production configuration and bounded runtime options', async () => {
    verifyIntelligentCaptchaWithOptions.mockResolvedValueOnce({
      body: {
        success: true,
        result: { verifyResult: true, verifyCode: 'T001' },
      },
    });
    const append = jest.fn();
    const validator = new CaptchaValidator(aliyunProvider, { append } as unknown as LogEntry);
    const token = 'raw-captcha-token';

    await expect(validator.verifyCaptcha(token)).resolves.toBe(true);
    expect(MockRetryOptions).toHaveBeenCalledWith({ retryable: false });
    expect(MockCaptchaClient).toHaveBeenCalledWith({
      accessKeyId,
      accessKeySecret,
      endpoint: 'captcha.cn-shanghai.aliyuncs.com',
      regionId: 'cn-shanghai',
      retryOptions: { retryable: false },
    });
    expect(verifyIntelligentCaptchaWithOptions).toHaveBeenCalledWith(
      {
        captchaVerifyParam: token,
        sceneId: aliyunConfig.sceneId,
      },
      {
        connectTimeout: 2000,
        readTimeout: 3000,
      }
    );
  });

  it('accepts only the documented successful verification result', async () => {
    const verifyAliyunCaptcha = jest.fn().mockResolvedValue({
      success: true,
      verifyResult: true,
      verifyCode: 'T001',
    });
    const { append, validator } = createValidator(verifyAliyunCaptcha);
    const token = 'raw-captcha-token';

    await expect(validator.verifyCaptcha(token)).resolves.toBe(true);
    expect(verifyAliyunCaptcha).toHaveBeenCalledWith(aliyunConfig, token);
    expect(append).toHaveBeenCalledWith({
      provider: CaptchaType.Aliyun,
      success: true,
      verifyResult: true,
      verifyCode: 'T001',
    });
  });

  it.each([
    ['unsuccessful request', { success: false, verifyResult: true, verifyCode: 'T001' }],
    ['failed verification', { success: true, verifyResult: false, verifyCode: 'T001' }],
    ['provider rejection', { success: true, verifyResult: false, verifyCode: 'F008' }],
    ['test-scene result', { success: true, verifyResult: true, verifyCode: 'T005' }],
    ['undefined response', undefined],
    ['malformed response', { success: 'true', verifyResult: true, verifyCode: 'T001' }],
  ])('rejects %s', async (_name, result) => {
    const verifyAliyunCaptcha = jest.fn().mockResolvedValue(result) as VerifyAliyunCaptcha;
    const { append, validator } = createValidator(verifyAliyunCaptcha);

    await expect(validator.verifyCaptcha('raw-captcha-token')).resolves.toBe(false);
    expect(append).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: CaptchaType.Aliyun,
        success: false,
      })
    );
  });

  it.each([new Error('network failure'), new Error('request timeout')])(
    'fails closed when the verifier throws: %s',
    async (error) => {
      const verifyAliyunCaptcha = jest.fn().mockRejectedValue(error) as VerifyAliyunCaptcha;
      const { validator } = createValidator(verifyAliyunCaptcha);

      await expect(validator.verifyCaptcha('raw-captcha-token')).resolves.toBe(false);
    }
  );

  it.each([
    ['empty', ''],
    ['over 16 KiB', 'x'.repeat(16_385)],
  ])('rejects an %s token before calling Alibaba', async (_name, token) => {
    const verifyAliyunCaptcha = jest.fn() as VerifyAliyunCaptcha;
    const { validator } = createValidator(verifyAliyunCaptcha);

    await expect(validator.verifyCaptcha(token)).resolves.toBe(false);
    expect(verifyAliyunCaptcha).not.toHaveBeenCalled();
  });

  it('passes a multibyte token at the exact 16 KiB boundary unchanged', async () => {
    const token = '你'.repeat(5461) + 'a';
    const verifyAliyunCaptcha = jest.fn().mockResolvedValue({
      success: true,
      verifyResult: true,
      verifyCode: 'T001',
    });
    const { validator } = createValidator(verifyAliyunCaptcha);

    expect(Buffer.byteLength(token, 'utf8')).toBe(16_384);
    await expect(validator.verifyCaptcha(token)).resolves.toBe(true);
    expect(verifyAliyunCaptcha).toHaveBeenCalledWith(aliyunConfig, token);
  });

  it('rejects a multibyte token over 16 KiB before calling Alibaba', async () => {
    const token = '你'.repeat(5461) + 'ab';
    const verifyAliyunCaptcha = jest.fn() as VerifyAliyunCaptcha;
    const { validator } = createValidator(verifyAliyunCaptcha);

    expect(Buffer.byteLength(token, 'utf8')).toBe(16_385);
    await expect(validator.verifyCaptcha(token)).resolves.toBe(false);
    expect(verifyAliyunCaptcha).not.toHaveBeenCalled();
  });

  it.each([
    { success: true, verifyResult: true, verifyCode: 'T001' },
    { success: true, verifyResult: false, verifyCode: 'F008' },
    undefined,
  ])('never writes token or credentials to the audit log for result %#', async (result) => {
    const token = 'sensitive-raw-captcha-token';
    const verifyAliyunCaptcha = jest.fn().mockResolvedValue(result) as VerifyAliyunCaptcha;
    const { append, validator } = createValidator(verifyAliyunCaptcha);

    await validator.verifyCaptcha(token);

    const auditPayload = JSON.stringify(append.mock.calls);

    expect(auditPayload).not.toContain(token);
    expect(auditPayload).not.toContain(accessKeyId);
    expect(auditPayload).not.toContain(accessKeySecret);
    expect(auditPayload).not.toContain('accessKeyId');
    expect(auditPayload).not.toContain('accessKeySecret');
  });

  it('never writes thrown provider messages to the audit log', async () => {
    const providerMessage = 'timeout while sending sensitive-raw-captcha-token';
    const verifyAliyunCaptcha = jest
      .fn()
      .mockRejectedValue(new Error(providerMessage)) as VerifyAliyunCaptcha;
    const { append, validator } = createValidator(verifyAliyunCaptcha);

    await validator.verifyCaptcha('sensitive-raw-captcha-token');

    expect(JSON.stringify(append.mock.calls)).not.toContain(providerMessage);
  });
});
