import { loadAliyunCaptchaRuntime } from '../routes/experience/classes/libraries/aliyun-captcha-sdk.js';

const {
  CaptchaClient,
  OpenApiConfig,
  RetryOptions,
  RuntimeOptions,
  VerifyIntelligentCaptchaRequest,
} = await loadAliyunCaptchaRuntime();

const client = new CaptchaClient(
  new OpenApiConfig({
    accessKeyId: 'runtime-probe',
    accessKeySecret: 'runtime-probe',
    endpoint: 'captcha.cn-shanghai.aliyuncs.com',
    regionId: 'cn-shanghai',
    retryOptions: new RetryOptions({ retryable: false }),
  })
);
const request = new VerifyIntelligentCaptchaRequest({
  captchaVerifyParam: 'runtime-probe',
  sceneId: 'runtime-probe',
});
const runtime = new RuntimeOptions({ connectTimeout: 2000, readTimeout: 3000 });

if (
  typeof client.verifyIntelligentCaptchaWithOptions !== 'function' ||
  typeof request.validate !== 'function' ||
  typeof runtime !== 'object'
) {
  throw new TypeError('Alibaba CAPTCHA runtime is incomplete.');
}
