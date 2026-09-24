export const loadAliyunCaptchaRuntime = async () => {
  const [captchaModule, openapiModule, daraModule] = await Promise.all([
    import('@alicloud/captcha20230305'),
    import('@alicloud/openapi-core'),
    import('@darabonba/typescript'),
  ]);

  const captcha = captchaModule.default;
  const openapi = openapiModule.default;
  const dara = daraModule.default;

  return {
    CaptchaClient: captcha.default,
    OpenApiConfig: openapi.$OpenApiUtil.Config,
    RetryOptions: dara.RetryOptions,
    RuntimeOptions: dara.RuntimeOptions,
    VerifyIntelligentCaptchaRequest: captcha.VerifyIntelligentCaptchaRequest,
  };
};
