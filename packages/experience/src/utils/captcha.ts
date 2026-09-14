import { type RequestErrorBody } from '@logto/schemas';
import { HTTPError } from 'ky';

export const isCaptchaRequiredError = async (error: unknown) => {
  if (!(error instanceof HTTPError)) {
    return false;
  }

  try {
    const { code } = await error.response.clone().json<RequestErrorBody>();
    return code === 'session.captcha_required';
  } catch {
    return false;
  }
};
