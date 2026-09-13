import { aliyunCaptchaScriptUrl } from './constant';

export enum CaptchaExecutionErrorCode {
  InitializationTimedOut = 'initialization_timed_out',
  InvalidToken = 'invalid_token',
  ProviderUnmounted = 'provider_unmounted',
  SdkInitializationFailed = 'sdk_initialization_failed',
  SdkLoadFailed = 'sdk_load_failed',
  SdkUnavailable = 'sdk_unavailable',
  Superseded = 'superseded',
  UserClosed = 'user_closed',
  VerificationFailed = 'verification_failed',
}

export class CaptchaExecutionError extends Error {
  constructor(public readonly code: CaptchaExecutionErrorCode) {
    super('Alibaba CAPTCHA execution was not completed');
    this.name = 'CaptchaExecutionError';
  }
}

export type AliyunCaptchaAttempt = {
  readonly initializationId: number;
  readonly resolve: (token: string) => void;
  readonly reject: (error: Error) => void;
  readonly timeoutId: ReturnType<typeof setTimeout>;
};

export type AliyunCaptchaInstanceRecord = {
  readonly initializationId: number;
  readonly instance: AliyunCaptchaInstance;
};

export type AliyunCaptchaOutcome =
  | { readonly token: string }
  | { readonly errorCode: CaptchaExecutionErrorCode }
  | { readonly unexpectedError: unknown };

const maximumAliyunCaptchaTokenBytes = 16 * 1024;

export const isValidAliyunCaptchaToken = (token: unknown): token is string =>
  typeof token === 'string' &&
  token.length > 0 &&
  token.length <= maximumAliyunCaptchaTokenBytes &&
  new Blob([token]).size <= maximumAliyunCaptchaTokenBytes;

export const aliyunCaptchaScriptOwnerAttribute = 'data-logto-aliyun-captcha';

export const isOwnedAliyunCaptchaScript = (script: HTMLScriptElement) =>
  script.src === aliyunCaptchaScriptUrl && script.hasAttribute(aliyunCaptchaScriptOwnerAttribute);
