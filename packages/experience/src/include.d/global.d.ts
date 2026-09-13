import { type SsrData } from '@logto/schemas';

type LogtoNativeSdkInfo = {
  platform: 'ios' | 'android';
  callbackLink: string;
  getPostMessage: () => (data: { callbackUri?: string; redirectTo?: string }) => void;
  supportedConnector: {
    universal: boolean;
    nativeTargets: string[];
  };
};

type LogtoSsr = string | Readonly<SsrData> | undefined;

declare global {
  type AliyunCaptchaInstance = {
    startTracelessVerification(): void;
    destroyCaptcha(): void;
  };

  type AliyunCaptchaOptions = {
    SceneId: string;
    mode: 'popup';
    element: string;
    button: string;
    success: (captchaVerifyParam: string) => void;
    fail: (result: unknown) => void;
    getInstance: (instance: AliyunCaptchaInstance) => void;
    slideStyle: { width: number; height: number };
    language: 'cn';
    timeout: number;
    onError: (errorInfo: { code: string; msg: string }) => void;
    onClose: (reason: 'userDismiss' | 'verifyComplete') => void;
    delayBeforeSuccess: false;
  };

  const logtoNativeSdk: LogtoNativeSdkInfo | undefined;
  const logtoSsr: LogtoSsr;

  interface Window {
    logtoNativeSdk: LogtoNativeSdkInfo | undefined;
    logtoSsr: LogtoSsr;

    // Captcha providers
    AliyunCaptchaConfig?: {
      region: 'cn';
      prefix: string;
    };
    initAliyunCaptcha?: (options: AliyunCaptchaOptions) => void;
    grecaptcha?: {
      enterprise: {
        ready: (callback: () => void) => void;
        execute: (sitekey: string, options: { action: string }) => Promise<string>;
        render: (
          element: HTMLElement,
          options: {
            sitekey: string;
            callback: (token: string) => void;
            theme?: 'light' | 'dark';
            'error-callback'?: (errorCode?: string) => void;
          }
        ) => number;
      };
    };
    turnstile?: {
      render: (
        element: HTMLElement,
        options: {
          sitekey: string;
          callback: (token: string) => void;
          theme: 'light' | 'dark';
          'error-callback': (errorCode: string) => void;
          size: string;
        }
      ) => void;
    };
  }
}
