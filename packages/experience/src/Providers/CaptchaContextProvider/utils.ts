import { CaptchaType, RecaptchaEnterpriseMode } from '@logto/schemas';
import { useCallback, useEffect, useRef } from 'react';

import { type SignInExperienceResponse } from '@/types';

import {
  type AliyunCaptchaAttempt,
  type AliyunCaptchaInstanceRecord,
  type AliyunCaptchaOutcome,
  aliyunCaptchaScriptOwnerAttribute,
  CaptchaExecutionError,
  CaptchaExecutionErrorCode,
  isOwnedAliyunCaptchaScript,
  isValidAliyunCaptchaToken,
} from './aliyun-captcha';
import {
  aliyunCaptchaButtonId,
  aliyunCaptchaElementId,
  aliyunCaptchaScriptUrl,
  aliyunCaptchaTimeout,
  scriptId,
} from './constant';

export const getScript = (config: SignInExperienceResponse['captchaConfig']) => {
  if (!config) {
    throw new Error('Captcha config is not found');
  }

  if (config.type === CaptchaType.Turnstile) {
    return `https://challenges.cloudflare.com/turnstile/v0/api.js`;
  }

  if (config.type === CaptchaType.Aliyun) {
    return aliyunCaptchaScriptUrl;
  }

  const domain = config.domain ?? 'www.google.com';

  if (config.mode === RecaptchaEnterpriseMode.Checkbox) {
    return `https://${domain}/recaptcha/enterprise.js?render=explicit`;
  }

  return `https://${domain}/recaptcha/enterprise.js?render=${config.siteKey}`;
};

export const useAliyunCaptcha = (
  captchaConfig: SignInExperienceResponse['captchaConfig'],
  onFailure: () => void
) => {
  const attemptRef = useRef<AliyunCaptchaAttempt>();
  const instanceRef = useRef<AliyunCaptchaInstanceRecord>();
  const initializationIdRef = useRef(0);
  const isInitializingRef = useRef(false);
  const isActiveRef = useRef(true);
  const sdkFailureRef = useRef<CaptchaExecutionErrorCode>();
  const failedOwnedScriptRef = useRef<HTMLScriptElement>();
  const aliyunConfig = captchaConfig?.type === CaptchaType.Aliyun ? captchaConfig : undefined;

  /* eslint-disable @silverhand/fp/no-mutation -- Alibaba's callback API requires mutable per-attempt instance state. */
  const settle = useCallback(
    (initializationId: number, outcome: AliyunCaptchaOutcome) => {
      const attempt = attemptRef.current;

      if (!attempt || attempt.initializationId !== initializationId) {
        return;
      }

      clearTimeout(attempt.timeoutId);
      attemptRef.current = undefined;
      if (initializationIdRef.current === initializationId) {
        isInitializingRef.current = false;
        initializationIdRef.current += 1;
      }

      const instanceRecord = instanceRef.current;
      if (instanceRecord?.initializationId === initializationId) {
        instanceRef.current = undefined;
        instanceRecord.instance.destroyCaptcha();
      }

      if ('token' in outcome) {
        attempt.resolve(outcome.token);
        return;
      }

      if ('errorCode' in outcome) {
        onFailure();
        attempt.reject(new CaptchaExecutionError(outcome.errorCode));
        return;
      }

      attempt.reject(
        outcome.unexpectedError instanceof Error
          ? outcome.unexpectedError
          : new Error('Unexpected Alibaba CAPTCHA failure')
      );
    },
    [onFailure]
  );

  const rejectAttempt = useCallback(
    (initializationId: number, errorCode: CaptchaExecutionErrorCode) => {
      settle(initializationId, { errorCode });
    },
    [settle]
  );

  const rejectUnexpectedAttempt = useCallback(
    (initializationId: number, unexpectedError: unknown) => {
      settle(initializationId, { unexpectedError });
    },
    [settle]
  );

  const start = useCallback(
    (initializationId: number, instance: AliyunCaptchaInstance) => {
      const attempt = attemptRef.current;
      if (attempt?.initializationId === initializationId) {
        clearTimeout(attempt.timeoutId);
      }

      try {
        instance.startTracelessVerification();
      } catch (error: unknown) {
        rejectUnexpectedAttempt(initializationId, error);
      }
    },
    [rejectUnexpectedAttempt]
  );

  const initialize = useCallback(() => {
    if (!isActiveRef.current || !aliyunConfig || !window.initAliyunCaptcha) {
      return;
    }

    const previousInstance = instanceRef.current;
    if (previousInstance) {
      instanceRef.current = undefined;
      previousInstance.instance.destroyCaptcha();
    }

    const initializationId = ++initializationIdRef.current;
    isInitializingRef.current = true;
    sdkFailureRef.current = undefined;
    failedOwnedScriptRef.current = undefined;

    try {
      window.initAliyunCaptcha({
        SceneId: aliyunConfig.sceneId,
        mode: 'popup',
        element: `#${aliyunCaptchaElementId}`,
        button: `#${aliyunCaptchaButtonId}`,
        success: (token) => {
          if (!isValidAliyunCaptchaToken(token)) {
            rejectAttempt(initializationId, CaptchaExecutionErrorCode.InvalidToken);
            return;
          }

          settle(initializationId, { token });
        },
        fail: () => {
          rejectAttempt(initializationId, CaptchaExecutionErrorCode.VerificationFailed);
        },
        getInstance: (instance) => {
          if (initializationId !== initializationIdRef.current) {
            instance.destroyCaptcha();
            return;
          }

          isInitializingRef.current = false;
          instanceRef.current = { initializationId, instance };

          if (attemptRef.current?.initializationId === initializationId) {
            start(initializationId, instance);
          }
        },
        slideStyle: { width: 360, height: 40 },
        language: 'cn',
        timeout: aliyunCaptchaTimeout,
        onError: () => {
          isInitializingRef.current = false;
          rejectAttempt(initializationId, CaptchaExecutionErrorCode.SdkInitializationFailed);
        },
        onClose: (reason) => {
          if (reason === 'userDismiss') {
            rejectAttempt(initializationId, CaptchaExecutionErrorCode.UserClosed);
          }
        },
        delayBeforeSuccess: false,
      });
    } catch (error: unknown) {
      isInitializingRef.current = false;
      if (attemptRef.current?.initializationId === initializationId) {
        rejectUnexpectedAttempt(initializationId, error);
        return;
      }

      throw error;
    }
  }, [aliyunConfig, rejectAttempt, rejectUnexpectedAttempt, settle, start]);

  const prepare = useCallback(() => {
    if (!isActiveRef.current || !aliyunConfig) {
      return;
    }

    window.AliyunCaptchaConfig = {
      region: aliyunConfig.region,
      prefix: aliyunConfig.prefix,
    };

    const handleLoadFailure = (script: HTMLScriptElement, errorCode: CaptchaExecutionErrorCode) => {
      sdkFailureRef.current = errorCode;
      if (isOwnedAliyunCaptchaScript(script)) {
        failedOwnedScriptRef.current = script;
      }
      rejectAttempt(
        attemptRef.current?.initializationId ?? initializationIdRef.current + 1,
        errorCode
      );
    };
    const observeScript = (script: HTMLScriptElement) => {
      script.addEventListener(
        'load',
        () => {
          if (!window.initAliyunCaptcha) {
            handleLoadFailure(script, CaptchaExecutionErrorCode.SdkUnavailable);
            return;
          }

          if (!instanceRef.current && !isInitializingRef.current) {
            initialize();
          }
        },
        { once: true }
      );
      script.addEventListener(
        'error',
        () => {
          handleLoadFailure(script, CaptchaExecutionErrorCode.SdkLoadFailed);
        },
        { once: true }
      );
    };

    const existingScript = document.querySelector<HTMLScriptElement>(`#${scriptId}`);
    if (existingScript) {
      if (window.initAliyunCaptcha) {
        initialize();
      } else if (existingScript.src === aliyunCaptchaScriptUrl) {
        observeScript(existingScript);
      }
      return;
    }

    const script = document.createElement('script');
    script.src = aliyunCaptchaScriptUrl;
    script.id = scriptId;
    script.async = true;
    script.setAttribute(aliyunCaptchaScriptOwnerAttribute, '');
    observeScript(script);
    document.body.append(script);

    if (window.initAliyunCaptcha) {
      initialize();
    }
  }, [aliyunConfig, initialize, rejectAttempt]);

  const execute = useCallback(
    async () =>
      new Promise<string>((resolve, reject) => {
        const failedScript = failedOwnedScriptRef.current;
        if (sdkFailureRef.current && failedScript && isOwnedAliyunCaptchaScript(failedScript)) {
          failedScript.remove();
          failedOwnedScriptRef.current = undefined;
          sdkFailureRef.current = undefined;
          isInitializingRef.current = false;
          initializationIdRef.current += 1;
          prepare();
        }

        const existingAttempt = attemptRef.current;
        if (existingAttempt) {
          rejectAttempt(existingAttempt.initializationId, CaptchaExecutionErrorCode.Superseded);
        }

        const instanceRecord = instanceRef.current;
        const initializationId =
          instanceRecord?.initializationId ??
          (isInitializingRef.current
            ? initializationIdRef.current
            : initializationIdRef.current + 1);
        const timeoutId = setTimeout(() => {
          rejectAttempt(initializationId, CaptchaExecutionErrorCode.InitializationTimedOut);
        }, aliyunCaptchaTimeout);
        attemptRef.current = {
          initializationId,
          resolve,
          reject,
          timeoutId,
        };

        if (sdkFailureRef.current) {
          rejectAttempt(initializationId, sdkFailureRef.current);
          return;
        }

        if (instanceRecord) {
          start(initializationId, instanceRecord.instance);
          return;
        }

        if (!isInitializingRef.current && window.initAliyunCaptcha) {
          initialize();
        }
      }),
    [initialize, prepare, rejectAttempt, start]
  );

  useEffect(() => {
    isActiveRef.current = true;

    return () => {
      isActiveRef.current = false;
      initializationIdRef.current += 1;
      const attempt = attemptRef.current;
      attemptRef.current = undefined;
      if (attempt) {
        clearTimeout(attempt.timeoutId);
        attempt.reject(new CaptchaExecutionError(CaptchaExecutionErrorCode.ProviderUnmounted));
      }

      const instanceRecord = instanceRef.current;
      instanceRef.current = undefined;
      instanceRecord?.instance.destroyCaptcha();
    };
  }, []);
  /* eslint-enable @silverhand/fp/no-mutation */

  return { prepare, execute };
};
