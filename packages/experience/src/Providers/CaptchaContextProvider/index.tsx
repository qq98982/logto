import {
  CaptchaPolicyScope,
  CaptchaType,
  RecaptchaEnterpriseMode,
  SignInIdentifier,
  Theme,
} from '@logto/schemas';
import { useMemo, useContext, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';

import useToast from '@/hooks/use-toast';
import { type VerificationCodeIdentifier } from '@/types';

import PageContext from '../PageContextProvider/PageContext';

import CaptchaContext, { type CaptchaContextType } from './CaptchaContext';
import { aliyunCaptchaButtonId, aliyunCaptchaElementId, scriptId } from './constant';
import { getScript, useAliyunCaptcha } from './utils';

type Props = {
  readonly children: React.ReactNode;
};

const CaptchaContextProvider = ({ children }: Props) => {
  const { experienceSettings, theme } = useContext(PageContext);
  const widgetRef = useRef<HTMLDivElement>(null);
  const { setToast } = useToast();
  const { t } = useTranslation();

  const captchaPolicy = experienceSettings?.captchaPolicy;
  const captchaConfig = experienceSettings?.captchaConfig;
  const isCaptchaRequired = Boolean(captchaPolicy?.enabled);
  const isAliyunCaptchaActive = isCaptchaRequired && captchaConfig?.type === CaptchaType.Aliyun;
  const handleAliyunFailure = useCallback(() => {
    setToast(t('error.captcha_verification_failed'));
  }, [setToast, t]);
  const { prepare: prepareAliyunCaptcha, execute: executeAliyunCaptcha } = useAliyunCaptcha(
    captchaConfig,
    handleAliyunFailure
  );

  const initCaptcha = useCallback(() => {
    if (!isCaptchaRequired || !captchaConfig) {
      return;
    }

    if (captchaConfig.type === CaptchaType.Aliyun) {
      prepareAliyunCaptcha();
      return;
    }

    if (document.querySelector(`#${scriptId}`)) {
      return;
    }

    const script = document.createElement('script');
    /* eslint-disable @silverhand/fp/no-mutation -- Script element properties must be set before attachment. */
    script.src = getScript(captchaConfig);
    script.id = scriptId;
    script.async = true;
    /* eslint-enable @silverhand/fp/no-mutation */
    document.body.append(script);
  }, [captchaConfig, isCaptchaRequired, prepareAliyunCaptcha]);

  const executeCaptcha = useCallback(
    async (identifier?: VerificationCodeIdentifier) => {
      if (!isCaptchaRequired || !captchaConfig) {
        return;
      }

      const captchaScope = captchaPolicy?.scope ?? CaptchaPolicyScope.Interaction;
      if (
        captchaScope === CaptchaPolicyScope.PhoneVerificationCode &&
        identifier !== SignInIdentifier.Phone
      ) {
        return;
      }

      if (captchaConfig.type === CaptchaType.Aliyun) {
        return executeAliyunCaptcha();
      }

      if (captchaConfig.type === CaptchaType.Turnstile) {
        return new Promise<string | undefined>((resolve, reject) => {
          if (!window.turnstile || !widgetRef.current) {
            resolve(undefined);
            return;
          }

          // eslint-disable-next-line @silverhand/fp/no-mutation -- The provider owns this SDK render target.
          widgetRef.current.innerHTML = '';

          window.turnstile.render(widgetRef.current, {
            sitekey: captchaConfig.siteKey,
            theme: theme === Theme.Light ? 'light' : 'dark',
            callback: (token: string) => {
              resolve(token);
            },
            'error-callback': (errorCode) => {
              setToast(t('error.captcha_verification_failed'));
              reject(new Error(`Turnstile error: ${errorCode}`));
            },
            size: 'flexible',
          });
        });
      }

      if (!window.grecaptcha?.enterprise) {
        return;
      }

      if (captchaConfig.mode === RecaptchaEnterpriseMode.Checkbox) {
        return new Promise<string | undefined>((resolve, reject) => {
          if (!window.grecaptcha || !widgetRef.current) {
            resolve(undefined);
            return;
          }

          // eslint-disable-next-line @silverhand/fp/no-mutation -- The provider owns this SDK render target.
          widgetRef.current.innerHTML = '';

          window.grecaptcha.enterprise.render(widgetRef.current, {
            sitekey: captchaConfig.siteKey,
            theme: theme === Theme.Light ? 'light' : 'dark',
            callback: (token: string) => {
              resolve(token);
            },
            'error-callback': (errorCode) => {
              setToast(t('error.captcha_verification_failed'));
              reject(new Error(`reCAPTCHA error: ${errorCode}`));
            },
          });
        });
      }

      return window.grecaptcha.enterprise.execute(captchaConfig.siteKey, {
        action: 'interaction',
      });
    },
    [
      captchaConfig,
      captchaPolicy?.scope,
      executeAliyunCaptcha,
      isCaptchaRequired,
      setToast,
      t,
      theme,
    ]
  );

  useEffect(() => {
    initCaptcha();
  }, [initCaptcha]);

  const captchaContext = useMemo<CaptchaContextType>(
    () => ({
      isCaptchaRequired,
      executeCaptcha,
      captchaConfig,
      widgetRef,
    }),
    [isCaptchaRequired, executeCaptcha, captchaConfig, widgetRef]
  );

  return (
    <CaptchaContext.Provider value={captchaContext}>
      {isAliyunCaptchaActive && (
        <>
          <div id={aliyunCaptchaElementId} />
          <button
            hidden
            id={aliyunCaptchaButtonId}
            type="button"
            aria-hidden="true"
            tabIndex={-1}
          />
        </>
      )}
      {children}
    </CaptchaContext.Provider>
  );
};

export default CaptchaContextProvider;
