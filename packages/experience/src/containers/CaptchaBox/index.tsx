import { CaptchaType, RecaptchaEnterpriseMode } from '@logto/schemas';
import { useContext } from 'react';

import CaptchaContext from '@/Providers/CaptchaContextProvider/CaptchaContext';

import styles from './index.module.scss';

const CaptchaBox = () => {
  const { captchaConfig, widgetRef, isCaptchaRequired } = useContext(CaptchaContext);

  // Check if widget rendering is needed
  // Turnstile always needs a target, while reCAPTCHA needs one only in checkbox mode.
  const needsWidget =
    isCaptchaRequired &&
    captchaConfig &&
    (captchaConfig.type === CaptchaType.Turnstile ||
      (captchaConfig.type === CaptchaType.RecaptchaEnterprise &&
        captchaConfig.mode === RecaptchaEnterpriseMode.Checkbox));

  if (!needsWidget) {
    return null;
  }

  return <div ref={widgetRef} className={styles.captchaBox} />;
};

export default CaptchaBox;
