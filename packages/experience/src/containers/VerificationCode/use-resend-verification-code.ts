import {
  InteractionEvent,
  SignInIdentifier,
  type VerificationCodeIdentifier,
} from '@logto/schemas';
import { t } from 'i18next';
import { useCallback, useContext, useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import { useTimer } from 'react-timer-hook';

import CaptchaContext from '@/Providers/CaptchaContextProvider/CaptchaContext';
import { CaptchaExecutionError } from '@/Providers/CaptchaContextProvider/aliyun-captcha';
import UserInteractionContext from '@/Providers/UserInteractionContextProvider/UserInteractionContext';
import { sendVerificationCode } from '@/apis/experience';
import { getInteractionEventFromState, userFlowToInteractionEventMap } from '@/apis/utils';
import useApi from '@/hooks/use-api';
import useErrorHandler from '@/hooks/use-error-handler';
import useToast from '@/hooks/use-toast';
import { UserFlow } from '@/types';
import { codeVerificationTypeMap } from '@/utils/sign-in-experience';

export const timeRange = 59;

const getTimeout = () => {
  const now = new Date();
  now.setSeconds(now.getSeconds() + timeRange);

  return now;
};

const useResendVerificationCode = (flow: UserFlow, identifier: VerificationCodeIdentifier) => {
  const { setToast } = useToast();
  const { state } = useLocation();

  const interactionEvent = useMemo<InteractionEvent>(() => {
    if (flow === UserFlow.Continue) {
      const interactionEvent = getInteractionEventFromState(state);
      return interactionEvent ?? InteractionEvent.SignIn;
    }

    return userFlowToInteractionEventMap[flow];
  }, [flow, state]);

  const { seconds, isRunning, restart } = useTimer({
    autoStart: true,
    expiryTimestamp: getTimeout(),
  });

  const handleError = useErrorHandler();
  const resendVerificationCode = useApi(sendVerificationCode);
  const { setVerificationId } = useContext(UserInteractionContext);
  const { executeCaptcha } = useContext(CaptchaContext);

  const onResendVerificationCode = useCallback(async () => {
    const captchaResult = await (async (): Promise<{ captchaToken?: string } | undefined> => {
      if (identifier.type !== SignInIdentifier.Phone) {
        return {};
      }

      try {
        return { captchaToken: await executeCaptcha(identifier.type) };
      } catch (error: unknown) {
        if (error instanceof CaptchaExecutionError) {
          return;
        }

        throw error;
      }
    })();

    if (!captchaResult) {
      return;
    }

    const { captchaToken } = captchaResult;
    const [error, result] =
      captchaToken === undefined
        ? await resendVerificationCode(interactionEvent, identifier)
        : await resendVerificationCode(interactionEvent, identifier, captchaToken);

    if (error) {
      await handleError(error);

      return;
    }

    if (result) {
      // Renew the verification ID in the context
      setVerificationId(codeVerificationTypeMap[identifier.type], result.verificationId);
      setToast(t('description.passcode_sent'));
      restart(getTimeout(), true);
    }
  }, [
    resendVerificationCode,
    interactionEvent,
    identifier,
    handleError,
    setVerificationId,
    setToast,
    restart,
    executeCaptcha,
  ]);

  return {
    seconds,
    isRunning,
    onResendVerificationCode,
  };
};

export default useResendVerificationCode;
