/* Replace legacy useSendVerificationCode hook with this one after the refactor */

import { SignInIdentifier } from '@logto/schemas';
import { conditional } from '@silverhand/essentials';
import { HTTPError } from 'ky';
import { useCallback, useContext, useState } from 'react';
import { useTranslation } from 'react-i18next';

import CaptchaContext from '@/Providers/CaptchaContextProvider/CaptchaContext';
import { CaptchaExecutionError } from '@/Providers/CaptchaContextProvider/aliyun-captcha';
import UserInteractionContext from '@/Providers/UserInteractionContextProvider/UserInteractionContext';
import { sendVerificationCodeApi } from '@/apis/utils';
import useApi from '@/hooks/use-api';
import useErrorHandler, { type ErrorHandlers } from '@/hooks/use-error-handler';
import useNavigateWithPreservedSearchParams from '@/hooks/use-navigate-with-preserved-search-params';
import useToast from '@/hooks/use-toast';
import {
  UserFlow,
  type ContinueFlowInteractionEvent,
  type VerificationCodeIdentifier,
} from '@/types';
import { isCaptchaRequiredError } from '@/utils/captcha';
import { codeVerificationTypeMap } from '@/utils/sign-in-experience';

type Payload = {
  identifier: VerificationCodeIdentifier;
  value: string;
};

const useSendVerificationCode = (flow: UserFlow, replaceCurrentPage?: boolean) => {
  const [errorMessage, setErrorMessage] = useState<string>();
  const navigate = useNavigateWithPreservedSearchParams();
  const { executeCaptcha } = useContext(CaptchaContext);

  const handleError = useErrorHandler();
  const { setToast } = useToast();
  const { t } = useTranslation();
  const asyncSendVerificationCode = useApi(sendVerificationCodeApi);
  const { setVerificationId } = useContext(UserInteractionContext);

  const clearErrorMessage = useCallback(() => {
    setErrorMessage('');
  }, []);

  const onSubmit = useCallback(
    async (
      { identifier, value }: Payload,
      interactionEvent?: ContinueFlowInteractionEvent,
      errorHandlers?: ErrorHandlers
    ) => {
      const send = async (captchaTokenOrGetter?: string | (() => Promise<string | undefined>)) =>
        asyncSendVerificationCode(
          flow,
          {
            type: identifier,
            value,
          },
          interactionEvent,
          captchaTokenOrGetter
        );

      const executeCaptchaAndSend = async () => {
        const response = await send(async () => executeCaptcha(identifier));
        const [error] = response;

        if (error instanceof CaptchaExecutionError) {
          return;
        }

        if (error && !(error instanceof HTTPError)) {
          if (error instanceof Error) {
            throw error;
          }

          throw new TypeError('Unexpected CAPTCHA execution failure', { cause: error });
        }

        return response;
      };

      const sendWithAdaptiveContinueCaptcha = async () => {
        const initialResponse = await send();

        if (!(await isCaptchaRequiredError(initialResponse[0]))) {
          return initialResponse;
        }

        return executeCaptchaAndSend();
      };

      const response =
        flow === UserFlow.Continue
          ? await sendWithAdaptiveContinueCaptcha()
          : await executeCaptchaAndSend();

      if (!response) {
        return;
      }

      const [error, result] = response;

      if (error) {
        await handleError(error, {
          'guard.invalid_input': () => {
            setErrorMessage(
              identifier === SignInIdentifier.Email ? 'invalid_email' : 'invalid_phone'
            );
          },
          'session.email_blocklist.email_not_allowed': (error) => {
            setErrorMessage(error.message);
          },
          'session.email_blocklist.email_subaddressing_not_allowed': (error) => {
            setErrorMessage(error.message);
          },
          // The hosted email service usage cap has been reached. Show a friendly, generic "couldn't
          // send the code" toast instead of the raw API "usage limit" message.
          'connector.usage_limit_exceeded': () => {
            setToast(t('error.send_verification_code_failed'));
          },
          // Per-call overrides win over the defaults above, so a caller can react to a specific
          // failure differently (e.g. sign-in falls back to the password page on a cap hit).
          ...errorHandlers,
        });

        return;
      }

      if (result) {
        // Store the verification ID in the context so that we can use it in the next step
        setVerificationId(codeVerificationTypeMap[identifier], result.verificationId);

        navigate(
          {
            pathname: `/${flow}/verification-code`,
            search: window.location.search,
          },
          {
            replace: replaceCurrentPage,
            // Append the interaction event to the state so that we can use it in the next step
            ...conditional(
              flow === UserFlow.Continue && {
                state: { interactionEvent },
              }
            ),
          }
        );
      }
    },
    [
      asyncSendVerificationCode,
      flow,
      handleError,
      navigate,
      replaceCurrentPage,
      setVerificationId,
      executeCaptcha,
      setToast,
      t,
    ]
  );

  return {
    errorMessage,
    clearErrorMessage,
    onSubmit,
  };
};

export default useSendVerificationCode;
