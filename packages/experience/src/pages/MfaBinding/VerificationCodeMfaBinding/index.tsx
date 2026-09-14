import { InteractionEvent, SignInIdentifier } from '@logto/schemas';
import { conditional } from '@silverhand/essentials';
import { type TFuncKey } from 'i18next';
import { useCallback, useContext, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { validate } from 'superstruct';

import SecondaryPageLayout from '@/Layout/SecondaryPageLayout';
import CaptchaContext from '@/Providers/CaptchaContextProvider/CaptchaContext';
import { CaptchaExecutionError } from '@/Providers/CaptchaContextProvider/aliyun-captcha';
import UserInteractionContext from '@/Providers/UserInteractionContextProvider/UserInteractionContext';
import { sendVerificationCode } from '@/apis/experience';
import SwitchMfaFactorsLink from '@/components/SwitchMfaFactorsLink';
import CaptchaBox from '@/containers/CaptchaBox';
import useErrorHandler from '@/hooks/use-error-handler';
import useNavigateWithPreservedSearchParams from '@/hooks/use-navigate-with-preserved-search-params';
import useSkipMfa from '@/hooks/use-skip-mfa';
import useSkipOptionalMfa from '@/hooks/use-skip-optional-mfa';
import IdentifierProfileForm from '@/pages/Continue/IdentifierProfileForm';
import ErrorPage from '@/pages/ErrorPage';
import { UserMfaFlow } from '@/types';
import { mfaFlowStateGuard } from '@/types/guard';
import { isCaptchaRequiredError } from '@/utils/captcha';
import { codeVerificationTypeMap } from '@/utils/sign-in-experience';

import styles from './index.module.scss';

type Props = {
  readonly identifierType: SignInIdentifier.Email | SignInIdentifier.Phone;
  readonly titleKey: TFuncKey;
  readonly descriptionKey: TFuncKey;
  readonly invalidInputErrorKey: string;
};

const VerificationCodeMfaBinding = ({
  identifierType,
  titleKey,
  descriptionKey,
  invalidInputErrorKey,
}: Props) => {
  const { state } = useLocation();
  const [, mfaFlowState] = validate(state, mfaFlowStateGuard);
  const { setVerificationId, setIdentifierInputValue } = useContext(UserInteractionContext);
  const navigate = useNavigateWithPreservedSearchParams();
  const [errorMessage, setErrorMessage] = useState<string>();

  const skipMfa = useSkipMfa();
  const skipOptionalMfa = useSkipOptionalMfa();
  const handleError = useErrorHandler();
  const { executeCaptcha } = useContext(CaptchaContext);

  const clearErrorMessage = useCallback(() => {
    setErrorMessage('');
  }, []);

  const handleSubmit = useCallback(
    async (_identifier: SignInIdentifier, value: string) => {
      const identifier = { type: identifierType, value };

      try {
        const result = await (async () => {
          try {
            return await sendVerificationCode(InteractionEvent.Register, identifier);
          } catch (error: unknown) {
            if (
              identifierType !== SignInIdentifier.Phone ||
              !(await isCaptchaRequiredError(error))
            ) {
              throw error;
            }

            const captchaToken = await executeCaptcha(identifierType);
            return sendVerificationCode(InteractionEvent.Register, identifier, captchaToken);
          }
        })();

        setVerificationId(codeVerificationTypeMap[identifierType], result.verificationId);
        setIdentifierInputValue(identifier);

        navigate('/continue/verification-code', {
          state: {
            flow: UserMfaFlow.MfaBinding,
            mfaFlowState,
          },
        });
      } catch (error: unknown) {
        if (error instanceof CaptchaExecutionError) {
          return;
        }

        await handleError(error, {
          'guard.invalid_input': () => {
            setErrorMessage(invalidInputErrorKey);
          },
        });
      }
    },
    [
      handleError,
      executeCaptcha,
      identifierType,
      invalidInputErrorKey,
      mfaFlowState,
      navigate,
      setIdentifierInputValue,
      setVerificationId,
    ]
  );

  if (!mfaFlowState) {
    return <ErrorPage title="error.invalid_session" />;
  }

  const { skippable, availableFactors, suggestion } = mfaFlowState;

  return (
    <SecondaryPageLayout
      title={titleKey}
      description={descriptionKey}
      onSkip={conditional(skippable && (suggestion ? skipOptionalMfa : skipMfa))}
    >
      <IdentifierProfileForm
        autoFocus
        errorMessage={errorMessage}
        clearErrorMessage={clearErrorMessage}
        defaultType={identifierType}
        enabledTypes={[identifierType]}
        onSubmit={handleSubmit}
      />
      <CaptchaBox />
      {availableFactors.length > 1 && (
        <SwitchMfaFactorsLink
          flow={UserMfaFlow.MfaBinding}
          flowState={mfaFlowState}
          className={styles.switchLink}
        />
      )}
    </SecondaryPageLayout>
  );
};

export default VerificationCodeMfaBinding;
