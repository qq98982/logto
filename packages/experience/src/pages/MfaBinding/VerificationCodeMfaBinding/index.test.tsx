import {
  CaptchaType,
  InteractionEvent,
  RecaptchaEnterpriseMode,
  type SignInIdentifier,
} from '@logto/schemas';
import { fireEvent, waitFor } from '@testing-library/react';
import { HTTPError } from 'ky';
import { createRef } from 'react';

import CaptchaContext from '@/Providers/CaptchaContextProvider/CaptchaContext';
import {
  CaptchaExecutionError,
  CaptchaExecutionErrorCode,
} from '@/Providers/CaptchaContextProvider/aliyun-captcha';
import UserInteractionContext from '@/Providers/UserInteractionContextProvider/UserInteractionContext';
import renderWithPageContext from '@/__mocks__/RenderWithPageContext';
import { sendVerificationCode } from '@/apis/experience';
import { type SignInExperienceResponse } from '@/types';

import VerificationCodeMfaBinding from '.';

const navigate = jest.fn();

jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useLocation: () => ({
    state: {
      availableFactors: ['PhoneVerificationCode'],
      skippable: false,
    },
  }),
}));

// eslint-disable-next-line unicorn/consistent-function-scoping -- The Jest factory returns a hook.
jest.mock('@/hooks/use-navigate-with-preserved-search-params', () => () => navigate);
jest.mock('@/apis/experience', () => ({ sendVerificationCode: jest.fn() }));
jest.mock('@/pages/Continue/IdentifierProfileForm', () => ({
  __esModule: true,
  default: ({
    onSubmit,
  }: {
    onSubmit?: (identifier: SignInIdentifier, value: string) => Promise<void> | void;
  }) => (
    <button
      onClick={() => {
        void onSubmit?.('phone' as SignInIdentifier, 'test-phone');
      }}
    >
      submit-identifier
    </button>
  ),
}));

const captchaRequiredError = () => {
  const response = {
    status: 422,
    statusText: 'Unprocessable Entity',
    clone: () => response,
    json: async () => ({ code: 'session.captcha_required' }),
  } as unknown as Response;

  return new HTTPError(response, {} as Request, {} as never);
};

const providerConfigs: ReadonlyArray<
  [
    name: string,
    config: NonNullable<SignInExperienceResponse['captchaConfig']>,
    needsWidget: boolean,
  ]
> = [
  [
    'Alibaba',
    {
      type: CaptchaType.Aliyun,
      region: 'cn',
      prefix: 'test-prefix',
      sceneId: 'test-scene',
    },
    false,
  ],
  ['Turnstile', { type: CaptchaType.Turnstile, siteKey: 'turnstile-site-key' }, true],
  [
    'reCAPTCHA checkbox',
    {
      type: CaptchaType.RecaptchaEnterprise,
      siteKey: 'recaptcha-site-key',
      mode: RecaptchaEnterpriseMode.Checkbox,
    },
    true,
  ],
  [
    'reCAPTCHA invisible',
    {
      type: CaptchaType.RecaptchaEnterprise,
      siteKey: 'recaptcha-site-key',
      mode: RecaptchaEnterpriseMode.Invisible,
    },
    false,
  ],
];

const renderBinding = (
  captchaConfig: NonNullable<SignInExperienceResponse['captchaConfig']>,
  executeCaptcha: jest.Mock,
  setVerificationId = jest.fn()
) => {
  const widgetRef = createRef<HTMLDivElement>();
  const view = renderWithPageContext(
    <CaptchaContext.Provider
      value={{ isCaptchaRequired: true, captchaConfig, widgetRef, executeCaptcha }}
    >
      <UserInteractionContext.Provider
        value={{ setVerificationId, setIdentifierInputValue: jest.fn() } as never}
      >
        <VerificationCodeMfaBinding
          identifierType={'phone' as SignInIdentifier.Phone}
          titleKey="mfa.link_phone_verification_code_description"
          descriptionKey="mfa.link_phone_2fa_description"
          invalidInputErrorKey="invalid_phone"
        />
      </UserInteractionContext.Provider>
    </CaptchaContext.Provider>
  );

  return { ...view, setVerificationId, widgetRef };
};

describe('<VerificationCodeMfaBinding /> phone CAPTCHA', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it.each(providerConfigs)(
    'retries %s phone binding with a fresh token and the expected widget target',
    async (_name, captchaConfig, needsWidget) => {
      const executeCaptcha = jest.fn().mockResolvedValue('fresh-captcha-token');
      jest
        .mocked(sendVerificationCode)
        .mockRejectedValueOnce(captchaRequiredError())
        .mockResolvedValueOnce({ verificationId: 'verification-id' });
      const { getByText, setVerificationId, widgetRef } = renderBinding(
        captchaConfig,
        executeCaptcha
      );

      fireEvent.click(getByText('submit-identifier'));

      await waitFor(() => {
        expect(sendVerificationCode).toHaveBeenNthCalledWith(
          2,
          InteractionEvent.Register,
          { type: 'phone', value: 'test-phone' },
          'fresh-captcha-token'
        );
      });
      expect(executeCaptcha).toHaveBeenCalledWith('phone');
      expect(setVerificationId).toHaveBeenCalledTimes(1);
      expect(widgetRef.current instanceof HTMLDivElement).toBe(needsWidget);
    }
  );

  it('uses the server-owned social skip without showing another CAPTCHA', async () => {
    const executeCaptcha = jest.fn();
    jest.mocked(sendVerificationCode).mockResolvedValueOnce({ verificationId: 'verification-id' });
    const { getByText } = renderBinding(providerConfigs[0]![1], executeCaptcha);

    fireEvent.click(getByText('submit-identifier'));

    await waitFor(() => {
      expect(sendVerificationCode).toHaveBeenCalledTimes(1);
    });
    expect(executeCaptcha).not.toHaveBeenCalled();
  });

  it('keeps the binding form recoverable when the CAPTCHA is cancelled', async () => {
    const executeCaptcha = jest
      .fn()
      .mockRejectedValue(new CaptchaExecutionError(CaptchaExecutionErrorCode.UserClosed));
    jest.mocked(sendVerificationCode).mockRejectedValueOnce(captchaRequiredError());
    const { getByText, setVerificationId } = renderBinding(providerConfigs[0]![1], executeCaptcha);

    const submit = getByText('submit-identifier');
    fireEvent.click(submit);

    await waitFor(() => {
      expect(executeCaptcha).toHaveBeenCalledWith('phone');
    });
    expect(sendVerificationCode).toHaveBeenCalledTimes(1);
    expect(setVerificationId).not.toHaveBeenCalled();
    expect(getByText('submit-identifier')).toBe(submit);
  });
});
