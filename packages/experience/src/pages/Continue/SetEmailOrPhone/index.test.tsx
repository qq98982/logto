import {
  CaptchaType,
  InteractionEvent,
  MissingProfile,
  RecaptchaEnterpriseMode,
  SignInIdentifier,
} from '@logto/schemas';
import { assert } from '@silverhand/essentials';
import { fireEvent, waitFor } from '@testing-library/react';
import { createRef } from 'react';
import { act } from 'react-dom/test-utils';

import CaptchaContext from '@/Providers/CaptchaContextProvider/CaptchaContext';
import renderWithPageContext from '@/__mocks__/RenderWithPageContext';
import SettingsProvider from '@/__mocks__/RenderWithPageContext/SettingsProvider';
import { mockSignInExperienceSettings } from '@/__mocks__/logto';
import { sendVerificationCodeApi } from '@/apis/utils';
import { UserFlow, type SignInExperienceResponse, type VerificationCodeIdentifier } from '@/types';
import { getDefaultCountryCallingCode } from '@/utils/country-code';

import SetEmailOrPhone, { type VerificationCodeProfileType, pageContent } from '.';

const mockedNavigate = jest.fn();
const defaultPhoneSettings = {
  ...mockSignInExperienceSettings,
  customContent: {
    ...mockSignInExperienceSettings.customContent,
    boxAiDefaultPhoneCountry: 'US',
  },
};

// PhoneNum CountryCode detection
jest.mock('i18next', () => ({
  language: 'en',
  t: (key: string) => key,
}));

jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockedNavigate,
  useLocation: jest.fn(() => ({
    state: {
      flow: UserFlow.SignIn,
      registeredSocialIdentity: {
        email: 'foo@logto.io',
      },
    },
  })),
}));

jest.mock('@/apis/utils', () => ({
  sendVerificationCodeApi: jest.fn(),
}));

describe('continue with email or phone', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  const renderPage = (missingProfile: VerificationCodeProfileType) =>
    renderWithPageContext(
      <SettingsProvider settings={defaultPhoneSettings}>
        <SetEmailOrPhone
          missingProfile={missingProfile}
          interactionEvent={InteractionEvent.Register}
        />
      </SettingsProvider>
    );

  const cases: Array<[VerificationCodeProfileType, { title: string; description: string }]> = [
    [MissingProfile.email, pageContent.email],
    [MissingProfile.phone, pageContent.phone],
    [MissingProfile.emailOrPhone, pageContent.emailOrPhone],
  ];

  test.each(cases)('render set %p', (type, content) => {
    const { queryByText, container } = renderPage(type);

    expect(queryByText(content.title)).not.toBeNull();
    expect(queryByText(content.description)).not.toBeNull();
    expect(container.querySelector('input[name="identifier"]')).not.toBeNull();
    expect(queryByText('action.continue')).not.toBeNull();

    if (type === MissingProfile.email || type === MissingProfile.emailOrPhone) {
      expect(queryByText('description.social_identity_exist')).not.toBeNull();
    }
  });

  test.each([
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
      'Alibaba',
      { type: CaptchaType.Aliyun, region: 'cn', prefix: 'test-prefix', sceneId: 'test-scene' },
      false,
    ],
  ] satisfies Array<
    [
      name: string,
      captchaConfig: NonNullable<SignInExperienceResponse['captchaConfig']>,
      needsWidget: boolean,
    ]
  >)('mounts the expected %s CAPTCHA target', (_name, captchaConfig, needsWidget) => {
    const widgetRef = createRef<HTMLDivElement>();

    renderWithPageContext(
      <CaptchaContext.Provider
        value={{
          isCaptchaRequired: true,
          captchaConfig,
          widgetRef,
          executeCaptcha: jest.fn(),
        }}
      >
        <SettingsProvider settings={defaultPhoneSettings}>
          <SetEmailOrPhone
            missingProfile={MissingProfile.phone}
            interactionEvent={InteractionEvent.Register}
          />
        </SettingsProvider>
      </CaptchaContext.Provider>
    );

    expect(widgetRef.current instanceof HTMLDivElement).toBe(needsWidget);
  });

  const email = 'foo@logto.io';
  const phone = '8573333333';
  const countryCode = getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' });

  test.each([
    [MissingProfile.email, SignInIdentifier.Email, email],
    [MissingProfile.phone, SignInIdentifier.Phone, phone],
    [MissingProfile.emailOrPhone, SignInIdentifier.Email, email],
    [MissingProfile.emailOrPhone, SignInIdentifier.Phone, phone],
  ] satisfies Array<[VerificationCodeProfileType, VerificationCodeIdentifier, string]>)(
    'should send verification code properly',
    async (type, identifier, input) => {
      const { getByText, container } = renderPage(type);

      const inputField = container.querySelector('input[name="identifier"]');
      const submitButton = getByText('action.continue');

      assert(inputField, new Error('input field not found'));
      expect(submitButton).not.toBeNull();

      act(() => {
        fireEvent.change(inputField, { target: { value: input } });
      });

      act(() => {
        fireEvent.click(submitButton);
      });

      await waitFor(() => {
        expect(sendVerificationCodeApi).toBeCalledWith(
          UserFlow.Continue,
          {
            type: identifier,
            value: identifier === SignInIdentifier.Phone ? `${countryCode}${input}` : input,
          },
          InteractionEvent.Register,
          undefined
        );
      });
    }
  );
});
