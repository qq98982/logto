import { CaptchaPolicyScope, CaptchaType, type CaptchaProvider } from '@logto/schemas';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type * as React from 'react';
import { useSWRConfig } from 'swr';

import useApi from '@/hooks/use-api';

import CaptchaForm from './CaptchaForm';

const mockPatch = jest.fn();
const mockMutateGlobal = jest.fn();

jest.mock('react-hot-toast', () => ({ toast: { success: jest.fn() } }));
jest.mock('swr', () => ({ useSWRConfig: jest.fn() }));
jest.mock('@/hooks/use-api', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('@/hooks/use-paywall', () => ({
  __esModule: true,
  default: () => ({ isFreeTenant: false }),
}));
jest.mock('@/consts/env', () => ({ isCloud: true }));
jest.mock('@/utils/form', () => ({
  trySubmitSafe:
    (callback: (...args: unknown[]) => Promise<void>) =>
    async (...args: unknown[]) =>
      callback(...args),
}));
jest.mock('@/contexts/SubscriptionDataProvider', () => {
  const { createContext } = jest.requireActual<typeof React>('react');
  return {
    SubscriptionDataContext: createContext({ mutateSubscriptionQuotaAndUsages: jest.fn() }),
  };
});
jest.mock('@/components/DetailsForm', () => ({
  __esModule: true,
  default: ({
    children,
    onSubmit,
  }: {
    readonly children: React.ReactNode;
    readonly onSubmit: () => void;
  }) => (
    <form>
      {children}
      <button type="button" onClick={onSubmit}>
        save
      </button>
    </form>
  ),
}));
jest.mock('@/components/FormCard', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <section>{children}</section>,
}));
jest.mock('@/components/FeatureTag', () => ({
  CombinedAddOnAndFeatureTag: () => null,
  addOnLabels: { addOnBundle: 'bundle' },
}));
jest.mock('@/ds-components/Button', () => ({
  __esModule: true,
  default: ({ title }: { readonly title: string }) => <button type="button">{title}</button>,
}));
jest.mock('@/ds-components/FormField', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <div>{children}</div>,
}));
jest.mock('@/components/UnsavedChangesAlertModal', () => ({
  __esModule: true,
  default: () => null,
}));
jest.mock('./CaptchaCard', () => ({ __esModule: true, default: () => null }));
jest.mock('./CreateCaptchaForm', () => ({ __esModule: true, default: () => null }));

const mockedUseApi = jest.mocked(useApi);
const mockedUseSWRConfig = jest.mocked(useSWRConfig);
const captchaProvider: CaptchaProvider = {
  id: 'captcha-provider-id',
  tenantId: 'tenant-id',
  config: {
    type: CaptchaType.Turnstile,
    siteKey: 'site-key',
    secretKey: 'secret-key',
  },
  createdAt: 1,
  updatedAt: 1,
};

describe('CaptchaForm policy scope', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPatch.mockReturnValue({
      json: async () => ({
        captchaPolicy: { enabled: true, scope: CaptchaPolicyScope.Interaction },
      }),
    });
    mockedUseApi.mockReturnValue({ patch: mockPatch } as unknown as ReturnType<typeof useApi>);
    mockedUseSWRConfig.mockReturnValue({
      mutate: mockMutateGlobal,
    } as unknown as ReturnType<typeof useSWRConfig>);
  });

  it('defaults missing scope and sends the exact PATCH body', async () => {
    render(<CaptchaForm captchaProvider={captchaProvider} formData={{ enabled: true }} />);

    fireEvent.click(screen.getByText('save'));

    await waitFor(() => {
      expect(mockPatch).toHaveBeenCalledWith('api/sign-in-exp', {
        json: {
          captchaPolicy: {
            enabled: true,
            scope: CaptchaPolicyScope.Interaction,
          },
        },
      });
    });
  });

  it('retains the selected phone scope when CAPTCHA is toggled and saved', async () => {
    render(
      <CaptchaForm
        captchaProvider={captchaProvider}
        formData={{ enabled: false, scope: CaptchaPolicyScope.PhoneVerificationCode }}
      />
    );

    expect(
      screen
        .getByRole('radio', { name: /captcha_scope_phone_verification_code/i })
        .querySelector('input')?.checked
    ).toBe(true);
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByText('save'));

    await waitFor(() => {
      expect(mockPatch).toHaveBeenCalledWith('api/sign-in-exp', {
        json: {
          captchaPolicy: {
            enabled: true,
            scope: CaptchaPolicyScope.PhoneVerificationCode,
          },
        },
      });
    });
  });
});
