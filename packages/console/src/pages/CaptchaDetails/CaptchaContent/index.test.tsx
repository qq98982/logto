import { CaptchaType, type CaptchaProvider } from '@logto/schemas';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type * as React from 'react';

import useApi from '@/hooks/use-api';

import CaptchaContent from '.';

const mockPut = jest.fn();

jest.mock('react-hot-toast', () => ({ toast: { success: jest.fn() } }));
jest.mock('@/hooks/use-api', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('@/consts/env', () => ({ isCloud: true }));
jest.mock('@/utils/form', () => ({
  trySubmitSafe:
    (callback: (...args: unknown[]) => Promise<void>) =>
    async (...args: unknown[]) =>
      callback(...args),
}));
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
jest.mock('@/components/UnsavedChangesAlertModal', () => ({
  __esModule: true,
  default: () => null,
}));
jest.mock('@/ds-components/FormField', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <label>{children}</label>,
}));
jest.mock('@/ds-components/InlineNotification', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <div>{children}</div>,
}));

const mockedUseApi = jest.mocked(useApi);
const aliyunProvider: CaptchaProvider = {
  id: 'captcha-id',
  tenantId: 'tenant-id',
  config: {
    type: CaptchaType.Aliyun,
    region: 'cn',
    prefix: 'prefix',
    sceneId: 'scene-id',
    accessKeyId: 'access-key-id-value',
    accessKeySecret: 'access-key-secret-value',
  },
  createdAt: 1,
  updatedAt: 1,
};

describe('Alibaba CAPTCHA details', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPut.mockReturnValue({ json: async () => aliyunProvider });
    mockedUseApi.mockReturnValue({ put: mockPut } as unknown as ReturnType<typeof useApi>);
  });

  it('edits Alibaba configuration without leaking fields from other providers', async () => {
    render(
      <CaptchaContent isDeleted={false} captchaProvider={aliyunProvider} onUpdate={jest.fn()} />
    );

    expect(screen.getByPlaceholderText(/aliyun_access_key_secret/).getAttribute('type')).toBe(
      'password'
    );
    expect(document.body.textContent).not.toContain('access-key-secret-value');
    fireEvent.change(screen.getByPlaceholderText(/aliyun_prefix/), {
      target: { value: 'updated-prefix' },
    });
    fireEvent.click(screen.getByText('save'));

    await waitFor(() => {
      expect(mockPut).toHaveBeenCalledWith('api/captcha-provider', {
        json: {
          config: {
            type: CaptchaType.Aliyun,
            region: 'cn',
            prefix: 'updated-prefix',
            sceneId: 'scene-id',
            accessKeyId: 'access-key-id-value',
            accessKeySecret: 'access-key-secret-value',
          },
        },
      });
    });
  });
});
