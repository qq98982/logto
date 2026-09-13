import { CaptchaType } from '@logto/schemas';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type * as React from 'react';

import useApi from '@/hooks/use-api';
import useTenantPathname from '@/hooks/use-tenant-pathname';

import useDataFetch from '../use-data-fetch';

import Guide from '.';

const mockPut = jest.fn();
const mockMutate = jest.fn();
const mockNavigate = jest.fn();

jest.mock('react-modal', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <div>{children}</div>,
}));
jest.mock('react-hot-toast', () => ({ toast: { success: jest.fn() } }));
jest.mock('@/scss/modal.module.scss', () => ({}));
jest.mock('@/hooks/use-api', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('@/hooks/use-tenant-pathname', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('../use-data-fetch', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('@/utils/form', () => ({
  trySubmitSafe:
    (callback: (...args: unknown[]) => Promise<void>) =>
    async (...args: unknown[]) =>
      callback(...args),
}));
jest.mock('@/components/Markdown', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <div>{children}</div>,
}));
jest.mock('@/ds-components/OverlayScrollbar', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <div>{children}</div>,
}));
jest.mock('@/ds-components/CardTitle', () => ({ __esModule: true, default: () => null }));
jest.mock('@/ds-components/IconButton', () => ({ __esModule: true, default: () => null }));
jest.mock('@/ds-components/FormField', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <label>{children}</label>,
}));
jest.mock('@/ds-components/InlineNotification', () => ({
  __esModule: true,
  default: ({ children }: { readonly children: React.ReactNode }) => <div>{children}</div>,
}));
jest.mock('@/ds-components/Button', () => ({
  __esModule: true,
  default: ({ title, htmlType }: { readonly title: string; readonly htmlType?: 'submit' }) => (
    <button type={htmlType ?? 'button'}>{title}</button>
  ),
}));

const mockedUseApi = jest.mocked(useApi);
const mockedUseTenantPathname = jest.mocked(useTenantPathname);
const mockedUseDataFetch = jest.mocked(useDataFetch);

describe('Alibaba CAPTCHA creation guide', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPut.mockReturnValue({
      json: async () => ({
        id: 'captcha-id',
        config: {
          type: CaptchaType.Aliyun,
          region: 'cn',
          prefix: 'prefix',
          sceneId: 'scene-id',
          accessKeyId: 'access-key-id-value',
          accessKeySecret: 'access-key-secret-value',
        },
      }),
    });
    mockedUseApi.mockReturnValue({ put: mockPut } as unknown as ReturnType<typeof useApi>);
    mockedUseTenantPathname.mockReturnValue({
      navigate: mockNavigate,
    } as unknown as ReturnType<typeof useTenantPathname>);
    mockedUseDataFetch.mockReturnValue({
      mutate: mockMutate,
    } as unknown as ReturnType<typeof useDataFetch>);
  });

  it('requires every Alibaba field and submits only the Alibaba config', async () => {
    render(<Guide type={CaptchaType.Aliyun} onClose={jest.fn()} />);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'connectors.save_and_done' }));
    });
    expect(mockPut).not.toHaveBeenCalled();

    const values = [
      ['aliyun_prefix', 'prefix'],
      ['aliyun_scene_id', 'scene-id'],
      ['aliyun_access_key_id', 'access-key-id-value'],
      ['aliyun_access_key_secret', 'access-key-secret-value'],
    ] as const;
    for (const [name, value] of values) {
      fireEvent.change(screen.getByPlaceholderText(new RegExp(name)), { target: { value } });
    }

    const secretInput = screen.getByPlaceholderText(/aliyun_access_key_secret/);
    expect(secretInput.getAttribute('type')).toBe('password');
    expect(document.body.textContent).not.toContain('access-key-secret-value');

    fireEvent.click(screen.getByRole('button', { name: 'connectors.save_and_done' }));

    await waitFor(() => {
      expect(mockPut).toHaveBeenCalledWith('api/captcha-provider', {
        json: {
          config: {
            type: CaptchaType.Aliyun,
            region: 'cn',
            prefix: 'prefix',
            sceneId: 'scene-id',
            accessKeyId: 'access-key-id-value',
            accessKeySecret: 'access-key-secret-value',
          },
        },
      });
    });
  });
});
