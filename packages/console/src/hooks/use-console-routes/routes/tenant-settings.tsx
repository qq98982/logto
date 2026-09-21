import { useMemo } from 'react';
import { Navigate, type RouteObject } from 'react-router-dom';
import { safeLazy } from 'react-safe-lazy';

import { TenantSettingsTabs } from '@/consts';

const OssTenantSettings = safeLazy(async () => import('@/pages/OssTenantSettings'));
const OidcConfigs = safeLazy(async () => import('@/components/OidcConfigs'));

export const useTenantSettings = (): RouteObject =>
  useMemo(
    () => ({
      path: 'tenant-settings',
      element: <OssTenantSettings />,
      children: [
        {
          index: true,
          element: <Navigate replace to={TenantSettingsTabs.OidcConfigs} />,
        },
        {
          path: TenantSettingsTabs.OidcConfigs,
          element: <OidcConfigs />,
        },
      ],
    }),
    []
  );
