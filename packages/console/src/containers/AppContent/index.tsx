import { conditional, joinPath } from '@silverhand/essentials';
import { useContext, useRef } from 'react';
import { Navigate, Outlet, useParams } from 'react-router-dom';

import AppLoading from '@/components/AppLoading';
import Topbar from '@/components/Topbar';
import SubscriptionDataProvider from '@/contexts/SubscriptionDataProvider';
import useSubscriptionData from '@/contexts/SubscriptionDataProvider/use-subscription-data';
import { TenantsContext } from '@/contexts/TenantsProvider';
import useScroll from '@/hooks/use-scroll';
import useUserPreferences from '@/hooks/use-user-preferences';

import { getPath } from '../ConsoleContent/Sidebar';
import { useSidebarMenuItems } from '../ConsoleContent/Sidebar/hook';

import styles from './index.module.scss';
import { type AppContentOutletContext } from './types';

export default function AppContent() {
  const { isLoading: isLoadingPreference } = useUserPreferences();
  const { currentTenant } = useContext(TenantsContext);

  const { isLoading: isLoadingSubscriptionData, ...subscriptionData } = useSubscriptionData();

  const scrollableContent = useRef<HTMLDivElement>(null);
  const { scrollTop } = useScroll(scrollableContent.current);

  const isLoading = isLoadingPreference || isLoadingSubscriptionData;

  if (isLoading || !currentTenant) {
    return <AppLoading />;
  }

  return (
    <SubscriptionDataProvider
      subscriptionDataAndUtils={{
        ...subscriptionData,
        hasSurpassedSubscriptionQuotaLimit: () => false,
        hasReachedSubscriptionQuotaLimit: () => false,
      }}
    >
      <div className={styles.app}>
        <Topbar className={conditional(scrollTop && styles.topbarShadow)} />
        <Outlet context={{ scrollableContent } satisfies AppContentOutletContext} />
      </div>
    </SubscriptionDataProvider>
  );
}

export function RedirectToFirstItem() {
  const { tenantId } = useParams();
  const { firstItem } = useSidebarMenuItems();

  if (!firstItem) {
    throw new Error('First sidebar item not found');
  }

  if (!tenantId) {
    throw new Error('Tenant ID not found');
  }

  return <Navigate replace to={joinPath(tenantId, getPath(firstItem.title))} />;
}
