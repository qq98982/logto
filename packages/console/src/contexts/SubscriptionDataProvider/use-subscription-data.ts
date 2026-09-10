import { noop } from '@silverhand/essentials';

import {
  defaultSku,
  defaultTenantResponse,
  defaultSubscriptionQuota,
  defaultSubscriptionUsage,
} from '@/consts';

import { type SubscriptionContext } from './types';

const useSubscriptionData = (): SubscriptionContext & { isLoading: boolean } => ({
  isLoading: false,
  skus: [],
  currentSku: defaultSku,
  currentSubscription: defaultTenantResponse.subscription,
  onCurrentSubscriptionUpdated: noop,
  mutateSubscriptionQuotaAndUsages: noop,
  currentSubscriptionQuota: defaultSubscriptionQuota,
  currentSubscriptionBasicQuota: defaultSubscriptionQuota,
  currentSubscriptionUsage: defaultSubscriptionUsage,
  currentSubscriptionResourceScopeUsage: {},
  currentSubscriptionRoleScopeUsage: {},
});

export default useSubscriptionData;
