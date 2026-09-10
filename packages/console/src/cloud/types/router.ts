import type router from '@logto/cloud/routes';
import { type GuardedResponse, type RouterRoutes } from '@withtyped/client';

type GetRoutes = RouterRoutes<typeof router>['get'];

export type GetArrayElementType<T> = T extends Array<infer U> ? U : never;

export type Subscription = GuardedResponse<GetRoutes['/api/tenants/:tenantId/subscription']>;

export type SystemLimit = GuardedResponse<GetRoutes['/api/tenants/my/subscription']>['systemLimit'];

type SubscriptionUsageResponse = GuardedResponse<
  GetRoutes['/api/tenants/:tenantId/subscription-usage']
>;

export type SubscriptionQuota = Omit<
  SubscriptionUsageResponse['quota'],
  // Drop once `@logto/cloud` no longer declares the legacy Actions quota key.
  | 'inlineHooksEnabled'
  // Since we are deprecating the `organizationsEnabled` key soon (use `organizationsLimit` instead), we exclude it from the quota keys for now to avoid confusion.
  | 'organizationsEnabled'
>;

export type SubscriptionSkuResponse = Omit<
  GetArrayElementType<GuardedResponse<GetRoutes['/api/skus']>>,
  'quota'
> & {
  // Drop the legacy key once `@logto/cloud` stops declaring it on SKU quotas.
  quota: Omit<
    GetArrayElementType<GuardedResponse<GetRoutes['/api/skus']>>['quota'],
    'inlineHooksEnabled'
  >;
};

export type SubscriptionCountBasedUsage = Omit<
  SubscriptionUsageResponse['usage'],
  // Drop once `@logto/cloud` no longer declares the legacy Actions quota key.
  | 'inlineHooksEnabled'
  // Since we are deprecating the `organizationsEnabled` key soon (use `organizationsLimit` instead), we exclude it from the usage keys for now to avoid confusion.
  | 'organizationsEnabled'
>;
export type SubscriptionResourceScopeUsage = SubscriptionUsageResponse['resources'];
export type SubscriptionRoleScopeUsage = Omit<
  SubscriptionUsageResponse['roles'],
  // Since we are deprecating the `organizationsEnabled` key soon (use `organizationsLimit` instead), we exclude it from the quota keys for now to avoid confusion.
  'organizationsEnabled'
>;

/** Type for the response of the `/api/tenants` endpoint. */
export type TenantResponse = GetArrayElementType<GuardedResponse<GetRoutes['/api/tenants']>>;
