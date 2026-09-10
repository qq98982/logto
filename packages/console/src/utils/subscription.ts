import { ReservedPlanId } from '@logto/schemas';
import { type Nullable } from '@silverhand/essentials';

export const isPaidPlan = (planId: string, isEnterprisePlan: boolean) =>
  isProPlan(planId) || isEnterprisePlan;

export const isFeatureEnabled = (quota: Nullable<number>): boolean => quota === null || quota > 0;

export const isProPlan = (planId: string) =>
  [ReservedPlanId.Pro, ReservedPlanId.Pro202411, ReservedPlanId.Pro202509].includes(
    // eslint-disable-next-line no-restricted-syntax -- Compare an external route value to its enum.
    planId as ReservedPlanId
  );
