import { defaultTenantId } from '@logto/schemas';
import type { ReactNode } from 'react';
import { createContext } from 'react';

import { type TenantResponse } from '@/cloud/types/router';
import { defaultTenantResponse } from '@/consts';

/**
 * The reserved routes that require authentication. Note they may not require the user to be in a
 * tenant context.
 */
export enum GlobalRoute {
  Profile = '/profile',
}

/** @see {@link TenantsProvider} for why `useSWR()` is not applicable for this context. */
type Tenants = {
  tenants: readonly TenantResponse[];
  /** Indicates if the tenants data is ready for the first render. */
  isInitComplete: boolean;
  /**
   * The current tenant ID parsed from the URL.
   *
   * - If it's a non-cloud deployment, it will always be `default`.
   * - For cloud deployment, if it's `''`, the user is not in a tenant context (e.g. in onboarding
   * routes).
   */
  currentTenantId: string;
  currentTenant?: TenantResponse;
  /** Indicates if the current tenant is a development tenant. */
  isDevTenant: boolean;
};

const initialTenants = Object.freeze([defaultTenantResponse]);

export const TenantsContext = createContext<Tenants>({
  tenants: initialTenants,
  isInitComplete: true,
  currentTenantId: defaultTenantId,
  currentTenant: defaultTenantResponse,
  isDevTenant: true,
});

const selfHostedTenantContext: Tenants = Object.freeze({
  tenants: initialTenants,
  isInitComplete: true,
  currentTenantId: defaultTenantId,
  currentTenant: defaultTenantResponse,
  isDevTenant: true,
});

type Props = {
  readonly children: ReactNode;
};

/**
 * The global tenants context provider for all available tenants of the current users.
 * It is used to manage the tenants information, including create, update, and delete;
 * also for navigating between tenants.
 *
 * Note it is not practical to use `useSWR()` for tenants context, since fetching tenants
 * requires authentication, and the authentication is managed by the `LogtoProvider` which
 * depends and locates inside the `TenantsProvider`. Thus the fetching tenants action should
 * be done by a component inside the `LogtoProvider`, which `useSWR()` cannot handle.
 */
function TenantsProvider({ children }: Props) {
  return (
    <TenantsContext.Provider value={selfHostedTenantContext}>{children}</TenantsContext.Provider>
  );
}

export default TenantsProvider;
