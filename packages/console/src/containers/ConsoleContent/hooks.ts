import { useLogto } from '@logto/react';
import { getTenantOrganizationId } from '@logto/schemas';
import { useContext, useEffect } from 'react';

import { TenantsContext } from '@/contexts/TenantsProvider';

/** Ensures the authenticated default-tenant Console has one current organization token. */
const useTenantScopeListener = () => {
  const { currentTenantId } = useContext(TenantsContext);
  const { getOrganizationTokenClaims, isAuthenticated } = useLogto();

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    void getOrganizationTokenClaims(getTenantOrganizationId(currentTenantId));
  }, [currentTenantId, getOrganizationTokenClaims, isAuthenticated]);
};

export default useTenantScopeListener;
