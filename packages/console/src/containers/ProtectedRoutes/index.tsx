import { useLogto } from '@logto/react';
import { conditional, yes } from '@silverhand/essentials';
import { useEffect } from 'react';
import { Outlet, useSearchParams } from 'react-router-dom';

import AppLoading from '@/components/AppLoading';
import { searchKeys } from '@/consts';
import useRedirectUri from '@/hooks/use-redirect-uri';
import { saveRedirect } from '@/utils/storage';

/**
 * The container for all protected routes. It renders `<AppLoading />` when the user is not
 * authenticated or the user is authenticated but the tenant is not initialized.
 *
 * That is, when it renders `<Outlet />`, you can expect:
 *
 * - `isAuthenticated` from `useLogto()` to be `true`.
 * - `isInitComplete` from `TenantsContext` to be `true`.
 *
 * Usage:
 *
 * ```tsx
 * <Route element={<ProtectedRoutes />}>
 *  <Route path="some-path" element={<SomeContent />} />
 * </Route>
 * ```
 *
 * Note that the `ProtectedRoutes` component should be put in a {@link https://reactrouter.com/en/main/start/concepts#pathless-routes | pathless route}.
 */
export default function ProtectedRoutes() {
  const [searchParameters] = useSearchParams();
  const { isAuthenticated, isLoading, signIn } = useLogto();
  const redirectUri = useRedirectUri();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      saveRedirect();
      const isSignUpMode = yes(searchParameters.get(searchKeys.signUp));
      void signIn(redirectUri.href, conditional(isSignUpMode && 'signUp'));
    }
  }, [redirectUri, isAuthenticated, isLoading, searchParameters, signIn]);

  if (!isAuthenticated) {
    return <AppLoading />;
  }

  return <Outlet />;
}
