import { useLogto } from '@logto/react';
import { useEffect } from 'react';

/**
 * Keep children unchanged, but throw errors reported by the upstream SDK
 * (`useLogto()`). The error should be handled by the upper `<ErrorBoundary />`.
 */
export default function AuthSdkErrorBoundary({ children }: { children: JSX.Element }) {
  const { error } = useLogto();

  useEffect(() => {
    if (error) {
      throw error;
    }
  }, [error]);

  return children;
}
