import { ReactNode } from 'react';
import {
  useIsAuthenticated,
  useMsal,
  AuthenticatedTemplate,
  UnauthenticatedTemplate,
} from '@azure/msal-react';
import { Navigate } from 'react-router-dom';

interface RequireAuthProps {
  children: ReactNode;
}

export default function RequireAuth({ children }: RequireAuthProps) {
  const isAuthenticated = useIsAuthenticated();
  const { inProgress } = useMsal();

  if (inProgress !== 'none') {
    return (
      <div className="loading">
        <div className="spinner"></div>
        <p>Authenticating...</p>
      </div>
    );
  }

  return (
    <>
      <AuthenticatedTemplate>{children}</AuthenticatedTemplate>
      <UnauthenticatedTemplate>
        {!isAuthenticated && <Navigate to="/login" replace />}
      </UnauthenticatedTemplate>
    </>
  );
}
