import { ReactNode, useEffect, useState } from 'react';
import {
  PublicClientApplication,
  EventType,
  EventMessage,
  AuthenticationResult,
} from '@azure/msal-browser';
import { MsalProvider } from '@azure/msal-react';
import { fetchMsalConfig } from './msalConfig';

interface AuthProviderProps {
  children: ReactNode;
}

export default function AuthProvider({ children }: AuthProviderProps) {
  const [msalInstance, setMsalInstance] = useState<PublicClientApplication | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      const config = await fetchMsalConfig();
      if (cancelled) return;

      if (!config) {
        setError('Authentication is not configured. Contact your administrator.');
        setLoading(false);
        return;
      }

      const instance = new PublicClientApplication(config);
      await instance.initialize();

      // Handle redirect promise
      const response = await instance.handleRedirectPromise();
      if (response) {
        instance.setActiveAccount(response.account);
      } else {
        const accounts = instance.getAllAccounts();
        if (accounts.length > 0) {
          instance.setActiveAccount(accounts[0]);
        }
      }

      // Listen for login events
      instance.addEventCallback((event: EventMessage) => {
        if (event.eventType === EventType.LOGIN_SUCCESS && event.payload) {
          const result = event.payload as AuthenticationResult;
          instance.setActiveAccount(result.account);
        }
      });

      if (!cancelled) {
        setMsalInstance(instance);
        setLoading(false);
      }
    }

    init();

    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        <p>Initializing authentication...</p>
      </div>
    );
  }

  if (error || !msalInstance) {
    return (
      <div className="loading">
        <p>{error || 'Failed to initialize authentication.'}</p>
      </div>
    );
  }

  return <MsalProvider instance={msalInstance}>{children}</MsalProvider>;
}
