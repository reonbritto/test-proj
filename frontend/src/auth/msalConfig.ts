import { Configuration, LogLevel } from '@azure/msal-browser';

export const loginRequest = {
  scopes: ['openid', 'profile', 'User.Read'],
};

export async function fetchMsalConfig(): Promise<Configuration | null> {
  try {
    const resp = await fetch('/api/config');
    const cfg = await resp.json();

    if (!cfg.client_id || !cfg.tenant_id) {
      console.warn('Entra ID not configured — auth disabled.');
      return null;
    }

    return {
      auth: {
        clientId: cfg.client_id,
        authority: 'https://login.microsoftonline.com/common',
        redirectUri: window.location.origin,
      },
      cache: {
        cacheLocation: 'localStorage',
      },
      system: {
        loggerOptions: {
          loggerCallback: (_level: LogLevel, message: string) => {
            if (import.meta.env.DEV) {
              console.debug(message);
            }
          },
          logLevel: LogLevel.Warning,
        },
      },
    };
  } catch (err) {
    console.error('Failed to fetch MSAL config:', err);
    return null;
  }
}
