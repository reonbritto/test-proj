import { IPublicClientApplication } from '@azure/msal-browser';
import { loginRequest } from '../auth/msalConfig';

let msalInstanceRef: IPublicClientApplication | null = null;

export function setMsalInstance(instance: IPublicClientApplication) {
  msalInstanceRef = instance;
}

/**
 * Get an ID token from MSAL silently, or redirect to login.
 */
async function getToken(): Promise<string | null> {
  if (!msalInstanceRef) return null;

  const accounts = msalInstanceRef.getAllAccounts();
  if (accounts.length === 0) {
    msalInstanceRef.loginRedirect(loginRequest);
    return null;
  }

  msalInstanceRef.setActiveAccount(accounts[0]);

  try {
    const result = await msalInstanceRef.acquireTokenSilent({
      scopes: loginRequest.scopes,
      account: accounts[0],
    });
    return result.idToken;
  } catch {
    console.warn('Silent token failed, redirecting to login.');
    msalInstanceRef.loginRedirect(loginRequest);
    return null;
  }
}

/**
 * Authenticated fetch wrapper — attaches Bearer token.
 */
export async function fetchAPI<T = unknown>(url: string): Promise<T> {
  const token = await getToken();
  if (!token) {
    throw new Error('Authentication required');
  }

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('Session expired');
  }

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `API error: ${response.status}`);
  }

  return response.json();
}

/**
 * Load service links from /api/services.
 */
export async function fetchServiceLinks(): Promise<Record<string, string>> {
  try {
    const resp = await fetch('/api/services');
    return resp.json();
  } catch {
    return {};
  }
}
