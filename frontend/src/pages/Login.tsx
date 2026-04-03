import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMsal, useIsAuthenticated } from '@azure/msal-react';
import { Lock } from 'lucide-react';
import { loginRequest } from '../auth/msalConfig';

export default function Login() {
  const { instance } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleLogin = async () => {
    try {
      await instance.loginRedirect(loginRequest);
    } catch (err) {
      console.error('Login error:', err);
      alert('Authentication is not configured. Contact your administrator.');
    }
  };

  return (
    <>
      <header className="navbar">
        <a href="/login" className="logo">
          <img src="/favicon.svg" alt="PureSecure" className="logo-favicon" />
          PureSecure <span>CWE Explorer</span>
        </a>
      </header>

      <div className="login-wrapper">
        <div className="login-card">
          <div className="logo-icon">
            <img src="/favicon.svg" alt="PureSecure" width="30" height="30" />
          </div>
          <h1>Welcome</h1>
          <p>Sign in with your Microsoft account to access the CWE weakness database.</p>
          <button className="btn-microsoft" onClick={handleLogin}>
            <svg width="20" height="20" viewBox="0 0 21 21" fill="none">
              <rect x="1" y="1" width="9" height="9" fill="#f25022" />
              <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
              <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
              <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
            </svg>
            Sign in with Microsoft
          </button>

          <div className="info-box info-note">
            <div className="box-label">How to sign in</div>
            <div className="box-text">
              Use your <strong>personal Microsoft account</strong> or{' '}
              <a href="https://signup.live.com" target="_blank" rel="noopener noreferrer">
                create one
              </a>{' '}
              to log in. Any Microsoft account (Outlook, Hotmail, Live) will work.
            </div>
          </div>

          <div className="login-footer">
            <Lock size={13} />
            Protected by Microsoft Entra ID
          </div>
        </div>
      </div>
    </>
  );
}
