import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useMsal } from '@azure/msal-react';
import { useEffect } from 'react';

import AuthProvider from './auth/AuthProvider';
import RequireAuth from './auth/RequireAuth';
import { setMsalInstance } from './utils/api';

import Navbar from './components/Navbar';
import Footer from './components/Footer';

import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Search from './pages/Search';
import CweDetail from './pages/CweDetail';
import CveDetail from './pages/CveDetail';
import AttackMatrix from './pages/AttackMatrix';
import NotFound from './pages/NotFound';

const queryClient = new QueryClient();

/**
 * Inner app — renders inside MsalProvider so useMsal() works.
 */
function AppRoutes() {
  const { instance } = useMsal();

  useEffect(() => {
    setMsalInstance(instance);
  }, [instance]);

  return (
    <Routes>
      {/* Public route — Login */}
      <Route path="/login" element={<Login />} />

      {/* Protected routes */}
      <Route
        path="/"
        element={
          <RequireAuth>
            <div className="app-layout">
              <Navbar />
              <Dashboard />
              <Footer />
            </div>
          </RequireAuth>
        }
      />
      <Route
        path="/search"
        element={
          <RequireAuth>
            <div className="app-layout">
              <Navbar />
              <Search />
              <Footer />
            </div>
          </RequireAuth>
        }
      />
      <Route
        path="/cwe/:id"
        element={
          <RequireAuth>
            <div className="app-layout">
              <Navbar />
              <CweDetail />
              <Footer />
            </div>
          </RequireAuth>
        }
      />
      <Route
        path="/cve/:id"
        element={
          <RequireAuth>
            <div className="app-layout">
              <Navbar />
              <CveDetail />
              <Footer />
            </div>
          </RequireAuth>
        }
      />
      <Route
        path="/attack"
        element={
          <RequireAuth>
            <div className="app-layout">
              <Navbar />
              <AttackMatrix />
              <Footer />
            </div>
          </RequireAuth>
        }
      />
      <Route
        path="*"
        element={
          <div className="app-layout">
            <Navbar />
            <NotFound />
            <Footer />
          </div>
        }
      />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
