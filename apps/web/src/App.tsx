import { useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { loadPendingInvite } from './lib/orgs';
import { AcceptInvitePage } from './pages/AcceptInvitePage';
import { OrgAdminPage } from './pages/admin/OrgAdminPage';
import { SSO_LINK_KEY, useSession } from './lib/session';
import { api } from './lib/api';
import { errorMessage, toast } from './components/Toast';
import { SsoCallbackPage, SsoStartPage } from './pages/SsoPages';
import type { SsoOrg } from '@enclavier/shared';
import { useAutoLock } from './lib/useAutoLock';
import { Layout } from './components/Layout';
import { Toaster } from './components/Toast';
import { LockPage, LoginPage, RegisterPage } from './pages/AuthPages';
import { VaultPage } from './pages/VaultPage';
import { GeneratorPage } from './pages/GeneratorPage';
import { SettingsPage } from './pages/SettingsPage';
import { VerifyEmailPage } from './pages/AccountGuards';
import { EmergencyAcceptPage, EmergencyVaultPage } from './pages/EmergencyPages';
import { BreakGlassPage } from './pages/BreakGlassPage';
import { HealthPage } from './pages/HealthPage';

function AppRoutes() {
  const status = useSession((s) => s.status);
  const location = useLocation();
  const navigate = useNavigate();
  useAutoLock();

  // Resume an invitation accepted from the e-mail link before signing in.
  useEffect(() => {
    if (status === 'unlocked' && location.pathname !== '/accept-invite' && loadPendingInvite()) {
      navigate('/accept-invite', { replace: true });
    }
  }, [status, location.pathname, navigate]);

  // Finish linking an existing account to organization SSO once its owner has signed in.
  const profileEmail = useSession((s) => s.profile?.email);
  const rememberSso = useSession((s) => s.rememberSso);
  useEffect(() => {
    if (status !== 'unlocked') return;
    const pending = JSON.parse(sessionStorage.getItem(SSO_LINK_KEY) ?? 'null') as { linkToken: string; org: SsoOrg; email: string } | null;
    if (!pending) return;
    sessionStorage.removeItem(SSO_LINK_KEY);
    if (pending.email !== profileEmail) return;
    api('POST', '/api/sso/link', { linkToken: pending.linkToken }).then(
      () => {
        rememberSso(pending.org);
        toast(`Your account is now linked to ${pending.org.name} single sign-on`);
      },
      (e) => toast(errorMessage(e), 'error'),
    );
  }, [status, profileEmail, rememberSso]);

  // E-mail verification links work whether or not this browser is signed in.
  if (location.pathname === '/verify-email') return <VerifyEmailPage />;
  // The identity provider returns here in any state (signed out, or unlocking a locked vault).
  if (location.pathname === '/sso/callback') return <SsoCallbackPage />;
  if (location.pathname === '/sso' && status !== 'unlocked') return <SsoStartPage />;

  if (status === 'loggedOut') {
    return (
      <Routes>
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/accept-invite" element={<AcceptInvitePage />} />
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }
  if (status === 'locked') return <LockPage />;
  if (location.pathname === '/accept-invite') return <AcceptInvitePage />;

  return (
    <Layout>
      <Routes>
        <Route path="/vault" element={<VaultPage />} />
        <Route path="/generator" element={<GeneratorPage />} />
        <Route path="/health" element={<HealthPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/orgs/:orgId/*" element={<OrgAdminPage />} />
        <Route path="/emergency/accept" element={<EmergencyAcceptPage />} />
        <Route path="/emergency/:id" element={<EmergencyVaultPage />} />
        <Route path="/recover-org" element={<BreakGlassPage />} />
        <Route path="*" element={<Navigate to="/vault" replace />} />
      </Routes>
    </Layout>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
      <Toaster />
    </BrowserRouter>
  );
}
