import { Suspense, lazy, useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AppLayout from "./components/layout/AppLayout";
import { useAuth } from "./stores/auth";
import { useUi } from "./stores/ui";
import { hasRole } from "./utils/roles";
import { Loader } from "./components/common";

const GetStarted = lazy(() => import("./pages/GetStarted"));
const QuickAudit = lazy(() => import("./pages/QuickAudit"));
const Login = lazy(() => import("./pages/Login"));
const SsoComplete = lazy(() => import("./pages/SsoComplete"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Assets = lazy(() => import("./pages/Assets"));
const AssetDetails = lazy(() => import("./pages/AssetDetails"));
const UploadConfiguration = lazy(() => import("./pages/UploadConfiguration"));
const ConfigurationDetails = lazy(() => import("./pages/ConfigurationDetails"));
const Audits = lazy(() => import("./pages/Audits"));
const AuditDetails = lazy(() => import("./pages/AuditDetails"));
const AuditResults = lazy(() => import("./pages/AuditResults"));
const Compliance = lazy(() => import("./pages/Compliance"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const VulnerabilityDetails = lazy(() => import("./pages/VulnerabilityDetails"));
const PQC = lazy(() => import("./pages/PQC"));
const SecurityAnalytics = lazy(() => import("./pages/SecurityAnalytics"));
const Findings = lazy(() => import("./pages/Findings"));
const FindingDetails = lazy(() => import("./pages/FindingDetails"));
const Training = lazy(() => import("./pages/Training"));
const Remediation = lazy(() => import("./pages/Remediation"));
const Reports = lazy(() => import("./pages/Reports"));
const Settings = lazy(() => import("./pages/Settings"));
const Admin = lazy(() => import("./pages/Admin"));
const Jobs = lazy(() => import("./pages/Jobs"));
const Schedules = lazy(() => import("./pages/Schedules"));
const Exceptions = lazy(() => import("./pages/Exceptions"));
const CloudSecurity = lazy(() => import("./pages/CloudSecurity"));
const Integrations = lazy(() => import("./pages/Integrations"));
const ChangePassword = lazy(() => import("./pages/ChangePassword"));

const qc = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 60_000, refetchOnWindowFocus: false } },
});

function Guard({ children }: { children: React.ReactNode }) {
  const { token, ready, user } = useAuth();
  const loc = useLocation();
  if (!ready) return <div className="p-6"><Loader label="Restoring session…" /></div>;
  if (!token) return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
  // A user created/reset by an admin must choose their own password before using the app.
  if (user?.must_change_password && loc.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }
  return <>{children}</>;
}

function AdminOnly({ children }: { children: React.ReactNode }) {
  const user = useAuth((s) => s.user);
  return hasRole(user?.role, "ADMIN") ? <>{children}</> : <Navigate to="/dashboard" replace />;
}

function Boot() {
  const b = useAuth((s) => s.bootstrap);
  const initTheme = useUi((s) => s.initTheme);
  useEffect(() => { void b(); initTheme(); }, [b, initTheme]);
  return null;
}

function LoginRoute() {
  const { token, ready } = useAuth();
  const nav = useNavigate();
  useEffect(() => {
    if (ready && token) nav("/dashboard", { replace: true });
  }, [ready, token, nav]);
  return <Login />;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Boot />
        <Routes>
          <Route path="/sso/complete" element={<Suspense fallback={null}><SsoComplete /></Suspense>} />
          <Route path="/login" element={<Suspense fallback={null}><LoginRoute /></Suspense>} />
          <Route path="/change-password" element={<Guard><Suspense fallback={<Loader />}><ChangePassword /></Suspense></Guard>} />
          <Route element={<Guard><AppLayout /></Guard>}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/get-started" element={<GetStarted />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/quick-audit" element={<QuickAudit />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/assets/:assetId" element={<AssetDetails />} />
            <Route path="/configurations/upload" element={<UploadConfiguration />} />
            <Route path="/configurations/:configurationId" element={<ConfigurationDetails />} />
            <Route path="/audits" element={<Audits />} />
            <Route path="/audits/:auditId" element={<AuditDetails />} />
            <Route path="/audits/:auditId/results" element={<AuditResults />} />
            <Route path="/audits/:auditId/compliance" element={<Compliance />} />
            <Route path="/audits/:auditId/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/audits/:auditId/pqc" element={<PQC />} />
            <Route path="/audits/:auditId/analytics" element={<SecurityAnalytics />} />
            <Route path="/audits/:auditId/findings" element={<Findings />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/audits/:auditId/vulnerabilities/:findingId" element={<VulnerabilityDetails />} />
            <Route path="/vulnerabilities/:findingId" element={<VulnerabilityDetails />} />
            <Route path="/pqc" element={<PQC />} />
            <Route path="/analytics" element={<SecurityAnalytics />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:findingId" element={<FindingDetails />} />
            <Route path="/training" element={<Training />} />
            <Route path="/remediation" element={<Remediation />} />
            <Route path="/remediation/:findingId" element={<Remediation />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/schedules" element={<Schedules />} />
            <Route path="/exceptions" element={<Exceptions />} />
            <Route path="/cloud" element={<CloudSecurity />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/admin" element={<AdminOnly><Admin /></AdminOnly>} />
            <Route path="/integrations" element={<AdminOnly><Integrations /></AdminOnly>} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
