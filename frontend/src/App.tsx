import { useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AppLayout from "./components/layout/AppLayout";
import { useAuth } from "./stores/auth";
import { useUi } from "./stores/ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import AssetDetails from "./pages/AssetDetails";
import UploadConfiguration from "./pages/UploadConfiguration";
import ConfigurationDetails from "./pages/ConfigurationDetails";
import Audits from "./pages/Audits";
import AuditDetails from "./pages/AuditDetails";
import AuditResults from "./pages/AuditResults";
import Compliance from "./pages/Compliance";
import Vulnerabilities from "./pages/Vulnerabilities";
import VulnerabilityDetails from "./pages/VulnerabilityDetails";
import PQC from "./pages/PQC";
import SecurityAnalytics from "./pages/SecurityAnalytics";
import Findings from "./pages/Findings";
import FindingDetails from "./pages/FindingDetails";
import Training from "./pages/Training";
import Remediation from "./pages/Remediation";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import { Loader } from "./components/common";

const qc = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 15000, refetchOnWindowFocus: false } },
});

function Guard({ children }: { children: React.ReactNode }) {
  const { token, ready } = useAuth();
  const loc = useLocation();
  if (!ready) return <div className="p-6"><Loader label="Restoring session…" /></div>;
  if (!token) return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
  return <>{children}</>;
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
          <Route path="/login" element={<LoginRoute />} />
          <Route element={<Guard><AppLayout /></Guard>}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
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
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
