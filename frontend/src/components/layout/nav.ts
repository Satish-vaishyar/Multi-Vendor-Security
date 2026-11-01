import {
  Activity, BrainCircuit, Bug, CalendarClock, ClipboardCheck, FileText, FileUp, KeyRound, LayoutDashboard,
  ListChecks, Plug, Rocket, Server, Settings as SettingsIcon, ShieldCheck, ShieldQuestion, TriangleAlert, UsersRound, Wrench,
  type LucideIcon,
} from "lucide-react";
import { hasRole, type Role } from "../../utils/roles";

export interface NavItem {
  to: string;
  label: string;
  /** one plain-language line: shown in the command palette and as a tooltip */
  desc: string;
  icon: LucideIcon;
  /** minimum role that can use the page (hidden below it) */
  min?: Role;
  /** extra words the palette should match */
  keywords?: string;
}

export interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "start",
    label: "Start",
    items: [
      { to: "/get-started", label: "Get started", desc: "A 5-step checklist from first upload to first report", icon: Rocket, keywords: "help onboarding tutorial checklist" },
      { to: "/dashboard", label: "Dashboard", desc: "Fleet-wide security overview", icon: LayoutDashboard, keywords: "overview summary home" },
    ],
  },
  {
    id: "audit",
    label: "Audit",
    items: [
      { to: "/assets", label: "Devices", desc: "Routers, firewalls and switches under audit", icon: Server, keywords: "assets inventory" },
      { to: "/quick-audit", label: "Upload & audit", desc: "Drop a config file and get results in one step", icon: FileUp, min: "AUDITOR", keywords: "upload configuration run new audit quick" },
      { to: "/audits", label: "Audit results", desc: "Every audit run and its outcome", icon: ClipboardCheck, keywords: "audits history" },
    ],
  },
  {
    id: "findings",
    label: "Findings",
    items: [
      { to: "/findings", label: "Findings", desc: "Everything the audits found, in one list", icon: TriangleAlert, keywords: "issues problems" },
      { to: "/vulnerabilities", label: "Vulnerabilities", desc: "Known CVEs that affect your devices", icon: Bug, keywords: "cve" },
      { to: "/pqc", label: "Post-quantum", desc: "Is your encryption ready for quantum computers?", icon: KeyRound, keywords: "pqc crypto cbom quantum" },
      { to: "/analytics", label: "Security analytics", desc: "Attack paths, risky settings and exposure", icon: Activity, keywords: "risk analytics" },
      { to: "/compliance", label: "Compliance", desc: "Scores against CIS, NIST, STIG and ISO 27001", icon: ShieldCheck, keywords: "cis nist stig iso framework" },
    ],
  },
  {
    id: "fix",
    label: "Fix & report",
    items: [
      { to: "/remediation", label: "Remediation", desc: "Device commands that fix each finding", icon: Wrench, keywords: "fix commands" },
      { to: "/reports", label: "Reports", desc: "Export PDF, CSV and evidence packs", icon: FileText, keywords: "export pdf download" },
      { to: "/exceptions", label: "Risk acceptance", desc: "Knowingly accept a finding, with an expiry date", icon: ShieldQuestion, keywords: "exceptions waiver" },
    ],
  },
  {
    id: "automate",
    label: "Automate",
    items: [
      { to: "/schedules", label: "Recurring audits", desc: "Re-audit devices on a schedule", icon: CalendarClock, keywords: "schedule cron drift" },
      { to: "/jobs", label: "Background jobs", desc: "Long-running work and its progress", icon: ListChecks, keywords: "queue tasks" },
      { to: "/integrations", label: "Integrations", desc: "Send events to other tools via webhooks", icon: Plug, min: "ADMIN", keywords: "webhook siem" },
    ],
  },
  {
    id: "admin",
    label: "Admin",
    items: [
      { to: "/training", label: "AI training", desc: "Review what the AI learned from unknown config lines", icon: BrainCircuit, keywords: "ai ml mappings review" },
      { to: "/admin", label: "Administration", desc: "Users, roles and the audit log", icon: UsersRound, min: "ADMIN", keywords: "users audit log" },
      { to: "/settings", label: "Settings", desc: "Your account, appearance and security", icon: SettingsIcon, keywords: "profile mfa password theme" },
    ],
  },
];

/** Groups filtered to what this role may use (empty groups dropped). */
export function visibleGroups(role: string | undefined | null): NavGroup[] {
  return NAV_GROUPS
    .map((g) => ({ ...g, items: g.items.filter((i) => !i.min || hasRole(role, i.min)) }))
    .filter((g) => g.items.length > 0);
}

/** Pages that are not in the menu but still need a title/breadcrumb. */
const EXTRA: { test: RegExp; group: string; parent?: { label: string; to: string }; label: string }[] = [
  { test: /^\/assets\/[^/]+$/, group: "Audit", parent: { label: "Devices", to: "/assets" }, label: "Device details" },
  { test: /^\/configurations\/upload$/, group: "Audit", parent: { label: "Upload & audit", to: "/quick-audit" }, label: "Advanced upload" },
  { test: /^\/configurations\/[^/]+$/, group: "Audit", parent: { label: "Devices", to: "/assets" }, label: "Configuration" },
  { test: /^\/audits\/[^/]+$/, group: "Audit", parent: { label: "Audit results", to: "/audits" }, label: "Audit progress" },
  { test: /^\/audits\/[^/]+\/results$/, group: "Audit", parent: { label: "Audit results", to: "/audits" }, label: "Results" },
  { test: /^\/audits\/[^/]+\/compliance$/, group: "Findings", parent: { label: "Compliance", to: "/compliance" }, label: "Audit compliance" },
  { test: /^\/audits\/[^/]+\/vulnerabilities(\/.*)?$/, group: "Findings", parent: { label: "Vulnerabilities", to: "/vulnerabilities" }, label: "Vulnerability" },
  { test: /^\/audits\/[^/]+\/pqc$/, group: "Findings", parent: { label: "Post-quantum", to: "/pqc" }, label: "Audit post-quantum" },
  { test: /^\/audits\/[^/]+\/analytics$/, group: "Findings", parent: { label: "Security analytics", to: "/analytics" }, label: "Audit analytics" },
  { test: /^\/audits\/[^/]+\/findings$/, group: "Findings", parent: { label: "Findings", to: "/findings" }, label: "Audit findings" },
  { test: /^\/vulnerabilities\/[^/]+$/, group: "Findings", parent: { label: "Vulnerabilities", to: "/vulnerabilities" }, label: "Vulnerability" },
  { test: /^\/findings\/[^/]+$/, group: "Findings", parent: { label: "Findings", to: "/findings" }, label: "Finding details" },
  { test: /^\/remediation\/[^/]+$/, group: "Fix & report", parent: { label: "Remediation", to: "/remediation" }, label: "Fix commands" },
  { test: /^\/change-password$/, group: "Admin", label: "Change password" },
];

export interface Crumb { label: string; to?: string }

/** Breadcrumb trail for a path: Group > (Parent >) Page. */
export function crumbsFor(path: string): Crumb[] {
  for (const g of NAV_GROUPS) {
    const hit = g.items.find((i) => i.to === path);
    if (hit) return [{ label: g.label }, { label: hit.label }];
  }
  const x = EXTRA.find((e) => e.test.test(path));
  if (x) {
    const trail: Crumb[] = [{ label: x.group }];
    if (x.parent) trail.push({ label: x.parent.label, to: x.parent.to });
    trail.push({ label: x.label });
    return trail;
  }
  return [];
}
