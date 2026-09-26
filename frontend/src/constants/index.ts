export const FRAMEWORKS = ["CIS", "NIST", "STIG", "ISO27001"] as const;
export const FRAMEWORK_LABELS: Record<string, string> = {
  CIS: "CIS Benchmarks",
  NIST: "NIST SP 800-53",
  STIG: "DISA STIG",
  ISO27001: "ISO/IEC 27001",
};
export const REPORT_SECTIONS = [
  "EXECUTIVE_SUMMARY",
  "DEVICE",
  "COMPLIANCE",
  "CVE",
  "PQC",
  "SECURITY",
  "REMEDIATION",
  "EVIDENCE",
];
export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
