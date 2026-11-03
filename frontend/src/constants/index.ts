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

/** Plain-language explanations shown by <Hint term="..."/> next to jargon. */
export const GLOSSARY: Record<string, string> = {
  CVE: "A publicly catalogued software vulnerability (Common Vulnerabilities and Exposures). We match your device's software version against known CVEs.",
  PQC: "Post-quantum cryptography. Checks whether the device's encryption (keys, ciphers, VPNs) would still hold up against future quantum computers.",
  CBOM: "Cryptographic Bill of Materials: an inventory of every algorithm, key size and protocol the device uses.",
  STIG: "Security Technical Implementation Guide: hardening rules published by the US DoD (DISA) for specific device types.",
  CIS: "Center for Internet Security benchmarks: widely used step-by-step hardening checklists.",
  NIST: "NIST SP 800-53: a US government catalogue of security and privacy controls.",
  ISO27001: "ISO/IEC 27001: the international standard for information security management.",
  drift: "A difference between a device's current configuration and the last audited one. Drift usually means an unreviewed change.",
  "risk acceptance": "A recorded decision to knowingly keep a failing control, with an owner, a reason and an expiry date, so it stops raising alarms until it expires.",
  compliance: "How many of the checked controls the configuration passes, as a percentage.",
  finding: "One issue the audit found: a failed control, a CVE, a weak cipher or a risky setting.",
  remediation: "The exact device commands that fix a finding. Review before applying.",
  vendor: "The device manufacturer (Cisco, Juniper, Fortinet...). Detected automatically from the file.",
  audit: "One run of all checks against one configuration file.",
};
