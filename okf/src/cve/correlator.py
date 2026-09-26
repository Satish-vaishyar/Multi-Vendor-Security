"""CVE correlator → unified findings (cve_okf §10, §16-18, §24-26).

For each software component: candidates via VulnKB → version_range match →
VULNERABLE / NOT_AFFECTED / UNKNOWN (unknown when product/version unresolvable).
Findings use the unified Finding schema (engine=cve, type=VULNERABILITY).
"""
from __future__ import annotations
from typing import Any, Dict, List
from .kb import VulnKB
from .cpe_resolver import resolve, confidence, canonical
from .version_range import match_record


def correlate(components: List[Dict[str, Any]], asset_id: str = "ASSET-001",
              kb: VulnKB | None = None) -> Dict[str, Any]:
    kb = kb or VulnKB().load()
    matches: List[Dict[str, Any]] = []
    for comp in components:
        vendor, product, version = comp.get("vendor", ""), comp.get("product", ""), comp.get("version", "")
        conf = confidence(vendor, product, version)
        cpes = resolve(vendor, product, version or "*")
        comp["cpe"] = cpes[0]
        if not vendor or not product or product == "unknown" or not version:
            matches.append({"asset_id": asset_id, "cve_id": None, "product": product,
                            "installed_version": version, "status": "UNKNOWN",
                            "reason": "Unable to establish authoritative CPE mapping.",
                            "cpe": cpes[0], "confidence": conf})
            continue
        cv, cp = canonical(vendor, product)
        for rec in kb.candidates(cv, cp):
            for aff in rec.get("affected", []):
                acv, acp = canonical(aff.get("vendor", ""), aff.get("product", ""))
                if (acv, acp) != (cv, cp):
                    # also try CPE-substring match for NVD-sourced records
                    if cv not in (aff.get("cpe") or "").lower():
                        continue
                mr = match_record(version, aff.get("affected_versions", []))
                cvss = rec.get("cvss", {}) or {}
                matches.append({
                    "asset_id": asset_id, "cve_id": rec["cve_id"], "product": product,
                    "installed_version": version,
                    "status": "VULNERABLE" if mr["affected"] else "NOT_AFFECTED",
                    "matched_rule": mr["matched_rule"], "fixed_version": mr.get("fixed_version"),
                    "cvss": {"score": cvss.get("base_score"), "severity": cvss.get("severity"),
                             "vector": cvss.get("vector")},
                    "cpe": aff.get("cpe") or cpes[0],
                    "references": rec.get("references", [])[:5],
                    "evidence": {"source": "configuration", "version": version},
                    "confidence": {**conf, "correlation_confidence": 0.97 if mr["affected"] else 0.90},
                })
    summary = {"total": len(matches),
               "vulnerable": sum(1 for m in matches if m["status"] == "VULNERABLE"),
               "not_affected": sum(1 for m in matches if m["status"] == "NOT_AFFECTED"),
               "unknown": sum(1 for m in matches if m["status"] == "UNKNOWN")}
    return {"matches": matches, "summary": summary, "components": components}


def to_findings(corr: Dict[str, Any], asset_id: str = "ASSET-001") -> List[Dict[str, Any]]:
    out = []
    for i, m in enumerate(corr["matches"]):
        if m["status"] != "VULNERABLE":
            continue
        sev = ((m.get("cvss") or {}).get("severity") or "HIGH").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = "HIGH"
        out.append({"finding_id": f"F-CVE-{i + 1:04d}", "engine": "cve",
                    "type": "VULNERABILITY", "source": "CVE",
                    "control_id": m["cve_id"] or "CVE-UNKNOWN", "cve_id": m["cve_id"],
                    "title": f"{m['cve_id']} affects {m['product']} {m['installed_version']}",
                    "severity": sev, "status": "FAIL", "asset_id": asset_id,
                    "evidence": m.get("evidence", {}), "confidence": 0.97,
                    "remediation": {"recommendation":
                        f"Upgrade to {m['fixed_version']}" if m.get("fixed_version")
                        else "See vendor advisory for fixed release",
                        "fixed_version": m.get("fixed_version")},
                    "risk": {}})
    return out
