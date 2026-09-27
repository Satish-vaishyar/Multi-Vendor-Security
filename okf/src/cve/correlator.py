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
              kb: VulnKB | None = None, include_seeds: bool = False) -> Dict[str, Any]:
    kb = kb or VulnKB().load()
    # Production matching uses real NVD records only. Synthetic seed records
    # (source OKF-SEED-SYNTHETIC) stay in the file as offline test fixtures
    # and are matched only when explicitly requested (okf golden tests).
    records = kb.records if include_seeds else \
        [r for r in kb.records if r.get("source") != "OKF-SEED-SYNTHETIC"]
    # Canonical (record, entry) index: one pass over the KB so each component
    # only version-checks entries naming ITS product. (A record-level index
    # re-scans every sibling entry per candidate — 300k+ redundant range
    # checks per component on a real-world NVD KB.)
    entries: Dict[tuple, List[tuple]] = {}
    for r in records:
        for a in r.get("affected", []) or []:
            entries.setdefault(
                canonical(a.get("vendor", ""), a.get("product", "")), []).append((r, a))
    matches: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    for comp in components:
        vendor, product, version = comp.get("vendor", ""), comp.get("product", ""), comp.get("version", "")
        conf = confidence(vendor, product, version)
        cpes = resolve(vendor, product, version or "*")
        comp["cpe"] = cpes[0]
        if not vendor or not product or product == "unknown" or not version:
            # Not a vulnerability row: the inventory gap is reported separately
            # so the matches list (and every severity/status column built from
            # it) only ever holds real CVE correlations.
            unresolved.append({"asset_id": asset_id, "product": product or "unknown",
                               "installed_version": version, "status": "UNKNOWN",
                               "reason": "Unable to establish authoritative CPE mapping "
                                         "(vendor/product/version incomplete).",
                               "cpe": cpes[0], "confidence": conf})
            continue
        cv, cp = canonical(vendor, product)
        # One row per CVE: several entries of the same record can name this
        # product — keep a single row, preferring an affected (VULNERABLE)
        # rule so the fixed version is surfaced.
        by_cve: Dict[str, Dict[str, Any]] = {}
        for rec, aff in entries.get((cv, cp), []):
            mr = match_record(version, aff.get("affected_versions", []))
            cvss = rec.get("cvss", {}) or {}
            m = {
                "asset_id": asset_id, "cve_id": rec["cve_id"], "product": product,
                "installed_version": version,
                "status": "VULNERABLE" if mr["affected"] else "NOT_AFFECTED",
                "matched_rule": mr["matched_rule"], "fixed_version": mr.get("fixed_version"),
                "cvss": {"score": cvss.get("base_score"), "severity": cvss.get("severity"),
                         "vector": cvss.get("vector")},
                "cpe": aff.get("cpe") or cpes[0],
                "installed_cpe": cpes[0],
                "references": rec.get("references", [])[:5],
                "evidence": {"source": "configuration", "version": version},
                "confidence": {**conf, "correlation_confidence": 0.97 if mr["affected"] else 0.90},
            }
            prev = by_cve.get(rec["cve_id"])
            if prev is None or (mr["affected"] and prev["status"] != "VULNERABLE"):
                by_cve[rec["cve_id"]] = m
        matches.extend(by_cve.values())
    summary = {"total": len(matches) + len(unresolved),
               "vulnerable": sum(1 for m in matches if m["status"] == "VULNERABLE"),
               "not_affected": sum(1 for m in matches if m["status"] == "NOT_AFFECTED"),
               "unknown": len(unresolved)}
    return {"matches": matches, "unresolved": unresolved,
            "summary": summary, "components": components}


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
