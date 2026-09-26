"""Central audit orchestration (arch.md §43-44, api.md §10-12).

Pipeline: ingestion(validated) -> M1 vendor detect -> parse (deterministic wins,
AI gap-fill) -> Canonical IR (M5 gate) -> 4 engines in parallel (compliance,
PQC, security analytics, CVE) -> unified findings (common schema arch.md §27)
-> risk (M6 rule + OKF RiskEngine) -> remediation pointers -> report data.
"""
from __future__ import annotations
import hashlib
import time
from typing import Any, Dict, List

from app.core import persist as db
from app.core import store
from app.parsers import vendor_detector, canonical as canon
from app.engines import pqc as pqc_eng
from app.engines import security as sec_eng
from app.services.integration import okf_layer, cve_layer, m6_rule_score, m5_validate


def _fid(prefix: str, audit_id: str, key: str, i: int) -> str:
    h = hashlib.sha256(f"{audit_id}:{key}:{i}".encode()).hexdigest()[:6].upper()
    return f"{prefix}-{h}"


def run_audit(*, asset_id: str, configuration_id: str, config_text: str,
              frameworks: List[str], run_cve: bool = True, run_pqc: bool = True,
              run_security: bool = True, asset_criticality: str = "HIGH",
              vendor_hint: str = "", detected: Dict[str, Any] | None = None) -> Dict[str, Any]:
    t0 = time.time()
    okf = okf_layer()
    det = detected or vendor_detector.detect_vendor(config_text, vendor_hint)
    vendor = det["vendor_id"]
    parsed = canon.parse_to_canonical(config_text, vendor)
    flat, nested = parsed["flat_ir"], parsed["nested_ir"]
    ir_validation = m5_validate(flat)  # M5 Canonical IR Validator gate

    stages: Dict[str, str] = {"ingestion": "COMPLETED", "detection": "COMPLETED",
                              "normalization": "COMPLETED",
                              "compliance": "RUNNING", "cve": "PENDING",
                              "pqc": "PENDING", "security": "PENDING",
                              "risk": "PENDING", "report": "PENDING"}

    # — Engine 1: Compliance (OKF deterministic control packs) —
    controls = okf["ckb"].for_frameworks(frameworks) if hasattr(okf["ckb"], "for_frameworks") else okf["ckb"].all()
    comp_eng = okf["ComplianceEngine"](controls, {k: v for k, v in okf["rem"].index.items()})
    comp_findings = comp_eng.evaluate(nested, asset_id=asset_id)
    comp_score = okf["ComplianceEngine"].score(comp_findings)
    stages["compliance"] = "COMPLETED"

    # — Engine 4: CVE (needs software inventory from config) —
    cve_out: Dict[str, Any] = {"summary": {"vulnerable": 0, "not_affected": 0, "unknown": 0},
                               "matches": [], "findings": [], "components": [], "cbom": []}
    if run_cve:
        stages["cve"] = "RUNNING"
        cve = cve_layer()
        comps = cve["inventory"].extract(config_text, default_vendor=vendor)
        if det.get("version") and not any(c.get("version") for c in comps):
            prod = {"cisco": "ios_xe", "juniper": "junos", "fortinet": "fortios"}.get(vendor, "unknown")
            comps.append({"vendor": vendor, "product": prod, "version": det["version"],
                          "component_type": "operating_system", "cpe": None, "source": "detector"})
        corr = cve["correlator"].correlate(comps, asset_id=asset_id)
        cve_out = {"summary": corr["summary"], "matches": corr["matches"],
                   "findings": cve["correlator"].to_findings(corr, asset_id),
                   "components": corr["components"],
                   "cbom": cve["build_cbom"](asset_id, corr["components"])}
        stages["cve"] = "COMPLETED"

    # — Engine 2: PQC —
    pqc_out: Dict[str, Any] = {"readiness_score": 0.0, "counts": {}, "algorithms": []}
    if run_pqc:
        stages["pqc"] = "RUNNING"
        cbom = pqc_eng.build_cbom(asset_id, flat, cve_out.get("components", []))
        pqc_out = pqc_eng.readiness(cbom)
        stages["pqc"] = "COMPLETED"

    # — Engine 3: Security analytics —
    sec_out: Dict[str, Any] = {"risk_score": 100, "anomalies": []}
    if run_security:
        stages["security"] = "RUNNING"
        sec_out = sec_eng.analyze(flat, asset_id)
        stages["security"] = "COMPLETED"

    # — Unified findings (common schema) + risk —
    stages["risk"] = "RUNNING"
    internet_exposed = flat.get("MGMT.INTERNET_EXPOSED") is True
    unified: List[Dict[str, Any]] = []
    for i, f in enumerate(comp_findings):
        fd = f.model_dump() if hasattr(f, "model_dump") else dict(f)
        risk = okf["RiskEngine"].score_finding(f, asset_criticality, internet_exposed)
        rule_risk = m6_rule_score(str(fd.get("severity", "medium")).lower(),
                                  "internet" if internet_exposed else "internal",
                                  asset_criticality.lower(), float(fd.get("confidence", 0.9) or 0.9))
        fid = _fid("F", configuration_id, fd.get("control_id", "?"), i)
        unified.append({"finding_id": fid, "type": "COMPLIANCE", "engine": "compliance",
                        "severity": fd.get("severity"), "title": fd.get("title"),
                        "control_id": fd.get("control_id"), "status": fd.get("status"),
                        "asset_id": asset_id, "evidence": fd.get("evidence"),
                        "frameworks": fd.get("frameworks"), "confidence": fd.get("confidence", 1.0),
                        "risk": {**risk, "rule_score": rule_risk},
                        "remediation": {"available": bool(fd.get("remediation")),
                                        "detail": fd.get("remediation", {})},
                        "source": {"control": fd.get("control_id")}})
    for i, m in enumerate(cve_out.get("matches", [])):
        sev = str((m.get("cvss") or {}).get("severity", "HIGH")).upper()
        fid = _fid("F-CVE", configuration_id, str(m.get("cve_id", "UNK")), i)
        risk = {"risk_score": float((m.get("cvss") or {}).get("score", 7.0)),
                "priority": sev, "factors": {"source": "CVSS"}}
        unified.append({"finding_id": fid, "type": "VULNERABILITY", "engine": "cve",
                        "severity": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
                        "title": f"{m.get('cve_id')}: {m.get('product')} {m.get('installed_version')} {m.get('status')}",
                        "status": "FAIL" if m.get("status") == "VULNERABLE" else ("PASS" if m.get("status") == "NOT_AFFECTED" else "UNKNOWN"),
                        "asset_id": asset_id, "evidence": {"property": "SOFTWARE.VERSION",
                                                           "observed": m.get("installed_version"),
                                                           "cpe": m.get("cpe"), "matched_rule": m.get("matched_rule")},
                        "confidence": (m.get("confidence") or {}).get("correlation", 0.9) if isinstance(m.get("confidence"), dict) else 0.9,
                        "risk": risk, "remediation": {"available": bool(m.get("fixed_version")),
                                                      "fixed_version": m.get("fixed_version")},
                        "source": {"cve": m.get("cve_id")}})
    for i, a in enumerate(sec_out.get("anomalies", [])):
        fid = _fid("F-SEC", configuration_id, a.get("type", "?"), i)
        unified.append({"finding_id": fid, "type": "SECURITY", "engine": "security",
                        "severity": a.get("severity", "MEDIUM"), "title": f"{a.get('type')}: {a.get('property')}",
                        "status": "FAIL", "asset_id": asset_id,
                        "evidence": {"property": a.get("property"), "detail": a.get("detail")},
                        "confidence": 0.9, "risk": {"risk_score": 7.0, "priority": a.get("severity")},
                        "remediation": {"available": False}, "source": {"analytics": a.get("type")}})
    for i, row in enumerate(pqc_out.get("algorithms", [])):
        if row.get("pqc_status") == "MIGRATION_REQUIRED":
            fid = _fid("F-PQC", configuration_id, row.get("algorithm", "?"), i)
            unified.append({"finding_id": fid, "type": "PQC", "engine": "pqc",
                            "severity": "MEDIUM", "title": f"PQC migration: {row.get('algorithm')} ({row.get('protocol')})",
                            "status": "FAIL", "asset_id": asset_id,
                            "evidence": {"property": "CRYPTO", "observed": row},
                            "confidence": 0.95, "risk": {"risk_score": 5.0, "priority": "MEDIUM"},
                            "remediation": {"available": True, "migration": row.get("migration")},
                            "source": {"cbom": True}})
    stages["risk"] = "COMPLETED"

    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for u in unified:
        if u["status"] == "FAIL" and u["severity"] in sev_count:
            sev_count[u["severity"]] += 1
    by_fw: Dict[str, Any] = {}
    for fw in frameworks:
        rel = [f for f in comp_findings
               if fw.upper() in (str(k).upper() for k in ((f.frameworks if hasattr(f, "frameworks") else {}) or {}))]
        by_fw[fw] = okf["ComplianceEngine"].score(rel) if rel else {"compliance_score": 0.0, "total": 0}
    audit_id = f"AUD-{hashlib.sha256(config_text.encode()).hexdigest()[:8].upper()}"
    try:  # arch.md §55-56: version every knowledge input for reproducibility
        import yaml as _yaml
        from app.core import config as _cfg
        _mani = _yaml.safe_load(((_cfg.OKF_DIR) / "okf_manifest.yaml").read_text())
        _okf_ver = str(_mani.get("okf_version", "1.0.0"))
    except Exception:
        _okf_ver = "1.0.0"
    record = {"audit_id": audit_id, "asset_id": asset_id, "configuration_id": configuration_id,
              "vendor": det, "frameworks": frameworks, "status": "COMPLETED", "progress": 100,
              "config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
              "versions": {"parser": "deterministic-regex@1.0+M4-gapfill",
                           "mapping_registry": "okf-mappings@1.0+learned",
                           "canonical_ir": "1.0", "control_pack": "okf-core/extended",
                           "okf": _okf_ver, "cve_kb": "okf-vulnKB+nvd-sync",
                           "pqc_rules": "backend-pqc@1.0", "risk_model": "M6-rules@1.0"},
              "stages": stages, "summary": {**comp_score, **sev_count,
                                            "cve": cve_out["summary"], "pqc_readiness": pqc_out.get("readiness_score"),
                                            "security_risk": sec_out.get("risk_score")},
              "by_framework": by_fw, "compliance": comp_score,
              "cve": cve_out, "pqc": pqc_out, "security": sec_out,
              "canonical_ir": nested, "flat_ir": flat, "provenance": parsed.get("provenance", {}),
              "unknown_lines": parsed.get("unknown_lines", []), "llm_offline": parsed.get("llm_offline", True),
              "ir_validation": ir_validation,
              "findings": unified, "duration_s": round(time.time() - t0, 2),
              "created_at": store.now()}
    db.save("audits", record)
    for u in unified:
        db.save("findings", {**u, "audit_id": audit_id})
    return record
