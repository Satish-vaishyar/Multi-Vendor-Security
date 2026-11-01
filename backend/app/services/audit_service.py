"""Central audit orchestration (arch.md §43-44, api.md §10-12).

Pipeline: ingestion(validated) -> M1 vendor detect -> parse (deterministic wins,
AI gap-fill) -> Canonical IR (M5 gate) -> 4 engines in parallel (compliance,
PQC, security analytics, CVE) -> unified findings (common schema arch.md §27)
-> risk (M6 rule + OKF RiskEngine) -> remediation pointers -> report data.
"""
from __future__ import annotations
import hashlib
import logging
import time
from typing import Any, Dict, List

from app.core import persist as db
from app.core import tenancy
from app.services import history
from app.core.redact import redact_line, redact_secrets
from app.core import store
from app.parsers import vendor_detector, canonical as canon
from app.engines import pqc as pqc_eng
from app.engines import security as sec_eng
from app.services.integration import okf_layer, cve_layer, m6_rule_score, m5_validate


def _parser_version() -> str:
    try:
        from src import vendor_parsers
        return str(vendor_parsers.__version__)
    except Exception:
        return "unknown"


def _fid(prefix: str, audit_id: str, key: str, i: int) -> str:
    """Deterministic (a re-run of the same audit upserts the same rows) and wide enough not to collide: 6 hex characters
    (24 bits) collided across a few thousand findings, which overwrote a finding in the same organisation or failed the whole
    audit when the id belonged to another one."""
    h = hashlib.sha256(f"{audit_id}:{key}:{i}".encode()).hexdigest()[:16].upper()
    return f"{prefix}-{h}"


def _redact_provenance(prov: Dict[str, Any]) -> Dict[str, Any]:
    """Evidence lines are stored and shown in the UI/PDF: never persist secret values."""
    out: Dict[str, Any] = {}
    for k, v in (prov or {}).items():
        v = dict(v) if isinstance(v, dict) else v
        if isinstance(v, dict) and isinstance(v.get("line"), str):
            v["line"] = redact_secrets(v["line"])
        out[k] = v
    return out


def run_audit(*, asset_id: str, configuration_id: str, config_text: str,
              frameworks: List[str], run_cve: bool = True, run_pqc: bool = True,
              run_security: bool = True, asset_criticality: str = "HIGH",
              vendor_hint: str = "", detected: Dict[str, Any] | None = None,
              trigger: str = "manual", snapshot: bool = True) -> Dict[str, Any]:
    t0 = time.time()
    okf = okf_layer()
    det = detected or vendor_detector.detect_vendor(config_text, vendor_hint)
    vendor = det["vendor_id"]
    parsed = canon.parse_to_canonical(config_text, vendor, str(det.get("platform") or ""))
    flat, nested = parsed["flat_ir"], parsed["nested_ir"]
    ir_validation = m5_validate(flat)  # M5 Canonical IR Validator gate
    # Anything that silently weakened this audit is listed here (shown in the UI and the PDF).
    degraded: List[str] = []
    if ir_validation.get("validator_error"):
        degraded.append(f"IR validator unavailable ({ir_validation.get('warning', 'error')}); schema checks were skipped")
    if str(det.get("method", "")).startswith("fallback"):
        degraded.append(f"vendor model unavailable ({det.get('method')}); deterministic fingerprints only")
    degraded += [f"parser: {n}" for n in (parsed.get("parser") or {}).get("notes", [])]

    stages: Dict[str, str] = {"ingestion": "COMPLETED", "detection": "COMPLETED",
                              "normalization": "COMPLETED",
                              "compliance": "RUNNING", "cve": "PENDING",
                              "pqc": "PENDING", "security": "PENDING",
                              "risk": "PENDING", "report": "PENDING"}

    # — Engine 1: Compliance (OKF deterministic control packs) —
    controls = okf["ckb"].for_frameworks(frameworks) if hasattr(okf["ckb"], "for_frameworks") else okf["ckb"].all()
    comp_eng = okf["ComplianceEngine"](controls, {k: v for k, v in okf["rem"].index.items()})
    # Platform-scoped evaluation (SCAP CPE model): controls that cannot apply
    # to this vendor/platform evaluate to NOT_APPLICABLE and leave the score.
    comp_findings = comp_eng.evaluate(nested, asset_id=asset_id,
                                      vendor=vendor, platform=str(det.get("platform") or ""),
                                      not_applicable=parsed.get("not_applicable"),
                                      provenance=parsed.get("provenance"))
    comp_score = okf["ComplianceEngine"].score(comp_findings)
    stages["compliance"] = "COMPLETED"

    # — Engine 4: CVE (needs software inventory from config) —
    cve_out: Dict[str, Any] = {"summary": {"vulnerable": 0, "not_affected": 0, "unknown": 0},
                               "matches": [], "unresolved": [],
                               "findings": [], "components": [], "cbom": []}
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
                   "unresolved": corr.get("unresolved", []),
                   "findings": cve["correlator"].to_findings(corr, asset_id),
                   "components": corr["components"],
                   "cbom": cve["build_cbom"](asset_id, corr["components"])}
        stages["cve"] = "COMPLETED"

    # — Engine 2: PQC —
    pqc_out: Dict[str, Any] = {"readiness_score": 0.0, "readiness": 0.0, "readiness_label": "At risk",
                               "counts": {}, "algorithms": [], "weak_algorithms": [],
                               "migration_recommendations": []}
    if run_pqc:
        stages["pqc"] = "RUNNING"
        cbom = pqc_eng.build_cbom(asset_id, flat, cve_out.get("components", []))
        pqc_out = pqc_eng.readiness(cbom)
        stages["pqc"] = "COMPLETED"

    # — Engine 3: Security analytics —
    sec_out: Dict[str, Any] = {"risk_score": 100, "anomalies": []}
    if run_security:
        stages["security"] = "RUNNING"
        dumped = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in comp_findings]
        failed_props = {str((d.get("evidence") or {}).get("property") or "") for d in dumped
                        if str(d.get("status") or "").upper() == "FAIL"}
        sec_out = sec_eng.analyze(flat, asset_id, provenance=parsed.get("provenance"),
                                  compliance_failed=failed_props - {""})
        stages["security"] = "COMPLETED"

    # — Unified findings (common schema) + risk —
    # audit_id derives from config content so re-uploads of the same config
    # map to the same audit; finding_ids key off audit_id (not configuration_id)
    # so re-runs upsert the same rows instead of accumulating duplicates
    # (which previously made the picker CVE count drift from the detail table).
    # Scoped by org + asset so identical configs on different devices/tenants can
    # never share (and silently overwrite) one audit; the same config re-run on the
    # same asset still upserts the same audit (idempotent, no duplicate findings).
    audit_id = "AUD-" + hashlib.sha256(
        f"{tenancy.current_org()}|{asset_id}|{config_text}".encode()).hexdigest()[:12].upper()
    stages["risk"] = "RUNNING"
    internet_exposed = flat.get("MGMT.INTERNET_EXPOSED") is True
    unified: List[Dict[str, Any]] = []
    for i, f in enumerate(comp_findings):
        fd = f.model_dump() if hasattr(f, "model_dump") else dict(f)
        risk = okf["RiskEngine"].score_finding(f, asset_criticality, internet_exposed)
        rule_risk = m6_rule_score(str(fd.get("severity", "medium")).lower(),
                                  "internet" if internet_exposed else "internal",
                                  asset_criticality.lower(), float(fd.get("confidence", 0.9) or 0.9))
        fid = _fid("F", audit_id, fd.get("control_id", "?"), i)
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
        # Keep UNKNOWN honest: a match without CVSS severity must stay UNKNOWN
        # so the findings GROUP BY agrees with GET /vulnerabilities/{audit_id}
        # (which buckets by match cvss.severity). Never inflate to HIGH here.
        raw_sev = str((m.get("cvss") or {}).get("severity", "")).upper()
        sev = raw_sev if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"
        fid = _fid("F-CVE", audit_id, str(m.get("cve_id", "UNK")), i)
        risk = {"risk_score": float((m.get("cvss") or {}).get("score", 7.0) or 0.0),
                "priority": sev, "factors": {"source": "CVSS"}}
        _refs: list[str] = []
        for _r in list(m.get("references") or []):
            _u = _r if isinstance(_r, str) else (_r.get("url") if isinstance(_r, dict) else str(_r))
            if _u and _u not in _refs:
                _refs.append(_u)
        _fixed = m.get("fixed_version")
        _rec = (f"Upgrade {m.get('product')} from {m.get('installed_version')} to {_fixed} (or a later fixed release)."
                if _fixed else
                f"No fixed release recorded for {m.get('cve_id')} — open the vendor advisory links below to pick the fixed release for {m.get('product')}.")
        unified.append({"finding_id": fid, "type": "VULNERABILITY", "engine": "cve",
                        "severity": sev,
                        "title": f"{m.get('cve_id')}: {m.get('product')} {m.get('installed_version')} {m.get('status')}",
                        "status": "FAIL" if m.get("status") == "VULNERABLE" else ("PASS" if m.get("status") == "NOT_AFFECTED" else "UNKNOWN"),
                        "asset_id": asset_id, "evidence": {"property": "SOFTWARE.VERSION",
                                                           "observed": m.get("installed_version"),
                                                           "product": m.get("product"),
                                                           "installed_version": m.get("installed_version"),
                                                           "cpe": m.get("cpe"),
                                                           "installed_cpe": m.get("installed_cpe") or m.get("cpe"),
                                                           "matched_rule": m.get("matched_rule"),
                                                           "cvss": m.get("cvss") or {},
                                                           "references": _refs},
                        "confidence": (m.get("confidence") or {}).get("correlation", 0.9) if isinstance(m.get("confidence"), dict) else 0.9,
                        "risk": risk, "remediation": {"available": bool(_fixed or m.get("status") == "VULNERABLE"),
                                                      "fixed_version": _fixed,
                                                      "cve_id": m.get("cve_id"),
                                                      "recommendation": _rec,
                                                      "references": _refs},
                        "source": {"cve": m.get("cve_id")}})
    for i, a in enumerate(sec_out.get("anomalies", [])):
        if a.get("duplicates_compliance"):
            continue                                   # already reported as a failed compliance control
        fid = _fid("F-SEC", audit_id, a.get("rule_id") or a.get("type", "?"), i)
        unified.append({"finding_id": fid, "type": "SECURITY", "engine": "security",
                        "severity": a.get("severity", "MEDIUM"), "title": f"{a.get('type')}: {a.get('property')}",
                        "status": "FAIL", "asset_id": asset_id,
                        "evidence": {"property": a.get("property"), "detail": a.get("detail"), "why": a.get("why"),
                                     "rule_id": a.get("rule_id"), "basis": a.get("basis", "observed")},
                        "confidence": 0.9 if a.get("basis") != "assumed" else 0.6,
                        "risk": {"risk_score": 7.0, "priority": a.get("severity")},
                        "remediation": {"available": bool(a.get("fix")), "recommendation": a.get("fix", "")},
                        "source": {"analytics": a.get("type"), "rule": a.get("rule_id")}})
    for i, p in enumerate(sec_out.get("patterns", [])):
        fid = _fid("F-PATH", audit_id, p.get("rule_id") or p.get("pattern", "?"), i)
        unified.append({"finding_id": fid, "type": "SECURITY", "engine": "security",
                        "severity": p.get("severity", "HIGH"), "title": f"Attack path: {p.get('pattern')}",
                        "status": "FAIL", "asset_id": asset_id,
                        "evidence": {"property": ",".join(p.get("contributors", [])), "detail": p.get("detail"),
                                     "rule_id": p.get("rule_id"), "basis": p.get("basis", "observed"),
                                     "signals": p.get("evidence", {})},
                        "confidence": 0.85 if p.get("basis") != "assumed" else 0.55,
                        "risk": {"risk_score": 8.5, "priority": p.get("severity")},
                        "remediation": {"available": bool(p.get("fix")), "recommendation": p.get("fix", "")},
                        "source": {"analytics": "ATTACK_PATH", "rule": p.get("rule_id")}})
    for i, row in enumerate(pqc_out.get("algorithms", [])):
        if row.get("pqc_status") == "MIGRATION_REQUIRED":
            fid = _fid("F-PQC", audit_id, row.get("algorithm", "?"), i)
            # Deprecated / broken crypto is exploitable today -> HIGH;
            # other quantum-only risk stays MEDIUM.
            sev = "HIGH" if str(row.get("klass", "")).startswith("deprecated") else "MEDIUM"
            unified.append({"finding_id": fid, "type": "PQC", "engine": "pqc",
                            "severity": sev, "title": f"PQC migration: {row.get('algorithm')} ({row.get('protocol')})",
                            "status": "FAIL", "asset_id": asset_id,
                            "evidence": {"property": "CRYPTO", "observed": row},
                            "confidence": 0.95, "risk": {"risk_score": 7.5 if sev == "HIGH" else 5.0, "priority": sev},
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
              "versions": {"parser": f"structured-vendor-parsers@{_parser_version()}+registry+M4-gapfill",
                           "mapping_registry": "okf-mappings@1.0+learned",
                           "canonical_ir": "1.0", "control_pack": "okf-core/extended",
                           "okf": _okf_ver, "cve_kb": "okf-vulnKB+nvd-sync",
                           "pqc_rules": "backend-pqc@1.0", "risk_model": "M6-rules@1.0"},
              "stages": stages, "summary": {**comp_score, **sev_count,
                                            "cve": cve_out["summary"], "pqc_readiness": pqc_out.get("readiness_score"),
                                            "security_risk": sec_out.get("risk_score")},
              "by_framework": by_fw, "compliance": comp_score,
              "cve": cve_out, "pqc": pqc_out, "security": sec_out,
              "canonical_ir": nested, "flat_ir": flat, "provenance": _redact_provenance(parsed.get("provenance", {})),
              "unknown_lines": [redact_line(l) for l in parsed.get("unknown_lines", [])], "llm_offline": parsed.get("llm_offline", True),
              "ir_validation": ir_validation, "parser": parsed.get("parser", {}), "degraded": degraded,
              "findings": unified, "duration_s": round(time.time() - t0, 2),
              "created_at": store.now()}
    db.save("audits", record)
    # Drop stale findings from earlier runs of this audit (e.g. match count
    # shrank) so per-engine GROUP BY counts agree with the stored matches.
    try:
        new_ids = {u["finding_id"] for u in unified}
        for row in db.select("findings", ["finding_id"], limit=5000, audit_id=audit_id):
            if row.get("finding_id") not in new_ids:
                db.delete("findings", row["finding_id"])
    except Exception as e:
        logging.getLogger("sih26155").warning("stale-finding cleanup failed for %s: %s", audit_id, e)
    for u in unified:
        db.save("findings", {**u, "audit_id": audit_id})
    # Append-only history (drift / aging / trend). Last step, so a retried job never double-records.
    # `snapshot=False` is used for what-if re-audits (remediation simulation) that must not appear as real runs.
    if snapshot:
        try:
            record["history"] = history.record_snapshot(record, trigger)
        except Exception as e:  # noqa: BLE001 - history must never fail an audit, but it must not vanish silently
            logging.getLogger("sih26155").error("history snapshot failed for %s: %s", audit_id, e)
            record["history_error"] = f"{type(e).__name__}: {e}"
    return record
