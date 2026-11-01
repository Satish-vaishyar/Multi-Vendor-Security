"""Scan-to-scan drift (RTM S25; CM-132). Pure comparison of two scan reports produced by cloud.pipeline.run_scan."""
from __future__ import annotations

from typing import Any, Dict, List


def _key(f: Dict[str, Any]) -> str:
    return f.get("dedupe_key") or f"{f['control_id']}|{f['resource_address']}|{f.get('source', {}).get('file', '')}"


def diff_scans(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """New, resolved, changed and unchanged findings, plus resources added/removed, between two completed scans."""
    prev = {_key(f): f for f in previous.get("findings", [])}
    cur = {_key(f): f for f in current.get("findings", [])}
    new = [cur[k] for k in cur if k not in prev]
    resolved = [prev[k] for k in prev if k not in cur]
    changed, unchanged = [], 0
    for k in cur.keys() & prev.keys():
        a, b = prev[k], cur[k]
        if a["evidence_state"] != b["evidence_state"] or a["severity"] != b["severity"]:
            changed.append({"control_id": b["control_id"], "resource_address": b["resource_address"],
                            "from": {"state": a["evidence_state"], "severity": a["severity"]},
                            "to": {"state": b["evidence_state"], "severity": b["severity"]}})
        else:
            unchanged += 1
    prev_res = {r["address"] for r in previous.get("resources", [])}
    cur_res = {r["address"] for r in current.get("resources", [])}
    regressions = [f for f in new if f["evidence_state"] == "FAIL_STATIC"] + [
        c for c in changed if c["to"]["state"] == "FAIL_STATIC" and c["from"]["state"] != "FAIL_STATIC"]
    return {"new": new, "resolved": resolved, "changed": changed, "unchanged": unchanged,
            "resources_added": sorted(cur_res - prev_res), "resources_removed": sorted(prev_res - cur_res),
            "regressions": len(regressions), "improvements": len(resolved) + len([
                c for c in changed if c["from"]["state"] == "FAIL_STATIC" and c["to"]["state"] != "FAIL_STATIC"]),
            "same_rule_pack": previous.get("rule_pack_version") == current.get("rule_pack_version")}
