"""Fleet/executive summary, per-framework evidence pack and report sign-off (P2-5).

Risk acceptances (app.core.risk_exceptions) are shown beside verdicts; they never change a verdict or a score.
"""
from __future__ import annotations
import csv
import datetime as _dt
import hashlib
import io
import uuid
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as _xesc

from app.core import config as cfg
from app.core import db as dbmod
from app.core import persist as db
from app.core import risk_exceptions as rx
from app.core import tenancy


class SignoffError(ValueError):
    pass


def _iso(ts: Optional[float]) -> Optional[str]:
    return _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


# ----------------------------------------------------------------------------- fleet
def fleet_data(days: int = 90) -> Dict[str, Any]:
    from app.services import history
    org = tenancy.current_org()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT asset_id, name, vendor, product, criticality, environment FROM assets WHERE org_id=%s", (org,))
        assets = {r[0]: {"asset_id": r[0], "name": r[1], "vendor": r[2], "product": r[3], "criticality": r[4], "environment": r[5]}
                  for r in cur.fetchall()}
        cur.execute("SELECT DISTINCT ON (asset_id) audit_id, asset_id, summary, vendor, extract(epoch from created_at) "
                    "FROM audits WHERE org_id=%s AND asset_id IS NOT NULL AND status='COMPLETED' "
                    "ORDER BY asset_id, created_at DESC", (org,))
        latest = cur.fetchall()
        audit_ids = [r[0] for r in latest]
        controls: List[Dict[str, Any]] = []
        crit_high: List[Any] = []
        if audit_ids:
            cur.execute("SELECT COALESCE(NULLIF(control_id,''), title) AS k, min(title), (array_agg(severity))[1], "
                        "count(DISTINCT asset_id) FROM findings WHERE audit_id = ANY(%s) AND UPPER(status)='FAIL' "
                        "GROUP BY 1 ORDER BY 4 DESC, 1 LIMIT 15", (audit_ids,))
            controls = [{"control": r[0], "title": r[1], "severity": r[2], "assets_failing": r[3]} for r in cur.fetchall()]
            cur.execute("SELECT asset_id, data FROM findings WHERE audit_id = ANY(%s) AND UPPER(status)='FAIL' "
                        "AND UPPER(severity) IN ('CRITICAL','HIGH')", (audit_ids,))
            crit_high = cur.fetchall()
    accepted = rx.active_keys()
    n_acc = sum(1 for aid, d in crit_high if (aid, rx.finding_key(d or {})) in accepted)
    rows: List[Dict[str, Any]] = []
    for audit_id, asset_id, summ, vend, ts in latest:
        s, a = summ or {}, assets.get(asset_id, {"asset_id": asset_id, "name": asset_id})
        v = (vend or {}).get("vendor_id") if isinstance(vend, dict) else None
        rows.append({"asset_id": asset_id, "name": a.get("name"), "vendor": v or a.get("vendor") or "unknown",
                     "criticality": a.get("criticality"), "audit_id": audit_id,
                     "compliance_score": float(s.get("compliance_score") or 0), "critical": int(s.get("CRITICAL") or 0),
                     "high": int(s.get("HIGH") or 0), "medium": int(s.get("MEDIUM") or 0), "low": int(s.get("LOW") or 0),
                     "failed": int(s.get("failed") or 0), "audited_at": _iso(ts)})
    by_vendor: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        b = by_vendor.setdefault(r["vendor"], {"vendor": r["vendor"], "assets": 0, "score_sum": 0.0, "critical": 0, "high": 0})
        b["assets"] += 1
        b["score_sum"] += r["compliance_score"]
        b["critical"] += r["critical"]
        b["high"] += r["high"]
    vendors = sorted(({"vendor": b["vendor"], "assets": b["assets"], "avg_score": round(b["score_sum"] / b["assets"], 1),
                       "critical": b["critical"], "high": b["high"]} for b in by_vendor.values()), key=lambda x: x["avg_score"])
    n = len(rows)
    return {"generated_at": _iso(_dt.datetime.now(_dt.timezone.utc).timestamp()), "org_id": org,
            "assets_total": len(assets), "assets_audited": n,
            "avg_score": round(sum(r["compliance_score"] for r in rows) / n, 1) if n else 0.0,
            "severity_totals": {k: sum(r[k] for r in rows) for k in ("critical", "high", "medium", "low")},
            "open_critical_high": len(crit_high), "accepted_critical_high": n_acc,
            "by_vendor": vendors,
            "worst_assets": sorted(rows, key=lambda r: (r["compliance_score"], -r["critical"]))[:10],
            "top_failing_controls": controls, "trend": history.trend(days), "trend_days": days, "assets": rows}


_FLEET_COLS = ["asset_id", "name", "vendor", "criticality", "audit_id", "compliance_score", "critical", "high",
               "medium", "low", "failed", "audited_at"]


def _csv_safe(v: Any) -> str:
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


def _csv(cols: List[str], rows: List[Dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_safe(r.get(c)) for c in cols])
    return buf.getvalue().encode("utf-8-sig")


def fleet_csv(data: Dict[str, Any]) -> bytes:
    return _csv(_FLEET_COLS, data["assets"])


def fleet_pdf(d: Dict[str, Any]) -> bytes:
    from reportlab.graphics.shapes import Drawing, PolyLine
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from app.api.v1 import reports as R
    Paragraph = R.safe_paragraph(Paragraph)    # noqa: F811 - asset names etc. are tenant text

    brand = cfg.REPORT_BRAND_NAME
    footer = cfg.REPORT_BRAND_FOOTER or "Internal — automated assessment, human approval required"
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm, leftMargin=15 * mm, rightMargin=15 * mm,
                            title="Fleet security posture summary", author=brand or "SIH-26155 auditor")
    W = A4[0] - 30 * mm
    ss = getSampleStyleSheet()
    ink = colors.HexColor(R.INK)
    st_t = ParagraphStyle("FT", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=ink)
    st_k = ParagraphStyle("FK", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor(R.PRIMARY), alignment=1)
    st_h = ParagraphStyle("FH", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=11, textColor=ink, spaceBefore=12, spaceAfter=4)
    st_b = ParagraphStyle("FB", parent=ss["Normal"], fontName="Times-Roman", fontSize=9.5, leading=14, textColor=ink)
    st_c = ParagraphStyle("FC", parent=ss["Normal"], fontName="Helvetica", fontSize=8, leading=10.5, textColor=ink)

    def tbl(rows, widths):
        data = [[Paragraph(f"<b>{_xesc(str(h))}</b>", st_c) for h in rows[0]]] + \
               [[Paragraph(_xesc(str(c)), st_c) for c in r] for r in rows[1:]]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(R.HEAD_BG)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(R.BORDER)),
                               ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        return t

    sev = d["severity_totals"]
    s: list = [Spacer(1, 6 * mm), Paragraph(_xesc(brand) if brand else "Network security · Fleet posture", st_k),
               Paragraph("Executive summary — fleet security posture", st_t),
               Paragraph(f"Generated {d['generated_at']} · {d['assets_audited']} of {d['assets_total']} assets audited", st_b),
               Spacer(1, 4 * mm),
               Paragraph(f"Average compliance across the latest audit of each asset is <b>{d['avg_score']}%</b>. "
                         f"There are <b>{d['open_critical_high']}</b> open critical/high findings "
                         f"({sev['critical']} critical and {sev['high']} high in the summaries), of which "
                         f"{d['accepted_critical_high']} carry an approved risk acceptance. Acceptances are shown, "
                         "never netted off: scores and verdicts are unchanged.", st_b)]
    s.append(Paragraph("Posture by vendor", st_h))
    s.append(tbl([["Vendor", "Assets", "Avg score %", "Critical", "High"]] +
                 [[v["vendor"], v["assets"], v["avg_score"], v["critical"], v["high"]] for v in d["by_vendor"]] or
                 [["Vendor", "Assets", "Avg score %", "Critical", "High"]], [W - 120 * mm, 24 * mm, 36 * mm, 30 * mm, 30 * mm]))
    s.append(Paragraph("Worst assets", st_h))
    s.append(tbl([["Asset", "Vendor", "Score %", "Critical", "High", "Audit"]] +
                 [[f"{a['name']} ({a['asset_id']})", a["vendor"], a["compliance_score"], a["critical"], a["high"], a["audit_id"]]
                  for a in d["worst_assets"]], [W - 130 * mm, 28 * mm, 20 * mm, 18 * mm, 14 * mm, 50 * mm]))
    s.append(Paragraph("Most widespread failing controls", st_h))
    s.append(tbl([["Control", "Title", "Severity", "Assets failing"]] +
                 [[c["control"], str(c["title"])[:90], c["severity"], c["assets_failing"]] for c in d["top_failing_controls"]],
                 [32 * mm, W - 78 * mm, 22 * mm, 24 * mm]))
    pts = d["trend"]
    s.append(Paragraph(f"Trend (last {d['trend_days']} days)", st_h))
    if len(pts) >= 2:
        dw, dh = W, 28 * mm
        dr = Drawing(dw, dh)
        xs = [i * (dw - 4) / (len(pts) - 1) + 2 for i in range(len(pts))]
        ys = [2 + (p["score"] / 100.0) * (dh - 4) for p in pts]
        dr.add(PolyLine([c for xy in zip(xs, ys) for c in xy], strokeColor=colors.HexColor(R.PRIMARY), strokeWidth=1.4))
        s.append(dr)
        s.append(Paragraph(f"Average score {pts[0]['score']}% on {pts[0]['day']} to {pts[-1]['score']}% on {pts[-1]['day']} "
                           "(scale 0-100).", st_c))
    else:
        s.append(Paragraph("Not enough history yet for a trend.", st_c))

    def chrome(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor(R.MUTED))
        canvas.drawCentredString(A4[0] / 2, 12 * mm, f"Page {doc_.page}  ·  {footer}")
        canvas.restoreState()
    doc.build(s, onFirstPage=chrome, onLaterPages=chrome)
    return buf.getvalue()


# ----------------------------------------------------------------------------- evidence pack
_RESULT = {"PASS": "PASS", "FAIL": "FAIL", "NOT_APPLICABLE": "N/A"}
EVIDENCE_COLS = ["framework", "clause", "control_id", "title", "severity", "result", "evidence", "config_line", "remediation",
                 "risk_accepted", "accepted_by", "accepted_until", "acceptance_reason", "auditor_signoff"]


def evidence_pack(audit_id: str, framework: str) -> Dict[str, Any]:
    from app.api.v1 import reports as R
    audit = db.get("audits", audit_id)
    if not audit:
        raise LookupError("Audit not found")
    fw = framework.strip().upper()
    accepted = rx.active_keys(audit.get("asset_id"))
    prov = audit.get("provenance") if isinstance(audit.get("provenance"), dict) else {}
    rows: List[Dict[str, Any]] = []
    for f in audit.get("findings") or []:
        fws = f.get("frameworks")
        fws = fws if isinstance(fws, dict) else {k: "" for k in (fws or [])}
        clause = next((v for k, v in fws.items() if str(k).upper() == fw), None)
        if clause is None or str(f.get("engine", "")).lower() != "compliance":
            continue
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        e = accepted.get((f.get("asset_id") or audit.get("asset_id"), rx.finding_key(f)))
        line = prov.get(ev.get("property"), {}) if isinstance(prov.get(ev.get("property")), dict) else {}
        status = str(f.get("status", "")).upper()
        rows.append({"framework": fw, "clause": clause if isinstance(clause, str) else ", ".join(map(str, clause or [])),
                     "control_id": f.get("control_id"), "title": f.get("title"), "severity": f.get("severity"),
                     "result": _RESULT.get(status, "NOT_ASSESSED"),
                     "evidence": R._finding_summary_text(f) or ev.get("note") or "",
                     "config_line": line.get("line", ""),
                     "remediation": "" if status == "PASS" else R._remediation_hint(f),
                     "risk_accepted": bool(e), "accepted_by": e["decided_by"] if e else None,
                     "accepted_until": _iso(e["expires_at"]) if e else None,
                     "acceptance_reason": e["reason"] if e else None, "auditor_signoff": ""})
    if not rows:
        raise LookupError(f"No {fw} controls in audit {audit_id}")
    rows.sort(key=lambda r: (str(r["clause"]), str(r["control_id"])))
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    return {"audit_id": audit_id, "asset_id": audit.get("asset_id"), "framework": fw, "config_sha256": audit.get("config_sha256"),
            "generated_at": _iso(_dt.datetime.now(_dt.timezone.utc).timestamp()), "counts": counts,
            "note": "Risk acceptances are shown beside verdicts and never change them.", "controls": rows}


def evidence_csv(pack: Dict[str, Any]) -> bytes:
    return _csv(EVIDENCE_COLS, pack["controls"])


# ----------------------------------------------------------------------------- sign-off
def sign(report_id: str, user: Dict[str, Any], comment: str = "") -> Dict[str, Any]:
    r = db.get("reports", report_id)
    if not r:
        raise LookupError("report not found")
    pdf = r.get("pdf")
    digest = hashlib.sha256(bytes(pdf)).hexdigest() if pdf else r.get("sha256")
    if not digest:
        raise SignoffError("report has no content hash to sign; regenerate it")
    who = str(user.get("email") or user.get("id") or "unknown")
    sid = "SGN-" + uuid.uuid4().hex[:10].upper()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT 1 FROM report_signoffs WHERE report_id=%s AND org_id=%s AND signed_by=%s",
                    (report_id, tenancy.current_org(), who))
        if cur.fetchone():
            raise SignoffError("you have already signed this report")
        cur.execute("INSERT INTO report_signoffs (signoff_id, report_id, org_id, signed_by, role, comment, report_sha256) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (sid, report_id, tenancy.current_org(), who, str(user.get("role") or ""), (comment or "")[:1000], digest))
    return next(x for x in signoffs(report_id) if x["signoff_id"] == sid)


def signoffs(report_id: str) -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT signoff_id, report_id, signed_by, role, comment, extract(epoch from signed_at), report_sha256 "
                    "FROM report_signoffs WHERE report_id=%s AND org_id=%s ORDER BY signed_at", (report_id, tenancy.current_org()))
        return [{"signoff_id": r[0], "report_id": r[1], "signed_by": r[2], "role": r[3], "comment": r[4],
                 "signed_at": float(r[5]), "report_sha256": r[6]} for r in cur.fetchall()]
