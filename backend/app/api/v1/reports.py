"""Reports: POST /reports, GET /reports, GET /reports/{id}, GET /reports/{id}/download.

Network-security compliance audit report (PDF via ReportLab).

Design notes (deliberately document-like, not dashboard-like):
  - Serif narrative (Times) + sans headings/tables (Helvetica), ragged-right
    body copy — justified sans is what makes auto-generated PDFs obvious.
  - Quiet tables: light-slate headers with ink text, hairline rules, no zebra
    striping, no rainbow fills. Colour is reserved for severity tokens only.
  - Real contents list (not a Yes/No grid), dynamic section numbering so
    cross-references stay correct whatever subset of sections is requested.
  - Small vector charts (severity bars, per-framework bars) drawn from the
    same data as the tables — a report with zero graphics reads as a dump.
  - Cover carries the engagement record and assessment snapshot; the running
    header/footer starts on page 2, and classification banners frame the cover.

Structure: cover -> about this report + contents -> executive summary ->
scope & methodology -> asset inventory -> compliance posture ->
vulnerability (CVE) -> cryptography/PQC -> security analytics ->
detailed findings register -> prioritized remediation roadmap ->
evidence appendix -> disclaimer & sign-off.

Palette follows the application light theme (frontend src/index.css).
PDF bytes live in Postgres (reports.pdf).
"""
from __future__ import annotations

import datetime as _dt
import io
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import List as _List

from app.core import config as cfg
from app.core import persist as db
from app.core import store

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

ALLOWED_SECTIONS = ["EXECUTIVE_SUMMARY", "DEVICE", "COMPLIANCE", "CVE",
                    "PQC", "SECURITY", "REMEDIATION", "EVIDENCE"]

# ---- light-theme palette (mirrors frontend :root) ----
PRIMARY = "#315E9B"
PRIMARY_DARK = "#284F86"
INK = "#1C2430"
MUTED = "#59616B"
FAINT = "#8A9199"
BORDER = "#E2E4E0"
HEAD_BG = "#E9EDF2"      # quiet slate table headers — not brand blue
TRACK = "#E8EBEE"        # chart track grey
DANGER = "#B23A3A"
HIGH = "#B45309"
WARN = "#9A6A00"
INFO = "#2F6F8F"
OK = "#277A4B"


class ReportBody(BaseModel):
    audit_id: str = Field(min_length=1)
    format: str = "PDF"
    sections: _List[str] = Field(default_factory=lambda: list(ALLOWED_SECTIONS))


def ensure_reports_schema() -> None:
    """Self-heal the reports table (migrate_002.sql) — idempotent."""
    try:
        from app.core import db as dbmod
        with dbmod.get_conn() as conn:
            cur = conn.cursor()
            cur.execute("ALTER TABLE reports ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'")
            cur.execute("ALTER TABLE reports ADD COLUMN IF NOT EXISTS pdf BYTEA")
            cur.execute("ALTER TABLE reports ADD COLUMN IF NOT EXISTS download_path TEXT")
    except Exception as e:  # pragma: no cover - defensive
        import logging
        logging.getLogger("sih26155").warning("ensure_reports_schema skipped: %s", e)


# ---------------------------------------------------------------- helpers ---
def _num(v: Any, default: float = 0.0) -> float:
    try:
        n = float(v)
        if n != n:  # NaN
            return default
        return n
    except (TypeError, ValueError):
        return default


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _txt(v: Any, default: str = "—") -> str:
    if v is None or v == "":
        return default
    s = str(v).strip()
    return s if s else default


def _norm_sections(sections: Any) -> List[str]:
    if not sections:
        return list(ALLOWED_SECTIONS)
    out: List[str] = []
    for s in sections:
        u = str(s or "").strip().upper()
        if u in ALLOWED_SECTIONS and u not in out:
            out.append(u)
    return out or list(ALLOWED_SECTIONS)


def _risk_rating(score: float, critical: int, high: int) -> tuple[str, str]:
    """(label, color) overall posture."""
    if critical > 0 or score < 40:
        return ("Critical", DANGER)
    if high > 0 or score < 60:
        return ("High", HIGH)
    if score < 80:
        return ("Medium", WARN)
    return ("Low", OK)


def _sev_order_key(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(str(sev or "").upper(), 4)


def _sev_color(sev: str) -> str:
    s = str(sev or "").upper()
    if s == "CRITICAL":
        return DANGER
    if s == "HIGH":
        return HIGH
    if s == "MEDIUM":
        return WARN
    if s == "LOW":
        return INFO
    return MUTED


def _sev_display(sev: str) -> str:
    s = str(sev or "").strip().upper()
    return {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
            "LOW": "Low"}.get(s, "Unknown")


def _pqc_display(status: str) -> tuple[str, str]:
    s = str(status or "").strip().upper()
    return {"MIGRATION_REQUIRED": ("Migration required", DANGER),
            "TRANSITION": ("Transition", HIGH),
            "READY": ("Ready", OK)}.get(s, ("Unknown", MUTED))


def _pl(n: int, singular: str, plural: str | None = None) -> str:
    """Human plural — '1 check', '17 checks'. Never 'check(s)'."""
    n = int(n)
    word = singular if n == 1 else (plural or singular + "s")
    return f"{n} {word}"


def _engine_display(f: Dict[str, Any]) -> str:
    eng = str(f.get("engine", "") or "").lower()
    typ = str(f.get("type", "") or "").upper()
    if eng == "compliance":
        return "Compliance"
    if eng == "cve" or typ == "VULNERABILITY":
        return "Vulnerability correlation"
    if eng == "security":
        return "Security analytics"
    if eng == "pqc":
        return "Post-quantum readiness"
    return (eng or typ or "assessment").replace("_", " ").title()


def _short_obs(value: Any) -> str:
    """Render an observed value without raw-dict dumps."""
    if value is None or value == "":
        return ""
    if isinstance(value, dict):
        for k in ("algorithm", "observed", "value", "product"):
            if value.get(k) not in (None, ""):
                extra = value.get("key_size") or value.get("version", "")
                base = str(value.get(k))
                return f"{base} {extra}".strip() if extra else base
        keys = [k for k in value if value.get(k) not in (None, "")]
        return ", ".join(f"{k}: {value[k]}" for k in keys[:3])[:140]
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    return str(value)


def _finding_summary_text(f: Dict[str, Any]) -> str:
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    parts: List[str] = []
    if isinstance(ev, dict):
        prop = ev.get("property")
        obs = _short_obs(ev.get("observed_value", ev.get("observed", "")))
        exp = _short_obs(ev.get("expected_value", ev.get("expected", "")))
        if prop and obs and exp:
            parts.append(f"{prop} is {obs} (expected {exp})")
        elif prop and obs:
            parts.append(f"{prop} is {obs}")
        elif prop and exp:
            parts.append(f"{prop} should be {exp}")
        elif prop:
            pass
        stated = bool(prop and (obs or exp))
        for k in ("cpe", "matched_rule", "detail"):
            if ev.get(k) not in (None, ""):
                if k == "detail" and prop and not stated:
                    parts.append(f"{prop} — {ev.get(k)}")
                else:
                    parts.append(f"{k}: {ev.get(k)}")
    risk = f.get("risk") if isinstance(f.get("risk"), dict) else {}
    if isinstance(risk, dict) and risk.get("risk_score") is not None:
        parts.append(f"risk score {risk.get('risk_score')}")
    return "; ".join(str(p)[:220] for p in parts if p)


def _remediation_hint(f: Dict[str, Any]) -> str:
    if str(f.get("status", "")).upper() == "PASS":
        return "No action required — retain the current configuration."
    rem = f.get("remediation") if isinstance(f.get("remediation"), dict) else {}
    if not isinstance(rem, dict):
        return "Remediate per the vendor hardening guide, then re-run the audit to verify."
    detail = rem.get("detail") if isinstance(rem.get("detail"), dict) else {}
    for k in ("commands", "fix_commands", "steps"):
        v = (detail or {}).get(k)
        if isinstance(v, list) and v:
            return "; ".join(str(c) for c in v[:3])[:300]
    if isinstance(detail, dict) and detail.get("recommendation"):
        return str(detail["recommendation"])[:300]
    if rem.get("fixed_version"):
        return f"Upgrade to vendor-validated release {rem.get('fixed_version')}, then re-run the audit."
    if rem.get("migration"):
        return str(rem.get("migration"))[:300]
    return "Remediate per framework guidance and the vendor hardening guide, then re-run the audit."


# ------------------------------------------------------------ PDF builder ---
def _build_pdf(audit: dict, *, report_id: str, sections: List[str]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, PageBreak, HRFlowable, KeepTogether)

    has = lambda s: s in sections  # noqa: E731

    audit_id = str(audit.get("audit_id", ""))
    asset_id = str(audit.get("asset_id", ""))
    asset = db.get("assets", asset_id) or {} if asset_id else {}
    vend = audit.get("vendor") or {}
    if not isinstance(vend, dict):
        vend = {}
    s = audit.get("summary") or {}
    if not isinstance(s, dict):
        s = {}
    cve = audit.get("cve") or {}
    if not isinstance(cve, dict):
        cve = {}
    cve_sum = cve.get("summary") or {}
    if not isinstance(cve_sum, dict):
        cve_sum = {}
    pqc = audit.get("pqc") or {}
    if not isinstance(pqc, dict):
        pqc = {}
    sec = audit.get("security") or {}
    if not isinstance(sec, dict):
        sec = {}
    by_fw = audit.get("by_framework") or {}
    if not isinstance(by_fw, dict):
        by_fw = {}
    compliance = audit.get("compliance") or {}
    if not isinstance(compliance, dict):
        compliance = {}
    findings = [f for f in (audit.get("findings") or []) if isinstance(f, dict)]
    versions = audit.get("versions") or {}
    stages = audit.get("stages") or {}

    score = _num(s.get("compliance_score", compliance.get("compliance_score", 0)))
    crit = _int(s.get("CRITICAL", 0)); high = _int(s.get("HIGH", 0))
    med = _int(s.get("MEDIUM", 0)); low = _int(s.get("LOW", 0))
    total = _int(s.get("total", len(findings))) or len(findings)
    passed = _int(s.get("passed", compliance.get("passed", 0)))
    failed = _int(s.get("failed", crit + high + med + low))
    rating, rating_color = _risk_rating(score, crit, high)
    pqc_score = _num(pqc.get("readiness_score", pqc.get("readiness", 0)))
    pqc_label = _txt(pqc.get("readiness_label", "—"))
    sec_score = _num(sec.get("risk_score", 0))
    cve_vuln = _int(cve_sum.get("vulnerable", 0)); cve_ok = _int(cve_sum.get("not_affected", 0))
    cve_unk = _int(cve_sum.get("unknown", 0))
    gen_date = _dt.datetime.now().strftime("%d %B %Y")
    gen_stamp = _dt.datetime.now().strftime("%d %B %Y, %H:%M")
    asset_name = _txt(asset.get("name", asset_id), asset_id or "—")
    vendor_name = _txt(vend.get("vendor_id", vend.get("vendor", asset.get("vendor", ""))), "unknown")
    platform = _txt(vend.get("platform", asset.get("product", "")), "—")
    version = _txt(vend.get("version", asset.get("version", "")), "—")
    target_line = f"{asset_name} — {vendor_name} {platform} {version}".strip()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            title=f"Network Security Compliance Audit Report - {audit_id}",
                            author="SIH-26155 auditor")
    W = A4[0] - 30 * mm
    ss = getSampleStyleSheet()

    # -- type system: Times narrative, Helvetica structure -----------------
    st_title = ParagraphStyle("RTitle", parent=ss["Title"], fontName="Helvetica-Bold",
                              fontSize=25, leading=29, textColor=colors.HexColor(INK),
                              alignment=TA_CENTER, spaceAfter=3)
    st_kicker = ParagraphStyle("RKick", parent=ss["Normal"], fontName="Helvetica-Bold",
                               fontSize=8, leading=11, textColor=colors.HexColor(PRIMARY),
                               alignment=TA_CENTER, spaceAfter=5)
    st_sub = ParagraphStyle("RSub", parent=ss["Normal"], fontName="Helvetica",
                            fontSize=9, leading=13, textColor=colors.HexColor(MUTED),
                            alignment=TA_CENTER)
    st_h1 = ParagraphStyle("RH1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                           fontSize=13, leading=16, textColor=colors.HexColor(INK),
                           spaceBefore=16, spaceAfter=2, keepWithNext=True)
    st_h1num = f'<font color="{PRIMARY}">'
    st_h2 = ParagraphStyle("RH2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                           fontSize=10.5, leading=14, textColor=colors.HexColor(INK),
                           spaceBefore=11, spaceAfter=4, keepWithNext=True)
    st_h3 = ParagraphStyle("RH3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                           fontSize=9.5, leading=12.5, textColor=colors.HexColor(INK),
                           spaceBefore=8, spaceAfter=3, keepWithNext=True)
    st_body = ParagraphStyle("RBody", parent=ss["Normal"], fontName="Times-Roman",
                             fontSize=9.5, leading=14.5, textColor=colors.HexColor(INK),
                             alignment=TA_LEFT, spaceAfter=5)
    st_small = ParagraphStyle("RSm", parent=ss["Normal"], fontName="Helvetica",
                              fontSize=7.8, leading=11, textColor=colors.HexColor(MUTED),
                              alignment=TA_LEFT, spaceAfter=3)
    st_cell = ParagraphStyle("RCell", parent=ss["Normal"], fontName="Helvetica",
                             fontSize=8, leading=10.5, textColor=colors.HexColor(INK))
    st_cell_h = ParagraphStyle("RCellH", parent=st_cell, fontName="Helvetica-Bold")
    st_term = ParagraphStyle("RTerm", parent=st_cell, fontName="Helvetica-Bold")
    st_cap = ParagraphStyle("RCap", parent=ss["Normal"], fontName="Helvetica-Oblique",
                            fontSize=7.5, leading=10, textColor=colors.HexColor(MUTED),
                            alignment=TA_LEFT, spaceBefore=3, spaceAfter=6)
    st_toc = ParagraphStyle("RToc", parent=ss["Normal"], fontName="Helvetica",
                            fontSize=9, leading=13, textColor=colors.HexColor(INK))
    st_cover_meta = ParagraphStyle("RCov", parent=ss["Normal"], fontName="Helvetica",
                                   fontSize=8.5, leading=12, textColor=colors.HexColor(MUTED),
                                   alignment=TA_CENTER)
    st_right = ParagraphStyle("RRight", parent=st_cell, alignment=TA_RIGHT)
    st_pill = ParagraphStyle("Pill", parent=ss["Normal"], fontName="Helvetica-Bold",
                             fontSize=7, leading=9, textColor=colors.white,
                             alignment=TA_CENTER)

    story: list = []
    table_no = [0]

    def p(*a: str) -> Paragraph:
        return Paragraph("<br/>".join(a), st_cell)

    def caption(text: str):
        table_no[0] += 1
        story.append(Paragraph(f"Table {table_no[0]} &nbsp;—&nbsp; {text}", st_cap))

    def grid_table(rows: List[list], widths: List[float] | None = None,
                   fontsize: float = 8) -> Table:
        """Quiet data table: slate header, hairline grid, no zebra."""
        t = Table(rows, repeatRows=1, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(HEAD_BG)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(INK)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), fontsize),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER)),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
        return t

    def def_table(pairs: List[tuple], term_w: float = 46 * mm) -> Table:
        """Header-less definition table: bold terms, hairline row rules."""
        rows = [[Paragraph(f"<b>{k}</b>", st_term), Paragraph(v, st_cell)]
                for k, v in pairs]
        t = Table(rows, colWidths=[term_w, W - term_w])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor(BORDER)),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2)]))
        return t

    from reportlab.graphics.shapes import Drawing, Rect

    def bar_drawing(frac: float, color: str, total_w: float = 52 * mm,
                    height: float = 3.2 * mm) -> Drawing:
        """Proportional bar as a vector Drawing — safe inside table cells
        (nested Tables in cells break the platypus layout engine)."""
        frac = max(0.0, min(1.0, frac))
        fill = frac * total_w
        if 0 < frac and fill < 2 * mm:
            fill = 2 * mm
        d = Drawing(total_w, height)
        d.add(Rect(0, 0, total_w, height, fillColor=colors.HexColor(TRACK),
                   strokeColor=None, strokeWidth=0))
        if fill > 0:
            d.add(Rect(0, 0, fill, height, fillColor=colors.HexColor(color),
                       strokeColor=None, strokeWidth=0))
        return d

    def sev_bars(counts: Dict[str, int], total_w: float = 52 * mm):
        peak = max([1] + list(counts.values()))
        rows = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = counts.get(sev, 0)
            col = _sev_color(sev)
            rows.append([Paragraph(f'<font color="{col}"><b>{_sev_display(sev)}</b></font>', st_cell),
                         bar_drawing(n / peak, col, total_w),
                         Paragraph(f"<b>{n}</b>", st_cell)])
        t = Table(rows, colWidths=[30 * mm, total_w + 4 * mm, 14 * mm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 2),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        story.append(t)
        story.append(Paragraph("Bars are scaled to the largest value in each chart.", st_small))

    def section_head(number: int, title: str):
        story.append(Paragraph(f"{st_h1num}{number}</font>&nbsp;&nbsp;{title}", st_h1))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor(BORDER), spaceAfter=5, spaceBefore=0))

    # -- section plan (dynamic numbering; cross-refs always correct) --------
    plan: List[tuple] = []
    if has("EXECUTIVE_SUMMARY"):
        plan.append(("EXEC", "Executive summary"))
    plan.append(("METHOD", "Scope and methodology"))
    if has("DEVICE"):
        plan.append(("DEVICE", "Asset inventory"))
    if has("COMPLIANCE"):
        plan.append(("COMPL", "Compliance posture"))
    if has("CVE"):
        plan.append(("CVE", "Vulnerability management"))
    if has("PQC"):
        plan.append(("PQC", "Cryptography and post-quantum readiness"))
    if has("SECURITY"):
        plan.append(("SEC", "Security analytics"))
    plan.append(("FIND", "Detailed findings register"))
    if has("REMEDIATION"):
        plan.append(("REM", "Prioritized remediation roadmap"))
    if has("EVIDENCE"):
        plan.append(("EVI", "Evidence appendix"))
    plan.append(("CLOSE", "Disclaimer and sign-off"))
    S = {k: i + 1 for i, (k, _t) in enumerate(plan)}

    # ================= COVER (page 1, banner chrome only) =================
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("Network security &nbsp;·&nbsp; Configuration audit", st_kicker))
    story.append(Paragraph("Compliance Audit Report", st_title))
    story.append(Paragraph(target_line, st_sub))
    story.append(Paragraph(f"Audit {audit_id} &nbsp;·&nbsp; Report {report_id} &nbsp;·&nbsp; {gen_date}", st_sub))
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Assessment at a glance", st_h2))
    sev_counts = {"CRITICAL": crit, "HIGH": high, "MEDIUM": med, "LOW": low}
    story.append(def_table([
        ("Overall risk",
         f'<font color="{rating_color}"><b>{rating}</b></font> — {failed} of {total} checks failed'),
        ("Compliance score", f"{score:.1f}% of evaluated controls passing"),
        ("Failed findings",
         f"{crit} critical · {high} high · {med} medium · {low} low"),
        ("Known vulnerabilities",
         f"{_pl(cve_vuln, 'vulnerable component')}, {cve_ok} not affected, {cve_unk} unknown"),
        ("Quantum readiness", f"{pqc_score:.1f} / 100 — {pqc_label}"),
        ("Security posture", f"{sec_score:.0f} / 100 (100 is clean)"),
    ]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Engagement record", st_h2))
    story.append(def_table([
        ("Report / audit", f"{report_id} &nbsp;/&nbsp; {audit_id}"),
        ("Asset", f"{asset_name} ({asset_id})"),
        ("Target", f"{vendor_name} {platform}, software {version}"),
        ("Frameworks", ", ".join(audit.get("frameworks") or ["CIS", "NIST", "STIG", "ISO27001"])),
        ("Evidence", f"Uploaded device configuration (SHA-256 {str(audit.get('config_sha256', '—'))[:24]}…)"),
        ("Classification", "Internal — distribution controlled"),
    ]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "This report records the findings of an offline audit of the configuration stated above. "
        "Section 1 summarises the outcome for decision-makers; the domain assessments, the full "
        "findings register and the sequenced remediation plan follow. No live system was touched "
        "during this assessment.", st_body))

    # ================= ABOUT + CONTENTS =================
    story.append(PageBreak())
    story.append(Paragraph("About this report", st_h2))
    story.append(def_table([
        ("Version", "1.0 (initial issue)"),
        ("Date issued", gen_stamp),
        ("Prepared by", "SIH-26155 automated auditor — configuration analysis only"),
        ("Review status", "Pending human review; remediation requires approval before use"),
        ("Classification", "Internal — distribution controlled"),
        ("Retention", "Retain with the audit record; re-issue after each re-audit"),
    ]))
    story.append(Paragraph("Contents", st_h2))
    toc_rows = []
    for i, (k, title) in enumerate(plan, 1):
        toc_rows.append([Paragraph(f"{st_h1num}<b>{i}</b></font>", st_toc),
                         Paragraph(title, st_toc)])
    toc = Table(toc_rows, colWidths=[10 * mm, W - 10 * mm])
    toc.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                             ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor(BORDER)),
                             ("TOPPADDING", (0, 0), (-1, -1), 3),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                             ("LEFTPADDING", (0, 0), (-1, -1), 2)]))
    story.append(toc)
    omitted = [t for t in ALLOWED_SECTIONS if t not in sections]
    if omitted:
        story.append(Paragraph(
            "Excluded from this issue at request: " +
            ", ".join(o.replace("_", " ").title() for o in omitted) + ".", st_small))
    story.append(Paragraph("Reading guide", st_h3))
    story.append(Paragraph(
        "Section 1 is written for leadership and states the risk in one page. The domain sections "
        "give the evidence behind that verdict. The findings register is authoritative: every finding "
        "carries its severity, status, observed evidence and recommended action. Severity follows a "
        "four-level scale — Critical (exploitable now or exposed), High (direct security impact), "
        "Medium (hardening gap), Low (hygiene).", st_body))

    # ================= 1 EXECUTIVE SUMMARY =================
    if has("EXECUTIVE_SUMMARY"):
        section_head(S["EXEC"], "Executive summary")
        story.append(Paragraph(
            f"The audited configuration of <b>{asset_name}</b> ({vendor_name} {platform} {version}) "
            f"is <b>{score:.1f}% compliant</b> across {total} evaluated checks, with an overall risk "
            f"rating of <b>{rating.lower()}</b>. {_pl(failed, 'check')} failed — {crit} critical, {high} high, "
            f"{med} medium and {low} low — alongside {_pl(cve_vuln, 'vulnerable software component')}. "
            f"Post-quantum readiness stands at {pqc_score:.1f} out of 100 ({pqc_label.lower()}); the "
            f"security-analytics posture score is {sec_score:.0f} out of 100.", st_body))
        story.append(Paragraph(
            "The highest priority is to remove cleartext administration and internet-facing exposure, "
            "apply the vendor security releases listed in the vulnerability section, and replace "
            "deprecated cryptography. The remaining compliance gaps and the phased post-quantum "
            "migration can then proceed in the order given in the remediation roadmap.", st_body))
        story.append(Paragraph("Findings by severity (failed checks)", st_h2))
        sev_bars(sev_counts)
        fails = sorted([f for f in findings if str(f.get("status", "")).upper() == "FAIL"],
                       key=lambda f: (_sev_order_key(f.get("severity")), str(f.get("finding_id"))))
        story.append(Paragraph("Findings requiring management attention", st_h2))
        if fails:
            rows = [[Paragraph("<b>Severity</b>", st_cell_h),
                     Paragraph("<b>Finding</b>", st_cell_h),
                     Paragraph("<b>Reference</b>", st_cell_h)]]
            for f in fails[:8]:
                col = _sev_color(f.get("severity"))
                ref = (f.get("control_id") or
                       ((f.get("source") or {}).get("cve", "") if isinstance(f.get("source"), dict) else "") or
                       str(f.get("finding_id", "")))
                rows.append([Paragraph(f'<font color="{col}"><b>{_sev_display(f.get("severity"))}</b></font>', st_cell),
                             p(f"{_txt(f.get('title'), '—')}"[:140]),
                             p(str(ref)[:28])])
            story.append(grid_table(rows, [28 * mm, W - 62 * mm, 34 * mm]))
            shown = min(8, len(fails))
            caption((f"the {shown} failed findings" if shown == len(fails) else
                     f"the {shown} most severe of {len(fails)} failed findings")
                    + f"; the full register is in section {S['FIND']}, the execution order in section "
                    + f"{S.get('REM', S['FIND'])}.")
        else:
            story.append(Paragraph("No failed findings. The audited configuration meets every evaluated "
                                   "control; maintain continuous monitoring and re-audit after each change.", st_body))

    # ================= SCOPE & METHODOLOGY =================
    section_head(S["METHOD"], "Scope and methodology")
    story.append(Paragraph(
        "The assessment is an offline analysis of a single uploaded device configuration. The auditor "
        "parses the configuration into a canonical model, evaluates framework control packs "
        "(CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001), correlates the software inventory against "
        "the vulnerability knowledge base, assesses the cryptographic inventory for post-quantum "
        "readiness, and applies security-analytics rules for posture issues such as weak authentication, "
        "exposure, permissive access rules, legacy services and logging gaps. No live device was "
        "contacted; runtime and telemetry state are outside the scope of this report.", st_body))
    story.append(Paragraph(
        "Controls that cannot apply to this vendor and platform evaluate to <i>not applicable</i> and "
        "are excluded from scoring rather than counted as passes or failures.", st_body))
    if by_fw:
        story.append(Paragraph("Frameworks in scope", st_h2))
        rows = [[Paragraph("<b>Framework</b>", st_cell_h),
                 Paragraph("<b>Compliance</b>", st_cell_h),
                 Paragraph("", st_cell_h),
                 Paragraph("<b>Passed / failed / total</b>", st_cell_h)]]
        peak = max([1] + [_num((v or {}).get("compliance_score", 0)) for v in by_fw.values()])
        for fw, v in by_fw.items():
            v = v or {}
            sc = _num(v.get("compliance_score", 0))
            rows.append([p(str(fw)), p(f"{sc:.1f}%"), bar_drawing(sc / 100, PRIMARY),
                         p(f"{_int(v.get('passed', 0))} / {_int(v.get('failed', 0))} / {_int(v.get('total', 0))}")])
        story.append(grid_table(rows, [30 * mm, 22 * mm, 56 * mm, W - 108 * mm]))
        caption("framework coverage; bars share a common 0–100 scale.")
    story.append(Paragraph("Provenance of this assessment", st_h2))
    story.append(def_table([
        ("Pipeline", ", ".join(f"{k} {v}" for k, v in (stages or {}).items()) or "—"),
        ("Knowledge versions", ", ".join(f"{k} {v}" for k, v in (versions or {}).items()) or "—"),
        ("Configuration SHA-256", _txt(audit.get("config_sha256", "—"))),
        ("Analysis duration", f"{_txt(audit.get('duration_s', '—'))} seconds"),
    ]))

    # ================= ASSET =================
    if has("DEVICE"):
        section_head(S["DEVICE"], "Asset inventory")
        story.append(Paragraph(
            "The system under assessment, as recorded in the asset inventory and as detected from "
            "the configuration itself. Discrepancies between recorded and detected values should be "
            "reconciled by the asset owner.", st_body))
        story.append(def_table([
            ("Asset ID", asset_id or "—"),
            ("Name", _txt(asset.get("name", ""))),
            ("Vendor (recorded)", _txt(asset.get("vendor", ""))),
            ("Product / model", f"{_txt(asset.get('product', ''))} / {_txt(asset.get('model', ''))}"),
            ("Software (recorded)", _txt(asset.get("version", ""))),
            ("Serial", _txt(asset.get("serial_number", ""))),
            ("Management address", _txt(asset.get("ip_address", ""))),
            ("Environment", _txt(asset.get("environment", ""))),
            ("Criticality", _txt(asset.get("criticality", ""))),
            ("Detected", f"{vendor_name} {platform}, software {version}"),
            ("Configuration", _txt(audit.get("configuration_id", "—"))),
        ]))

    # ================= COMPLIANCE =================
    if has("COMPLIANCE"):
        section_head(S["COMPL"], "Compliance posture")
        story.append(Paragraph(
            f"Overall compliance is <b>{score:.1f}%</b> over {total} evaluated checks ({passed} passed, "
            f"{failed} failed). The per-framework view and the failed-control register follow; passing "
            f"controls are listed in the findings register in section {S['FIND']}.", st_body))
        comp_fails = [f for f in findings
                      if str(f.get("engine", "")).lower() == "compliance"
                      and str(f.get("status", "")).upper() == "FAIL"]
        comp_fails.sort(key=lambda f: (_sev_order_key(f.get("severity")), str(f.get("control_id"))))
        story.append(Paragraph(f"Failed controls ({len(comp_fails)})", st_h2))
        if comp_fails:
            rows = [[Paragraph("<b>Control</b>", st_cell_h),
                     Paragraph("<b>Severity</b>", st_cell_h),
                     Paragraph("<b>Requirement</b>", st_cell_h),
                     Paragraph("<b>Observed</b>", st_cell_h)]]
            for f in comp_fails[:60]:
                col = _sev_color(f.get("severity"))
                ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
                obs = ""
                if isinstance(ev, dict):
                    obs = f"{ev.get('property', '')}: {ev.get('observed_value', ev.get('observed', ''))}"[:110]
                rows.append([p(str(f.get("control_id", f.get("finding_id", "—")))),
                             Paragraph(f'<font color="{col}"><b>{_sev_display(f.get("severity"))}</b></font>', st_cell),
                             p(_txt(f.get("title"))[:130]), p(obs or "—")])
            story.append(grid_table(rows, [26 * mm, 24 * mm, W - 100 * mm, 50 * mm], fontsize=7.5))
            if len(comp_fails) > 60:
                caption(f"first 60 of {len(comp_fails)} failed controls; the remainder appear in section {S['FIND']}.")
        else:
            story.append(Paragraph("No failed compliance controls.", st_body))

    # ================= CVE =================
    if has("CVE"):
        section_head(S["CVE"], "Vulnerability management")
        story.append(Paragraph(
            f"Correlation of the detected software inventory against the vulnerability knowledge base "
            f"found <b>{_pl(cve_vuln, 'vulnerable component')}</b>, {cve_ok} unaffected and {cve_unk} unknown. "
            "Each entry below states the assessed severity with its CVSS reference where available, the "
            "installed release, and the remediating release if one is known.", st_body))
        matches = cve.get("matches") or []
        if not isinstance(matches, list):
            matches = []
        if matches:
            rows = [[Paragraph("<b>Advisory</b>", st_cell_h),
                     Paragraph("<b>Severity (CVSS)</b>", st_cell_h),
                     Paragraph("<b>Installed</b>", st_cell_h),
                     Paragraph("<b>Remediation</b>", st_cell_h)]]
            for m in matches[:50]:
                if not isinstance(m, dict):
                    continue
                cvss = m.get("cvss") or {}
                sev_txt = _sev_display((cvss or {}).get("severity", m.get("severity", "")))
                cvss_sc = (cvss or {}).get("score", "")
                col = _sev_color((cvss or {}).get("severity", m.get("severity", "")))
                inst = f"{_txt(m.get('product', ''), '')} {_txt(m.get('installed_version', ''), '')}".strip() or "—"
                fix = _txt(m.get("fixed_version", ""), "no fixed release in knowledge base")
                rows.append([p(_txt(m.get("cve_id", "—"))),
                             Paragraph(f'<font color="{col}"><b>{sev_txt}</b></font>'
                                       + (f" ({cvss_sc})" if cvss_sc not in ("", None) else ""), st_cell),
                             p(inst[:60]),
                             p(f"{_txt(m.get('status', '—'))} — upgrade to {fix}"[:90])])
            story.append(grid_table(rows, [34 * mm, 32 * mm, W - 108 * mm, 42 * mm], fontsize=7.5))
            caption(f"correlated advisories ({len(matches)}"
                    + ("" if len(matches) <= 50 else "; first 50 shown")
                    + "); verify critical entries against vendor advisories before acting.")
            if len(matches) > 50:
                story.append(Paragraph(f"A further {len(matches) - 50} matches are available through the API; "
                                       "prioritise by severity and exposure.", st_small))
        else:
            story.append(Paragraph("No advisories correlate with the detected inventory. This reflects the "
                                   "knowledge-base snapshot at audit time, not proof of absence — verify "
                                   "critical services against current vendor advisories.", st_body))
        unresolved = cve.get("unresolved") or []
        if isinstance(unresolved, list) and unresolved:
            names = ", ".join(str(u.get("product", u))[:40] for u in unresolved[:10]
                              if isinstance(u, dict))
            story.append(Paragraph(f"Inventory without a knowledge-base entry ({len(unresolved)}): "
                                   f"{names}.", st_small))

    # ================= PQC =================
    if has("PQC"):
        section_head(S["PQC"], "Cryptography and post-quantum readiness")
        counts = pqc.get("counts") or {}
        if not isinstance(counts, dict):
            counts = {}
        story.append(Paragraph(
            f"Readiness is scored <b>{pqc_score:.1f} out of 100</b> ({pqc_label.lower()}). "
            "<i>Migration required</i> marks cryptography that is already deprecated and must be replaced "
            "regardless of quantum timelines. <i>Transition</i> marks cryptography that is sound today but "
            "will not survive a large quantum computer — key exchange in this class should move to hybrid "
            "post-quantum algorithms (ML-KEM) promptly because recorded traffic can be decrypted later, "
            "while signatures (ML-DSA) follow as product support arrives. "
            "Industry milestones per NIST IR 8547: deprecate after 2030, disallow after 2035.", st_body))
        story.append(def_table([
            ("Ready", f"{_int(counts.get('READY', 0))} — post-quantum or hybrid algorithms present"),
            ("Transition", f"{_int(counts.get('TRANSITION', 0))} — plan hybrid migration"),
            ("Migration required", f"{_int(counts.get('MIGRATION_REQUIRED', 0))} — replace without delay"),
            ("Unknown", f"{_int(counts.get('UNKNOWN', 0))} — no cryptographic signal in the configuration"),
        ]))
        algos = pqc.get("algorithms") or []
        if not isinstance(algos, list):
            algos = []
        if algos:
            story.append(Spacer(1, 3 * mm))
            rows = [[Paragraph("<b>Component</b>", st_cell_h),
                     Paragraph("<b>Area</b>", st_cell_h),
                     Paragraph("<b>Assessment</b>", st_cell_h),
                     Paragraph("<b>Direction</b>", st_cell_h)]]
            for a in algos[:40]:
                if not isinstance(a, dict):
                    continue
                label, col = _pqc_display(a.get("pqc_status"))
                rows.append([p(f"{_txt(a.get('algorithm', '—'))}"[:90]),
                             p(_txt(a.get("protocol", "—"))[:36]),
                             Paragraph(f'<font color="{col}"><b>{label}</b></font>', st_cell),
                             p(_txt(a.get("migration", a.get("recommended", "—")) )[:110])])
            story.append(grid_table(rows, [W - 96 * mm, 26 * mm, 30 * mm, 40 * mm], fontsize=7.5))
            caption("cryptographic inventory as observed; full migration notes accompany each entry in the source data.")
            if len(algos) > 40:
                story.append(Paragraph(f"A further {len(algos) - 40} inventory rows are available through the API.", st_small))
        recs = pqc.get("migration_recommendations") or []
        if isinstance(recs, list) and recs:
            story.append(Paragraph("Migration priorities", st_h2))
            for r in recs[:10]:
                if isinstance(r, dict):
                    story.append(Paragraph(
                        f"<b>{_txt(r.get('algorithm', 'Cryptography'))}</b> "
                        f"({_txt(r.get('protocol', ''), '')}; {_txt(r.get('priority', 'planned'), '')}) — "
                        f"{_txt(r.get('recommended_direction', r.get('migration', '')))}"[:320],
                        ParagraphStyle("RBul", parent=st_body, leftIndent=10, spaceAfter=2),
                        bulletText="–"))

    # ================= SECURITY =================
    if has("SECURITY"):
        section_head(S["SEC"], "Security analytics")
        anoms = sec.get("anomalies") or []
        if not isinstance(anoms, list):
            anoms = []
        patterns = sec.get("patterns") or []
        if not isinstance(patterns, list):
            patterns = []
        story.append(Paragraph(
            f"The posture score is <b>{sec_score:.0f} out of 100</b>, derived from "
            f"{_pl(len(anoms), 'observation')}"
            f"{f' and {_pl(len(patterns), 'correlated pattern')}' if patterns else ''}. "
            "These rules describe posture weaknesses — weak authentication, exposure, permissive rules, "
            "legacy services and logging gaps — and are distinct from framework verdicts, so an item may "
            "appear here and as a failed control.", st_body))
        if anoms:
            rows = [[Paragraph("<b>Observation</b>", st_cell_h),
                     Paragraph("<b>Location</b>", st_cell_h),
                     Paragraph("<b>Severity</b>", st_cell_h),
                     Paragraph("<b>Detail</b>", st_cell_h)]]
            for a in anoms[:50]:
                if not isinstance(a, dict):
                    continue
                col = _sev_color(a.get("severity"))
                rows.append([p(_txt(a.get("type", "—")).replace("_", " ").title()),
                             p(_txt(a.get("property", "—"))),
                             Paragraph(f'<font color="{col}"><b>{_sev_display(a.get("severity"))}</b></font>', st_cell),
                             p(_txt(a.get("detail", "—"))[:120])])
            story.append(grid_table(rows, [30 * mm, 44 * mm, 24 * mm, W - 98 * mm], fontsize=7.5))
            caption(f"security observations ({len(anoms)}"
                    + ("" if len(anoms) <= 50 else "; first 50 shown") + ").")
            if len(anoms) > 50:
                story.append(Paragraph(f"A further {len(anoms) - 50} observations are listed in section {S['FIND']}.", st_small))
        for pat in patterns:
            if isinstance(pat, dict):
                story.append(Paragraph(
                    f"Correlated pattern — <b>{_txt(pat.get('pattern', '—'))}</b> "
                    f"({_sev_display(pat.get('severity', ''))}): {_txt(pat.get('detail', ''))}"[:350],
                    ParagraphStyle("PBul", parent=st_body, leftIndent=10, spaceAfter=2),
                    bulletText="–"))

    # ================= FINDINGS REGISTER =================
    section_head(S["FIND"], "Detailed findings register")
    by_sev: Dict[str, list] = {}
    for f in findings:
        by_sev.setdefault(str(f.get("severity", "UNKNOWN")).upper(), []).append(f)
    story.append(Paragraph(
        f"This register is the authoritative record of all {len(findings)} findings. Entries are ordered "
        "with failures first, critical first. Each entry states the severity, the verdict, the control or "
        "advisory reference, the observed evidence and the recommended action.", st_body))
    dist = [[Paragraph("<b>Severity</b>", st_cell_h),
             Paragraph("<b>Failed</b>", st_cell_h),
             Paragraph("<b>Passed</b>", st_cell_h),
             Paragraph("<b>Total</b>", st_cell_h)]]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        items = by_sev.get(sev, [])
        fails_n = sum(1 for f in items if str(f.get("status", "")).upper() == "FAIL")
        pass_n = sum(1 for f in items if str(f.get("status", "")).upper() == "PASS")
        dist.append([Paragraph(f'<font color="{_sev_color(sev)}"><b>{_sev_display(sev)}</b></font>', st_cell),
                     p(str(fails_n)), p(str(pass_n)), p(str(len(items)))])
    story.append(grid_table(dist, [W - 60 * mm, 20 * mm, 20 * mm, 20 * mm]))
    caption("register composition by severity and verdict.")

    def finding_block(f: Dict[str, Any], idx: int):
        """One flat table per finding — no nested tables (platypus cannot
        reliably lay out tables nested inside table cells)."""
        col = _sev_color(f.get("severity"))
        status = str(f.get("status", "—")).upper()
        status_txt = {"FAIL": "Fail", "PASS": "Pass"}.get(status, status.title())
        status_col = DANGER if status == "FAIL" else (OK if status == "PASS" else MUTED)
        ref = (f.get("control_id") or
               ((f.get("source") or {}).get("cve", "") if isinstance(f.get("source"), dict) else "") or
               str(f.get("finding_id", "")))
        engine = _engine_display(f)
        conf = f.get("confidence", "")
        try:
            conf_txt = f" · confidence {float(conf):.2f}" if conf not in ("", None) else ""
        except (TypeError, ValueError):
            conf_txt = ""
        meta_txt = (f"{_txt(f.get('finding_id', ''), '')}"
                    + (f" &nbsp;·&nbsp; {ref}" if ref and ref != f.get("finding_id") else "")
                    + (f" &nbsp;·&nbsp; {engine}" if engine else "")
                    + conf_txt)
        obs = _finding_summary_text(f)
        data = [[Paragraph("", st_cell),
                 Paragraph(f"<b>{_sev_display(f.get('severity'))}</b>", st_pill),
                 Paragraph(f"<b>{idx}. &nbsp;{_txt(f.get('title'), 'Untitled finding')}</b>", st_cell),
                 Paragraph(f'<font color="{status_col}"><i>{status_txt}</i></font>', st_right)],
                [Paragraph("", st_cell), Paragraph(meta_txt, st_small), "", ""]]
        if obs and obs != "—":
            data.append([Paragraph("", st_cell),
                         Paragraph(f"<b>Observation.</b> {obs}"[:520], st_small), "", ""])
        data.append([Paragraph("", st_cell),
                     Paragraph(f"<b>Recommendation.</b> {_txt(_remediation_hint(f), '—')}"[:440], st_small),
                     "", ""])
        last = len(data) - 1
        span = [("SPAN", (1, r), (3, r)) for r in range(1, len(data))]
        outer = Table(data, colWidths=[1.8 * mm, 22 * mm, W - 51.8 * mm, 28 * mm])
        outer.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, last), colors.HexColor(col)),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(col)),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (0, last), 0),
            ("RIGHTPADDING", (0, 0), (0, last), 0),
            ("LEFTPADDING", (1, 0), (-1, -1), 4),
            ("RIGHTPADDING", (1, 0), (-1, -1), 4),
        ] + span))
        return KeepTogether(outer)

    ordered = sorted(findings, key=lambda f: (
        0 if str(f.get("status", "")).upper() == "FAIL" else 1,
        _sev_order_key(f.get("severity")), str(f.get("finding_id"))))
    MAX_DETAIL = 50
    for i, f in enumerate(ordered[:MAX_DETAIL], 1):
        story.append(finding_block(f, i))
        story.append(Spacer(1, 2.5 * mm))
    if len(ordered) > MAX_DETAIL:
        rest = ordered[MAX_DETAIL:MAX_DETAIL + 100]
        story.append(Paragraph(f"Further findings ({len(ordered) - MAX_DETAIL} summarised)", st_h2))
        rows = [[Paragraph("<b>Reference</b>", st_cell_h),
                 Paragraph("<b>Severity</b>", st_cell_h),
                 Paragraph("<b>Verdict</b>", st_cell_h),
                 Paragraph("<b>Finding</b>", st_cell_h)]]
        for f in rest:
            col = _sev_color(f.get("severity"))
            rows.append([p(str(f.get("finding_id", "—"))),
                         Paragraph(f'<font color="{col}"><b>{_sev_display(f.get("severity"))}</b></font>', st_cell),
                         p(str(f.get("status", "—")).title()),
                         p(_txt(f.get("title"))[:110])])
        story.append(grid_table(rows, [28 * mm, 24 * mm, 22 * mm, W - 74 * mm], fontsize=7.5))
        if len(ordered) - MAX_DETAIL > 100:
            story.append(Paragraph("The remaining findings are available through the API.", st_small))

    # ================= REMEDIATION =================
    if has("REMEDIATION"):
        section_head(S["REM"], "Prioritized remediation roadmap")
        story.append(Paragraph(
            "Actions are sequenced by risk. Immediate items cover critical findings, exposed management "
            "services and deprecated cryptography; short-term items cover high-severity findings and "
            "advisories with known fixed releases; planned items cover remaining hygiene and the "
            "post-quantum transition. Every change follows propose, review, approve, apply in simulation, "
            "and validate by re-audit — a finding is closed only when a re-audit returns a passing verdict. "
            "Assign an owner and a target date to each action before work begins.", st_body))
        fails = sorted([f for f in findings if str(f.get("status", "")).upper() == "FAIL"],
                       key=lambda f: (_sev_order_key(f.get("severity")), str(f.get("finding_id"))))
        p1 = [f for f in fails if str(f.get("severity", "")).upper() == "CRITICAL"]
        p1 += [f for f in fails if f not in p1 and
               ("INTERNET" in str(f.get("title", "")).upper()
                or "EXPOS" in str(f.get("title", "")).upper())][:5]
        p2 = [f for f in fails if f not in p1 and str(f.get("severity", "")).upper() == "HIGH"]
        p3 = [f for f in fails if f not in p1 and f not in p2][:15]
        for band, window, items in [("P1", "Immediate — within 7 days", p1[:12]),
                                    ("P2", "Short term — within 4 weeks", p2[:12]),
                                    ("P3", "Planned — hygiene and transition", p3[:12])]:
            story.append(Paragraph(f"{band} &nbsp;·&nbsp; {window}", st_h2))
            if not items:
                story.append(Paragraph("No actions in this band.", st_body))
                continue
            rows = [[Paragraph("<b>Action</b>", st_cell_h),
                     Paragraph("<b>Finding</b>", st_cell_h),
                     Paragraph("<b>Recommended action</b>", st_cell_h),
                     Paragraph("<b>Owner / due</b>", st_cell_h)]]
            for j, f in enumerate(items, 1):
                rows.append([p(f"{band}-{j}"),
                             p(f"{_txt(f.get('finding_id'))} — {_txt(f.get('title'))}"[:120]),
                             p(_txt(_remediation_hint(f))[:160]),
                             p("—")])
            story.append(grid_table(rows, [16 * mm, W - 96 * mm, 56 * mm, 24 * mm], fontsize=7.5))
        story.append(Paragraph("Owner and due columns are completed by the receiving team on acceptance "
                               "of this report.", st_small))

    # ================= EVIDENCE =================
    if has("EVIDENCE"):
        section_head(S["EVI"], "Evidence appendix")
        story.append(Paragraph(
            "Supporting material for independent verification. Provenance links evaluated properties to "
            "their source lines in the uploaded configuration.", st_body))
        story.append(Paragraph("Configuration provenance (sample)", st_h2))
        prov = audit.get("provenance") or {}
        if isinstance(prov, dict) and prov:
            rows = [[Paragraph("<b>Property</b>", st_cell_h),
                     Paragraph("<b>Source line</b>", st_cell_h)]]
            for k in list(prov.keys())[:30]:
                v = prov.get(k) or {}
                line = v.get("line", "") if isinstance(v, dict) else str(v)
                no = v.get("line_no", "") if isinstance(v, dict) else ""
                rows.append([p(str(k)[:60]),
                             Paragraph(f"<font face='Courier' size='7.5'>{str(line)[:120]}</font>"
                                       + (f" &nbsp;<i>(line {no})</i>" if no else ""), st_cell)])
            story.append(grid_table(rows, [50 * mm, W - 50 * mm], fontsize=7.5))
            if len(prov) > 30:
                story.append(Paragraph(f"A further {len(prov) - 30} provenance entries are available through the API.", st_small))
        else:
            story.append(Paragraph("Provenance was not recorded for this audit.", st_body))
        story.append(Paragraph("Reproducibility", st_h2))
        story.append(def_table([
            ("Configuration SHA-256", _txt(audit.get("config_sha256", "—"))),
            ("Unparsed lines", str(len(audit.get("unknown_lines") or []))),
            ("Language-model assistance", "Not used — deterministic analysis" if audit.get("llm_offline", True) else "Assisted parsing enabled"),
            ("Knowledge versions", ", ".join(f"{k} {v}" for k, v in (versions or {}).items()) or "—"),
        ]))
        unk = audit.get("unknown_lines") or []
        if isinstance(unk, list) and unk:
            story.append(Paragraph("Unparsed configuration lines (sample — parser improvement queue)", st_h2))
            code_st = ParagraphStyle("Code", parent=ss["Normal"],
                                     fontName="Courier", fontSize=7.5, leading=11,
                                     textColor=colors.HexColor(INK), leftIndent=0,
                                     borderColor=colors.HexColor(BORDER), borderWidth=0.4,
                                     backColor=colors.HexColor("#F8FAFC"),
                                     borderPadding=(6, 6, 6))
            code_html = "<br/>".join(str(line)[:150].replace(" ", "&nbsp;") for line in unk[:15])
            story.append(Paragraph(code_html, code_st))
            if len(unk) > 15:
                story.append(Paragraph(f"A further {len(unk) - 15} unparsed lines are available through the API.", st_small))

    # ================= DISCLAIMER =================
    section_head(S["CLOSE"], "Disclaimer and sign-off")
    story.append(Paragraph(
        "This report reflects an automated analysis of the configuration as supplied at the time of the "
        "audit. It does not replace penetration testing, runtime verification or expert review. "
        "Vulnerability information reflects the knowledge-base snapshot at audit time and may lag upstream "
        "disclosures; confirm critical advisories against current vendor publications before acting. "
        "Recommended commands must be reviewed and approved by the responsible engineer, applied within a "
        "scheduled maintenance window and backed by a current configuration backup. The authors accept no "
        "responsibility for changes applied without that approval.", st_body))
    story.append(Spacer(1, 3 * mm))
    rule = '<u>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</u>'
    story.append(grid_table(
        [[Paragraph("<b>Role</b>", st_cell_h), Paragraph("<b>Signature</b>", st_cell_h),
          Paragraph("<b>Name (print)</b>", st_cell_h), Paragraph("<b>Date</b>", st_cell_h)],
         [p("Auditor (system)"), p("SIH-26155 automated auditor"), p("—"), p(gen_date)],
         [p("Reviewed by"), Paragraph(rule, st_cell), Paragraph(rule, st_cell), Paragraph(rule, st_cell)],
         [p("Approved by"), Paragraph(rule, st_cell), Paragraph(rule, st_cell), Paragraph(rule, st_cell)]],
        [30 * mm, 55 * mm, 55 * mm, 40 * mm]))

    # -- page furniture ------------------------------------------------------
    def _body_chrome(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor(BORDER))
        canvas.setLineWidth(0.5)
        canvas.line(15 * mm, A4[1] - 12 * mm, A4[0] - 15 * mm, A4[1] - 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.drawString(15 * mm, A4[1] - 10 * mm, "Network Security Compliance Audit Report")
        canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 10 * mm, f"{audit_id}  ·  Internal")
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(A4[0] / 2, 12 * mm,
                                 f"Page {doc_.page}  ·  {report_id}  ·  Internal — automated assessment, human approval required")
        canvas.restoreState()

    def _cover_chrome(canvas, doc_):
        canvas.saveState()
        for y in (A4[1] - 7 * mm, 13 * mm):
            canvas.setFillColor(colors.HexColor(PRIMARY))
            canvas.rect(0, y, A4[0], 7 * mm, stroke=0, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 7)
            canvas.drawCentredString(A4[0] / 2, y + 2.6 * mm,
                                     "INTERNAL  ·  DISTRIBUTION CONTROLLED")
        canvas.restoreState()

    doc.build(story, onFirstPage=_cover_chrome, onLaterPages=_body_chrome)
    return buf.getvalue()


# ----------------------------------------------------------------- routes ---
@router.post("")
def create_report(body: ReportBody):
    audit = db.get("audits", body.audit_id)
    if not audit:
        raise HTTPException(404, "Audit not found")
    if str(body.format or "").upper() != "PDF":
        raise HTTPException(400, "Only format='PDF' is supported")
    sections = _norm_sections(body.sections)
    ensure_reports_schema()
    rid = store.nid("REP")
    pdf = _build_pdf(audit, report_id=rid, sections=sections)
    download_url = f"/api/v1/reports/{rid}/download"
    db.save("reports", {"report_id": rid, "audit_id": body.audit_id, "status": "COMPLETED",
                        "format": "PDF", "sections": sections,
                        "download_url": download_url, "download_path": download_url,
                        "pdf": pdf, "created_at": store.now()})
    return cfg.ok({"report_id": rid, "status": "COMPLETED", "audit_id": body.audit_id,
                   "format": "PDF", "sections": sections,
                   "download_url": download_url}, "Report generated")


@router.get("")
def list_reports(limit: int = 50):
    try:
        rows = db.select("reports", ["report_id", "audit_id", "format", "status",
                                     "download_path", "data->'download_url' AS download_url",
                                     "data->'sections' AS sections",
                                     "data->'created_at' AS created_at"],
                         limit=max(1, min(int(limit), 200)))
    except Exception:
        rows = []
    items = [{"report_id": r.get("report_id"), "audit_id": r.get("audit_id"),
              "format": r.get("format", "PDF"), "status": r.get("status"),
              "sections": r.get("sections") or [],
              "download_url": r.get("download_url") or r.get("download_path"),
              "created_at": r.get("created_at")} for r in rows]
    return cfg.ok({"items": items, "total": len(items)})


@router.get("/{report_id}")
def get_report(report_id: str):
    r = db.get("reports", report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    url = r.get("download_url") or r.get("download_path") or f"/api/v1/reports/{report_id}/download"
    return cfg.ok({"report_id": report_id, "status": r.get("status", "COMPLETED"),
                   "audit_id": r.get("audit_id"), "format": r.get("format", "PDF"),
                   "sections": r.get("sections") or list(ALLOWED_SECTIONS),
                   "download_url": url, "created_at": r.get("created_at")})


@router.get("/{report_id}/download")
def download_report(report_id: str):
    r = db.get("reports", report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    pdf = r.get("pdf")
    if not pdf:
        raise HTTPException(500, "Report has no PDF bytes — regenerate it via POST /reports")
    data = bytes(pdf) if not isinstance(pdf, (bytes, bytearray)) else bytes(pdf)
    if not data.startswith(b"%PDF"):
        raise HTTPException(500, "Stored report bytes are corrupt — regenerate via POST /reports")
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={report_id}.pdf",
                             "Content-Length": str(len(data))})
