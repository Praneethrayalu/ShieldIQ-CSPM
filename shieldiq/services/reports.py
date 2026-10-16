"""Reports: executive PDF (ReportLab), CSV and JSON exports."""
import csv
import io
import json
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from ..rules import get_rule

INK = colors.HexColor("#151515")
ACCENT = colors.HexColor("#ff5a1f")
SEV_COL = {"critical": colors.HexColor("#ff5a1f"), "high": colors.HexColor("#b5651d"),
           "medium": colors.HexColor("#8f7a2a"), "low": colors.HexColor("#8a8a85")}


def _esc(s):
    return (str(s or "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_pdf(path: Path, org_name, score, findings, compliance, graph, framework=None, author="", coverage=None):
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], textColor=INK, fontSize=24, leading=28, alignment=0)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=ACCENT, spaceBefore=10)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#55554f"))
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"ShieldIQ report - {org_name}", author="ShieldIQ")
    el = [Paragraph("ShieldIQ Security Posture Report", h1),
          Paragraph(f"{_esc(org_name)} \u00b7 generated {datetime.now():%d %b %Y %H:%M} \u00b7 by {_esc(author)}"
                    + (f" \u00b7 focus: {_esc(compliance[framework]['name'])}" if framework and framework in compliance else ""), small),
          Spacer(1, 8)]
    active = [f for f in findings if f.status in ("open", "in_progress")]
    sev = {k: sum(1 for f in active if f.severity == k) for k in SEV_COL}
    kpi = Table([["Posture score", "Open findings", "Critical", "High", "Attack paths"],
                 [f"{score if score is not None else '-'}/100", len(active), sev["critical"], sev["high"], len(graph["paths"])]],
                colWidths=[36 * mm] * 5)
    kpi.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), INK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                             ("FONTSIZE", (0, 1), (-1, 1), 16), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                             ("TOPPADDING", (0, 1), (-1, 1), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                             ("TEXTCOLOR", (2, 1), (2, 1), SEV_COL["critical"]), ("TEXTCOLOR", (3, 1), (3, 1), SEV_COL["high"]),
                             ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d9d9d4"))]))
    el += [kpi, Spacer(1, 6)]
    if coverage:
        names = ", ".join(_esc(c["name"]) for c in coverage)
        el.append(Paragraph(
            f"<b>Coverage:</b> score and compliance cover evaluated checks only - "
            f"{len(coverage)} source(s) had partial coverage: {names}. "
            f"Reads that were denied or failed were not evaluated and are not counted as passing or failing.",
            small))
        el.append(Spacer(1, 6))
    el.append(Paragraph("Executive summary", h2))
    worst, seen = [], set()
    for f in sorted(active, key=lambda f: (["critical", "high", "medium", "low"].index(f.severity), f.id)):
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            worst.append(f)
        if len(worst) == 3:
            break
    summary = (f"ShieldIQ evaluated the connected environments and found <b>{len(active)}</b> open issues "
               f"({sev['critical']} critical, {sev['high']} high). ")
    if graph["paths"]:
        summary += (f"<b>{len(graph['paths'])}</b> attack path(s) lead from the internet to sensitive data; "
                    f"the riskiest scores {graph['paths'][0]['risk_score']}/100. ")
    if graph["choke_points"]:
        c = graph["choke_points"][0]
        summary += f"Fixing <b>{_esc(c['node']['label'])}</b> alone breaks {c['paths']} path(s). "
    if worst:
        summary += "Top priorities: " + "; ".join(_esc(f.title) for f in worst) + "."
    el.append(Paragraph(summary, body))

    el.append(Paragraph("Compliance posture", h2))
    rows = [["Framework", "Version", "Score", "Controls passing", "Open findings"]]
    for fw in compliance.values():
        rows.append([Paragraph(_esc(fw["name"]), small), Paragraph(_esc(fw["version"]), small), f"{fw['score']}%" if fw["score"] is not None else "n/a",
                     f"{fw['controls_passed']}/{fw['controls_assessed']}", fw["failed"]])
    t = Table(rows, colWidths=[52 * mm, 44 * mm, 18 * mm, 30 * mm, 28 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ffede3")), ("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9d9d4")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafaf7")])]))
    el.append(t)
    if framework and framework in compliance:
        fw = compliance[framework]
        el.append(Paragraph(f"{fw['name']} control detail", h2))
        rows = [["Control", "Name", "Status", "Pass rate", "Open findings"]] + [
            [c["id"], Paragraph(_esc(c["name"]), small), c["status"].upper(),
             f"{c['score']}%" if c["score"] is not None else "n/a", c["findings"]] for c in fw["controls"]]
        t = Table(rows, colWidths=[28 * mm, 78 * mm, 18 * mm, 20 * mm, 28 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ffede3")), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                               ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9d9d4"))]))
        el.append(t)

    if graph["paths"]:
        el.append(Paragraph("Attack paths", h2))
        for p in graph["paths"][:6]:
            chain = " \u2192 ".join(_esc(n["label"]) for n in p["nodes"])
            el.append(Paragraph(f"<b>{p['id']}</b> (risk {p['risk_score']}, {_esc(p['integration'])}): {chain}", body))
            if p.get("choke_point"):
                el.append(Paragraph(f"Break it at: {_esc(p['choke_point']['label'])}", small))
            el.append(Spacer(1, 3))

    el += [PageBreak(), Paragraph("Findings and remediation", h2)]
    for f in sorted(active, key=lambda f: (["critical", "high", "medium", "low"].index(f.severity), f.id))[:60]:
        rule = get_rule(f.rule_id)
        block = [Paragraph(f"<font color='{SEV_COL[f.severity].hexval()}'><b>{f.severity.upper()}</b></font> "
                           f"<b>#{f.id} {_esc(f.title)}</b>", body),
                 Paragraph(f"{_esc(f.resource_id)} \u00b7 {_esc(f.detail)}", small)]
        if rule:
            block.append(Paragraph("Fix: " + _esc(" ".join(rule.steps[:2])), small))
        block.append(Spacer(1, 5))
        el.append(KeepTogether(block))
    if len(active) > 60:
        el.append(Paragraph(f"... and {len(active) - 60} more (see CSV export).", small))
    el += [Spacer(1, 10), Paragraph("Generated by ShieldIQ. Results reflect the data available at scan time; "
                                    "demo environments contain sample data.", small)]
    doc.build(el)


def findings_csv(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "status", "provider", "service", "rule_id", "title", "resource", "detail",
                "first_seen", "last_seen", "compliance"])
    from .compliance import control_labels
    for f in findings:
        rule = get_rule(f.rule_id)
        row = [f.id, f.severity, f.status, f.provider, f.service, f.rule_id, f.title, f.resource_id, f.detail,
               f.first_seen, f.last_seen, "; ".join(control_labels(rule)) if rule else ""]
        # CSV/formula injection guard
        w.writerow([("'" + str(v)) if str(v)[:1] in ("=", "+", "-", "@") else v for v in row])
    return buf.getvalue()


def findings_json(findings, score, compliance, graph, coverage=None):
    return json.dumps({"generated_at": datetime.utcnow().isoformat() + "Z", "posture_score": score,
                       "coverage_notes": coverage or [],
                       "coverage_disclaimer": ("Score and compliance cover evaluated checks only; reads that were "
                                               "denied or failed were not evaluated, passed, or failed."),
                       "findings": [f.to_dict() for f in findings],
                       "compliance": {k: {kk: v[kk] for kk in ("name", "score", "controls_passed", "controls_assessed")}
                                      for k, v in compliance.items()},
                       "attack_paths": [{k: p[k] for k in ("id", "risk_score", "title", "integration")} for p in graph["paths"]]},
                      indent=2, default=str)
