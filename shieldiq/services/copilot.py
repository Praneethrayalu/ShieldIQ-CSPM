"""Security Copilot.

Works fully offline: every answer is built from the rule knowledge base and the organization's own
live data (findings, compliance scores, attack paths). If an OpenAI-compatible API key is set
(SHIELDIQ_LLM_API_KEY / OPENAI_API_KEY), chat questions are answered by that model with the same
data as grounding context, and the app falls back to the offline engine on any error.
"""
import re
from collections import Counter

import requests
from flask import current_app

from ..models import SEVERITY_WEIGHT, Finding
from ..rules import RULES, get_rule
from . import attack_graph
from .compliance import FRAMEWORKS, control_labels

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def analyze_finding(finding: Finding) -> dict:
    rule = get_rule(finding.rule_id)
    impact = attack_graph.impact_of_finding(finding.org_id, finding.id)
    priority = SEVERITY_WEIGHT[finding.severity] * 10 + impact["paths"] * 8
    blast = (f"This resource sits on {impact['paths']} attack path(s) (highest path risk {impact['max_risk']}/100): "
             + ", ".join(impact["path_ids"]) + ".") if impact["paths"] else \
        "No internet-reachable attack path currently runs through this resource."
    return {
        "finding_id": finding.id, "rule_id": rule.id, "title": rule.title, "resource": finding.resource_id,
        "severity": finding.severity, "detail": finding.detail,
        "root_cause": rule.root_cause, "impact": rule.impact, "blast_radius": blast,
        "attack_paths": impact, "priority_score": min(100, priority),
        "steps": [rule.render(s, finding.resource_id) for s in rule.steps],
        "terraform": rule.render(rule.terraform, finding.resource_id),
        "cli": rule.render(rule.cli, finding.resource_id),
        "compliance": control_labels(rule),
        "auto_fix_available": bool(rule.fix) and finding.integration is not None and
        finding.integration.mode in ("demo", "snapshot", "upload"),
        "engine": "offline knowledge base",
    }


def _active(org_id):
    return Finding.query.filter(Finding.org_id == org_id, Finding.status.in_(["open", "in_progress"])).all()


def _fmt(f):
    return f"#{f.id} [{f.severity.upper()}] {f.title} on {f.resource_id.split('/')[-1]}"


def context_summary(org_id, compliance=None, score=None):
    fs = _active(org_id)
    sev = Counter(f.severity for f in fs)
    top = sorted(fs, key=lambda f: (SEV_ORDER[f.severity], f.id))[:12]
    graph = attack_graph.build(org_id)
    lines = [f"Posture score: {score}/100" if score is not None else "Posture score: not scanned yet",
             f"Open findings: {len(fs)} (critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']})",
             "Top findings:"] + [f"- {_fmt(f)}" for f in top]
    if compliance:
        lines.append("Compliance: " + ", ".join(f"{v['name']} {v['score']}%" for v in compliance.values() if v['score'] is not None))
    lines.append(f"Attack paths: {len(graph['paths'])}")
    for p in graph["paths"][:5]:
        lines.append(f"- {p['id']} risk {p['risk_score']}: " + " -> ".join(n["label"] for n in p["nodes"]))
    if graph["choke_points"]:
        c = graph["choke_points"][0]
        lines.append(f"Best choke point: {c['node']['label']} (in {c['paths']} paths)")
    return "\n".join(lines), fs, graph


def _offline_answer(q, org_id, compliance, score):
    ql = q.lower()
    summary, fs, graph = context_summary(org_id, compliance, score)
    m = re.search(r"#?(\d+)", ql) if "finding" in ql or "#" in ql else None
    if m:
        f = next((x for x in fs if x.id == int(m.group(1))), None) or Finding.query.filter_by(org_id=org_id, id=int(m.group(1))).first()
        if f:
            a = analyze_finding(f)
            return (f"**{a['title']}** on `{a['resource']}`\n\n**Why it matters:** {a['impact']}\n\n**Root cause:** "
                    f"{a['root_cause']}\n\n**Fix:**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(a["steps"], 1)) +
                    (f"\n\n```bash\n{a['cli']}\n```" if a["cli"] else "") + f"\n\n{a['blast_radius']}")
    if any(w in ql for w in ("first", "priorit", "top", "most important", "urgent", "start")):
        if not fs:
            return "Nothing open right now. Run a scan to check again."
        ranked = sorted(fs, key=lambda f: (-(SEVERITY_WEIGHT[f.severity] * 10 + sum(
            1 for p in graph["paths"] for n in p["nodes"] for x in n["findings"] if x["id"] == f.id) * 8), f.id))[:5]
        out = "Here is what I would fix first (severity + how many attack paths each one opens):\n"
        out += "\n".join(f"{i}. {_fmt(f)}" for i, f in enumerate(ranked, 1))
        if graph["choke_points"]:
            c = graph["choke_points"][0]
            out += f"\n\nQuick win: fixing **{c['node']['label']}** breaks {c['paths']} attack path(s) at once."
        return out
    if any(w in ql for w in ("attack", "path", "chain", "lateral", "breach")):
        if not graph["paths"]:
            return "No internet-to-data attack paths right now. Nice."
        out = f"I found {len(graph['paths'])} attack path(s). The riskiest:\n"
        for p in graph["paths"][:3]:
            out += f"\n**{p['id']} (risk {p['risk_score']})**: " + " \u2192 ".join(n["label"] for n in p["nodes"])
            if p.get("choke_point"):
                out += f"\n  Break it at: {p['choke_point']['label']} (finding #{p['choke_point']['finding']['id']})"
        return out
    for key, meta in FRAMEWORKS.items():
        names = {key.lower(), meta["name"].lower(), meta["name"].lower().replace(" ", "")}
        if any(n in ql.replace("-", " ") for n in names) or (key == "PCI" and "pci" in ql) or (key == "ISO27001" and "iso" in ql):
            fw = (compliance or {}).get(key)
            if not fw or fw["score"] is None:
                return f"No checks mapped to {meta['name']} have run yet. Run a scan first."
            failing = [c for c in fw["controls"] if c["status"] == "fail"]
            return (f"**{meta['name']} ({meta['version']})**: compliance score {fw['score']}% (average control pass rate), "
                    f"{fw['controls_passed']}/{fw['controls_assessed']} assessed controls fully passing.\n\nFailing controls:\n" +
                    "\n".join(f"- {c['id']} {c['name']}: {c['findings']} open finding(s)" for c in failing[:8]))
    for rule in RULES.values():
        words = [w for w in re.findall(r"[a-z0-9]+", rule.service.lower()) if len(w) > 2]
        keys = {"s3": "AWS-S3", "mfa": "MFA", "ssh": "SSH", "rdp": "RDP", "imds": "IMDS", "rds": "AWS-RDS",
                "secret": "CODE-SEC", "privileged": "K8S-001", "bucket": "bucket", "firewall": "Firewall"}
        for k, v in keys.items():
            if k in ql and (v in rule.id or v.lower() in rule.title.lower()):
                related = [f for f in fs if f.rule_id == rule.id]
                return (f"**{rule.title}** ({rule.severity})\n\n{rule.root_cause}\n\n**Impact:** {rule.impact}\n\n**How to fix:**\n"
                        + "\n".join(f"{i}. {s}" for i, s in enumerate(rule.steps, 1)) +
                        (f"\n\nYou have {len(related)} open finding(s) for this: " + ", ".join(f"#{f.id}" for f in related[:6])
                         if related else "\n\nYou have no open findings for this right now."))
        if words and any(w in ql for w in words) and "how" in ql:
            continue
    if any(w in ql for w in ("score", "posture", "summary", "overview", "status", "how are we", "doing")):
        return summary.replace("\n- ", "\n• ")
    return ("I can help with:\n• \"What should I fix first?\"\n• \"Show the attack paths\"\n• \"How do we look for PCI DSS?\"\n"
            "• \"Explain finding #12\"\n• \"How do I fix public S3 buckets?\"\n\nCurrent snapshot:\n" + summary.split("Top findings:")[0])


def chat(question, org_id, compliance=None, score=None, history=None):
    question = (question or "").strip()[:2000]
    if not question:
        return {"answer": "Ask me anything about your security posture.", "engine": "offline"}
    cfg = current_app.config
    if cfg.get("LLM_API_KEY"):
        summary, _, _ = context_summary(org_id, compliance, score)
        msgs = [{"role": "system", "content":
                 "You are ShieldIQ Copilot, a concise cloud security engineer. Answer using ONLY the organization's "
                 "data below; say so when the data does not cover a question. Give concrete fixes (CLI/Terraform) "
                 "when asked.\n\nORGANIZATION DATA:\n" + summary}]
        for h in (history or [])[-6:]:
            if h.get("role") in ("user", "assistant"):
                msgs.append({"role": h["role"], "content": str(h.get("content", ""))[:2000]})
        msgs.append({"role": "user", "content": question})
        try:
            r = requests.post(f"{cfg['LLM_BASE_URL'].rstrip('/')}/chat/completions",
                              headers={"Authorization": f"Bearer {cfg['LLM_API_KEY']}"},
                              json={"model": cfg["LLM_MODEL"], "messages": msgs, "temperature": 0.2}, timeout=30)
            r.raise_for_status()
            return {"answer": r.json()["choices"][0]["message"]["content"], "engine": f"llm:{cfg['LLM_MODEL']}"}
        except Exception as exc:  # graceful fallback
            ans = _offline_answer(question, org_id, compliance, score)
            return {"answer": ans, "engine": "offline", "note": f"LLM unavailable ({exc.__class__.__name__}), used offline engine"}
    return {"answer": _offline_answer(question, org_id, compliance, score), "engine": "offline"}
