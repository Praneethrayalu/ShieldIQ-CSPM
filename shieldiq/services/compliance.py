"""Compliance frameworks and control mapping.

Each rule carries tags (mfa, network, logging...). Tags map to framework controls, so every
check automatically counts toward SOC 2, ISO 27001, PCI-DSS, GDPR, NIST CSF, HIPAA and CIS.
"""
from collections import defaultdict

from ..models import SEVERITY_WEIGHT
from ..rules import RULES

FRAMEWORKS = {
    "CIS": {"name": "CIS Benchmarks", "version": "Cloud Foundations (section level)", "controls": {
        "CIS-1": "Identity & Access Management", "CIS-2": "Storage", "CIS-3": "Logging",
        "CIS-4": "Monitoring", "CIS-5": "Networking", "CIS-6": "Compute & Workloads",
        "CIS-7": "Databases & Backups", "CIS-8": "Source Code & SaaS"}},
    "SOC2": {"name": "SOC 2", "version": "Trust Services Criteria", "controls": {
        "CC6.1": "Logical access security", "CC6.2": "User registration & credentials",
        "CC6.3": "Role-based access / least privilege", "CC6.6": "Boundary protection",
        "CC6.7": "Data transmission protection", "CC7.1": "Configuration & vulnerability management",
        "CC7.2": "Security event monitoring", "CC8.1": "Change management", "A1.2": "Backup & recovery"}},
    "ISO27001": {"name": "ISO/IEC 27001", "version": "2022 Annex A", "controls": {
        "A.5.15": "Access control", "A.5.17": "Authentication information", "A.8.2": "Privileged access rights",
        "A.8.5": "Secure authentication", "A.8.9": "Configuration management", "A.8.12": "Data leakage prevention",
        "A.8.13": "Information backup", "A.8.15": "Logging", "A.8.16": "Monitoring activities",
        "A.8.20": "Network security", "A.8.24": "Use of cryptography", "A.8.28": "Secure coding",
        "A.8.32": "Change management"}},
    "PCI": {"name": "PCI DSS", "version": "v4.0", "controls": {
        "1.3": "Restrict network access to the CDE", "2.2": "Secure system configurations",
        "3.5": "Protect stored account data", "4.2": "Protect data in transit", "6.3": "Identify & fix vulnerabilities",
        "7.2": "Least-privilege access", "8.3": "Strong authentication", "8.4": "Multi-factor authentication",
        "8.6": "System & application account management", "10.2": "Audit logs", "11.5": "Intrusion & change detection"}},
    "GDPR": {"name": "GDPR", "version": "EU 2016/679", "controls": {
        "Art.5(1)(f)": "Integrity & confidentiality", "Art.25": "Data protection by design and default",
        "Art.32": "Security of processing", "Art.33": "Breach detection & notification"}},
    "NIST": {"name": "NIST CSF", "version": "2.0", "controls": {
        "ID.AM": "Asset management", "PR.AA": "Identity management, authentication & access control",
        "PR.DS": "Data security", "PR.PS": "Platform security", "PR.IR": "Technology infrastructure resilience",
        "DE.CM": "Continuous monitoring"}},
    "HIPAA": {"name": "HIPAA Security Rule", "version": "45 CFR 164", "controls": {
        "164.308(a)(7)": "Contingency plan (backup)", "164.312(a)(1)": "Access control",
        "164.312(a)(2)(iv)": "Encryption and decryption", "164.312(b)": "Audit controls",
        "164.312(c)(1)": "Integrity", "164.312(d)": "Person or entity authentication",
        "164.312(e)(1)": "Transmission security"}},
}

TAG_CONTROLS = {
    "mfa": {"CIS": ["CIS-1"], "SOC2": ["CC6.1"], "ISO27001": ["A.8.5"], "PCI": ["8.4"], "GDPR": ["Art.32"],
            "NIST": ["PR.AA"], "HIPAA": ["164.312(d)"]},
    "access": {"CIS": ["CIS-1"], "SOC2": ["CC6.3"], "ISO27001": ["A.5.15", "A.8.2"], "PCI": ["7.2"],
               "GDPR": ["Art.25"], "NIST": ["PR.AA"], "HIPAA": ["164.312(a)(1)"]},
    "credentials": {"CIS": ["CIS-1"], "SOC2": ["CC6.2"], "ISO27001": ["A.5.17"], "PCI": ["8.3", "8.6"],
                    "NIST": ["PR.AA"], "HIPAA": ["164.312(d)"]},
    "public_data": {"CIS": ["CIS-2"], "SOC2": ["CC6.1", "CC6.6"], "ISO27001": ["A.8.12"], "PCI": ["1.3"],
                    "GDPR": ["Art.5(1)(f)", "Art.32"], "NIST": ["PR.DS"], "HIPAA": ["164.312(a)(1)"]},
    "encryption_rest": {"CIS": ["CIS-2"], "SOC2": ["CC6.1"], "ISO27001": ["A.8.24"], "PCI": ["3.5"],
                        "GDPR": ["Art.32"], "NIST": ["PR.DS"], "HIPAA": ["164.312(a)(2)(iv)"]},
    "encryption_transit": {"CIS": ["CIS-5"], "SOC2": ["CC6.7"], "ISO27001": ["A.8.24"], "PCI": ["4.2"],
                           "GDPR": ["Art.32"], "NIST": ["PR.DS"], "HIPAA": ["164.312(e)(1)"]},
    "network": {"CIS": ["CIS-5"], "SOC2": ["CC6.6"], "ISO27001": ["A.8.20"], "PCI": ["1.3"], "GDPR": ["Art.32"],
                "NIST": ["PR.IR"], "HIPAA": ["164.312(e)(1)"]},
    "logging": {"CIS": ["CIS-3"], "SOC2": ["CC7.2"], "ISO27001": ["A.8.15"], "PCI": ["10.2"], "GDPR": ["Art.33"],
                "NIST": ["DE.CM"], "HIPAA": ["164.312(b)"]},
    "monitoring": {"CIS": ["CIS-4"], "SOC2": ["CC7.2"], "ISO27001": ["A.8.16"], "PCI": ["11.5"],
                   "GDPR": ["Art.33"], "NIST": ["DE.CM"]},
    "backup": {"CIS": ["CIS-7"], "SOC2": ["A1.2"], "ISO27001": ["A.8.13"], "GDPR": ["Art.32"], "NIST": ["PR.IR"],
               "HIPAA": ["164.308(a)(7)"]},
    "hardening": {"CIS": ["CIS-6"], "SOC2": ["CC7.1"], "ISO27001": ["A.8.9"], "PCI": ["2.2"], "GDPR": ["Art.25"],
                  "NIST": ["PR.PS"], "HIPAA": ["164.312(c)(1)"]},
    "code": {"CIS": ["CIS-8"], "SOC2": ["CC8.1"], "ISO27001": ["A.8.28", "A.8.32"], "PCI": ["6.3"],
             "GDPR": ["Art.25"], "NIST": ["PR.PS"]},
    "vuln": {"CIS": ["CIS-8"], "SOC2": ["CC7.1"], "ISO27001": ["A.8.9"], "PCI": ["6.3"], "NIST": ["ID.AM", "PR.PS"]},
    "secrets": {"CIS": ["CIS-8"], "SOC2": ["CC6.1"], "ISO27001": ["A.5.17", "A.8.12"], "PCI": ["8.6"],
                "GDPR": ["Art.32"], "NIST": ["PR.AA"], "HIPAA": ["164.312(a)(1)"]},
}


def rule_controls(rule):
    out = defaultdict(set)
    for tag in rule.tags:
        for fw, ctrls in TAG_CONTROLS.get(tag, {}).items():
            out[fw].update(ctrls)
    return {fw: sorted(c) for fw, c in out.items()}


def control_labels(rule):
    """['SOC 2 CC6.1', 'PCI DSS 8.4', ...] for display."""
    labels = []
    for fw, ctrls in rule_controls(rule).items():
        labels += [f"{FRAMEWORKS[fw]['name']} {c}" for c in ctrls]
    return labels + rule.refs


def compute(check_stats, active_findings):
    """check_stats: {rule_id: {"total": n, "failed": m}} from the latest evaluation of every source.
    active_findings: iterable of Finding rows still open. Returns per-framework scores + controls."""
    failing_by_rule = defaultdict(list)
    for f in active_findings:
        failing_by_rule[f.rule_id].append(f)
    result = {}
    for fw, meta in FRAMEWORKS.items():
        controls = {cid: {"id": cid, "name": name, "rules": [], "total": 0, "failed": 0, "findings": 0}
                    for cid, name in meta["controls"].items()}
        for rid, stats in check_stats.items():
            rule = RULES.get(rid)
            if not rule or not stats.get("total"):
                continue
            failed = min(len(failing_by_rule.get(rid, [])), stats["total"])
            w = SEVERITY_WEIGHT[rule.severity]
            for cid in rule_controls(rule).get(fw, []):
                c = controls[cid]
                c["rules"].append(rid)
                c["total"] += stats["total"] * w
                c["failed"] += failed * w
                c["findings"] += failed
        total = sum(c["total"] for c in controls.values())
        failed = sum(c["failed"] for c in controls.values())
        checks = sum(len(c["rules"]) for c in controls.values())
        fw_rules = {rid for c in controls.values() for rid in c["rules"]}
        open_findings = sum(min(len(failing_by_rule.get(rid, [])), check_stats[rid]["total"]) for rid in fw_rules)
        for c in controls.values():
            c["status"] = "n/a" if not c["total"] else ("fail" if c["failed"] else "pass")
            c["score"] = None if not c["total"] else round(100 * (c["total"] - c["failed"]) / c["total"])
        assessed = [c for c in controls.values() if c["status"] != "n/a"]
        # framework score = average pass rate of its assessed controls (each control counts equally)
        result[fw] = {"key": fw, "name": meta["name"], "version": meta["version"],
                      "score": round(sum(c["score"] for c in assessed) / len(assessed)) if assessed else None,
                      "checks": checks, "failed": open_findings,
                      "controls_passed": sum(1 for c in assessed if c["status"] == "pass"),
                      "controls_assessed": len(assessed), "controls_total": len(controls),
                      "controls": list(controls.values())}
    return result


def heatmap(check_stats, active_findings):
    """framework x service matrix of pass rates."""
    failing = defaultdict(int)
    for f in active_findings:
        failing[f.rule_id] += 1
    cells = defaultdict(lambda: [0, 0])
    services = set()
    for rid, stats in check_stats.items():
        rule = RULES.get(rid)
        if not rule or not stats.get("total"):
            continue
        svc = f"{rule.provider.upper() if rule.provider in ('aws', 'gcp') else rule.provider.title()} {rule.service}"
        services.add(svc)
        for fw in rule_controls(rule):
            cells[(fw, svc)][0] += stats["total"]
            cells[(fw, svc)][1] += min(failing.get(rid, 0), stats["total"])
    services = sorted(services)
    rows = []
    for fw in FRAMEWORKS:
        row = {"framework": fw, "name": FRAMEWORKS[fw]["name"], "cells": []}
        for svc in services:
            tot, bad = cells.get((fw, svc), (0, 0))
            row["cells"].append(None if not tot else round(100 * (tot - bad) / tot))
        rows.append(row)
    return {"services": services, "rows": rows}
