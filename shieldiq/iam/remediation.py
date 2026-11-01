"""Safe IAM remediation: preview -> validate -> explicit approval -> apply (stored inventories only) -> re-scan.

Nothing in this module calls a write API on AWS. For live AWS integrations ShieldIQ's credentials are read-only by
design, so the approved change is handed over as the exact proposed policy plus CLI instructions; after the operator
applies it, "Verify" re-scans the account and reports whether the finding is resolved.

How the proposal is built (least-privilege, minimal disruption):
- an offending statement that lists the risky action explicitly -> remove just those actions (drop the statement if
  nothing is left);
- an offending statement that grants them through a wildcard / NotAction (e.g. "iam:*", "*") -> keep it and add an
  explicit Deny statement for exactly the risky actions on exactly the affected resources (a Deny always wins);
- an AWS-managed policy cannot be edited -> propose a customer-managed copy with the change, attached in its place.
The proposal is validated before it can be approved: structure and size limits, re-evaluation of the principal with
the proposed document (the risky decisions must become Denied and the finding must clear in the model), and an
impact list of actions that change from Allowed/Indeterminate to Denied. The AWS policy-simulator check
(iam:SimulateCustomPolicy, shieldiq/iam/simulate.py) is not called from previews in v2.3; the preview says so.
"""
import copy
import difflib
import json

from .analysis import ADMIN_PROBES, Analyzer
from .evaluator import DENIED, evaluate
from .model import build_model
from .policy import as_list, statements, stmt_matches_action

SIZE_LIMITS = {"managed": 6144, "aws-managed": 6144, "inline:user": 2048, "inline:group": 5120, "inline:role": 10240}
GUARD_SID = "ShieldIQLeastPrivilegeGuard"


def _pretty(doc):
    return json.dumps(doc, indent=2, sort_keys=True, default=str)


def diff(before, after, name="policy"):
    return "".join(difflib.unified_diff(_pretty(before).splitlines(True), _pretty(after).splitlines(True),
                                        fromfile=f"{name} (current)", tofile=f"{name} (proposed)"))


def _risky_decisions(an, p, rule_id, evidence):
    """Decisions (action, resource) that make the finding true, with their evidence."""
    out = []
    if rule_id == "AWS-IAM-007":
        paths = (evidence or {}).get("paths") or []
        if not paths:
            paths = [x for x in an.paths() if x["start"]["arn"] == p.arn]
        if paths:
            first = paths[0]["steps"][0]
            for ev in first["evidence"]:
                act, res = ev.get("action"), ev.get("resource")
                if act and act != "trust policy":
                    out.append(an.ev(p, act, res))
    else:  # AWS-IAM-005 (admin / escalation)
        adm, ds = an.admin(p)
        if adm != DENIED:
            out += [d for d in ds if d.possible]
        for tgt, e in an.edges_from(p):
            if e["kind"] in ("self_escalation", "credentials", "update_trust", "pass_role"):
                for ev in e["evidence"]:
                    if ev.get("action") and ev["action"] != "trust policy":
                        out.append(an.ev(p, ev["action"], ev["resource"]))
    # least privilege, least disruption: break the chain at the IAM/STS permission (e.g. iam:PassRole) rather than the
    # service action paired with it (ec2:RunInstances); the admin probe (a full "*" grant) is kept whole
    if rule_id == "AWS-IAM-007" or not any(d.action.startswith("shieldiq-probe") for d in out):
        key = [d for d in out if d.action.lower().startswith(("iam:", "sts:"))]
        out = key or out
    seen, uniq = set(), []
    for d in out:
        if d.possible and (d.action, d.resource) not in seen:
            seen.add((d.action, d.resource))
            uniq.append(d)
    return uniq


def _ref_key(ev):
    return (ev.get("policy"), ev.get("policy_arn"), ev.get("via"), ev.get("policy_kind"))


def propose(inv, principal_arn, rule_id, evidence=None, context=None):
    """Build the remediation preview. Returns a JSON-serialisable dict (never touches AWS)."""
    model = build_model(inv)
    an = Analyzer(model, context)
    p = model.principals.get(principal_arn)
    if p is None:
        return {"ok": False, "error": "principal not found in the collected IAM data", "mode": "manual"}
    risky = _risky_decisions(an, p, rule_id, evidence)
    if not risky:
        return {"ok": False, "error": "no risky permission could be attributed to a readable policy statement "
                                      "(the finding may come from a policy NAME only or unreadable documents)",
                "mode": "manual", "principal": principal_arn}
    # group offending Allow statements by policy document
    per_policy = {}
    for d in risky:
        for ev in d.evidence:
            if ev.get("layer") != "identity" or ev.get("effect") != "Allow":
                continue
            k = _ref_key(ev)
            entry = per_policy.setdefault(k, {"ref": ev, "items": []})
            entry["items"].append((ev["statement_index"], d.action, d.resource))
    refs = {(r.name, r.arn, r.via, r.kind): r for r in p.identity}
    changes = []
    for k, entry in per_policy.items():
        ref = refs.get(k)
        if ref is None or ref.document is None:
            continue
        before = copy.deepcopy(ref.document)
        after = copy.deepcopy(ref.document)
        sts = statements(after)
        if isinstance(after.get("Statement"), dict):
            after["Statement"] = sts
        guard = {}
        removed = []
        drop = set()
        for idx, action, resource in entry["items"]:
            st = sts[idx]
            acts = as_list(st.get("Action"))
            full = any(str(a) in ("*", "*:*") for a in acts) and "*" in as_list(st.get("Resource")) \
                and "NotResource" not in st
            if full and rule_id == "AWS-IAM-005" and any(d.action.startswith("shieldiq-probe") for d in risky):
                drop.add(idx)  # a full "*" grant: remove it; scoped replacement must come from real usage data
                continue
            if action.startswith("shieldiq-probe"):
                continue
            exact = [a for a in acts if str(a).lower() == action.lower()]
            if exact and "Action" in st:
                st["Action"] = [a for a in acts if str(a).lower() != action.lower()]
                removed.append(action)
            else:
                guard.setdefault(action, set()).add(resource or "*")
        after["Statement"] = [s for i, s in enumerate(sts) if i not in drop and
                              not ("Action" in s and as_list(s.get("Action")) == [])]
        if guard:
            res_all = sorted({r for v in guard.values() for r in v})
            after["Statement"].append({"Sid": GUARD_SID, "Effect": "Deny", "Action": sorted(guard),
                                       "Resource": "*" if "*" in res_all else res_all})
        remove_policy = not after["Statement"]
        kind = ref.kind if ref.kind != "inline" else "inline:" + ("group" if ref.via.startswith("group:") else p.kind)
        changes.append({"policy": ref.name, "policy_arn": ref.arn, "kind": ref.kind, "via": ref.via,
                        "editable": ref.kind != "aws-managed", "before": before, "after": after,
                        "diff": diff(before, after, ref.name), "removed_actions": sorted(set(removed)),
                        "denied_by_guard": sorted(guard), "size_limit": SIZE_LIMITS.get(kind),
                        "size_kind": kind, "removed_statements": sorted(drop), "remove_policy": remove_policy,
                        "note": ("Nothing would remain in this policy: the proposal is to remove (detach / delete) it."
                                 if remove_policy else None)})
    if not changes:
        return {"ok": False, "error": "the granting statements are in unreadable or non-identity policies",
                "mode": "manual", "principal": principal_arn}
    validation = validate(inv, p, changes, risky, rule_id, context)
    return {"ok": True, "principal": principal_arn, "principal_name": p.name, "principal_kind": p.kind,
            "rule_id": rule_id, "risk": risk_text(rule_id, p, risky),
            "offending": [{"policy": c["policy"], "via": c["via"], "statements": [
                s for i, s in enumerate(statements(c["before"]))
                if any(i == it[0] for it in per_policy.get((c["policy"], c["policy_arn"], c["via"], c["kind"]),
                                                          {"items": []})["items"])]} for c in changes],
            "risky_permissions": [{"action": d.action, "resource": d.resource, "decision": d.decision}
                                  for d in risky],
            "changes": changes, "validation": validation, "impact": validation["impact"],
            "instructions": instructions(p, changes)}


def risk_text(rule_id, p, risky):
    acts = sorted({d.action for d in risky})
    who = f"{p.kind} '{p.name}'"
    if any(a.startswith("shieldiq-probe") for a in acts):
        return (f"The {who} can do practically anything in this AWS account (a policy grants every action on every "
                f"resource). If its credentials leak, the attacker owns the account.")
    return (f"The {who} holds permissions that let it give itself more power ({', '.join(a for a in acts[:5])}). "
            f"Someone who steals its credentials could turn them into administrator access.")


def _apply_to_model(model, p, changes):
    refs = {(r.name, r.arn, r.via): r for r in p.identity}
    for c in changes:
        r = refs.get((c["policy"], c["policy_arn"], c["via"]))
        if r is not None:
            r.document = c["after"]


def _probe_actions(changes):
    acts = set(ADMIN_PROBES)
    for c in changes:
        for st in statements(c["before"]):
            for a in as_list(st.get("Action")):
                if "*" not in str(a):
                    acts.add(str(a))
    return sorted(acts)[:60]


def validate(inv, p, changes, risky, rule_id, context=None):
    problems = []
    for c in changes:
        doc = c["after"]
        try:
            text = json.dumps(doc, separators=(",", ":"))
        except (TypeError, ValueError):
            problems.append(f"{c['policy']}: not JSON-serialisable")
            continue
        for i, st in enumerate(statements(doc)):
            if st.get("Effect") not in ("Allow", "Deny"):
                problems.append(f"{c['policy']} statement {i}: Effect must be Allow or Deny")
            if not ("Action" in st or "NotAction" in st):
                problems.append(f"{c['policy']} statement {i}: needs Action or NotAction")
            if not ("Resource" in st or "NotResource" in st):
                problems.append(f"{c['policy']} statement {i}: needs Resource or NotResource")
        if not statements(doc) and not c.get("remove_policy"):
            problems.append(f"{c['policy']}: no statement would remain - detach / delete this policy instead of "
                            f"publishing an empty one (IAM rejects a policy without statements)")
        if c.get("size_limit") and len(text) > c["size_limit"]:
            problems.append(f"{c['policy']}: {len(text)} characters exceeds the {c['size_kind']} limit {c['size_limit']}")
        if not c["editable"] and not c.get("remove_policy"):
            problems.append(f"{c['policy']} is AWS-managed and cannot be edited: create a customer-managed copy with "
                            f"the proposed content, attach it, then detach the AWS-managed policy")
    # re-evaluate with the proposed documents
    before_model = build_model(inv)
    after_model = build_model(inv)
    pb = before_model.principals[p.arn]
    pa = after_model.principals[p.arn]
    _apply_to_model(after_model, pa, changes)
    still = []
    for d in risky:
        nd = evaluate(after_model, pa, d.action, d.resource, context)
        if nd.decision != DENIED:
            still.append({"action": d.action, "resource": d.resource, "decision": nd.decision})
    an_after = Analyzer(after_model, context)
    adm_after, _ = an_after.admin(pa)
    paths_after = [x for x in an_after.paths() if x["start"]["arn"] == p.arn]
    impact = []
    for a in _probe_actions(changes):
        if a.startswith("shieldiq-probe"):
            continue
        b = evaluate(before_model, pb, a, "*", context).decision
        n = evaluate(after_model, pa, a, "*", context).decision
        if b != n:
            impact.append({"action": a, "resource": "*", "before": b, "after": n})
    resolved_in_model = (not still) and (adm_after == DENIED if rule_id == "AWS-IAM-005" else not paths_after)
    if rule_id == "AWS-IAM-005" and adm_after == DENIED:
        # 005 also flags single escalation permissions: re-check them
        esc_left = [e for t, e in an_after.edges_from(pa) if e["kind"] in ("self_escalation", "credentials",
                                                                          "update_trust", "pass_role")]
        resolved_in_model = resolved_in_model and not esc_left
    return {"structural_problems": problems, "risky_still_possible": still, "admin_after": adm_after,
            "paths_after": len(paths_after), "resolved_in_model": resolved_in_model, "impact": impact,
            "disruption": ("Removes access the principal has today. Workloads or people that rely on the removed "
                           "actions will get AccessDenied. Check CloudTrail / IAM last-accessed data for these actions "
                           "before applying.") if impact else "No change to the sampled non-risky actions.",
            "aws_simulator": {"status": "not_run",
                              "detail": "previews do not call AWS in v2.3; cross-check the proposed document with "
                                        "iam:SimulateCustomPolicy (shieldiq/iam/simulate.py, or the validation kit) "
                                        "before applying it to a live account"},
            "ok": not problems or all("AWS-managed" in x for x in problems)}


def instructions(p, changes):
    out = []
    for c in changes:
        fn = f"shieldiq-proposed-{c['policy']}.json"
        if c.get("remove_policy"):
            grp = c["via"].split(":", 1)[1] if c["via"].startswith("group:") else None
            who = f"--group-name '{grp}'" if grp else (f"--user-name '{p.name}'" if p.kind == "user" else f"--role-name '{p.name}'")
            verb = "group" if grp else p.kind
            if c["kind"] == "inline":
                out.append(f"# {c['policy']}: nothing would remain - delete the inline policy\n"
                           f"aws iam delete-{verb}-policy {who} --policy-name '{c['policy']}'")
            else:
                out.append(f"# {c['policy']}: nothing would remain - detach it (check other attachments first:\n"
                           f"#   aws iam list-entities-for-policy --policy-arn '{c['policy_arn']}')\n"
                           f"aws iam detach-{verb}-policy {who} --policy-arn '{c['policy_arn']}'")
            continue
        if c["kind"] == "managed":
            out.append(f"# {c['policy']} (customer-managed): publish the proposed version as default\n"
                       f"aws iam create-policy-version --policy-arn '{c['policy_arn']}' "
                       f"--policy-document file://{fn} --set-as-default\n"
                       f"# (a policy keeps at most 5 versions: delete an old non-default one first if needed)")
        elif c["kind"] == "aws-managed":
            target = (f"--user-name '{p.name}'" if p.kind == "user" else f"--role-name '{p.name}'") \
                if not c["via"].startswith("group:") else f"--group-name '{c['via'].split(':', 1)[1]}'"
            verb = "user" if "user-name" in target else "role" if "role-name" in target else "group"
            out.append(f"# {c['policy']} is AWS-managed (read-only): create a scoped copy, attach it, detach the original\n"
                       f"aws iam create-policy --policy-name 'ShieldIQ-{c['policy']}-scoped' --policy-document file://{fn}\n"
                       f"aws iam attach-{verb}-policy {target} --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/ShieldIQ-{c['policy']}-scoped\n"
                       f"aws iam detach-{verb}-policy {target} --policy-arn '{c['policy_arn']}'")
        else:
            if c["via"].startswith("group:"):
                g = c["via"].split(":", 1)[1]
                out.append(f"aws iam put-group-policy --group-name '{g}' --policy-name '{c['policy']}' --policy-document file://{fn}")
            elif p.kind == "user":
                out.append(f"aws iam put-user-policy --user-name '{p.name}' --policy-name '{c['policy']}' --policy-document file://{fn}")
            else:
                out.append(f"aws iam put-role-policy --role-name '{p.name}' --policy-name '{c['policy']}' --policy-document file://{fn}")
    out.append("# then run a ShieldIQ re-scan (Verify) to confirm the finding is resolved")
    return out


# ------------------------------------------------------------------ apply to a STORED inventory (demo / snapshot)
def apply_to_inventory(inv, principal_arn, changes):
    """Write the proposed documents into a stored inventory (both the v2.3 `iam` model and legacy fields).
    Returns the number of documents changed. Never used for live accounts."""
    n = 0
    acct = str(inv.get("account_id") or "")
    for c in changes:
        if c.get("remove_policy"):
            n += _remove_from_inventory(inv, principal_arn, c)
            continue
        new = c["after"]
        if not c["editable"]:
            new_name = f"ShieldIQ-{c['policy']}-scoped"
            new_arn = f"arn:aws:iam::{acct}:policy/{new_name}"
        else:
            new_name, new_arn = c["policy"], c["policy_arn"]
        rich = inv.get("iam") if isinstance(inv.get("iam"), dict) else None
        if rich is not None:
            if c["kind"] in ("managed", "aws-managed"):
                pols = rich.setdefault("policies", {})
                pols[new_arn] = {"name": new_name, "document": new, "default_version": "shieldiq-proposed"}
                if new_arn != c["policy_arn"]:
                    for coll in ("users", "groups", "roles"):
                        for x in rich.get(coll) or []:
                            for a in x.get("attached") or []:
                                if a.get("arn") == c["policy_arn"] and _owner_matches(x, coll, c, principal_arn):
                                    a["arn"], a["name"] = new_arn, new_name
                n += 1
            else:
                coll, name = ("groups", c["via"].split(":", 1)[1]) if c["via"].startswith("group:") else \
                    (("users" if ":user/" in principal_arn else "roles"), principal_arn.split("/")[-1])
                for x in rich.get(coll) or []:
                    if x.get("name") == name:
                        for i in x.get("inline") or []:
                            if i.get("name") == c["policy"]:
                                i["document"] = new
                                n += 1
        for coll, names_key in (("iam_users", "attached_policies"), ("iam_roles", "policies")):
            for x in inv.get(coll) or []:
                for d in x.get("policy_documents") or []:
                    src = str(d.get("source") or "")
                    hit = d.get("name") == c["policy"] and (
                        (c["policy_arn"] and src.endswith(c["policy_arn"])) or
                        (not c["policy_arn"] and (src == "inline" and c["via"] in ("direct", "role") and
                                                  x.get("name") == principal_arn.split("/")[-1]
                                                  or src == "group-inline:" + c["via"].split(":", 1)[-1])))
                    if hit:
                        d["document"] = new
                        if new_arn != c["policy_arn"] and src.startswith(("managed:", "group-managed:")):
                            d["source"] = src.replace(c["policy_arn"], new_arn)
                            d["name"] = new_name
                            x[names_key] = [new_name if nm == c["policy"] else nm for nm in x.get(names_key) or []]
                        n += 1
    return n


def _owner_matches(x, coll, c, principal_arn):
    if c["via"].startswith("group:"):
        return coll == "groups" and x.get("name") == c["via"].split(":", 1)[1]
    return x.get("arn") == principal_arn or x.get("name") == principal_arn.split("/")[-1]


def _remove_from_inventory(inv, principal_arn, c):
    """Detach (managed) or delete (inline) one policy from the principal - or from its group - in a stored inventory."""
    n = 0
    name = principal_arn.split("/")[-1]
    grp = c["via"].split(":", 1)[1] if c["via"].startswith("group:") else None
    rich = inv.get("iam") if isinstance(inv.get("iam"), dict) else None
    if rich is not None:
        coll = "groups" if grp else ("users" if ":user/" in principal_arn else "roles")
        for x in rich.get(coll) or []:
            if x.get("name") != (grp or name):
                continue
            if c["kind"] == "inline":
                before = len(x.get("inline") or [])
                x["inline"] = [i for i in x.get("inline") or [] if i.get("name") != c["policy"]]
                n += before - len(x["inline"])
            else:
                before = len(x.get("attached") or [])
                x["attached"] = [a for a in x.get("attached") or [] if a.get("arn") != c["policy_arn"]]
                n += before - len(x["attached"])
    for coll, names_key in (("iam_users", "attached_policies"), ("iam_roles", "policies")):
        for x in inv.get(coll) or []:
            if not grp and x.get("name") != name:
                continue
            keep = []
            for d in x.get("policy_documents") or []:
                src = str(d.get("source") or "")
                hit = d.get("name") == c["policy"] and (
                    (c["policy_arn"] and src.endswith(c["policy_arn"]) and (not grp or src.startswith("group-managed:" + grp + ":")))
                    or (not c["policy_arn"] and (src == ("group-inline:" + grp if grp else "inline"))))
                if hit:
                    n += 1
                else:
                    keep.append(d)
            if "policy_documents" in x:
                x["policy_documents"] = keep
            if c["policy_arn"] and x.get(names_key):
                x[names_key] = [nm for nm in x[names_key] if nm != c["policy"]]
    return n
