"""Privilege analysis and evidence-based IAM attack paths on top of the evaluator.

Nothing here looks at policy *names*. Every capability is an evaluator Decision for a concrete action on a
concrete resource from the collected inventory (a user, group, role or managed policy ARN), so every edge carries
the exact statements that grant it, and the layers (boundary, SCP, deny) that were checked.

Path edges (attacker = the starting principal, or a principal it has already reached):
  assume_role         sts:AssumeRole on R, and R's trust policy allows the principal (or its account + identity)
  update_trust        iam:UpdateAssumeRolePolicy on R -> rewrite trust, then assume R
  pass_role           iam:PassRole on R + a service create action, and R trusts that service
  credentials         iam:CreateAccessKey / CreateLoginProfile / UpdateLoginProfile on another user U
  self_escalation     Attach/Put policy on itself or one of its groups, CreatePolicyVersion / SetDefaultPolicyVersion
                      on a customer-managed policy attached to it, AddUserToGroup into an admin group
  modify_role         Attach/PutRolePolicy on a role it can already reach
Targets: "full account admin" (every probe action Allowed on "*") and data stores (S3 read).

Confidence: "confirmed" = every edge is Allowed by every layer ShieldIQ evaluated; "likely" = at least one edge
is Indeterminate only because of condition keys / variables; "unverified" = some edge depends on data that was
not collected (unreadable documents, unknown boundary or SCPs). Confirmed is still ShieldIQ's model, not AWS: use
the policy-simulator cross-check (iam.simulate) for authoritative confirmation.
"""
from collections import deque

from .evaluator import ALLOWED, DENIED, INDETERMINATE, evaluate
from .model import PolicyRef, Principal
from .policy import as_list, principal_match, statements

ADMIN_PROBES = ["shieldiq-probe:AnyAction", "iam:AttachUserPolicy", "iam:PassRole", "iam:CreateAccessKey",
                "ec2:RunInstances", "s3:GetObject", "kms:Decrypt", "sts:AssumeRole"]

PASSROLE_SERVICES = {
    "ec2:RunInstances": "ec2.amazonaws.com",
    "lambda:CreateFunction": "lambda.amazonaws.com",
    "cloudformation:CreateStack": "cloudformation.amazonaws.com",
    "glue:CreateDevEndpoint": "glue.amazonaws.com",
    "datapipeline:CreatePipeline": "datapipeline.amazonaws.com",
    "ecs:RunTask": "ecs-tasks.amazonaws.com",
    "sagemaker:CreateNotebookInstance": "sagemaker.amazonaws.com",
}

SELF_ACTIONS = {
    "iam:AttachUserPolicy": "attach any managed policy (e.g. AdministratorAccess) to itself",
    "iam:PutUserPolicy": "write an inline admin policy on itself",
    "iam:DeleteUserPermissionsBoundary": "remove its own permissions boundary",
    "iam:PutUserPermissionsBoundary": "replace its own permissions boundary",
}
GROUP_ACTIONS = {
    "iam:AttachGroupPolicy": "attach an admin managed policy to a group it belongs to",
    "iam:PutGroupPolicy": "write an inline admin policy on a group it belongs to",
}
POLICY_ACTIONS = {
    "iam:CreatePolicyVersion": "publish a new default version (e.g. *:*) of a customer-managed policy attached to it",
    "iam:SetDefaultPolicyVersion": "switch a policy attached to it to another (possibly broader) stored version",
}
CRED_ACTIONS = {
    "iam:CreateAccessKey": "create access keys for another user and act as that user",
    "iam:CreateLoginProfile": "set a console password on another user",
    "iam:UpdateLoginProfile": "reset another user's console password",
}
ROLE_ACTIONS = {
    "iam:AttachRolePolicy": "attach an admin managed policy to a role it can use",
    "iam:PutRolePolicy": "write an inline admin policy on a role it can use",
}


def _sev_conf(decisions):
    ds = [d for d in decisions if d is not None]
    if any(d.decision == DENIED for d in ds):
        return None
    if all(d.decision == ALLOWED for d in ds):
        return "confirmed"
    data_gap = any(d.decision == INDETERMINATE and d.missing for d in ds)
    return "unverified" if data_gap else "likely"


def _combine(confs):
    order = {"confirmed": 0, "likely": 1, "unverified": 2}
    return max(confs, key=lambda c: order[c]) if confs else "confirmed"


def _has_grant_evidence(d):
    """A real Allow statement (identity layer, or a resource policy naming the principal) supports this decision."""
    if any(e["effect"] == "Allow" and e.get("layer") == "identity" for e in d.evidence):
        return True
    return d.layers.get("resource_grant") is not False and any(e.get("layer") == "resource" and e["effect"] == "Allow"
                                                                for e in d.evidence)


def _rank(conf):
    return {"confirmed": 0, "likely": 1, "unverified": 2}[conf]


def _edge_evidence(decisions):
    out = []
    for d in decisions:
        out.append({"action": d.action, "resource": d.resource, "decision": d.decision, "reason": d.reason,
                    "statements": [{k: e[k] for k in ("layer", "policy", "policy_arn", "via", "sid",
                                                      "statement_index", "effect", "match", "statement")}
                                   for e in d.evidence][:6],
                    "missing": d.missing, "notes": d.notes})
    return out


class Analyzer:
    def __init__(self, model, context=None):
        self.m = model
        self.ctx = context
        self._cache = {}
        self.unknown_edges = {}  # principal arn -> capabilities that could not be ruled out (missing data)

    def ev(self, p, action, resource="*"):
        key = (p.arn, action, resource)
        if key not in self._cache:
            self._cache[key] = evaluate(self.m, p, action, resource, self.ctx)
        return self._cache[key]

    # ------------------------------------------------------------------ admin
    def admin(self, p):
        ds = [self.ev(p, a, "*") for a in ADMIN_PROBES]
        if all(d.decision == ALLOWED for d in ds):
            return "Allowed", ds
        if all(d.possible for d in ds):
            return "Indeterminate", ds
        return "Denied", ds

    def group_pseudo(self, gname, like):
        g = self.m.groups.get(gname)
        if not g:
            return None
        return Principal("user", like.name, like.arn, like.account_id, identity=list(like.identity) + list(g["policies"]),
                         identity_complete=like.identity_complete and g["complete"], groups=like.groups,
                         boundary_status=like.boundary_status, boundary=like.boundary, tags=like.tags)

    # ------------------------------------------------------------------ trust
    def trust_allows(self, role, p=None, service=None):
        """Does any Allow statement of the role's trust policy cover `p` (or `service`)? Tri-state + kind + evidence.
        Conditions are NOT decided here: for principals the evaluator does that (trust policy passed as the resource
        policy); for services a conditional statement makes the answer UNKNOWN."""
        if role.trust_policy is None:
            return None, None, []
        res, kind, ev = False, None, []
        for i, s in enumerate(statements(role.trust_policy)):
            if str(s.get("Effect", "")).lower() != "allow":
                continue
            acts = as_list(s.get("Action"))
            if not any(str(a).lower() in ("sts:assumerole", "sts:*", "*") for a in acts):
                continue
            pm, pk = principal_match(s, p.arn if p else "", self.m.account_id, service=service)
            if pm is False:
                continue
            if service is not None and s.get("Condition"):
                pm = None
            ev.append({"layer": "trust", "policy": f"trust policy of {role.name}", "policy_arn": role.arn,
                       "via": "trust", "sid": s.get("Sid"), "statement_index": i, "effect": "Allow",
                       "match": "yes" if pm is True else "unknown", "statement": s})
            if pm is True and res is not True:
                res, kind = True, pk
            elif pm is None and res is False:
                res, kind = None, pk
        return res, kind, ev

    def assume(self, p, r):
        rp = {"status": "collected", "document": r.trust_policy, "name": f"trust policy of {r.name}"} \
            if r.trust_policy is not None else {"status": "unknown"}
        d = evaluate(self.m, p, "sts:AssumeRole", r.arn, self.ctx, resource_policy=rp)
        if r.trust_policy is None and d.decision == ALLOWED:
            # sts:AssumeRole needs the role's trust policy to agree; without it the answer is not known
            d.decision, d.reason = INDETERMINATE, "indeterminate: trust policy not collected"
            d.missing.append(f"trust policy of {r.name} not collected")
        return d

    # ------------------------------------------------------------------ edges
    def edges_from(self, p):
        """[(target_key, edge)] where target_key is a principal ARN or 'ADMIN'."""
        out = []
        acct = self.m.account_id
        users = self.m.users()
        roles = [r for r in self.m.roles() if not r.service_linked]

        def add(target, kind, title, decisions, extra_ev=None, missing=None):
            conf = _sev_conf(decisions)
            if conf is None:
                return
            # an edge needs real policy evidence: a decision that is Indeterminate only because documents are
            # missing (no statement matched) is an UNKNOWN, not an attack-path edge
            for d in decisions:
                if d.decision != ALLOWED and not _has_grant_evidence(d):
                    self.unknown_edges.setdefault(p.arn, set()).add(title)
                    return
            ev = _edge_evidence(decisions)
            if missing and not extra_ev:
                ev.append({"action": "trust policy", "resource": target, "decision": INDETERMINATE,
                           "reason": "required data not collected", "statements": [], "missing": missing,
                           "notes": []})
            if extra_ev:
                ev.append({"action": "trust policy", "resource": target, "decision": "Allowed" if conf == "confirmed"
                           else "Indeterminate", "reason": "trust policy evaluated", "statements": extra_ev,
                           "missing": missing or [], "notes": []})
                if any(e["match"] == "unknown" for e in extra_ev):
                    conf = _combine([conf, "likely"])
            if missing:
                conf = _combine([conf, "unverified"])
            out.append((target, {"kind": kind, "title": title, "confidence": conf, "evidence": ev,
                                 "from": p.arn, "to": target}))

        # full admin
        adm, ds = self.admin(p)
        if adm != "Denied":
            add("ADMIN", "already_admin", "has full administrator access", ds)
            if adm == "Allowed":
                return out  # already admin: further escalation edges add nothing
        # self escalation
        if p.kind == "user":
            for a, why in SELF_ACTIONS.items():
                if "Boundary" in a and p.boundary_status != "present":
                    continue
                d = self.ev(p, a, p.arn)
                if d.possible:
                    add("ADMIN", "self_escalation", f"{a} on itself: {why}", [d])
            for g in p.groups or []:
                garn = (self.m.groups.get(g) or {}).get("arn") or f"arn:aws:iam::{acct}:group/{g}"
                for a, why in GROUP_ACTIONS.items():
                    d = self.ev(p, a, garn)
                    if d.possible:
                        add("ADMIN", "self_escalation", f"{a} on its group {g}: {why}", [d])
            for gname, g in self.m.groups.items():
                if gname in (p.groups or []):
                    continue
                d = self.ev(p, "iam:AddUserToGroup", g.get("arn") or f"arn:aws:iam::{acct}:group/{gname}")
                if d.possible:
                    pseudo = self.group_pseudo(gname, p)
                    gadm, gds = self.admin(pseudo) if pseudo else ("Denied", [])
                    if gadm != "Denied":
                        add("ADMIN", "self_escalation", f"iam:AddUserToGroup into admin group {gname}", [d] + gds[:1])
        if p.kind == "role":
            for a in ("iam:AttachRolePolicy", "iam:PutRolePolicy"):
                d = self.ev(p, a, p.arn)
                if d.possible:
                    add("ADMIN", "self_escalation", f"{a} on itself: {ROLE_ACTIONS[a]}", [d])
        for ref in p.identity:
            if ref.kind == "managed" and ref.arn:
                for a, why in POLICY_ACTIONS.items():
                    d = self.ev(p, a, ref.arn)
                    if d.possible:
                        add("ADMIN", "self_escalation", f"{a} on {ref.name} ({ref.via}): {why}", [d])
        # credentials of other users
        for u in users:
            if u.arn == p.arn:
                continue
            for a, why in CRED_ACTIONS.items():
                d = self.ev(p, a, u.arn)
                if d.possible:
                    add(u.arn, "credentials", f"{a} on user {u.name}: {why}", [d])
                    break
        # roles
        for r in roles:
            if r.arn == p.arn:
                continue
            tr, tkind, tev = self.trust_allows(r, p)
            if tr is not False:
                d = self.assume(p, r)
                if d.possible:
                    how = "trust policy names it" if tkind == "direct" else "trust policy delegates to the account"
                    add(r.arn, "assume_role", f"sts:AssumeRole into {r.name} ({how})", [d], tev,
                        [] if r.trust_policy is not None else [f"trust policy of {r.name} not collected"])
            d2 = self.ev(p, "iam:UpdateAssumeRolePolicy", r.arn)
            if d2.possible:
                add(r.arn, "update_trust", f"iam:UpdateAssumeRolePolicy on {r.name}, then assume it", [d2])
            missing = [] if r.trust_policy is not None else [f"trust policy of {r.name} not collected"]
            pr = self.ev(p, "iam:PassRole", r.arn)
            if pr.possible:
                for act, svc in PASSROLE_SERVICES.items():
                    st, _, sev = self.trust_allows(r, service=svc)
                    if st is False:
                        continue
                    d3 = self.ev(p, act, "*")
                    if d3.possible:
                        add(r.arn, "pass_role", f"iam:PassRole {r.name} to {svc} via {act}", [pr, d3], sev,
                            missing if st is None else None)
                        break
        return out

    def modify_role_edges(self, p, reachable_roles):
        out = []
        for r in reachable_roles:
            for a, why in ROLE_ACTIONS.items():
                d = self.ev(p, a, r.arn)
                if d.possible and (d.decision == ALLOWED or _has_grant_evidence(d)):
                    conf = _sev_conf([d])
                    out.append(("ADMIN", {"kind": "modify_role", "title": f"{a} on {r.name}: {why}",
                                          "confidence": conf, "evidence": _edge_evidence([d]),
                                          "from": p.arn, "to": "ADMIN"}))
                    break
        return out

    # ------------------------------------------------------------------ paths
    def paths(self, max_hops=3):
        edges = {p.arn: self.edges_from(p) for p in self.m.principals.values() if not p.service_linked}
        results = []
        for start in self.m.principals.values():
            if start.service_linked:
                continue
            direct_admin = any(t == "ADMIN" and e["kind"] == "already_admin" for t, e in edges[start.arn])
            direct_admin = direct_admin or self.admin(start)[0] == ALLOWED
            if direct_admin:
                continue  # already admin: reported by AWS-IAM-005, not as a path
            q = deque([(start.arn, [])])
            seen = {start.arn}
            best = {}
            while q:
                node, path = q.popleft()
                if len(path) >= max_hops:
                    continue
                cand = list(edges.get(node, []))
                reach_roles = [self.m.principals[e["to"]] for _, e in cand if e["to"] in self.m.principals
                               and self.m.principals[e["to"]].kind == "role"]
                if node == start.arn and reach_roles:
                    cand += self.modify_role_edges(start, reach_roles)
                for tgt, e in cand:
                    newp = path + [e]
                    if tgt == "ADMIN":
                        key = tuple(x["title"] for x in newp)
                        if key not in best:
                            best[key] = newp
                    elif tgt not in seen:
                        seen.add(tgt)
                        q.append((tgt, newp))
            chosen, firsts = [], set()
            for steps in sorted(best.values(), key=lambda st: (len(st), _rank(_combine([s["confidence"] for s in st])))):
                if steps[0]["title"] in firsts and len(chosen) >= 1:
                    continue
                firsts.add(steps[0]["title"])
                chosen.append(steps)
            for steps in chosen[:3]:
                conf = _combine([s["confidence"] for s in steps])
                sev = "critical" if conf == "confirmed" else "high" if conf == "likely" else "medium"
                missing = sorted({m for s in steps for ev in s["evidence"] for m in ev.get("missing", [])})
                results.append({
                    "start": {"arn": start.arn, "kind": start.kind, "name": start.name},
                    "target": "full account administrator",
                    "steps": [{"from": s["from"], "to": s["to"], "kind": s["kind"], "title": s["title"],
                               "confidence": s["confidence"], "evidence": s["evidence"]} for s in steps],
                    "hops": len(steps), "confidence": conf, "severity": sev, "missing": missing,
                    "status": "confirmed by ShieldIQ evaluation" if conf == "confirmed" else
                    "potential - not confirmed (see missing / conditions)"})
        results.sort(key=lambda r: ({"critical": 0, "high": 1, "medium": 2}[r["severity"]], r["hops"]))
        for i, r in enumerate(results, 1):
            r["id"] = f"IAM-PATH-{i:03d}"
        return results

    def data_access(self, buckets):
        """Principals that can read S3 objects, with evidence. buckets: [bucket name]."""
        out = []
        for p in self.m.principals.values():
            if p.service_linked:
                continue
            for b in buckets:
                d = self.ev(p, "s3:GetObject", f"arn:aws:s3:::{b}/*")
                if d.possible:
                    out.append({"principal": p.arn, "bucket": b, "decision": d.decision,
                                "evidence": _edge_evidence([d])})
        return out

    # ------------------------------------------------------------------ per-principal summary
    def principal_report(self, p):
        adm, ads = self.admin(p)
        esc = []
        for tgt, e in self.edges_from(p):
            if e["kind"] == "already_admin":
                continue
            esc.append(e)
        admin_has_evidence = any(any(e["effect"] == "Allow" for e in d.evidence) for d in ads)
        if adm == "Allowed" or esc or (adm == "Indeterminate" and admin_has_evidence):
            state = "Finding"  # possible admin / escalation is reported with its confidence, never hidden
        elif p.identity_complete is not True or adm == "Indeterminate" or self.unknown_edges.get(p.arn):
            state = "Unknown"
        else:
            state = "Secure"
        return {"arn": p.arn, "name": p.name, "kind": p.kind, "admin": adm,
                "admin_evidence": _edge_evidence([d for d in ads if d.evidence or d.missing][:2]),
                "escalations": esc, "state": state,
                "unknown_capabilities": sorted(self.unknown_edges.get(p.arn, []))[:20], "sources": p.sources_summary(),
                "groups": p.groups, "boundary": {"status": p.boundary_status,
                                                 "policy": p.boundary.to_dict() if p.boundary else None},
                "identity_complete": p.identity_complete, "service_linked": p.service_linked,
                "trust_policy": p.trust_policy}
